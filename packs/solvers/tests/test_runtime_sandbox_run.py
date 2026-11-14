"""B-242: tools/sandbox.py runtime_run, the only place a runtime container is started.

The docker CLI is a stand-in script ($CTF_DOCKER) that carries the test stub marker, answers
`image inspect` from a state file, records every call and keeps the stdin of `run`. No real docker
is touched, no image, no container, no network.
"""
from __future__ import annotations

import hashlib
import importlib
import io
import json
import re
import sys
import tarfile
import textwrap
from pathlib import Path

import pytest

TAG = "ctf-runtime-wasm:1"
IMAGE_ID = "sha256:" + "0123456789abcdef" * 4
HASH = hashlib.sha256(b"the files of docker/runtime").hexdigest()
OTHER = hashlib.sha256(b"other files").hexdigest()
ARGV = ("python3", "-I", "/opt/runner/trace_runner.py", "--artifact", "/work/artifact.bin")
MEMBERS = [("artifact.bin", b"\x00asm\x01\x00\x00\x00"), ("dep/000.bin", b"dep-zero")]

STUB = textwrap.dedent('''\
    #!{python} -I
    # {marker}
    import json, os, sys, time
    state = json.load(open(os.environ["RT_STUB_STATE"]))
    args = sys.argv[1:]
    entry = {{"argv": args}}
    rc = 0
    if state.get("down"):
        sys.stderr.write("Cannot connect to the Docker daemon at unix:///var/run/docker.sock\\n")
        rc = 1
    elif args[:2] == ["image", "inspect"]:
        img = state.get("images", {{}}).get(args[-1])
        if img is None:
            sys.stderr.write("Error response from daemon: No such image: " + args[-1] + "\\n")
            rc = 1
        else:
            sys.stdout.write(img["id"] + " " + img.get("label", "") + "\\n")
    elif args[:1] == ["run"]:
        data = sys.stdin.buffer.read()
        with open(os.environ["RT_STUB_STDIN"], "wb") as fh:
            fh.write(data)
        entry["stdin_bytes"] = len(data)
        with open(os.environ["RT_STUB_LOG"], "a") as fh:
            fh.write(json.dumps(entry) + "\\n")
        entry = None
        time.sleep(state.get("sleep", 0))
        sys.stdout.write(state.get("stdout", ""))
        sys.stderr.write(state.get("stderr", ""))
        rc = state.get("run_rc", 0)
    if entry is not None:
        with open(os.environ["RT_STUB_LOG"], "a") as fh:
            fh.write(json.dumps(entry) + "\\n")
    sys.exit(rc)
    ''')


class Docker:
    def __init__(self, tmp: Path, monkeypatch, marker: str = "ctf-docker-stub"):
        self.state, self.log, self.stdin = tmp / "state.json", tmp / "log.jsonl", tmp / "stdin.bin"
        self.exe = tmp / "docker-stand-in"
        self.exe.write_text(STUB.format(python=sys.executable, marker=marker))
        self.exe.chmod(0o755)
        monkeypatch.setenv("CTF_DOCKER", str(self.exe))
        monkeypatch.setenv("RT_STUB_STATE", str(self.state))
        monkeypatch.setenv("RT_STUB_LOG", str(self.log))
        monkeypatch.setenv("RT_STUB_STDIN", str(self.stdin))
        self.set(images={TAG: {"id": IMAGE_ID, "label": HASH}})

    def set(self, **state) -> None:
        self.state.write_text(json.dumps(state))

    def calls(self) -> list:
        if not self.log.exists():
            return []
        return [json.loads(x) for x in self.log.read_text().splitlines() if x.strip()]

    def verbs(self) -> list:
        return [c["argv"][0] for c in self.calls()]


@pytest.fixture
def sb():
    yield importlib.import_module("sandbox")
    sys.modules.pop("sandbox", None)


@pytest.fixture
def docker(tmp_path, monkeypatch):
    return Docker(tmp_path, monkeypatch)


# ---------------------------------------------------------------------------------------- request
def test_the_request_is_a_tar_of_the_fixed_member_names(sb):
    blob = sb.runtime_request([("dep/001.bin", b"one"), ("artifact.bin", b"ART"), ("dep/000.bin", b"zero")])
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        infos = tar.getmembers()
        assert [(i.name, i.isdir()) for i in infos] == [("dep", True), ("artifact.bin", False),
                                                        ("dep/000.bin", False), ("dep/001.bin", False)]
        assert tar.extractfile("artifact.bin").read() == b"ART"
        assert tar.extractfile("dep/001.bin").read() == b"one"
        assert all(i.mode == (0o755 if i.isdir() else 0o644) and i.uid == 0 and i.gid == 0 for i in infos)


def test_the_dep_folder_is_always_in_the_request(sb):
    with tarfile.open(fileobj=io.BytesIO(sb.runtime_request([("artifact.bin", b"A")]))) as tar:
        assert tar.getnames() == ["dep", "artifact.bin"]


@pytest.mark.parametrize("members, msg", [
    ([("dep/000.bin", b"d")], "exactly one artifact.bin"),
    ([("artifact.bin", b"a"), ("artifact.bin", b"b")], "exactly one artifact.bin"),
    ([("artifact.bin", b"a"), ("dep/000.bin", b"d"), ("dep/000.bin", b"e")], "no name twice"),
    ([("artifact.bin", b"a"), ("../escape", b"x")], "not a runtime request member name: '../escape'"),
    ([("artifact.bin", b"a"), ("dep/0.bin", b"x")], "not a runtime request member name"),
    ([("artifact.bin", b"a"), ("dep/000.bin/x", b"x")], "not a runtime request member name"),
    ([("artifact.bin", b"a"), ("/etc/passwd", b"x")], "not a runtime request member name"),
    ([("artifact.bin", b"a"), ("dep/000.bin\n", b"x")], "not a runtime request member name"),
])
def test_a_request_with_any_other_member_is_refused(sb, members, msg):
    with pytest.raises(ValueError, match=msg):
        sb.runtime_request(members)


def test_the_request_size_cap(sb, monkeypatch):
    monkeypatch.setattr(sb, "RUNTIME_MAX_INPUT", 8)
    assert sb.runtime_request([("artifact.bin", b"12345"), ("dep/000.bin", b"678")])
    with pytest.raises(ValueError, match="over 8 bytes"):
        sb.runtime_request([("artifact.bin", b"12345"), ("dep/000.bin", b"6789")])


# ------------------------------------------------------------------------------------------- argv
NAME = "ctf-runtime-0123456789ab"


def test_the_container_has_no_network_no_mount_and_no_privilege(sb):
    args = sb.runtime_argv(IMAGE_ID, NAME, 35, ARGV)
    assert args[:5] == ["run", "--rm", "-i", "--name", NAME]
    for flag, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges"),
                        ("--user", "10001:10001"), ("--memory", "768m"), ("--memory-swap", "768m"),
                        ("--cpus", "1"), ("--pids-limit", "96"), ("--restart", "no"), ("--workdir", "/work"),
                        ("--entrypoint", "/usr/local/bin/ctf-runtime-entry")):
        assert args[args.index(flag) + 1] == value, flag
    assert "--pull=never" in args and "--read-only" in args and "--init" in args
    banned = {"-v", "--volume", "--mount", "--privileged", "-e", "--env", "--env-file", "--cap-add", "--device",
              "-p", "--publish", "--pid", "--ipc", "--volumes-from", "-t", "--tty", "-d", "--detach"}
    assert not banned & set(args)
    assert not any(a.startswith(("--volume=", "--mount=", "--env=", "--network=host", "--cap-add=")) for a in args)
    tmpfs = [args[i + 1] for i, a in enumerate(args) if a == "--tmpfs"]
    assert len(tmpfs) == 2 and tmpfs[0].startswith("/tmp:rw,nosuid,nodev")
    assert tmpfs[1] == "/work:rw,nosuid,nodev,noexec,size=256m,mode=1777"


def test_the_image_id_the_time_limit_and_the_runner_end_the_command(sb):
    args = sb.runtime_argv(IMAGE_ID, NAME, 35, ARGV, memory="512m", cpus="0.5", pids=64)
    at = args.index(IMAGE_ID)
    assert args[at - 2:at] == ["--entrypoint", "/usr/local/bin/ctf-runtime-entry"]
    assert args[at + 1:] == ["35", *ARGV]
    assert args.count(IMAGE_ID) == 1
    assert args[args.index("--memory") + 1] == "512m" and args[args.index("--memory-swap") + 1] == "512m"
    assert args[args.index("--cpus") + 1] == "0.5" and args[args.index("--pids-limit") + 1] == "64"


@pytest.mark.parametrize("kw, msg", [
    (dict(image_id=TAG), "runs an image id"),
    (dict(image_id="sha256:" + "ab" * 31), "runs an image id"),
    (dict(image_id=IMAGE_ID + "\n--privileged"), "runs an image id"),
    (dict(name="csctf-sandbox"), "is named ctf-runtime-<12 hex>"),
    (dict(name="ctf-runtime-0123456789abc"), "is named ctf-runtime-<12 hex>"),
    (dict(seconds=0), "seconds must be 1..305"),
    (dict(seconds=306), "seconds must be 1..305"),
    (dict(seconds=1.5), "seconds must be 1..305"),
    (dict(seconds=True), "seconds must be 1..305"),
    (dict(memory="lots"), "memory is <int><k|m|g>"),
    (dict(memory="1G"), "memory is <int><k|m|g>"),
    (dict(cpus="-1"), "cpus a positive number"),
    (dict(cpus="2 --privileged"), "cpus a positive number"),
    (dict(pids=7), "pids must be 8..1024"),
    (dict(pids=1025), "pids must be 8..1024"),
    (dict(pids="64"), "pids must be 8..1024"),
    (dict(argv=()), "argv must be non-empty"),
    (dict(argv=("a\x00b",)), "argv must be non-empty"),
])
def test_arguments_of_any_other_shape_are_refused(sb, kw, msg):
    base = dict(image_id=IMAGE_ID, name=NAME, seconds=35, argv=ARGV)
    base.update(kw)
    with pytest.raises(ValueError, match=re.escape(msg)):
        sb.runtime_argv(base.pop("image_id"), base.pop("name"), base.pop("seconds"), base.pop("argv"), **base)


def test_the_bounds_of_the_limits_are_accepted(sb):
    assert sb.runtime_argv(IMAGE_ID, NAME, 1, ARGV, pids=8)
    assert sb.runtime_argv(IMAGE_ID, NAME, 305, ARGV, pids=1024, memory="2g", cpus="2")
    args = sb.runtime_argv(IMAGE_ID, NAME, 30, ARGV, memory="1024m", cpus="10")
    assert args[args.index("--memory") + 1] == "1024m" and args[args.index("--cpus") + 1] == "10"
    assert sb.runtime_argv(IMAGE_ID, NAME, 30, ARGV, memory="900k")


# ------------------------------------------------------------------------------------------ image
def test_an_image_with_the_expected_hash_gives_its_id(sb, docker):
    assert sb.runtime_image(TAG, HASH) == IMAGE_ID
    call = docker.calls()[0]["argv"]
    assert call[:2] == ["image", "inspect"] and call[-1] == TAG
    assert "org.ctf-tools.toolchain.hash" in call[call.index("--format") + 1]


def test_an_image_that_is_not_built_names_the_build_step(sb, docker):
    docker.set(images={})
    with pytest.raises(sb.SandboxDown) as e:
        sb.runtime_image(TAG, HASH, "python -m ctf toolchain build --apply --only runtime-wasm")
    assert str(e.value) == (f"the image {TAG} is not built "
                            "(python -m ctf toolchain build --apply --only runtime-wasm)")


def test_an_image_without_the_label_is_refused(sb, docker):
    docker.set(images={TAG: {"id": IMAGE_ID, "label": ""}})
    with pytest.raises(sb.SandboxDown, match="carries no org.ctf-tools.toolchain.hash label"):
        sb.runtime_image(TAG, HASH)


def test_an_image_built_from_other_files_is_refused(sb, docker):
    docker.set(images={TAG: {"id": IMAGE_ID, "label": OTHER}})
    with pytest.raises(sb.SandboxDown) as e:
        sb.runtime_image(TAG, HASH, "rebuild it")
    assert "was built from other files" in str(e.value)
    assert OTHER[:12] in str(e.value) and HASH[:12] in str(e.value) and "(rebuild it)" in str(e.value)


def test_a_daemon_that_does_not_answer_is_not_a_missing_image(sb, docker):
    docker.set(down=True)
    with pytest.raises(sb.SandboxDown) as e:
        sb.runtime_image(TAG, HASH)
    assert str(e.value) == ("the Docker daemon does not answer (Cannot connect to the Docker daemon at "
                            "unix:///var/run/docker.sock)")


def test_an_inspect_answer_without_an_image_id_is_refused(sb, docker):
    docker.set(images={TAG: {"id": "not-an-id", "label": HASH}})
    with pytest.raises(sb.SandboxDown, match="gave no image id"):
        sb.runtime_image(TAG, HASH)


@pytest.mark.parametrize("tag, want", [("ctf-runtime-wasm:latest", HASH), ("ctf-runtime-wasm", HASH),
                                        ("-v /:/host img:1", HASH), (TAG, "abc"), (TAG, HASH.upper())])
def test_a_floating_tag_or_a_bad_hash_never_reaches_docker(sb, docker, tag, want):
    with pytest.raises(ValueError):
        sb.runtime_image(tag, want)
    assert docker.calls() == []


# -------------------------------------------------------------------------------------------- run
def test_run_checks_the_image_then_runs_it_by_id_with_the_request_on_stdin(sb, docker):
    docker.set(images={TAG: {"id": IMAGE_ID, "label": HASH}}, stdout="@@CTF-RUNTIME-TRACE@@ {}\n",
               stderr="runner note\n", run_rc=0)
    r = sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 35, memory="512m", cpus="1", pids=64)
    assert (r.code, r.stdout, r.stderr, r.files, r.out_dir) == (0, b"@@CTF-RUNTIME-TRACE@@ {}\n",
                                                                b"runner note\n", {}, None)
    assert r.image == TAG and not r.timed_out
    assert docker.verbs() == ["image", "run"]
    run = docker.calls()[1]
    assert IMAGE_ID in run["argv"] and TAG not in run["argv"]
    assert run["argv"][run["argv"].index(IMAGE_ID) + 1:] == ["35", *ARGV]
    assert re.fullmatch(r"ctf-runtime-[0-9a-f]{12}", run["argv"][run["argv"].index("--name") + 1])
    assert run["argv"][run["argv"].index("--memory") + 1] == "512m"
    assert run["argv"][run["argv"].index("--pids-limit") + 1] == "64"
    with tarfile.open(fileobj=io.BytesIO(docker.stdin.read_bytes())) as tar:
        assert tar.getnames() == ["dep", "artifact.bin", "dep/000.bin"]
        assert tar.extractfile("artifact.bin").read() == MEMBERS[0][1]
    assert run["stdin_bytes"] == len(docker.stdin.read_bytes())


def test_two_runs_use_two_container_names(sb, docker):
    sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 5)
    sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 5)
    names = [c["argv"][c["argv"].index("--name") + 1] for c in docker.calls() if c["argv"][0] == "run"]
    assert len(names) == 2 and names[0] != names[1]


def test_a_run_without_limits_gets_the_default_ones_and_reports_how_long_it_took(sb, docker):
    import time
    t0 = time.perf_counter()
    r = sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 5)
    elapsed = time.perf_counter() - t0
    assert 0 < r.seconds <= elapsed
    run = docker.calls()[1]["argv"]
    assert (run[run.index("--memory") + 1], run[run.index("--cpus") + 1], run[run.index("--pids-limit") + 1]) == (
        "768m", "1", "96")


@pytest.mark.parametrize("state", [
    dict(images={}),
    dict(images={TAG: {"id": IMAGE_ID, "label": ""}}),
    dict(images={TAG: {"id": IMAGE_ID, "label": OTHER}}),
    dict(down=True),
])
def test_nothing_is_run_when_the_image_check_fails(sb, docker, state):
    docker.set(**state)
    with pytest.raises(sb.SandboxDown):
        sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 35)
    assert "run" not in docker.verbs()
    assert not docker.stdin.exists()


def test_a_bad_request_is_refused_before_any_container(sb, docker):
    with pytest.raises(ValueError):
        sb.runtime_run(TAG, HASH, ARGV, [("artifact.bin", b"a"), ("../x", b"b")], 35)
    assert "run" not in docker.verbs()


@pytest.mark.parametrize("rc, timed_out", [(3, False), (124, True), (137, False), (125, False)])
def test_the_runners_exit_status_is_passed_through(sb, docker, rc, timed_out):
    docker.set(images={TAG: {"id": IMAGE_ID, "label": HASH}}, stdout="partial", stderr="the artifact said so\n",
               run_rc=rc)
    r = sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 35)
    assert r.code == rc and r.timed_out is timed_out and r.stdout == b"partial"


@pytest.mark.parametrize("rc", [125, 126, 127])
def test_a_container_that_never_started_is_sandbox_down(sb, docker, rc):
    docker.set(images={TAG: {"id": IMAGE_ID, "label": HASH}}, run_rc=rc,
               stderr="docker: Error response from daemon: failed to create task\n")
    with pytest.raises(sb.SandboxDown, match="docker run could not start ctf-runtime-wasm:1"):
        sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 35)


def test_a_runner_that_only_prints_dockers_words_is_not_sandbox_down(sb, docker):
    docker.set(images={TAG: {"id": IMAGE_ID, "label": HASH}}, run_rc=1,
               stderr="docker: Error response from daemon: not really\n")
    assert sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 35).code == 1


def test_a_docker_run_that_never_returns_is_killed_by_its_own_name(sb, docker, monkeypatch):
    # Real elapsed time on purpose: the stand-in sleeps far longer than the one second the call
    # allows, so the host-side limit is what ends it at any machine load.
    monkeypatch.setattr(sb, "RUNTIME_START_SLACK", 0.0)
    docker.set(images={TAG: {"id": IMAGE_ID, "label": HASH}}, sleep=120)
    with pytest.raises(sb.SandboxDown, match="did not answer"):
        sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 1)
    kills = [c["argv"] for c in docker.calls() if c["argv"][0] == "kill"]
    assert len(kills) == 1 and re.fullmatch(r"ctf-runtime-[0-9a-f]{12}", kills[0][1])


# ---------------------------------------------------------------------------------- test guard
def test_under_testing_a_docker_that_cannot_be_read_is_refused(sb, tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_DOCKER", str(tmp_path / "no-such-docker"))
    with pytest.raises(sb.SandboxDown, match="refused under CTF_TESTING"):
        sb.runtime_image(TAG, HASH)


def test_under_testing_the_marker_must_be_near_the_start_of_the_file(sb, tmp_path, monkeypatch):
    late = Docker(tmp_path, monkeypatch, marker="x" * 5000 + " ctf-docker-stub")
    with pytest.raises(sb.SandboxDown, match="refused under CTF_TESTING"):
        sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 35)
    assert late.calls() == []


@pytest.mark.parametrize("start, accepted", [(4096 - 15, True), (4096 - 14, False)])
def test_under_testing_the_marker_must_lie_wholly_in_the_first_4096_bytes(sb, tmp_path, monkeypatch, start, accepted):
    d = Docker(tmp_path, monkeypatch)
    text = d.exe.read_text().replace("# ctf-docker-stub\n", "", 1)
    head, sep, rest = text.partition("\n")
    filler = "# " + "x" * (start - len(head) - 1 - 2 - 1) + " "
    d.exe.write_text(head + sep + filler + "ctf-docker-stub\n" + rest)
    assert d.exe.read_bytes().index(b"ctf-docker-stub") == start
    if accepted:
        assert sb.runtime_image(TAG, HASH) == IMAGE_ID
    else:
        with pytest.raises(sb.SandboxDown, match="refused under CTF_TESTING"):
            sb.runtime_image(TAG, HASH)
        assert d.calls() == []


def test_under_testing_a_docker_without_the_stub_marker_is_never_called(sb, tmp_path, monkeypatch):
    plain = Docker(tmp_path, monkeypatch, marker="a real docker would not carry the marker")
    with pytest.raises(sb.SandboxDown, match="refused under CTF_TESTING"):
        sb.runtime_run(TAG, HASH, ARGV, MEMBERS, 35)
    with pytest.raises(sb.SandboxDown, match="refused under CTF_TESTING"):
        sb.runtime_image(TAG, HASH)
    assert plain.calls() == []
