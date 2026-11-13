"""Test helpers for B-157 (algebra_service, lattice_templates): a stub `sage` and a stub `docker`.

Both start the real Sage worker (solvers/common/_algebra_sage_worker.py, as the service staged it)
against the fake `sage` package in tests/algebra_fake_sage/, through its runner.py. Nothing here is
SageMath or Docker: the stub docker carries the stub marker (ctf.toolchain.images.STUB_MARKER), so the
CTF_TESTING guard lets it run, answers `image inspect` from a JSON state file and logs every call.

    state keys   images        {tag: labels-dict-or-null}; a tag not listed is "No such image"
                 down          true: every docker call fails like a stopped daemon
                 mode          FAKE_SAGE_MODE for the worker run (runner.py lists the modes)
                 sage_version  the release the fake reports (default: the image tag's, or 10.7)
                 hang          seconds the `hang` mode sleeps
                 kill_fails    true: `docker kill <name>` fails like a refusing daemon (else it succeeds)
                 kill_gone     true: `docker kill <name>` answers "No such container" (it already ended)
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

from ctf import paths
from ctf.toolchain import images

RUNNER = paths.repo_root() / "tests" / "algebra_fake_sage" / "runner.py"

_COMMON = '''\
    import json, os, subprocess, sys
    state = json.load(open(os.environ["STUB_STATE"]))
    def log(entry):
        with open(os.environ["STUB_LOG"], "a") as fh:
            fh.write(json.dumps(entry) + "\\n")
    def run_worker(worker, job, version):
        env = dict(os.environ)
        env["FAKE_SAGE_MODE"] = state.get("mode", "")
        env["FAKE_SAGE_VERSION"] = state.get("sage_version") or version
        env["FAKE_SAGE_HANG"] = str(state.get("hang", 30))
        env["FAKE_SAGE_LOG"] = os.environ["STUB_LOG"]
        return subprocess.call([{python!r}, "-I", {runner!r}, worker, job], env=env)
'''

SAGE = "#!{python} -I\n" + textwrap.dedent(_COMMON + '''\
    args = sys.argv[1:]
    log({{"tool": "sage", "argv": args}})
    if args[:1] != ["-python"] or len(args) != 3:
        print("stub sage: only `sage -python worker job` is supported", file=sys.stderr)
        sys.exit(2)
    sys.exit(run_worker(args[1], args[2], "10.7"))
    ''')

DOCKER = "#!{python} -I\n# {marker}\n" + textwrap.dedent(_COMMON + '''\
    args = sys.argv[1:]
    log({{"tool": "docker", "argv": args}})
    if state.get("down"):
        print("Cannot connect to the Docker daemon", file=sys.stderr)
        sys.exit(1)
    if args[:2] == ["image", "inspect"]:
        tag = args[-1]
        if tag in state.get("images", {{}}):
            print(json.dumps(state["images"][tag]))
            sys.exit(0)
        print("Error response from daemon: No such image: " + tag, file=sys.stderr)
        sys.exit(1)
    if args[:1] == ["kill"] and len(args) == 2:
        if state.get("kill_fails"):
            print("Error response from daemon: cannot kill container: " + args[1], file=sys.stderr)
            sys.exit(1)
        if state.get("kill_gone"):
            print("Error response from daemon: No such container: " + args[1], file=sys.stderr)
            sys.exit(1)
        print(args[1])
        sys.exit(0)
    if args[:1] != ["run"]:
        print("stub docker: unsupported " + " ".join(args[:2]), file=sys.stderr)
        sys.exit(2)
    mount = args[args.index("-v") + 1]
    host, _, inside = mount.partition(":")
    tag = next(a for a in args if a.startswith("ctf-sage:"))
    cmd = args[args.index(tag) + 1:]
    if tag not in state.get("images", {{}}):
        print("Unable to find image " + tag + " locally", file=sys.stderr)
        sys.exit(125)
    if cmd[:3] != ["timeout", "-k", "10"] or cmd[4:6] != ["sage", "-python"] or inside != "/work":
        print("stub docker: unexpected command " + " ".join(cmd), file=sys.stderr)
        sys.exit(2)
    worker, job = (host + p[len("/work"):] for p in cmd[6:8])
    sys.exit(run_worker(worker, job, tag.split(":", 1)[1]))
    ''')


def _write(tmp: Path, name: str, text: str) -> Path:
    bindir = tmp / "stubbin"
    bindir.mkdir(parents=True, exist_ok=True)
    exe = bindir / name
    exe.write_text(text)
    exe.chmod(0o755)
    return bindir


def _environ(tmp: Path, bindir: Path, state: dict) -> dict:
    st = tmp / "stub-state.json"
    st.write_text(json.dumps(state))
    return {"PATH": str(bindir), "STUB_STATE": str(st), "STUB_LOG": str(tmp / "stub-log.jsonl"),
            "CTF_TESTING": "1", "HOME": str(tmp)}


def sage_stub(tmp: Path, state: dict | None = None) -> dict:
    """A bin folder holding a stub `sage`; returns the environ to pass to the service."""
    bindir = _write(tmp, "sage", SAGE.format(python=sys.executable, runner=str(RUNNER)))
    return _environ(tmp, bindir, state or {})


def docker_stub(tmp: Path, state: dict | None = None, *, marker: bool = True) -> dict:
    """A bin folder holding a stub `docker` (marker=False: one the CTF_TESTING guard refuses)."""
    text = DOCKER.format(python=sys.executable, runner=str(RUNNER),
                         marker=images.STUB_MARKER if marker else "plain")
    return _environ(tmp, _write(tmp, "docker", text), state or {})


def built(*versions: str, root: Path | None = None) -> dict:
    """The `images` state for Sage images that are built and fresh: each carries the label that
    `images.status` wants for the checkout's current files."""
    out = {}
    for im in images.load(images.manifest_path(root)):
        if im.version_of("sage") in versions:
            out[im.tag] = {images.LABEL: images.content_hash(im, root)}
    return out


def set_state(environ: dict, state: dict) -> None:
    Path(environ["STUB_STATE"]).write_text(json.dumps(state))


ALARM_CALLS = ("alarm", "cancel_alarm")


def calls(environ: dict, tool: str | None = None) -> list[dict]:
    """The log: every entry, or those of one kind. `docker` / `sage`: the stub's argv; `fake`: the
    fake Sage's mathematics calls (LLL, BKZ, small_roots); `alarm`: the fake cysignals calls."""
    p = Path(environ["STUB_LOG"])
    if not p.exists():
        return []
    rows = [json.loads(x) for x in p.read_text().splitlines() if x.strip()]
    if tool is None:
        return rows
    if tool == "fake":
        return [r for r in rows if "call" in r and r["call"] not in ALARM_CALLS]
    if tool == "alarm":
        return [r for r in rows if r.get("call") in ALARM_CALLS]
    return [r for r in rows if r.get("tool") == tool]
