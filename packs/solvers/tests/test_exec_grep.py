"""B-024 sandbox exec-and-grep: the docker command, the unavailable (blocked) path, the grep/compose
logic (with a fake backend), and one real end-to-end run of a self-compiled binary (needs cc).

No challenge binary is ever read or run.  The real-exec test compiles its own tiny C program and runs
it through a test-local native backend; the Docker command builder is checked as a pure function.
"""
import os
import shutil
import subprocess
import textwrap

import pytest

import exec_grep as X

FLAG = "CSCTF{sandbox_printed_me}"


def _profile():
    from ctf import event
    return event.load("csctf")


def _elf_dir(tmp_path, data=b"\x7fELF" + b"\x00" * 64, name="target"):
    cdir = tmp_path / "chal"
    (cdir / "files").mkdir(parents=True)
    (cdir / "files" / name).write_bytes(data)
    return cdir


# --------------------------------------------------------------------------- docker command builder
def test_docker_run_argv_locks_the_container_down():
    argv = X.docker_run_argv("csctf-pwn:1", "/host/fcunlock", ["CODE"], timeout=7)
    assert argv[:3] == ["docker", "run", "--rm"]
    pairs = list(zip(argv, argv[1:]))
    assert ("--network", "none") in pairs
    assert "--read-only" in argv
    assert ("--cap-drop", "ALL") in pairs
    assert ("--security-opt", "no-new-privileges") in pairs
    assert ("--memory", X.MEM_LIMIT) in pairs
    assert ("--pids-limit", str(X.PIDS_LIMIT)) in pairs
    assert ("--cpus", X.CPU_LIMIT) in pairs
    assert "-v" in argv and f"/host/fcunlock:{X.CONTAINER_PATH}:ro" in argv
    assert "csctf-pwn:1" in argv
    assert "7" in argv                     # the container-side timeout value
    assert argv[-1] == "CODE"              # the candidate input reaches the program


def test_docker_run_argv_mounts_read_only_and_never_names_the_host_home(tmp_path):
    argv = X.docker_run_argv("img", "/a/b/bin", [], timeout=3)
    mount = [a for a in argv if ":ro" in a]
    assert mount == [f"/a/b/bin:{X.CONTAINER_PATH}:ro"]


# --------------------------------------------------------------------------- fake backend helpers
class FakeExec:
    """Records calls; returns a canned RunResult. The grep/aggregation is the thing under test."""
    def __init__(self, output=b"", *, available=True, reason=""):
        self._out = output
        self._avail = (available, reason)
        self.calls = []

    def available(self):
        return self._avail

    def run(self, host_path, argv=(), *, timeout=X.DEFAULT_TIMEOUT):
        self.calls.append((os.path.basename(str(host_path)), list(argv)))
        return X.RunResult(stdout=self._out)


class ExplodingExec:
    """A backend whose run() must never be called (used to prove the binary is not run when blocked)."""
    def __init__(self, reason):
        self._reason = reason

    def available(self):
        return (False, self._reason)

    def run(self, *a, **k):               # pragma: no cover - asserts it is never reached
        raise AssertionError("run() must not be called when the sandbox is unavailable")


# --------------------------------------------------------------------------- engine: grep + compose
def test_solve_reports_solved_when_a_run_prints_the_flag(tmp_path):
    cdir = _elf_dir(tmp_path)
    fake = FakeExec(output=b"interlock released. token: " + FLAG.encode())
    r = X.solve(cdir, _profile(), exec_backend=fake)
    assert r.status == "solved"
    assert FLAG in r.flags
    assert r.evidence and r.evidence[0].kind == "oracle"
    assert fake.calls                      # the binary was actually run through the backend


def test_solve_tries_recovered_mixer_codes_as_arguments(tmp_path):
    cdir = _elf_dir(tmp_path, name="fcunlock")
    mix = cdir / "recon" / "mixer"
    mix.mkdir(parents=True)
    (mix / "recovered.txt").write_text("HALCYON_1B5FC6D72036689A\n")
    fake = FakeExec(output=b"usage")
    X.solve(cdir, _profile(), exec_backend=fake)
    tried = [argv for _, argv in fake.calls]
    assert [] in tried                                       # the no-arg run
    assert ["HALCYON_1B5FC6D72036689A"] in tried             # the recovered code as argv


def test_solve_blocks_and_never_runs_the_binary_when_the_sandbox_is_unavailable(tmp_path):
    cdir = _elf_dir(tmp_path)
    r = X.solve(cdir, _profile(), exec_backend=ExplodingExec("docker not found on PATH"))
    assert r.status == "blocked"
    assert "docker not found" in r.notes and "never run on the host" in r.notes


def test_solve_is_none_without_an_elf(tmp_path):
    cdir = tmp_path / "chal"
    (cdir / "files").mkdir(parents=True)
    (cdir / "files" / "notes.txt").write_text("no binary here")
    r = X.solve(cdir, _profile(), exec_backend=FakeExec(output=FLAG.encode()))
    assert r.status == "none"


def test_solve_is_none_when_output_has_no_flag(tmp_path):
    cdir = _elf_dir(tmp_path)
    r = X.solve(cdir, _profile(), exec_backend=FakeExec(output=b"permission denied"))
    assert r.status == "none" and not r.flags


# --------------------------------------------------------------------------- DockerExec backend
def _inspect_ok(cmd):
    """True iff cmd is the ``docker image inspect`` image-presence probe."""
    return cmd[:3] == ["docker", "image", "inspect"]


def test_dockerexec_blocks_when_docker_is_absent():
    dx = X.DockerExec("csctf-pwn:1", which_fn=lambda _n: None)
    ok, why = dx.available()
    assert not ok and "docker" in why
    with pytest.raises(X.SandboxUnavailable):
        dx.run("/x/bin")


def test_dockerexec_blocks_when_the_sandbox_image_is_absent():
    # docker is on PATH but `docker image inspect csctf-pwn:1` fails -> a missing required resource
    # must be reported loudly (blocked), and the container must never be run (rule 6/10).
    def fake_run(cmd, **kw):
        if _inspect_ok(cmd):
            return subprocess.CompletedProcess(cmd, 1, stdout=b"", stderr=b"No such image: csctf-pwn:1")
        raise AssertionError("must not `docker run` the container when the image is absent")

    dx = X.DockerExec("csctf-pwn:1", run_fn=fake_run, which_fn=lambda _n: "/usr/bin/docker")
    ok, why = dx.available()
    assert not ok and "image" in why and "csctf-pwn:1" in why
    with pytest.raises(X.SandboxUnavailable):
        dx.run("/x/bin")


def test_dockerexec_parses_a_completed_run(tmp_path):
    calls = {}

    def fake_run(cmd, **kw):
        calls["cmd"] = cmd
        calls["env"] = kw.get("env", {})
        return subprocess.CompletedProcess(cmd, 0, stdout=FLAG.encode(), stderr=b"")

    dx = X.DockerExec("img", run_fn=fake_run, which_fn=lambda _n: "/usr/bin/docker")
    res = dx.run("/x/bin", ["ARG"])
    assert FLAG.encode() in res.output and res.exit_code == 0
    assert calls["cmd"][:3] == ["docker", "run", "--rm"]    # last call is the run, not the probe
    assert not any("TOKEN" in k for k in calls["env"])       # secrets scrubbed from docker's env


def test_dockerexec_marks_a_timeout():
    def fake_run(cmd, **kw):
        if _inspect_ok(cmd):                                 # image probe succeeds
            return subprocess.CompletedProcess(cmd, 0, stdout=b"[]", stderr=b"")
        raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 1), output=b"partial", stderr=b"")

    dx = X.DockerExec("img", run_fn=fake_run, which_fn=lambda _n: "/usr/bin/docker")
    res = dx.run("/x/bin")
    assert res.timed_out and res.exit_code == 124 and b"partial" in res.output


# --------------------------------------------------------------------------- real end-to-end (cc)
class _NativeExec:
    """Test-only backend: run a *self-compiled* binary directly (no Docker) to prove real stdout is
    grepped. Only ever used on fixtures the test itself compiled (rule 4 permits that)."""
    def available(self):
        return (True, "")

    def run(self, host_path, argv=(), *, timeout=X.DEFAULT_TIMEOUT):
        cp = subprocess.run([str(host_path), *map(str, argv)], capture_output=True,
                            timeout=timeout, check=False)
        return X.RunResult(stdout=cp.stdout, stderr=cp.stderr, exit_code=cp.returncode)


@pytest.mark.needs_tool("cc")
def test_exec_grep_finds_a_flag_a_real_binary_prints(tmp_path):
    src = tmp_path / "keygen.c"
    src.write_text(textwrap.dedent(f"""
        #include <stdio.h>
        #include <string.h>
        int main(int argc, char **argv) {{
            if (argc > 1 && strcmp(argv[1], "OPEN") == 0) {{
                printf("unlocked: {FLAG}\\n");
                return 0;
            }}
            printf("usage: %s <code>\\n", argv[0]);
            return 1;
        }}
    """))
    binp = tmp_path / "chal" / "files" / "keygen"
    binp.parent.mkdir(parents=True)
    subprocess.run(["cc", str(src), "-o", str(binp)], check=True)
    cdir = binp.parent.parent
    (cdir / "recon" / "mixer").mkdir(parents=True)
    (cdir / "recon" / "mixer" / "recovered.txt").write_text("OPEN\n")

    r = X.solve(cdir, _profile(), exec_backend=_NativeExec())
    assert r.status == "solved"
    assert FLAG in r.flags
