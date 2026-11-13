"""B-192: the needs_loopback / needs_jit markers and the loopback auto-not-run rule
(ctf/testing/capabilities.py, ctf/testing/pytest_plugin.py), observed in a child pytest.

A sandbox is simulated in the child by a conftest that seeds the capability cache with a failed
probe (this process cannot nest a real sandbox); the plugin is what is under test.
"""
from __future__ import annotations

import errno
import os
import signal
import subprocess
import sys
import textwrap
import urllib.error

import pytest

from ctf import paths, sandboxinfo
from ctf.testing import capabilities as caps

SUITE = textwrap.dedent("""\
    import errno
    import socket
    import pytest

    @pytest.mark.needs_loopback
    def test_marked_loopback():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.close()

    @pytest.mark.needs_jit
    def test_marked_jit():
        pass

    def test_socket_denial():
        raise PermissionError(errno.EPERM, "Operation not permitted")

    def test_file_denial():
        raise PermissionError(errno.EPERM, "Operation not permitted", "/some/file")

    def test_plain_failure():
        assert 1 == 2

    @pytest.fixture
    def fake_service():
        raise PermissionError(errno.EPERM, "Operation not permitted")

    def test_setup_denial(fake_service):
        pass
    """)

SANDBOX_CONFTEST = textwrap.dedent("""\
    from ctf.testing import capabilities
    capabilities._CACHE["loopback"] = capabilities.Capability(False, "SIMULATED loopback denial")
    capabilities._CACHE["jit"] = capabilities.Capability(False, "SIMULATED jit denial")
    """)


def run_child(tmp_path, *args, sandboxed=False, env=None, suite=SUITE):
    (tmp_path / "test_synth.py").write_text(suite)
    if sandboxed:
        (tmp_path / "conftest.py").write_text(SANDBOX_CONFTEST)
    e = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "CTF_STRICT_TESTS")}
    e["PYTHONPATH"] = str(paths.repo_root())
    e.update(env or {})
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-rfEs", "-p", "no:cacheprovider",
                        "-p", "ctf.testing.pytest_plugin", "-o", "addopts=", "--rootdir", str(tmp_path),
                        str(tmp_path / "test_synth.py"), *args],
                       cwd=tmp_path, env=e, capture_output=True, text=True, timeout=600)
    return r.returncode, r.stdout + r.stderr


@pytest.mark.needs_loopback
@pytest.mark.needs_jit
def test_with_loopback_marked_tests_run_and_socket_denials_stay_failures(tmp_path):
    code, out = run_child(tmp_path)
    assert code == 1, out
    assert "3 failed, 2 passed, 1 error" in out, out
    assert "FAILED test_synth.py::test_socket_denial" in out
    assert "ERROR test_synth.py::test_setup_denial" in out
    assert "NOT RUN" not in out


def test_in_a_sandbox_marked_tests_and_socket_denials_are_not_run(tmp_path):
    code, out = run_child(tmp_path, sandboxed=True)
    assert code == 1, out                                  # the two real failures still fail
    assert "2 failed, 4 skipped" in out, out
    assert "error" not in out.splitlines()[-1]
    assert "FAILED test_synth.py::test_file_denial" in out
    assert "FAILED test_synth.py::test_plain_failure" in out
    nr = out.split("NOT RUN:", 1)[1]
    assert "4 test(s) did not run (needs_loopback 3, needs_jit 1)" in nr
    assert "needs_loopback: SIMULATED loopback denial\n" in nr
    assert "needs_jit: SIMULATED jit denial" in nr
    assert ("needs_loopback: SIMULATED loopback denial (auto: the test failed on PermissionError: "
            "[Errno 1] Operation not permitted)") in nr
    assert "test_synth.py::test_socket_denial" in nr
    assert "test_synth.py::test_setup_denial" in nr


def test_strict_mode_fails_a_sandboxed_run_that_only_skipped(tmp_path):
    suite = textwrap.dedent("""\
        import errno, pytest
        @pytest.mark.needs_loopback
        def test_a():
            pass
        def test_b():
            raise PermissionError(errno.EACCES, "Permission denied")
        """)
    code, out = run_child(tmp_path, sandboxed=True, suite=suite)
    assert code == 0 and "2 skipped" in out, out
    code, out = run_child(tmp_path, "--strict-not-run", sandboxed=True, suite=suite)
    assert code == 1 and "2 skipped" in out, out


@pytest.mark.needs_tool("py:xdist")
def test_auto_not_run_survives_xdist(tmp_path):
    code, out = run_child(tmp_path, "-n", "2", sandboxed=True)
    assert code == 1, out
    assert "2 failed, 4 skipped" in out, out
    assert "(needs_loopback 3, needs_jit 1)" in out


# --------------------------------------------------------------------------------- the probes
@pytest.mark.parametrize("rc, out, ok, words", [
    (0, "JIT-OK 42 unicorn\n", True, ""),
    (0, "JIT-OK 42 no-unicorn\n", True, ""),
    (0, "JIT-OK 41 unicorn\n", False, "exit 0"),
    (-signal.SIGILL, "", False, "SIGILL"),
    (128 + signal.SIGILL, "", False, "SIGILL (exit 132)"),
    (128 + signal.SIGKILL, "", False, "SIGKILL"),
    (3, "JIT-DENIED mmap: EINVAL Invalid argument\n", False, "JIT-DENIED mmap: EINVAL"),
    (1, "", False, "exit 1: no output"),
])
def test_classify_jit(rc, out, ok, words):
    cap = caps.classify_jit(rc, out, "")
    assert cap.ok is ok
    assert words in cap.reason


def test_probe_jit_reads_a_child_killed_by_sigill():
    kill = [sys.executable, "-I", "-c", "import os, signal; os.kill(os.getpid(), signal.SIGILL)"]
    cap = caps.probe_jit(kill)
    assert not cap.ok and "SIGILL" in cap.reason
    good = caps.probe_jit([sys.executable, "-I", "-c", "print('JIT-OK 42 no-unicorn')"])
    assert good.ok
    missing = caps.probe_jit(["/nonexistent/python-xyz"])
    assert not missing.ok and "could not start" in missing.reason


@pytest.mark.needs_jit
@pytest.mark.needs_tool("py:unicorn")
def test_the_real_jit_probe_runs_unicorn():
    r = subprocess.run([sys.executable, "-I", "-c", caps.JIT_PROBE_SRC], capture_output=True, text=True,
                       timeout=600)
    assert r.returncode == 0 and r.stdout.strip() == "JIT-OK 42 unicorn", r.stdout + r.stderr


@pytest.mark.needs_tool("sandbox-exec", "py:unicorn")
def test_the_real_jit_probe_catches_codexs_sysctl_denial():
    """The cause of Unicorn's SIGILL under Codex (codex-cli 0.167): its seatbelt denies the sysctl
    hw.cachelinesize. Reproduced with that one rule; needs a process that can apply a sandbox."""
    if sandboxinfo.macos_sandboxed():
        pytest.skip("needs_unsandboxed: macOS cannot apply a sandbox inside another one")
    prof = '(version 1)(allow default)(deny sysctl-read (sysctl-name "hw.cachelinesize"))'
    cap = caps.probe_jit(["sandbox-exec", "-p", prof, sys.executable, "-I", "-c", caps.JIT_PROBE_SRC])
    assert not cap.ok and "SIGILL" in cap.reason, cap


def test_loopback_probe_reports_the_denial(monkeypatch):
    def denied():
        raise PermissionError(errno.EPERM, "Operation not permitted")
    monkeypatch.setattr(sandboxinfo, "probe_loopback", denied)
    cap = caps.probe_loopback()
    assert not cap.ok and "Operation not permitted" in cap.reason and "loopback" in cap.reason
    monkeypatch.setattr(sandboxinfo, "probe_loopback", lambda: None)
    assert caps.probe_loopback().ok


def test_loopback_and_jit_are_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(caps, "probe_loopback", lambda: calls.append(1) or caps.Capability(True))
    caps.reset()
    try:
        assert caps.loopback().ok and caps.loopback().ok
        assert len(calls) == 1
    finally:
        caps.reset()


def _chained() -> BaseException:
    try:
        try:
            raise PermissionError(errno.EACCES, "Permission denied")
        except PermissionError as inner:
            raise RuntimeError("server failed to start") from inner
    except RuntimeError as e:
        return e


def _raised_while_handling(make) -> BaseException:
    """An exception raised inside `except PermissionError:` (EPERM, no file name): only its
    __context__ points at the EPERM."""
    try:
        try:
            raise PermissionError(errno.EPERM, "Operation not permitted")
        except PermissionError as err:
            raise make(err)
    except BaseException as e:      # noqa: BLE001 - the test inspects whatever was raised
        assert e.__cause__ is None and isinstance(e.__context__, PermissionError)
        return e


class _WrapsInArgs(OSError):
    """Like requests.exceptions.ConnectionError: the underlying error is its first argument."""


@pytest.mark.parametrize("exc, want", [
    # an assert that fails while handling an EPERM, an EPERM from os.kill, a test's own error: real
    # failures, not socket denials (the old rule followed __context__ and hid them as not run)
    (_raised_while_handling(lambda err: AssertionError("server answered 500")), False),
    (_raised_while_handling(lambda err: ValueError("bad pid")), False),
    (_raised_while_handling(lambda err: AssertionError(err)), False),
    # explicit wrapping still counts: raise ... from, and an exception carried in args
    (_raised_while_handling(lambda err: _WrapsInArgs(err)), True),
    (_WrapsInArgs(urllib.error.URLError(PermissionError(errno.EACCES, "denied"))), True),
    (_WrapsInArgs(ConnectionRefusedError(errno.ECONNREFUSED, "refused")), False),
    (PermissionError(errno.EPERM, "Operation not permitted"), True),
    (OSError(errno.EACCES, "Permission denied"), True),
    (PermissionError(errno.EPERM, "Operation not permitted", "/a/file"), False),
    (OSError(errno.ECONNREFUSED, "Connection refused"), False),
    (urllib.error.URLError(PermissionError(errno.EPERM, "Operation not permitted")), True),
    (urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "refused")), False),
    (_chained(), True),
    (AssertionError("x"), False),
    (None, False),
])
def test_is_socket_denial(exc, want):
    assert caps.is_socket_denial(exc) is want


def test_is_socket_denial_survives_a_cycle():
    a, b = RuntimeError("a"), RuntimeError("b")
    a.__context__, b.__context__ = b, a
    assert caps.is_socket_denial(a) is False
