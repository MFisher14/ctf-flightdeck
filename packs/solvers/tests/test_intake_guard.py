"""The network guard intake runs engines under (B-002): ctf/intake/guard.py and ctf/intake/_guardboot.py.

Every target here is a script the test writes, and every socket is a loopback listener the test owns.
"""
from __future__ import annotations

import socket
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import paths
from ctf.intake import guard as G

BOOT = G.boot_path(paths.repo_root())


@pytest.fixture
def listener():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    s.setblocking(False)
    yield s
    s.close()


def _accepted(s) -> bool:
    try:
        conn, _ = s.accept()
    except BlockingIOError:
        return False
    conn.close()
    return True


def _run(tmp_path, body: str, mode: str = "hook", *args) -> subprocess.CompletedProcess:
    script = tmp_path / "target.py"
    script.write_text(textwrap.dedent(body), encoding="utf-8")
    return subprocess.run([sys.executable, "-I", str(BOOT), "--mode", mode, "--", str(script), *args],
                          capture_output=True, text=True, timeout=60, cwd=tmp_path)


TRY = """
import sys
def attempt(name, fn):
    try:
        fn()
        print(name, "ALLOWED")
    except PermissionError as e:
        print(name, "REFUSED", e)
"""


def test_hook_refuses_tcp_connect_and_nothing_reaches_the_listener(tmp_path, listener):
    port = listener.getsockname()[1]
    cp = _run(tmp_path, TRY + f"""
import socket
attempt("connect", lambda: socket.create_connection(("127.0.0.1", {port}), timeout=2))
""")
    assert "connect REFUSED intake network guard" in cp.stdout, cp.stdout + cp.stderr
    assert not _accepted(listener)


def test_hook_refuses_connect_on_an_inherited_inet_socket(tmp_path, listener):
    """A socket built from a file descriptor passes creation (family unknown there); its connect is refused."""
    inherited = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        fd, port = inherited.fileno(), listener.getsockname()[1]
        script = tmp_path / "target.py"
        script.write_text(TRY + f"import socket\ns = socket.socket(fileno={fd})\n"
                                f"attempt('connect', lambda: s.connect(('127.0.0.1', {port})))\n", encoding="utf-8")
        cp = subprocess.run([sys.executable, "-I", str(BOOT), "--mode", "hook", "--", str(script)],
                            capture_output=True, text=True, timeout=60, pass_fds=(fd,))
        assert "connect REFUSED intake network guard: socket.connect" in cp.stdout, cp.stdout + cp.stderr
        assert not _accepted(listener)
    finally:
        inherited.close()


@pytest.mark.parametrize("how", ["sendto", "sendmsg"])
def test_hook_refuses_sendto_and_sendmsg_on_an_inherited_udp_socket(tmp_path, how):
    """An unconnected UDP socket handed down by file descriptor passes creation (family -1); sending
    a datagram with an address on it is refused, and the test's receiver gets nothing."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.setblocking(False)
    inherited = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        fd, port = inherited.fileno(), rx.getsockname()[1]
        send = (f"s.sendto(b'leak', ('127.0.0.1', {port}))" if how == "sendto"
                else f"s.sendmsg([b'leak'], [], 0, ('127.0.0.1', {port}))")
        script = tmp_path / "target.py"
        script.write_text(TRY + f"import socket\ns = socket.socket(fileno={fd})\n"
                                f"attempt('{how}', lambda: {send})\n", encoding="utf-8")
        cp = subprocess.run([sys.executable, "-I", str(BOOT), "--mode", "hook", "--", str(script)],
                            capture_output=True, text=True, timeout=60, pass_fds=(fd,))
        assert f"{how} REFUSED intake network guard: socket.{how}" in cp.stdout, cp.stdout + cp.stderr
        with pytest.raises(BlockingIOError):
            rx.recv(16)
    finally:
        inherited.close()
        rx.close()


def test_the_same_inherited_udp_send_gets_through_without_the_guard(tmp_path):
    """The control for the test above: the send it refuses does reach the receiver when unguarded."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(5)
    inherited = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        fd, port = inherited.fileno(), rx.getsockname()[1]
        script = tmp_path / "target.py"
        script.write_text(f"import socket\ns = socket.socket(fileno={fd})\n"
                          f"s.sendto(b'leak', ('127.0.0.1', {port}))\n", encoding="utf-8")
        cp = subprocess.run([sys.executable, "-I", str(script)], capture_output=True, text=True, timeout=60,
                            pass_fds=(fd,))
        assert cp.returncode == 0, cp.stderr
        assert rx.recv(16) == b"leak"
    finally:
        inherited.close()
        rx.close()


MP_CHILD = """
import multiprocessing, socket, sys
def child(port):
    socket.create_connection(("127.0.0.1", port), timeout=2).sendall(b"from-child")
"""


def test_hook_mode_refuses_a_multiprocessing_spawn_child(tmp_path, listener):
    """multiprocessing's spawn start method uses _posixsubprocess.fork_exec, not subprocess: its child
    would be an interpreter without the hook. It is refused, and nothing reaches the listener."""
    port = listener.getsockname()[1]
    cp = _run(tmp_path, TRY + MP_CHILD + f"""
if __name__ == "__main__":
    ctx = multiprocessing.get_context("spawn")
    def go():
        p = ctx.Process(target=child, args=({port},))
        p.start()
        p.join(20)
    attempt("mp-spawn", go)
    import _posixsubprocess
    attempt("fork_exec", lambda: _posixsubprocess.fork_exec())
""")
    assert "mp-spawn REFUSED intake network guard: _posixsubprocess.fork_exec" in cp.stdout, cp.stdout + cp.stderr
    assert "fork_exec REFUSED intake network guard" in cp.stdout, cp.stdout + cp.stderr
    assert not _accepted(listener)


def test_hook_mode_refuses_a_fresh_copy_of_posixsubprocess(tmp_path):
    cp = _run(tmp_path, """
import sys
del sys.modules["_posixsubprocess"]
try:
    import _posixsubprocess
    print("FRESH", _posixsubprocess.fork_exec)
except ImportError as e:
    print("REFUSED", e)
""")
    assert "REFUSED intake network guard: import of _posixsubprocess refused" in cp.stdout, cp.stdout + cp.stderr
    assert "FRESH" not in cp.stdout


def test_hook_mode_refuses_ctypes_and_os_mode_allows_it(tmp_path):
    body = """
try:
    import ctypes
    print("CTYPES", ctypes.CDLL(None).getpid() > 0)
except ImportError as e:
    print("NOCTYPES", e)
"""
    hook = _run(tmp_path, body, "hook")
    assert "NOCTYPES intake network guard: import of _ctypes refused" in hook.stdout, hook.stdout + hook.stderr
    osm = _run(tmp_path, body, "os")
    assert "CTYPES True" in osm.stdout, osm.stdout + osm.stderr


@pytest.mark.parametrize("mod", ["_xxsubinterpreters", "_interpreters", "_testinternalcapi", "_testcapi"])
def test_hook_mode_refuses_the_modules_that_make_a_sub_interpreter(tmp_path, mod):
    """A sub-interpreter has none of the hooks; whether or not this build ships the module, its
    import is refused before any finder looks for it."""
    cp = _run(tmp_path, f"""
try:
    import {mod}
    print("IMPORTED")
except ImportError as e:
    print("NOIMPORT", e)
""")
    assert f"NOIMPORT intake network guard: import of {mod} refused" in cp.stdout, cp.stdout + cp.stderr


def test_sub_interpreters_work_without_hook_mode(tmp_path):
    """The control: in mode os the module imports and creates an interpreter."""
    cp = _run(tmp_path, """
try:
    import _interpreters as interp          # 3.13 and later
except ImportError:
    import _xxsubinterpreters as interp     # 3.12
i = interp.create()
interp.destroy(i)
print("SUBINTERP OK")
""", "os")
    assert "SUBINTERP OK" in cp.stdout, cp.stdout + cp.stderr


def test_os_mode_leaves_multiprocessing_and_subprocess_working(tmp_path):
    """Mode os does not replace fork_exec: under the OS sandbox the child inherits the sandbox."""
    cp = _run(tmp_path, """
import multiprocessing, subprocess, sys
def child(q):
    q.put("child ran")
if __name__ == "__main__":
    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=child, args=(q,))
    p.start()
    print(q.get(timeout=30))
    p.join(30)
    print(subprocess.run([sys.executable, "-c", "print('sub ran')"], capture_output=True, text=True).stdout.strip())
""", "os")
    assert "child ran" in cp.stdout and "sub ran" in cp.stdout, cp.stdout + cp.stderr


@pytest.mark.parametrize("call", [
    "socket.getaddrinfo('localhost', 80)",
    "socket.gethostbyname('localhost')",
    "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
    "socket.socket(socket.AF_INET6, socket.SOCK_STREAM)",
])
def test_hook_refuses_lookups_and_inet_sockets(tmp_path, call):
    cp = _run(tmp_path, TRY + f"import socket\nattempt('x', lambda: {call})\n")
    assert "x REFUSED" in cp.stdout, cp.stdout + cp.stderr


def test_hook_allows_unix_sockets(tmp_path):
    cp = _run(tmp_path, TRY + "import socket\na, b = socket.socketpair()\n"
                              "attempt('pair', lambda: a.send(b'x') and print('got', b.recv(1)))\n")
    assert "got b'x'" in cp.stdout
    assert "pair ALLOWED" in cp.stdout, cp.stdout + cp.stderr


def test_spawning_is_refused_in_hook_mode_and_allowed_in_os_mode(tmp_path):
    body = TRY + "import subprocess, os\n" \
                 "attempt('popen', lambda: subprocess.run([sys.executable, '-c', 'pass'], check=True))\n" \
                 "attempt('system', lambda: os.system('true'))\n"
    hook = _run(tmp_path, body, "hook")
    assert "popen REFUSED" in hook.stdout and "system REFUSED" in hook.stdout, hook.stdout + hook.stderr
    osm = _run(tmp_path, body, "os")       # the boot alone (no OS sandbox applied here): children allowed
    assert "popen ALLOWED" in osm.stdout and "system ALLOWED" in osm.stdout, osm.stdout + osm.stderr


def test_target_runs_as_main_with_its_args_and_exit_code(tmp_path):
    cp = _run(tmp_path, "import sys\nprint(__name__, sys.argv[1:])\nraise SystemExit(int(sys.argv[1]))\n",
              "hook", "7", "x")
    assert cp.returncode == 7
    assert "__main__ ['7', 'x']" in cp.stdout


def test_bad_usage_exits_2(tmp_path):
    for argv in (["--mode", "none", "--", "x.py"], ["--mode", "hook", "x.py"], []):
        cp = subprocess.run([sys.executable, "-I", str(BOOT), *argv], capture_output=True, text=True)
        assert cp.returncode == 2 and "usage" in cp.stderr


# ---------------------------------------------------------------- resolve / wrap

def _probe(monkeypatch, value):
    monkeypatch.setitem(G._PROBE, "os", value)


def test_resolve_modes(monkeypatch):
    with pytest.raises(G.GuardError, match="use one of auto, os, hook"):
        G.resolve("off")
    _probe(monkeypatch, (None, "sandbox-exec probe exited 71: Operation not permitted"))
    h = G.resolve("hook")
    assert h.mode == "hook" and not h.allows_spawn
    auto = G.resolve("auto")
    assert auto.mode == "hook" and not auto.allows_spawn and auto.prefix == ()
    assert "Operation not permitted" in auto.reason
    with pytest.raises(G.GuardError, match="OS sandbox is unavailable: sandbox-exec probe exited 71"):
        G.resolve("os")
    _probe(monkeypatch, (("/x/sandbox-exec", "-p", G.DARWIN_PROFILE), "sandbox-exec deny-network profile"))
    for mode in ("auto", "os"):
        g = G.resolve(mode)
        assert g.mode == "os" and g.allows_spawn and g.prefix == ("/x/sandbox-exec", "-p", G.DARWIN_PROFILE)
    assert G.resolve("hook").mode == "hook"


def test_probe_runs_true_under_the_candidate_and_caches(monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 71, b"", b"sandbox_apply: Operation not permitted\n")

    monkeypatch.setattr(G, "_candidate", lambda: (("sbx", "-p", "P"), "sbx profile"))
    monkeypatch.setattr(G.subprocess, "run", fake_run)
    monkeypatch.setattr(G, "_PROBE", {})
    prefix, why = G.os_sandbox()
    assert prefix is None and why == "sbx profile probe exited 71: sandbox_apply: Operation not permitted"
    assert calls[0][:3] == ["sbx", "-p", "P"] and Path(calls[0][3]).name == "true"
    G.os_sandbox()
    assert len(calls) == 1                     # cached
    monkeypatch.setattr(G.subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, b"", b""))
    assert G.os_sandbox(refresh=True) == (("sbx", "-p", "P"), "sbx profile")


def test_wrap_puts_the_guard_boot_before_the_engine_boot(tmp_path):
    from ctf.engines import runner
    cmd = runner.command("toolkits.x", ["a"], python="/py", root=tmp_path, via="intake")
    g = G.Guard("os", ("sbx", "-p", "P"), "r")
    assert G.wrap(g, cmd, tmp_path) == ["sbx", "-p", "P", "/py", "-I", str(tmp_path / "ctf/intake/_guardboot.py"),
                                        "--mode", "os", "--", *cmd[2:]]
    assert cmd[2] == str(tmp_path / "ctf/engines/_boot.py")
    with pytest.raises(G.GuardError, match="runner.command changed"):
        G.wrap(g, ["/py", str(tmp_path / "x.py")], tmp_path)


def test_os_sandbox_denies_a_child_process_the_network(tmp_path, listener):
    prefix, why = G.os_sandbox(refresh=True)
    if prefix is None:
        pytest.skip(f"OS network sandbox unavailable here: {why}")
    port = listener.getsockname()[1]
    child = (f"import socket\ntry:\n    socket.create_connection(('127.0.0.1', {port}), timeout=2)\n"
             "    print('CONNECTED')\nexcept OSError as e:\n    print('DENIED', type(e).__name__)\n")
    body = f"import subprocess, sys\nsubprocess.run([sys.executable, '-c', {child!r}])\n"
    script = tmp_path / "target.py"
    script.write_text(body, encoding="utf-8")
    cp = subprocess.run([*prefix, sys.executable, "-I", str(BOOT), "--mode", "os", "--", str(script)],
                        capture_output=True, text=True, timeout=60)
    assert "DENIED" in cp.stdout and "CONNECTED" not in cp.stdout, cp.stdout + cp.stderr
    assert not _accepted(listener)
