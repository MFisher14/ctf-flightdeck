"""B-153: the shared 127.0.0.1 port-0 harness (ctf/testing/loopback.py). It binds loopback only, on a
kernel-chosen port, closes what it opened, and turns a sandbox-denied bind into a GATE-ENV failure the
gate reports as ENV -- never a FAIL and never a pass. Every server is a toy started by the test."""
from __future__ import annotations

import errno
import json
import socket
import subprocess
import sys
import textwrap
import urllib.request
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from ctf.gate import config, envfail
from ctf.gate.impact import Graph, Selection
from ctf.gate.runner import run_gate
from ctf.testing import loopback as lb
from gate_repo import make_repo

REPO = Path(__file__).resolve().parent.parent


class Hello(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = json.dumps({"path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _deny_bind(monkeypatch, err=errno.EPERM):
    def denied(self, addr):
        raise PermissionError(err, "Operation not permitted")
    monkeypatch.setattr(socket.socket, "bind", denied)


# ----------------------------------------------------------------------------- the harness itself

@pytest.mark.parametrize("kind,stype", [("tcp", socket.SOCK_STREAM), ("udp", socket.SOCK_DGRAM)])
def test_bind_is_loopback_on_a_kernel_chosen_port(kind, stype):
    s = lb.bind(kind)
    try:
        host, port = s.getsockname()[:2]
        assert host == "127.0.0.1" and port > 0 and s.type == stype
    finally:
        s.close()
    with pytest.raises(ValueError):
        lb.bind("sctp")


def test_two_binds_never_share_a_port():
    a, b = lb.bind(), lb.bind()
    try:
        assert a.getsockname()[1] != b.getsockname()[1]
    finally:
        a.close()
        b.close()


def test_the_fixture_serves_http_and_closes_it_at_teardown(loopback):
    srv = loopback.http(Hello)
    assert srv.url == f"http://127.0.0.1:{srv.port}"
    with urllib.request.urlopen(srv.url + "/ping", timeout=30) as r:
        assert json.loads(r.read()) == {"path": "/ping"}
    loopback.close()
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", srv.port), timeout=5).close()


def test_the_fixture_closes_raw_sockets(loopback):
    s = loopback.socket()
    s.listen(1)
    port = s.getsockname()[1]
    loopback.close()
    assert s.fileno() == -1
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=5).close()


LEAKY = """\
import socket, urllib.request
from http.server import BaseHTTPRequestHandler

class Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()
    def log_message(self, *a):
        pass

OPENED = {}

def test_a_opens_and_leaves_everything_open(loopback):
    srv = loopback.http(Hello)
    raw = loopback.socket()
    raw.listen(1)
    tcp = loopback.tcp(Hello)
    OPENED.update(http=srv.port, raw=raw.getsockname()[1], tcp=tcp.port, sock=raw)
    with urllib.request.urlopen(srv.url, timeout=30) as r:
        assert r.status == 204
    socket.create_connection(("127.0.0.1", OPENED["raw"]), timeout=30).close()   # open while the test runs

def test_b_after_teardown_nothing_is_listening():
    assert OPENED, "test_a did not run first"
    assert OPENED["sock"].fileno() == -1, "the raw socket survived the fixture's teardown"
    for name in ("http", "raw", "tcp"):
        try:
            socket.create_connection(("127.0.0.1", OPENED[name]), timeout=5).close()
        except OSError:
            continue
        raise AssertionError(f"the {name} listener on port {OPENED[name]} survived the fixture's teardown")
"""


def test_the_fixture_itself_closes_what_a_test_leaves_open(tmp_path):
    """The test never calls close(): the fixture's own teardown must shut every server and socket, so
    the next test of the same session finds nothing listening (and no thread still serving)."""
    (tmp_path / "conftest.py").write_text(f"import sys\nsys.path.insert(0, {str(REPO)!r})\n"
                                          f"pytest_plugins = ('ctf.testing.loopback',)\n", encoding="utf-8")
    (tmp_path / "test_leaky.py").write_text(LEAKY, encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "no:xdist",
                        "test_leaky.py"], cwd=tmp_path, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "2 passed" in r.stdout, r.stdout


def test_a_wrapped_oserror_is_classified_by_its_errno():
    """A library may wrap a refused bind in its own OSError subclass (not a PermissionError): the errno
    decides. EPERM and EACCES are the sandbox; anything else is not."""
    class Wrapped(OSError):
        pass
    assert not isinstance(Wrapped(errno.EACCES, "x"), PermissionError)
    assert lb.is_denied(Wrapped(errno.EACCES, "Permission denied"))
    assert lb.is_denied(Wrapped(errno.EPERM, "Operation not permitted"))
    assert not lb.is_denied(Wrapped(errno.EADDRINUSE, "Address already in use"))
    assert not lb.is_denied(ValueError("not an OSError"))


@pytest.mark.parametrize("err", [errno.EPERM, errno.EACCES])
def test_a_denied_bind_raises_loopback_denied_with_the_env_marker(monkeypatch, err):
    _deny_bind(monkeypatch, err)
    with pytest.raises(lb.LoopbackDenied) as ei:
        lb.bind()
    msg = str(ei.value)
    assert "GATE-ENV:" in msg and "127.0.0.1" in msg
    verdict = envfail.classify([f"{type(ei.value).__name__}: {msg}"])
    assert verdict and verdict.is_env


def test_a_denied_server_bind_is_env_too(monkeypatch):
    _deny_bind(monkeypatch)
    with pytest.raises(lb.LoopbackDenied, match="GATE-ENV: sandbox denied a http server bind"):
        lb.serve_http(Hello)


def test_another_bind_error_is_not_dressed_up_as_env(monkeypatch):
    def busy(self, addr):
        raise OSError(errno.EADDRINUSE, "Address already in use")
    monkeypatch.setattr(socket.socket, "bind", busy)
    with pytest.raises(OSError) as ei:
        lb.bind()
    assert not isinstance(ei.value, lb.LoopbackDenied) and "GATE-ENV" not in str(ei.value)


# ------------------------------------------------------------------------ through the gate (ENV)

CONFTEST = """\
import os, sys
sys.path.insert(0, os.environ["B153_REPO"])
pytest_plugins = ("ctf.testing.loopback",)
"""

DENY = """\
import socket, pytest

@pytest.fixture(autouse=True)
def _sandbox(monkeypatch):
    def denied(self, addr):
        raise PermissionError(1, "Operation not permitted")
    monkeypatch.setattr(socket.socket, "bind", denied)
"""


def _run(tmp_path, files):
    repo = make_repo(tmp_path / "repo", files)
    cfg = config.load(repo, repo / "gate.toml")
    state = tmp_path / "state"
    g = Graph(repo, cfg, state / "co")
    tests = sorted(t for t in files if t.startswith("tests/test_"))
    rep = run_gate(g, Selection("full", tests, ["test"], {}), state=state, out_dir=tmp_path / "out", warm=False,
                   emit=lambda s: None, load_fn=lambda: 0.0, cpus=4)
    return {r.test: r for r in rep.rows}, rep


def test_a_sandbox_denied_fixture_bind_is_env_not_fail_in_the_gate(tmp_path, monkeypatch):
    monkeypatch.setenv("B153_REPO", str(REPO))
    rows, rep = _run(tmp_path, {
        "conftest.py": CONFTEST,
        "tests/conftest.py": DENY,
        "tests/test_server.py": "def test_serves(loopback):\n    loopback.socket().listen(1)\n",
    })
    row = rows["tests/test_server.py"]
    assert row.status == "ENV", row
    assert rep.ok                                        # ENV never turns the gate red ...
    assert row.passed == 0                               # ... and is not a pass either


def test_a_real_failure_beside_the_harness_stays_red(tmp_path, monkeypatch):
    monkeypatch.setenv("B153_REPO", str(REPO))
    rows, rep = _run(tmp_path, {
        "conftest.py": CONFTEST,
        "tests/test_server.py": "def test_serves(loopback):\n    s = loopback.socket()\n    assert s is None\n",
    })
    assert rows["tests/test_server.py"].status == "FAIL" and not rep.ok


@pytest.mark.needs_tool("sandbox-exec")
def test_a_real_seatbelt_bind_denial_is_reported_with_the_marker(tmp_path):
    """Under a Seatbelt profile that denies network-bind, the harness raises LoopbackDenied with the
    marker. Seatbelt does not nest: inside the suite's own sandbox-exec this is reported not run."""
    prof = tmp_path / "nobind.sb"
    prof.write_text("(version 1)\n(allow default)\n(deny network-bind)\n", encoding="utf-8")
    probe = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(REPO)!r})
        from ctf.testing import loopback
        try:
            loopback.bind().close()
            print("BOUND")
        except loopback.LoopbackDenied as e:
            print("DENIED", e)
        """)
    r = subprocess.run(["sandbox-exec", "-f", str(prof), sys.executable, "-c", probe],
                       capture_output=True, text=True, timeout=120)
    if "sandbox_apply" in r.stderr and "Operation not permitted" in r.stderr:
        pytest.skip("already inside a sandbox-exec sandbox (Seatbelt does not nest): run outside it to check")
    assert r.returncode == 0, r.stderr
    assert r.stdout.startswith("DENIED") and "GATE-ENV:" in r.stdout
