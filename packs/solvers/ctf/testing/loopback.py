"""One shared 127.0.0.1, port-0 harness for tests that start a fake service (B-153).

Build runs went red on 51 tool outputs that were nothing but a sandbox refusing a socket bind: each test
bound its own port its own way, failed with a bare PermissionError, and the gate painted it as a code
failure. Every test that needs a listener uses this instead:

    def test_client_talks_to_a_fake(loopback):
        srv = loopback.http(MyHandler)            # ThreadingHTTPServer on 127.0.0.1:<free port>, served
        url = srv.url                             # "http://127.0.0.1:<port>"
        sock = loopback.socket()                  # a bound TCP socket (call .listen() yourself)
        udp = loopback.socket("udp")
        tcp = loopback.tcp(MyStreamHandler)       # ThreadingTCPServer, served

Rules it enforces:

  * the host is always 127.0.0.1 and the port always 0 (the kernel picks a free one: no fixed port, no
    race with another test or agent on this shared machine);
  * a bind the environment refuses (EPERM / EACCES: an agent sandbox, a Seatbelt profile) raises
    `LoopbackDenied`, whose message starts with `GATE-ENV:` -- the explicit marker the gate's ENV
    classifier reads (ctf/gate/envfail.py), so the gate reports ENV, not FAIL, and never a pass;
  * every server is shut down and every socket closed at teardown, even when the test fails.

Outside pytest, `bind(kind)` and `serve_http(handler)` are the same calls without the fixture.
"""
from __future__ import annotations

import contextlib
import errno
import socket
import socketserver
import threading
from http.server import ThreadingHTTPServer

import pytest

HOST = "127.0.0.1"
ENV_MARKER = "GATE-ENV:"
_DENIED = {errno.EPERM, errno.EACCES}


class LoopbackDenied(OSError):
    """The environment refused a bind on 127.0.0.1 (a sandbox): not a defect in the code under test."""


def _denied(e: OSError, what: str) -> LoopbackDenied:
    return LoopbackDenied(e.errno, f"{ENV_MARKER} sandbox denied {what} on {HOST}:0 "
                                   f"({type(e).__name__}: [Errno {e.errno}] {e.strerror or e}); "
                                   f"run outside the sandbox, the code under test is not what failed")


def is_denied(e: BaseException) -> bool:
    return isinstance(e, OSError) and (isinstance(e, PermissionError) or e.errno in _DENIED)


def bind(kind: str = "tcp") -> socket.socket:
    """A socket bound to 127.0.0.1 on a kernel-chosen port. `kind` is "tcp" or "udp"."""
    if kind not in ("tcp", "udp"):
        raise ValueError(f"loopback kind must be 'tcp' or 'udp', got {kind!r}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM)
    try:
        s.bind((HOST, 0))
    except OSError as e:
        s.close()
        if is_denied(e):
            raise _denied(e, f"a {kind} bind") from e
        raise
    return s


class Served:
    """A socketserver running in a daemon thread. `.port`, `.url` (http), `.address`, `.close()`."""

    def __init__(self, server: socketserver.BaseServer, scheme: str):
        self.server = server
        self.address = server.server_address[:2]
        self.port = self.address[1]
        self.url = f"{scheme}://{HOST}:{self.port}"
        self._thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05},
                                        name=f"loopback-{self.port}", daemon=True)
        self._thread.start()
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=30)


def _serve(cls, handler, scheme: str) -> Served:
    try:
        srv = cls((HOST, 0), handler)
    except OSError as e:
        if is_denied(e):
            raise _denied(e, f"a {scheme} server bind") from e
        raise
    srv.daemon_threads = True
    return Served(srv, scheme)


def serve_http(handler) -> Served:
    """A ThreadingHTTPServer on 127.0.0.1:<free port> with `handler`, already serving."""
    return _serve(ThreadingHTTPServer, handler, "http")


class _TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def serve_tcp(handler) -> Served:
    """A ThreadingTCPServer on 127.0.0.1:<free port> with `handler`, already serving."""
    return _serve(_TCP, handler, "tcp")


class Loopback:
    """What the `loopback` fixture yields: every socket and server it makes is closed at teardown."""

    host = HOST

    def __init__(self):
        self._sockets: list[socket.socket] = []
        self._servers: list[Served] = []

    def socket(self, kind: str = "tcp") -> socket.socket:
        s = bind(kind)
        self._sockets.append(s)
        return s

    def http(self, handler) -> Served:
        s = serve_http(handler)
        self._servers.append(s)
        return s

    def tcp(self, handler) -> Served:
        s = serve_tcp(handler)
        self._servers.append(s)
        return s

    def close(self) -> None:
        for s in reversed(self._servers):
            with contextlib.suppress(OSError):
                s.close()
        for s in self._sockets:
            with contextlib.suppress(OSError):
                s.close()
        self._servers.clear()
        self._sockets.clear()


@pytest.fixture(name="loopback")
def loopback_fixture():
    """A Loopback harness; a sandbox-denied bind fails the test with a GATE-ENV marker (gate: ENV)."""
    lb = Loopback()
    try:
        yield lb
    finally:
        lb.close()
