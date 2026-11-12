"""A fake webhook receiver, for tests: real HTTP on 127.0.0.1 in a background thread, so the
notifier is tested end to end with nothing mocked (httpx, headers, JSON, status codes, time
limits). Every request is recorded: its method, its path (with the query: where a webhook's
token usually is), its headers and its JSON body.

It answers 204 unless told otherwise: `status` is the answer to every request (500: a
receiver that fails; 302 with `location`: one that redirects), and `hang` makes it hold every
request until the test lets go (release()) or the server stops: a receiver that never answers.
"""

from __future__ import annotations

import json
import socket
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STOP_WAIT = 5.0
SECRET_PATH = "/hooks/T0PSECRET/webhook-token-of-the-test-7f3a91c2"  # synthetic: what a webhook's URL holds


class FakeWebhook:
    """A receiver on 127.0.0.1 (a free port, known before it starts). Entering the context
    starts serving; leaving it lets held requests go, hangs up and stops the server."""

    def __init__(self, *, status: int = 204, location: str = "", hang: bool = False, path: str = SECRET_PATH) -> None:
        self.status = status
        self.location = location
        self.hang = hang
        self.requests: list[dict] = []  # each {"method", "path", "headers" (lower-case names), "json"}
        self._lock = threading.Lock()
        self._let_go = threading.Event()
        self._httpd = _Server(self)
        self.port = self._httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}{path}"
        self._thread: threading.Thread | None = None

    def __enter__(self) -> FakeWebhook:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, name="fake-webhook", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.release()
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
        self._httpd.close(wait=STOP_WAIT)

    def release(self) -> None:
        """Let every held request go (each then gets its answer)."""
        self._let_go.set()

    def bodies(self) -> list[object]:
        """The JSON body of every POST, in the order they arrived."""
        with self._lock:
            return [r["json"] for r in self.requests if r["method"] == "POST"]

    def wait_for(self, count: int, seconds: float = 10.0) -> list[object]:
        """The bodies once `count` POSTs have arrived (AssertionError if they do not)."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            bodies = self.bodies()
            if len(bodies) >= count:
                return bodies
            time.sleep(0.02)
        raise AssertionError(f"the webhook got {len(self.bodies())} message(s) within {seconds} s, not {count}: {self.bodies()}")

    def _record(self, method: str, path: str, headers: dict[str, str], body: object) -> None:
        with self._lock:
            self.requests.append({"method": method, "path": path, "headers": headers, "json": body})
        if self.hang:
            self._let_go.wait()


class _Server(ThreadingHTTPServer):
    """Tracks its connections and request threads, so stopping can hang up on clients and
    wait for the threads (the pattern of fake_ctfd.py and fake_model.py)."""

    def __init__(self, fake: FakeWebhook) -> None:
        self.fake = fake
        self._open: set[socket.socket] = set()
        self._workers: list[threading.Thread] = []
        self._track = threading.Lock()
        super().__init__(("127.0.0.1", 0), _Handler)

    def server_bind(self) -> None:
        socketserver.TCPServer.server_bind(self)  # no lookup of the host's full name: it can stall
        self.server_name, self.server_port = self.server_address[:2]

    def process_request(self, request, client_address) -> None:
        worker = threading.Thread(
            target=self.process_request_thread, args=(request, client_address), name="fake-webhook-request", daemon=True
        )
        with self._track:
            self._open.add(request)
            self._workers = [w for w in self._workers if w.is_alive()]
            self._workers.append(worker)
        worker.start()

    def shutdown_request(self, request) -> None:
        with self._track:
            self._open.discard(request)
        super().shutdown_request(request)

    def close(self, wait: float) -> None:
        with self._track:
            still_open, workers = list(self._open), list(self._workers)
        for sock in still_open:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        deadline = time.monotonic() + wait
        for worker in workers:
            worker.join(max(0.0, deadline - time.monotonic()))
        self.server_close()

    def handle_error(self, request, client_address) -> None:
        pass  # a client that hung up or timed out: what the hang tests set up


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30
    server: _Server

    def do_POST(self) -> None:
        self._answer("POST")

    def do_GET(self) -> None:
        self._answer("GET")

    def _answer(self, method: str) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b""
        try:
            body = json.loads(raw) if raw else None
        except ValueError:
            body = None
        fake = self.server.fake
        fake._record(method, self.path, {name.lower(): value for name, value in self.headers.items()}, body)
        try:
            self.send_response(fake.status)
            if fake.location:
                self.send_header("Location", fake.location)
            self.send_header("Content-Length", "0")
            self.end_headers()
        except OSError:
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        pass
