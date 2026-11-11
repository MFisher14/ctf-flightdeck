"""A fake CTFd, for tests: the parts of CTFd's REST API (v1) that flightdeck uses.

It answers real HTTP on 127.0.0.1 in a background thread, so the CTFd adapter is tested
end to end with nothing mocked: httpx, headers, JSON, status codes, retries and downloads all
run for real. The challenges are invented. Where flightdeck depends on CTFd's behaviour, the
fake behaves as CTFd 3.x does:

- the token is read from `Authorization: Token <token>` only when the request says
  `Content-Type: application/json`, GETs included (CTFd's request.is_json); a wrong token
  is a 401, a request without a usable token is anonymous and gets a 403;
- GET /api/v1/challenges: the list, in CTFd's order (value, then id); in pages with
  meta.pagination when `page_size` is set (CTFd itself does not page it). A challenge locked
  behind another is listed as CTFd lists it: type "hidden", name "???", value 0;
- GET /api/v1/challenges/<id>: the details, whose "files" are URLs
  /files/<dir>/<name>?token=<file token>, as CTFd's are;
- GET /files/<dir>/<name>: the file (the file token or the API token lets it through);
- POST /api/v1/challenges/attempt: a status in the data whatever the HTTP status: correct,
  incorrect (with the tries left when max_attempts is set), already_solved (for any flag,
  once solved), partial, paused (403) and, out of tries, incorrect with 403 (both of the
  last two sent before the flag is looked at);
- GET /api/v1/teams/me/solves (404 in users mode, 403 when `no_team`) and
  GET /api/v1/users/me/solves.

Tests script replies ahead of these for one method and path (errors, 429 with Retry-After,
redirects, bodies that are not JSON, a hang-up), and read back every request in `requests`.

With `tls` (from make_tls(), which needs the openssl command) it answers https instead, with
a certificate for 127.0.0.1 from a throwaway authority: a client trusts it through
SSL_CERT_FILE. It stands for a CTFd on https, or for the object storage a CTFd sends file
downloads to.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

TOKEN = "fake-ctfd-api-token-for-tests-7c1e"  # synthetic; no real CTFd token has this shape
FLAG_FORMAT = r"test\{\w+\}"  # the flags of the invented challenges below
STOP_WAIT = 5.0  # seconds leaving the context waits for request threads in all


@dataclass
class FakeChallenge:
    """An invented challenge. `files` are its file names and contents. `file_urls`, when set,
    is sent as "files" instead of the real URLs (to test hostile ones)."""

    id: int
    name: str
    category: str = "misc"
    value: int = 100
    solves: int | None = 0
    description: str = ""
    connection_info: str | None = None
    files: dict[str, bytes] = field(default_factory=dict)
    flag: str = "test{right}"
    partial: tuple[str, ...] = ()  # submissions answered "partial"
    type: str = "standard"  # "hidden": locked behind a prerequisite
    max_attempts: int = 0
    file_urls: list[str] | None = None


def sample() -> list[FakeChallenge]:
    """Four invented challenges: files, a web instance, an nc service, CTFd's category names."""
    return [
        FakeChallenge(1, "Warmup", category="Misc", value=50, solves=120, description="Say hello.",
                      files={"hello.txt": b"hello\n"}, flag="test{hello}"),
        FakeChallenge(2, "Baby RSA", category="Crypto", value=100, solves=40, description="e is small.",
                      files={"out.txt": b"n = 3233\ne = 3\nc = 2201\n"}, flag="test{rsa}"),
        FakeChallenge(3, "Login Portal", category="Web", value=200, solves=10, description="Log in as admin.",
                      connection_info="http://web.example.org:8080/login", flag="test{web}"),
        FakeChallenge(4, "Echo Service", category="Pwn", value=300, solves=2, description="It echoes.",
                      connection_info="nc pwn.example.org 1337", files={"echo.bin": b"not a real program\n"},
                      flag="test{pwn}"),
    ]


@dataclass
class Reply:
    """One scripted answer. A dict or list body goes out as JSON, str as text, bytes as is."""

    status: int = 200
    body: dict | list | str | bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)
    hang_up: bool = False  # close the connection without answering
    until_close: bool = False  # no Content-Length: the body ends when the connection closes


HANG_UP = Reply(hang_up=True)


@dataclass
class Request:
    method: str
    path: str  # as sent, with its query
    headers: dict[str, str]  # lower-case names
    body: bytes
    at: float  # time.monotonic() when it arrived

    @property
    def route(self) -> str:
        return urlsplit(self.path).path

    @property
    def json(self) -> object:
        try:
            return json.loads(self.body) if self.body else None
        except ValueError:
            return None


@dataclass(frozen=True)
class TLS:
    """A throwaway certificate authority, and a server certificate for 127.0.0.1 it signed."""

    ca: Path  # what a client must trust: point SSL_CERT_FILE at it
    cert: Path
    key: Path


_OPENSSL_CONFIG = """\
[req]
distinguished_name = dn
[dn]
[ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
[server]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def make_tls(folder: Path) -> TLS:
    """Make the certificates in `folder` with the openssl command (OpenSSL or LibreSSL). Raises
    FileNotFoundError when openssl is not installed, CalledProcessError when it fails."""
    openssl = shutil.which("openssl")
    if openssl is None:
        raise FileNotFoundError("openssl")
    (folder / "openssl.cnf").write_text(_OPENSSL_CONFIG)
    for args in (
        ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2",
         "-subj", "/CN=ctf-flightdeck test CA", "-config", "openssl.cnf", "-extensions", "ca"],
        ["req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.csr",
         "-subj", "/CN=127.0.0.1", "-config", "openssl.cnf"],
        ["x509", "-req", "-in", "server.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "1",
         "-out", "server.pem", "-days", "2", "-extfile", "openssl.cnf", "-extensions", "server"],
    ):
        subprocess.run([openssl, *args], cwd=folder, check=True, capture_output=True, timeout=120)
    return TLS(folder / "ca.pem", folder / "server.pem", folder / "server.key")


def not_found() -> Reply:
    return Reply(404, {"message": "The requested URL was not found on the server."})


def forbidden(message: str = "You don't have the permission to access the requested resource.") -> Reply:
    return Reply(403, {"message": message})


class FakeCTFd:
    """A fake CTFd on 127.0.0.1 (a free port, known before it starts). Entering the context
    starts serving; leaving it hangs up on clients still connected and stops the server."""

    def __init__(
        self,
        challenges: tuple[FakeChallenge, ...] | list[FakeChallenge] = (),
        *,
        token: str = TOKEN,
        team_mode: bool = True,
        page_size: int | None = None,
        name: str = "Fake CTF",
        tls: TLS | None = None,
    ) -> None:
        self.challenges: dict[int, FakeChallenge] = {c.id: c for c in challenges}
        self.token = token
        self.team_mode = team_mode
        self.page_size = page_size
        self.name = name
        self.paused = False
        self.no_team = False  # team mode, but this user has not joined a team yet
        self.solved: set[int] = set()  # solved by this account: the team in team mode
        self.user_solved: set[int] | None = None  # this user's own solves in team mode (None: the same)
        self.fails: dict[int, int] = {}
        self.requests: list[Request] = []
        self._scripted: dict[tuple[str, str], deque[Reply]] = {}
        self._lock = threading.Lock()
        self._httpd = _Server(self, tls)
        self.base_url = f"{'https' if tls else 'http'}://127.0.0.1:{self._httpd.server_address[1]}"
        self._thread: threading.Thread | None = None

    def __enter__(self) -> FakeCTFd:
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.05}, name="fake-ctfd", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join()
        self._httpd.close(wait=STOP_WAIT)

    # ------------------------------------------------------------------ for tests

    def add(self, *challenges: FakeChallenge) -> None:
        """New challenges on the board (a wave)."""
        with self._lock:
            for challenge in challenges:
                self.challenges[challenge.id] = challenge

    def script(self, method: str, path: str, *replies: Reply) -> None:
        """The next requests to `method path` (the path without its query) get these replies
        first, in order; after them, the fake answers as CTFd would."""
        with self._lock:
            self._scripted.setdefault((method, path), deque()).extend(replies)

    def to(self, path: str, method: str | None = None) -> list[Request]:
        """The requests made to `path` (without the query), in order."""
        with self._lock:
            return [r for r in self.requests if r.route == path and (method is None or r.method == method)]

    def file_url(self, challenge_id: int, name: str) -> str:
        """The URL CTFd would list for a challenge's file (with its file token)."""
        folder = _folder(challenge_id, name)
        return f"/files/{folder}/{quote(name, safe='')}?token={_file_token(folder)}"

    def listing(self) -> dict:
        """The answer CTFd would give GET /api/v1/challenges now, unpaged (to script it ahead of failures)."""
        with self._lock:
            return {"success": True, "data": self._entries()}

    # ------------------------------------------------------------------ answering

    def _answer(self, method: str, path: str, headers: dict[str, str], body: bytes) -> Reply:
        with self._lock:
            self.requests.append(Request(method, path, headers, body, time.monotonic()))
            parts = urlsplit(path)
            queued = self._scripted.get((method, parts.path))
            if queued:
                return queued.popleft()
            try:
                return self._route(method, parts.path, parse_qs(parts.query), headers, body)
            except Exception as exc:  # a bug in the fake: say so instead of hanging the client
                return Reply(500, {"message": f"fake CTFd: {type(exc).__name__}: {exc}"})

    def _route(self, method: str, route: str, query: dict, headers: dict[str, str], body: bytes) -> Reply:
        if route.startswith("/files/") and method == "GET":
            return self._file(route, query, headers)
        if not route.startswith("/api/v1/"):
            return not_found()
        refused = self._refused(headers)
        if refused is not None:
            return refused
        if method == "GET" and route == "/api/v1/challenges":
            return self._list(query)
        found = re.fullmatch(r"/api/v1/challenges/(\d+)", route)
        if method == "GET" and found:
            return self._detail(int(found.group(1)))
        if method == "POST" and route == "/api/v1/challenges/attempt":
            return self._attempt(body)
        if method == "GET" and route == "/api/v1/teams/me/solves":
            if not self.team_mode:
                return not_found()  # CTFd's require_team_mode
            if self.no_team:
                return forbidden()  # CTFd's require_team
            return self._solves(self.solved)
        if method == "GET" and route == "/api/v1/users/me/solves":
            mine = self.user_solved if self.team_mode and self.user_solved is not None else self.solved
            return self._solves(set() if self.no_team else mine)
        return not_found()

    def _refused(self, headers: dict[str, str]) -> Reply | None:
        """CTFd's token check: only a JSON request's token is read."""
        is_json = headers.get("content-type", "").split(";")[0].strip().lower() == "application/json"
        given = headers.get("authorization")
        if given is None or not is_json:
            return forbidden()  # anonymous
        _scheme, _, value = given.partition(" ")
        if value != self.token:
            return Reply(401, {"message": "Your access token is invalid"})
        return None

    def _entry(self, c: FakeChallenge) -> dict:
        if c.type == "hidden":
            return {
                "id": c.id, "type": "hidden", "name": "???", "value": 0, "solves": None,
                "solved_by_me": False, "category": "???", "tags": [], "template": "", "script": "",
            }
        return {
            "id": c.id, "type": c.type, "name": c.name, "value": c.value, "solves": c.solves,
            "solved_by_me": c.id in self.solved, "category": c.category, "tags": [],
            "template": "/plugins/challenges/assets/view.html", "script": "/plugins/challenges/assets/view.js",
        }

    def _entries(self) -> list[dict]:
        return [self._entry(c) for c in sorted(self.challenges.values(), key=lambda c: (c.value, c.id))]

    def _list(self, query: dict) -> Reply:
        entries = self._entries()
        if self.page_size is None:
            return Reply(200, {"success": True, "data": entries})
        page = int(query.get("page", ["1"])[0])
        pages = max(1, math.ceil(len(entries) / self.page_size))
        chunk = entries[(page - 1) * self.page_size : page * self.page_size]
        meta = {
            "pagination": {
                "page": page,
                "next": page + 1 if page < pages else None,
                "prev": page - 1 if page > 1 else None,
                "pages": pages,
                "per_page": self.page_size,
                "total": len(entries),
            }
        }
        return Reply(200, {"success": True, "data": chunk, "meta": meta})

    def _detail(self, challenge_id: int) -> Reply:
        c = self.challenges.get(challenge_id)
        if c is None:
            return not_found()
        if c.type == "hidden":
            return forbidden()
        files = c.file_urls if c.file_urls is not None else [self.file_url(c.id, name) for name in c.files]
        data = {
            "id": c.id, "name": c.name, "value": c.value, "description": c.description, "attribution": None,
            "connection_info": c.connection_info, "next_id": None, "category": c.category, "state": "visible",
            "max_attempts": c.max_attempts, "type": c.type,
            "type_data": {"id": c.type, "name": c.type, "templates": {}, "scripts": {}},
            "solves": c.solves, "solved_by_me": c.id in self.solved, "attempts": self.fails.get(c.id, 0),
            "files": files, "tags": [], "hints": [], "view": "<div class='challenge'></div>",
        }
        return Reply(200, {"success": True, "data": data})

    def _file(self, route: str, query: dict, headers: dict[str, str]) -> Reply:
        found = re.fullmatch(r"/files/([0-9a-f]{16})/([^/]+)", route)
        if not found:
            return not_found()
        folder = found.group(1)
        token_ok = query.get("token", [""])[0] == _file_token(folder)
        if not token_ok and self._refused(headers) is not None:
            return forbidden()
        for c in self.challenges.values():
            for name, content in c.files.items():
                if _folder(c.id, name) == folder:
                    return Reply(
                        200,
                        content,
                        {"Content-Type": "application/octet-stream", "Content-Disposition": f"attachment; filename={quote(name)}"},
                    )
        return not_found()

    def _attempt(self, body: bytes) -> Reply:
        if self.paused:
            return Reply(403, {"success": True, "data": {"status": "paused", "message": f"{self.name} is paused"}})
        try:
            payload = json.loads(body)
        except ValueError:
            return Reply(400, {"success": False, "errors": {"submission": ["Invalid JSON"]}})
        number = payload.get("challenge_id") if isinstance(payload, dict) else None
        submission = payload.get("submission") if isinstance(payload, dict) else None
        c = self.challenges.get(number) if isinstance(number, int) else None
        if c is None or c.type == "hidden":
            return not_found()
        if number in self.solved:  # answered before the flag is looked at, as CTFd does
            return Reply(200, {"success": True, "data": {"status": "already_solved", "message": "You already solved this"}})
        fails = self.fails.get(number, 0)
        if c.max_attempts and fails >= c.max_attempts:
            return Reply(403, {"success": True, "data": {"status": "incorrect", "message": "You have 0 tries remaining"}})
        if submission == c.flag:
            self.solved.add(number)
            return Reply(200, {"success": True, "data": {"status": "correct", "message": "Correct"}})
        if submission in c.partial:
            return Reply(200, {"success": True, "data": {"status": "partial", "message": "Partially correct"}})
        self.fails[number] = fails + 1
        message = "Incorrect"
        if c.max_attempts:
            left = c.max_attempts - fails - 1
            message = f"Incorrect. You have {left} {'try' if left == 1 else 'tries'} remaining."
        return Reply(200, {"success": True, "data": {"status": "incorrect", "message": message}})

    def _solves(self, ids: set[int]) -> Reply:
        data = []
        for n, number in enumerate(sorted(ids), 1):
            c = self.challenges.get(number)
            data.append(
                {
                    "challenge_id": number,
                    "challenge": {"id": number, "name": c.name if c else "?", "value": c.value if c else 0,
                                  "category": c.category if c else ""},
                    "user": 1, "team": 1 if self.team_mode else None,
                    "date": "2026-01-01T00:00:00.000000Z", "type": "correct", "id": n,
                }
            )
        return Reply(200, {"success": True, "data": data, "meta": {"count": len(data)}})


def _folder(challenge_id: int, name: str) -> str:
    return hashlib.sha256(f"{challenge_id}/{name}".encode()).hexdigest()[:16]


def _file_token(folder: str) -> str:
    return f"ft-{folder[:8]}"


class _Server(ThreadingHTTPServer):
    """The HTTP server. It tracks its connections and request threads, so stopping can hang
    up on clients and wait for the threads, and `requests` is final once it has."""

    def __init__(self, fake: FakeCTFd, tls: TLS | None) -> None:
        self.fake = fake
        self._open: set[socket.socket] = set()
        self._workers: list[threading.Thread] = []
        self._track = threading.Lock()
        self._tls = None
        if tls is not None:
            self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._tls.load_cert_chain(tls.cert, tls.key)
        super().__init__(("127.0.0.1", 0), _Handler)

    def server_bind(self) -> None:
        # HTTPServer.server_bind looks up the host's full name, which can stall on some networks.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]

    def finish_request(self, request, client_address) -> None:
        if self._tls is None:
            super().finish_request(request, client_address)
            return
        request.settimeout(10)
        try:
            secure = self._tls.wrap_socket(request, server_side=True)  # the handshake, in this request's thread
        except (ssl.SSLError, OSError):
            return  # a client that does not speak TLS (plain http sent here), or hung up
        with self._track:
            self._open.discard(request)
            self._open.add(secure)
        try:
            self.RequestHandlerClass(secure, client_address, self)
        finally:
            with self._track:
                self._open.discard(secure)
            try:
                secure.close()
            except OSError:
                pass

    def process_request(self, request, client_address) -> None:
        worker = threading.Thread(
            target=self.process_request_thread, args=(request, client_address), name="fake-ctfd-request", daemon=True
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
        if isinstance(sys.exc_info()[1], (ConnectionError, TimeoutError)):
            return  # a client that hung up
        super().handle_error(request, client_address)


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive, as CTFd behind a web server does
    timeout = 30
    server: _Server

    def do_GET(self) -> None:
        self._send(self.server.fake._answer("GET", self.path, self._headers(), self._body()))

    def do_POST(self) -> None:
        self._send(self.server.fake._answer("POST", self.path, self._headers(), self._body()))

    def _headers(self) -> dict[str, str]:
        return {name.lower(): value for name, value in self.headers.items()}

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length > 0 else b""

    def _send(self, reply: Reply) -> None:
        if reply.hang_up:
            self.close_connection = True
            return
        if isinstance(reply.body, (dict, list)):
            data, kind = json.dumps(reply.body).encode(), "application/json"
        elif isinstance(reply.body, str):
            data, kind = reply.body.encode(), "text/html; charset=utf-8"
        elif isinstance(reply.body, bytes):
            data, kind = reply.body, "application/octet-stream"
        else:
            data, kind = b"", None
        headers = {"Content-Type": kind} if kind else {}
        headers.update(reply.headers)
        if reply.until_close:
            headers["Connection"] = "close"
        try:
            self.send_response(reply.status)
            for name, value in headers.items():
                self.send_header(name, value)
            if not reply.until_close and not any(name.lower() == "content-length" for name in headers):
                self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            self.close_connection = True
        if reply.until_close:
            self.close_connection = True

    def log_message(self, format: str, *args: object) -> None:
        pass
