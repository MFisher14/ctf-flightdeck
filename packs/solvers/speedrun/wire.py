"""Fast wire: pre-opened TCP+TLS connections, requests fired from prebuilt bytes, headers seen early.

Carried from Huntress speedrun/wire.py (SPEC.md section 5.4) per the hand-merge decision: the
transport is kept (Conn, Pool, Req: connect + TLS before the clock, TCP_NODELAY, 1 MB buffers, a
pre-started worker per connection, an on_hdr hook that runs the moment the response headers are
parsed, streamed on_chunk reads), and the Game Master binding is dropped (its tools/gm.py start and
retry body builder, the CTF_PLATFORM_URL target rule and the ~/.huntress_gm token reader). On top of
the transport sits a platform-neutral fast CTFd client for the wave-open race:

    target(url)                         -> Target   (https anywhere; plain http only on loopback)
    Headers(tgt, token, scheme)         prebuilt header bytes; the Authorization line lives only here
    Conn(tgt).open() / Pool(tgt, n).open()   connections opened in parallel before the clock (cap 3 s)
    conn.fire(data, what, on_hdr=...)   -> Req (t_sent, t_hdr, t_done, status, headers, body, error)
    FastCTFd(base_url, token).open()    list_challenges, challenge, download_many, submit
    FastCTFd.from_config(ctf.config.load())

Reads (list, detail, file downloads) go out in parallel on the pre-opened connections. Submits are
serial and spaced by submit_interval_s (CSCTF rate-limited parallel submits for about 15 minutes);
submit() is the raw call, like ctf.client.CTFd.submit: routine play goes through
ctf.submit.guarded_submit. Paid hint paths (/unlocks, /hints/<id>) are refused, and a file URL on
another host than the target is refused (the Authorization header never leaves for another host).

Scope (R-13): this is a platform client, so it contacts only the event platform. FastCTFd(),
Pool.open() and Conn.open() pass the target through ctf.scope.check_platform_url first: a host and
port that are not the current event profile's platform.base_url (or $CTF_PLATFORM_URL) raise
ctf.scope.OutOfScope before any socket is opened. A Pool checks once and hands its Conns the result,
so a pool of N connections reads the profile once, not N times. A loopback fixture server is a platform only when
CTF_PLATFORM_URL (or a pinned profile) names it.

The token is held only in the prebuilt header bytes; it is never printed, logged, put in argv or in
an error message, and neither is a file URL's query (CTFd file tokens).
"""
from __future__ import annotations

import gzip
import http.client
import json
import queue
import re
import socket
import ssl
import threading
import time
import zlib
from dataclasses import dataclass
from urllib.parse import urlsplit

from ctf import scope

USER_AGENT = "ctf-tools-wire/1"
BUF = 1 << 20
LOOPBACK = ("127.0.0.1", "localhost", "::1")

try:
    import certifi
    _CAFILE = certifi.where()
except Exception:  # pragma: no cover - the .venv has it; the system store is used otherwise
    _CAFILE = None


def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=_CAFILE)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


SSL_CONTEXT = _ssl_context()


class WireError(Exception):
    """A usage problem found before any socket (bad URL, bad token, bad path, off-host URL)."""


@dataclass(frozen=True)
class Target:
    base: str        # scheme://host[:port]/prefix/ as given (normalized)
    host: str
    port: int
    tls: bool
    fake: bool       # a loopback test server (plain http)
    prefix: str = ""  # a path the platform is mounted under ("" or "/ctf")


def target(url: str) -> Target:
    """The platform to talk to. https on any host; plain http only on a loopback address (a local
    fixture server). No user info, query or fragment."""
    if not isinstance(url, str) or not url.strip():
        raise WireError("no platform URL")
    try:
        u = urlsplit(url.strip())
        port = u.port
    except ValueError as e:
        raise WireError(f"bad platform URL: {e}") from None
    host = (u.hostname or "").lower()
    if u.scheme not in ("https", "http") or not host:
        raise WireError(f"platform URL must be https://<host>/ (it is {url!r})")
    if u.username or u.password or u.query or u.fragment:
        raise WireError("platform URL must not carry user info, a query or a fragment")
    if u.scheme == "http" and host not in LOOPBACK:
        raise WireError(f"plain http is allowed only on loopback (it is {host}); use https")
    tls = u.scheme == "https"
    port = port or (443 if tls else 80)
    prefix = u.path.rstrip("/")
    _check_path(prefix or "/")
    default = (tls and port == 443) or (not tls and port == 80)
    hostport = host if default else f"{host}:{port}"
    if ":" in host:
        hostport = f"[{host}]" if default else f"[{host}]:{port}"
    return Target(f"{u.scheme}://{hostport}{prefix}/", host, port, tls, not tls, prefix)


_TOKEN_BAD = re.compile(r"[\x00-\x20\x7f]")
_PATH_BAD = re.compile(r"[\x00-\x20\x7f]")


def _check_token(token: str) -> str:
    if not isinstance(token, str) or not token:
        raise WireError("empty token")
    if _TOKEN_BAD.search(token):
        raise WireError("the token holds a space, a line break or a control character (its value is not shown)")
    if not token.isascii():
        raise WireError("the token holds a non-ASCII character (its value is not shown)")
    return token


def _check_path(path: str) -> str:
    """A request target: starts with '/', ASCII, no space or control character (no header injection)."""
    if not isinstance(path, str) or not path.startswith("/") or not path.isascii() or _PATH_BAD.search(path):
        raise WireError(f"bad request path {_redact(path)!r}: it must start with '/' and be ASCII without spaces")
    return path


def _redact(path) -> str:
    """A path as an error or log line may show it: without its query (a CTFd file token lives there)."""
    return str(path).split("?", 1)[0]


def check_platform(tgt: Target) -> Target:
    """The scope guard of every connection: `tgt` must be the event platform (ctf.scope). Raises
    ctf.scope.OutOfScope otherwise; opens nothing."""
    scope.check_platform_url(tgt.base, what=f"fast wire target {tgt.base}")
    return tgt


class Headers:
    """Prebuilt header bytes for one target. The Authorization line lives only in here."""

    def __init__(self, tgt: Target, token: str | None = None, scheme: str = "Token",
                 accept: str = "application/json", user_agent: str = USER_AGENT):
        host = tgt.base.split("://", 1)[1].split("/", 1)[0]
        for name, value in (("scheme", scheme), ("accept", accept), ("user_agent", user_agent)):
            if not isinstance(value, str) or not value.isascii() or re.search(r"[\x00-\x1f\x7f]", value):
                raise WireError(f"bad header value for {name}")
        common = (f"Host: {host}\r\nUser-Agent: {user_agent}\r\nAccept: {accept}\r\n"
                  f"Accept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n").encode()
        if token is not None:
            common += f"Authorization: {scheme} ".encode() + _check_token(token).encode("ascii") + b"\r\n"
        self._common = common
        self.auth = token is not None

    def __repr__(self):
        return f"Headers(auth={self.auth})"   # never the bytes

    def get(self, path: str) -> bytes:
        return b"GET " + _check_path(path).encode("ascii") + b" HTTP/1.1\r\n" + self._common + b"\r\n"

    def post(self, path: str, body: bytes) -> bytes:
        return (b"POST " + _check_path(path).encode("ascii") + b" HTTP/1.1\r\n" + self._common
                + b"Content-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def json_body(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Req:
    """One request on one connection, with its times (time.perf_counter values)."""

    __slots__ = ("what", "t_fire", "t_sent", "t_hdr", "t_done", "status", "headers", "body", "error",
                 "hdr", "done", "nbytes", "on_hdr", "on_chunk", "hook_error")

    def __init__(self, what: str):
        self.what = what
        self.t_fire = time.perf_counter()
        self.t_sent = self.t_hdr = self.t_done = None
        self.status = None
        self.headers = {}
        self.body = b""
        self.error = None
        self.nbytes = 0
        self.on_hdr = None
        self.on_chunk = None
        self.hook_error = None
        self.hdr = threading.Event()
        self.done = threading.Event()

    def json(self):
        try:
            v = json.loads(self.body)
        except (ValueError, UnicodeDecodeError):
            return None
        return v

    def __repr__(self):
        return f"Req({self.what} status={self.status} error={self.error} bytes={self.nbytes})"


def _decode(body: bytes, enc: str) -> bytes:
    enc = (enc or "").strip().lower()
    if enc == "gzip":
        return gzip.decompress(body)
    if enc == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -15)
    return body


def _err_word(e: BaseException) -> str:
    if isinstance(e, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(e, (ConnectionResetError, BrokenPipeError, http.client.RemoteDisconnected,
                      http.client.IncompleteRead, ConnectionAbortedError)):
        return "reset"
    return type(e).__name__


class Conn:
    """One connection and one pre-started worker thread. A request's bytes are sent either on the
    caller's thread (inline: the send time is exactly when the caller asked) or by the worker; the
    worker always reads the response, so the caller is free at once."""

    def __init__(self, tgt: Target, timeout: float = 10.0, name: str = "conn", *, checked: bool = False):
        self.tgt = tgt
        self.timeout = timeout
        self.name = name
        # True only when a Pool that has just run check_platform on this same target makes the Conn:
        # the profile is then read once per pool, not once per connection.
        self.checked = bool(checked)
        self.sock = None
        self.t_connect = None
        self.error = None
        self._q: queue.SimpleQueue = queue.SimpleQueue()
        self._thread = None
        self.busy = False
        self._taken = False
        self.cold = False

    def open(self) -> "Conn":
        if not self.checked:              # outside the try: a refusal is raised, never recorded as an error word
            check_platform(self.tgt)
        t = time.perf_counter()
        try:
            raw = socket.create_connection((self.tgt.host, self.tgt.port), timeout=self.timeout)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for opt in (socket.SO_SNDBUF, socket.SO_RCVBUF):
                try:
                    raw.setsockopt(socket.SOL_SOCKET, opt, BUF)
                except OSError:
                    pass
            if self.tgt.tls:
                raw = SSL_CONTEXT.wrap_socket(raw, server_hostname=self.tgt.host)
            self.sock = raw
        except Exception as e:
            self.error = _err_word(e)
            self.sock = None
            return self
        self.t_connect = time.perf_counter() - t
        self._thread = threading.Thread(target=self._work, name=f"wire-{self.name}", daemon=True)
        self._thread.start()
        return self

    @property
    def ok(self) -> bool:
        return self.sock is not None

    def _work(self):
        while True:
            item = self._q.get()
            if item is None:
                return
            req, data = item
            try:
                if data is not None:
                    self.sock.sendall(data)
                    req.t_sent = time.perf_counter()
                self._read(req)
            except Exception as e:  # anything on the wire is data, never raised into the window
                req.error = _err_word(e)
            finally:
                if req.t_hdr is None:
                    req.t_hdr = time.perf_counter()
                    req.hdr.set()
                if req.t_done is None:
                    req.t_done = time.perf_counter()
                self.busy = False
                req.done.set()

    def _read(self, req: Req):
        self.sock.settimeout(self.timeout)
        resp = http.client.HTTPResponse(self.sock, method="GET" if req.what.startswith("GET") else "POST")
        resp.begin()
        req.t_hdr = time.perf_counter()
        req.status = resp.status
        req.headers = {k.lower(): v for k, v in resp.getheaders()}
        if req.on_hdr is not None:      # runs on this worker, right at the headers (no thread hop)
            try:
                req.on_hdr(req)
            except Exception as e:
                req.hook_error = f"{type(e).__name__}: {e}"
        req.hdr.set()
        if req.on_chunk is None or req.status != 200:
            body = resp.read()
            req.nbytes = len(body)
            req.body = _decode(body, req.headers.get("content-encoding"))
        else:
            # Streamed: on_chunk(req, decoded bytes so far) after each piece until it returns True.
            enc = (req.headers.get("content-encoding") or "").strip().lower()
            dec = (zlib.decompressobj(16 + zlib.MAX_WBITS) if enc == "gzip"
                   else zlib.decompressobj() if enc == "deflate" else None)
            parts, raw_n, want = [], 0, True
            seen = bytearray()
            while True:
                chunk = resp.read1(1 << 16)
                if not chunk:
                    break
                raw_n += len(chunk)
                piece = dec.decompress(chunk) if dec is not None else chunk
                parts.append(piece)
                if want:
                    seen += piece
                    try:
                        want = not req.on_chunk(req, seen)
                    except Exception as e:
                        req.hook_error = f"{type(e).__name__}: {e}"
                        want = False
                    if not want:
                        seen = None
            if dec is not None:
                parts.append(dec.flush())
            req.nbytes = raw_n
            req.body = b"".join(parts)
        req.t_done = time.perf_counter()
        if resp.will_close:
            self.close()

    def fire(self, data: bytes, what: str = "", inline: bool = False, on_hdr=None, on_chunk=None) -> Req:
        """Send prebuilt request bytes. With inline=True the sendall runs on this thread. on_hdr(req)
        is called on the worker as soon as the response headers are parsed (status and headers set,
        body not read); it must be quick and must not raise."""
        req = Req(what)
        req.on_hdr = on_hdr
        req.on_chunk = on_chunk
        if self.sock is None:
            req.error = self.error or "not_connected"
            req.t_hdr = req.t_done = time.perf_counter()
            req.hdr.set()
            req.done.set()
            return req
        self.busy = True
        if inline:
            try:
                self.sock.sendall(data)
                req.t_sent = time.perf_counter()
            except Exception as e:
                req.error = _err_word(e)
                req.t_hdr = req.t_done = time.perf_counter()
                self.busy = False
                req.hdr.set()
                req.done.set()
                return req
            self._q.put((req, None))
        else:
            self._q.put((req, data))
        return req

    def close(self):
        s, self.sock = self.sock, None
        if s is not None:
            try:
                s.close()
            except OSError:
                pass

    def stop(self):
        self.close()
        if self._thread is not None:
            self._q.put(None)


class Pool:
    """n connections opened in parallel, before the clock. Opening costs no request."""

    def __init__(self, tgt: Target, n: int, timeout: float = 10.0, cap: float = 3.0):
        self.tgt = tgt
        self.n = n
        self.timeout = timeout
        self.cap = cap
        self.conns: list[Conn] = []
        self.t_open = None
        self._checked = False

    def open(self) -> "Pool":
        check_platform(self.tgt)          # before the threads: a refusal inside one would be lost
        self._checked = True              # once per pool: the Conns below do not read the profile again
        t = time.perf_counter()
        conns = [Conn(self.tgt, self.timeout, name=f"c{i}", checked=True) for i in range(self.n)]
        threads = [threading.Thread(target=c.open, daemon=True) for c in conns]
        for th in threads:
            th.start()
        end = t + self.cap
        for th in threads:
            th.join(max(0.0, end - time.perf_counter()))
        self.conns = [c for c in conns if c.ok]
        self._late = [c for c in conns if not c.ok]
        self.t_open = time.perf_counter() - t
        return self

    def take(self) -> Conn:
        """A connected, idle connection, or a new one opened now (cold)."""
        for c in self.conns:
            if c.ok and not c.busy and not getattr(c, "_taken", False):
                c._taken = True
                return c
        c = Conn(self.tgt, self.timeout, name=f"cold{len(self.conns)}", checked=self._checked).open()
        c._taken = True
        c.cold = True
        self.conns.append(c)
        return c

    def release(self, c: Conn) -> None:
        """Give a connection back after its response is read; a closed one is not reused."""
        if c.ok and not c.busy:
            c._taken = False

    def close(self):
        for c in self.conns + getattr(self, "_late", []):
            c.stop()

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()


# ---- a fast CTFd client on the pre-opened connections -------------------------------------------------

API = "/api/v1"
SUBMIT = API + "/challenges/attempt"


class FastCTFdError(RuntimeError):
    """A CTFd answer the client cannot use (HTTP status, not JSON, success false, wire error).
    The text never holds request headers, the token or a file URL's query."""


def _refuse_if_hint(api_path: str) -> None:
    """Same rule as ctf.client.CTFd._refuse_if_hint: unlocking or fetching a paid hint spends
    points, which is a human decision, never the solver's."""
    p = api_path.split("?", 1)[0].rstrip("/")
    if p == "/unlocks" or (p.startswith("/hints/") and p != "/hints"):
        raise WireError(f"blocked: {p} would unlock or fetch a paid hint and spend points")


class FastCTFd:
    """List, detail, file downloads and the one submit endpoint of a CTFd, over pre-opened
    connections. Open it before the wave (open() costs no request), then:

        with FastCTFd(url, token, conns=6) as c:
            rows = c.list_challenges()
            files = c.download_many(c.challenge(rows[0]["id"])["files"])
            verdict = c.submit(rows[0]["id"], flag)      # raw; serial and spaced
    """

    def __init__(self, base_url: str, token: str, conns: int = 4, timeout: float = 20.0,
                 submit_interval_s: float = 3.0, user_agent: str = USER_AGENT, open_cap: float = 3.0):
        if token is None:
            raise WireError("the fast client needs a CTFd API token (cookie auth goes through ctf.client)")
        if conns < 1:
            raise WireError("conns must be at least 1")
        self.tgt = check_platform(target(base_url))
        self.headers = Headers(self.tgt, token, "Token", "application/json", user_agent)
        self.n = int(conns)
        self.timeout = float(timeout)
        self.open_cap = float(open_cap)
        self.submit_interval_s = float(submit_interval_s)
        self.pool: Pool | None = None
        self._submit_lock = threading.Lock()
        self._last_submit = None

    @classmethod
    def from_config(cls, cfg, conns: int = 4) -> "FastCTFd":
        """From a ctf.config.Config: base_url, token, submit_interval_min_s, request_timeout_s,
        user_agent. A config with only a session cookie is refused (WireError)."""
        if not getattr(cfg, "token", None):
            raise WireError("the fast client needs a CTFd API token in the event config; "
                            "a session cookie alone goes through ctf.client")
        return cls(cfg.base_url, cfg.token, conns, cfg.request_timeout_s, cfg.submit_interval_min_s,
                   getattr(cfg, "user_agent", USER_AGENT))

    def __repr__(self):
        return f"FastCTFd({self.tgt.base}, conns={self.n}, open={self.pool is not None})"

    # -- connections
    def open(self) -> "FastCTFd":
        if self.pool is None:
            self.pool = Pool(self.tgt, self.n, self.timeout, self.open_cap).open()
        return self

    def close(self) -> None:
        if self.pool is not None:
            self.pool.close()
            self.pool = None

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()

    def _pool(self) -> "Pool":
        if self.pool is None:
            raise WireError("FastCTFd is not open: call open() (before the wave) or use it as a context manager")
        return self.pool

    # -- one request
    def _fire(self, method: str, path: str, body: bytes | None = None):
        pool = self._pool()
        data = self.headers.get(path) if method == "GET" else self.headers.post(path, body or b"")
        conn = pool.take()
        req = conn.fire(data, f"{method} {_redact(path)}")
        return conn, req

    def _wait(self, conn, req):
        if not req.done.wait(self.timeout + 5.0):
            req.error = req.error or "timeout"
            conn.close()
        self._pool().release(conn)
        return req

    def _request(self, method: str, path: str, body: bytes | None = None):
        conn, req = self._fire(method, path, body)
        return self._wait(conn, req)

    @staticmethod
    def _envelope(req, allow=(200,)):
        if req.error:
            raise FastCTFdError(f"{req.what}: {req.error}")
        if req.status not in allow:
            raise FastCTFdError(f"{req.what} -> HTTP {req.status}")
        body = req.json()
        if body is None:
            raise FastCTFdError(f"{req.what}: non-JSON answer (HTTP {req.status}); token not accepted?")
        if isinstance(body, dict) and body.get("success") is False and "data" not in body:
            raise FastCTFdError(f"{req.what}: CTFd said success=false")
        return body

    def api_path(self, path: str) -> str:
        _refuse_if_hint(path)
        return self.tgt.prefix + API + path

    # -- reads
    def list_challenges(self) -> list:
        """GET /api/v1/challenges: every challenge visible now."""
        return self._envelope(self._request("GET", self.api_path("/challenges")))["data"]

    def challenge(self, cid: int) -> dict:
        return self._envelope(self._request("GET", self.api_path(f"/challenges/{int(cid)}")))["data"]

    def challenges(self, cids) -> dict:
        """{id: detail} for several challenges, fetched in parallel on the open connections."""
        cids = [int(c) for c in dict.fromkeys(cids)]
        fired = [(c, *self._fire("GET", self.api_path(f"/challenges/{c}"))) for c in cids]
        return {c: self._envelope(self._wait(conn, req))["data"] for c, conn, req in fired}

    def file_path(self, url: str) -> str:
        """A challenge `files` entry as a request path on the target: a '/files/...' path, or an
        absolute URL on the same scheme, host and port. Anything else is refused (WireError): the
        Authorization header would go to another host."""
        if not isinstance(url, str) or not url:
            raise WireError("empty file URL")
        if url.startswith("/") and not url.startswith("//"):
            path = url if (not self.tgt.prefix or url.startswith(self.tgt.prefix + "/")) else self.tgt.prefix + url
            return _check_path(path)
        try:
            u = urlsplit(url)
            port = u.port or (443 if u.scheme == "https" else 80 if u.scheme == "http" else None)
        except ValueError:
            raise WireError(f"bad file URL {_redact(url)!r}") from None
        same = (u.scheme == ("https" if self.tgt.tls else "http") and (u.hostname or "").lower() == self.tgt.host
                and port == self.tgt.port)
        if not same:
            raise WireError(f"file URL {_redact(url)!r} is not on {self.tgt.base}: refused")
        return _check_path((u.path or "/") + (f"?{u.query}" if u.query else ""))

    def download_many(self, urls) -> dict:
        """{file name: bytes} for every URL, all fired at once (one connection each, cold ones
        opened when there are more files than pre-opened connections). Raises FastCTFdError naming
        the first file that failed (its path, never its query)."""
        paths = [self.file_path(u) for u in urls]
        fired = [(p, *self._fire("GET", p)) for p in paths]
        out, first_error = {}, None
        for p, conn, req in fired:
            self._wait(conn, req)
            if first_error is None and (req.error or req.status != 200):
                first_error = f"download {_redact(p)} -> {req.error or f'HTTP {req.status}'}"
            name = _redact(p).rstrip("/").rsplit("/", 1)[-1] or "file.bin"
            k, stem = 2, name
            while name in out:
                name, k = f"{stem}.{k}", k + 1
            out[name] = req.body
        if first_error:
            raise FastCTFdError(first_error)
        return out

    # -- the one write
    def submit(self, cid: int, flag: str):
        """POST one flag to /api/v1/challenges/attempt -> ctf.client.Submission. Serial (one at a
        time across threads) and spaced by submit_interval_s since the previous submit. The raw
        call: routine play goes through ctf.submit.guarded_submit. Never loop it over candidates."""
        from ctf.client import Submission
        if not isinstance(flag, str) or not flag:
            raise WireError("empty flag")
        with self._submit_lock:
            if self._last_submit is not None:
                gap = self.submit_interval_s - (time.monotonic() - self._last_submit)
                if gap > 0:
                    time.sleep(gap)
            body = json_body({"challenge_id": int(cid), "submission": flag})
            try:
                req = self._request("POST", self.tgt.prefix + SUBMIT, body)
            finally:
                self._last_submit = time.monotonic()
            data = (self._envelope(req, allow=(200, 403, 429)).get("data") or {})
        if req.status == 429 and "status" not in data:
            data = {"status": "ratelimited", "message": "HTTP 429"}
        return Submission(status=str(data.get("status", "unknown")), message=str(data.get("message", "")))
