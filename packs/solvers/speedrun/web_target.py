"""Narrow live-target runtime for dedicated Web speed solvers.

This module deliberately knows nothing about the Game Master.  It receives the
fresh ``targets[]`` from an already-open attempt, keeps every request on the
one assigned origin, never forwards an Authorization header, and returns only
proofs derived from target responses.  Challenge-family readers live in
``speedrun.solvers.web``; this file owns the bounded HTTP and concurrency
machinery so speed solver modules themselves stay network-free.

The ranked runner calls this module only after the fresh contract fingerprint
matches the tracked production-shape loopback qualification.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from urllib.parse import urlsplit

from ctf import flagfmt as _flagfmt
from ctf import scope as _scope


MAX_BODY = 1 << 20
MAX_REQUEST_BODY = 1 << 18
MAX_TARGETS = 16
MAX_WORKERS = 8
# The one observed race family required a true 20-client burst.  Keep that
# wider shape explicit and central: ordinary target fan-out remains capped at
# eight, while a barrier burst cannot grow beyond the production evidence.
MAX_BARRIER_CALLS = 20
REQUEST_HEADERS = {
    "accept", "content-type", "origin", "referer", "sec-fetch-dest",
    "sec-fetch-mode", "sec-fetch-site", "user-agent", "x-forwarded-for",
    "x-delegated-user",
}
DYNAMIC_REQUEST_HEADER = re.compile(r"^x-arena-[0-9a-f]{6,64}$")
COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_TLS_CONTEXT: ssl.SSLContext | None = None
_TLS_CONTEXT_LOCK = threading.Lock()
_DIAGNOSTICS = threading.local()


def clear_target_diagnostics() -> None:
    """Clear the calling solve thread's proof-free target execution summaries."""
    _DIAGNOSTICS.value = []


def take_target_diagnostics() -> list[dict]:
    """Return and clear the calling solve thread's latest target summaries."""
    value = getattr(_DIAGNOSTICS, "value", [])
    _DIAGNOSTICS.value = []
    return [dict(item) for item in value] if isinstance(value, list) else []


class TargetError(RuntimeError):
    """A target could not be read safely or completely."""


class TargetOutOfScope(TargetError, _scope.OutOfScope):
    """The assigned target is outside the active event's live-service scope, or is its platform.

    Raised by :func:`target_identity` (so by every :class:`TargetClient` constructor) before any
    socket is opened or any name resolved. It is both a ``TargetError`` (the readers and
    ``solve_fresh_targets`` already omit a target that raises one) and a ``ctf.scope.OutOfScope``
    (so ``except ctf.scope.OutOfScope`` catches it, as it does every other client's refusal)."""


def prepare_tls_context() -> None:
    """Build the private verified-client context once, before a ranked clock.

    ``SSLContext`` is safe to share between connections when it is not
    reconfigured after use.  The object remains module-private and every TLS
    connection keeps the default hostname and certificate verification from
    :func:`ssl.create_default_context`.  The lock also makes the lazy fallback
    safe for tests or callers which did not run a solver's ``prepare()`` hook.
    """
    global _TLS_CONTEXT
    if _TLS_CONTEXT is not None:
        return
    with _TLS_CONTEXT_LOCK:
        if _TLS_CONTEXT is None:
            _TLS_CONTEXT = ssl.create_default_context()


def _tls_context() -> ssl.SSLContext:
    prepare_tls_context()
    assert _TLS_CONTEXT is not None
    return _TLS_CONTEXT


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class WebAnswers(dict):
    """{answer_id: wire string} plus the count of target requests that produced it.

    The Huntress speed readers originally returned ``speedrun.common.Answers``, the guess-marking
    dict. The master dropped that class on purpose (a first solve never guesses, so nothing may fill
    an answer from a table of past keys), so the Web readers return this instead: a plain dict that
    never marks a guess and only carries the request tally. ``target_requests`` is None until a solve
    sets it from the executed run.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.target_requests = None


def proof_tokens(data: bytes) -> list[str]:
    """Proof tokens in ``data``, from the active event's ``[proof]`` format.

    The Web speed readers hunt the one objective token planted on a payoff response and subtract it
    from the controls. Its shape is the event's, read through ``ctf.flagfmt`` (the single flag/proof
    source), never hardcoded here. Raises ``LookupError`` (from ``ctf.flagfmt``) when the active event
    defines no ``[proof]`` token, so a misconfigured event fails loudly instead of silently matching
    nothing.
    """
    # Scan the latin-1 text form (a 1:1 byte mapping), not ctf.flagfmt's bytes form: the bytes form
    # drops the left word boundary, so an ``xproof_<hex>`` / ``fakeproof_<hex>`` decoy on a payoff
    # would be harvested. The carried readers required a boundary on both sides; the text form keeps
    # both.
    return _flagfmt.current().find_proofs(bytes(data).decode("latin-1"))


def is_proof_value(value: str) -> bool:
    """True when ``value`` is exactly one proof token of the active event's ``[proof]`` format.

    Raises ``LookupError`` when the event defines no ``[proof]`` token (see :func:`proof_tokens`)."""
    # ctf.flagfmt.is_proof strips surrounding whitespace; a wire value must already be exact, so a
    # padded value (" proof_<hex> ") is refused here, as the carried exact-match check did.
    return isinstance(value, str) and value == value.strip() and _flagfmt.current().is_proof(value)


def require_proof_format() -> None:
    """Raise ``LookupError`` unless the active event defines a ``[proof]`` token.

    Called by :func:`solve_fresh_targets` before any target is contacted. A reader's own
    ``proof_tokens`` call would raise too, but only after its first live requests, and inside a solve
    that exception is caught per target and reported as a quiet ``reader_exception`` decline. Checking
    up front makes a misconfigured event fail loudly with a named reason and send nothing."""
    if not _flagfmt.has_proof():
        raise LookupError(
            "the active event profile defines no [proof] format; the Web speed readers hunt a [proof] "
            "token, so no target is contacted (add [proof] to the event's event.toml)")


class TargetValues(dict):
    """Derived answers plus bounded, proof-free target execution summaries."""

    def __init__(self):
        super().__init__()
        self.target_requests = 0
        self.target_diagnostics = []


def target_identity(url: str) -> tuple[str, str, int, str]:
    """Validate, scope-check and normalize one assigned target without opening a socket.

    The host and port must pass ``ctf.scope.check_host`` under the active event profile (inside
    ``rules.live_service_scope``, never the event platform); otherwise :class:`TargetOutOfScope`.

    The path and query remain byte-for-byte URL text because they are part of
    the target capability.  Scheme/host case, a trailing DNS dot, an omitted
    default port and an empty path are normalized so aliases cannot bind two
    answer ids to the same target while appearing distinct.
    """
    if not isinstance(url, str) or not url:
        raise TargetError("target URL is not absolute HTTP(S)")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in url):
        raise TargetError("target URL contains a control character")
    try:
        parsed = urlsplit(url)
        host_value = parsed.hostname
        port_value = parsed.port
    except ValueError as exc:
        raise TargetError("target URL is malformed") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https") or not host_value:
        raise TargetError("target URL is not absolute HTTP(S)")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise TargetError("target URL carries credentials or a fragment")
    host = host_value.rstrip(".").lower()
    if not host:
        raise TargetError("target URL has no host")
    if port_value is not None and port_value <= 0:
        raise TargetError("target URL has an invalid port")
    port = port_value if port_value is not None else (443 if scheme == "https" else 80)
    # The live-service scope guard (ctf.scope, CONTRACTS.md section 13): the host and port must be
    # inside the active event's rules.live_service_scope and must not be its platform (Game Master /
    # scoreboard). Opens no socket and resolves no name. The URL path is a target capability, so the
    # refusal names only the origin.
    _scope.check_host(host, port, what=f"Web speed target {scheme}://{host}:{port}",
                      error=TargetOutOfScope)
    path = parsed.path or "/"
    if not path.startswith("/") or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in path):
        raise TargetError("target URL path is invalid")
    if parsed.query:
        path += "?" + parsed.query
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in path):
        raise TargetError("target URL query is invalid")
    return scheme, host, port, path


class _RequestBudget:
    """One target's request cap, shared by origin-pinned forks."""

    def __init__(self, maximum: int):
        self.maximum = max(0, min(int(maximum), 128))
        self.used = 0
        self._lock = threading.Lock()

    def claim(self):
        with self._lock:
            if self.used >= self.maximum:
                raise TargetError("target request budget exhausted")
            self.used += 1


class TargetClient:
    """One bounded keep-alive client pinned to one HTTP(S) origin."""

    def __init__(self, url: str, *, deadline: float, max_requests: int = 32,
                 _budget: _RequestBudget | None = None, _cookies: dict[str, str] | None = None,
                 _derived_headers: set[str] | None = None):
        self.scheme, self.host, self.port, self.root = target_identity(url)
        self.origin = (self.scheme, self.host, self.port)
        default_port = (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)
        authority_host = f"[{self.host}]" if ":" in self.host else self.host
        authority = authority_host if default_port else f"{authority_host}:{self.port}"
        self.base_url = f"{self.scheme}://{authority}"
        self.deadline = float(deadline)
        self._budget = _budget or _RequestBudget(max_requests)
        self.max_requests = self._budget.maximum
        self._conn = None
        self._cookies: dict[str, str] = dict(_cookies or {})
        self._derived_headers = _derived_headers if _derived_headers is not None else set()

    @property
    def requests(self) -> int:
        return self._budget.used

    def fork(self) -> "TargetClient":
        """A second connection to exactly this origin, sharing its deadline and request cap."""
        return TargetClient(self.base_url + self.root, deadline=self.deadline,
                            max_requests=self.max_requests, _budget=self._budget,
                            _cookies=self._cookies, _derived_headers=self._derived_headers)

    def _remaining(self) -> float:
        return self.deadline - time.time()

    def _bounded_timeout(self) -> float:
        """Return a socket timeout inside this client's absolute deadline."""
        remaining = self._remaining()
        if remaining <= 0.05:
            raise TargetError("target deadline exhausted")
        # Leave a small amount of the ranked path for response handling and
        # the one submit.  The lower bound is below the 50 ms admission guard,
        # so even a request admitted near that guard cannot inherit a timeout
        # which extends beyond the client's absolute cutoff.
        return max(0.01, min(3.0, remaining - 0.02))

    def _refresh_connection_timeout(self):
        """Bound both lazy connects and an existing keep-alive socket anew."""
        timeout = self._bounded_timeout()
        self._conn.timeout = timeout
        sock = getattr(self._conn, "sock", None)
        if sock is not None:
            sock.settimeout(timeout)

    def _open(self):
        timeout = self._bounded_timeout()
        if self.scheme == "https":
            self._conn = http.client.HTTPSConnection(
                self.host, self.port, timeout=timeout, context=_tls_context())
        else:
            self._conn = http.client.HTTPConnection(self.host, self.port, timeout=timeout)

    def preconnect(self):
        """Open this client's origin-pinned socket without spending a request.

        Race readers use this before a barrier so DNS/TLS setup cannot serialize
        the mutation boundary.  The socket still has this client's original
        deadline and exact assigned origin; request accounting begins only when
        :meth:`request` claims the shared budget.
        """
        if self._remaining() <= 0.05:
            raise TargetError("target deadline exhausted")
        if self._conn is None:
            self._open()
        try:
            self._refresh_connection_timeout()
            if self._conn.sock is None:
                self._conn.connect()
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            self.close()
            raise TargetError(f"target preconnect failed: {type(exc).__name__}") from exc

    @staticmethod
    def _path(value: str) -> str:
        text = str(value)
        parsed = urlsplit(text)
        if parsed.scheme or parsed.netloc or parsed.fragment or not text.startswith("/"):
            raise TargetError("request escaped the assigned origin")
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text):
            raise TargetError("request path contains a control character")
        return text

    def _headers(self, values: dict[str, str] | None) -> dict[str, str]:
        out = {}
        for key, value in (values or {}).items():
            low = str(key).strip().lower()
            text = str(value)
            if low not in REQUEST_HEADERS and low not in self._derived_headers:
                raise TargetError(f"request header {low or '<empty>'} is not allowed")
            if low in out or len(text) > 2048 or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in text):
                raise TargetError(f"request header {low} is ambiguous or invalid")
            out[low] = text
        return out

    def _store_cookie(self, raw: str):
        first = str(raw).split(";", 1)[0]
        name, separator, value = first.partition("=")
        name = name.strip()
        value = value.strip()
        if not separator or not COOKIE_NAME.fullmatch(name) or len(value) > 1024 \
                or any(ord(ch) < 0x21 or ord(ch) >= 0x7f or ch in ";," for ch in value):
            raise TargetError("target returned an invalid Set-Cookie")
        if len(self._cookies) >= 32 and name not in self._cookies:
            raise TargetError("target returned too many cookies")
        self._cookies[name] = value

    def request(self, method: str, path: str, *, body: bytes | str | None = None,
                headers: dict[str, str] | None = None) -> Response:
        method = str(method).upper()
        if method not in ("GET", "POST"):
            raise TargetError("request method is not allowed")
        path = self._path(path)
        if method == "GET" and body not in (None, b"", ""):
            raise TargetError("GET request carries a body")
        if body is None:
            body_bytes = None
        elif isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            raise TargetError("request body is not bytes or text")
        if body_bytes is not None and len(body_bytes) > MAX_REQUEST_BODY:
            raise TargetError("request body exceeded the size limit")
        if self._remaining() <= 0.05:
            raise TargetError("target deadline exhausted")
        self._budget.claim()
        if self._conn is None:
            self._open()
        request_headers = {
            "Accept": "application/json,text/plain,text/html,application/octet-stream;q=0.8",
            "Connection": "keep-alive",
            "User-Agent": "huntress-speedrun-web/1",
        }
        for key, value in self._headers(headers).items():
            request_headers[key.title()] = value
        if self._cookies:
            request_headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in sorted(self._cookies.items()))
        try:
            # HTTPConnection keeps the timeout from its first connect.  Reset
            # it on every request so a late keep-alive request cannot consume
            # the original three-second allowance past the submit cutoff.
            self._refresh_connection_timeout()
            self._conn.request(method, path, body=body_bytes, headers=request_headers)
            response = self._conn.getresponse()
            raw_headers = response.getheaders()
            length = response.getheader("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise TargetError("target returned an invalid Content-Length") from exc
                if declared < 0 or declared > MAX_BODY:
                    raise TargetError("target body is outside the size limit")
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise TargetError("target body exceeded the size limit")
            headers_out: dict[str, str] = {}
            for key, value in raw_headers:
                low = str(key).lower()
                if low == "set-cookie":
                    self._store_cookie(str(value))
                    continue
                if low in headers_out:
                    raise TargetError(f"target returned ambiguous {low} headers")
                headers_out[low] = str(value)
            # The final two Web families use one fresh trust-boundary header named by a prior
            # response's Vary contract.  Admit only one tightly shaped name from one response;
            # arbitrary/static x-* headers and ambiguous multi-name responses remain refused.
            dynamic = {
                item.strip().lower()
                for item in headers_out.get("vary", "").split(",")
                if DYNAMIC_REQUEST_HEADER.fullmatch(item.strip().lower())
            }
            if len(dynamic) == 1:
                self._derived_headers.update(dynamic)
            return Response(int(response.status), headers_out, bytes(body))
        except TargetError:
            self.close()
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            self.close()
            raise TargetError(f"target request failed: {type(exc).__name__}") from exc

    def get(self, path: str, *, headers: dict[str, str] | None = None) -> Response:
        return self.request("GET", path, headers=headers)

    def post(self, path: str, *, body: bytes | str,
             headers: dict[str, str] | None = None) -> Response:
        return self.request("POST", path, body=body, headers=headers)

    def post_json(self, path: str, value) -> Response:
        raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return self.post(path, body=raw, headers={"Content-Type": "application/json"})

    def websocket_text(self, path: str) -> Response:
        """Receive one bounded server-first WebSocket text frame from this assigned origin."""
        path = self._path(path)
        remaining = self._remaining()
        if remaining <= 0.05:
            raise TargetError("target deadline exhausted")
        self._budget.claim()
        timeout = self._bounded_timeout()
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        default_port = (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443)
        host = self.host if default_port else f"{self.host}:{self.port}"
        lines = [
            f"GET {path} HTTP/1.1", f"Host: {host}", "User-Agent: huntress-speedrun-web/1",
            "Connection: Upgrade", "Upgrade: websocket", f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if self._cookies:
            lines.append("Cookie: " + "; ".join(
                f"{name}={value}" for name, value in sorted(self._cookies.items())))
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        raw_sock = None
        try:
            raw_sock = socket.create_connection((self.host, self.port), timeout=timeout)
            if self.scheme == "https":
                raw_sock = _tls_context().wrap_socket(raw_sock, server_hostname=self.host)
            raw_sock.settimeout(self._bounded_timeout())
            raw_sock.sendall(request)
            buffered = bytearray()
            while b"\r\n\r\n" not in buffered:
                chunk = raw_sock.recv(4096)
                if not chunk or len(buffered) + len(chunk) > 16384:
                    raise TargetError("invalid WebSocket handshake")
                buffered.extend(chunk)
            head, pending = bytes(buffered).split(b"\r\n\r\n", 1)
            header_lines = head.split(b"\r\n")
            if not header_lines or not re.fullmatch(rb"HTTP/1\.[01] 101(?: .*)?", header_lines[0]):
                raise TargetError("target refused the WebSocket upgrade")
            headers: dict[str, str] = {}
            for line in header_lines[1:]:
                if b":" not in line:
                    raise TargetError("malformed WebSocket handshake header")
                name, value = line.split(b":", 1)
                low = name.decode("ascii", "strict").strip().lower()
                if low in headers:
                    raise TargetError("ambiguous WebSocket handshake header")
                headers[low] = value.decode("latin-1").strip()
            expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("ascii")).digest()).decode("ascii")
            connections = {part.strip().lower() for part in headers.get("connection", "").split(",")}
            if headers.get("upgrade", "").lower() != "websocket" or "upgrade" not in connections \
                    or headers.get("sec-websocket-accept") != expected:
                raise TargetError("invalid WebSocket handshake proof")

            def take(size: int) -> bytes:
                nonlocal pending
                while len(pending) < size:
                    chunk = raw_sock.recv(max(4096, size - len(pending)))
                    if not chunk:
                        raise TargetError("truncated WebSocket frame")
                    pending += chunk
                out, pending = pending[:size], pending[size:]
                return out

            first = take(2)
            if first[0] != 0x81 or first[1] & 0x80:
                raise TargetError("WebSocket response is not one final unmasked text frame")
            length = first[1] & 0x7f
            if length == 126:
                length = int.from_bytes(take(2), "big")
                if length < 126:
                    raise TargetError("non-minimal WebSocket length")
            elif length == 127:
                raise TargetError("WebSocket response is outside the bounded shape")
            if length > MAX_BODY:
                raise TargetError("WebSocket message is outside the size limit")
            payload = take(length)
            payload.decode("utf-8", "strict")
            if pending:
                raise TargetError("multiple WebSocket frames are ambiguous")
            raw_sock.settimeout(min(0.10, max(0.01, self._remaining())))
            try:
                if raw_sock.recv(1):
                    raise TargetError("multiple WebSocket frames are ambiguous")
            except socket.timeout:
                # A server-first feed may stay open waiting for future events.
                # The one authenticated complete frame is sufficient; any byte
                # already available above still makes the response ambiguous.
                pass
            return Response(101, headers, payload)
        except TargetError:
            raise
        except (OSError, UnicodeError, ssl.SSLError) as exc:
            raise TargetError(f"WebSocket request failed: {type(exc).__name__}") from exc
        finally:
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except OSError:
                pass
            self._conn = None


def parallel_calls(calls: list, *, max_workers: int = MAX_WORKERS) -> list:
    """Run a small fixed set of already origin-pinned callables, preserving input order."""
    if not isinstance(calls, list) or not calls or len(calls) > MAX_WORKERS:
        raise TargetError("parallel target call count is outside the bounded policy")
    workers = max(1, min(int(max_workers), MAX_WORKERS, len(calls)))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="speed-web-call") as pool:
        futures = [pool.submit(call) for call in calls]
        return [future.result() for future in futures]


def barrier_calls(calls: list, *, preparations: list | None = None,
                  deadline: float) -> list:
    """Prepare, then release one bounded set of calls at the same instant.

    Every worker completes its optional preparation (normally an origin-pinned
    ``TargetClient.preconnect``) before any worker may enter its call.  A failed
    preparation or an elapsed deadline breaks the barrier, so no partial burst
    crosses the mutation boundary.  This is intentionally capped at the one
    20-client race width observed in the solved production evidence.
    """
    if not isinstance(calls, list) or len(calls) < 2 or len(calls) > MAX_BARRIER_CALLS \
            or not all(callable(call) for call in calls):
        raise TargetError("barrier target call count is outside the bounded policy")
    if preparations is None:
        preparations = [None] * len(calls)
    if not isinstance(preparations, list) or len(preparations) != len(calls) \
            or any(item is not None and not callable(item) for item in preparations):
        raise TargetError("barrier target preparations are malformed")
    try:
        end = float(deadline)
    except (TypeError, ValueError) as exc:
        raise TargetError("barrier target deadline is invalid") from exc
    if end - time.time() <= 0.05:
        raise TargetError("target deadline exhausted")

    barrier = threading.Barrier(len(calls) + 1)

    def one(index: int):
        try:
            prepare = preparations[index]
            if prepare is not None:
                prepare()
            remaining = end - time.time()
            if remaining <= 0.05:
                raise TargetError("target deadline exhausted before barrier")
            barrier.wait(timeout=remaining)
            return calls[index]()
        except threading.BrokenBarrierError as exc:
            raise TargetError("target barrier did not become ready") from exc
        except Exception:
            try:
                barrier.abort()
            except threading.BrokenBarrierError:
                pass
            raise

    with ThreadPoolExecutor(max_workers=len(calls), thread_name_prefix="speed-web-barrier") as pool:
        futures = [pool.submit(one, index) for index in range(len(calls))]
        try:
            remaining = end - time.time()
            if remaining <= 0.05:
                raise TargetError("target deadline exhausted before barrier")
            barrier.wait(timeout=remaining)
        except (threading.BrokenBarrierError, TargetError) as exc:
            try:
                barrier.abort()
            except threading.BrokenBarrierError:
                pass
            for future in futures:
                future.cancel()
            if isinstance(exc, TargetError):
                raise
            raise TargetError("target barrier did not become ready") from exc
        return [future.result() for future in futures]


def solve_fresh_targets(attempt: dict, reader, *, deadline: float, max_requests: int = 32,
                        indexed: bool = False) -> dict[str, str]:
    """Run ``reader(client, attempt)`` once per fresh target, in parallel.

    Target order is bound to ``answer_ids`` by the target ``id``/question
    artifact when possible and by position only when both lists have the same
    length.  Any ambiguity, exception, missing proof or duplicate answer id is
    omitted; the ranked runner will therefore decline the whole try.

    Raises ``LookupError`` (see :func:`require_proof_format`) before any target is contacted when the
    active event defines no ``[proof]`` token.
    """
    require_proof_format()
    clear_target_diagnostics()
    targets = attempt.get("targets")
    answer_ids = attempt.get("answer_ids")
    questions = attempt.get("questions")
    if not isinstance(targets, list) or not isinstance(answer_ids, list) \
            or not isinstance(questions, list) or not targets or len(targets) > MAX_TARGETS \
            or len(targets) != len(answer_ids) or len(questions) != len(answer_ids):
        return {}
    tasks = []
    seen_ids = set()
    for index, (target, aid, question) in enumerate(zip(targets, answer_ids, questions), 1):
        if not isinstance(target, dict) or not isinstance(aid, str) or not aid or aid in seen_ids \
                or not isinstance(question, dict):
            return {}
        target_id = target.get("id")
        artifact = question.get("artifact")
        qid = question.get("id")
        if target_id and artifact and str(target_id) != str(artifact):
            return {}
        if qid and str(qid) != aid:
            return {}
        url = target.get("url")
        if not isinstance(url, str):
            return {}
        seen_ids.add(aid)
        tasks.append((index, aid, url))

    def one(row):
        index, aid, url = row
        client = None
        proof = None
        requests = 0
        stage = "target_init_failed"
        try:
            client = TargetClient(url, deadline=deadline, max_requests=max_requests)
            stage = "reader_declined"
            try:
                proof = reader(client, attempt, index) if indexed else reader(client, attempt)
            except Exception:
                proof = None
                stage = "reader_exception"
            requests = client.requests
            if isinstance(proof, str):
                stage = "value_returned"
        except Exception:
            # Target URLs and exception strings may contain capabilities or response material.
            # Preserve only this fixed class; the ranked runner applies the final persistence
            # allowlist before writing it.
            proof = None
            requests = client.requests if client is not None else 0
        finally:
            if client is not None:
                client.close()
        return index, aid, proof, requests, stage

    out = TargetValues()
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(tasks)), thread_name_prefix="speed-web") as pool:
        futures = {pool.submit(one, row): (row[0], row[1]) for row in tasks}
        for future in as_completed(futures):
            try:
                index, aid, proof, requests, stage = future.result()
            except Exception:
                index, aid = futures[future]
                out.target_diagnostics.append({
                    "index": index, "answer_id": aid,
                    "stage": "worker_exception", "requests": 0,
                })
                continue
            out.target_requests += requests
            out.target_diagnostics.append({
                "index": index, "answer_id": aid, "stage": stage, "requests": requests,
            })
            if isinstance(proof, str):
                out[aid] = proof
    out.target_diagnostics.sort(key=lambda item: item["index"])
    _DIAGNOSTICS.value = [dict(item) for item in out.target_diagnostics]
    return out
