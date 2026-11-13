"""Replayable live-service challenges for the blind rehearsal corpus (B-155).

Some past challenges were solved only against live infrastructure: a DNS server handing out TXT
records (CSCTF "logs"), a remote line service reached over socat (CSCTF "print"), a web container.
Those paths were never rehearsed offline. This module re-serves such a service from a *declarative*
spec (never by running a challenge binary): a tiny DNS, line (socat) or web server bound to 127.0.0.1
that answers exactly what the spec says. The spec and its response bytes live in the external corpus
(ctf.paths.rehearsal_corpus_root), never in this repo.

    from ctf import livereplay
    with livereplay.start(spec) as svc:          # spec = {"kind": "dns"|"socat"|"web", ...}
        svc.address                          # (host, port), loopback only
        data = livereplay.run_probe(svc, spec)   # drive the spec's probe, return the bytes it yielded

Every server binds 127.0.0.1 on an ephemeral port and stops on exit from the `with` block. Nothing
here reaches off-loopback, executes a binary, or reads a flag from this repo.

Spec shapes (all values come from the corpus):

  dns    {"kind":"dns", "records": {"<name>": ["<txt>", ...], ...},
          "probe": {"name":"<name>", "qtype":"TXT"}}
  socat  {"kind":"socat", "banner":"<sent on connect>", "turns":[{"recv_contains":<str|null>,
          "send":"<reply>"}, ...], "probe": {"inputs": ["<line>", ...], "until": "<text>"?}}
  web    {"kind":"web", "routes": {"<path>": {"status":200, "body":"<text>", "headers":{...},
          "variants": [{"when": {"<request header>": "<value>"}, "status":..., "body":..., "headers":...}]?},
          ...}, "probe": {"path":"<path>", "method":"GET"}}
         (a variant is served when every `when` header equals the request's; the service keeps
         every request in `.requests`)
"""
from __future__ import annotations

import select
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOOPBACK = "127.0.0.1"
DNS_TYPE_TXT = 16
_PROBE_TIMEOUT = 5.0
_REPLY_WAIT = 2.0          # seconds to wait for the first byte of a socat reply
_IDLE = 0.15               # then read until the line is quiet this long


class ReplayError(RuntimeError):
    """A service spec is malformed or a probe could not run; the message says why."""


def _require(spec: dict, key: str):
    if key not in spec:
        raise ReplayError(f"{spec.get('kind', '?')} service spec has no {key!r}")
    return spec[key]


# ----------------------------------------------------------------------------------- DNS (TXT)

def _dns_decode_name(msg: bytes, off: int) -> tuple[str, int]:
    labels = []
    while True:
        if off >= len(msg):
            raise ReplayError("truncated DNS question name")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0:                                   # a pointer in a question: not expected here
            raise ReplayError("compressed DNS question name is not supported")
        off += 1
        labels.append(msg[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels), off


def _dns_encode_txt_rdata(strings: list[str]) -> bytes:
    out = bytearray()
    for s in strings:
        b = s.encode("utf-8")
        if len(b) > 255:
            raise ReplayError("a DNS TXT character-string exceeds 255 bytes")
        out.append(len(b))
        out += b
    return bytes(out)


class DnsReplay:
    """A UDP DNS server answering TXT queries from `records` (name -> list of TXT strings)."""

    def __init__(self, records: dict[str, list[str]]):
        self.records = {k.rstrip(".").lower(): list(v) for k, v in records.items()}
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def address(self) -> tuple[str, int]:
        if self._sock is None:
            raise RuntimeError("DnsReplay is not running (use it as a context manager)")
        return self._sock.getsockname()[:2]

    def __enter__(self) -> "DnsReplay":
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((LOOPBACK, 0))
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, name="dns-replay", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                reply = self._answer(data)
            except ReplayError:
                continue
            if reply is not None:
                try:
                    self._sock.sendto(reply, addr)
                except OSError:
                    break

    def _answer(self, msg: bytes) -> bytes | None:
        if len(msg) < 12:
            return None
        txid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", msg[:12])
        if qd < 1:
            return None
        name, off = _dns_decode_name(msg, 12)
        qtype, qclass = struct.unpack(">HH", msg[off:off + 4])
        off += 4
        question = msg[12:off]
        key = name.lower()
        records = self.records.get(key) if qtype == DNS_TYPE_TXT else None
        if records is None:
            rcode = 3                                  # NXDOMAIN
            header = struct.pack(">HHHHHH", txid, 0x8180 | rcode, 1, 0, 0, 0)
            return header + question
        header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
        rdata = _dns_encode_txt_rdata(records)
        answer = (b"\xc0\x0c" + struct.pack(">HHIH", DNS_TYPE_TXT, 1, 60, len(rdata)) + rdata)
        return header + question + answer


def probe_dns(address: tuple[str, int], name: str, qtype: str = "TXT",
              timeout: float = _PROBE_TIMEOUT) -> list[str]:
    """Send one TXT query and return the TXT strings in the answer (empty on NXDOMAIN)."""
    if qtype.upper() != "TXT":
        raise ReplayError(f"only TXT queries are supported, got {qtype!r}")
    qname = bytearray()
    for label in name.rstrip(".").split("."):
        b = label.encode("ascii")
        qname.append(len(b))
        qname += b
    qname.append(0)
    query = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + bytes(qname) + struct.pack(">HH", DNS_TYPE_TXT, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(query, address)
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    _, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
    if an == 0:
        return []
    _, off = _dns_decode_name(data, 12)
    off += 4                                           # qtype, qclass
    out: list[str] = []
    for _ in range(an):
        # name (pointer or labels)
        if data[off] & 0xC0:
            off += 2
        else:
            _, off = _dns_decode_name(data, off)
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlen]
        off += rdlen
        if rtype == DNS_TYPE_TXT:
            i = 0
            while i < len(rdata):
                n = rdata[i]
                out.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
    return out


# ----------------------------------------------------------------------------------- socat (line)

class SocatReplay:
    """A TCP line service: send `banner` on connect, then for each received chunk reply with the
    first not-yet-used turn whose `recv_contains` is None or a substring of the chunk."""

    def __init__(self, banner: str = "", turns: list[dict] | None = None):
        self.banner = banner
        self.turns = list(turns or [])
        self._server: _TcpServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("SocatReplay is not running (use it as a context manager)")
        return self._server.server_address[:2]

    def __enter__(self) -> "SocatReplay":
        banner, turns = self.banner, self.turns

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                conn = self.request
                conn.settimeout(2.0)
                try:
                    if banner:
                        conn.sendall(banner.encode("utf-8"))
                    used = [False] * len(turns)
                    while not all(used):
                        try:
                            chunk = conn.recv(4096)
                        except (socket.timeout, OSError):
                            break
                        if not chunk:
                            break
                        text = chunk.decode("utf-8", "replace")
                        for i, turn in enumerate(turns):
                            if used[i]:
                                continue
                            want = turn.get("recv_contains")
                            if want is None or want in text:
                                conn.sendall(str(turn.get("send", "")).encode("utf-8"))
                                used[i] = True
                                break
                except OSError:
                    pass

        self._server = socketserver.ThreadingTCPServer((LOOPBACK, 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="socat-replay", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def probe_socat(address: tuple[str, int], inputs: list[str], timeout: float = _PROBE_TIMEOUT, *,
                until: str | None = None, reply_wait: float = _REPLY_WAIT, idle: float = _IDLE) -> bytes:
    """Connect, read the banner, send each input line, and return everything received.

    After connecting and after each send it waits up to `reply_wait` seconds for the first byte of a
    reply (select, not a fixed sleep, so a slow reply on a loaded machine is still read), then keeps
    reading until the line has been quiet for `idle` seconds. With `until`, it stops as soon as that
    text has arrived, or raises ReplayError when the overall `timeout` passes first."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    deadline = time.monotonic() + timeout
    collected = bytearray()
    want = until.encode("utf-8") if until else None
    try:
        s.connect(address)
        collected += _read_reply(s, reply_wait, idle, deadline)
        for line in inputs:
            if want is not None and want in collected:
                break
            s.sendall(line.encode("utf-8"))
            collected += _read_reply(s, reply_wait, idle, deadline)
        while want is not None and want not in collected:
            left = deadline - time.monotonic()
            if left <= 0:
                raise ReplayError(f"socat probe: {until!r} did not arrive within {timeout:g}s")
            more = _read_reply(s, left, idle, deadline)
            if not more:
                raise ReplayError(f"socat probe: the service went quiet before {until!r} arrived")
            collected += more
    finally:
        s.close()
    return bytes(collected)


def _read_reply(s: socket.socket, first_wait: float, idle: float, deadline: float) -> bytes:
    """Wait up to `first_wait` for data, then read until quiet for `idle` (never past `deadline`)."""
    out = bytearray()
    wait = first_wait
    while True:
        wait = min(wait, deadline - time.monotonic())
        if wait <= 0:
            break
        ready, _, _ = select.select([s], [], [], wait)
        if not ready:
            break
        try:
            chunk = s.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        out += chunk
        wait = idle
    return bytes(out)


# ----------------------------------------------------------------------------------- web

class WebReplay:
    """An HTTP server answering `routes` (path -> {status, body, headers}); an unknown path is 404.

    A route may carry `variants`: a list of {"when": {<request header>: <exact value>, ...}, status,
    body, headers}. The first variant whose every `when` header equals the request's is served in
    place of the route's own reply (B-131: a page that answers one User-Agent differently). Every
    request is appended to `.requests` as (method, path, {lower-cased header: value})."""

    def __init__(self, routes: dict[str, dict]):
        self.routes = dict(routes)
        self.requests: list[tuple[str, str, dict[str, str]]] = []
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        if self._server is None:
            raise RuntimeError("WebReplay is not running (use it as a context manager)")
        return self._server.server_address[:2]

    @property
    def base_url(self) -> str:
        host, port = self.address
        return f"http://{host}:{port}"

    def __enter__(self) -> "WebReplay":
        routes = self.routes
        seen = self.requests

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _serve(self):
                path = self.path.split("?", 1)[0]
                seen.append((self.command, self.path, {k.lower(): v for k, v in self.headers.items()}))
                route = routes.get(path)
                if route is None:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"not found")
                    return
                for variant in route.get("variants") or ():
                    when = variant.get("when") or {}
                    if when and all(self.headers.get(k) == v for k, v in when.items()):
                        route = variant
                        break
                body = str(route.get("body", "")).encode("utf-8")
                self.send_response(int(route.get("status", 200)))
                for k, v in (route.get("headers") or {}).items():
                    self.send_header(str(k), str(v))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self._serve()

            def do_POST(self):
                self._serve()

        self._server = ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, name="web-replay", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


def probe_web(base_url: str, path: str, method: str = "GET", timeout: float = _PROBE_TIMEOUT) -> bytes:
    import http.client
    from urllib.parse import urlsplit
    u = urlsplit(base_url)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.request(method.upper(), path)
        resp = conn.getresponse()
        return resp.read()
    finally:
        conn.close()


# ----------------------------------------------------------------------------------- dispatch

@dataclass
class _Running:
    kind: str
    service: object

    @property
    def address(self) -> tuple[str, int]:
        return self.service.address

    @property
    def endpoint(self) -> str:
        host, port = self.address
        if self.kind == "web":
            return f"http://{host}:{port}"
        proto = "udp" if self.kind == "dns" else "tcp"
        return f"{proto}://{host}:{port}"


VALID_KINDS = ("dns", "socat", "web")


class _Starter:
    def __init__(self, spec: dict):
        self.spec = spec
        self.kind = _require(spec, "kind")
        if self.kind not in VALID_KINDS:
            raise ReplayError(f"unknown live-service kind {self.kind!r} (expected one of {VALID_KINDS})")
        self._cm = None
        self._svc = None

    def __enter__(self) -> _Running:
        if self.kind == "dns":
            self._cm = DnsReplay(_require(self.spec, "records"))
        elif self.kind == "socat":
            self._cm = SocatReplay(self.spec.get("banner", ""), self.spec.get("turns", []))
        else:
            self._cm = WebReplay(_require(self.spec, "routes"))
        self._svc = self._cm.__enter__()
        return _Running(self.kind, self._svc)

    def __exit__(self, *exc):
        if self._cm is not None:
            return self._cm.__exit__(*exc)
        return False


def start(spec: dict):
    """Context manager that starts the replay service described by `spec` on loopback."""
    return _Starter(spec)


def run_probe(running: _Running, spec: dict) -> bytes:
    """Drive the spec's `probe` against a running service and return the bytes it yielded. The caller
    scans these bytes for a flag, so the live path is exercised end to end."""
    probe = spec.get("probe")
    if not probe:
        raise ReplayError(f"{running.kind} service spec has no 'probe' to drive the live path")
    if running.kind == "dns":
        txts = probe_dns(running.address, _require(probe, "name"), probe.get("qtype", "TXT"))
        return "\n".join(txts).encode("utf-8")
    if running.kind == "socat":
        return probe_socat(running.address, list(probe.get("inputs", [])), until=probe.get("until"))
    return probe_web(running.service.base_url, _require(probe, "path"), probe.get("method", "GET"))
