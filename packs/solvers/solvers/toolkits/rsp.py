#!/usr/bin/env python3
"""GDB Remote Serial Protocol (RSP) live-bench client (B-056).

A mechanical client for the GDB remote stub a live reverse-engineering challenge exposes (CSCTF
9104 "ghost-bank": a bare-metal target reachable only over gdbserver/RSP, whose ciphertext lives in
a device-memory page and whose decrypt is triggered by one host write). It speaks the wire -- packet
framing, the mod-256 checksum, `+`/`-` acknowledgements and no-ack mode, the `qSupported` handshake,
`qXfer:memory-map:read` enumeration, batched `m` reads capped near 40 packets, and a *paced* MMIO
page walker -- so an operator drives the target by naming addresses rather than hand-assembling
packets. It generates no exploit and discovers no address: what to read, and the single write that
matters, stay the operator's.

Scope is never this module's own. Every socket is opened through `pwn_target.PwnTarget`, whose
constructor calls `chat_target.assert_host_in_scope` -> `ctf.scope.check_host`, read from the current
event profile's `rules.live_service_scope`. An out-of-scope or platform host is refused before any
connection. Slots come from `ctf.instances` / `live_harness.InstanceLifecycle` (B-003): this module
writes no scheduler of its own -- `from_instances()` reads the assigned instance's host:port and
builds a scoped client on it.

READS BY DEFAULT. `read_memory`/`walk_pages` only ever send `m` (read) packets. A `M` (write) is sent
*only* by `write_memory`, and only for an address the caller passed in an explicit `allow` list. There
is no range write, no write sweep and no address guessing: the 0x9c host write that unlocks ghost-bank
was found by live probing, so it must be named by the operator, never discovered by this tool.

Everything the target returns is DATA: decoded, returned to the caller and logged to the transport
transcript, never executed and never treated as an instruction. The memory-map XML is parsed with DTDs
and entities refused (it is untrusted target output).

CLI (offline helpers only; no connection is made):

  .venv/bin/python solvers/toolkits/rsp.py checksum <packet-text>     # the two-hex-digit RSP checksum
  .venv/bin/python solvers/toolkits/rsp.py frame <packet-text>        # the exact $...#cs bytes on the wire
  .venv/bin/python solvers/toolkits/rsp.py decode '$OK#9a'            # unframe + verify + un-RLE a reply
"""
import sys
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(1, str(HERE))
import chat_target as ct     # noqa: E402  (shared errors + the scope guard)
import pwn_target as pt      # noqa: E402  (the scope-checked raw-TCP socket)

# The RSP reply to an `m`/`M` reply must fit the negotiated PacketSize; without a qSupported answer we
# assume this conservative default (the GDB remote default). `m` hex-encodes bytes 2:1, so the readable
# payload per packet is about half of this.
DEFAULT_PACKET_SIZE = 0x3fff
DEFAULT_READ_CHUNK = 256              # bytes per `m` packet unless the caller/PacketSize lowers it
MAX_BATCH_PACKETS = 40                # a single contiguous read is capped near this many `m` packets
DEFAULT_WALK_PAGE = 0x100             # MMIO page size for the paced walker
MAX_RESEND = 3                        # `-` nak retransmits before giving up
READ_RETRIES = 400                    # recv() refills before a frame is declared incomplete

_SPECIAL = {0x24, 0x23, 0x7d, 0x2a}   # $  #  }  *  : escaped as } (b ^ 0x20) inside packet data
_ESCAPE = 0x7d
_RUN = 0x2a                           # *  run-length marker
_RUN_BIAS = 29                        # a run count byte of value v means (v - 29) ADDITIONAL repeats


class RSPError(RuntimeError):
    """An RSP-level problem (a target error reply, a cap exceeded, a refused write). Loud, never silent."""


class RSPProtocolError(RSPError):
    """A malformed frame: a bad checksum, a truncated packet, an unparsable reply. Loud, never silent."""


# ======================================================================================
#  Pure wire helpers: checksum, escaping, run-length, framing. No sockets here.
# ======================================================================================

def checksum(payload: bytes) -> int:
    """The RSP checksum of packet data: the sum of its bytes, modulo 256."""
    return sum(_as_bytes(payload)) & 0xff


def escape(payload: bytes) -> bytes:
    """Escape the four bytes that are special inside packet data ($ # } *) as `}`,(b ^ 0x20).

    Normal command text contains none of these, so this is a no-op for it; `M` write data is hex, so
    also untouched. It exists so a caller may put arbitrary bytes in a packet without corrupting framing.
    """
    out = bytearray()
    for b in _as_bytes(payload):
        if b in _SPECIAL:
            out += bytes((_ESCAPE, b ^ 0x20))
        else:
            out.append(b)
    return bytes(out)


def unescape(data: bytes) -> bytes:
    """Reverse escaping AND expand run-length encoding in a reply's packet data.

    RLE: a byte, then `*`, then a count byte `v`, means that byte repeated (v - 29) ADDITIONAL times
    (GDB's convention: a count byte of ' ' (0x20) adds 3). The escape `}` takes precedence; a `*` that
    is itself escaped (`}\\x0a`) is literal.
    """
    data = _as_bytes(data)
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b == _ESCAPE:
            if i + 1 >= n:
                raise RSPProtocolError("dangling escape '}' at end of packet data")
            out.append(data[i + 1] ^ 0x20)
            i += 2
            continue
        if b == _RUN:
            if not out:
                raise RSPProtocolError("run-length '*' with no preceding byte to repeat")
            if i + 1 >= n:
                raise RSPProtocolError("run-length '*' with no count byte")
            extra = data[i + 1] - _RUN_BIAS
            if extra < 0:
                raise RSPProtocolError(f"run-length count byte {data[i + 1]} is below the {_RUN_BIAS} bias")
            out.extend(bytes((out[-1],)) * extra)
            i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


def frame_packet(payload: bytes) -> bytes:
    """The exact bytes on the wire for `payload`: `$` + escaped data + `#` + two lowercase checksum hex."""
    body = escape(payload)
    return b"$" + body + b"#" + f"{checksum(body):02x}".encode()


def parse_frame(buf: bytes) -> tuple:
    """(packet_data, rest) when `buf` holds one complete, checksum-valid `$...#cs` frame, else (None, buf).

    Leading `+`/`-` acks and stray bytes before `$` are NOT consumed here (the reader handles acks); a
    `$` with a complete `#cs` but a wrong checksum raises RSPProtocolError -- a corrupt frame is loud.
    Returned packet_data is still escaped/RLE-encoded; call `unescape` to get the logical bytes.
    """
    start = buf.find(b"$")
    if start < 0:
        return None, buf
    hash_at = buf.find(b"#", start)
    if hash_at < 0 or hash_at + 2 >= len(buf):
        return None, buf                     # no terminator, or checksum digits not all here yet
    body = buf[start + 1:hash_at]
    cs_hex = buf[hash_at + 1:hash_at + 3]
    try:
        want = int(cs_hex, 16)
    except ValueError:
        raise RSPProtocolError(f"frame checksum {cs_hex!r} is not two hex digits")
    got = checksum(body)
    if got != want:
        raise RSPProtocolError(f"frame checksum mismatch: computed {got:#04x}, packet says {want:#04x}")
    return body, buf[hash_at + 3:]


def _as_bytes(x) -> bytes:
    if isinstance(x, str):
        return x.encode()
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x)
    raise TypeError(f"expected bytes/str, got {type(x).__name__}")


# ======================================================================================
#  Memory map (qXfer:memory-map:read) and pacing.
# ======================================================================================

@dataclass(frozen=True)
class MemoryRegion:
    """One `<memory>` element of the target's memory map: an address window and its kind."""
    start: int
    length: int
    type: str = "ram"                     # ram | flash | io | ... (as the target labels it)

    @property
    def end(self) -> int:
        return self.start + self.length

    def contains(self, addr: int, length: int = 1) -> bool:
        return self.start <= addr and addr + length <= self.end


def parse_memory_map(xml: bytes) -> list:
    """Parse memory-map XML into [MemoryRegion]. DTDs and entities are refused (untrusted target data)."""
    data = _as_bytes(xml).strip()
    if not data:
        return []
    low = data.lower()
    if b"<!doctype" in low or b"<!entity" in low or b"<!element" in low:
        raise RSPProtocolError("memory-map XML declares a DTD/entity; refusing to parse untrusted markup")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise RSPProtocolError(f"memory-map XML did not parse: {e}") from e
    regions = []
    for el in root.iter("memory"):
        try:
            start = int(el.attrib["start"], 0)
            length = int(el.attrib["length"], 0)
        except (KeyError, ValueError) as e:
            raise RSPProtocolError(f"memory-map <memory> missing/!int start/length: {el.attrib!r}") from e
        regions.append(MemoryRegion(start, length, el.attrib.get("type", "ram")))
    return regions


@dataclass
class Pacer:
    """A paced delay between MMIO reads. `interval` seconds via `sleeper` (injected in tests so no real
    wall-clock wait happens). `waits` counts how many times it paced -- the testable record of pacing."""
    interval: float = 0.0
    sleeper: Callable[[float], None] = time.sleep
    waits: int = 0

    def wait(self) -> None:
        self.waits += 1
        if self.interval > 0:
            self.sleeper(self.interval)


# ======================================================================================
#  The client.
# ======================================================================================

class RSPClient:
    """A scope-locked GDB-RSP client over one in-scope target.

    Build it from a host+port, an existing `pwn_target.PwnTarget`, a `live_harness.Session`
    (`from_session`), a connect mapping (`from_endpoint`) or an assigned instance
    (`from_instances`). The target is scope-checked (ctf.scope) before any socket opens. `connect()`
    opens the socket; `handshake()` runs qSupported and (by default) switches to no-ack mode.
    """

    def __init__(self, target, port=None, *, packet_size: int = DEFAULT_PACKET_SIZE,
                 read_chunk: int = DEFAULT_READ_CHUNK, **target_kw):
        if isinstance(target, pt.PwnTarget):
            self.target = target
        else:
            self.target = pt.PwnTarget(target, port, **target_kw)
        self.packet_size = int(packet_size)
        self.read_chunk = int(read_chunk)
        self.ack_mode = True
        self.features: dict = {}
        self.packets_sent = 0
        self._buf = b""

    # -- factories ----------------------------------------------------------------------
    @classmethod
    def from_session(cls, session, **kw) -> "RSPClient":
        """Reuse a `live_harness.Session`'s scope-checked PwnTarget as the transport."""
        return cls(session.target, **kw)

    @classmethod
    def from_endpoint(cls, endpoint: Mapping, **kw) -> "RSPClient":
        """Build from a connect-info mapping {"host","port"} (e.g. ctf.instances status)."""
        host = endpoint.get("host")
        port = endpoint.get("port")
        if not host or not port:
            raise ct.OutOfScope(f"endpoint needs host and port; got {endpoint!r}")
        return cls(str(host), int(port), **kw)

    @classmethod
    def from_instances(cls, instances, cid: int, **kw) -> "RSPClient":
        """Build on the host:port of our assigned instance for challenge `cid` (B-003 Instances).

        Reads `instances.status(cid)` once and opens a scoped client on it; it schedules nothing of its
        own. For a target that rotates mid-session, drive `live_harness.InstanceLifecycle` and rebuild
        the client from the new `from_endpoint(life.read_endpoint())`.
        """
        return cls.from_endpoint(instances.status(cid), **kw)

    @property
    def host(self):
        return self.target.host

    @property
    def port(self):
        return self.target.port

    @property
    def transcript(self):
        return self.target.transcript

    # -- connection ---------------------------------------------------------------------
    def connect(self) -> "RSPClient":
        self.target.connect()
        return self

    def close(self) -> None:
        self.target.close()
        self._buf = b""

    def __enter__(self):
        return self.connect()

    def __exit__(self, *exc):
        self.close()
        return False

    # -- the wire -----------------------------------------------------------------------
    def _refill(self) -> bytes:
        chunk = self.target.recv()
        if chunk:
            self._buf += chunk
        return chunk

    def _read_ack(self) -> None:
        """Consume one `+`/`-` acknowledgement (ack mode only). Returns on `+`; raises on `-` so the
        sender can retransmit; a non-ack byte is a protocol error."""
        for _ in range(READ_RETRIES):
            if self._buf:
                b, self._buf = self._buf[:1], self._buf[1:]
                if b == b"+":
                    return
                if b == b"-":
                    raise _Nak()
                raise RSPProtocolError(f"expected an ack (+/-) but got {b!r}")
            if not self._refill():
                raise RSPProtocolError("connection closed while awaiting an ack")
        raise RSPProtocolError("no ack arrived")

    def _write_packet(self, payload: bytes) -> None:
        frame = frame_packet(_as_bytes(payload))
        last_err: Exception | None = None
        for _ in range(MAX_RESEND + 1):
            self.target.send(frame)
            self.packets_sent += 1
            if not self.ack_mode:
                return
            try:
                self._read_ack()
                return
            except _Nak as e:
                last_err = e
                continue
        raise RSPProtocolError(f"packet NAK'd {MAX_RESEND} times, giving up: {payload!r}") from last_err

    def _read_packet(self) -> bytes:
        """Read one complete frame, send our `+` ack (ack mode), and return the DECODED packet data."""
        for _ in range(READ_RETRIES):
            try:
                body, self._buf = parse_frame(self._buf)
            except RSPProtocolError:
                if self.ack_mode:
                    self.target.send(b"-")       # ask for a retransmit of the corrupt frame
                raise
            if body is not None:
                if self.ack_mode:
                    self.target.send(b"+")
                return unescape(body)
            if not self._refill():
                raise RSPProtocolError(f"connection closed mid-frame ({len(self._buf)} byte(s) buffered)")
        raise RSPProtocolError("no complete frame arrived")

    def command(self, payload) -> bytes:
        """Send one packet and return the target's one decoded reply. The unit every method is built on."""
        self._write_packet(_as_bytes(payload))
        return self._read_packet()

    # -- handshake ----------------------------------------------------------------------
    def qsupported(self, features: Sequence[str] = ("multiprocess+", "qXfer:memory-map:read+")) -> dict:
        """Run `qSupported`, store and return the parsed feature map, and record PacketSize.

        The map: `key=value` -> str, `key+`/`key-` -> True/False, `key?` -> "?"."""
        req = b"qSupported"
        if features:
            req += b":" + ";".join(features).encode()
        reply = self.command(req)
        feats = _parse_features(reply)
        self.features = feats
        size = feats.get("PacketSize")
        if isinstance(size, str):
            try:
                self.packet_size = int(size, 16)
            except ValueError:
                raise RSPProtocolError(f"qSupported PacketSize={size!r} is not hex") from None
            # keep the read chunk inside what one reply can carry (hex is 2:1), with headroom for framing.
            self.read_chunk = max(1, min(self.read_chunk, (self.packet_size - 8) // 2))
        return feats

    def start_no_ack_mode(self) -> None:
        """Negotiate `QStartNoAckMode`: after the target's `OK`, neither side sends `+`/`-` again."""
        reply = self.command(b"QStartNoAckMode")
        if reply != b"OK":
            raise RSPError(f"QStartNoAckMode refused (reply {reply!r}); staying in ack mode")
        self.ack_mode = False

    def handshake(self, *, no_ack: bool = True,
                  features: Sequence[str] = ("multiprocess+", "qXfer:memory-map:read+")) -> dict:
        """qSupported, then (default) switch to no-ack mode. Returns the feature map."""
        feats = self.qsupported(features)
        if no_ack and feats.get("QStartNoAckMode") is True:
            self.start_no_ack_mode()
        return feats

    # -- memory map ---------------------------------------------------------------------
    def memory_map(self, *, max_packets: int = MAX_BATCH_PACKETS) -> list:
        """Enumerate the target's memory map via `qXfer:memory-map:read` (chunked until the `l` reply)."""
        xml = self._qxfer_read("memory-map", "", max_packets=max_packets)
        return parse_memory_map(xml)

    def _qxfer_read(self, obj: str, annex: str, *, max_packets: int) -> bytes:
        offset = 0
        out = bytearray()
        for _ in range(max_packets):
            length = max(1, (self.packet_size - 8))
            reply = self.command(f"qXfer:{obj}:read:{annex}:{offset:x},{length:x}".encode())
            if not reply:
                raise RSPProtocolError(f"empty reply to qXfer:{obj}:read")
            if reply[:1] == b"E":
                raise RSPError(f"qXfer:{obj}:read error reply {reply!r}")
            marker, chunk = reply[:1], reply[1:]
            if marker not in (b"m", b"l"):
                raise RSPProtocolError(f"qXfer:{obj}:read reply has no m/l marker: {reply!r}")
            out += chunk
            if marker == b"l":
                return bytes(out)
            offset += len(chunk)
        raise RSPError(f"qXfer:{obj}:read did not terminate within {max_packets} packets")

    # -- memory reads (READ by default) -------------------------------------------------
    def read_memory(self, addr: int, length: int, *, chunk: int | None = None,
                    max_packets: int = MAX_BATCH_PACKETS) -> bytes:
        """Read `length` bytes from `addr` with batched `m` packets, capped near `max_packets`.

        A read that would need more than `max_packets` packets raises rather than silently flooding the
        target: use `walk_pages` to stream a large/MMIO region paced instead. Reads only; sends no `M`.
        """
        if length < 0:
            raise RSPError(f"read length must be >= 0, got {length}")
        chunk = int(chunk) if chunk else self.read_chunk
        if chunk < 1:
            raise RSPError(f"read chunk must be >= 1, got {chunk}")
        packets = (length + chunk - 1) // chunk if length else 0
        if packets > max_packets:
            raise RSPError(
                f"read of {length} bytes needs {packets} `m` packets, over the {max_packets}-packet "
                f"batch cap; stream it with walk_pages(addr, length, page_size=...) instead of a flood")
        out = bytearray()
        remaining = length
        a = addr
        while remaining > 0:
            n = min(chunk, remaining)
            out += self._read_once(a, n)
            a += n
            remaining -= n
        return bytes(out)

    def _read_once(self, addr: int, n: int) -> bytes:
        reply = self.command(f"m{addr:x},{n:x}".encode())
        if reply[:1] == b"E" and len(reply) <= 3:
            raise RSPError(f"m{addr:#x},{n:#x} read error reply {reply!r}")
        try:
            data = bytes.fromhex(reply.decode("latin-1"))
        except ValueError as e:
            raise RSPProtocolError(f"m read reply is not hex: {reply!r}") from e
        if len(data) != n:
            raise RSPProtocolError(f"m{addr:#x},{n:#x} returned {len(data)} bytes, expected {n}")
        return data

    def walk_pages(self, start: int, length: int, *, page_size: int = DEFAULT_WALK_PAGE,
                   pacer: Pacer | None = None) -> Iterable:
        """Yield (page_addr, bytes) over [start, start+length) one paced `m` read per page.

        Each page is a single `m` packet; the pacer delays between pages (MMIO settle time), so the
        walk never bursts the target. Reads only. Build a dict/bytes from what it yields; it decides
        nothing about which page matters -- that stays the operator's.
        """
        if page_size < 1:
            raise RSPError(f"page_size must be >= 1, got {page_size}")
        if length < 0:
            raise RSPError(f"length must be >= 0, got {length}")
        pacer = pacer if pacer is not None else Pacer()
        addr = start
        remaining = length
        first = True
        while remaining > 0:
            n = min(page_size, remaining)
            if not first:
                pacer.wait()
            page = self.read_memory(addr, n, chunk=n, max_packets=1)
            yield addr, page
            addr += n
            remaining -= n
            first = False

    # -- memory writes (allowlisted ONLY) -----------------------------------------------
    def write_memory(self, addr: int, data: bytes, *, allow: Iterable[int]) -> bool:
        """Write `data` to `addr` with one `M` packet -- ONLY if `addr` is in `allow`.

        `allow` is the operator's explicit list of write addresses (e.g. [0x9c]). An address not in it
        is refused loudly: this tool never guesses a write and never sweeps a range of writes. There is
        no bulk/range write by design.
        """
        data = _as_bytes(data)
        allowed = {int(x) for x in allow}
        if not allowed:
            raise RSPError("write_memory refused: `allow` is empty; name the exact address(es) the "
                           "operator confirmed must be written -- writes are never guessed or swept")
        if int(addr) not in allowed:
            raise RSPError(
                f"write_memory refused: {addr:#x} is not in the caller's allow list "
                f"({sorted(hex(x) for x in allowed)}); the host write must be an operator-confirmed "
                f"address, never discovered by this tool")
        reply = self.command(f"M{addr:x},{len(data):x}:{data.hex()}".encode())
        if reply != b"OK":
            raise RSPError(f"M{addr:#x} write failed (reply {reply!r})")
        return True


class _Nak(Exception):
    """Internal: the target sent `-` (retransmit). Never leaves this module."""


def _parse_features(reply: bytes) -> dict:
    feats: dict = {}
    for item in reply.split(b";"):
        if not item:
            continue
        s = item.decode("latin-1")
        if "=" in s:
            k, _, v = s.partition("=")
            feats[k] = v
        elif s[-1:] in ("+", "-", "?"):
            feats[s[:-1]] = {"+": True, "-": False, "?": "?"}[s[-1]]
        else:
            feats[s] = True
    return feats


# ======================================================================================
#  CLI (offline)
# ======================================================================================

def main(argv):
    if not argv:
        print("usage: rsp.py checksum <text> | frame <text> | decode <$...#cs>", file=sys.stderr)
        return 2
    cmd = argv[0]
    if cmd == "checksum":
        if len(argv) < 2:
            print("usage: rsp.py checksum <text>", file=sys.stderr)
            return 2
        print(f"{checksum(argv[1].encode()):02x}")
        return 0
    if cmd == "frame":
        if len(argv) < 2:
            print("usage: rsp.py frame <text>", file=sys.stderr)
            return 2
        sys.stdout.buffer.write(frame_packet(argv[1].encode()) + b"\n")
        return 0
    if cmd == "decode":
        if len(argv) < 2:
            print("usage: rsp.py decode <$...#cs>", file=sys.stderr)
            return 2
        body, rest = parse_frame(argv[1].encode())
        if body is None:
            print("no complete frame", file=sys.stderr)
            return 1
        sys.stdout.buffer.write(unescape(body) + b"\n")
        return 0
    print(f"unknown command {cmd!r}; use: checksum | frame | decode", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
