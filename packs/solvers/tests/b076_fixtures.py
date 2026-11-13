"""B-076 test fixtures, built synthetically: a pcap writer for HTTP over TCP and a socat -v -x log writer
with an XMODEM sender/receiver. No challenge file is read or copied; the shapes follow the public formats
(libpcap, socat's hexdump, XMODEM/XMODEM-CRC/XMODEM-1K)."""
from __future__ import annotations

import base64
import binascii
import struct

# ---------------------------------------------------------------- pcap


def _ip_checksum(h: bytes) -> int:
    s = sum(struct.unpack("!%dH" % (len(h) // 2), h))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def _packet(src, dst, sport, dport, seq, ack, flags, payload=b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0)
    total = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 6, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    eth = b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02" + b"\x08\x00"
    return eth + ip + tcp + payload


class Pcap:
    """An Ethernet pcap; conversation() adds one whole TCP connection (handshake, request, response, FINs)."""

    def __init__(self):
        self.frames = []
        self.t = 1_700_000_000.0
        self.port = 40000

    def _add(self, frame):
        self.t += 0.001
        self.frames.append((self.t, frame))

    def conversation(self, request: bytes, response: bytes | None, client=(10, 0, 0, 2), server=(10, 0, 0, 1),
                     dport=80):
        c, s = bytes(client), bytes(server)
        self.port += 1
        cp = self.port
        ci, si = 1000, 5000
        self._add(_packet(c, s, cp, dport, ci, 0, 0x02))
        self._add(_packet(s, c, dport, cp, si, ci + 1, 0x12))
        self._add(_packet(c, s, cp, dport, ci + 1, si + 1, 0x10))
        self._add(_packet(c, s, cp, dport, ci + 1, si + 1, 0x18, request))
        cseq = ci + 1 + len(request)
        sseq = si + 1
        if response is not None:
            self._add(_packet(s, c, dport, cp, sseq, cseq, 0x18, response))
            sseq += len(response)
        self._add(_packet(s, c, dport, cp, sseq, cseq, 0x11))
        self._add(_packet(c, s, cp, dport, cseq, sseq + 1, 0x11))
        self._add(_packet(s, c, dport, cp, sseq + 1, cseq + 1, 0x10))

    def bytes(self) -> bytes:
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for t, f in self.frames:
            sec = int(t)
            out += struct.pack("<IIII", sec, int((t - sec) * 1e6), len(f), len(f)) + f
        return out


def http_request(method: str, path: str, headers=(), body: bytes = b"", host="bridge.local") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"] + [f"{k}: {v}" for k, v in headers]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(status: int, reason: str, headers=(), body: bytes = b"") -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}", "Content-Type: text/plain", f"Content-Length: {len(body)}"]
    lines += [f"{k}: {v}" for k, v in headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def basic(user: str, pw: str) -> str:
    return "Basic " + b64(f"{user}:{pw}")


# ---------------------------------------------------------------- socat -v -x


def socat_record(direction: str, data: bytes, start: int, ts: str = "2026/10/07 12:17:40.615989",
                 length: int | None = None) -> str:
    """One record as socat -v -x writes it: the header, then rows of at most 16 bytes, a row ending early
    after a 0x0a byte, each byte as ' %02x', the ASCII column after padding and two spaces, then '--'."""
    n = len(data) if length is None else length
    out = [f"{direction} {ts}  length={n} from={start} to={start + n - 1}"]
    row = bytearray()

    def flush():
        hexpart = "".join(f" {b:02x}" for b in row)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        out.append(hexpart.ljust(16 * 3) + "  " + text)

    for b in data:
        row.append(b)
        if b == 0x0A or len(row) == 16:
            flush()
            row = bytearray()
    if row:
        flush()
    out.append("--")
    return "\n".join(out) + "\n"


class SocatLog:
    """Records in order; each direction keeps its own from= offset."""

    def __init__(self):
        self.parts = []
        self.off = {">": 0, "<": 0}
        self.sec = 0

    def add(self, direction: str, data: bytes, length: int | None = None):
        self.sec += 1
        ts = f"2026/10/07 12:{17 + self.sec // 60:02d}:{self.sec % 60:02d}.{self.sec:06d}"
        self.parts.append(socat_record(direction, data, self.off[direction], ts, length))
        self.off[direction] += len(data)

    def text(self) -> str:
        return "".join(self.parts)


SOH, STX, EOT, ACK, NAK, CAN = 1, 2, 4, 6, 0x15, 0x18


def xmodem_block(n: int, data: bytes, crc: bool = False, size: int = 128, corrupt: bool = False) -> bytes:
    body = data.ljust(size, b"\x1a")
    head = bytes([SOH if size == 128 else STX, n & 0xFF, 0xFF - (n & 0xFF)])
    if crc:
        check = struct.pack(">H", binascii.crc_hqx(body, 0))
    else:
        check = bytes([sum(body) & 0xFF])
    if corrupt:
        check = bytes([check[0] ^ 0xFF]) + check[1:]
    return head + body + check


def xmodem_send(log: SocatLog, payload: bytes, *, sender=">", crc=False, size=128, nak_first=(), dup_after=(),
                eot_nak=False, receiver=True, eot_ack=True, start=True):
    """One XMODEM transfer of `payload` into `log`: the receiver's start (NAK or 'C'; none with
    start=False), each block ACKed (a block whose number is in `nak_first` is first sent corrupted and
    NAKed; one in `dup_after` is re-sent once after its ACK, as when the ACK is lost), then EOT (NAKed
    once first with eot_nak; never answered with eot_ack=False, as in the Xenoglossophobia log, whose
    receiver left the first EOT unanswered and NAKed again later to start the second transfer)."""
    rx = "<" if sender == ">" else ">"
    if receiver and start:
        log.add(rx, b"C" if crc else bytes([NAK]))
    chunks = [payload[i:i + size] for i in range(0, len(payload), size)] or [b""]
    for i, chunk in enumerate(chunks, 1):
        if i in nak_first:
            log.add(sender, xmodem_block(i, chunk, crc, size, corrupt=True))
            if receiver:
                log.add(rx, bytes([NAK]))
        log.add(sender, xmodem_block(i, chunk, crc, size))
        if receiver:
            log.add(rx, bytes([ACK]))
        if i in dup_after:
            log.add(sender, xmodem_block(i, chunk, crc, size))
            if receiver:
                log.add(rx, bytes([ACK]))
    if eot_nak:
        log.add(sender, bytes([EOT]))
        if receiver:
            log.add(rx, bytes([NAK]))
    log.add(sender, bytes([EOT]))
    if receiver and eot_ack:
        log.add(rx, bytes([ACK]))


def fake_jpeg(n: int = 300) -> bytes:
    """JPEG-shaped bytes (SOI/APP0 ... EOI) with every byte value in the body, newlines included."""
    body = bytes((i * 37 + 11) % 256 for i in range(n))
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + body + b"\xff\xd9"
