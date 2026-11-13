#!/usr/bin/env python3
"""Fail-closed, offline network-forensics helpers for supplied artifacts.

This module never opens a socket and never invokes an external program.  It adds an
evidence-oriented layer to the repository's broad :mod:`network` toolkit:

* exact, bounded PCAP/PCAPNG container admission;
* independently checked IPv4/IPv6 TCP extraction and sequence reassembly;
* strict HTTP/1, DNS, WebSocket, and HTTP/2 framing;
* complete SMB2 file objects, filtered through the existing conservative SMB reader;
* TLS 1.3 and QUIC wrappers that expose plaintext only after AEAD authentication; and
* inert TLS/QUIC plans which describe what can be decrypted from caller-supplied keys.

Malformed, truncated, ambiguous, gapped, or conflicting inputs return ``None``.  All
inputs are bytes already supplied by the caller; there is deliberately no path/URL API.
The one opt-in exception is :func:`reassemble_tcp_tolerant` (B-080): it drops bad-checksum
and unparseable TCP segments, keeps the first valid copy of every byte, and reports each
drop, conflicting copy and gap instead of declining the capture.  Strict stays the default.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import hashlib
import ipaddress
import re
import struct
import zlib
from collections import defaultdict
from typing import Iterable, Sequence
from urllib.parse import unquote, urlsplit

try:  # Package import in pytest.
    from . import net_auth as _net_auth
    from . import network as _network
    from . import network_ics_depth as _depth
except ImportError:  # Direct import when solvers/toolkits is on sys.path.
    import net_auth as _net_auth  # type: ignore
    import network as _network  # type: ignore
    import network_ics_depth as _depth  # type: ignore


MAX_CAPTURE = 256 << 20
MAX_PACKETS = 500_000
MAX_PACKET = 16 << 20
MAX_STREAM = 128 << 20
MAX_HTTP_HEAD = 64 << 10
MAX_HTTP_BODY = 64 << 20
MAX_HTTP_MESSAGES = 100_000
MAX_DNS_MESSAGES = 200_000
MAX_DNS_RECORDS = 16_384
MAX_PROTOCOL_FRAMES = 200_000
MAX_KEYLOG = 16 << 20

_PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_SUPPORTED_LINKS = frozenset(_network.LINKTYPES)
_TOKEN = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HTTP_METHOD = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}$")
_KEY_LABEL = re.compile(
    r"^(?:CLIENT_RANDOM|(?:CLIENT|SERVER)_(?:EARLY_|HANDSHAKE_)?TRAFFIC_SECRET(?:_\d+)?|"
    r"EXPORTER_SECRET|EARLY_EXPORTER_SECRET)$"
)


@dataclasses.dataclass(frozen=True, slots=True)
class CaptureArtifact:
    format: str
    packets: int
    linktypes: tuple[int, ...]
    sha256: str
    capture: object = dataclasses.field(repr=False, compare=False)
    dpkt_crosschecked: bool = False


@dataclasses.dataclass(frozen=True, slots=True)
class TCPSegment:
    src: str
    sport: int
    dst: str
    dport: int
    seq: int
    flags: int
    payload: bytes
    timestamp_ns: int | None = None
    packet_index: int = 0
    generation: int = 0


@dataclasses.dataclass(frozen=True, slots=True)
class TCPStream:
    src: str
    sport: int
    dst: str
    dport: int
    generation: int
    first_sequence: int
    data: bytes
    syn: bool
    fin: bool
    complete: bool
    segment_count: int
    retransmitted_bytes: int
    first_timestamp_ns: int | None
    last_timestamp_ns: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class HTTPMessage:
    kind: str
    version: str
    method: str | None
    target: str | None
    status: int | None
    reason: str | None
    headers: tuple[tuple[str, str], ...]
    trailers: tuple[tuple[str, str], ...]
    raw_body: bytes
    body: bytes
    offset: int
    end: int

    def header(self, name: str) -> str | None:
        if type(name) is not str or not isinstance(self.headers, tuple):
            return None
        if any(not isinstance(row, tuple) or len(row) != 2 or
               type(row[0]) is not str or type(row[1]) is not str for row in self.headers):
            return None
        values = [v for k, v in self.headers if k == name.lower()]
        return ", ".join(values) if values else None


@dataclasses.dataclass(frozen=True, slots=True)
class ReconstructedObject:
    protocol: str
    direction: str
    name: str | None
    data: bytes
    sha256: str
    metadata: tuple[tuple[str, str], ...] = ()


@dataclasses.dataclass(frozen=True, slots=True)
class DNSQuestion:
    name: str
    qtype: int
    qclass: int


@dataclasses.dataclass(frozen=True, slots=True)
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    value: object
    raw: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class DNSMessage:
    ident: int
    flags: int
    questions: tuple[DNSQuestion, ...]
    answers: tuple[DNSRecord, ...]
    authority: tuple[DNSRecord, ...]
    additional: tuple[DNSRecord, ...]
    raw: bytes = dataclasses.field(repr=False)

    @property
    def response(self) -> bool:
        return type(self.flags) is int and bool(self.flags & 0x8000)

    @property
    def truncated(self) -> bool:
        return type(self.flags) is int and bool(self.flags & 0x0200)


@dataclasses.dataclass(frozen=True, slots=True)
class DNSDatagram:
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes
    transport: str = "udp"
    timestamp_ns: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class DNSTransaction:
    query: DNSMessage
    response: DNSMessage
    client: str
    server: str
    transport: str
    latency_ns: int | None


@dataclasses.dataclass(frozen=True, slots=True)
class WebSocketMessage:
    opcode: int
    data: bytes
    text: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class WebSocketTranscript:
    messages: tuple[WebSocketMessage, ...]
    pings: tuple[bytes, ...]
    pongs: tuple[bytes, ...]
    close_code: int | None
    close_reason: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class HTTP2Frame:
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class KeyLogEntry:
    label: str
    client_random: bytes
    secret: bytes


@dataclasses.dataclass(frozen=True, slots=True)
class KeyLog:
    entries: tuple[KeyLogEntry, ...]

    def secret(self, client_random: bytes | str, label: str) -> bytes | None:
        if (not isinstance(self.entries, tuple) or len(self.entries) > MAX_PROTOCOL_FRAMES or
                any(not isinstance(entry, KeyLogEntry) or type(entry.label) is not str or
                    type(entry.client_random) is not bytes or type(entry.secret) is not bytes
                    for entry in self.entries)):
            return None
        if type(label) is not str or len(label) > 80 or not _KEY_LABEL.fullmatch(label):
            return None
        try:
            if type(client_random) is str:
                if len(client_random) != 64 or not re.fullmatch(r"[0-9A-Fa-f]{64}", client_random):
                    return None
                random_bytes = bytes.fromhex(client_random)
            elif type(client_random) is bytes:
                random_bytes = client_random
            else:
                return None
        except (ValueError, TypeError, OverflowError):
            return None
        if len(random_bytes) != 32:
            return None
        found = [e.secret for e in self.entries
                 if e.client_random == random_bytes and e.label == label]
        return found[0] if len(found) == 1 else None


@dataclasses.dataclass(frozen=True, slots=True)
class DecryptionPlan:
    protocol: str
    engine: str
    client_random: str
    labels: tuple[str, ...]
    cipher_suite: int | None
    packet_count: int
    notes: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class DecryptedTLS:
    suite: int
    records: tuple[bytes, ...]
    content_types: tuple[int, ...]
    final_epoch: int


@dataclasses.dataclass(frozen=True, slots=True)
class DecryptedQUIC:
    version: int
    packet_number: int
    plaintext: bytes
    frames: tuple[dict, ...] | None
    packet_type: str


def _pcap_layout(data: bytes) -> tuple[int, tuple[int, ...]] | None:
    if len(data) < 24 or data[:4] not in _PCAP_MAGIC:
        return None
    endian, fraction_limit = _PCAP_MAGIC[data[:4]]
    try:
        major, minor, _zone, _sigfigs, snaplen, link_raw = struct.unpack_from(
            endian + "HHiIII", data, 4
        )
    except struct.error:
        return None
    linktype = link_raw & 0x0FFFFFFF
    if major != 2 or minor not in (4,) or not 1 <= snaplen <= MAX_PACKET:
        return None
    if linktype not in _SUPPORTED_LINKS:
        return None
    offset = 24
    count = 0
    while offset < len(data):
        if count >= MAX_PACKETS or offset + 16 > len(data):
            return None
        try:
            _sec, frac, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        except struct.error:
            return None
        if frac >= fraction_limit or captured > snaplen or captured > MAX_PACKET or original < captured:
            return None
        offset += 16
        if offset + captured > len(data):
            return None
        offset += captured
        count += 1
    return count, (linktype,)


def _pcapng_options_valid(body: bytes, offset: int, endian: str) -> bool:
    """Validate a padded pcapng option tail, including its explicit end marker."""
    if offset == len(body):
        return True
    saw_end = False
    while offset + 4 <= len(body):
        code, length = struct.unpack_from(endian + "HH", body, offset)
        offset += 4
        if code == 0:
            if length != 0 or any(body[offset:]):
                return False
            saw_end = True
            offset = len(body)
            break
        padded = (length + 3) & ~3
        if offset + padded > len(body) or any(body[offset + length:offset + padded]):
            return False
        offset += padded
    return offset == len(body) and saw_end


def _pcapng_layout(data: bytes) -> tuple[int, tuple[int, ...]] | None:
    if len(data) < 28 or data[:4] != _PCAPNG_MAGIC:
        return None
    offset = 0
    count = 0
    blocks = 0
    endian: str | None = None
    interfaces: list[tuple[int, int]] = []
    links: set[int] = set()
    saw_section = False
    while offset < len(data):
        if blocks >= MAX_PACKETS * 4 or offset + 12 > len(data):
            return None
        if data[offset:offset + 4] == _PCAPNG_MAGIC:
            if offset + 12 > len(data):
                return None
            bom = data[offset + 8:offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                return None
        if endian is None:
            return None
        block_type, block_len = struct.unpack_from(endian + "II", data, offset)
        if block_len < 12 or block_len & 3 or offset + block_len > len(data):
            return None
        if struct.unpack_from(endian + "I", data, offset + block_len - 4)[0] != block_len:
            return None
        body = data[offset + 8:offset + block_len - 4]
        if block_type == 0x0A0D0D0A:
            if len(body) < 16 or body[:4] not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                return None
            major, minor = struct.unpack_from(endian + "HH", body, 4)
            if major != 1 or minor != 0 or not _pcapng_options_valid(body, 16, endian):
                return None
            interfaces = []
            saw_section = True
        elif not saw_section:
            return None
        elif block_type == 1:  # Interface Description Block
            if len(body) < 8:
                return None
            link, _reserved, snaplen = struct.unpack_from(endian + "HHI", body, 0)
            if link not in _SUPPORTED_LINKS or not 1 <= snaplen <= MAX_PACKET:
                return None
            if not _pcapng_options_valid(body, 8, endian):
                return None
            interfaces.append((link, snaplen))
            links.add(link)
        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                return None
            interface_id, _hi, _lo, captured, original = struct.unpack_from(endian + "IIIII", body, 0)
            if interface_id >= len(interfaces):
                return None
            _link, snaplen = interfaces[interface_id]
            padded = (captured + 3) & ~3
            if captured > snaplen or captured > MAX_PACKET or original < captured or 20 + padded > len(body):
                return None
            if any(body[20 + captured:20 + padded]) or not _pcapng_options_valid(body, 20 + padded, endian):
                return None
            count += 1
        elif block_type == 3:  # Simple Packet Block
            if len(body) < 4 or not interfaces:
                return None
            original = struct.unpack_from(endian + "I", body, 0)[0]
            _link, snaplen = interfaces[0]
            captured = min(original, snaplen)
            padded = (captured + 3) & ~3
            if captured > MAX_PACKET or len(body) != 4 + padded or any(body[4 + captured:]):
                return None
            count += 1
        elif block_type == 2:  # Obsolete Packet Block
            if len(body) < 20:
                return None
            interface_id, _drops, _hi, _lo, captured, original = struct.unpack_from(endian + "HHIIII", body, 0)
            if interface_id >= len(interfaces):
                return None
            _link, snaplen = interfaces[interface_id]
            padded = (captured + 3) & ~3
            if captured > snaplen or captured > MAX_PACKET or original < captured or 20 + padded > len(body):
                return None
            if any(body[20 + captured:20 + padded]) or not _pcapng_options_valid(body, 20 + padded, endian):
                return None
            count += 1
        elif block_type == 0x0000000A:  # Decryption Secrets Block
            if len(body) < 8:
                return None
            _stype, secrets_len = struct.unpack_from(endian + "II", body, 0)
            padded = (secrets_len + 3) & ~3
            if secrets_len > MAX_KEYLOG or 8 + padded > len(body):
                return None
            if any(body[8 + secrets_len:8 + padded]) or not _pcapng_options_valid(body, 8 + padded, endian):
                return None
        if count > MAX_PACKETS:
            return None
        offset += block_len
        blocks += 1
    if not saw_section or not interfaces:
        return None
    return count, tuple(sorted(links))


def _dpkt_count(data: bytes, expected: int) -> bool:
    """Best-effort independent parser cross-check; absence is not an admission failure."""
    try:
        import dpkt  # type: ignore
        from io import BytesIO

        reader = dpkt.pcap.Reader(BytesIO(data)) if data[:4] in _PCAP_MAGIC else dpkt.pcapng.Reader(BytesIO(data))
        return sum(1 for _timestamp, _packet in reader) == expected
    except ImportError:
        return False
    except Exception:
        return False


def admit_capture(data: bytes, *, crosscheck: bool = True) -> CaptureArtifact | None:
    """Admit one exact, bounded PCAP/PCAPNG byte string, else decline with ``None``.

    The validator checks both block/record length copies, packet counts, snap lengths,
    padding, interface references, and exact EOF before invoking the existing parser.
    """
    if not isinstance(crosscheck, bool) or not isinstance(data, bytes) or not 24 <= len(data) <= MAX_CAPTURE:
        return None
    layout = _pcap_layout(data)
    fmt = "pcap"
    if layout is None:
        layout = _pcapng_layout(data)
        fmt = "pcapng"
    if layout is None:
        return None
    expected, links = layout
    try:
        capture = _network.Capture(data, "supplied-capture", limit=MAX_PACKETS + 1)
    except Exception:
        return None
    if capture.damaged is not None or capture.truncated or len(capture.packets) != expected:
        return None
    checked = _dpkt_count(data, expected) if crosscheck else False
    # A present independent parser disagreeing is a reason to decline a classic PCAP.
    # dpkt's pcapng support intentionally rejects several valid block types, so its
    # absence/disagreement there is retained only as metadata.
    if crosscheck and fmt == "pcap":
        try:
            import dpkt  # noqa: F401  # type: ignore
        except ImportError:
            pass
        else:
            if not checked:
                return None
    return CaptureArtifact(fmt, expected, links, hashlib.sha256(data).hexdigest(), capture, checked)


def _checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    total = 0
    # Fixed-size chunks avoid constructing a tuple proportional to a maximum-size packet.
    for offset in range(0, len(data), 65536):
        chunk = data[offset:offset + 65536]
        total += sum(struct.unpack("!%dH" % (len(chunk) // 2), chunk))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _bounded_sequence(value: object, maximum: int) -> bool:
    """True for one non-string Sequence whose reported size is safely bounded."""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return False
    try:
        length = len(value)
    except Exception:
        return False
    return 1 <= length <= maximum


def _network_payload(link: int, raw: bytes) -> tuple[int, bytes] | None:
    offset = 0
    ethertype: int | None = None
    if link == 1:
        if len(raw) < 14:
            return None
        ethertype, offset = int.from_bytes(raw[12:14], "big"), 14
        for _ in range(3):
            if ethertype not in (0x8100, 0x88A8, 0x9100):
                break
            if offset + 4 > len(raw):
                return None
            ethertype, offset = int.from_bytes(raw[offset + 2:offset + 4], "big"), offset + 4
    elif link == 113:
        if len(raw) < 16:
            return None
        ethertype, offset = int.from_bytes(raw[14:16], "big"), 16
    elif link == 276:
        if len(raw) < 20:
            return None
        ethertype, offset = int.from_bytes(raw[:2], "big"), 20
    elif link in (0, 108):
        if len(raw) < 4:
            return None
        first = int.from_bytes(raw[:4], "big" if link == 108 else "little")
        if first > 0xFFFF:
            first = int.from_bytes(raw[:4], "little" if link == 108 else "big")
        ethertype, offset = (0x0800 if first == 2 else 0x86DD if first in (10, 24, 28, 30) else None), 4
    elif link in (12, 14, 101, 228, 229):
        if not raw:
            return None
        ethertype = 0x0800 if raw[0] >> 4 == 4 else 0x86DD if raw[0] >> 4 == 6 else None
    else:
        return None
    if ethertype not in (0x0800, 0x86DD):
        return None
    return ethertype, raw[offset:]


def _tcp_from_packet(packet: object) -> TCPSegment | bool | None:
    """Return a strict TCP segment, False for non-TCP, None for malformed TCP/IP."""
    decoded, problem = _tcp_decode(packet)
    if problem:
        return None
    return decoded


# Problems _tcp_decode names. A checksum problem still returns the parsed segment (or False for a
# non-TCP packet) so the tolerant reader can report what it dropped; any problem is None to the strict
# reader, exactly as before B-080.
CHECKSUM_IPV4 = "ipv4-header-checksum"
CHECKSUM_TCP = "tcp-checksum"
MALFORMED = "malformed"


def _tcp_decode(packet: object) -> tuple[TCPSegment | bool | None, str]:
    """(segment, "") for a valid TCP segment, (False, "") for non-TCP, (None, MALFORMED) for TCP/IP
    that cannot be parsed, and (segment or False, CHECKSUM_IPV4 / CHECKSUM_TCP) when it parses but a
    present checksum does not verify."""
    got = _network_payload(packet.link, bytes(packet.raw))
    if got is None:
        return False, ""
    ethertype, raw = got
    pseudo: bytes
    ip_problem = ""
    if ethertype == 0x0800:
        if len(raw) < 20 or raw[0] >> 4 != 4:
            return None, MALFORMED
        ihl = (raw[0] & 15) * 4
        total = int.from_bytes(raw[2:4], "big")
        if ihl < 20 or ihl > len(raw) or total < ihl or total > len(raw):
            return None, MALFORMED
        if _checksum(raw[:ihl]) != 0:
            ip_problem = CHECKSUM_IPV4
        fragment = int.from_bytes(raw[6:8], "big")
        if fragment & 0x3FFF:
            return False, ip_problem  # IP fragments require separate, authenticated reassembly.
        if raw[9] != 6:
            return False, ip_problem
        src_b, dst_b = raw[12:16], raw[16:20]
        src, dst = str(ipaddress.ip_address(src_b)), str(ipaddress.ip_address(dst_b))
        segment = raw[ihl:total]
        pseudo = src_b + dst_b + b"\x00\x06" + len(segment).to_bytes(2, "big")
    else:
        if len(raw) < 40 or raw[0] >> 4 != 6:
            return None, MALFORMED
        payload_len = int.from_bytes(raw[4:6], "big")
        if payload_len == 0 or 40 + payload_len > len(raw):
            return None, MALFORMED
        end, nxt, offset = 40 + payload_len, raw[6], 40
        for _ in range(8):
            if nxt in (0, 43, 60):
                if offset + 8 > end:
                    return None, MALFORMED
                new, length = raw[offset], (raw[offset + 1] + 1) * 8
            elif nxt == 51:
                if offset + 8 > end:
                    return None, MALFORMED
                new, length = raw[offset], (raw[offset + 1] + 2) * 4
            elif nxt == 44:
                return False, ""
            else:
                break
            if offset + length > end:
                return None, MALFORMED
            nxt, offset = new, offset + length
        if nxt != 6:
            return False, ""
        src_b, dst_b = raw[8:24], raw[24:40]
        src, dst = str(ipaddress.ip_address(src_b)), str(ipaddress.ip_address(dst_b))
        segment = raw[offset:end]
        pseudo = src_b + dst_b + len(segment).to_bytes(4, "big") + b"\x00\x00\x00\x06"
    if len(segment) < 20:
        return None, MALFORMED
    sport, dport, seq = struct.unpack_from("!HHI", segment, 0)
    data_offset = (segment[12] >> 4) * 4
    if not sport or not dport or data_offset < 20 or data_offset > len(segment):
        return None, MALFORMED
    parsed = TCPSegment(src, sport, dst, dport, seq, segment[13], bytes(segment[data_offset:]),
                        packet.ts, packet.i, 0)
    tcp_checksum = int.from_bytes(segment[16:18], "big")
    if tcp_checksum and _checksum(pseudo + segment) != 0:
        return parsed, CHECKSUM_TCP
    return parsed, ip_problem


def _assign_generations(segments: Sequence[TCPSegment]) -> tuple[TCPSegment, ...]:
    generations: dict[tuple[tuple[str, int], tuple[str, int]], int] = defaultdict(int)
    seen_syn: dict[tuple[tuple[str, int], tuple[str, int]], tuple[str, int, int]] = {}
    out: list[TCPSegment] = []
    for segment in sorted(segments, key=lambda s: s.packet_index):
        a, b = (segment.src, segment.sport), (segment.dst, segment.dport)
        pair = (a, b) if a <= b else (b, a)
        if segment.flags & 0x02 and not segment.flags & 0x10:
            signature = (segment.src, segment.sport, segment.seq)
            old = seen_syn.get(pair)
            if old is not None and signature != old:
                generations[pair] += 1
            seen_syn[pair] = signature
        out.append(dataclasses.replace(segment, generation=generations[pair]))
    return tuple(out)


def _extract_tcp(artifact: CaptureArtifact) -> tuple[TCPSegment, ...] | None:
    rows: list[TCPSegment] = []
    for packet in artifact.capture.packets:
        decoded = _tcp_from_packet(packet)
        if decoded is None:
            return None
        if decoded is not False:
            rows.append(decoded)
    return _assign_generations(rows)


def _signed_delta(value: int, anchor: int) -> int:
    delta = (value - anchor) & 0xFFFFFFFF
    return delta - (1 << 32) if delta >= 1 << 31 else delta


def _reassemble_direction(rows: Sequence[TCPSegment]) -> TCPStream | None:
    ordered = sorted(rows, key=lambda s: s.packet_index)
    if not ordered or sum(len(x.payload) for x in ordered) > MAX_STREAM * 4:
        return None
    syns = [x for x in ordered if x.flags & 0x02]
    if syns and any(x.seq != syns[0].seq for x in syns):
        return None
    payload_rows = [x for x in ordered if x.payload]
    if syns:
        anchor = (syns[0].seq + 1) & 0xFFFFFFFF
    else:
        first_sequence = payload_rows[0].seq
        deltas = [_signed_delta(row.seq, first_sequence) for row in payload_rows]
        if max(deltas) - min(deltas) > MAX_STREAM:
            return None
        anchor = (first_sequence + min(deltas)) & 0xFFFFFFFF
    intervals: list[tuple[int, bytes]] = []
    for row in ordered:
        if not row.payload:
            continue
        pos = _signed_delta(row.seq, anchor)
        if pos < 0:
            return None
        payload = row.payload
        if payload:
            intervals.append((pos, payload))
    if not intervals:
        return None
    intervals.sort(key=lambda item: (item[0], len(item[1])))
    if intervals[0][0] != 0:
        return None
    buf = bytearray()
    retransmitted = 0
    for pos, payload in intervals:
        if pos > len(buf):
            return None
        overlap = min(len(payload), len(buf) - pos)
        if overlap and bytes(buf[pos:pos + overlap]) != payload[:overlap]:
            return None
        retransmitted += overlap
        if overlap < len(payload):
            buf.extend(payload[overlap:])
        if len(buf) > MAX_STREAM:
            return None
    fins = [(_signed_delta(x.seq, anchor) + len(x.payload)) for x in ordered if x.flags & 0x01]
    if fins and (len(set(fins)) != 1 or fins[0] != len(buf)):
        return None
    timestamps = [x.timestamp_ns for x in ordered if x.timestamp_ns is not None]
    first = ordered[0]
    return TCPStream(
        first.src, first.sport, first.dst, first.dport, first.generation, anchor, bytes(buf),
        bool(syns), bool(fins), bool(syns and fins), len(ordered), retransmitted,
        min(timestamps) if timestamps else None, max(timestamps) if timestamps else None,
    )


def reassemble_tcp(data: bytes) -> tuple[TCPStream, ...] | None:
    """Strictly reassemble every payload-bearing TCP direction in a supplied capture.

    Identical retransmissions are accepted.  A missing byte, ambiguous sequence span,
    inconsistent FIN, or conflicting overlap declines the entire result.
    """
    artifact = admit_capture(data)
    if artifact is None:
        return None
    segments = _extract_tcp(artifact)
    if segments is None:
        return None
    grouped: dict[tuple[str, int, str, int, int], list[TCPSegment]] = defaultdict(list)
    for segment in segments:
        grouped[(segment.src, segment.sport, segment.dst, segment.dport,
                 segment.generation)].append(segment)
    streams: list[TCPStream] = []
    for key in sorted(grouped):
        if any(row.payload for row in grouped[key]):
            stream = _reassemble_direction(grouped[key])
            if stream is None:
                return None
            streams.append(stream)
    return tuple(streams) if streams else None


# ---- tolerant TCP reassembly (B-080) ------------------------------------------------------------
#
# reassemble_tcp above is strict: one bad checksum or one conflicting retransmission declines the
# whole capture. A forensics capture with forged duplicates (an injected copy of a segment carrying
# other bytes, often with a checksum that does not verify) needs the opposite: keep the stream the
# receiver would have accepted and SAY what was set aside. reassemble_tcp_tolerant is that opt-in
# mode; strict stays the default everywhere. Its rules:
#   1. a TCP segment whose IPv4 header or TCP checksum is present and does not verify is dropped;
#      so is a TCP/IP packet that cannot be parsed. Each drop is reported (DroppedSegment).
#   2. within one direction, bytes are taken in capture order: the first valid copy of a byte wins.
#      A later copy whose bytes differ from the accepted stream is reported (ConflictingSegment);
#      an identical one is a counted retransmission, as in strict mode.
#   3. a hole in the sequence space ends the stream's data (the contiguous prefix is kept) and is
#      reported (StreamGap); a direction that cannot be anchored at all is reported in `declined`.
#   4. data carried in a SYN starts at seq+1 (the SYN takes one sequence number). A segment that
#      straddles the stream start keeps its bytes from the start on; the bytes before it are reported
#      as a DROP_TRIMMED drop. A segment that ends at or before the start is dropped whole.
#   5. the first SYN of a direction anchors it. A later SYN in the same direction and generation
#      whose seq disagrees (a second SYN-ACK with another ISN: a SYN-ACK does not open a generation)
#      is set aside whole, its payload with it, and reported as a DROP_SYN_DISAGREES drop. The strict
#      reader declines such a direction.
#   6. tolerant mode reassembles TCP only. An IPv4 packet it would not use anyway (non-TCP, or an IP
#      fragment) whose header checksum does not verify is still reported, as a DROP_NOT_TCP_BAD_IPV4
#      drop with no addresses; the strict reader declines the whole capture on it. A non-TCP packet
#      with a good checksum is ignored silently, as before.

DROP_NOT_TCP_BAD_IPV4 = "ipv4-header-checksum-not-tcp"  # rule 6: non-TCP or fragment, bad IPv4 checksum
DROP_BEFORE_START = "before-stream-start"
DROP_SYN_DISAGREES = "syn-seq-disagrees"       # a later SYN whose seq differs from the anchoring one
DROP_TRIMMED = "trimmed-before-stream-start"   # the leading bytes of a segment that straddles the start
DROP_TOO_LARGE = "beyond-stream-limit"


@dataclasses.dataclass(frozen=True, slots=True)
class DroppedSegment:
    packet_index: int
    reason: str                 # CHECKSUM_IPV4 | CHECKSUM_TCP | MALFORMED | DROP_BEFORE_START |
                                # DROP_TRIMMED (payload = the trimmed leading bytes) | DROP_TOO_LARGE |
                                # DROP_SYN_DISAGREES | DROP_NOT_TCP_BAD_IPV4
    src: str | None = None
    sport: int | None = None
    dst: str | None = None
    dport: int | None = None
    seq: int | None = None
    payload: bytes = b""


@dataclasses.dataclass(frozen=True, slots=True)
class ConflictingSegment:
    """A valid copy that arrived after the accepted bytes and disagrees with them."""
    src: str
    sport: int
    dst: str
    dport: int
    generation: int
    packet_index: int
    offset: int                 # stream offset of the segment's first byte
    payload: bytes              # what this copy carried
    accepted: bytes             # the accepted stream bytes over the same span
    differing_bytes: int


@dataclasses.dataclass(frozen=True, slots=True)
class StreamGap:
    src: str
    sport: int
    dst: str
    dport: int
    generation: int
    offset: int
    length: int


@dataclasses.dataclass(frozen=True, slots=True)
class TolerantReassembly:
    streams: tuple[TCPStream, ...]
    dropped: tuple[DroppedSegment, ...]
    conflicts: tuple[ConflictingSegment, ...]
    gaps: tuple[StreamGap, ...]
    declined: tuple[str, ...]   # one line per direction that could not be reassembled at all

    def report(self) -> list[str]:
        """One line per stream, drop, conflict, gap and declined direction (for a log or notes)."""
        out = []
        for s in self.streams:
            out.append(f"stream {s.src}:{s.sport} -> {s.dst}:{s.dport} gen {s.generation}: "
                       f"{len(s.data)} bytes, {s.segment_count} segments, "
                       f"{s.retransmitted_bytes} retransmitted bytes, complete={s.complete}")
        for d in self.dropped:
            where = (f" {d.src}:{d.sport} -> {d.dst}:{d.dport} seq {d.seq}" if d.src is not None else "")
            out.append(f"dropped packet {d.packet_index} ({d.reason}){where}, {len(d.payload)} payload bytes")
        for c in self.conflicts:
            out.append(f"conflicting copy in packet {c.packet_index} ({c.src}:{c.sport} -> {c.dst}:{c.dport} "
                       f"offset {c.offset}, {len(c.payload)} bytes, {c.differing_bytes} differ): first copy kept")
        for g in self.gaps:
            out.append(f"gap in {g.src}:{g.sport} -> {g.dst}:{g.dport} at offset {g.offset} "
                       f"({g.length} bytes missing): stream data ends there")
        out.extend(f"declined: {x}" for x in self.declined)
        return out


def _tolerant_direction(rows: Sequence[TCPSegment]) -> tuple[
        TCPStream | None, list[DroppedSegment], list[ConflictingSegment], list[StreamGap], str]:
    """(stream, drops, conflicts, gaps, declined reason) for one direction, first copy wins."""
    ordered = sorted(rows, key=lambda s: s.packet_index)
    first = ordered[0]
    key = (first.src, first.sport, first.dst, first.dport, first.generation)
    drops: list[DroppedSegment] = []
    conflicts: list[ConflictingSegment] = []
    gaps: list[StreamGap] = []
    syns = [x for x in ordered if x.flags & 0x02]
    set_aside = set()
    for x in syns[1:]:
        if x.seq != syns[0].seq:            # rule 5: the first SYN anchors; a disagreeing one is set aside
            set_aside.add(x.packet_index)
            drops.append(DroppedSegment(x.packet_index, DROP_SYN_DISAGREES, x.src, x.sport, x.dst, x.dport,
                                        x.seq, x.payload))
    payload_rows = [x for x in ordered if x.payload and x.packet_index not in set_aside]
    if syns:
        anchor = (syns[0].seq + 1) & 0xFFFFFFFF
    else:
        base = payload_rows[0].seq
        deltas = [_signed_delta(row.seq, base) for row in payload_rows]
        if max(deltas) - min(deltas) > MAX_STREAM:
            return None, drops, conflicts, gaps, (
                f"{first.src}:{first.sport} -> {first.dst}:{first.dport}: sequence span over {MAX_STREAM} "
                f"bytes with no SYN to anchor it")
        anchor = (base + min(deltas)) & 0xFFFFFFFF
    buf = bytearray()
    filled = bytearray()        # 1 where buf holds an accepted byte
    retransmitted = 0
    for row in payload_rows:
        # Data in a SYN starts one past its seq: the SYN flag itself takes one sequence number.
        data_seq = (row.seq + 1) & 0xFFFFFFFF if row.flags & 0x02 else row.seq
        pos = _signed_delta(data_seq, anchor)
        payload = row.payload
        n = len(payload)
        if pos + n <= 0:
            drops.append(DroppedSegment(row.packet_index, DROP_BEFORE_START, row.src, row.sport, row.dst,
                                        row.dport, row.seq, payload))
            continue
        if pos < 0:                         # straddles the start: keep the bytes from the start on
            drops.append(DroppedSegment(row.packet_index, DROP_TRIMMED, row.src, row.sport, row.dst,
                                        row.dport, row.seq, payload[:-pos]))
            payload, pos = payload[-pos:], 0
            n = len(payload)
        end = pos + n
        if end > MAX_STREAM:
            drops.append(DroppedSegment(row.packet_index, DROP_TOO_LARGE, row.src, row.sport, row.dst,
                                        row.dport, row.seq, row.payload))
            continue
        if end > len(buf):
            grow = end - len(buf)
            buf.extend(bytes(grow))
            filled.extend(bytes(grow))
        span = filled[pos:end]
        have = n - span.count(0)
        if have == 0:                       # all new: accept the whole copy
            buf[pos:end] = payload
            filled[pos:end] = b"\x01" * n
            continue
        if have < n:                        # partly new: accept only the bytes not yet held
            for i in range(n):
                if not filled[pos + i]:
                    buf[pos + i] = payload[i]
                    filled[pos + i] = 1
        retransmitted += have
        accepted = bytes(buf[pos:end])
        if accepted != payload:
            differing = sum(1 for a, b in zip(accepted, payload) if a != b)
            conflicts.append(ConflictingSegment(*key, row.packet_index, pos, payload, accepted, differing))
    if not filled:
        return None, drops, conflicts, gaps, (
            f"{first.src}:{first.sport} -> {first.dst}:{first.dport}: no payload byte at or after the "
            f"stream start")
    # The contiguous prefix is the stream; every hole is reported, and the data ends at the first.
    i, length = 0, len(filled)
    while i < length:
        hole = filled.find(0, i)
        if hole < 0:
            break
        back = filled.find(1, hole)
        stop = length if back < 0 else back
        gaps.append(StreamGap(*key, hole, stop - hole))
        i = stop
    data = bytes(buf[:gaps[0].offset]) if gaps else bytes(buf)
    fins = {(_signed_delta(x.seq, anchor) + len(x.payload)) & 0xFFFFFFFF for x in ordered
            if x.flags & 0x01 and x.packet_index not in set_aside}
    fin_ok = len(fins) == 1 and next(iter(fins)) == len(buf)
    timestamps = [x.timestamp_ns for x in ordered if x.timestamp_ns is not None]
    stream = TCPStream(
        first.src, first.sport, first.dst, first.dport, first.generation, anchor, data,
        bool(syns), bool(fins), bool(syns and fin_ok and not gaps), len(ordered), retransmitted,
        min(timestamps) if timestamps else None, max(timestamps) if timestamps else None,
    )
    return stream, drops, conflicts, gaps, ""


def reassemble_tcp_tolerant(data: bytes) -> TolerantReassembly | None:
    """Tolerant, opt-in TCP reassembly: drop bad-checksum and unparseable segments, keep the first
    valid copy of every byte, and report each drop, conflicting copy and gap.

    None only when the capture container itself is not admitted (admit_capture). A capture with no
    payload-bearing TCP gives an empty TolerantReassembly (its drops are still reported).
    """
    artifact = admit_capture(data)
    if artifact is None:
        return None
    dropped: list[DroppedSegment] = []
    rows: list[TCPSegment] = []
    for packet in artifact.capture.packets:
        decoded, problem = _tcp_decode(packet)
        if decoded is False:
            if problem:                     # rule 6: not used, but its bad checksum is still reported
                dropped.append(DroppedSegment(packet.i, DROP_NOT_TCP_BAD_IPV4))
            continue
        if problem or decoded is None:
            if decoded is None:
                dropped.append(DroppedSegment(packet.i, problem or MALFORMED))
            else:
                dropped.append(DroppedSegment(packet.i, problem, decoded.src, decoded.sport, decoded.dst,
                                              decoded.dport, decoded.seq, decoded.payload))
            continue
        rows.append(decoded)
    grouped: dict[tuple[str, int, str, int, int], list[TCPSegment]] = defaultdict(list)
    for segment in _assign_generations(rows):
        grouped[(segment.src, segment.sport, segment.dst, segment.dport, segment.generation)].append(segment)
    streams: list[TCPStream] = []
    conflicts: list[ConflictingSegment] = []
    gaps: list[StreamGap] = []
    declined: list[str] = []
    for key in sorted(grouped):
        if not any(row.payload for row in grouped[key]):
            continue
        stream, d, c, g, why = _tolerant_direction(grouped[key])
        dropped.extend(d)
        conflicts.extend(c)
        gaps.extend(g)
        if stream is None:
            declined.append(why)
        else:
            streams.append(stream)
    dropped.sort(key=lambda x: x.packet_index)
    conflicts.sort(key=lambda x: x.packet_index)
    return TolerantReassembly(tuple(streams), tuple(dropped), tuple(conflicts), tuple(gaps), tuple(declined))


# ---- HTTP/1 object reconstruction ---------------------------------------------------------------


def _header_block(data: bytes, start: int) -> tuple[bytes, int] | None:
    end = data.find(b"\r\n\r\n", start, min(len(data), start + MAX_HTTP_HEAD + 4))
    if end < 0 or end - start > MAX_HTTP_HEAD:
        return None
    return data[start:end], end + 4


def _headers(lines: Sequence[bytes]) -> tuple[tuple[tuple[str, str], ...], dict[str, list[str]]] | None:
    if len(lines) > 256:
        return None
    ordered: list[tuple[str, str]] = []
    grouped: dict[str, list[str]] = defaultdict(list)
    for raw in lines:
        if not raw or raw[:1] in b" \t" or b":" not in raw:
            return None
        name, value = raw.split(b":", 1)
        if not _TOKEN.fullmatch(name):
            return None
        value = value.strip(b" \t")
        if any(byte < 32 and byte != 9 or byte == 127 for byte in value):
            return None
        try:
            key, text = name.decode("ascii").lower(), value.decode("latin-1")
        except UnicodeDecodeError:
            return None
        ordered.append((key, text))
        grouped[key].append(text)
    return tuple(ordered), grouped


def _content_length(headers: dict[str, list[str]]) -> int | None | bool:
    values: list[str] = []
    for raw in headers.get("content-length", []):
        values.extend(piece.strip() for piece in raw.split(","))
    if not values:
        return None
    if any(not value.isdigit() or len(value) > 20 for value in values):
        return False
    numbers = [int(value) for value in values]
    if len(set(numbers)) != 1 or numbers[0] > MAX_HTTP_BODY:
        return False
    return numbers[0]


def _chunked(data: bytes, offset: int) -> tuple[bytes, tuple[tuple[str, str], ...], int] | None:
    body = bytearray()
    chunks = 0
    while True:
        if chunks >= MAX_HTTP_MESSAGES:
            return None
        line_end = data.find(b"\r\n", offset, min(len(data), offset + 8192))
        if line_end < 0:
            return None
        line = data[offset:line_end]
        size_text, separator, extensions = line.partition(b";")
        size_text = size_text.strip()
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", size_text):
            return None
        if separator and (not extensions or any(x < 32 or x == 127 for x in extensions)):
            return None
        size = int(size_text, 16)
        if size > MAX_HTTP_BODY or len(body) + size > MAX_HTTP_BODY:
            return None
        offset = line_end + 2
        if size == 0:
            trailer_end = data.find(b"\r\n\r\n", offset, min(len(data), offset + MAX_HTTP_HEAD + 4))
            if trailer_end < 0:
                # An empty trailer is exactly one CRLF, not CRLFCRLF from this offset.
                if data[offset:offset + 2] != b"\r\n":
                    return None
                return bytes(body), (), offset + 2
            raw_trailers = data[offset:trailer_end]
            parsed = _headers(raw_trailers.split(b"\r\n") if raw_trailers else ())
            if parsed is None:
                return None
            trailers, grouped = parsed
            if any(name in grouped for name in ("content-length", "transfer-encoding", "host")):
                return None
            return bytes(body), trailers, trailer_end + 4
        if offset + size + 2 > len(data) or data[offset + size:offset + size + 2] != b"\r\n":
            return None
        body.extend(data[offset:offset + size])
        offset += size + 2
        chunks += 1


def _decompress_exact(data: bytes, encoding: str) -> bytes | None:
    try:
        if encoding in ("", "identity"):
            out = data
        elif encoding == "gzip":
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            out = decoder.decompress(data, MAX_HTTP_BODY + 1)
            if len(out) > MAX_HTTP_BODY or decoder.unconsumed_tail:
                return None
            out += decoder.flush(MAX_HTTP_BODY + 1 - len(out))
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                return None
        elif encoding == "deflate":
            decoder = zlib.decompressobj(zlib.MAX_WBITS)
            out = decoder.decompress(data, MAX_HTTP_BODY + 1)
            if len(out) > MAX_HTTP_BODY or decoder.unconsumed_tail:
                return None
            out += decoder.flush(MAX_HTTP_BODY + 1 - len(out))
            if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                return None
        elif encoding == "br":
            import brotli  # type: ignore

            decoder = brotli.Decompressor()
            pieces: list[bytes] = []
            total = 0
            for offset in range(0, len(data), 4096):
                piece = decoder.process(data[offset:offset + 4096])
                total += len(piece)
                if total > MAX_HTTP_BODY:
                    return None
                pieces.append(piece)
            if hasattr(decoder, "is_finished") and not decoder.is_finished():
                return None
            out = b"".join(pieces)
        else:
            return None
    except Exception:
        return None
    return bytes(out) if len(out) <= MAX_HTTP_BODY else None


def _decode_codings(data: bytes, codings: Sequence[str]) -> bytes | None:
    output = data
    for coding in reversed(codings):
        got = _decompress_exact(output, coding.strip().lower())
        if got is None:
            return None
        output = got
    return output


def _http_messages(data: bytes, *, eof: bool, response_methods: Sequence[str] = ()) -> tuple[HTTPMessage, ...] | None:
    if not isinstance(data, bytes) or not data or len(data) > MAX_STREAM:
        return None
    offset = 0
    output: list[HTTPMessage] = []
    response_index = 0
    while offset < len(data):
        if len(output) >= MAX_HTTP_MESSAGES:
            return None
        start = offset
        block = _header_block(data, offset)
        if block is None:
            return None
        header_bytes, offset = block
        lines = header_bytes.split(b"\r\n")
        if not lines or not lines[0]:
            return None
        parsed = _headers(lines[1:])
        if parsed is None:
            return None
        ordered, grouped = parsed
        first = lines[0]
        kind: str
        method = target = reason = None
        status = None
        if first.startswith(b"HTTP/"):
            match = re.fullmatch(rb"HTTP/(1\.[01]) ([0-9]{3})(?: ([\x20-\x7e\x80-\xff]*))?", first)
            if not match:
                return None
            kind = "response"
            version = match.group(1).decode("ascii")
            status = int(match.group(2))
            if not 100 <= status <= 599:
                return None
            reason = (match.group(3) or b"").decode("latin-1")
            associated_method = (response_methods[response_index].upper()
                                 if response_index < len(response_methods) else None)
        else:
            pieces = first.split(b" ")
            if len(pieces) != 3 or not _HTTP_METHOD.fullmatch(pieces[0]) or not pieces[1]:
                return None
            match = re.fullmatch(rb"HTTP/(1\.[01])", pieces[2])
            if not match or any(byte < 0x21 or byte > 0x7E for byte in pieces[1]):
                return None
            kind, version = "request", match.group(1).decode("ascii")
            method, target = pieces[0].decode("ascii"), pieces[1].decode("ascii")
            associated_method = method
            if version == "1.1" and method != "CONNECT" and len(grouped.get("host", [])) != 1:
                return None

        content_length = _content_length(grouped)
        if content_length is False:
            return None
        transfer_tokens = [token.strip().lower() for value in grouped.get("transfer-encoding", [])
                           for token in value.split(",") if token.strip()]
        if transfer_tokens and content_length is not None:
            return None
        if transfer_tokens and (transfer_tokens[-1] != "chunked" or
                                transfer_tokens.count("chunked") != 1 or
                                any(token not in ("gzip", "deflate", "chunked") for token in transfer_tokens)):
            return None

        no_body = kind == "response" and (
            status is not None and (100 <= status < 200 or status in (204, 304))
            or associated_method == "HEAD"
            or associated_method == "CONNECT" and status is not None and 200 <= status < 300
        )
        trailers: tuple[tuple[str, str], ...] = ()
        transfer_codings: list[str] = []
        if no_body:
            raw_body = b""
        elif transfer_tokens:
            got = _chunked(data, offset)
            if got is None:
                return None
            raw_body, trailers, offset = got
            transfer_codings = transfer_tokens[:-1]
        elif content_length is not None:
            if offset + content_length > len(data):
                return None
            raw_body = data[offset:offset + content_length]
            offset += content_length
        elif kind == "request":
            raw_body = b""
        else:
            if not eof or any(message.kind == "response" and message.status is not None and
                              message.status >= 200 for message in output):
                return None
            raw_body = data[offset:]
            offset = len(data)

        content_codings = [token.strip().lower() for value in grouped.get("content-encoding", [])
                           for token in value.split(",") if token.strip()]
        decoded_transfer = _decode_codings(raw_body, transfer_codings)
        body = _decode_codings(decoded_transfer, content_codings) if decoded_transfer is not None else None
        if body is None:
            return None
        output.append(HTTPMessage(kind, version, method, target, status, reason, ordered,
                                  trailers, raw_body, body, start, offset))
        if kind == "response" and status is not None and status >= 200:
            response_index += 1
        if offset <= start:
            return None
    return tuple(output)


def decode_http_stream(data: bytes, *, eof: bool = False) -> tuple[HTTPMessage, ...] | None:
    """Decode a complete HTTP/1.x direction with unambiguous message framing.

    A close-delimited final response is accepted only when ``eof=True``.  Compression
    output is bounded and all chunk terminators/trailers must be present.
    """
    if not isinstance(eof, bool):
        return None
    return _http_messages(data, eof=eof)


def _object_name(message: HTTPMessage, fallback_target: str | None) -> str | None:
    disposition = message.header("content-disposition") or ""
    names = re.findall(r"(?i)(?:^|;)\s*filename\*?=(?:UTF-8''([^;]+)|\"([^\"]*)\"|([^;\s]+))", disposition)
    candidate = next((piece for group in names for piece in group if piece), "")
    if candidate:
        candidate = unquote(candidate)
    elif fallback_target:
        try:
            candidate = unquote(urlsplit(fallback_target).path).rstrip("/").rsplit("/", 1)[-1]
        except ValueError:
            candidate = ""
    candidate = candidate.replace("\\", "/").rsplit("/", 1)[-1].strip(".\x00")
    return candidate[:255] or None


def reconstruct_http_objects(client_stream: bytes, server_stream: bytes, *,
                             server_eof: bool = False) -> tuple[ReconstructedObject, ...] | None:
    """Pair strict HTTP requests/responses and return complete uploaded/downloaded bodies."""
    if not isinstance(server_eof, bool):
        return None
    requests = _http_messages(client_stream, eof=False)
    if requests is None or any(message.kind != "request" for message in requests):
        return None
    methods = tuple(message.method or "" for message in requests)
    responses = _http_messages(server_stream, eof=server_eof, response_methods=methods)
    if responses is None or any(message.kind != "response" for message in responses):
        return None
    final = [message for message in responses if message.status is not None and message.status >= 200]
    if len(final) > len(requests):
        return None
    objects: list[ReconstructedObject] = []
    for index, request in enumerate(requests):
        if request.body:
            name = _object_name(request, request.target)
            objects.append(ReconstructedObject(
                "http", "upload", name, request.body, hashlib.sha256(request.body).hexdigest(),
                (("method", request.method or ""), ("target", request.target or "")),
            ))
        if index < len(final):
            response = final[index]
            if response.body and response.status is not None and 200 <= response.status < 300:
                name = _object_name(response, request.target)
                objects.append(ReconstructedObject(
                    "http", "download", name, response.body, hashlib.sha256(response.body).hexdigest(),
                    (("status", str(response.status)), ("target", request.target or "")),
                ))
    return tuple(objects) if objects else None


# ---- DNS -----------------------------------------------------------------------------------------


def _dns_name(message: bytes, offset: int) -> tuple[str, int] | None:
    if not 0 <= offset < len(message):
        return None
    labels: list[bytes] = []
    cursor = offset
    consumed: int | None = None
    visited: set[int] = set()
    wire_length = 1
    for _ in range(128):
        if cursor >= len(message) or cursor in visited:
            return None
        visited.add(cursor)
        length = message[cursor]
        if length & 0xC0 == 0xC0:
            if cursor + 2 > len(message):
                return None
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= cursor or pointer >= len(message):
                return None
            if consumed is None:
                consumed = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0:
            return None
        cursor += 1
        if length == 0:
            if consumed is None:
                consumed = cursor
            break
        if length > 63 or cursor + length > len(message):
            return None
        label = message[cursor:cursor + length]
        wire_length += length + 1
        if wire_length > 255:
            return None
        labels.append(label)
        cursor += length
    else:
        return None

    def render(label: bytes) -> str:
        result = []
        for byte in label:
            if 0x21 <= byte <= 0x7E and byte not in (0x2E, 0x5C):
                result.append(chr(byte))
            else:
                result.append(f"\\{byte:03d}")
        return "".join(result)

    return ".".join(render(label) for label in labels), consumed


def _dns_question(message: bytes, offset: int) -> tuple[DNSQuestion, int] | None:
    got = _dns_name(message, offset)
    if got is None:
        return None
    name, offset = got
    if offset + 4 > len(message):
        return None
    qtype, qclass = struct.unpack_from("!HH", message, offset)
    if qclass == 0:
        return None
    return DNSQuestion(name, qtype, qclass), offset + 4


def _dns_rr(message: bytes, offset: int) -> tuple[DNSRecord, int] | None:
    got = _dns_name(message, offset)
    if got is None:
        return None
    name, offset = got
    if offset + 10 > len(message):
        return None
    rtype, rclass, ttl, length = struct.unpack_from("!HHIH", message, offset)
    start, end = offset + 10, offset + 10 + length
    if end > len(message):
        return None
    raw = message[start:end]
    value: object = raw
    if rtype == 1:
        if length != 4:
            return None
        value = str(ipaddress.ip_address(raw))
    elif rtype == 28:
        if length != 16:
            return None
        value = str(ipaddress.ip_address(raw))
    elif rtype in (2, 5, 12, 39):
        named = _dns_name(message, start)
        if named is None or named[1] != end:
            return None
        value = named[0]
    elif rtype == 15:
        if length < 3:
            return None
        named = _dns_name(message, start + 2)
        if named is None or named[1] != end:
            return None
        value = (int.from_bytes(raw[:2], "big"), named[0])
    elif rtype == 33:
        if length < 7:
            return None
        named = _dns_name(message, start + 6)
        if named is None or named[1] != end:
            return None
        value = (*struct.unpack_from("!HHH", message, start), named[0])
    elif rtype == 6:
        first = _dns_name(message, start)
        second = _dns_name(message, first[1]) if first is not None else None
        if first is None or second is None or second[1] + 20 != end:
            return None
        value = (first[0], second[0], *struct.unpack_from("!IIIII", message, second[1]))
    elif rtype in (16, 99):
        strings: list[bytes] = []
        cursor = start
        while cursor < end:
            size = message[cursor]
            cursor += 1
            if cursor + size > end:
                return None
            strings.append(bytes(message[cursor:cursor + size]))
            cursor += size
        value = tuple(strings)
    elif rtype == 257:
        if length < 2 or raw[1] == 0 or 2 + raw[1] > len(raw):
            return None
        try:
            tag = raw[2:2 + raw[1]].decode("ascii")
            caa_value = raw[2 + raw[1]:].decode("ascii")
        except UnicodeDecodeError:
            return None
        value = (raw[0], tag, caa_value)
    elif rtype == 41:  # OPT: class is UDP size; TTL encodes extended rcode/version/flags.
        options: list[tuple[int, bytes]] = []
        cursor = start
        while cursor < end:
            if cursor + 4 > end:
                return None
            code, size = struct.unpack_from("!HH", message, cursor)
            cursor += 4
            if cursor + size > end:
                return None
            options.append((code, bytes(message[cursor:cursor + size])))
            cursor += size
        value = tuple(options)
    return DNSRecord(name, rtype, rclass, ttl, value, bytes(raw)), end


def decode_dns_message(data: bytes, *, tcp: bool = False) -> DNSMessage | None:
    """Decode exactly one complete DNS message (optionally with its TCP length prefix)."""
    if not isinstance(tcp, bool) or not isinstance(data, bytes) or len(data) > 65537:
        return None
    if tcp:
        if len(data) < 2:
            return None
        length = int.from_bytes(data[:2], "big")
        if length < 12 or length != len(data) - 2:
            return None
        data = data[2:]
    if len(data) < 12:
        return None
    ident, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data, 0)
    if flags & 0x0040 or ((flags >> 11) & 0xF) not in (0, 1, 2, 4, 5):
        return None
    if qd + an + ns + ar > MAX_DNS_RECORDS:
        return None
    offset = 12
    questions: list[DNSQuestion] = []
    for _ in range(qd):
        got = _dns_question(data, offset)
        if got is None:
            return None
        row, offset = got
        questions.append(row)

    sections: list[tuple[DNSRecord, ...]] = []
    for count in (an, ns, ar):
        records: list[DNSRecord] = []
        for _ in range(count):
            got = _dns_rr(data, offset)
            if got is None:
                return None
            row, offset = got
            records.append(row)
        sections.append(tuple(records))
    if offset != len(data):
        return None
    return DNSMessage(ident, flags, tuple(questions), sections[0], sections[1], sections[2], data)


def decode_dns_tcp_stream(data: bytes) -> tuple[DNSMessage, ...] | None:
    """Decode a TCP DNS stream only when every length-prefixed message is complete."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_STREAM:
        return None
    offset = 0
    messages: list[DNSMessage] = []
    while offset < len(data):
        if len(messages) >= MAX_DNS_MESSAGES or offset + 2 > len(data):
            return None
        length = int.from_bytes(data[offset:offset + 2], "big")
        end = offset + 2 + length
        if length < 12 or end > len(data):
            return None
        message = decode_dns_message(data[offset:end], tcp=True)
        if message is None:
            return None
        messages.append(message)
        offset = end
    return tuple(messages) if messages else None


def reconstruct_dns_transactions(datagrams: Sequence[DNSDatagram]) -> tuple[DNSTransaction, ...] | None:
    """Pair unambiguous UDP/TCP DNS queries and responses by endpoints, ID, and question."""
    if not _bounded_sequence(datagrams, MAX_DNS_MESSAGES):
        return None
    queries: dict[tuple, tuple[DNSDatagram, DNSMessage]] = {}
    responses: dict[tuple, tuple[DNSDatagram, DNSMessage]] = {}
    for datagram in datagrams:
        if not isinstance(datagram, DNSDatagram) or type(datagram.transport) is not str or datagram.transport not in ("udp", "tcp"):
            return None
        if (type(datagram.src) is not str or type(datagram.dst) is not str or
                type(datagram.sport) is not int or type(datagram.dport) is not int or
                not 1 <= datagram.sport <= 65535 or not 1 <= datagram.dport <= 65535 or
                not isinstance(datagram.payload, bytes) or
                (datagram.timestamp_ns is not None and type(datagram.timestamp_ns) is not int)):
            return None
        message = decode_dns_message(datagram.payload, tcp=datagram.transport == "tcp")
        if message is None or message.truncated or not message.questions:
            return None
        question_key = tuple((q.name.lower(), q.qtype, q.qclass) for q in message.questions)
        if message.response:
            response_key = (datagram.src, datagram.sport, datagram.dst, datagram.dport,
                            datagram.transport, message.ident, question_key)
            previous = responses.get(response_key)
            if previous is not None and previous[1].raw != message.raw:
                return None
            responses.setdefault(response_key, (datagram, message))
        else:
            key = (datagram.src, datagram.sport, datagram.dst, datagram.dport,
                   datagram.transport, message.ident, question_key)
            # Byte-identical retransmissions are one query; divergent duplicates are ambiguous.
            previous = queries.get(key)
            if previous is not None and previous[1].raw != message.raw:
                return None
            queries.setdefault(key, (datagram, message))
    output: list[DNSTransaction] = []
    used: set[tuple] = set()
    for datagram, response in responses.values():
        question_key = tuple((q.name.lower(), q.qtype, q.qclass) for q in response.questions)
        key = (datagram.dst, datagram.dport, datagram.src, datagram.sport,
               datagram.transport, response.ident, question_key)
        match = queries.get(key)
        if match is None or key in used:
            return None
        query_datagram, query = match
        latency = None
        if query_datagram.timestamp_ns is not None and datagram.timestamp_ns is not None:
            latency = datagram.timestamp_ns - query_datagram.timestamp_ns
            if latency < 0:
                return None
        output.append(DNSTransaction(query, response, datagram.dst, datagram.src,
                                     datagram.transport, latency))
        used.add(key)
    return tuple(output) if output else None


def extract_dns_txt_objects(messages: Sequence[DNSMessage]) -> tuple[ReconstructedObject, ...] | None:
    """Return byte-exact objects from fully validated TXT/SPF resource records."""
    if not _bounded_sequence(messages, MAX_DNS_MESSAGES):
        return None
    output: list[ReconstructedObject] = []
    total_output = 0
    for message in messages:
        if not isinstance(message, DNSMessage) or decode_dns_message(message.raw) != message:
            return None
        for record in (*message.answers, *message.authority, *message.additional):
            if record.rtype not in (16, 99) or not isinstance(record.value, tuple):
                continue
            if not record.value or any(not isinstance(item, bytes) for item in record.value):
                return None
            data = b"".join(record.value)
            if not data or len(data) > MAX_HTTP_BODY:
                continue
            total_output += len(data)
            if total_output > MAX_STREAM or len(output) >= MAX_DNS_RECORDS:
                return None
            output.append(ReconstructedObject(
                "dns-txt", "response", record.name or None, data,
                hashlib.sha256(data).hexdigest(), (("ttl", str(record.ttl)),),
            ))
    return tuple(output) if output else None


def reconstruct_dns_label_object(messages: Sequence[DNSMessage], suffix: str, *,
                                 expected_sha256: str | None = None) -> ReconstructedObject | None:
    """Reassemble a checked base32 DNS tunnel object.

    The explicit CTF framing is ``INDEX-TOTAL-BASE32.suffix`` (one query per
    chunk).  Every index from 1 through TOTAL must occur, duplicates must agree,
    and optional ``expected_sha256`` anchors the final object.
    """
    if not _bounded_sequence(messages, MAX_DNS_MESSAGES) or type(suffix) is not str:
        return None
    if expected_sha256 is not None and type(expected_sha256) is not str:
        return None
    suffix = suffix.strip(".").lower()
    if not suffix or not re.fullmatch(r"[a-z0-9_.-]{1,253}", suffix):
        return None
    if expected_sha256 is not None and not re.fullmatch(r"[0-9a-fA-F]{64}", expected_sha256):
        return None
    chunks: dict[int, bytes] = {}
    total: int | None = None
    for message in messages:
        if not isinstance(message, DNSMessage) or decode_dns_message(message.raw) != message:
            return None
        for question in message.questions:
            lowered = question.name.lower()
            tail = "." + suffix
            if not lowered.endswith(tail):
                continue
            prefix = question.name[:-len(tail)]
            match = re.fullmatch(r"([1-9][0-9]{0,5})-([1-9][0-9]{0,5})-([A-Z2-7]+)", prefix, re.I)
            if not match:
                return None
            index, declared = int(match.group(1)), int(match.group(2))
            if declared > 100_000 or index > declared or (total is not None and total != declared):
                return None
            total = declared
            encoded = match.group(3).upper()
            padding = "=" * ((8 - len(encoded) % 8) % 8)
            try:
                chunk = base64.b32decode(encoded + padding, casefold=False)
            except binascii.Error:
                return None
            canonical = base64.b32encode(chunk).decode("ascii").rstrip("=")
            if canonical != encoded:
                return None
            if index in chunks and chunks[index] != chunk:
                return None
            chunks[index] = chunk
    if total is None or set(chunks) != set(range(1, total + 1)):
        return None
    data = b"".join(chunks[index] for index in range(1, total + 1))
    if not data or len(data) > MAX_HTTP_BODY:
        return None
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256.lower():
        return None
    return ReconstructedObject("dns-label", "query", suffix, data, digest,
                               (("chunks", str(total)),))


# ---- SMB2 verified object facade -----------------------------------------------------------------


def reconstruct_smb2_files(data: bytes) -> tuple[ReconstructedObject, ...] | None:
    """Return only complete SMB2 READ/WRITE objects proven by the supplied capture.

    The repository's SMB reader already understands CREATE/READ/WRITE/CLOSE and file
    IDs.  This facade first requires our independent container and TCP checks, then
    verifies every returned size and digest before exposing bytes.
    """
    artifact = admit_capture(data)
    if artifact is None or reassemble_tcp(data) is None:
        return None
    try:
        transfers = _net_auth.smb_transfers(artifact.capture)
    except Exception:
        return None
    output: list[ReconstructedObject] = []
    for row in transfers or ():
        if row.get("proto") != "smb2" or row.get("complete") is not True:
            continue
        blob = row.get("data")
        if not isinstance(blob, bytes) or not blob or len(blob) > MAX_STREAM:
            continue
        if row.get("size") != len(blob) or row.get("sha256") != hashlib.sha256(blob).hexdigest():
            return None
        direction = row.get("direction")
        if direction not in ("read", "write"):
            return None
        output.append(ReconstructedObject(
            "smb2", "download" if direction == "read" else "upload",
            row.get("name") if isinstance(row.get("name"), str) else None,
            blob, hashlib.sha256(blob).hexdigest(),
            (("path", row.get("path") or ""), ("declared_size", str(row.get("declared_size")))),
        ))
    return tuple(output) if output else None


# ---- WebSocket and HTTP/2 -------------------------------------------------------------------------


def _valid_close_code(code: int) -> bool:
    if 1000 <= code <= 1014:
        return code not in (1004, 1005, 1006)
    return 3000 <= code <= 4999


def decode_websocket_stream(data: bytes, *, from_client: bool) -> WebSocketTranscript | None:
    """Decode one exact RFC 6455 frame stream without negotiated extensions.

    Client frames must be masked and server frames must be unmasked.  Fragment order,
    minimal length encodings, control-frame limits, UTF-8, and close codes are checked.
    """
    if not isinstance(from_client, bool) or not isinstance(data, bytes) or not data or len(data) > MAX_STREAM:
        return None
    offset = 0
    frames = 0
    messages: list[WebSocketMessage] = []
    pings: list[bytes] = []
    pongs: list[bytes] = []
    fragment_opcode: int | None = None
    fragment = bytearray()
    close_code: int | None = None
    close_reason: str | None = None
    closed = False
    while offset < len(data):
        if frames >= MAX_PROTOCOL_FRAMES or closed or offset + 2 > len(data):
            return None
        first, second = data[offset], data[offset + 1]
        offset += 2
        fin, rsv, opcode = bool(first & 0x80), first & 0x70, first & 0x0F
        masked, length = bool(second & 0x80), second & 0x7F
        if rsv or opcode not in (0, 1, 2, 8, 9, 10) or masked != from_client:
            return None
        if length == 126:
            if offset + 2 > len(data):
                return None
            length = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
            if length < 126:
                return None
        elif length == 127:
            if offset + 8 > len(data) or data[offset] & 0x80:
                return None
            length = int.from_bytes(data[offset:offset + 8], "big")
            offset += 8
            if length < 65536:
                return None
        if length > MAX_STREAM:
            return None
        mask = b""
        if masked:
            if offset + 4 > len(data):
                return None
            mask, offset = data[offset:offset + 4], offset + 4
        if offset + length > len(data):
            return None
        payload = bytes(data[offset + index] ^ mask[index & 3] for index in range(length)) if masked \
            else bytes(data[offset:offset + length])
        offset += length
        frames += 1
        if opcode >= 8:
            if not fin or length > 125:
                return None
            if opcode == 8:
                if length == 1:
                    return None
                if length >= 2:
                    close_code = int.from_bytes(payload[:2], "big")
                    if not _valid_close_code(close_code):
                        return None
                    try:
                        close_reason = payload[2:].decode("utf-8")
                    except UnicodeDecodeError:
                        return None
                closed = True
            elif opcode == 9:
                pings.append(payload)
            else:
                pongs.append(payload)
            continue
        if opcode == 0:
            if fragment_opcode is None:
                return None
            fragment.extend(payload)
            if len(fragment) > MAX_STREAM:
                return None
            if not fin:
                continue
            opcode, payload = fragment_opcode, bytes(fragment)
            fragment_opcode, fragment = None, bytearray()
        else:
            if fragment_opcode is not None:
                return None
            if not fin:
                fragment_opcode, fragment = opcode, bytearray(payload)
                continue
        text = None
        if opcode == 1:
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                return None
        messages.append(WebSocketMessage(opcode, payload, text))
    if fragment_opcode is not None:
        return None
    return WebSocketTranscript(tuple(messages), tuple(pings), tuple(pongs), close_code, close_reason)


_HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def _http2_payload_valid(frame_type: int, flags: int, stream: int, payload: bytes) -> bool:
    length = len(payload)
    if frame_type == 0:  # DATA
        if stream == 0:
            return False
        if flags & 0x08:
            return length >= 1 and payload[0] < length
    elif frame_type == 1:  # HEADERS
        if stream == 0:
            return False
        padding = payload[0] if flags & 0x08 and payload else 0
        cursor = 1 if flags & 0x08 else 0
        content_end = length - padding
        if flags & 0x08 and (not payload or content_end < cursor):
            return False
        if flags & 0x20:
            if cursor + 5 > content_end:
                return False
            dependency = int.from_bytes(payload[cursor:cursor + 4], "big") & 0x7FFFFFFF
            if dependency == stream:
                return False
    elif frame_type == 2:  # PRIORITY
        if stream == 0 or length != 5:
            return False
        if int.from_bytes(payload[:4], "big") & 0x7FFFFFFF == stream:
            return False
    elif frame_type == 3:  # RST_STREAM
        if stream == 0 or length != 4:
            return False
    elif frame_type == 4:  # SETTINGS
        if stream != 0 or flags & ~0x01 or (flags & 0x01 and length != 0) or length % 6:
            return False
        seen: set[int] = set()
        for offset in range(0, length, 6):
            ident, value = struct.unpack_from("!HI", payload, offset)
            if ident in seen:
                return False
            seen.add(ident)
            if ident == 2 and value not in (0, 1):
                return False
            if ident == 4 and value > 0x7FFFFFFF:
                return False
            if ident == 5 and not 16384 <= value <= 16777215:
                return False
    elif frame_type == 5:  # PUSH_PROMISE
        if stream == 0:
            return False
        padding = payload[0] if flags & 0x08 and payload else 0
        cursor = 1 if flags & 0x08 else 0
        content_end = length - padding
        if flags & 0x08 and (not payload or content_end < cursor):
            return False
        if cursor + 4 > content_end or not (int.from_bytes(payload[cursor:cursor + 4], "big") & 0x7FFFFFFF):
            return False
    elif frame_type == 6:  # PING
        if stream != 0 or length != 8 or flags & ~0x01:
            return False
    elif frame_type == 7:  # GOAWAY
        if stream != 0 or length < 8:
            return False
    elif frame_type == 8:  # WINDOW_UPDATE
        if length != 4 or not (int.from_bytes(payload, "big") & 0x7FFFFFFF):
            return False
    elif frame_type == 9:  # CONTINUATION
        if stream == 0:
            return False
    return True


def decode_http2_frames(data: bytes, *, expect_preface: bool = False) -> tuple[HTTP2Frame, ...] | None:
    """Decode an exact HTTP/2 frame sequence and enforce connection-level invariants."""
    if not isinstance(expect_preface, bool) or not isinstance(data, bytes) or not data or len(data) > MAX_STREAM:
        return None
    offset = 0
    if expect_preface or data.startswith(_HTTP2_PREFACE):
        if not data.startswith(_HTTP2_PREFACE):
            return None
        offset = len(_HTTP2_PREFACE)
    frames: list[HTTP2Frame] = []
    continuation_stream: int | None = None
    while offset < len(data):
        if len(frames) >= MAX_PROTOCOL_FRAMES or offset + 9 > len(data):
            return None
        length = int.from_bytes(data[offset:offset + 3], "big")
        frame_type, flags = data[offset + 3], data[offset + 4]
        raw_stream = int.from_bytes(data[offset + 5:offset + 9], "big")
        if raw_stream & 0x80000000 or length > 0xFFFFFF or offset + 9 + length > len(data):
            return None
        stream = raw_stream & 0x7FFFFFFF
        payload = bytes(data[offset + 9:offset + 9 + length])
        if continuation_stream is not None:
            if frame_type != 9 or stream != continuation_stream:
                return None
        elif frame_type == 9:
            return None
        if not _http2_payload_valid(frame_type, flags, stream, payload):
            return None
        if frame_type in (1, 5) and not flags & 0x04:
            continuation_stream = stream
        elif frame_type == 9 and flags & 0x04:
            continuation_stream = None
        frames.append(HTTP2Frame(frame_type, flags, stream, payload))
        offset += 9 + length
    if continuation_stream is not None:
        return None
    return tuple(frames) if frames else None


# ---- caller-supplied TLS/QUIC secret orchestration -----------------------------------------------


def parse_keylog(data: bytes) -> KeyLog | None:
    """Strictly parse an NSS key log; conflicting or malformed lines decline."""
    if not isinstance(data, bytes) or not data or len(data) > MAX_KEYLOG:
        return None
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return None
    entries: dict[tuple[str, bytes], bytes] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 3 or not _KEY_LABEL.fullmatch(fields[0]):
            return None
        label, random_hex, secret_hex = fields
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", random_hex) or not re.fullmatch(
            r"[0-9A-Fa-f]+", secret_hex
        ) or len(secret_hex) & 1:
            return None
        client_random = bytes.fromhex(random_hex)
        secret = bytes.fromhex(secret_hex)
        allowed = (48,) if label == "CLIENT_RANDOM" else (32, 48)
        if len(secret) not in allowed:
            return None
        key = (label, client_random)
        if key in entries and entries[key] != secret:
            return None
        entries[key] = secret
    if not entries:
        return None
    result = KeyLog(tuple(KeyLogEntry(label, random, secret)
                         for (label, random), secret in sorted(entries.items(),
                                                               key=lambda item: (item[0][1], item[0][0]))))
    # Cross-check all accepted entries against the installed repository parser.
    try:
        checked = _depth.parse_extended_keylog(data)
    except Exception:
        return None
    if checked.get("conflicts"):
        return None
    for entry in result.entries:
        value = checked.get("sessions", {}).get(entry.client_random.hex(), {}).get(entry.label)
        if value != entry.secret.hex():
            return None
    return result


def _udp_from_packet(packet: object) -> tuple[str, int, str, int, bytes] | bool | None:
    got = _network_payload(packet.link, bytes(packet.raw))
    if got is None:
        return False
    ethertype, raw = got
    if ethertype == 0x0800:
        if len(raw) < 20 or raw[0] >> 4 != 4:
            return None
        ihl, total = (raw[0] & 15) * 4, int.from_bytes(raw[2:4], "big")
        if ihl < 20 or total < ihl or total > len(raw) or _checksum(raw[:ihl]) != 0:
            return None
        if int.from_bytes(raw[6:8], "big") & 0x3FFF:
            return False
        if raw[9] != 17:
            return False
        src_b, dst_b = raw[12:16], raw[16:20]
        datagram = raw[ihl:total]
        pseudo = src_b + dst_b + b"\x00\x11" + len(datagram).to_bytes(2, "big")
    else:
        if len(raw) < 40 or raw[0] >> 4 != 6:
            return None
        payload_len = int.from_bytes(raw[4:6], "big")
        if not payload_len or 40 + payload_len > len(raw):
            return None
        end, nxt, offset = 40 + payload_len, raw[6], 40
        for _ in range(8):
            if nxt in (0, 43, 60):
                if offset + 8 > end:
                    return None
                new, length = raw[offset], (raw[offset + 1] + 1) * 8
            elif nxt == 51:
                if offset + 8 > end:
                    return None
                new, length = raw[offset], (raw[offset + 1] + 2) * 4
            elif nxt == 44:
                return False
            else:
                break
            if offset + length > end:
                return None
            nxt, offset = new, offset + length
        if nxt != 17:
            return False
        src_b, dst_b = raw[8:24], raw[24:40]
        datagram = raw[offset:end]
        pseudo = src_b + dst_b + len(datagram).to_bytes(4, "big") + b"\x00\x00\x00\x11"
    if len(datagram) < 8:
        return None
    sport, dport, length, checksum = struct.unpack_from("!HHHH", datagram, 0)
    if not sport or not dport or length < 8 or length != len(datagram):
        return None
    if ethertype == 0x86DD and checksum == 0:
        return None
    if checksum and _checksum(pseudo + datagram) != 0:
        return None
    return (str(ipaddress.ip_address(src_b)), sport, str(ipaddress.ip_address(dst_b)), dport,
            bytes(datagram[8:]))


def plan_tls_decryption(data: bytes, keylog: bytes) -> tuple[DecryptionPlan, ...] | None:
    """Create inert per-session TLS plans after capture/key-log correlation.

    Plans contain no secret material and execute nothing.  TLS 1.3 sessions name the
    in-process authenticated engine; older ``CLIENT_RANDOM`` sessions name an offline
    NSS-key-log dissector plan.
    """
    artifact, parsed = admit_capture(data), parse_keylog(keylog)
    if artifact is None or parsed is None or reassemble_tcp(data) is None:
        return None
    entries: dict[bytes, list[KeyLogEntry]] = defaultdict(list)
    for entry in parsed.entries:
        entries[entry.client_random].append(entry)
    output: list[DecryptionPlan] = []
    try:
        hellos = artifact.capture.tls()
    except Exception:
        return None
    for hello in hellos:
        try:
            random_bytes = bytes.fromhex(hello.client_random)
        except (TypeError, ValueError):
            continue
        selected = entries.get(random_bytes, [])
        if not selected:
            continue
        labels = tuple(sorted(entry.label for entry in selected))
        cipher = hello.cipher if isinstance(hello.cipher, int) else None
        native = cipher in (0x1301, 0x1302, 0x1303) and any(
            "TRAFFIC_SECRET" in label for label in labels
        )
        output.append(DecryptionPlan(
            "tls", "network_ics_depth.decrypt_tls13_keylog" if native else "offline-nss-keylog-dissector",
            random_bytes.hex(), labels, cipher, artifact.packets,
            ("supplied capture only", "AEAD tags must verify before plaintext is exposed",
             "no process or network action is performed"),
        ))
    return tuple(output) if output else None


def plan_quic_decryption(data: bytes, keylog: bytes, *,
                         client_random: bytes | str | None = None) -> DecryptionPlan | None:
    """Create an inert QUIC decryption plan from strict UDP packets and supplied secrets."""
    artifact, parsed = admit_capture(data), parse_keylog(keylog)
    if artifact is None or parsed is None:
        return None
    sessions = sorted({entry.client_random for entry in parsed.entries})
    if client_random is None:
        if len(sessions) != 1:
            return None
        selected_random = sessions[0]
    else:
        try:
            if isinstance(client_random, str):
                if len(client_random) != 64 or not re.fullmatch(r"[0-9A-Fa-f]{64}", client_random):
                    return None
                selected_random = bytes.fromhex(client_random)
            elif isinstance(client_random, bytes):
                selected_random = client_random
            else:
                return None
        except (TypeError, ValueError, OverflowError):
            return None
        if len(selected_random) != 32 or selected_random not in sessions:
            return None
    quic_packets = 0
    versions: set[int] = set()
    for packet in artifact.capture.packets:
        row = _udp_from_packet(packet)
        if row is None:
            return None
        if row is False:
            continue
        payload = row[4]
        if len(payload) >= 17 and payload[0] & 0x40:
            if payload[0] & 0x80:
                if len(payload) < 7:
                    return None
                version = int.from_bytes(payload[1:5], "big")
                if version:
                    versions.add(version)
            quic_packets += 1
    if not quic_packets or any(version not in (1, 0x6B3343CF) for version in versions):
        return None
    labels = tuple(sorted(entry.label for entry in parsed.entries
                          if entry.client_random == selected_random and "TRAFFIC_SECRET" in entry.label))
    if not labels:
        return None
    return DecryptionPlan(
        "quic", "network_ics_depth.decrypt_quic_long/short_keylog", selected_random.hex(),
        labels, None, quic_packets,
        ("caller supplies cipher suite and short-header DCID length",
         "header protection and AEAD tag are verified before plaintext is exposed",
         "no packet is transmitted"),
    )


def decrypt_tls13(records: bytes | Sequence[bytes], keylog: bytes, client_random: bytes | str,
                  label: str, suite: int, *, search_updates: int = 0) -> DecryptedTLS | None:
    """Decrypt complete TLS 1.3 records, returning content only after every tag verifies."""
    if (not isinstance(records, (bytes, list, tuple)) or
            isinstance(records, bytes) and len(records) > MAX_STREAM or
            isinstance(records, (list, tuple)) and len(records) > MAX_PROTOCOL_FRAMES or
            isinstance(records, (list, tuple)) and any(not isinstance(row, bytes) for row in records) or
            not isinstance(keylog, bytes) or not isinstance(client_random, (bytes, str)) or
            not isinstance(label, str) or len(label) > 80 or not _KEY_LABEL.fullmatch(label) or
            type(suite) is not int or suite not in (0x1301, 0x1302, 0x1303) or
            type(search_updates) is not int or not 0 <= search_updates <= 8):
        return None
    parsed = parse_keylog(keylog)
    if parsed is None or parsed.secret(client_random, label) is None:
        return None
    try:
        result = _depth.decrypt_tls13_keylog(records, keylog, client_random, label, suite,
                                             search_updates=search_updates)
    except Exception:
        return None
    rows = result.get("records") if isinstance(result, dict) else None
    if result.get("verified") is not True or result.get("complete") is not True or not isinstance(rows, list) or not rows:
        return None
    contents: list[bytes] = []
    content_types: list[int] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or row.get("index") != index or not isinstance(row.get("content"), bytes):
            return None
        if row.get("content_type") not in (20, 21, 22, 23, 24):
            return None
        contents.append(row["content"])
        content_types.append(row["content_type"])
    epoch = result.get("final_epoch")
    if not isinstance(epoch, int) or epoch < 0:
        return None
    return DecryptedTLS(suite, tuple(contents), tuple(content_types), epoch)


def decrypt_quic_packet(packet: bytes, keylog: bytes, client_random: bytes | str,
                        label: str, suite: int, *, dcid_length: int | None = None,
                        largest_packet_number: int = -1, search_updates: int = 0) -> DecryptedQUIC | None:
    """Remove QUIC header protection and expose only uniquely AEAD-authenticated plaintext."""
    if (not isinstance(packet, bytes) or not isinstance(keylog, bytes) or
            not isinstance(client_random, (bytes, str)) or not isinstance(label, str) or
            len(label) > 80 or not _KEY_LABEL.fullmatch(label) or type(suite) is not int or
            suite not in (0x1301, 0x1302, 0x1303) or
            (dcid_length is not None and (type(dcid_length) is not int or not 0 <= dcid_length <= 20)) or
            type(largest_packet_number) is not int or not -1 <= largest_packet_number < 1 << 62 or
            type(search_updates) is not int or not 0 <= search_updates <= 8):
        return None
    parsed = parse_keylog(keylog)
    secret = parsed.secret(client_random, label) if parsed is not None else None
    if secret is None or not isinstance(packet, bytes) or not packet:
        return None
    try:
        if packet[0] & 0x80:
            result = _depth.decrypt_quic_long(packet, secret, suite,
                                              largest_packet_number=largest_packet_number)
            if result is not None and result.get("packet_length") != len(packet):
                return None
        else:
            if dcid_length is None:
                return None
            result = _depth.decrypt_quic_short(
                packet, secret, suite, dcid_length,
                largest_packet_number=largest_packet_number, search_updates=search_updates,
            )
    except Exception:
        return None
    if not isinstance(result, dict) or result.get("verified") is not True:
        return None
    plaintext, packet_number, version = (result.get("plaintext"), result.get("packet_number"),
                                         result.get("version"))
    if not isinstance(plaintext, bytes) or not isinstance(packet_number, int) or not isinstance(version, int):
        return None
    frames = result.get("frames")
    if frames is not None and (not isinstance(frames, list) or
                               any(not isinstance(frame, dict) for frame in frames)):
        return None
    return DecryptedQUIC(version, packet_number, plaintext,
                         tuple(frames) if frames is not None else None,
                         str(result.get("packet_type") or "one_rtt"))


__all__ = [
    "CaptureArtifact", "TCPSegment", "TCPStream", "HTTPMessage", "ReconstructedObject",
    "DNSQuestion", "DNSRecord", "DNSMessage", "DNSDatagram", "DNSTransaction",
    "WebSocketMessage", "WebSocketTranscript", "HTTP2Frame", "KeyLogEntry", "KeyLog",
    "DecryptionPlan", "DecryptedTLS", "DecryptedQUIC", "admit_capture", "reassemble_tcp",
    "decode_http_stream", "reconstruct_http_objects", "decode_dns_message",
    "decode_dns_tcp_stream", "reconstruct_dns_transactions", "extract_dns_txt_objects",
    "reconstruct_dns_label_object", "reconstruct_smb2_files", "decode_websocket_stream",
    "decode_http2_frames", "parse_keylog", "plan_tls_decryption", "plan_quic_decryption",
    "decrypt_tls13", "decrypt_quic_packet",
]
