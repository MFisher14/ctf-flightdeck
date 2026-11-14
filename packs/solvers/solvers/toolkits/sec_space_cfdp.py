#!/usr/bin/env python3
"""CFDP (CCSDS 727.0-B-5) PDU parser, File Data coverage tracker and NAK PDU builder.

A capture of a CFDP file transfer with missing File Data has one deterministic answer to "which NAK
would the receiver send": the complement of the received byte coverage, serialised as a NAK PDU. This
module does that mechanical part with no model:

    walk_space_packets(raw) / walk_pdus(raw)   the outer framing (no resynchronisation)
    parse_pdu(data)                            fixed header + Metadata, File Data, EOF, NAK (and the rest by name)
    survey(raw)                                every transaction in a capture, its coverage and gaps
    skeleton(row, framing)                     a filter config pre-filled with one surveyed transaction
    parse_filter(d) / load_filter(path)        the mission filter (TOML): selection, state policy, NAK, output
    reconstruct(raw, flt)                      run the filter; coverage, missing ranges, the NAK PDU(s)
    build_nak(...)                             serialise a NAK PDU
    render_output(pdu, output, profile)        the answer in the stated format, through ctf.flagfmt
    solve(challenge_dir, profile, **opts)      the engine entry (docs/CONTRACTS.md sections 6-7)

What stays with the reader: WHICH packets and PDUs count. A challenge's mission profile states that in
prose (APID, the entity/transaction tuple, which Metadata and EOF are accepted, what happens to data
before Metadata). None of it is assumed here: every such rule is a key of the filter config. A key
that is not stated is not checked, and the state policy defaults to the CFDP standard receiver, never
to one challenge's rules. Without a filter the engine only surveys. The answer format is a parameter
too (`[output]`): a handout may override the board's format.

Captured bytes are data. Nothing here opens a socket or runs anything.

Reference: CCSDS 727.0-B-5 (CFDP), CCSDS 133.0-B-2 (Space Packet). Usage: docs/toolkits/sec_space_cfdp.md.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import fnmatch
import hashlib
import json
import re
import sys
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ENGINE_ID = "toolkits.sec_space_cfdp"
FILTER_NAME = "cfdp-filter.toml"          # looked for at the top of the challenge folder
MAX_STREAM = 16 * 1024 * 1024             # a larger file is not read (named in the result)
MAX_UNITS = 1_000_000
MAX_DATA_FIELD = 0xFFFF                   # the PDU data field length is 16 bits

FRAMINGS = ("space-packet", "cfdp-pdu")
DIRECTIONS = ("toward-receiver", "toward-sender")
MODES = ("acknowledged", "unacknowledged")
PACKET_TYPES = ("tm", "tc")
DIRECTIVES = {0x04: "eof", 0x05: "finished", 0x06: "ack", 0x07: "metadata", 0x08: "nak",
              0x09: "prompt", 0x0C: "keep-alive"}
NAK_CODE = 0x08
ENCODINGS = ("hex-upper", "hex-lower", "base64")
WRAPS = ("flag", "none")


class CfdpError(ValueError):
    """A stream or PDU that is malformed, truncated or outside what this module reads."""


class AmbiguousTransaction(CfdpError):
    """The filter lets PDUs of more than one transaction through; the message lists them."""


class FilterError(ValueError):
    """A filter config that is missing a key or holds a bad one. The message names the dotted key."""


class OutputError(ValueError):
    """The answer cannot be rendered in the stated format; the message says what is missing."""


# ------------------------------------------------------------------------------------------ framing

@dataclass(frozen=True)
class Unit:
    """One framing unit: a Space Packet's user data, or one bare PDU."""
    index: int
    offset: int                     # of the unit (packet primary header, or the PDU) in the stream
    data_offset: int                # of `data` in the stream
    data: bytes                     # the bytes that should be one CFDP PDU
    packet: Mapping[str, Any] | None = None   # the Space Packet primary header fields, when there is one


def _raw(data: object, what: str) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise CfdpError(f"{what} must be bytes, not {type(data).__name__}")
    raw = bytes(data)
    if len(raw) > MAX_STREAM:
        raise CfdpError(f"{what} is {len(raw)} bytes, over the {MAX_STREAM}-byte limit")
    return raw


def walk_space_packets(data: object) -> list[Unit]:
    """Walk an exact concatenation of CCSDS Space Packets: six primary-header octets, then
    packet-data-length + 1 user-data octets. A truncated recording is an error; there is no
    resynchronisation. The packet version is reported, not judged (a filter selects on it)."""
    raw = _raw(data, "the Space Packet stream")
    if not raw:
        raise CfdpError("the Space Packet stream is empty")
    units: list[Unit] = []
    i, n = 0, len(raw)
    while i < n:
        if n - i < 6:
            raise CfdpError(f"truncated Space Packet primary header at offset {i} ({n - i} of 6 octets)")
        word = int.from_bytes(raw[i:i + 2], "big")
        control = int.from_bytes(raw[i + 2:i + 4], "big")
        size = int.from_bytes(raw[i + 4:i + 6], "big") + 1
        if n - i - 6 < size:
            raise CfdpError(f"truncated Space Packet at offset {i}: the header declares {size} "
                            f"user-data octets, {n - i - 6} remain")
        if len(units) >= MAX_UNITS:
            raise CfdpError(f"more than {MAX_UNITS} Space Packets in the stream")
        units.append(Unit(
            index=len(units), offset=i, data_offset=i + 6, data=raw[i + 6:i + 6 + size],
            packet={
                "pvn": word >> 13,
                "type": PACKET_TYPES[(word >> 12) & 1],
                "secondary_header": bool(word & 0x0800),
                "apid": word & 0x07FF,
                "sequence_flags": control >> 14,
                "sequence_count": control & 0x3FFF,
            }))
        i += 6 + size
    return units


def _header_length(raw: bytes, at: int, what: str) -> tuple[int, int]:
    """(fixed + variable header length, data field length) of the PDU starting at `at`."""
    if len(raw) - at < 4:
        raise CfdpError(f"truncated CFDP fixed header {what} ({len(raw) - at} of 4 octets)")
    data_length = int.from_bytes(raw[at + 1:at + 3], "big")
    id_length = ((raw[at + 3] >> 4) & 7) + 1
    seq_length = (raw[at + 3] & 7) + 1
    return 4 + 2 * id_length + seq_length, data_length


def walk_pdus(data: object) -> list[Unit]:
    """Walk an exact concatenation of bare CFDP PDUs by their declared lengths (no resynchronisation)."""
    raw = _raw(data, "the CFDP PDU stream")
    if not raw:
        raise CfdpError("the CFDP PDU stream is empty")
    units: list[Unit] = []
    i, n = 0, len(raw)
    while i < n:
        header, body = _header_length(raw, i, f"at offset {i}")
        if n - i < header + body:
            raise CfdpError(f"truncated CFDP PDU at offset {i}: it declares {header + body} octets, "
                            f"{n - i} remain")
        if len(units) >= MAX_UNITS:
            raise CfdpError(f"more than {MAX_UNITS} PDUs in the stream")
        units.append(Unit(index=len(units), offset=i, data_offset=i, data=raw[i:i + header + body]))
        i += header + body
    return units


def walk(data: object, framing: str) -> list[Unit]:
    if framing == "space-packet":
        return walk_space_packets(data)
    if framing == "cfdp-pdu":
        return walk_pdus(data)
    raise CfdpError(f"unknown framing {framing!r} (one of: {', '.join(FRAMINGS)})")


# ---------------------------------------------------------------------------------------------- PDU

def crc16(data: bytes) -> int:
    """The CFDP PDU CRC: CRC-16 with polynomial 0x1021 and an all-ones preset (the CCSDS FECF CRC)."""
    return binascii.crc_hqx(bytes(data), 0xFFFF)


@dataclass(frozen=True)
class Pdu:
    version: int
    kind: str                       # file-data | metadata | eof | nak | finished | ack | prompt | keep-alive | directive-0xNN
    file_directive: bool
    direction: str                  # toward-receiver | toward-sender
    mode: str                       # acknowledged | unacknowledged
    crc: bool
    large_file: bool
    data_field_length: int
    segmentation_control: bool
    entity_id_length: int
    segment_metadata: bool
    sequence_number_length: int
    source: int
    sequence: int
    destination: int
    header_length: int
    fields: Mapping[str, Any] = field(default_factory=dict)
    payload: bytes = b""            # File Data only: the file octets

    @property
    def identity(self) -> tuple[int, int, int, int, int]:
        """What makes two PDUs the same transaction: the ID lengths and source/sequence/destination."""
        return (self.entity_id_length, self.sequence_number_length, self.source, self.sequence,
                self.destination)

    def to_dict(self) -> dict[str, Any]:
        d = {k: getattr(self, k) for k in (
            "version", "kind", "file_directive", "direction", "mode", "crc", "large_file",
            "data_field_length", "segmentation_control", "entity_id_length", "segment_metadata",
            "sequence_number_length", "source", "sequence", "destination", "header_length")}
        d["fields"] = dict(self.fields)
        return d


def _tlvs(body: bytes, what: str) -> list[dict[str, Any]]:
    out, p = [], 0
    while p < len(body):
        if len(body) - p < 2 or len(body) - p - 2 < body[p + 1]:
            raise CfdpError(f"truncated TLV in {what}")
        out.append({"type": body[p], "value_hex": body[p + 2:p + 2 + body[p + 1]].hex()})
        p += 2 + body[p + 1]
    return out


def _lv(body: bytes, p: int, what: str) -> tuple[bytes, int]:
    if p >= len(body) or len(body) - p - 1 < body[p]:
        raise CfdpError(f"truncated {what}")
    return body[p + 1:p + 1 + body[p]], p + 1 + body[p]


def _directive(code: int, rest: bytes, fss: int) -> tuple[str, dict[str, Any]]:
    kind = DIRECTIVES.get(code, f"directive-0x{code:02x}")
    f: dict[str, Any] = {"directive_code": code}
    if kind == "metadata":
        if len(rest) < 1 + fss:
            raise CfdpError("truncated Metadata PDU")
        f["closure_requested"] = bool(rest[0] & 0x40)
        f["checksum_type"] = rest[0] & 0x0F
        f["reserved_bits"] = rest[0] & 0xB0
        f["file_size"] = int.from_bytes(rest[1:1 + fss], "big")
        source_name, p = _lv(rest, 1 + fss, "Metadata source file name")
        dest_name, p = _lv(rest, p, "Metadata destination file name")
        f["source_file_name"] = source_name.decode("latin-1")
        f["destination_file_name"] = dest_name.decode("latin-1")
        f["options"] = _tlvs(rest[p:], "Metadata options")
    elif kind == "eof":
        if len(rest) < 5 + fss:
            raise CfdpError("truncated EOF PDU")
        f["condition_code"] = rest[0] >> 4
        f["spare"] = rest[0] & 0x0F
        f["checksum"] = int.from_bytes(rest[1:5], "big")
        f["file_size"] = int.from_bytes(rest[5:5 + fss], "big")
        tlvs = _tlvs(rest[5 + fss:], "EOF fault location")
        if len(tlvs) > 1:
            raise CfdpError("an EOF PDU carries at most one fault-location TLV")
        f["fault_location"] = tlvs[0] if tlvs else None
    elif kind == "nak":
        if len(rest) < 2 * fss or (len(rest) - 2 * fss) % (2 * fss):
            raise CfdpError("a NAK PDU is a scope and whole segment-request pairs")
        words = [int.from_bytes(rest[i:i + fss], "big") for i in range(0, len(rest), fss)]
        f["scope_start"], f["scope_end"] = words[0], words[1]
        f["segment_requests"] = [(words[i], words[i + 1]) for i in range(2, len(words), 2)]
    elif kind == "finished":
        if not rest:
            raise CfdpError("truncated Finished PDU")
        f["condition_code"] = rest[0] >> 4
        f["delivery_code"] = (rest[0] >> 2) & 1
        f["file_status"] = rest[0] & 3
        f["tlvs"] = _tlvs(rest[1:], "Finished TLVs")
    elif kind == "ack":
        if len(rest) != 2:
            raise CfdpError("an ACK PDU body is two octets")
        f["acked_directive_code"] = rest[0] >> 4
        f["acked_directive_subtype"] = rest[0] & 0x0F
        f["condition_code"] = rest[1] >> 4
        f["transaction_status"] = rest[1] & 3
    elif kind == "prompt":
        if len(rest) != 1:
            raise CfdpError("a Prompt PDU body is one octet")
        f["response_required"] = "keep-alive" if rest[0] & 0x80 else "nak"
    elif kind == "keep-alive":
        if len(rest) != fss:
            raise CfdpError("a Keep Alive PDU body is one progress value")
        f["progress"] = int.from_bytes(rest, "big")
    else:
        f["body_hex"] = rest.hex()
    return kind, f


def parse_pdu(data: object) -> Pdu:
    """Parse exactly one CFDP PDU. The declared data field length must consume `data` exactly, a
    flagged CRC must verify, and the body must be whole; anything else is a CfdpError."""
    raw = _raw(data, "a CFDP PDU")
    header_length, data_length = _header_length(raw, 0, "")
    first, third = raw[0], raw[3]
    version = first >> 5
    if version > 1:
        raise CfdpError(f"unsupported CFDP version {version} (this reads 0 and 1)")
    if len(raw) < header_length:
        raise CfdpError(f"truncated CFDP header ({len(raw)} of {header_length} octets)")
    if header_length + data_length != len(raw):
        raise CfdpError(f"the PDU declares {header_length + data_length} octets (header {header_length} "
                        f"+ data field {data_length}), the unit holds {len(raw)}")
    id_length = ((third >> 4) & 7) + 1
    seq_length = (third & 7) + 1
    p = 4
    source = int.from_bytes(raw[p:p + id_length], "big")
    sequence = int.from_bytes(raw[p + id_length:p + id_length + seq_length], "big")
    destination = int.from_bytes(raw[p + id_length + seq_length:header_length], "big")
    has_crc = bool(first & 0x02)
    large = bool(first & 0x01)
    fss = 8 if large else 4
    body = raw[header_length:]
    fields: dict[str, Any] = {}
    if has_crc:
        if len(body) < 2:
            raise CfdpError("the CRC flag is set but the data field has no room for a CRC")
        stated = int.from_bytes(body[-2:], "big")
        if crc16(raw[:-2]) != stated:
            raise CfdpError(f"PDU CRC mismatch (stated 0x{stated:04x}, computed 0x{crc16(raw[:-2]):04x})")
        body = body[:-2]
        fields["crc_value"] = stated
    # Version 0 (727.0-B-4) has spare bits where version 1 has segmentation control and the
    # segment-metadata flag; they are reported as read and only version 1 acts on the second.
    segment_metadata = bool(third & 0x08)
    payload = b""
    if first & 0x10:                                   # File Data
        kind, p = "file-data", 0
        if segment_metadata and version == 1:
            if not body:
                raise CfdpError("truncated File Data segment metadata")
            length = body[0] & 0x3F
            if len(body) - 1 < length:
                raise CfdpError("truncated File Data segment metadata")
            fields["record_continuation_state"] = body[0] >> 6
            fields["segment_metadata_hex"] = body[1:1 + length].hex()
            p = 1 + length
        if len(body) - p < fss:
            raise CfdpError("truncated File Data offset")
        offset = int.from_bytes(body[p:p + fss], "big")
        payload = body[p + fss:]
        fields.update(offset=offset, length=len(payload), end=offset + len(payload))
    else:
        if not body:
            raise CfdpError("a File Directive PDU with no directive code")
        kind, more = _directive(body[0], body[1:], fss)
        fields.update(more)
    return Pdu(
        version=version, kind=kind, file_directive=not first & 0x10,
        direction=DIRECTIONS[(first >> 3) & 1], mode=MODES[(first >> 2) & 1], crc=has_crc,
        large_file=large, data_field_length=data_length, segmentation_control=bool(third & 0x80),
        entity_id_length=id_length, segment_metadata=segment_metadata,
        sequence_number_length=seq_length, source=source, sequence=sequence, destination=destination,
        header_length=header_length, fields=fields, payload=payload)


def _fits(value: int, octets: int, what: str) -> bytes:
    if type(value) is not int or value < 0 or value >> (8 * octets):
        raise CfdpError(f"{what} {value!r} does not fit {octets} octet(s)")
    return value.to_bytes(octets, "big")


def build_nak(*, source: int, sequence: int, destination: int, scope_start: int, scope_end: int,
              segment_requests: Iterable[Sequence[int]], entity_id_length: int = 1,
              sequence_number_length: int = 1, version: int = 1, direction: str = "toward-sender",
              mode: str = "acknowledged", crc: bool = False, large_file: bool = False) -> bytes:
    """Serialise one NAK PDU: fixed header, directive 0x08, the scope, then each [start, end)
    segment request in the order given, with 32-bit offsets (64-bit when `large_file`)."""
    if version not in (0, 1):
        raise CfdpError(f"unsupported CFDP version {version!r}")
    if direction not in DIRECTIONS:
        raise CfdpError(f"direction must be one of {', '.join(DIRECTIONS)}; got {direction!r}")
    if mode not in MODES:
        raise CfdpError(f"mode must be one of {', '.join(MODES)}; got {mode!r}")
    for name, length in (("entity_id_length", entity_id_length),
                         ("sequence_number_length", sequence_number_length)):
        if type(length) is not int or not 1 <= length <= 8:
            raise CfdpError(f"{name} must be 1..8, got {length!r}")
    fss = 8 if large_file else 4
    if scope_start > scope_end:
        raise CfdpError(f"NAK scope [{scope_start}, {scope_end}) is reversed")
    body = bytearray([NAK_CODE])
    body += _fits(scope_start, fss, "NAK start of scope") + _fits(scope_end, fss, "NAK end of scope")
    for pair in segment_requests:
        start, end = pair
        if start > end:
            raise CfdpError(f"segment request [{start}, {end}) is reversed")
        body += _fits(start, fss, "segment request start") + _fits(end, fss, "segment request end")
    data_length = len(body) + (2 if crc else 0)
    if data_length > MAX_DATA_FIELD:
        raise CfdpError(f"the NAK data field would be {data_length} octets, over {MAX_DATA_FIELD}: "
                        f"split it ([nak] max_segment_requests)")
    first = (version << 5) | (DIRECTIONS.index(direction) << 3) | (MODES.index(mode) << 2) \
        | (0x02 if crc else 0) | (0x01 if large_file else 0)
    third = ((entity_id_length - 1) << 4) | (sequence_number_length - 1)
    pdu = bytes([first]) + data_length.to_bytes(2, "big") + bytes([third]) \
        + _fits(source, entity_id_length, "source entity ID") \
        + _fits(sequence, sequence_number_length, "transaction sequence number") \
        + _fits(destination, entity_id_length, "destination entity ID") + bytes(body)
    if crc:
        pdu += crc16(pdu).to_bytes(2, "big")
    return pdu


# ----------------------------------------------------------------------------------------- coverage

def merge_ranges(ranges: Iterable[Sequence[int]]) -> list[tuple[int, int]]:
    """Half-open [start, end) ranges as ascending, maximal, non-overlapping ranges. Empty ranges
    drop out; overlapping and touching ranges join."""
    out: list[tuple[int, int]] = []
    for start, end in sorted((int(s), int(e)) for s, e in ranges):
        if end <= start:
            continue
        if out and start <= out[-1][1]:
            if end > out[-1][1]:
                out[-1] = (out[-1][0], end)
        else:
            out.append((start, end))
    return out


def complement(ranges: Iterable[Sequence[int]], start: int, end: int) -> list[tuple[int, int]]:
    """What [start, end) holds that `ranges` do not: ascending, maximal [a, b) gaps."""
    gaps: list[tuple[int, int]] = []
    at = start
    for lo, hi in merge_ranges(ranges):
        if hi <= at:
            continue
        if lo >= end:
            break
        if lo > at:
            gaps.append((at, lo))
        at = hi
    if at < end:
        gaps.append((at, end))
    return gaps


# ------------------------------------------------------------------------------------------- filter

def _bool(value, key):
    if type(value) is not bool:
        raise FilterError(f"{key}: expected true or false, got {value!r}")
    return value


def _int(lo: int, hi: int | None):
    def check(value, key):
        if type(value) is not int or value < lo or (hi is not None and value > hi):
            raise FilterError(f"{key}: expected an integer {lo}..{hi if hi is not None else ''}, "
                              f"got {value!r}")
        return value
    return check


def _enum(*choices: str):
    def check(value, key):
        if not isinstance(value, str) or value not in choices:
            raise FilterError(f"{key}: expected one of {', '.join(choices)}; got {value!r}")
        return value
    return check


def _apid(value, key):
    one = _int(0, 0x7FF)
    values = value if isinstance(value, list) else [value]
    if not values:
        raise FilterError(f"{key}: an empty list selects nothing")
    return tuple(one(v, key) for v in values)


def _str(value, key):
    if not isinstance(value, str) or not value:
        raise FilterError(f"{key}: expected a non-empty string, got {value!r}")
    return value


def _prefix(value, key):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,32}", value):
        raise FilterError(f"{key}: expected a flag prefix of 1-32 letters, digits or _, got {value!r}")
    return value


def _scope_end(value, key):
    if value in ("eof", "metadata") and isinstance(value, str):
        return value
    if type(value) is int and value >= 0:
        return value
    raise FilterError(f'{key}: expected "eof", "metadata" or a byte count, got {value!r}')


def _eof_size(value, key):
    if value == "metadata" and isinstance(value, str):
        return value
    if type(value) is int and value >= 0:
        return value
    raise FilterError(f'{key}: expected "metadata" or a byte count, got {value!r}')


# Every key the filter knows. A selection key ([packet], [transaction], [file_data], [metadata],
# [eof]) that is not stated is not checked; [policy] and [nak] keys have the defaults below.
SCHEMA: dict[str, dict[str, Any]] = {
    "stream": {"framing": _enum(*FRAMINGS), "file": _str},
    "packet": {"pvn": _int(0, 7), "type": _enum(*PACKET_TYPES), "secondary_header": _bool,
               "apid": _apid, "sequence_flags": _int(0, 3)},
    "transaction": {"version": _int(0, 1), "direction": _enum(*DIRECTIONS), "mode": _enum(*MODES),
                    "crc": _bool, "large_file": _bool, "entity_id_length": _int(1, 8),
                    "sequence_number_length": _int(1, 8), "source": _int(0, 2 ** 64 - 1),
                    "sequence": _int(0, 2 ** 64 - 1), "destination": _int(0, 2 ** 64 - 1)},
    "file_data": {"segmentation_control": _bool, "segment_metadata": _bool},
    "metadata": {"checksum_type": _int(0, 15), "closure_requested": _bool, "options": _bool},
    "eof": {"condition_code": _int(0, 15), "spare": _int(0, 15), "checksum": _int(0, 2 ** 32 - 1),
            "fault_location": _bool, "file_size": _eof_size},
    "policy": {"metadata_first": _bool, "beyond_file_size": _enum("keep", "discard"),
               "eof_snapshot": _bool},
    "nak": {"scope_start": _int(0, None), "scope_end": _scope_end, "direction": _enum(*DIRECTIONS),
            "mode": _enum(*MODES), "crc": _bool, "large_file": _bool, "request_metadata": _bool,
            "max_segment_requests": _int(1, None)},
    "output": {"encoding": _enum(*ENCODINGS), "wrap": _enum(*WRAPS), "prefix": _prefix},
}

# The CFDP standard receiver (727.0-B-5 class 2): File Data and EOF count whether or not Metadata
# came first, nothing is dropped for running past the Metadata size, the deferred NAK reflects what
# had arrived when the first accepted EOF came in, covers [0, EOF file size) and asks for the
# Metadata too when none was accepted. A mission profile that says otherwise states it in the filter.
STANDARD_POLICY = {"metadata_first": False, "beyond_file_size": "keep", "eof_snapshot": True}
STANDARD_NAK = {"scope_start": 0, "scope_end": "eof", "direction": "toward-sender",
                "request_metadata": True}


@dataclass(frozen=True)
class Filter:
    framing: str
    file: str | None = None
    packet: Mapping[str, Any] = field(default_factory=dict)
    transaction: Mapping[str, Any] = field(default_factory=dict)
    file_data: Mapping[str, Any] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    eof: Mapping[str, Any] = field(default_factory=dict)
    policy: Mapping[str, Any] = field(default_factory=lambda: dict(STANDARD_POLICY))
    nak: Mapping[str, Any] = field(default_factory=lambda: dict(STANDARD_NAK))
    output: Mapping[str, Any] | None = None
    source: str = "<filter>"

    def stated(self) -> dict[str, Any]:
        """The effective config, for a report: what was selected on and which policy ran."""
        d = {"stream": {"framing": self.framing}}
        for name in ("packet", "transaction", "file_data", "metadata", "eof", "policy", "nak"):
            section = {k: (list(v) if isinstance(v, tuple) else v) for k, v in getattr(self, name).items()}
            if section:
                d[name] = section
        if self.output is not None:
            d["output"] = dict(self.output)
        return d


def parse_filter(data: object, *, source: str = "<filter>") -> Filter:
    """Check a filter config (the parsed TOML) and return it. Unknown sections and keys, wrong
    types and missing required keys are a FilterError naming the dotted key."""
    if not isinstance(data, Mapping):
        raise FilterError(f"{source}: a filter is a table of sections")
    sections: dict[str, dict[str, Any]] = {}
    for name, table in data.items():
        if name not in SCHEMA:
            raise FilterError(f"{source}: unknown section [{name}] (known: {', '.join(SCHEMA)})")
        if not isinstance(table, Mapping):
            raise FilterError(f"{source}: [{name}] must be a table")
        checked = {}
        for key, value in table.items():
            if key not in SCHEMA[name]:
                raise FilterError(f"{source}: unknown key {name}.{key} "
                                  f"(known: {', '.join(SCHEMA[name])})")
            checked[key] = SCHEMA[name][key](value, f"{source}: {name}.{key}")
        sections[name] = checked
    stream = sections.get("stream", {})
    if "framing" not in stream:
        raise FilterError(f'{source}: stream.framing is required (one of: {", ".join(FRAMINGS)})')
    if stream["framing"] != "space-packet" and sections.get("packet"):
        raise FilterError(f'{source}: [packet] selects Space Packets, so it needs '
                          f'stream.framing = "space-packet"')
    output = sections.get("output")
    if output is not None:
        for key in ("encoding", "wrap"):
            if key not in output:
                raise FilterError(f"{source}: output.{key} is required when [output] is present")
        if output["wrap"] == "none" and "prefix" in output:
            raise FilterError(f'{source}: output.prefix has no meaning with output.wrap = "none"')
    nak = {**STANDARD_NAK, **sections.get("nak", {})}
    if isinstance(nak["scope_end"], int) and nak["scope_start"] > nak["scope_end"]:
        raise FilterError(f"{source}: nak.scope_start is past nak.scope_end")
    return Filter(
        framing=stream["framing"], file=stream.get("file"), packet=sections.get("packet", {}),
        transaction=sections.get("transaction", {}), file_data=sections.get("file_data", {}),
        metadata=sections.get("metadata", {}), eof=sections.get("eof", {}),
        policy={**STANDARD_POLICY, **sections.get("policy", {})}, nak=nak, output=output,
        source=source)


def load_filter(path: str | Path) -> Filter:
    p = Path(path)
    try:
        data = tomllib.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise FilterError(f"{p}: cannot read the filter ({e.strerror or e})") from None
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise FilterError(f"{p}: not valid TOML ({e})") from None
    return parse_filter(data, source=str(p))


_PACKET_KEYS = ("pvn", "type", "secondary_header", "apid", "sequence_flags")
_TRANSACTION_KEYS = ("version", "direction", "mode", "crc", "large_file", "entity_id_length",
                     "sequence_number_length", "source", "sequence", "destination")


def _packet_mismatch(packet: Mapping[str, Any], want: Mapping[str, Any]) -> str | None:
    for key in _PACKET_KEYS:
        if key in want:
            if (packet[key] not in want[key]) if key == "apid" else (packet[key] != want[key]):
                return key
    return None


def _transaction_mismatch(pdu: Pdu, want: Mapping[str, Any]) -> str | None:
    for key in _TRANSACTION_KEYS:
        if key in want and getattr(pdu, key) != want[key]:
            return key
    return None


def _metadata_mismatch(pdu: Pdu, want: Mapping[str, Any]) -> str | None:
    for key in ("checksum_type", "closure_requested"):
        if key in want and pdu.fields[key] != want[key]:
            return key
    if "options" in want and bool(pdu.fields["options"]) != want["options"]:
        return "options"
    return None


def _eof_mismatch(pdu: Pdu, want: Mapping[str, Any], metadata: "Accepted | None") -> str | None:
    for key in ("condition_code", "spare", "checksum"):
        if key in want and pdu.fields[key] != want[key]:
            return key
    if "fault_location" in want and (pdu.fields["fault_location"] is not None) != want["fault_location"]:
        return "fault_location"
    if "file_size" in want:
        size = want["file_size"]
        if size == "metadata":
            # With no Metadata accepted there is no size to equal: the EOF does not qualify.
            size = metadata.pdu.fields["file_size"] if metadata is not None else None
        if pdu.fields["file_size"] != size:
            return "file_size"
    return None


# ----------------------------------------------------------------------------------- reconstruction

@dataclass(frozen=True)
class Accepted:
    unit: Unit
    pdu: Pdu


@dataclass
class _State:
    metadata: Accepted | None = None
    eof: Accepted | None = None
    first: Accepted | None = None           # the first PDU that counted, of any kind
    segments: list[tuple[int, int]] = field(default_factory=list)


@dataclass(frozen=True)
class Reconstruction:
    framing: str
    units: int                               # framing units in the stream
    selected: int                            # units that passed the packet and transaction selection
    discards: Mapping[str, int]              # reason -> count, for every unit that did not count
    ignored: Mapping[str, int]               # selected PDU kinds that carry no coverage (ack, nak, ...)
    malformed: tuple[str, ...]               # the first few malformed-PDU reasons
    transaction: Mapping[str, Any] | None
    metadata: Mapping[str, Any] | None       # the accepted Metadata: unit, offset, file_size, ...
    eof: Mapping[str, Any] | None            # the accepted EOF
    segments: int                            # File Data PDUs that contributed
    coverage: tuple[tuple[int, int], ...]    # merged [start, end) coverage
    scope: tuple[int, int] | None
    missing: tuple[tuple[int, int], ...]     # the complement of coverage within the scope
    requests: tuple[tuple[int, int], ...]    # the segment requests sent (missing, plus (0, 0) for Metadata)
    naks: tuple[bytes, ...]
    reason: str                              # why there is no NAK, when there is none
    trace: tuple[tuple[int, int, str, str], ...]   # (unit, offset, kind, "accept" | discard reason)

    @property
    def covered_bytes(self) -> int:
        return sum(e - s for s, e in self.coverage)

    @property
    def missing_bytes(self) -> int:
        return sum(e - s for s, e in self.missing)

    def to_dict(self, ranges: int = 64) -> dict[str, Any]:
        return {
            "framing": self.framing, "units": self.units, "selected": self.selected,
            "discards": dict(self.discards), "ignored": dict(self.ignored),
            "malformed": list(self.malformed), "transaction": self.transaction,
            "metadata": self.metadata, "eof": self.eof, "segments": self.segments,
            "covered_bytes": self.covered_bytes, "coverage_ranges": len(self.coverage),
            "coverage": [list(r) for r in self.coverage[:ranges]],
            "scope": list(self.scope) if self.scope else None,
            "missing_bytes": self.missing_bytes, "missing_ranges": len(self.missing),
            "missing": [list(r) for r in self.missing[:ranges]],
            "naks_hex": [n.hex() for n in self.naks], "reason": self.reason,
        }


def _select(units: Sequence[Unit], flt: Filter):
    """The units that pass the packet and transaction selection, as (unit, pdu) pairs."""
    selected: list[tuple[Unit, Pdu]] = []
    discards: Counter[str] = Counter()
    malformed: list[str] = []
    trace: list[tuple[int, int, str, str]] = []
    for unit in units:
        if unit.packet is not None:
            why = _packet_mismatch(unit.packet, flt.packet)
            if why:
                discards[f"packet.{why}"] += 1
                trace.append((unit.index, unit.offset, "-", f"packet.{why}"))
                continue
        try:
            pdu = parse_pdu(unit.data)
        except CfdpError as e:
            discards["malformed"] += 1
            if len(malformed) < 5:
                malformed.append(f"unit {unit.index} at offset {unit.offset}: {e}")
            trace.append((unit.index, unit.offset, "-", "malformed"))
            continue
        why = _transaction_mismatch(pdu, flt.transaction)
        if why:
            discards[f"transaction.{why}"] += 1
            trace.append((unit.index, unit.offset, pdu.kind, f"transaction.{why}"))
            continue
        selected.append((unit, pdu))
    return selected, discards, malformed, trace


def _judge(st: _State, pdu: Pdu, flt: Filter) -> str | None:
    """Why a selected PDU does not count (a discard reason, or "ignored" for a kind that carries no
    coverage), or None when it does."""
    policy = flt.policy
    if pdu.kind == "metadata":
        why = _metadata_mismatch(pdu, flt.metadata)
        if why:
            return f"metadata.{why}"
        return "metadata.later" if st.metadata is not None else None
    if pdu.kind == "file-data":
        for key in ("segmentation_control", "segment_metadata"):
            if key in flt.file_data and getattr(pdu, key) != flt.file_data[key]:
                return f"file_data.{key}"
        if st.metadata is None and policy["metadata_first"]:
            return "file_data.before_metadata"
        if st.eof is not None and policy["eof_snapshot"]:
            return "file_data.after_eof"
        if (policy["beyond_file_size"] == "discard" and st.metadata is not None
                and pdu.fields["end"] > st.metadata.pdu.fields["file_size"]):
            return "file_data.beyond_file_size"
        return None
    if pdu.kind == "eof":
        if st.metadata is None and policy["metadata_first"]:
            return "eof.before_metadata"
        why = _eof_mismatch(pdu, flt.eof, st.metadata)
        if why:
            return f"eof.{why}"
        return "eof.later" if st.eof is not None else None
    return "ignored"


def _run_state(selected: Sequence[tuple[Unit, Pdu]], flt: Filter, discards: Counter,
               ignored: Counter, trace: list) -> _State:
    """The receiver: which selected Metadata, File Data and EOF count, in stream order."""
    st = _State()
    for unit, pdu in selected:
        why = _judge(st, pdu, flt)
        trace.append((unit.index, unit.offset, pdu.kind, why or "accept"))
        if why == "ignored":
            ignored[pdu.kind] += 1
        elif why is not None:
            discards[why] += 1
        else:
            got = Accepted(unit, pdu)
            if pdu.kind == "metadata":
                st.metadata = got
            elif pdu.kind == "eof":
                st.eof = got
            else:
                st.segments.append((pdu.fields["offset"], pdu.fields["end"]))
            if st.first is None:
                st.first = got
    return st


def _accepted(a: Accepted | None) -> dict[str, Any] | None:
    if a is None:
        return None
    keep = ("file_size", "checksum_type", "closure_requested", "condition_code", "checksum")
    return {"unit": a.unit.index, "offset": a.unit.offset,
            **{k: a.pdu.fields[k] for k in keep if k in a.pdu.fields}}


def _finish(st: _State, flt: Filter, *, units: int, selected: int, discards: Counter,
            ignored: Counter, malformed: Sequence[str], trace: Sequence) -> Reconstruction:
    coverage = merge_ranges(st.segments)
    nak = flt.nak
    template = (st.eof or st.metadata or st.first)
    transaction = None
    if template is not None:
        p = template.pdu
        transaction = {k: getattr(p, k) for k in _TRANSACTION_KEYS}
    reason, scope, missing, requests, naks = "", None, [], [], []
    start, end = nak["scope_start"], nak["scope_end"]
    if template is None:
        reason = "no PDU passed the filter"
    elif end == "eof":
        end = st.eof.pdu.fields["file_size"] if st.eof is not None else None
        if end is None:
            reason = ('no EOF was accepted, so nak.scope_end = "eof" has no file size '
                      '(state nak.scope_end = "metadata" or a byte count if the profile allows it)')
    elif end == "metadata":
        end = st.metadata.pdu.fields["file_size"] if st.metadata is not None else None
        if end is None:
            reason = 'no Metadata was accepted, so nak.scope_end = "metadata" has no file size'
    if not reason and start > end:
        reason = f"nak.scope_start {start} is past the end of scope {end}"
    if not reason:
        scope = (start, end)
        missing = complement(coverage, start, end)
        requests = list(missing)
        if nak["request_metadata"] and st.metadata is None:
            requests.insert(0, (0, 0))
        if not requests:
            reason = f"coverage of [{start}, {end}) is complete: the receiver sends no NAK"
    if not reason:
        p = template.pdu
        common = dict(
            version=p.version, source=p.source, sequence=p.sequence, destination=p.destination,
            entity_id_length=p.entity_id_length, sequence_number_length=p.sequence_number_length,
            direction=nak["direction"], mode=nak.get("mode", p.mode), crc=nak.get("crc", p.crc),
            large_file=nak.get("large_file", p.large_file))
        size = nak.get("max_segment_requests") or len(requests)
        chunks = [requests[i:i + size] for i in range(0, len(requests), size)]
        at = start
        try:
            for n, chunk in enumerate(chunks):
                # A NAK sequence: each PDU's scope starts where the previous one ended; all but the
                # last end at their last request, the last at the end of the whole scope.
                stop = end if n == len(chunks) - 1 else chunk[-1][1]
                naks.append(build_nak(scope_start=at, scope_end=stop, segment_requests=chunk, **common))
                at = stop
        except CfdpError as e:
            naks, reason = [], f"the NAK cannot be serialised: {e}"
    return Reconstruction(
        framing=flt.framing, units=units, selected=selected,
        discards=dict(sorted(discards.items())), ignored=dict(sorted(ignored.items())),
        malformed=tuple(malformed), transaction=transaction, metadata=_accepted(st.metadata),
        eof=_accepted(st.eof), segments=len(st.segments), coverage=tuple(coverage), scope=scope,
        missing=tuple(missing), requests=tuple(requests), naks=tuple(naks), reason=reason,
        trace=tuple(sorted(trace)))


def _identity_text(identity: Sequence[int]) -> str:
    id_length, seq_length, source, sequence, destination = identity
    return (f"0x{source:0{2 * id_length}x}/0x{sequence:0{2 * seq_length}x}/"
            f"0x{destination:0{2 * id_length}x}")


def reconstruct(data: object, flt: Filter) -> Reconstruction:
    """Run the filter over a capture: select, run the receiver state, complement the coverage and
    serialise the NAK PDU(s). Raises CfdpError for a stream the framing cannot walk and
    AmbiguousTransaction when the selection lets more than one transaction through."""
    units = walk(data, flt.framing)
    selected, discards, malformed, trace = _select(units, flt)
    identities: dict[tuple, int] = {}
    for _, pdu in selected:
        identities[pdu.identity] = identities.get(pdu.identity, 0) + 1
    if len(identities) > 1:
        listed = ", ".join(f"{_identity_text(i)} ({n} PDU{'s' if n != 1 else ''})"
                           for i, n in list(identities.items())[:8])
        raise AmbiguousTransaction(
            f"the filter selects {len(identities)} transactions (source/sequence/destination): "
            f"{listed}; state transaction.source, .sequence and .destination")
    ignored: Counter[str] = Counter()
    st = _run_state(selected, flt, discards, ignored, trace)
    return _finish(st, flt, units=len(units), selected=len(selected), discards=discards,
                   ignored=ignored, malformed=malformed, trace=trace)


# ------------------------------------------------------------------------------------------- survey

def detect_framing(data: object) -> str:
    """`space-packet` when the bytes walk exactly as Space Packets and at least one carries a whole
    CFDP PDU; `cfdp-pdu` when they walk exactly as bare PDUs that all parse; else a CfdpError."""
    why = []
    try:
        if any(_parses(u.data) for u in walk_space_packets(data)):
            return "space-packet"
        why.append("it walks as Space Packets but none carries a whole CFDP PDU")
    except CfdpError as e:
        why.append(f"not a Space Packet stream ({e})")
    try:
        if all(_parses(u.data) for u in walk_pdus(data)):
            return "cfdp-pdu"
        why.append("it walks as bare PDUs but not all of them parse")
    except CfdpError as e:
        why.append(f"not a bare CFDP PDU stream ({e})")
    raise CfdpError("no CFDP found: " + "; ".join(why))


def _parses(data: bytes) -> bool:
    try:
        parse_pdu(data)
    except CfdpError:
        return False
    return True


def survey(data: object, framing: str | None = None) -> dict[str, Any]:
    """Every distinct (packet selection, CFDP header selection) combination in a capture, with its
    PDU counts, File Data coverage and, under the CFDP standard receiver policy, the gaps and NAK.
    The rows are facts about the capture; which row is the target is the mission profile's call."""
    framing = framing or detect_framing(data)
    units = walk(data, framing)
    groups: dict[tuple, list[tuple[Unit, Pdu]]] = {}
    other = 0
    for unit in units:
        try:
            pdu = parse_pdu(unit.data)
        except CfdpError:
            other += 1
            continue
        packet = unit.packet
        key = (tuple(packet[k] for k in _PACKET_KEYS) if packet is not None else None,
               tuple(getattr(pdu, k) for k in _TRANSACTION_KEYS))
        groups.setdefault(key, []).append((unit, pdu))
    rows = []
    for (packet_key, transaction_key), group in groups.items():
        std = Filter(framing=framing)
        st = _run_state(group, std, Counter(), Counter(), [])
        size_from = "eof" if st.eof is not None else "metadata" if st.metadata is not None else None
        row: dict[str, Any] = {
            "packet": dict(zip(_PACKET_KEYS, packet_key)) if packet_key is not None else None,
            "transaction": dict(zip(_TRANSACTION_KEYS, transaction_key)),
            "pdus": dict(sorted(Counter(p.kind for _, p in group).items())),
            "first_unit": group[0][0].index, "first_offset": group[0][0].offset,
            "file_size": None, "file_size_from": size_from, "standard_nak_hex": None,
        }
        coverage = merge_ranges(st.segments)
        row["segments"] = len(st.segments)
        row["covered_bytes"] = sum(e - s for s, e in coverage)
        row["coverage"] = coverage
        row["missing"] = []
        if size_from is not None:
            size = (st.eof if size_from == "eof" else st.metadata).pdu.fields["file_size"]
            row["file_size"] = size
            row["missing"] = complement(coverage, 0, size)
        if size_from == "eof":
            # Only a transaction with an accepted EOF has a deferred NAK to speak of.
            rec = _finish(st, std, units=len(units), selected=len(group), discards=Counter(),
                          ignored=Counter(), malformed=(), trace=())
            if len(rec.naks) == 1:
                row["standard_nak_hex"] = rec.naks[0].hex()
        row["missing_bytes"] = sum(e - s for s, e in row["missing"])
        rows.append(row)
    return {"framing": framing, "units": len(units), "cfdp_units": len(units) - other,
            "other_units": other, "rows": rows}


def skeleton(row: Mapping[str, Any], framing: str) -> str:
    """A filter config (TOML text) that selects exactly one surveyed row under the CFDP standard
    policy. The values are what the capture holds; the policy lines are for the reader to set to
    what the mission profile states."""
    def value(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        return f'"{v}"' if isinstance(v, str) else str(v)

    lines = ["# CFDP NAK filter (docs/toolkits/sec_space_cfdp.md). The selection values are read from the",
             "# capture; the policy is the CFDP standard receiver. Set every line the mission profile",
             "# states differently, then run the engine again.",
             "[stream]", f'framing = "{framing}"', ""]
    if row.get("packet") is not None:
        lines.append("[packet]")
        for key in _PACKET_KEYS:
            v = row["packet"][key]
            lines.append(f"{key} = 0x{v:03X}" if key == "apid" else f"{key} = {value(v)}")
        lines.append("")
    lines.append("[transaction]")
    t = row["transaction"]
    for key in _TRANSACTION_KEYS:
        if key in ("source", "destination"):
            lines.append(f"{key} = 0x{t[key]:0{2 * t['entity_id_length']}X}")
        elif key == "sequence":
            lines.append(f"{key} = 0x{t[key]:0{2 * t['sequence_number_length']}X}")
        else:
            lines.append(f"{key} = {value(t[key])}")
    lines += ["", "[policy]"]
    lines += [f"{k} = {value(v)}" for k, v in STANDARD_POLICY.items()]
    lines += ["", "[nak]"]
    lines += [f"{k} = {value(v)}" for k, v in STANDARD_NAK.items()]
    lines += ["",
              "# Selection the profile may add (a key that is absent is not checked):",
              "# [file_data]", "# segmentation_control = false", "# segment_metadata = false",
              "# [metadata]", "# checksum_type = 15", "# closure_requested = false", "# options = false",
              "# [eof]", "# condition_code = 0", "# spare = 0", "# checksum = 0",
              "# fault_location = false", '# file_size = "metadata"',
              "",
              "# The answer format the challenge states (without it the NAK is reported as hex only):",
              "# [output]", '# encoding = "hex-upper"    # hex-upper | hex-lower | base64',
              '# wrap = "flag"             # flag: PREFIX{...}, the prefix from the event profile | none',
              ""]
    return "\n".join(lines)


# ------------------------------------------------------------------------------------------- output

def render_output(pdu: bytes, output: Mapping[str, Any], profile=None) -> tuple[str, bool | None, str]:
    """The NAK in the stated answer format: (value, in the event's flag format?, note).

    The flag lead comes from ctf.flagfmt (the event profile's first prefix) unless the handout states
    its own `prefix`; the result is checked against the event format through ctf.flagfmt, and the
    second value is None when there is no event profile to check against."""
    encoding = output["encoding"]
    if encoding == "base64":
        body = base64.b64encode(pdu).decode("ascii")
    else:
        body = pdu.hex().upper() if encoding == "hex-upper" else pdu.hex()
    ff = None
    if profile is not None:
        from ctf import flagfmt
        ff = flagfmt.for_profile(profile)
    if output["wrap"] == "none":
        value = body
    elif "prefix" in output:
        value = f"{output['prefix']}{{{body}}}"
    else:
        if ff is None:
            raise OutputError('output.wrap = "flag" takes the prefix from the event profile and there is '
                              'none: pass --event (or set CTF_EVENT), or state output.prefix')
        try:
            lead = ff.cribs()[0]
        except LookupError:
            raise OutputError("the event profile has no known flag prefix: state output.prefix") from None
        value = f"{lead}{body}}}"
    if ff is None:
        return value, None, "no event profile: not checked against the event's flag format"
    if ff.is_flag(value):
        return value, True, "in the event's flag format"
    return value, False, ("NOT in the event profile's flag format: the filter's [output] states a "
                          "format of its own (a handout may override the board's)")


# --------------------------------------------------------------------------------------- the engine

_SKIP_DIRS = {"recon"}


def stream_files(challenge_dir: Path) -> tuple[list[Path], list[str]]:
    """(files to try, notes): every distinct non-empty file under the challenge folder, by content,
    leaving out intake's own `recon/` output, dot-folders, the filter file and anything over MAX_STREAM."""
    files, notes, seen = [], [], set()
    for p in sorted(challenge_dir.rglob("*")):
        rel = p.relative_to(challenge_dir)
        if any(part in _SKIP_DIRS or part.startswith(".") for part in rel.parts):
            continue
        if not p.is_file() or p.is_symlink() or rel.as_posix() == FILTER_NAME:
            continue
        size = p.stat().st_size
        if size == 0:
            continue
        if size > MAX_STREAM:
            notes.append(f"{rel.as_posix()} not read: {size} bytes is over the {MAX_STREAM}-byte limit")
            continue
        digest = hashlib.sha256(p.read_bytes()).digest()
        if digest in seen:
            continue
        seen.add(digest)
        files.append(p)
    return files, notes


def _ranges_text(ranges: Sequence[Sequence[int]], cap: int = 16) -> str:
    text = " ".join(f"[{s},{e})" for s, e in ranges[:cap])
    return text + (f" ... (+{len(ranges) - cap} more)" if len(ranges) > cap else "")


def _row_text(row: Mapping[str, Any]) -> str:
    t = row["transaction"]
    ident = _identity_text((t["entity_id_length"], t["sequence_number_length"], t["source"],
                            t["sequence"], t["destination"]))
    where = f" on APID 0x{row['packet']['apid']:03x}" if row["packet"] is not None else ""
    pdus = ", ".join(f"{n} {k}" for k, n in row["pdus"].items())
    text = (f"transaction {ident}{where} (v{t['version']} {t['direction']} {t['mode']}"
            f"{' crc' if t['crc'] else ''}{' large-file' if t['large_file'] else ''}): {pdus}; "
            f"{row['segments']} segment(s) cover {row['covered_bytes']} byte(s)")
    if row["file_size"] is not None:
        text += f"; file size {row['file_size']} (from {row['file_size_from']})"
        text += (f"; missing {row['missing_bytes']} byte(s) in {len(row['missing'])} range(s): "
                 f"{_ranges_text(row['missing'])}" if row["missing"] else "; nothing missing")
    else:
        text += "; no Metadata or EOF, so no file size"
    if row["standard_nak_hex"]:
        text += f"; standard-policy NAK {row['standard_nak_hex']}"
    return text


def _blocked(notes: str):
    from ctf.result import SolverResult
    return SolverResult(status="blocked", engine=ENGINE_ID, notes=notes)


def solve(challenge_dir, profile=None, **opts):
    """Engine entry. With no filter config: survey every capture in the challenge folder and report
    each CFDP transaction (`unsure`; `none` when there is no CFDP). With one (`cfdp-filter.toml` at
    the top of the challenge folder, or `--opt filter=PATH`): reconstruct the NAK and, when the filter
    states an `[output]` format, return it as a `candidate` (the selection rules are the reader's
    translation of prose, so it is never `solved`). `--opt file=RELATIVE/PATH` names one capture."""
    from ctf.result import Evidence, SolverResult

    challenge_dir = Path(challenge_dir)
    unknown = sorted(set(opts) - {"filter", "file"})
    if unknown:
        return _blocked(f"unknown option(s) {', '.join(unknown)} (this engine takes filter=PATH and "
                        f"file=RELATIVE/PATH)")
    if not challenge_dir.is_dir():
        return _blocked(f"the challenge folder {challenge_dir} does not exist")

    flt = None
    filter_path = None
    if opts.get("filter") is not None:
        filter_path = Path(str(opts["filter"]))
        if not filter_path.is_absolute():
            filter_path = challenge_dir / filter_path
        if not filter_path.is_file():
            return _blocked(f"the filter config {filter_path} does not exist")
    elif (challenge_dir / FILTER_NAME).is_file():
        filter_path = challenge_dir / FILTER_NAME
    if filter_path is not None:
        try:
            flt = load_filter(filter_path)
        except FilterError as e:
            return _blocked(f"bad filter config: {e}")

    files, notes = stream_files(challenge_dir)
    if filter_path is not None:
        files = [p for p in files if p.resolve() != filter_path.resolve()]
    if opts.get("file") is not None:
        wanted = challenge_dir / str(opts["file"])
        try:
            wanted.resolve().relative_to(challenge_dir.resolve())
        except ValueError:
            return _blocked(f"file={opts['file']!r} is outside the challenge folder {challenge_dir}: "
                            f"name a capture inside it")
        if not wanted.is_file():
            return _blocked(f"the capture {wanted} does not exist")
        files = [wanted]
    elif flt is not None and flt.file is not None:
        files = [p for p in files if fnmatch.fnmatch(p.name, flt.file)]
        if not files:
            return _blocked(f"no file in {challenge_dir} matches stream.file = {flt.file!r}")

    if flt is None:
        return _solve_survey(challenge_dir, files, notes)

    evidence: list = []
    flags: list[str] = []
    walked = built = ambiguous = 0
    for p in files:
        rel = p.relative_to(challenge_dir).as_posix()
        try:
            rec = reconstruct(p.read_bytes(), flt)
        except AmbiguousTransaction as e:
            walked += 1
            ambiguous += 1
            notes.append(f"{rel}: {e}")
            continue
        except CfdpError as e:
            notes.append(f"{rel}: not a {flt.framing} stream ({e})")
            continue
        walked += 1
        summary = (f"{rec.units} unit(s), {rec.selected} selected; {rec.segments} File Data segment(s) "
                   f"cover {rec.covered_bytes} byte(s)")
        if rec.metadata:
            summary += f"; Metadata at unit {rec.metadata['unit']} (file size {rec.metadata['file_size']})"
        if rec.eof:
            summary += f"; EOF at unit {rec.eof['unit']} (file size {rec.eof['file_size']})"
        if rec.discards:
            summary += "; not counted: " + ", ".join(f"{n} {k}" for k, n in rec.discards.items())
        evidence.append(Evidence("wire", summary, path=rel))
        if not rec.naks:
            notes.append(f"{rel}: no NAK: {rec.reason}")
            continue
        built += len(rec.naks)
        evidence.append(Evidence(
            "wire", f"scope [{rec.scope[0]},{rec.scope[1]}): missing {rec.missing_bytes} byte(s) in "
                    f"{len(rec.missing)} range(s): {_ranges_text(rec.missing)}", path=rel))
        for n, nak in enumerate(rec.naks):
            label = f"NAK PDU {n + 1} of {len(rec.naks)}" if len(rec.naks) > 1 else "NAK PDU"
            evidence.append(Evidence("wire", f"{label}: {nak.hex()}", path=rel))
            if flt.output is None:
                continue
            try:
                value, _in_format, note = render_output(nak, flt.output, profile)
            except OutputError as e:
                notes.append(f"{rel}: the {label} was built but not rendered: {e}")
                continue
            if value not in flags:
                flags.append(value)
                notes.append(f"{rel}: {label} rendered as {flt.output['encoding']}"
                             f"{'' if flt.output['wrap'] == 'none' else ' in a flag wrapper'}: {note}")
    notes.insert(0, f"filter {filter_path.name}: {json.dumps(flt.stated(), sort_keys=True)}")
    if built and flt.output is None:
        notes.append("the filter states no [output] format, so the NAK is reported as hex only: add "
                     "[output] encoding and wrap as the challenge states them")
    if not walked:
        notes.insert(0, f"no file walks as a {flt.framing} stream")
    text = "; ".join(notes)
    if flags:
        # The selection is the reader's translation of the mission profile's prose: a candidate.
        status = "candidate"
    elif built or ambiguous:
        status = "unsure"                  # a NAK with no stated answer format, or a filter to narrow
    else:
        status = "none"
    return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence), engine=ENGINE_ID,
                        notes=text)


def _solve_survey(challenge_dir: Path, files: Sequence[Path], notes: list[str]):
    from ctf.result import Evidence, SolverResult

    evidence = []
    found = 0
    for p in files:
        rel = p.relative_to(challenge_dir).as_posix()
        try:
            got = survey(p.read_bytes())
        except CfdpError:
            continue                       # not a CFDP capture: most files in a handout are not
        found += 1
        evidence.append(Evidence(
            "wire", f"{got['framing']} stream: {got['units']} unit(s), {got['cfdp_units']} carry a whole "
                    f"CFDP PDU, {len(got['rows'])} distinct packet/transaction selection(s)", path=rel))
        for row in got["rows"][:24]:
            evidence.append(Evidence("wire", _row_text(row), path=rel, offset=row["first_offset"]))
        if len(got["rows"]) > 24:
            notes.append(f"{rel}: {len(got['rows']) - 24} more selection(s) not listed (run the survey CLI)")
    if not found:
        return SolverResult(status="none", engine=ENGINE_ID,
                            notes="; ".join([f"no CFDP PDUs in {len(files)} file(s)", *notes]))
    notes.insert(0, (
        f"CFDP found, no filter config: this is a survey under the CFDP standard receiver policy, not "
        f"an answer. Read the handout's mission profile, write {FILTER_NAME} at the top of the challenge "
        f"folder (start from: tools/ctfpy solvers/toolkits/sec_space_cfdp.py skeleton <capture>; keys in "
        f"docs/toolkits/sec_space_cfdp.md) and run: python -m ctf run {ENGINE_ID} <challenge_dir>"))
    return SolverResult(status="unsure", evidence=tuple(evidence), engine=ENGINE_ID,
                        notes="; ".join(notes))


# ------------------------------------------------------------------------------------------ the CLI

def _read(path: str) -> bytes:
    p = Path(path)
    size = p.stat().st_size
    if size > MAX_STREAM:
        raise CfdpError(f"{p} is {size} bytes, over the {MAX_STREAM}-byte limit")
    return p.read_bytes()


def _survey_json(got: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(got)
    out["rows"] = [{**row, "coverage_ranges": len(row["coverage"]),
                    "coverage": [list(r) for r in row["coverage"][:64]],
                    "missing_ranges": len(row["missing"]),
                    "missing": [list(r) for r in row["missing"][:64]]} for row in got["rows"]]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sec_space_cfdp", description="CFDP capture survey, mission filter and NAK reconstruction")
    sub = ap.add_subparsers(dest="command", required=True)
    s = sub.add_parser("survey", help="list every CFDP transaction in a capture with its coverage")
    s.add_argument("capture")
    s.add_argument("--framing", choices=FRAMINGS)
    s.add_argument("--json", action="store_true")
    k = sub.add_parser("skeleton", help="print a filter config pre-filled with one surveyed transaction")
    k.add_argument("capture")
    k.add_argument("--framing", choices=FRAMINGS)
    k.add_argument("--row", type=int, help="the survey row (0-based); needed when there are several")
    n = sub.add_parser("nak", help="run a filter over a capture and print the NAK PDU")
    n.add_argument("capture")
    n.add_argument("--filter", required=True, help="the filter config (TOML)")
    n.add_argument("--event", help="event slug for the [output] flag wrapper (default: CTF_EVENT)")
    n.add_argument("--trace", action="store_true", help="print the decision for every unit")
    n.add_argument("--json", action="store_true")
    try:
        args = ap.parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 2
    try:
        raw = _read(args.capture)
        if args.command == "survey":
            got = survey(raw, args.framing)
            if args.json:
                print(json.dumps(_survey_json(got), indent=2, sort_keys=True))
            else:
                print(f"{got['framing']} stream: {got['units']} unit(s), {got['cfdp_units']} carry a "
                      f"whole CFDP PDU")
                for i, row in enumerate(got["rows"]):
                    print(f"row {i}: {_row_text(row)}")
            return 0
        if args.command == "skeleton":
            got = survey(raw, args.framing)
            rows = got["rows"]
            if args.row is None and len(rows) != 1:
                print(f"sec_space_cfdp: the capture holds {len(rows)} selections; pick one with --row:",
                      file=sys.stderr)
                for i, row in enumerate(rows):
                    print(f"  row {i}: {_row_text(row)}", file=sys.stderr)
                return 2
            index = args.row or 0
            if not 0 <= index < len(rows):
                print(f"sec_space_cfdp: --row {index} is outside 0..{len(rows) - 1}", file=sys.stderr)
                return 2
            print(skeleton(rows[index], got["framing"]))
            return 0
        flt = load_filter(args.filter)
        rec = reconstruct(raw, flt)
        rendered = []
        if flt.output is not None and rec.naks:
            profile = None
            if args.event or flt.output["wrap"] == "flag":
                try:
                    from ctf import event
                except ImportError as e:
                    event = None
                    missing = (f"the repo's ctf package is not importable ({e}): run this through "
                               f"tools/ctfpy so the event profile can be read")
                if event is None:
                    # Same rule as a missing profile below: only a stated prefix goes on without one.
                    if args.event or "prefix" not in flt.output:
                        raise OutputError(f"no event profile for the [output] flag wrapper: {missing}")
                else:
                    try:
                        profile = event.load(args.event) if args.event else event.current()
                    except event.EventError as e:
                        if args.event or "prefix" not in flt.output:
                            raise OutputError(
                                f"no event profile for the [output] flag wrapper: {e}") from None
            rendered = [render_output(nak, flt.output, profile) for nak in rec.naks]
        if args.json:
            out = rec.to_dict()
            out["rendered"] = [{"value": v, "in_event_format": ok, "note": note} for v, ok, note in rendered]
            if args.trace:
                out["trace"] = [list(t) for t in rec.trace]
            print(json.dumps(out, indent=2, sort_keys=True))
        else:
            if args.trace:
                for unit, offset, kind, decision in rec.trace:
                    print(f"unit {unit} @{offset} {kind}: {decision}")
            print(f"{rec.units} unit(s), {rec.selected} selected, {rec.segments} segment(s) cover "
                  f"{rec.covered_bytes} byte(s)")
            for why, count in rec.discards.items():
                print(f"not counted: {count} {why}")
            for why in rec.malformed:
                print(f"malformed: {why}")
            if rec.scope:
                print(f"scope [{rec.scope[0]},{rec.scope[1]}): missing {rec.missing_bytes} byte(s) in "
                      f"{len(rec.missing)} range(s): {_ranges_text(rec.missing)}")
            if not rec.naks:
                print(f"no NAK: {rec.reason}")
            for nak in rec.naks:
                print(f"NAK {nak.hex()}")
            for value, _ok, note in rendered:
                print(f"answer {value}  ({note})")
        return 0 if rec.naks else 1
    except (CfdpError, FilterError, OutputError, OSError) as e:
        print(f"sec_space_cfdp: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
