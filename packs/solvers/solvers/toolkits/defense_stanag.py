#!/usr/bin/env python3
"""Bounded offline STANAG 4607 GMTI and STANAG 5066 SIS envelope readers.

4607: editions represented by 21/30, header/segment framing, mission and platform
location. Other segment bodies are opaque. 5066: SIS version 0 or explicit old
edition1 framing, NOT DTS radio framing; PDU bodies remain opaque. Input is a
complete packet or concatenated stream already extracted from a capture.

Layouts cross-checked against Wireshark's packet-stanag4607.c and
packet-s5066sis.c. No network, decompression, subprocess or artifact execution.
Public parsers raise only DefenseStanagError on malformed/unsupported input.
CLI: defense_stanag.py {4607,5066} payload.bin [--edition-one]
"""
from __future__ import annotations

import argparse
from datetime import date
import json
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_BYTES = 8 * 1024 * 1024
MAX_RECORDS = 4096


class DefenseStanagError(ValueError):
    """Malformed, unsupported or oversized STANAG input."""


def _data(value):
    if type(value) not in (bytes, bytearray) or not 0 < len(value) <= MAX_BYTES:
        raise DefenseStanagError("expected nonempty bounded bytes")
    return bytes(value)


def _uint(data):
    return int.from_bytes(data, "big")


def _text(data):
    data = data.rstrip(b"\0 ")
    if any(x < 32 or x > 126 for x in data):
        raise DefenseStanagError("invalid ASCII header field")
    return data.decode("ascii")


def _flags(data):
    return [x.decode("ascii") for x in dict.fromkeys(
        flagfmt.BYTES.findall(data))]


def _mission(body):
    if len(body) != 39:
        raise DefenseStanagError("mission segment must have 39 body bytes")
    year, month, day = _uint(body[35:37]), body[37], body[38]
    try:
        stamp = date(year, month, day).isoformat()
    except ValueError as exc:
        raise DefenseStanagError("invalid mission date") from exc
    return {"mission_plan": _text(body[:12]), "flight_plan": _text(body[12:24]),
            "platform_type": body[24], "platform_configuration": _text(body[25:35]),
            "date": stamp}


def _location(body):
    if len(body) != 23:
        raise DefenseStanagError("platform location must have 23 body bytes")
    lat = int.from_bytes(body[4:8], "big", signed=True) * 90 / 2**31
    if not -90 <= lat <= 90:
        raise DefenseStanagError("platform latitude outside terrestrial range")
    lon = _uint(body[8:12]) * 360 / 2**32
    return {"time_ms": _uint(body[:4]), "latitude_deg": lat,
            "longitude_deg": lon, "longitude_signed_deg": lon if lon <= 180 else lon - 360,
            "altitude_cm": int.from_bytes(body[12:16], "big", signed=True),
            "track_deg": _uint(body[16:18]) * 360 / 2**16,
            "speed_mm_s": _uint(body[18:22]),
            "vertical_velocity_dm_s": int.from_bytes(body[22:23], "big", signed=True)}


def parse_4607(value: bytes) -> dict:
    """Parse full 21/30 GMTI packet stream, requiring all declared bytes."""
    data = _data(value)
    packets, offset, nsegments = [], 0, 0
    while offset < len(data):
        if len(packets) >= MAX_RECORDS or len(data) - offset < 32:
            raise DefenseStanagError("truncated header or too many packets")
        h = data[offset:offset + 32]
        if h[:2] not in (b"21", b"30"):
            raise DefenseStanagError("supported GMTI versions are 21 and 30")
        size = _uint(h[2:6])
        if size < 37 or size > len(data) - offset:
            raise DefenseStanagError("invalid packet size")
        end = offset + size
        packet = {"offset": offset, "length": size, "version": h[:2].decode("ascii"),
                  "nationality": _text(h[6:8]), "security_class": h[8],
                  "security_system": _text(h[9:11]), "security_code": _uint(h[11:13]),
                  "exercise_indicator": h[13], "platform_id": _text(h[14:24]),
                  "mission_id": _uint(h[24:28]), "job_id": _uint(h[28:32]),
                  "segments": []}
        cursor = offset + 32
        while cursor < end:
            nsegments += 1
            if nsegments > MAX_RECORDS or end - cursor < 5:
                raise DefenseStanagError("truncated segment header or too many segments")
            kind, length = data[cursor], _uint(data[cursor + 1:cursor + 5])
            if length < 5 or length > end - cursor:
                raise DefenseStanagError("invalid segment length")
            body = data[cursor + 5:cursor + length]
            segment = {"type": kind, "offset": cursor, "length": length,
                       "body_hex": body.hex()}
            if kind == 1:
                segment["mission"] = _mission(body)
            elif kind == 13:
                segment["platform_location"] = _location(body)
            else:
                segment["opaque"] = True
            packet["segments"].append(segment)
            cursor += length
        packets.append(packet)
        offset = end
    return {"format": "STANAG 4607", "packets": packets, "flags": _flags(data)}


_SIS_NAMES = (
    "UNKNOWN", "S_BIND_REQUEST", "S_UNBIND_REQUEST", "S_BIND_ACCEPTED", "S_BIND_REJECTED",
    "S_UNBIND_INDICATION", "S_HARD_LINK_ESTABLISH", "S_HARD_LINK_TERMINATE",
    "S_HARD_LINK_ESTABLISHED", "S_HARD_LINK_REJECTED", "S_HARD_LINK_TERMINATED",
    "S_HARD_LINK_INDICATION", "S_HARD_LINK_ACCEPT", "S_HARD_LINK_REJECT",
    "S_SUBNET_AVAILABILITY", "S_DATAFLOW_ON", "S_DATAFLOW_OFF", "S_KEEP_ALIVE",
    "S_MANAGEMENT_MESSAGE_REQUEST", "S_MANAGEMENT_MESSAGE_INDICATION",
    "S_UNIDATA_REQUEST", "S_UNIDATA_INDICATION", "S_UNIDATA_REQUEST_CONFIRM",
    "S_UNIDATA_REQUEST_REJECTED", "S_EXPEDITED_UNIDATA_REQUEST",
    "S_EXPEDITED_UNIDATA_INDICATION", "S_EXPEDITED_UNIDATA_REQUEST_CONFIRM",
    "S_EXPEDITED_UNIDATA_REQUEST_REJECTED")


def parse_5066(value: bytes, *, edition_one: bool = False) -> dict:
    """Frame SIS stream. Unknown PDU bodies stay opaque; no TCP reassembly."""
    data = _data(value)
    if type(edition_one) is not bool:
        raise DefenseStanagError("edition_one must be boolean")
    header = 4 if edition_one else 5
    records, offset = [], 0
    while offset < len(data):
        if len(records) >= MAX_RECORDS or len(data) - offset < header + 1:
            raise DefenseStanagError("truncated SIS header or too many PDUs")
        if data[offset:offset + 2] != b"\x90\xeb":
            raise DefenseStanagError("SIS sync must be 90EB")
        if not edition_one and data[offset + 2] != 0:
            raise DefenseStanagError("only SIS version 0 supported")
        size = _uint(data[offset + header - 2:offset + header])
        if size < 1 or size + header > len(data) - offset:
            raise DefenseStanagError("invalid SIS PDU length")
        kind = data[offset + header]
        body = data[offset + header + 1:offset + header + size]
        records.append({"offset": offset, "length": header + size,
                        "pdu_type": kind, "name": _SIS_NAMES[kind] if kind < len(_SIS_NAMES) else "UNKNOWN",
                        "body_hex": body.hex(), "body_validation": "opaque"})
        offset += header + size
    return {"format": "STANAG 5066 SIS", "edition_one": edition_one,
            "records": records, "flags": _flags(data)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("format", choices=("4607", "5066"))
    parser.add_argument("file")
    parser.add_argument("--edition-one", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.edition_one and args.format != "5066":
            raise DefenseStanagError("--edition-one only applies to 5066 SIS")
        with Path(args.file).open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        report = parse_4607(raw) if args.format == "4607" else parse_5066(raw, edition_one=args.edition_one)
        print(json.dumps(report, indent=2))
        return 0
    except (DefenseStanagError, OSError, ValueError) as exc:
        print(f"defense_stanag: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
