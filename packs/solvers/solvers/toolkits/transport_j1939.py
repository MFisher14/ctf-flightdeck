#!/usr/bin/env python3
"""Offline J1939 SPN/NAME and J1587 payload analysis.

Reuses automotive_advanced's candump, identifier and TP readers. No adapters,
network, transmission, code execution or automatic submission. Unknown PGNs
return None; malformed arguments raise TransportJ1939Error. Raw values remain
available beside physical units, including reserved/error/not-available codes.

References: SAE J1939-71/81; CSS Electronics J1939 tutorial's published EEC1
example; Kvaser J1587/J1708 introductions. This is a deliberately small public
PGN table, not a substitute for the licensed SAE Digital Annex.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import automotive_advanced as _auto

MAX_FILE = 16 << 20


class TransportJ1939Error(ValueError):
    """Malformed, unsupported serialization, or over-limit transport artifact."""


def _bytes(data, cap=1785):
    if isinstance(data, str):
        if len(data) > cap * 3:
            raise TransportJ1939Error("hex payload exceeds limit")
        try:
            data = bytes.fromhex(data)
        except ValueError as exc:
            raise TransportJ1939Error("invalid hex payload") from exc
    if not isinstance(data, (bytes, bytearray)) or len(data) > cap:
        raise TransportJ1939Error("payload must be bounded bytes or hex")
    return bytes(data)


def _integer(value, maximum, label):
    if type(value) is not int or not 0 <= value <= maximum:
        raise TransportJ1939Error(f"invalid {label}")
    return value


def _spn(data, offset, size, scale, bias, unit):
    raw = int.from_bytes(data[offset:offset + size], "little")
    high = raw >> (8 * (size - 1))
    status = "available" if high < 0xFB else {
        0xFF: "not_available", 0xFE: "error"}.get(high, "reserved")
    return {"raw": raw, "value": raw * scale + bias if status == "available" else None,
            "unit": unit, "status": status}


def decode_name(data):
    """Decode the little-endian 64-bit NAME used by PGN 60928 address claims."""
    data = _bytes(data, 8)
    if len(data) != 8:
        raise TransportJ1939Error("NAME requires exactly eight bytes")
    name = int.from_bytes(data, "little")
    return {"name": name, "identity_number": name & 0x1FFFFF,
            "manufacturer_code": (name >> 21) & 0x7FF,
            "ecu_instance": (name >> 32) & 7,
            "function_instance": (name >> 35) & 31,
            "function": (name >> 40) & 255,
            "reserved": (name >> 48) & 1,
            "vehicle_system": (name >> 49) & 127,
            "vehicle_system_instance": (name >> 56) & 15,
            "industry_group": (name >> 60) & 7,
            "arbitrary_address_capable": bool(name >> 63)}


# SPN number, label, byte offset, width, scale, offset, unit.
_TABLE = {
    61444: ("EEC1", [(190, "engine_speed", 3, 2, .125, 0, "rpm"),
                      (512, "driver_demand_torque", 1, 1, 1, -125, "%"),
                      (513, "actual_engine_torque", 2, 1, 1, -125, "%")]),
    65265: ("CCVS1", [(84, "wheel_based_vehicle_speed", 1, 2, 1/256, 0, "km/h")]),
    65262: ("ET1", [(110, "engine_coolant_temperature", 0, 1, 1, -40, "degC")]),
    65253: ("HOURS", [(247, "engine_total_hours", 0, 4, .05, 0, "h"),
                       (249, "engine_total_revolutions", 4, 4, 1000, 0, "rev")]),
    65257: ("LFC", [(182, "engine_trip_fuel", 0, 4, .5, 0, "L"),
                     (250, "engine_total_fuel_used", 4, 4, .5, 0, "L")]),
}


def decode_pgn(pgn, data):
    """Decode a complete PGN payload, including a caller-reassembled TP payload."""
    pgn = _integer(pgn, 0x3FFFF, "PGN")
    data = _bytes(data)
    if pgn not in _TABLE and pgn not in (60928, 59904, 65260):
        return None
    out = {"pgn": pgn, "raw_hex": data.hex()}
    if pgn == 65260:
        if not data or any(b < 32 or b > 126 for b in data):
            raise TransportJ1939Error("vehicle identification must be printable ASCII")
        out.update(name="VI", vehicle_identification=data.decode("ascii").rstrip("*"))
        return out
    expected = 3 if pgn == 59904 else 8
    if len(data) != expected:
        raise TransportJ1939Error(f"PGN {pgn} requires {expected} bytes")
    if pgn == 60928:
        out.update(decode_name(data))
        # Preserve the human-readable label independently of numeric NAME.
        out["pgn_name"] = "Address Claimed"
    elif pgn == 59904:
        requested = int.from_bytes(data, "little")
        if requested > 0x3FFFF:
            raise TransportJ1939Error("requested PGN exceeds 18 bits")
        out.update(name="Request", requested_pgn=requested)
    else:
        name, specs = _TABLE[pgn]
        out.update(name=name, spns={})
        for spn, label, offset, size, scale, bias, unit in specs:
            out["spns"][str(spn)] = {"label": label, **_spn(data, offset, size, scale, bias, unit)}
    return out


def decode_frame(can_id, data):
    """Decode a single CAN payload; TP transport frames themselves return None."""
    _integer(can_id, 0x1FFFFFFF, "CAN identifier")
    data = _bytes(data, 8)
    try:
        fields = _auto.parse_j1939_id(can_id)
    except Exception as exc:
        raise TransportJ1939Error("invalid J1939 identifier") from exc
    result = decode_pgn(fields["pgn"], data)
    return {**fields, **result} if result is not None else None


def decode_j1587(data):
    """Read one complete J1708 packet; UART idle-gap framing is caller supplied.

    Handles fixed/variable-length PIDs and the 255 page-extension escape. PID254
    proprietary framing is deliberately rejected. Unknown standard PIDs retain
    bytes; no guesses are made about their meaning or engineering units.
    """
    data = _bytes(data, 21)
    if len(data) < 4 or data[0] < 128:
        raise TransportJ1939Error("J1587 needs MID 128..255, PID/data, checksum")
    if sum(data) & 255:
        raise TransportJ1939Error("J1708 checksum mismatch")
    parameters = []
    pos, end = 1, len(data) - 1
    while pos < end:
        pid = data[pos]
        pos += 1
        if pid == 255:
            if pos >= end:
                raise TransportJ1939Error("truncated extended PID")
            pid = 256 + data[pos]
            pos += 1
        base = pid % 256
        if base >= 254:
            raise TransportJ1939Error("proprietary/reserved PID framing unsupported")
        if base < 128:
            size = 1
        elif base < 192:
            size = 2
        else:
            if pos >= end:
                raise TransportJ1939Error("missing variable PID length")
            size = data[pos]
            pos += 1
        if pos + size > end:
            raise TransportJ1939Error("truncated PID data")
        value = data[pos:pos + size]
        pos += size
        row = {"pid": pid, "raw_hex": value.hex(), "unsigned": int.from_bytes(value, "little")}
        if pid == 21:
            row.update(value=int.from_bytes(value, "little", signed=True) * 2.5, unit="degF")
        if pid in (225, 226, 227, 237):
            row["text_latin1"] = value.decode("latin1")
        parameters.append(row)
    return {"mid": data[0], "parameters": parameters, "checksum_valid": True}


def analyze_candump(text):
    """Read saved frames and existing TP reassembly, then apply PGN semantics."""
    try:
        if not isinstance(text, (str, bytes)) or len(text) > MAX_FILE:
            raise TransportJ1939Error("candump exceeds text limit")
        frames = _auto.parse_candump(text)
        frames = [f for f in frames if f["extended"] and not f["fd"]]
        transfer = _auto.reassemble_j1939_tp(frames)
        rows = []
        for frame in frames:
            row = decode_frame(frame["can_id"], frame["data"])
            if row is not None:
                rows.append({"frame": frame["index"], **row})
        for message in transfer["messages"]:
            row = decode_pgn(message["pgn"], message["data"])
            if row is not None:
                rows.append({"source": message["source"], "destination": message["destination"],
                             "frame_indices": message["frame_indices"], **row})
        return {"messages": rows, "tp_issues": transfer["issues"]}
    except TransportJ1939Error:
        raise
    except Exception as exc:
        raise TransportJ1939Error("malformed candump/TP input") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--format", choices=("candump", "j1587"), default="candump")
    try:
        args = parser.parse_args(argv)
        with args.file.open("rb") as stream:
            data = stream.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise TransportJ1939Error("input exceeds file limit")
        if args.format == "j1587":
            text = data.decode("ascii")
            result = [decode_j1587(line) for line in text.splitlines() if line.strip()]
        else:
            result = analyze_candump(data)
        print(json.dumps(result, indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (ValueError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
