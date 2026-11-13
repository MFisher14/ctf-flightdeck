#!/usr/bin/env python3
"""Offline physical-field decoder for selected NMEA 2000 PGNs.

Reads complete payloads or saved candump. Reuses automotive_advanced's existing
CAN/fast-packet readers. Supports 126992, 127250, 127488, 129025, 129026, 129029.
Layouts: CANboat PGN documentation, https://canboat.github.io/canboat/canboat.html
No sockets, adapters, subprocesses, transmission, or untrusted code execution.
Malformed input raises TransportNMEA2000Error; unsupported PGNs return None.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

import automotive_advanced as _auto

MAX_FILE = 16 << 20
SUPPORTED = frozenset((126992, 127250, 127488, 129025, 129026, 129029))


class TransportNMEA2000Error(ValueError):
    """Malformed or over-limit NMEA 2000 artifact."""


def _raw(data):
    if isinstance(data, str):
        if len(data) > 669:
            raise TransportNMEA2000Error("payload exceeds fast-packet limit")
        try:
            data = bytes.fromhex(data)
        except ValueError as exc:
            raise TransportNMEA2000Error("invalid hex payload") from exc
    if not isinstance(data, (bytes, bytearray)) or len(data) > 223:
        raise TransportNMEA2000Error("expected at most 223 bytes")
    return bytes(data)


def _number(data, pos, size, scale=1, signed=False):
    raw = int.from_bytes(data[pos:pos+size], "little", signed=signed)
    maximum = (1 << (8 * size - int(signed))) - 1
    if raw >= maximum - 2:
        return None
    return raw * scale


def _coordinate(value, bound):
    if value is not None and not -bound <= value <= bound:
        raise TransportNMEA2000Error("coordinate outside physical range")
    return value


def _angle(value, signed=False):
    if value is not None and not (-math.pi if signed else 0) <= value <= (math.pi if signed else 2*math.pi):
        raise TransportNMEA2000Error("angle outside physical range")
    return value


def _time(days, seconds):
    if seconds is not None and not 0 <= seconds <= 86401:
        raise TransportNMEA2000Error("UTC seconds exceed one day")
    return days * 86400 + seconds if days is not None and seconds is not None else None


def decode_pgn(pgn, data):
    """Decode a complete payload; unavailable/error/reserved numeric sentinels -> None.

    raw_hex is always retained so distinct sentinel values remain inspectable.
    Fast packet 129029 must be reassembled before calling this entry point.
    """
    if type(pgn) is not int or not 0 <= pgn <= 0x3FFFF:
        raise TransportNMEA2000Error("invalid PGN")
    data = _raw(data)
    if pgn not in SUPPORTED:
        return None
    if len(data) != 8 and pgn != 129029:
        raise TransportNMEA2000Error("single-frame PGN requires eight bytes")
    if pgn == 129029 and len(data) < 43:
        raise TransportNMEA2000Error("GNSS payload requires at least 43 bytes")
    out = {"pgn": pgn, "raw_hex": data.hex()}
    n = lambda p, s, scale=1, signed=False: _number(data, p, s, scale, signed)
    if pgn == 129025:
        out.update(latitude=_coordinate(n(0, 4, 1e-7, True), 90),
                   longitude=_coordinate(n(4, 4, 1e-7, True), 180))
    elif pgn == 129026:
        out.update(sid=n(0, 1), reference=data[1] & 3,
                   course_rad=_angle(n(2, 2, .0001)), speed_m_s=n(4, 2, .01))
    elif pgn == 127250:
        out.update(sid=n(0, 1), reference=data[7] & 3,
                   heading_rad=_angle(n(1, 2, .0001)),
                   deviation_rad=_angle(n(3, 2, .0001, True), True),
                   variation_rad=_angle(n(5, 2, .0001, True), True))
    elif pgn == 127488:
        out.update(instance=n(0, 1), engine_speed_rpm=n(1, 2, .25),
                   boost_pressure_pa=n(3, 2, 100), tilt_trim_percent=n(5, 1, 1, True))
    elif pgn == 126992:
        days, seconds = n(2, 2), n(4, 4, .0001)
        out.update(sid=n(0, 1), time_source=data[1] & 15,
                   epoch_days=days, seconds_since_midnight=seconds,
                   unix_time=_time(days, seconds))
    else:
        count = n(42, 1)
        if len(data) != 43 + (count or 0) * 4:
            raise TransportNMEA2000Error("GNSS reference-station count/length mismatch")
        days, seconds = n(1, 2), n(3, 4, .0001)
        out.update(sid=n(0, 1), epoch_days=days, seconds_since_midnight=seconds,
                   unix_time=_time(days, seconds),
                   latitude=_coordinate(n(7, 8, 1e-16, True), 90),
                   longitude=_coordinate(n(15, 8, 1e-16, True), 180),
                   altitude_m=n(23, 8, 1e-6, True),
                   gnss_type=data[31] & 15, method=data[31] >> 4,
                   integrity=data[32] & 3, satellites=n(33, 1),
                   hdop=n(34, 2, .01, True), pdop=n(36, 2, .01, True),
                   geoidal_separation_m=n(38, 4, .01, True),
                   reference_station_count=count, reference_stations=[])
        for pos in range(43, len(data), 4):
            word = int.from_bytes(data[pos:pos+2], "little")
            out["reference_stations"].append({"type": word & 15, "id": word >> 4,
                                               "age_seconds": n(pos+2, 2, .01)})
    return out


def analyze_candump(text):
    """Select supported PGNs, reassemble GNSS fast packets, decode fields."""
    try:
        if not isinstance(text, (str, bytes)) or len(text) > MAX_FILE:
            raise TransportNMEA2000Error("candump exceeds input limit")
        frames = _auto.parse_candump(text)
        singles, fast = [], []
        for frame in frames:
            if not frame["extended"] or frame["fd"]:
                continue
            fields = _auto.parse_j1939_id(frame["can_id"])
            if fields["pgn"] == 129029:
                fast.append(frame)
            elif fields["pgn"] in SUPPORTED:
                singles.append({"source": fields["source"], "frame": frame["index"],
                                **decode_pgn(fields["pgn"], frame["data"])})
        assembled = _auto.reassemble_j1939_fast_packets(fast)
        for message in assembled["messages"]:
            singles.append({"source": message["source"], "frame_indices": message["frame_indices"],
                            **decode_pgn(message["pgn"], message["data"])})
        return {"messages": singles, "fast_packet_issues": assembled["issues"]}
    except TransportNMEA2000Error:
        raise
    except Exception as exc:
        raise TransportNMEA2000Error("malformed candump/fast-packet input") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", type=Path)
    parser.add_argument("--pgn", type=int, help="file is one complete binary PGN, not candump")
    try:
        args = parser.parse_args(argv)
        with args.file.open("rb") as stream:
            data = stream.read(MAX_FILE + 1)
        if len(data) > MAX_FILE:
            raise TransportNMEA2000Error("input exceeds file limit")
        result = decode_pgn(args.pgn, data) if args.pgn is not None else analyze_candump(data)
        print(json.dumps(result, indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
