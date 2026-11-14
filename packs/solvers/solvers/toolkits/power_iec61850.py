#!/usr/bin/env python3
"""Offline IEC 61850 SV decoder and strict adapter for the existing GOOSE decoder.

Inputs are one raw Ethernet frame (including optional VLAN tags) or one APPID
payload. For PCAP/PCAPNG use the existing capture readers and pass their Ethernet
frames to parse_frame/analyze_frames. No capture interface or network operations.

SV fields follow IEC 61850-9-2 and libiec61850's sv_subscriber.c. seqData remains
opaque unless the caller explicitly selects the 64-byte 9-2LE dataset. GOOSE
typed decoding is reused from network_ics_depth, not reimplemented here.
All public parser failures raise Power61850Error, including invalid argument types.
"""
from __future__ import annotations

import argparse
from functools import wraps
import json
import math
from pathlib import Path
import sys

MAX_FRAME = 65599
MAX_ITEMS = 10000
MAX_DEPTH = 16


class Power61850Error(ValueError):
    """Malformed, unsupported, or excessive IEC 61850 input."""


def _guard(fn):
    @wraps(fn)
    def call(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Power61850Error:
            raise
        except Exception as exc:
            raise Power61850Error(f"{fn.__name__}: {exc}") from None
    return call


def _blob(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise Power61850Error("input must be bytes-like")
    if (data.nbytes if isinstance(data, memoryview) else len(data)) > MAX_FRAME:
        raise Power61850Error("frame exceeds size cap")
    return bytes(data)


def _tlvs(data, budget):
    at, rows = 0, []
    while at < len(data):
        if budget[0] <= 0 or at + 2 > len(data):
            raise Power61850Error("truncated BER or item limit exceeded")
        budget[0] -= 1
        tag, size = data[at:at + 2]
        at += 2
        if tag & 31 == 31:
            raise Power61850Error("high-tag-number BER is unsupported")
        if size & 128:
            count = size & 127
            if not 1 <= count <= 4 or at + count > len(data):
                raise Power61850Error("unsupported indefinite or invalid BER length")
            size = int.from_bytes(data[at:at + count], "big")
            at += count
        if size > len(data) - at:
            raise Power61850Error("BER value is truncated")
        rows.append((tag, data[at:at + size]))
        at += size
    return rows


def _fields(data, allowed, required, budget):
    rows = _tlvs(data, budget)
    out, previous = {}, -1
    for tag, value in rows:
        if tag not in allowed or tag in out or (tag & 31) <= previous:
            raise Power61850Error("unknown, duplicate, or unordered field")
        previous = tag & 31
        out[tag] = value
    if not required <= out.keys():
        raise Power61850Error("missing mandatory field")
    return out


def _uint(raw, max_value=0xffffffff):
    if not 1 <= len(raw) <= 5 or raw[0] & 128:
        raise Power61850Error("invalid nonnegative BER integer")
    value = int.from_bytes(raw, "big")
    if value > max_value:
        raise Power61850Error("BER integer is out of range")
    return value


def _width(raw, size):
    if len(raw) != size:
        raise Power61850Error(f"field must contain {size} bytes")


def _visible(raw):
    if any(b < 32 or b > 126 for b in raw):
        raise Power61850Error("invalid VisibleString")
    return raw.decode("ascii")


def _utc(raw):
    _width(raw, 8)
    fraction = int.from_bytes(raw[4:7], "big")
    return {"seconds": int.from_bytes(raw[:4], "big"), "fraction_raw": fraction,
            "fraction_seconds": fraction / (1 << 24), "quality": raw[7],
            "leap_seconds_known": bool(raw[7] & 128),
            "clock_failure": bool(raw[7] & 64), "not_synchronized": bool(raw[7] & 32),
            "time_accuracy": raw[7] & 31, "raw_hex": raw.hex()}


def _envelope(data, outer_tag):
    data = _blob(data)
    if len(data) < 10:
        raise Power61850Error("truncated APPID header/PDU")
    declared = int.from_bytes(data[2:4], "big")
    if declared != len(data):
        raise Power61850Error("APPID length mismatch")
    budget = [MAX_ITEMS]
    rows = _tlvs(data[8:], budget)
    if len(rows) != 1 or rows[0][0] != outer_tag:
        raise Power61850Error("unexpected application PDU")
    return data, rows[0][1], budget


def _validate_data(data, budget, depth=0):
    if depth >= MAX_DEPTH:
        raise Power61850Error("dataset nesting limit exceeded")
    rows = _tlvs(data, budget)
    for tag, raw in rows:
        if tag in (0xa1, 0xa2):
            _validate_data(raw, budget, depth + 1)
        elif tag == 0x83:
            _width(raw, 1)
        elif tag in (0x84, 0x8e):
            if not raw or raw[0] > 7 or (len(raw) == 1 and raw[0]):
                raise Power61850Error("invalid bit-string")
            if raw[0] and raw[-1] & ((1 << raw[0]) - 1):
                raise Power61850Error("nonzero bit-string padding")
        elif tag in (0x85, 0x86, 0x8d):
            if not 1 <= len(raw) <= 9 or (tag == 0x86 and raw[0] & 128):
                raise Power61850Error("invalid dataset integer")
        elif tag == 0x87:
            if not ((len(raw) == 5 and raw[0] == 8) or (len(raw) == 9 and raw[0] == 11)):
                raise Power61850Error("unsupported floating-point representation")
        elif tag == 0x8a:
            _visible(raw)
        elif tag == 0x8c:
            if len(raw) not in (4, 6):
                raise Power61850Error("invalid binary-time length")
        elif tag == 0x90:
            raw.decode("utf-8")
        elif tag == 0x91:
            _utc(raw)
        elif tag != 0x89:
            raise Power61850Error(f"unsupported dataset tag 0x{tag:02x}")
    return len(rows)


def _json_values(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {k: _json_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_values(v) for v in obj]
    if isinstance(obj, float) and not math.isfinite(obj):
        return str(obj)
    return obj


@_guard
def parse_goose(payload):
    """Validate a complete APPID payload, then reuse existing GOOSE value decoding."""
    data, body, budget = _envelope(payload, 0x61)
    allowed = set(range(0x80, 0x8b)) | {0xab}
    required = allowed - {0x83, 0x87, 0x89}  # goID optional; booleans DEFAULT FALSE
    fields = _fields(body, allowed, required, budget)
    for tag in (0x80, 0x82, 0x83):
        if tag in fields:
            _visible(fields[tag])
    for tag in (0x81, 0x85, 0x86, 0x88, 0x8a):
        _uint(fields[tag])
    for tag in (0x87, 0x89):
        if tag in fields:
            _width(fields[tag], 1)
    timestamp = _utc(fields[0x84])
    count = _validate_data(fields[0xab], budget)
    if count != _uint(fields[0x8a]):
        raise Power61850Error("numDatSetEntries does not match allData")
    from network_ics_depth import parse_goose as existing_decode
    result = existing_decode(data)
    if result is None:
        raise Power61850Error("existing GOOSE decoder rejected validated payload")
    result = _json_values(result)
    result["fields"].setdefault("simulation", False)
    result["fields"].setdefault("needs_commissioning", False)
    result["timestamp_detail"] = timestamp
    result["all_data_hex"] = fields[0xab].hex()
    return result


@_guard
def parse_sv(payload, *, decode_9_2le=False):
    """Decode SV APPID payload. Optional 9-2LE interpretation requires 64 seqData bytes.

    Without SCL/schema, samples have no general type or scale. 9-2LE mode returns
    signed integer counts and raw quality words, without applying engineering units.
    """
    if not isinstance(decode_9_2le, bool):
        raise Power61850Error("decode_9_2le must be boolean")
    data, body, budget = _envelope(payload, 0x60)
    fields = _fields(body, {0x80, 0xa2}, {0x80, 0xa2}, budget)
    count = _uint(fields[0x80], 65535)
    rows = _tlvs(fields[0xa2], budget)
    if not count or count != len(rows):
        raise Power61850Error("noASDU does not match nonempty ASDU sequence")
    asdus = []
    for tag, raw in rows:
        if tag != 0x30:
            raise Power61850Error("ASDU must be a BER sequence")
        f = _fields(raw, set(range(0x80, 0x8a)), {0x80, 0x82, 0x83, 0x87}, budget)
        row = {"sv_id": _visible(f[0x80]), "data_hex": f[0x87].hex()}
        for tag, name, width in ((0x82, "sample_count", 2), (0x83, "conf_revision", 4),
                                 (0x85, "sample_sync", 1), (0x86, "sample_rate", 2),
                                 (0x88, "sample_mode", 1)):
            if tag in f:
                _width(f[tag], width)
                row[name] = int.from_bytes(f[tag], "big")
        # Ed2 permits 5..254 as a local synchronization source identifier.
        # See IEEE PSRC H6 report 053, p.30; do not confuse it with Ed2.1's enum.
        if row.get("sample_sync", 0) in (3, 4, 255) or row.get("sample_mode", 0) > 2:
            raise Power61850Error("unsupported sample sync/mode enumeration")
        if row.get("sample_sync", 0) >= 5:
            row["legacy_local_sync_source_id"] = row["sample_sync"]
        if 0x81 in f:
            row["dataset"] = _visible(f[0x81])
        if 0x84 in f:
            row["reference_time"] = _utc(f[0x84])
        if 0x89 in f:
            _width(f[0x89], 8)
            row["gmid_hex"] = f[0x89].hex()
        if decode_9_2le:
            _width(f[0x87], 64)
            samples = []
            for i, channel in enumerate(("Ia", "Ib", "Ic", "In", "Va", "Vb", "Vc", "Vn")):
                value = f[0x87][i * 8:i * 8 + 8]
                samples.append({"channel": channel, "raw_value": int.from_bytes(value[:4], "big", signed=True),
                                "quality": int.from_bytes(value[4:], "big")})
            row["profile"] = "9-2LE (caller selected)"
            row["samples"] = samples
        asdus.append(row)
    return {"protocol": "iec61850-sv", "appid": int.from_bytes(data[:2], "big"),
            "declared_length": len(data), "reserved": [int.from_bytes(data[4:6], "big"),
            int.from_bytes(data[6:8], "big")], "asdu_count": count, "asdus": asdus}


@_guard
def parse_frame(frame, *, decode_9_2le=False):
    """Decode one Ethernet GOOSE/SV frame; retain any padding/FCS as opaque trailer."""
    if not isinstance(decode_9_2le, bool):
        raise Power61850Error("decode_9_2le must be boolean")
    data = _blob(frame)
    if len(data) < 14:
        raise Power61850Error("truncated Ethernet frame")
    ethertype, at, vlans = int.from_bytes(data[12:14], "big"), 14, []
    while ethertype in (0x8100, 0x88a8, 0x9100):
        if len(vlans) >= 4 or at + 4 > len(data):
            raise Power61850Error("truncated/excessive VLAN tags")
        tci = int.from_bytes(data[at:at + 2], "big")
        vlans.append({"tpid": ethertype, "id": tci & 4095, "priority": tci >> 13,
                      "dei": bool(tci & 4096)})
        ethertype = int.from_bytes(data[at + 2:at + 4], "big")
        at += 4
    if ethertype not in (0x88b8, 0x88ba) or len(data) < at + 8:
        raise Power61850Error("not a complete GOOSE/SV Ethernet frame")
    size = int.from_bytes(data[at + 2:at + 4], "big")
    if size < 10 or at + size > len(data):
        raise Power61850Error("truncated or invalid APPID payload")
    payload = data[at:at + size]
    out = parse_goose(payload) if ethertype == 0x88b8 else parse_sv(payload, decode_9_2le=decode_9_2le)
    out["ethernet"] = {"source": data[6:12].hex(":"), "destination": data[:6].hex(":"),
                       "ethertype": ethertype, "vlans": vlans, "trailer_hex": data[at + size:].hex()}
    return out


@_guard
def analyze_frames(frames, *, decode_9_2le=False):
    """Decode a bounded list of GOOSE/SV Ethernet frames and report GOOSE counter observations.

    Observations are evidence, not intrusion verdicts: restarts, loss and reordering
    can explain nonmonotonic counters. SV wrap intervals require external configuration.
    """
    if not isinstance(decode_9_2le, bool):
        raise Power61850Error("decode_9_2le must be boolean")
    if not isinstance(frames, (list, tuple)) or len(frames) > MAX_ITEMS:
        raise Power61850Error("frames must be a bounded list/tuple")
    if sum(len(_blob(f)) for f in frames) > 32 << 20:
        raise Power61850Error("frame batch exceeds 32 MiB")
    decoded, observations, previous = [], [], {}
    for i, frame in enumerate(frames):
        row = parse_frame(frame, decode_9_2le=decode_9_2le)
        decoded.append(row)
        if row["protocol"] != "iec61850-goose":
            continue
        f = row["fields"]
        key = (row["ethernet"]["source"], row["ethernet"]["destination"],
               tuple(v["id"] for v in row["ethernet"]["vlans"]), row["appid"], f["gocb_ref"])
        if key in previous:
            old = previous[key]
            of = old["fields"]
            kinds = []
            if f["conf_revision"] != of["conf_revision"]:
                kinds.append("configuration_changed")
            if f["state_number"] == of["state_number"]:
                if row["all_data_hex"] != old["all_data_hex"]:
                    kinds.append("dataset_encoding_changed_without_state_change")
                if f["sequence_number"] <= of["sequence_number"]:
                    kinds.append("sequence_not_increasing")
            elif f["state_number"] < of["state_number"]:
                kinds.append("state_decreased_or_wrapped")
            for kind in kinds:
                observations.append({"frame_index": i, "gocb_ref": f["gocb_ref"], "kind": kind})
        previous[key] = row
    return {"frames": decoded, "observations": observations}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="one raw Ethernet frame or APPID payload")
    parser.add_argument("--format", choices=("ethernet", "goose", "sv"), default="ethernet")
    parser.add_argument("--hex", action="store_true", help="input is whitespace-separated hexadecimal text")
    parser.add_argument("--le", action="store_true", help="explicitly interpret SV seqData as 64-byte 9-2LE")
    try:
        args = parser.parse_args(argv)
        with Path(args.input).open("rb") as handle:
            data = handle.read(MAX_FRAME * 4 + 1 if args.hex else MAX_FRAME + 1)
        if args.hex:
            if len(data) > MAX_FRAME * 4:
                raise Power61850Error("hex input exceeds cap")
            data = bytes.fromhex(data.decode("ascii"))
        if args.format == "ethernet":
            out = parse_frame(data, decode_9_2le=args.le)
        elif args.format == "goose":
            out = parse_goose(data)
        else:
            out = parse_sv(data, decode_9_2le=args.le)
        print(json.dumps(out, indent=2, allow_nan=False))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (Power61850Error, OSError, ValueError, TypeError) as exc:
        print(f"power_iec61850: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
