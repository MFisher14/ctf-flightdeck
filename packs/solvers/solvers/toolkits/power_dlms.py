"""Offline DLMS/COSEM logical-name APDU, wrapper and A-XDR decoder.

No transport client, decryption or device control. Supported APDUs: GET normal,
list and block; SET/ACTION normal; data notification. HDLC must first be
deframed by a transport-aware tool. Unknown/encrypted APDUs are rejected.
All public decoders raise PowerDLMSError for malformed or unsupported input.
Calendar values retain special/wildcard octets; no timezone is guessed.
"""
from __future__ import annotations

import argparse
import calendar
import json
import math
import re
import struct
import sys
from pathlib import Path

MAX_INPUT = 8 * 1024 * 1024
MAX_ITEMS = 65536
MAX_DEPTH = 32


class PowerDLMSError(ValueError):
    """Malformed, unsupported, or over-budget DLMS input."""


def _blob(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise PowerDLMSError("input must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_INPUT:
            raise PowerDLMSError("input exceeds 8 MiB")
        raw = bytes(data)
        if len(raw) > MAX_INPUT:
            raise PowerDLMSError("input exceeds 8 MiB")
        return raw
    except (ValueError, TypeError) as exc:
        raise PowerDLMSError("invalid bytes-like input") from exc


class _Reader:
    def __init__(self, data):
        self.data = _blob(data)
        self.pos = 0
        self.items = 0

    def take(self, size):
        if size < 0 or self.pos + size > len(self.data):
            raise PowerDLMSError("truncated DLMS field")
        out = self.data[self.pos:self.pos + size]
        self.pos += size
        return out

    def uint(self, size=1):
        return int.from_bytes(self.take(size), "big")

    def length(self):
        n = self.uint()
        if n < 128:
            return n
        width = n & 127
        if not 1 <= width <= 4:
            raise PowerDLMSError("invalid A-XDR length determinant")
        n = self.uint(width)
        if n > MAX_INPUT:
            raise PowerDLMSError("A-XDR length exceeds limit")
        return n

    def count(self):
        n = self.length()
        if n > MAX_ITEMS:
            raise PowerDLMSError("too many A-XDR elements")
        return n

    def end(self):
        if self.pos != len(self.data):
            raise PowerDLMSError("undeclared trailing bytes")

    def boolean(self):
        n = self.uint()
        if n not in (0, 1):
            raise PowerDLMSError("invalid A-XDR boolean")
        return bool(n)


_OBIS_NAMES = {
    (0, 0, 1, 0, 0, 255): "clock",
    (0, 0, 40, 0, 0, 255): "current association",
    (0, 0, 42, 0, 0, 255): "logical device name",
    (0, 0, 96, 1, 0, 255): "meter identifier",
    (1, 0, 1, 8, 0, 255): "active energy import, total",
    (1, 0, 2, 8, 0, 255): "active energy export, total",
    (1, 0, 1, 7, 0, 255): "instantaneous active power import",
    (1, 0, 2, 7, 0, 255): "instantaneous active power export",
    (1, 0, 32, 7, 0, 255): "L1 voltage",
    (1, 0, 52, 7, 0, 255): "L2 voltage",
    (1, 0, 72, 7, 0, 255): "L3 voltage",
    (1, 0, 31, 7, 0, 255): "L1 current",
    (1, 0, 51, 7, 0, 255): "L2 current",
    (1, 0, 71, 7, 0, 255): "L3 current",
}


def parse_obis(value):
    """Render exactly six octets or full A-B:C.D.E*F / A.B.C.D.E.F text.

    No implicit channel/history defaults and no label for unknown identifiers.
    """
    if isinstance(value, str):
        if len(value) > 32:
            raise PowerDLMSError("invalid OBIS text")
        match = re.fullmatch(r"(\d{1,3})-(\d{1,3}):(\d{1,3})\.(\d{1,3})\.(\d{1,3})\*(\d{1,3})", value)
        if not match:
            match = re.fullmatch(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", value)
        if not match:
            raise PowerDLMSError("OBIS requires all six groups")
        groups = tuple(int(x) for x in match.groups())
        if any(x > 255 for x in groups):
            raise PowerDLMSError("OBIS groups must fit octets")
    else:
        raw = _blob(value)
        if len(raw) != 6:
            raise PowerDLMSError("OBIS requires six octets")
        groups = tuple(raw)
    a, b, c, d, e, f = groups
    return {"groups": list(groups), "canonical": f"{a}-{b}:{c}.{d}.{e}*{f}",
            "dotted": ".".join(map(str, groups)), "name": _OBIS_NAMES.get(groups)}


def _calendar(raw, kind):
    # Wildcards and special month/day values are preserved, not normalized.
    out = {"hex": raw.hex()}
    off = 0
    if kind in ("date", "date-time"):
        year = int.from_bytes(raw[:2], "big")
        month, day, dow = raw[2:5]
        if not (year == 65535 or 1 <= year <= 9999):
            raise PowerDLMSError("invalid calendar year")
        if not (1 <= month <= 12 or month in (253, 254, 255)):
            raise PowerDLMSError("invalid calendar month")
        if not (1 <= day <= 31 or day in (253, 254, 255)):
            raise PowerDLMSError("invalid calendar day")
        if dow not in (1, 2, 3, 4, 5, 6, 7, 255):
            raise PowerDLMSError("invalid calendar weekday")
        if year != 65535 and month <= 12 and day <= 31:
            if day > calendar.monthrange(year, month)[1]:
                raise PowerDLMSError("invalid calendar date")
        out.update(year=year, month=month, day=day, day_of_week=dow)
        off = 5
    if kind in ("time", "date-time"):
        hour, minute, second, hundredths = raw[off:off + 4]
        for n, maximum in ((hour, 23), (minute, 59), (second, 59), (hundredths, 99)):
            if n > maximum and n != 255:
                raise PowerDLMSError("invalid calendar time")
        out.update(hour=hour, minute=minute, second=second, hundredths=hundredths)
    if kind == "date-time":
        deviation = int.from_bytes(raw[9:11], "big", signed=True)
        if deviation != -32768 and not -720 <= deviation <= 720:
            raise PowerDLMSError("invalid calendar deviation")
        out.update(deviation_minutes=None if deviation == -32768 else deviation,
                   clock_status=raw[11])
    return out


_INTS = {5: ("double-long", 4, True), 6: ("double-long-unsigned", 4, False),
         15: ("integer", 1, True), 16: ("long", 2, True),
         17: ("unsigned", 1, False), 18: ("long-unsigned", 2, False),
         20: ("long64", 8, True), 21: ("long64-unsigned", 8, False),
         22: ("enum", 1, False)}


def _value(r, depth=0):
    r.items += 1
    if depth > MAX_DEPTH or r.items > MAX_ITEMS:
        raise PowerDLMSError("A-XDR nesting or element budget exceeded")
    tag = r.uint()
    if tag == 0:
        name, value = "null-data", None
    elif tag in (1, 2):
        name = "array" if tag == 1 else "structure"
        value = [_value(r, depth + 1) for _ in range(r.count())]
    elif tag == 3:
        name, value = "boolean", r.boolean()
    elif tag == 4:
        count = r.length()
        raw = r.take((count + 7) // 8)
        if count % 8 and raw[-1] & ((1 << (8 - count % 8)) - 1):
            raise PowerDLMSError("nonzero bit-string padding")
        name, value = "bit-string", {"bit_count": count, "hex": raw.hex()}
    elif tag in _INTS:
        name, size, signed = _INTS[tag]
        value = int.from_bytes(r.take(size), "big", signed=signed)
    elif tag in (9, 10, 12):
        raw = r.take(r.length())
        name = {9: "octet-string", 10: "visible-string", 12: "utf8-string"}[tag]
        if tag == 9:
            value = {"hex": raw.hex()}
            if raw and all(32 <= c <= 126 for c in raw):
                value["ascii"] = raw.decode("ascii")
        else:
            try:
                value = raw.decode("ascii" if tag == 10 else "utf-8")
            except UnicodeDecodeError as exc:
                raise PowerDLMSError("invalid DLMS string encoding") from exc
    elif tag in (23, 24):
        name = "float32" if tag == 23 else "float64"
        value = struct.unpack(">f" if tag == 23 else ">d", r.take(4 if tag == 23 else 8))[0]
        # Valid IEEE special values remain JSON-compatible and explicitly named.
        if not math.isfinite(value):
            value = "NaN" if math.isnan(value) else ("Infinity" if value > 0 else "-Infinity")
    elif tag in (25, 26, 27):
        name, size = {25: ("date-time", 12), 26: ("date", 5), 27: ("time", 4)}[tag]
        value = _calendar(r.take(size), name)
    else:
        raise PowerDLMSError(f"unsupported A-XDR tag {tag}")
    return {"tag": tag, "type": name, "value": value}


def parse_axdr(data):
    """Parse exactly one A-XDR Data value, rejecting trailing bytes."""
    r = _Reader(data)
    out = _value(r)
    r.end()
    return out


_ACCESS_ERRORS = {0: "success", 1: "hardware-fault", 2: "temporary-failure",
                  3: "read-write-denied", 4: "object-undefined", 9: "object-class-inconsistent",
                  11: "object-unavailable", 12: "type-unmatched", 13: "scope-of-access-violated",
                  14: "data-block-unavailable", 15: "long-get-aborted", 16: "no-long-get-in-progress",
                  17: "long-set-aborted", 18: "no-long-set-in-progress", 19: "data-block-number-invalid",
                  250: "other-reason"}


def _error(r):
    code = r.uint()
    if code not in _ACCESS_ERRORS:
        raise PowerDLMSError("invalid data-access-result")
    return {"code": code, "name": _ACCESS_ERRORS[code]}


def _result(r):
    choice = r.uint()
    if choice == 0:
        return {"data": _value(r)}
    if choice == 1:
        return {"error": _error(r)}
    raise PowerDLMSError("invalid Get-Data-Result choice")


def _descriptor(r, method=False):
    out = {"class_id": r.uint(2), "obis": parse_obis(r.take(6))}
    # IEC 62056-53 section 8.3 defines both attribute-id and method-id as Integer8.
    index = int.from_bytes(r.take(1), "big", signed=True)
    out["method_id" if method else "attribute_id"] = index
    if not method:
        if r.boolean():
            out["selection"] = {"selector": r.uint(), "parameters": _value(r)}
    return out


def parse_apdu(data):
    """Parse one supported plaintext logical-name xDLMS APDU."""
    r = _Reader(data)
    command = r.uint()
    out = {"protocol": "dlms-cosem", "command_tag": command}
    if command == 0x0F:
        out.update(service="data-notification", long_invoke_id_and_priority=r.uint(4))
        n = r.length()
        if n not in (0, 12):
            raise PowerDLMSError("notification date-time must be absent or 12 octets")
        out["date_time"] = _calendar(r.take(n), "date-time") if n else None
        out["data"] = _value(r)
    elif command in (0xC0, 0xC1, 0xC3, 0xC4, 0xC5, 0xC7):
        subtype, invoke = r.uint(), r.uint()
        out.update(subtype=subtype, invoke_id_and_priority=invoke)
        if command == 0xC0:
            out["service"] = "get-request"
            if subtype == 1:
                out["descriptor"] = _descriptor(r)
            elif subtype == 2:
                out["block_number"] = r.uint(4)
            elif subtype == 3:
                out["descriptors"] = [_descriptor(r) for _ in range(r.count())]
            else:
                raise PowerDLMSError("unsupported GET request subtype")
        elif command == 0xC4:
            out["service"] = "get-response"
            if subtype == 1:
                out["result"] = _result(r)
            elif subtype == 2:
                out.update(last_block=r.boolean(), block_number=r.uint(4))
                choice = r.uint()
                if choice == 0:
                    out["raw_data_hex"] = r.take(r.length()).hex()
                elif choice == 1:
                    out["error"] = _error(r)
                else:
                    raise PowerDLMSError("invalid data-block result choice")
            elif subtype == 3:
                out["results"] = [_result(r) for _ in range(r.count())]
            else:
                raise PowerDLMSError("unsupported GET response subtype")
        else:
            if subtype != 1:
                raise PowerDLMSError("only normal SET/ACTION supported")
            out["service"] = {0xC1: "set-request", 0xC5: "set-response",
                              0xC3: "action-request", 0xC7: "action-response"}[command]
            if command == 0xC1:
                out["descriptor"] = _descriptor(r)
                out["data"] = _value(r)
            elif command == 0xC5:
                out["result"] = _error(r)
            elif command == 0xC3:
                out["descriptor"] = _descriptor(r, method=True)
                out["parameters"] = _value(r) if r.boolean() else None
            elif command == 0xC7:
                # Action result is a separate enumeration. Preserve the raw code.
                code = r.uint()
                if code not in (0, 1, 2, 3, 4, 9, 11, 12, 13, 14, 15, 16, 250):
                    raise PowerDLMSError("invalid action-result")
                out["action_result"] = code
                out["return_parameters"] = _result(r) if r.boolean() else None
    else:
        raise PowerDLMSError(f"unsupported or encrypted APDU 0x{command:02x}")
    r.end()
    return out


def parse_wrapper(data):
    """Parse exactly one IEC 62056 wrapper (version 1, two wPorts, length)."""
    r = _Reader(data)
    if r.uint(2) != 1:
        raise PowerDLMSError("unsupported DLMS wrapper version")
    source, destination, length = r.uint(2), r.uint(2), r.uint(2)
    out = {"version": 1, "source_wport": source, "destination_wport": destination,
           "length": length, "apdu": parse_apdu(r.take(length))}
    r.end()
    return out


def parse_wrapper_stream(data):
    """Parse consecutive complete wrapper frames; no resynchronization guessing."""
    r = _Reader(data)
    out = []
    while r.pos < len(r.data):
        if len(out) >= MAX_ITEMS:
            raise PowerDLMSError("too many wrapper frames")
        header = r.take(8)
        length = int.from_bytes(header[6:8], "big")
        out.append(parse_wrapper(header + r.take(length)))
    if not out:
        raise PowerDLMSError("empty wrapper stream")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="local binary file, or full OBIS text with --format obis")
    parser.add_argument("--format", choices=("auto", "apdu", "wrapper", "wrapper-stream", "axdr", "obis"), default="auto")
    parser.add_argument("--hex", action="store_true", help="read a file containing hexadecimal bytes")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.format == "obis":
            result = parse_obis(args.input)
        else:
            with Path(args.input).open("rb") as source:
                data = source.read(MAX_INPUT + 1)
            if len(data) > MAX_INPUT:
                raise PowerDLMSError("input file exceeds 8 MiB")
            if args.hex:
                try:
                    data = bytes.fromhex(data.decode("ascii"))
                except (ValueError, UnicodeDecodeError) as exc:
                    raise PowerDLMSError("invalid hexadecimal input") from exc
            kind = args.format
            if kind == "auto":
                kind = "wrapper-stream" if data[:2] == b"\x00\x01" else "apdu"
            result = {"apdu": parse_apdu, "wrapper": parse_wrapper,
                      "wrapper-stream": parse_wrapper_stream, "axdr": parse_axdr}[kind](data)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (PowerDLMSError, OSError, ValueError) as exc:
        print(f"power_dlms: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
