#!/usr/bin/env python3
"""Deep, bounded, offline dissectors for common industrial protocols.

The module accepts protocol payload bytes already obtained from an artifact.  It never opens a
socket, talks to a PLC, or executes embedded content.  Parsers return JSON-compatible dictionaries
and preserve undecoded bytes as hexadecimal so a caller can independently verify every conclusion.

Covered payloads:

* Modbus/TCP and Modbus/RTU, including diagnostics, file records, FIFO and device identity;
* DNP3 data-link, transport, application and common static/event/control objects;
* Siemens S7comm over TPKT/COTP, including variable access, setup, block and userdata/SZL traffic;
* BACnet/IP BVLC, NPDU, APDU and the generic application/context tag grammar;
* EtherNet/IP encapsulation, CPF and CIP paths/services, including Logix tag operations;
* IEC 60870-5-104 APCI/ASDU values, commands, causes and CP24/CP56 timestamps.

Malformed input raises ParseError.  Allocation and recursion are capped, and all public entry points
require bytes no larger than MAX_PAYLOAD.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_PAYLOAD = 32 << 20
MAX_ITEMS = 16_384
MAX_TAG_DEPTH = 64
FLAG_RE = flagfmt.BYTES
ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")


class ParseError(ValueError):
    """The supplied payload is not a complete, well-formed message."""


def _blob(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("payload must be bytes-like")
    out = bytes(data)
    if len(out) > MAX_PAYLOAD:
        raise ParseError("payload exceeds 32 MiB cap")
    return out


def _need(data: bytes, offset: int, length: int, what: str = "field") -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ParseError(f"truncated {what} at offset {offset}")


def _u16be(data: bytes, offset: int) -> int:
    _need(data, offset, 2, "uint16")
    return int.from_bytes(data[offset : offset + 2], "big")


def _u16le(data: bytes, offset: int) -> int:
    _need(data, offset, 2, "uint16")
    return int.from_bytes(data[offset : offset + 2], "little")


def _u24le(data: bytes, offset: int) -> int:
    _need(data, offset, 3, "uint24")
    return int.from_bytes(data[offset : offset + 3], "little")


def _u32le(data: bytes, offset: int) -> int:
    _need(data, offset, 4, "uint32")
    return int.from_bytes(data[offset : offset + 4], "little")


def _text_indicators(data: bytes) -> dict[str, list[str]]:
    flags, strings = [], []
    seen_flags, seen_strings = set(), set()
    for match in FLAG_RE.finditer(data):
        value = match.group().decode("latin-1")
        if value not in seen_flags:
            flags.append(value)
            seen_flags.add(value)
        if len(flags) >= 256:
            break
    for match in ASCII_RE.finditer(data):
        value = match.group().decode("latin-1")
        if value not in seen_strings:
            strings.append(value)
            seen_strings.add(value)
        if len(strings) >= 256:
            break
    return {"flags": flags, "strings": strings}


def _finding(kind: str, severity: str, detail: str, **fields: Any) -> dict[str, Any]:
    return {"kind": kind, "severity": severity, "detail": detail, **fields}


# --------------------------------------------------------------------------- Modbus

MODBUS_FUNCTIONS = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    7: "Read Exception Status",
    8: "Diagnostics",
    11: "Get Comm Event Counter",
    12: "Get Comm Event Log",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    20: "Read File Record",
    21: "Write File Record",
    22: "Mask Write Register",
    23: "Read/Write Multiple Registers",
    24: "Read FIFO Queue",
    43: "Encapsulated Interface Transport",
}

MODBUS_EXCEPTIONS = {
    1: "Illegal Function",
    2: "Illegal Data Address",
    3: "Illegal Data Value",
    4: "Server Device Failure",
    5: "Acknowledge",
    6: "Server Device Busy",
    8: "Memory Parity Error",
    10: "Gateway Path Unavailable",
    11: "Gateway Target Failed to Respond",
}

MODBUS_DIAGNOSTICS = {
    0: "Return Query Data",
    1: "Restart Communications Option",
    2: "Return Diagnostic Register",
    4: "Force Listen Only Mode",
    10: "Clear Counters and Diagnostic Register",
    11: "Return Bus Message Count",
    12: "Return Bus Communication Error Count",
    13: "Return Bus Exception Error Count",
    14: "Return Server Message Count",
    15: "Return Server No Response Count",
    16: "Return Server NAK Count",
    17: "Return Server Busy Count",
    18: "Return Bus Character Overrun Count",
    20: "Clear Overrun Counter and Flag",
}


def crc16_modbus(data: bytes) -> int:
    """Return the wire-order Modbus CRC value for data."""
    crc = 0xFFFF
    for byte in _blob(data):
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _modbus_registers(data: bytes) -> list[int]:
    if len(data) % 2:
        raise ParseError("odd-length Modbus register data")
    return [_u16be(data, i) for i in range(0, len(data), 2)]


def _modbus_file_subrequests(body: bytes, *, write: bool) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    offset = 0
    while offset < len(body):
        if len(out) >= MAX_ITEMS:
            raise ParseError("too many Modbus file subrequests")
        _need(body, offset, 7, "file record subrequest")
        reference_type = body[offset]
        file_number = _u16be(body, offset + 1)
        record_number = _u16be(body, offset + 3)
        record_length = _u16be(body, offset + 5)
        offset += 7
        row: dict[str, Any] = {
            "reference_type": reference_type,
            "file_number": file_number,
            "record_number": record_number,
            "record_length": record_length,
        }
        if write:
            byte_length = record_length * 2
            _need(body, offset, byte_length, "file record values")
            row["values"] = _modbus_registers(body[offset : offset + byte_length])
            offset += byte_length
        out.append(row)
    return out


def _modbus_exact(body: bytes, length: int, what: str) -> None:
    if len(body) != length:
        raise ParseError(f"{what} length mismatch: expected {length}, got {len(body)}")


def _parse_modbus_pdu(pdu: bytes, direction: str) -> dict[str, Any]:
    _need(pdu, 0, 1, "Modbus function")
    raw_function = pdu[0]
    is_exception = bool(raw_function & 0x80)
    function = raw_function & 0x7F
    body = pdu[1:]
    out: dict[str, Any] = {
        "function": function,
        "function_name": MODBUS_FUNCTIONS.get(function, f"Unknown 0x{function:02x}"),
        "direction": direction,
        "is_exception": is_exception,
        "raw_data": body.hex(),
        "findings": [],
    }
    if is_exception:
        _modbus_exact(body, 1, "Modbus exception")
        out["exception_code"] = body[0]
        out["exception_name"] = MODBUS_EXCEPTIONS.get(body[0], "Unknown exception")
        return out

    request = direction == "request"
    response = direction == "response"

    if function in (1, 2):
        if request or (direction == "auto" and len(body) == 4):
            _modbus_exact(body, 4, "read-bits request")
            out.update(address=_u16be(body, 0), quantity=_u16be(body, 2))
        else:
            _need(body, 0, 1, "read-bits response")
            count = body[0]
            _modbus_exact(body, 1 + count, "read-bits response")
            values = body[1 : 1 + count]
            out["packed_bits"] = values.hex()
            out["bits"] = [(byte >> bit) & 1 for byte in values for bit in range(8)]
    elif function in (3, 4):
        if request or (direction == "auto" and len(body) == 4):
            _modbus_exact(body, 4, "read-register request")
            out.update(address=_u16be(body, 0), quantity=_u16be(body, 2))
        else:
            _need(body, 0, 1, "read-register response")
            count = body[0]
            _modbus_exact(body, 1 + count, "read-register response")
            out["registers"] = _modbus_registers(body[1 : 1 + count])
    elif function == 5:
        _modbus_exact(body, 4, "write-coil")
        value = _u16be(body, 2)
        out.update(address=_u16be(body, 0), value=value, coil=value == 0xFF00)
        out["findings"].append(
            _finding("coil-write", "high", "Modbus force-single-coil operation", address=out["address"])
        )
    elif function == 6:
        _modbus_exact(body, 4, "write-register")
        out.update(address=_u16be(body, 0), value=_u16be(body, 2))
        out["findings"].append(
            _finding("register-write", "high", "Modbus preset-single-register operation", address=out["address"])
        )
    elif function == 7:
        is_request = request or (direction == "auto" and not body)
        _modbus_exact(body, 0 if is_request else 1, "exception-status message")
        if not is_request:
            out["status"] = body[0]
    elif function == 8:
        _modbus_exact(body, 4, "diagnostic")
        subfunction = _u16be(body, 0)
        out.update(
            subfunction=subfunction,
            subfunction_name=MODBUS_DIAGNOSTICS.get(subfunction, f"Unknown {subfunction}"),
            diagnostic_data=body[2:].hex(),
        )
        if subfunction in (1, 4, 10, 20):
            out["findings"].append(
                _finding("diagnostic-control", "high", out["subfunction_name"], subfunction=subfunction)
            )
    elif function == 11:
        is_request = request or (direction == "auto" and not body)
        _modbus_exact(body, 0 if is_request else 4, "event-counter message")
        if not is_request:
            out.update(status=_u16be(body, 0), event_count=_u16be(body, 2))
    elif function in (12, 17):
        is_request = request or (direction == "auto" and not body)
        if is_request:
            _modbus_exact(body, 0, "variable-status request")
        else:
            _need(body, 0, 1, "variable-status byte count")
            _modbus_exact(body, 1 + body[0], "variable-status response")
            out["byte_count"] = body[0]
            out["payload"] = body[1 : 1 + body[0]].hex()
    elif function == 15:
        _need(body, 0, 4, "write-multiple-coils")
        out.update(address=_u16be(body, 0), quantity=_u16be(body, 2))
        is_request = request or (direction == "auto" and len(body) != 4)
        if is_request:
            _need(body, 4, 1, "coil-write byte count")
            count = body[4]
            _modbus_exact(body, 5 + count, "write-multiple-coils request")
            if count != (out["quantity"] + 7) // 8:
                raise ParseError("write-multiple-coils quantity/byte-count mismatch")
            out["packed_bits"] = body[5 : 5 + count].hex()
        else:
            _modbus_exact(body, 4, "write-multiple-coils response")
        out["findings"].append(
            _finding("coil-write", "high", "Modbus force-multiple-coils operation", address=out["address"])
        )
    elif function == 16:
        _need(body, 0, 4, "write-multiple-registers")
        out.update(address=_u16be(body, 0), quantity=_u16be(body, 2))
        is_request = request or (direction == "auto" and len(body) != 4)
        if is_request:
            _need(body, 4, 1, "register-write byte count")
            count = body[4]
            _modbus_exact(body, 5 + count, "write-multiple-registers request")
            if count != out["quantity"] * 2:
                raise ParseError("write-multiple-registers quantity/byte-count mismatch")
            out["registers"] = _modbus_registers(body[5 : 5 + count])
        else:
            _modbus_exact(body, 4, "write-multiple-registers response")
        out["findings"].append(
            _finding("register-write", "high", "Modbus preset-multiple-registers operation", address=out["address"])
        )
    elif function == 20:
        _need(body, 0, 1, "read-file byte count")
        count = body[0]
        _modbus_exact(body, 1 + count, "read-file message")
        if request:
            out["subrequests"] = _modbus_file_subrequests(body[1 : 1 + count], write=False)
        else:
            rows, offset = [], 1
            end = 1 + count
            while offset < end:
                _need(body, offset, 2, "file record response")
                sublen = body[offset]
                _need(body, offset + 1, sublen, "file record response data")
                if sublen < 1 or (sublen - 1) & 1:
                    raise ParseError("invalid read-file subresponse length")
                rows.append(
                    {
                        "reference_type": body[offset + 1],
                        "registers": _modbus_registers(body[offset + 2 : offset + 1 + sublen]),
                    }
                )
                offset += 1 + sublen
            out["subresponses"] = rows
    elif function == 21:
        _need(body, 0, 1, "write-file byte count")
        count = body[0]
        _modbus_exact(body, 1 + count, "write-file message")
        out["subrequests"] = _modbus_file_subrequests(body[1 : 1 + count], write=True)
        out["findings"].append(_finding("file-write", "high", "Modbus write-file-record operation"))
    elif function == 22:
        _modbus_exact(body, 6, "mask-write")
        out.update(address=_u16be(body, 0), and_mask=_u16be(body, 2), or_mask=_u16be(body, 4))
        out["findings"].append(_finding("register-write", "high", "Modbus mask-write-register operation"))
    elif function == 23:
        _need(body, 0, 1 if response else 9, "read/write registers")
        if response:
            count = body[0]
            _modbus_exact(body, 1 + count, "read/write response")
            out["read_registers"] = _modbus_registers(body[1 : 1 + count])
        else:
            out.update(
                read_address=_u16be(body, 0),
                read_quantity=_u16be(body, 2),
                write_address=_u16be(body, 4),
                write_quantity=_u16be(body, 6),
            )
            count = body[8]
            _modbus_exact(body, 9 + count, "read/write request")
            if count != out["write_quantity"] * 2:
                raise ParseError("read/write-register quantity/byte-count mismatch")
            out["write_registers"] = _modbus_registers(body[9 : 9 + count])
            out["findings"].append(_finding("register-write", "high", "Modbus read/write-multiple-registers"))
    elif function == 24:
        if request:
            _modbus_exact(body, 2, "FIFO request")
            out["fifo_pointer_address"] = _u16be(body, 0)
        else:
            _need(body, 0, 4, "FIFO response")
            byte_count = _u16be(body, 0)
            fifo_count = _u16be(body, 2)
            _modbus_exact(body, 4 + fifo_count * 2, "FIFO response")
            if byte_count != 2 + fifo_count * 2:
                raise ParseError("FIFO byte-count/value-count mismatch")
            out.update(byte_count=byte_count, fifo_count=fifo_count, registers=_modbus_registers(body[4 : 4 + 2 * fifo_count]))
    elif function == 43:
        _need(body, 0, 1, "MEI type")
        out["mei_type"] = body[0]
        if body[0] == 14:
            if request:
                _modbus_exact(body, 3, "device-id request")
                out.update(read_device_id_code=body[1], object_id=body[2])
            else:
                _need(body, 1, 6, "device-id response")
                out.update(
                    read_device_id_code=body[1],
                    conformity_level=body[2],
                    more_follows=body[3],
                    next_object_id=body[4],
                    object_count=body[5],
                )
                objects, offset = [], 6
                for _ in range(body[5]):
                    _need(body, offset, 2, "device-id object")
                    object_id, length = body[offset], body[offset + 1]
                    _need(body, offset + 2, length, "device-id value")
                    value = body[offset + 2 : offset + 2 + length]
                    objects.append({"id": object_id, "value": value.decode("utf-8", "replace"), "raw": value.hex()})
                    offset += 2 + length
                if offset != len(body):
                    raise ParseError("device-id response has undeclared trailing bytes")
                out["objects"] = objects
    out.update(_text_indicators(body))
    return out


def parse_modbus(data: bytes, *, transport: str = "auto", direction: str = "auto") -> dict[str, Any]:
    """Parse one Modbus/TCP or Modbus/RTU ADU.

    direction is request, response or auto.  Auto is deterministic but some four-byte read responses
    are inherently ambiguous, so capture callers should infer direction from the server port.
    """
    data = _blob(data)
    if transport not in {"auto", "tcp", "rtu", "pdu"}:
        raise ValueError("transport must be auto, tcp, rtu or pdu")
    if direction not in {"auto", "request", "response"}:
        raise ValueError("direction must be auto, request or response")
    if transport == "auto":
        transport = "tcp" if len(data) >= 8 and data[2:4] == b"\x00\x00" and _u16be(data, 4) + 6 == len(data) else "rtu"
    out: dict[str, Any] = {"protocol": "modbus", "transport": transport}
    if transport == "tcp":
        _need(data, 0, 8, "MBAP ADU")
        length = _u16be(data, 4)
        if data[2:4] != b"\x00\x00":
            raise ParseError("nonzero Modbus protocol identifier")
        if length < 2 or length + 6 != len(data):
            raise ParseError("Modbus/TCP MBAP length mismatch")
        out.update(transaction_id=_u16be(data, 0), protocol_id=0, length=length, unit_id=data[6])
        pdu = data[7:]
    elif transport == "rtu":
        _need(data, 0, 4, "Modbus/RTU ADU")
        expected = int.from_bytes(data[-2:], "little")
        actual = crc16_modbus(data[:-2])
        out.update(unit_id=data[0], crc=expected, crc_valid=expected == actual)
        if expected != actual:
            raise ParseError("Modbus/RTU CRC mismatch")
        pdu = data[1:-2]
    else:
        pdu = data
    out["pdu"] = _parse_modbus_pdu(pdu, direction)
    out.update(_text_indicators(data))
    return out


# --------------------------------------------------------------------------- DNP3

DNP3_LINK_FUNCTIONS = {
    0: "RESET_LINK_STATES/ACK",
    1: "RESET_USER_PROCESS/NACK",
    2: "TEST_LINK_STATES",
    3: "CONFIRMED_USER_DATA",
    4: "UNCONFIRMED_USER_DATA",
    9: "REQUEST_LINK_STATUS",
    11: "LINK_STATUS",
    14: "REQUEST_NOT_SUPPORTED",
}

DNP3_APP_FUNCTIONS = {
    0x00: "CONFIRM",
    0x01: "READ",
    0x02: "WRITE",
    0x03: "SELECT",
    0x04: "OPERATE",
    0x05: "DIRECT_OPERATE",
    0x06: "DIRECT_OPERATE_NR",
    0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART",
    0x12: "STOP_APPLICATION",
    0x13: "SAVE_CONFIGURATION",
    0x17: "ENABLE_UNSOLICITED",
    0x18: "DISABLE_UNSOLICITED",
    0x19: "ASSIGN_CLASS",
    0x1B: "DELAY_MEASURE",
    0x1C: "RECORD_CURRENT_TIME",
    0x81: "RESPONSE",
    0x82: "UNSOLICITED_RESPONSE",
    0x83: "AUTHENTICATE_RESPONSE",
}

DNP3_GROUPS = {
    1: "Binary Input",
    2: "Binary Input Event",
    10: "Binary Output Status",
    11: "Binary Output Event",
    12: "Binary Output Command",
    13: "Binary Output Command Event",
    20: "Binary Counter",
    21: "Frozen Counter",
    22: "Counter Event",
    23: "Frozen Counter Event",
    30: "Analog Input",
    31: "Frozen Analog Input",
    32: "Analog Input Event",
    33: "Frozen Analog Event",
    34: "Analog Deadband",
    40: "Analog Output Status",
    41: "Analog Output Command",
    42: "Analog Output Event",
    43: "Analog Output Command Event",
    50: "Time and Date",
    51: "Common Time",
    52: "Time Delay",
    60: "Class Data",
    70: "File Control",
    80: "Internal Indications",
    110: "Octet String",
    111: "Octet String Event",
    120: "Secure Authentication",
}


def crc16_dnp3(data: bytes) -> int:
    """DNP3 CRC with reflected polynomial and final complement."""
    crc = 0
    for byte in _blob(data):
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


def _dnp3_time48(raw: bytes) -> dict[str, Any]:
    _need(raw, 0, 6, "DNP3 time")
    milliseconds = int.from_bytes(raw[:6], "little")
    out: dict[str, Any] = {"unix_ms": milliseconds}
    try:
        out["iso"] = datetime.fromtimestamp(milliseconds / 1000, timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        pass
    return out


def _dnp3_object_size(group: int, variation: int) -> int | None:
    table = {
        (1, 1): 0,
        (1, 2): 1,
        (2, 1): 1,
        (2, 2): 7,
        (2, 3): 3,
        (10, 2): 1,
        (11, 1): 1,
        (11, 2): 7,
        (12, 1): 11,
        (20, 1): 5,
        (20, 2): 3,
        (20, 5): 4,
        (20, 6): 2,
        (21, 1): 5,
        (21, 2): 3,
        (21, 5): 4,
        (21, 6): 2,
        (22, 1): 5,
        (22, 2): 3,
        (22, 5): 11,
        (22, 6): 9,
        (23, 1): 5,
        (23, 2): 3,
        (23, 5): 11,
        (23, 6): 9,
        (30, 1): 5,
        (30, 2): 3,
        (30, 3): 4,
        (30, 4): 2,
        (30, 5): 5,
        (30, 6): 9,
        (30, 7): 4,
        (30, 8): 8,
        (31, 1): 5,
        (31, 2): 3,
        (31, 3): 4,
        (31, 4): 2,
        (31, 5): 5,
        (31, 6): 9,
        (31, 7): 4,
        (31, 8): 8,
        (32, 1): 5,
        (32, 2): 3,
        (32, 3): 11,
        (32, 4): 9,
        (32, 5): 5,
        (32, 6): 9,
        (32, 7): 11,
        (32, 8): 15,
        (33, 1): 5,
        (33, 2): 3,
        (33, 3): 11,
        (33, 4): 9,
        (33, 5): 5,
        (33, 6): 9,
        (33, 7): 11,
        (33, 8): 15,
        (34, 1): 2,
        (34, 2): 4,
        (34, 3): 4,
        (40, 1): 5,
        (40, 2): 3,
        (40, 3): 5,
        (40, 4): 9,
        (41, 1): 5,
        (41, 2): 3,
        (41, 3): 5,
        (41, 4): 9,
        (42, 1): 5,
        (42, 2): 3,
        (42, 3): 11,
        (42, 4): 9,
        (42, 5): 5,
        (42, 6): 9,
        (42, 7): 11,
        (42, 8): 15,
        (43, 1): 5,
        (43, 2): 3,
        (43, 3): 11,
        (43, 4): 9,
        (43, 5): 5,
        (43, 6): 9,
        (43, 7): 11,
        (43, 8): 15,
        (50, 1): 6,
        (50, 3): 10,
        (51, 1): 6,
        (51, 2): 6,
        (52, 1): 2,
        (52, 2): 2,
        (80, 1): 1,
    }
    if group in (110, 111):
        return variation
    return table.get((group, variation))


def _dnp3_decode_value(group: int, variation: int, raw: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"raw": raw.hex()}
    if not raw:
        return out
    flags_groups = {1, 2, 10, 11, 22, 23, 32, 33, 40, 42}
    if group in (20, 21) and variation in (1, 2):
        flags_groups.add(group)
    if group in (30, 31) and variation in (1, 2, 5, 6):
        flags_groups.add(group)
    offset = 0
    if group in flags_groups and variation not in ({1} if group == 1 else set()):
        out["flags"] = raw[0]
        if group in (1, 2, 10, 11):
            out["state"] = bool(raw[0] & 0x80)
        offset = 1
    if group == 43:
        # Analog command events carry status before the value, unlike group 41.
        out["status"] = raw[0]
        offset = 1
    if group == 12 and variation == 1 and len(raw) >= 11:
        control = raw[0]
        out.update(
            control_code=control & 0x0F,
            trip_close_code=(control >> 6) & 0x03,
            clear=bool(control & 0x20),
            queue=bool(control & 0x10),
            count=raw[1],
            on_time_ms=_u32le(raw, 2),
            off_time_ms=_u32le(raw, 6),
            status=raw[10],
        )
    elif group in (20, 21, 22, 23):
        value_raw = raw[offset:]
        if group in (22, 23) and variation in (5, 6):
            out["time"] = _dnp3_time48(value_raw[-6:])
            value_raw = value_raw[:-6]
        width = len(value_raw)
        if width in (2, 4):
            out["value"] = int.from_bytes(value_raw, "little")
    elif group in (30, 31, 32, 33, 40, 41, 42, 43):
        value_raw = raw[offset:]
        timed = group in (32, 33, 42, 43) and variation in (3, 4, 7, 8)
        if timed:
            out["time"] = _dnp3_time48(value_raw[-6:])
            value_raw = value_raw[:-6]
        command = group == 41
        if command:
            if not value_raw:
                return out
            out["status"] = value_raw[-1]
            value_part = value_raw[:-1]
            numeric_variation = variation
        else:
            value_part = value_raw
            numeric_variation = variation
        if len(value_part) == 2:
            out["value"] = int.from_bytes(value_part, "little", signed=True)
        elif len(value_part) == 4:
            # group 40 var 3 (Analog Output Status, single float) carries its float at var 3, not 5/7
            is_float = (numeric_variation in (5, 7) or (command and numeric_variation == 3)
                        or (group == 40 and variation == 3))
            if is_float:
                out["value"] = struct.unpack("<f", value_part)[0]
            else:
                out["value"] = int.from_bytes(value_part, "little", signed=True)
        elif len(value_part) == 8:
            out["value"] = struct.unpack("<d", value_part)[0]
    elif group in (50, 51) and len(raw) >= 6:
        out["time"] = _dnp3_time48(raw[:6])
    elif group in (110, 111):
        out["octets"] = raw.hex()
        out.update(_text_indicators(raw))
    return out


def _dnp3_range(body: bytes, offset: int, qualifier: int) -> tuple[list[int], int, int]:
    prefix_code, range_code = qualifier >> 4, qualifier & 0x0F
    if range_code in (0, 1, 2):
        width = (1, 2, 4)[range_code]
        _need(body, offset, width * 2, "DNP3 start/stop range")
        start = int.from_bytes(body[offset : offset + width], "little")
        stop = int.from_bytes(body[offset + width : offset + 2 * width], "little")
        if stop < start or stop - start + 1 > MAX_ITEMS:
            raise ParseError("invalid or excessive DNP3 point range")
        return list(range(start, stop + 1)), offset + width * 2, prefix_code
    if range_code in (3, 4, 5):
        width = (1, 2, 4)[range_code - 3]
        _need(body, offset, width * 2, "DNP3 start/count range")
        start = int.from_bytes(body[offset : offset + width], "little")
        count = int.from_bytes(body[offset + width : offset + 2 * width], "little")
        if count > MAX_ITEMS:
            raise ParseError("excessive DNP3 point count")
        return list(range(start, start + count)), offset + width * 2, prefix_code
    if range_code in (7, 8, 9):
        width = (1, 2, 4)[range_code - 7]
        _need(body, offset, width, "DNP3 object count")
        count = int.from_bytes(body[offset : offset + width], "little")
        if count > MAX_ITEMS:
            raise ParseError("excessive DNP3 object count")
        return list(range(count)), offset + width, prefix_code
    if range_code == 6:
        return [], offset, prefix_code
    raise ParseError(f"unsupported DNP3 qualifier range 0x{range_code:x}")


def _parse_dnp3_objects(body: bytes, *, header_only: bool = False) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    offset = 0
    while offset < len(body):
        if len(objects) >= MAX_ITEMS:
            raise ParseError("too many DNP3 object headers")
        _need(body, offset, 3, "DNP3 object header")
        group, variation, qualifier = body[offset : offset + 3]
        offset += 3
        indices, offset, prefix_code = _dnp3_range(body, offset, qualifier)
        size = _dnp3_object_size(group, variation)
        row: dict[str, Any] = {
            "group": group,
            "group_name": DNP3_GROUPS.get(group, f"Group {group}"),
            "variation": variation,
            "qualifier": qualifier,
            "points": [],
        }
        if header_only:
            row["requested_indices"] = indices
            row["prefix_code"] = prefix_code
            objects.append(row)
            continue
        if not indices and (qualifier & 0x0F) == 6:
            objects.append(row)
            continue
        if (group, variation) in ((1, 1), (10, 1)):
            if prefix_code:
                raise ParseError("packed DNP3 binary objects cannot carry an index prefix")
            packed_length = (len(indices) + 7) // 8
            _need(body, offset, packed_length, "packed DNP3 binary values")
            packed = body[offset : offset + packed_length]
            offset += packed_length
            row["packed"] = packed.hex()
            row["points"] = [
                {"index": index, "state": bool(packed[position // 8] & (1 << (position & 7)))}
                for position, index in enumerate(indices)
            ]
            objects.append(row)
            continue
        if size is None:
            row["undecoded"] = body[offset:].hex()
            objects.append(row)
            break
        for default_index in indices:
            index = default_index
            if prefix_code in (1, 2, 3):
                width = (1, 2, 4)[prefix_code - 1]
                _need(body, offset, width, "DNP3 index prefix")
                index = int.from_bytes(body[offset : offset + width], "little")
                offset += width
            elif prefix_code in (4, 5, 6):
                width = (1, 2, 4)[prefix_code - 4]
                _need(body, offset, width, "DNP3 size prefix")
                size = int.from_bytes(body[offset : offset + width], "little")
                offset += width
            _need(body, offset, size, "DNP3 object value")
            raw = body[offset : offset + size]
            offset += size
            row["points"].append({"index": index, **_dnp3_decode_value(group, variation, raw)})
        objects.append(row)
    return objects


def parse_dnp3_application(fragment: bytes) -> dict[str, Any]:
    """Decode one fully reassembled DNP3 application fragment."""
    fragment = _blob(fragment)
    _need(fragment, 0, 2, "DNP3 application header")
    app_control, app_function = fragment[0], fragment[1]
    app: dict[str, Any] = {
        "control": app_control,
        "final": bool(app_control & 0x80),
        "first": bool(app_control & 0x40),
        "confirm": bool(app_control & 0x20),
        "unsolicited": bool(app_control & 0x10),
        "sequence": app_control & 0x0F,
        "function": app_function,
        "function_name": DNP3_APP_FUNCTIONS.get(app_function, f"Unknown 0x{app_function:02x}"),
    }
    body_offset = 2
    if app_function & 0x80:
        _need(fragment, 2, 2, "DNP3 internal indications")
        app["iin"] = _u16le(fragment, 2)
        body_offset = 4
    object_body = fragment[body_offset:]
    if object_body:
        app["objects"] = _parse_dnp3_objects(object_body, header_only=app_function == 0x01)
    app.update(_text_indicators(object_body))
    findings = []
    if app_function in (2, 3, 4, 5, 6, 0x0D, 0x0E, 0x12, 0x13, 0x19):
        severity = "critical" if app_function in (4, 5, 6, 0x0D, 0x0E, 0x12) else "high"
        findings.append(_finding("dnp3-control", severity, app["function_name"], function=app_function))
    if any(obj["group"] == 120 for obj in app.get("objects", [])):
        findings.append(_finding("dnp3-auth", "info", "DNP3 Secure Authentication object present"))
    return {"application": app, "findings": findings}


def parse_dnp3(data: bytes) -> dict[str, Any]:
    """Parse one complete DNP3 data-link frame and its transport/application fragment."""
    data = _blob(data)
    _need(data, 0, 10, "DNP3 link header")
    if data[:2] != b"\x05\x64":
        raise ParseError("DNP3 start bytes are absent")
    length = data[2]
    if length < 5:
        raise ParseError("invalid DNP3 link length")
    user_length = length - 5
    encoded_length = 10 + user_length + 2 * math.ceil(user_length / 16)
    if encoded_length != len(data):
        raise ParseError("DNP3 encoded length mismatch")
    header_crc = _u16le(data, 8)
    if crc16_dnp3(data[:8]) != header_crc:
        raise ParseError("DNP3 link header CRC mismatch")
    offset, remaining, user = 10, user_length, bytearray()
    block_crcs: list[bool] = []
    while remaining:
        size = min(16, remaining)
        _need(data, offset, size + 2, "DNP3 data block")
        block = data[offset : offset + size]
        valid = crc16_dnp3(block) == _u16le(data, offset + size)
        block_crcs.append(valid)
        if not valid:
            raise ParseError("DNP3 data block CRC mismatch")
        user.extend(block)
        offset += size + 2
        remaining -= size
    control = data[3]
    out: dict[str, Any] = {
        "protocol": "dnp3",
        "length": length,
        "control": control,
        "direction": "from-master" if control & 0x80 else "from-outstation",
        "primary": bool(control & 0x40),
        "frame_count_bit": bool(control & 0x20),
        "frame_count_valid": bool(control & 0x10),
        "link_function": control & 0x0F,
        "link_function_name": DNP3_LINK_FUNCTIONS.get(control & 0x0F, "Unknown"),
        "destination": _u16le(data, 4),
        "source": _u16le(data, 6),
        "header_crc_valid": True,
        "block_crcs_valid": all(block_crcs),
        "findings": [],
    }
    if not user:
        return out
    transport = user[0]
    out["transport"] = {
        "final": bool(transport & 0x80),
        "first": bool(transport & 0x40),
        "sequence": transport & 0x3F,
    }
    fragment = bytes(user[1:])
    out["transport"]["fragment"] = fragment.hex()
    if not fragment:
        return out
    if out["transport"]["first"] and out["transport"]["final"]:
        application = parse_dnp3_application(fragment)
        out["application"] = application["application"]
        out["findings"].extend(application["findings"])
    else:
        out["fragmented_application"] = True
    out.update(_text_indicators(data))
    return out


# --------------------------------------------------------------------------- S7comm

S7_ROSCTR = {1: "Job", 2: "Ack", 3: "Ack_Data", 7: "Userdata"}
S7_FUNCTIONS = {
    0x04: "Read Var",
    0x05: "Write Var",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload",
    0x1F: "End Upload",
    0x28: "PLC Control",
    0x29: "PLC Stop",
    0xF0: "Setup Communication",
}
S7_AREAS = {
    0x1C: "Counters",
    0x1D: "Timers",
    0x80: "Peripheral",
    0x81: "Inputs",
    0x82: "Outputs",
    0x83: "Markers",
    0x84: "Data Blocks",
    0x85: "Instance Data Blocks",
    0x86: "Local Data",
}
S7_USERDATA_GROUPS = {1: "Programmer", 2: "Cyclic", 3: "Block", 4: "CPU", 5: "Security", 6: "PBC", 7: "Time"}
S7_CPU_SUBFUNCTIONS = {
    1: "Read SZL",
    2: "Message service",
    3: "Diagnostic message",
    5: "Alarm indication",
    11: "Alarm query",
}


def _parse_s7_varspecs(parameter: bytes, count: int) -> list[dict[str, Any]]:
    rows, offset = [], 2
    for _ in range(count):
        _need(parameter, offset, 2, "S7 variable specification")
        if parameter[offset] != 0x12:
            raise ParseError("unsupported S7 variable specification type")
        size = parameter[offset + 1]
        _need(parameter, offset + 2, size, "S7 variable specification body")
        body = parameter[offset + 2 : offset + 2 + size]
        row: dict[str, Any] = {"raw": body.hex()}
        if len(body) >= 10 and body[0] == 0x10:
            bit_address = int.from_bytes(body[7:10], "big")
            row.update(
                syntax="S7ANY",
                transport_size=body[1],
                element_count=_u16be(body, 2),
                db_number=_u16be(body, 4),
                area=body[6],
                area_name=S7_AREAS.get(body[6], f"0x{body[6]:02x}"),
                bit_address=bit_address,
                byte_address=bit_address >> 3,
                bit_offset=bit_address & 7,
            )
        rows.append(row)
        offset += 2 + size
    if offset != len(parameter):
        raise ParseError("S7 variable specifications have undeclared trailing bytes")
    return rows


def _parse_s7_data_items(data: bytes, count: int) -> list[dict[str, Any]]:
    rows, offset = [], 0
    for index in range(count):
        _need(data, offset, 4, "S7 data item")
        return_code, transport_size = data[offset], data[offset + 1]
        raw_length = _u16be(data, offset + 2)
        offset += 4
        length = (raw_length + 7) // 8 if transport_size in (3, 4, 5) else raw_length
        _need(data, offset, length, "S7 data value")
        raw = data[offset : offset + length]
        rows.append(
            {
                "return_code": return_code,
                "transport_size": transport_size,
                "length": raw_length,
                "value": raw.hex(),
                **_text_indicators(raw),
            }
        )
        offset += length
        if index + 1 < count and length & 1:
            _need(data, offset, 1, "S7 fill byte")
            offset += 1
    if offset != len(data):
        raise ParseError("S7 data items have undeclared trailing bytes")
    return rows


def _parse_s7_userdata(parameter: bytes, data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"parameter": parameter.hex(), "data": data.hex()}
    if parameter[:3] == b"\x00\x01\x12":
        _need(parameter, 0, 8, "S7 userdata parameter")
        parameter_length = parameter[3]
        if parameter_length + 4 != len(parameter):
            raise ParseError("S7 userdata parameter length mismatch")
        type_group = parameter[5]
        out.update(
            parameter_length=parameter_length,
            userdata_type=(type_group >> 4) & 0x0F,
            function_group=type_group & 0x0F,
            function_group_name=S7_USERDATA_GROUPS.get(type_group & 0x0F, "Unknown"),
            subfunction=parameter[6],
            sequence=parameter[7],
        )
        if (type_group & 0x0F) == 4:
            out["subfunction_name"] = S7_CPU_SUBFUNCTIONS.get(parameter[6], "Unknown CPU service")
    payload = data
    if data:
        _need(data, 0, 4, "S7 userdata data header")
        out.update(return_code=data[0], transport_size=data[1], data_length=_u16be(data, 2))
        length = (_u16be(data, 2) + 7) // 8 if data[1] in (3, 4, 5) else _u16be(data, 2)
        _need(data, 4, length, "S7 userdata payload")
        if 4 + length != len(data):
            raise ParseError("S7 userdata data length mismatch")
        payload = data[4 : 4 + length]
    if out.get("function_group") == 4 and out.get("subfunction") == 1 and len(payload) >= 4:
        out["szl_id"] = _u16be(payload, 0)
        out["szl_index"] = _u16be(payload, 2)
        if len(payload) >= 8:
            element_length, element_count = _u16be(payload, 4), _u16be(payload, 6)
            out.update(szl_element_length=element_length, szl_element_count=element_count)
            values = []
            cursor = 8
            for _ in range(min(element_count, MAX_ITEMS)):
                _need(payload, cursor, element_length, "SZL element")
                value = payload[cursor : cursor + element_length]
                values.append({"raw": value.hex(), **_text_indicators(value)})
                cursor += element_length
            if element_count > MAX_ITEMS:
                raise ParseError("S7 SZL element count exceeds cap")
            if cursor != len(payload):
                raise ParseError("S7 SZL element geometry mismatch")
            out["szl_elements"] = values
    out.update(_text_indicators(payload))
    return out


def parse_s7comm(data: bytes) -> dict[str, Any]:
    """Parse one TPKT/COTP/S7comm or S7comm-plus message."""
    data = _blob(data)
    _need(data, 0, 7, "TPKT/COTP")
    if data[0:2] != b"\x03\x00":
        raise ParseError("invalid TPKT header")
    total_length = _u16be(data, 2)
    if total_length != len(data):
        raise ParseError("TPKT length mismatch")
    cotp_length = data[4]
    _need(data, 5, cotp_length, "COTP header")
    cotp = data[5 : 5 + cotp_length]
    if not cotp:
        raise ParseError("empty COTP header")
    offset = 5 + cotp_length
    payload = data[offset:]
    out: dict[str, Any] = {
        "protocol": "s7comm",
        "tpkt_length": total_length,
        "cotp_pdu_type": cotp[0] & 0xF0,
        "cotp": cotp.hex(),
        "findings": [],
    }
    if out["cotp_pdu_type"] == 0xF0:
        _need(cotp, 1, 1, "COTP data TPDU flags")
        out["cotp_eot"] = bool(cotp[1] & 0x80)
        if not out["cotp_eot"]:
            out["segmented"] = True
            out["s7_fragment"] = payload.hex()
            out.update(_text_indicators(payload))
            return out
    if not payload:
        return out
    if payload[0] == 0x72:
        out["variant"] = "s7comm-plus"
        out["s7comm_plus"] = {
            "protocol_id": 0x72,
            "version": payload[1] if len(payload) > 1 else None,
            "opcode": payload[2] if len(payload) > 2 else None,
            "raw": payload[1:].hex(),
            **_text_indicators(payload),
        }
        return out
    _need(payload, 0, 10, "S7 header")
    if payload[0] != 0x32:
        raise ParseError("S7 protocol identifier is absent")
    rosctr = payload[1]
    header_length = 12 if rosctr in (2, 3) else 10
    _need(payload, 0, header_length, "S7 header")
    parameter_length, data_length = _u16be(payload, 6), _u16be(payload, 8)
    if header_length + parameter_length + data_length != len(payload):
        raise ParseError("S7 parameter/data lengths do not exactly match TPKT payload")
    parameter = payload[header_length : header_length + parameter_length]
    data_part = payload[header_length + parameter_length : header_length + parameter_length + data_length]
    s7: dict[str, Any] = {
        "protocol_id": 0x32,
        "rosctr": rosctr,
        "rosctr_name": S7_ROSCTR.get(rosctr, "Unknown"),
        "pdu_reference": _u16be(payload, 4),
        "parameter_length": parameter_length,
        "data_length": data_length,
    }
    if rosctr in (2, 3):
        s7.update(error_class=payload[10], error_code=payload[11])
    if parameter:
        function = parameter[0]
        s7.update(function=function, function_name=S7_FUNCTIONS.get(function, f"Unknown 0x{function:02x}"))
        if function == 0xF0:
            if len(parameter) != 8:
                raise ParseError("S7 setup-communication parameter length mismatch")
            s7["setup"] = {
                "reserved": parameter[1],
                "max_amq_calling": _u16be(parameter, 2),
                "max_amq_called": _u16be(parameter, 4),
                "pdu_length": _u16be(parameter, 6),
            }
        elif function in (4, 5):
            _need(parameter, 1, 1, "S7 item count")
            count = parameter[1]
            s7["item_count"] = count
            if rosctr == 1:
                s7["variables"] = _parse_s7_varspecs(parameter, count)
            elif len(parameter) != 2:
                raise ParseError("S7 read/write response parameter length mismatch")
            if function == 5 and rosctr == 3:
                if len(data_part) != count:
                    raise ParseError("S7 Write Var response return-code count mismatch")
                s7["data_items"] = [{"return_code": code} for code in data_part]
            elif data_part:
                s7["data_items"] = _parse_s7_data_items(data_part, count)
            if function == 5:
                out["findings"].append(_finding("s7-write", "high", "S7 Write Var request/response"))
        elif function in (0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x28, 0x29):
            s7["operation_data"] = parameter[1:].hex()
            s7["operation_strings"] = _text_indicators(parameter[1:])["strings"]
            severity = "critical" if function in (0x28, 0x29) else "high"
            out["findings"].append(_finding("s7-control", severity, s7["function_name"], function=function))
    if rosctr == 7:
        s7["userdata"] = _parse_s7_userdata(parameter, data_part)
    s7["raw_data"] = data_part.hex()
    s7.update(_text_indicators(parameter + data_part))
    out["s7"] = s7
    out.update(_text_indicators(data))
    return out


# --------------------------------------------------------------------------- BACnet/IP

BACNET_BVLC = {
    0x00: "BVLC-Result",
    0x01: "Write-BDT",
    0x02: "Read-BDT",
    0x03: "Read-BDT-Ack",
    0x04: "Forwarded-NPDU",
    0x05: "Register-Foreign-Device",
    0x06: "Read-FDT",
    0x07: "Read-FDT-Ack",
    0x08: "Delete-FDT-Entry",
    0x09: "Distribute-Broadcast",
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x0C: "Secure-BVLL",
}
BACNET_CONFIRMED = {
    0: "acknowledgeAlarm",
    5: "subscribeCOV",
    6: "atomicReadFile",
    7: "atomicWriteFile",
    8: "addListElement",
    9: "removeListElement",
    10: "createObject",
    11: "deleteObject",
    12: "readProperty",
    14: "readPropertyMultiple",
    15: "writeProperty",
    16: "writePropertyMultiple",
    17: "deviceCommunicationControl",
    20: "reinitializeDevice",
    26: "readRange",
}
BACNET_UNCONFIRMED = {
    0: "i-Am",
    1: "i-Have",
    2: "unconfirmedCOVNotification",
    4: "unconfirmedPrivateTransfer",
    5: "unconfirmedTextMessage",
    6: "timeSynchronization",
    7: "who-Has",
    8: "who-Is",
    9: "utcTimeSynchronization",
    10: "writeGroup",
}
BACNET_PROPERTIES = {
    28: "description",
    44: "firmware-revision",
    70: "model-name",
    75: "object-identifier",
    76: "object-list",
    77: "object-name",
    79: "object-type",
    81: "out-of-service",
    85: "present-value",
    87: "priority-array",
    103: "reliability",
    111: "status-flags",
    112: "system-status",
    117: "units",
    120: "vendor-identifier",
    121: "vendor-name",
    155: "database-revision",
}


def _bacnet_tag(data: bytes, offset: int, depth: int) -> tuple[dict[str, Any], int]:
    if depth > MAX_TAG_DEPTH:
        raise ParseError("BACnet tag nesting exceeds cap")
    _need(data, offset, 1, "BACnet tag")
    first = data[offset]
    offset += 1
    number = first >> 4
    context = bool(first & 0x08)
    lvt = first & 0x07
    if number == 15:
        _need(data, offset, 1, "extended BACnet tag number")
        number = data[offset]
        offset += 1
    if context and lvt in (6, 7):
        return {"class": "context", "number": number, "kind": "open" if lvt == 6 else "close"}, offset
    if not context and number == 1:
        return {"class": "application", "number": 1, "type": "boolean", "value": bool(lvt)}, offset
    length = lvt
    if lvt == 5:
        _need(data, offset, 1, "extended BACnet length")
        length = data[offset]
        offset += 1
        if length == 254:
            length = _u16be(data, offset)
            offset += 2
        elif length == 255:
            _need(data, offset, 4, "extended BACnet length")
            length = int.from_bytes(data[offset : offset + 4], "big")
            offset += 4
    _need(data, offset, length, "BACnet tag value")
    raw = data[offset : offset + length]
    offset += length
    row: dict[str, Any] = {
        "class": "context" if context else "application",
        "number": number,
        "kind": "primitive",
        "raw": raw.hex(),
    }
    if context:
        if 1 <= len(raw) <= 4:
            row["as_unsigned"] = int.from_bytes(raw, "big")
        if number == 0 and len(raw) == 4:
            identifier = int.from_bytes(raw, "big")
            row["as_object_identifier"] = {
                "object_type": identifier >> 22,
                "instance": identifier & 0x3FFFFF,
            }
    else:
        if number == 0:
            row.update(type="null", value=None)
        elif number == 2:
            row.update(type="unsigned", value=int.from_bytes(raw, "big") if raw else 0)
        elif number == 3:
            row.update(type="signed", value=int.from_bytes(raw, "big", signed=True) if raw else 0)
        elif number == 4 and len(raw) == 4:
            row.update(type="real", value=struct.unpack(">f", raw)[0])
        elif number == 5 and len(raw) == 8:
            row.update(type="double", value=struct.unpack(">d", raw)[0])
        elif number == 6:
            row.update(type="octet-string")
        elif number == 7:
            encoding = raw[0] if raw else None
            codecs = {0: "utf-8", 3: "utf-32-be", 4: "utf-16-be", 5: "latin-1"}
            codec = codecs.get(encoding, "latin-1")
            row.update(type="character-string", encoding=encoding, value=raw[1:].decode(codec, "replace") if raw else "")
        elif number == 9:
            value = int.from_bytes(raw, "big") if raw else 0
            row.update(type="enumerated", value=value)
        elif number == 12 and len(raw) == 4:
            value = int.from_bytes(raw, "big")
            row.update(type="object-identifier", object_type=value >> 22, instance=value & 0x3FFFFF)
    row.update(_text_indicators(raw))
    return row, offset


def _bacnet_tags(data: bytes) -> list[dict[str, Any]]:
    rows, offset, depth = [], 0, 0
    while offset < len(data):
        if len(rows) >= MAX_ITEMS:
            raise ParseError("too many BACnet tags")
        row, offset = _bacnet_tag(data, offset, depth)
        if row["kind"] == "close":
            depth = max(0, depth - 1)
        row["depth"] = depth
        rows.append(row)
        if row["kind"] == "open":
            depth += 1
    return rows


def parse_bacnet(data: bytes) -> dict[str, Any]:
    """Parse one BACnet/IP BVLC message."""
    data = _blob(data)
    _need(data, 0, 4, "BACnet BVLC")
    if data[0] not in (0x81, 0x82):
        raise ParseError("BACnet BVLC type is absent")
    length = _u16be(data, 2)
    if length != len(data):
        raise ParseError("BACnet BVLC length mismatch")
    function = data[1]
    out: dict[str, Any] = {
        "protocol": "bacnet",
        "bvlc_type": data[0],
        "bvlc_function": function,
        "bvlc_function_name": BACNET_BVLC.get(function, "Unknown"),
        "length": length,
        "findings": [],
    }
    offset = 4
    if function == 0:
        _need(data, offset, 2, "BVLC result")
        out["result_code"] = _u16be(data, offset)
        return out
    if function == 4:
        _need(data, offset, 6, "forwarded NPDU source")
        out["forwarded_from"] = ".".join(map(str, data[offset : offset + 4])) + f":{_u16be(data, offset + 4)}"
        offset += 6
    if function == 5:
        _need(data, offset, 2, "foreign-device TTL")
        out["ttl"] = _u16be(data, offset)
        return out
    if function in (1, 3):
        entries = []
        while offset + 10 <= len(data):
            entries.append(
                {
                    "address": ".".join(map(str, data[offset : offset + 4])) + f":{_u16be(data, offset + 4)}",
                    "mask": ".".join(map(str, data[offset + 6 : offset + 10])),
                }
            )
            offset += 10
        out["bdt"] = entries
        return out
    if function == 7:
        entries = []
        while offset + 10 <= len(data):
            entries.append(
                {
                    "address": ".".join(map(str, data[offset : offset + 4])) + f":{_u16be(data, offset + 4)}",
                    "ttl": _u16be(data, offset + 6),
                    "remaining": _u16be(data, offset + 8),
                }
            )
            offset += 10
        out["fdt"] = entries
        return out
    if function == 0x0C:
        out["secure_bvll_payload"] = data[offset:].hex()
        out.update(_text_indicators(data[offset:]))
        return out
    if offset >= len(data):
        return out
    _need(data, offset, 2, "BACnet NPDU")
    version, control = data[offset], data[offset + 1]
    offset += 2
    if version != 1:
        raise ParseError("unsupported BACnet NPDU version")
    npdu: dict[str, Any] = {
        "version": version,
        "control": control,
        "network_message": bool(control & 0x80),
        "expecting_reply": bool(control & 0x04),
        "priority": control & 0x03,
    }
    if control & 0x20:
        _need(data, offset, 3, "BACnet destination")
        dnet, dlen = _u16be(data, offset), data[offset + 2]
        _need(data, offset + 3, dlen, "BACnet destination address")
        npdu.update(dnet=dnet, dadr=data[offset + 3 : offset + 3 + dlen].hex())
        offset += 3 + dlen
    if control & 0x08:
        _need(data, offset, 3, "BACnet source")
        snet, slen = _u16be(data, offset), data[offset + 2]
        _need(data, offset + 3, slen, "BACnet source address")
        npdu.update(snet=snet, sadr=data[offset + 3 : offset + 3 + slen].hex())
        offset += 3 + slen
    if control & 0x20:
        _need(data, offset, 1, "BACnet hop count")
        npdu["hop_count"] = data[offset]
        offset += 1
    if control & 0x80:
        _need(data, offset, 1, "BACnet network message type")
        npdu["message_type"] = data[offset]
        offset += 1
        if data[offset - 1] >= 0x80:
            _need(data, offset, 2, "BACnet vendor id")
            npdu["vendor_id"] = _u16be(data, offset)
            offset += 2
        npdu["payload"] = data[offset:].hex()
        out["npdu"] = npdu
        return out
    out["npdu"] = npdu
    _need(data, offset, 1, "BACnet APDU")
    first = data[offset]
    pdu_type = first >> 4
    apdu: dict[str, Any] = {"pdu_type": pdu_type, "segmented": bool(first & 0x08), "more_follows": bool(first & 0x04)}
    service: int | None = None
    tag_offset = offset + 1
    if pdu_type == 0:
        _need(data, offset, 4, "confirmed request")
        apdu.update(max_segments=(data[offset + 1] >> 4) & 7, max_apdu=data[offset + 1] & 0x0F, invoke_id=data[offset + 2])
        cursor = offset + 3
        if first & 0x08:
            _need(data, cursor, 2, "segmented request fields")
            apdu.update(sequence_number=data[cursor], proposed_window=data[cursor + 1])
            cursor += 2
        _need(data, cursor, 1, "confirmed request service")
        service = data[cursor]
        tag_offset = cursor + 1
        apdu.update(service=service, service_name=BACNET_CONFIRMED.get(service, f"confirmed-{service}"))
    elif pdu_type == 1:
        _need(data, offset, 2, "unconfirmed request")
        service = data[offset + 1]
        tag_offset = offset + 2
        apdu.update(service=service, service_name=BACNET_UNCONFIRMED.get(service, f"unconfirmed-{service}"))
    elif pdu_type == 2:
        _need(data, offset, 3, "BACnet simple ACK")
        service = data[offset + 2]
        apdu.update(invoke_id=data[offset + 1], service=service, service_name=BACNET_CONFIRMED.get(service, f"confirmed-{service}"))
        tag_offset = offset + 3
    elif pdu_type == 3:
        _need(data, offset, 3, "BACnet complex ACK")
        apdu["invoke_id"] = data[offset + 1]
        cursor = offset + 2
        if first & 0x08:
            _need(data, cursor, 2, "segmented complex ACK fields")
            apdu.update(sequence_number=data[cursor], proposed_window=data[cursor + 1])
            cursor += 2
        _need(data, cursor, 1, "complex ACK service")
        service = data[cursor]
        apdu.update(service=service, service_name=BACNET_CONFIRMED.get(service, f"confirmed-{service}"))
        tag_offset = cursor + 1
    elif pdu_type == 4:
        _need(data, offset, 4, "BACnet segment ACK")
        apdu.update(invoke_id=data[offset + 1], sequence_number=data[offset + 2], actual_window=data[offset + 3])
        tag_offset = len(data)
    elif pdu_type == 5:
        _need(data, offset, 3, "BACnet error")
        service = data[offset + 2]
        apdu.update(invoke_id=data[offset + 1], service=service, service_name=BACNET_CONFIRMED.get(service, f"confirmed-{service}"))
        tag_offset = offset + 3
    elif pdu_type in (6, 7):
        _need(data, offset, 3, "BACnet reject/abort")
        apdu.update(invoke_id=data[offset + 1], reason=data[offset + 2])
        tag_offset = offset + 3
    else:
        tag_offset = offset + 1
    tag_data = data[tag_offset:]
    if tag_data:
        apdu["tags"] = _bacnet_tags(tag_data)
        context_values = {
            tag["number"]: tag
            for tag in apdu["tags"]
            if tag.get("class") == "context" and tag.get("kind") == "primitive"
        }
        if service in (12, 14, 15, 16):
            object_tag = context_values.get(0)
            property_tag = context_values.get(1)
            if object_tag and "as_object_identifier" in object_tag:
                apdu["object_identifier"] = object_tag["as_object_identifier"]
            if property_tag and "as_unsigned" in property_tag:
                property_id = property_tag["as_unsigned"]
                apdu.update(property_id=property_id, property_name=BACNET_PROPERTIES.get(property_id, f"property-{property_id}"))
            priority_tag = context_values.get(4)
            if priority_tag and "as_unsigned" in priority_tag:
                apdu["priority"] = priority_tag["as_unsigned"]
    if service in (7, 8, 9, 10, 11, 15, 16, 17, 20) or (pdu_type == 1 and service == 10):
        severity = "critical" if service in (17, 20) else "high"
        out["findings"].append(_finding("bacnet-control", severity, apdu.get("service_name", "write/control service")))
    apdu.update(_text_indicators(tag_data))
    out["apdu"] = apdu
    out.update(_text_indicators(data))
    return out


# --------------------------------------------------------------------------- EtherNet/IP + CIP

ENIP_COMMANDS = {
    0x0001: "ListServices",
    0x0004: "ListInterfaces",
    0x0063: "ListIdentity",
    0x0064: "ListInterfaces",
    0x0065: "RegisterSession",
    0x0066: "UnregisterSession",
    0x006F: "SendRRData",
    0x0070: "SendUnitData",
}
CIP_SERVICES = {
    0x01: "Get_Attributes_All",
    0x02: "Set_Attributes_All",
    0x03: "Get_Attribute_List",
    0x04: "Set_Attribute_List",
    0x05: "Reset",
    0x06: "Start",
    0x07: "Stop",
    0x08: "Create",
    0x09: "Delete",
    0x0A: "Multiple_Service_Packet",
    0x0E: "Get_Attribute_Single",
    0x10: "Set_Attribute_Single",
    0x4B: "Execute_PCCC",
    0x4C: "Read_Tag",
    0x4D: "Write_Tag",
    0x4E: "Read_Modify_Write_Tag",
    0x52: "Read_Tag_Fragmented/Unconnected_Send",
    0x53: "Write_Tag_Fragmented",
    0x54: "Forward_Open",
    0x5B: "Large_Forward_Open",
}
CIP_CLASSES = {
    1: "Identity",
    2: "Message Router",
    4: "Assembly",
    6: "Connection Manager",
    0x64: "PCCC",
    0x67: "ControlNet",
    0x6B: "Symbol Object",
    0x6C: "Template Object",
    0xF5: "TCP/IP Interface",
    0xF6: "Ethernet Link",
}


def _parse_cip_path(path: bytes) -> list[dict[str, Any]]:
    rows, offset = [], 0
    while offset < len(path):
        if len(rows) >= 256:
            raise ParseError("CIP path segment cap exceeded")
        segment = path[offset]
        offset += 1
        if segment == 0:
            continue
        if segment == 0x91:
            _need(path, offset, 1, "CIP ANSI symbol length")
            length = path[offset]
            _need(path, offset + 1, length, "CIP ANSI symbol")
            value = path[offset + 1 : offset + 1 + length]
            rows.append({"type": "symbol", "value": value.decode("utf-8", "replace")})
            offset += 1 + length + (length & 1)
        elif segment & 0xE0 == 0x20:
            logical_type = (segment >> 2) & 7
            fmt = segment & 3
            names = {0: "class", 1: "instance", 2: "member", 3: "connection-point", 4: "attribute", 5: "special"}
            if fmt == 0:
                _need(path, offset, 1, "8-bit CIP logical value")
                value, offset = path[offset], offset + 1
            elif fmt == 1:
                _need(path, offset, 3, "16-bit CIP logical value")
                value, offset = _u16le(path, offset + 1), offset + 3
            elif fmt == 2:
                _need(path, offset, 5, "32-bit CIP logical value")
                value, offset = _u32le(path, offset + 1), offset + 5
            else:
                raise ParseError("reserved CIP logical segment format")
            row: dict[str, Any] = {"type": names.get(logical_type, f"logical-{logical_type}"), "value": value}
            if logical_type == 0:
                row["name"] = CIP_CLASSES.get(value, f"Class 0x{value:x}")
            rows.append(row)
        elif segment & 0xE0 == 0x00:
            segment_start = offset - 1
            port = segment & 0x0F
            extended_link = bool(segment & 0x10)
            if port == 15:
                _need(path, offset, 2, "extended CIP port identifier")
                port = _u16le(path, offset)
                offset += 2
            if extended_link:
                _need(path, offset, 1, "extended CIP link-address length")
                length = path[offset]
                _need(path, offset + 1, length, "extended CIP link address")
                link = path[offset + 1 : offset + 1 + length]
                offset += 1 + length
            else:
                _need(path, offset, 1, "CIP link address")
                link = path[offset : offset + 1]
                offset += 1
            rows.append({"type": "port", "port": port, "link": link.hex()})
            if (offset - segment_start) & 1:
                _need(path, offset, 1, "CIP port-segment padding")
                offset += 1
        elif segment & 0xE0 == 0x80:
            subtype = segment & 0x1F
            _need(path, offset, 1, "CIP data segment length")
            words = path[offset]
            _need(path, offset + 1, words * 2, "CIP data segment")
            raw = path[offset + 1 : offset + 1 + words * 2]
            rows.append({"type": f"data-{subtype}", "raw": raw.hex()})
            offset += 1 + words * 2
        else:
            rows.append({"type": "unknown", "segment": segment, "remaining": path[offset:].hex()})
            break
    return rows


def parse_cip(data: bytes, *, _depth: int = 0) -> dict[str, Any]:
    data = _blob(data)
    if _depth > MAX_TAG_DEPTH:
        raise ParseError("CIP nested-service depth exceeds cap")
    _need(data, 0, 1, "CIP service")
    raw_service = data[0]
    response = bool(raw_service & 0x80)
    service = raw_service & 0x7F
    out: dict[str, Any] = {
        "service": service,
        "service_name": CIP_SERVICES.get(service, f"Unknown 0x{service:02x}"),
        "response": response,
        "findings": [],
    }
    if response:
        _need(data, 1, 3, "CIP response header")
        additional_count = data[3]
        _need(data, 4, additional_count * 2, "CIP additional status")
        out.update(
            reserved=data[1],
            general_status=data[2],
            additional_status=[_u16le(data, 4 + 2 * i) for i in range(additional_count)],
        )
        payload = data[4 + additional_count * 2 :]
    else:
        _need(data, 1, 1, "CIP path size")
        path_length = data[1] * 2
        _need(data, 2, path_length, "CIP request path")
        out["path"] = _parse_cip_path(data[2 : 2 + path_length])
        payload = data[2 + path_length :]
    out["data"] = payload.hex()
    if service == 0x0A:
        _need(payload, 0, 2, "multiple-service count")
        count = _u16le(payload, 0)
        if count > 256:
            raise ParseError("excessive CIP multiple-service count")
        _need(payload, 2, count * 2, "multiple-service offsets")
        offsets = [_u16le(payload, 2 + i * 2) for i in range(count)]
        services = []
        for index, start in enumerate(offsets):
            end = offsets[index + 1] if index + 1 < len(offsets) else len(payload)
            if start < 2 + 2 * count or end < start or end > len(payload):
                raise ParseError("invalid CIP multiple-service offset")
            services.append(parse_cip(payload[start:end], _depth=_depth + 1))
        out["services"] = services
    elif not response and service == 0x52 and any(
        row.get("type") == "class" and row.get("value") == 6 for row in out.get("path", [])
    ):
        _need(payload, 0, 4, "CIP Unconnected_Send header")
        message_length = _u16le(payload, 2)
        _need(payload, 4, message_length, "embedded unconnected CIP request")
        embedded = payload[4 : 4 + message_length]
        cursor = 4 + message_length + (message_length & 1)
        _need(payload, cursor, 2, "Unconnected_Send route header")
        route_words = payload[cursor]
        _need(payload, cursor + 2, route_words * 2, "Unconnected_Send route path")
        if cursor + 2 + route_words * 2 != len(payload):
            raise ParseError("Unconnected_Send route has undeclared trailing bytes")
        out.update(
            priority_time_tick=payload[0],
            timeout_ticks=payload[1],
            embedded_request=parse_cip(embedded, _depth=_depth + 1),
            route_path=_parse_cip_path(payload[cursor + 2 : cursor + 2 + route_words * 2]),
        )
    elif not response and service in (0x4C, 0x52):
        _need(payload, 0, 2, "CIP tag-read element count")
        if service == 0x4C and len(payload) != 2:
            raise ParseError("CIP Read_Tag request has undeclared trailing bytes")
        out["element_count"] = _u16le(payload, 0)
        if service == 0x52:
            if len(payload) != 6:
                raise ParseError("CIP fragmented-read request length mismatch")
            out["offset"] = _u32le(payload, 2)
    elif not response and service in (0x4D, 0x53):
        _need(payload, 0, 4, "CIP tag write")
        out.update(type_code=_u16le(payload, 0), element_count=_u16le(payload, 2))
        cursor = 4
        if service == 0x53:
            _need(payload, cursor, 4, "fragmented write offset")
            out["offset"] = _u32le(payload, cursor)
            cursor += 4
        out["write_data"] = payload[cursor:].hex()
    elif not response and service == 0x4E:
        _need(payload, 0, 2, "CIP read-modify-write masks")
        width = _u16le(payload, 0)
        if len(payload) != 2 + width * 2:
            raise ParseError("CIP read-modify-write mask length mismatch")
        out.update(mask_width=width, or_mask=payload[2 : 2 + width].hex(), and_mask=payload[2 + width : 2 + 2 * width].hex())
    elif not response and service in (0x54, 0x5B):
        _need(payload, 0, 20, "CIP Forward_Open")
        out.update(
            priority_time_tick=payload[0],
            timeout_ticks=payload[1],
            originator_to_target_connection_id=_u32le(payload, 2),
            target_to_originator_connection_id=_u32le(payload, 6),
            connection_serial=_u16le(payload, 10),
            originator_vendor=_u16le(payload, 12),
            originator_serial=_u32le(payload, 14),
            timeout_multiplier=payload[18],
        )
    if not response and service in (2, 4, 5, 6, 7, 8, 9, 0x10, 0x4B, 0x4D, 0x4E, 0x53, 0x54, 0x5B):
        severity = "critical" if service in (5, 6, 7, 0x4B) else "high"
        out["findings"].append(_finding("cip-control", severity, out["service_name"], service=service))
    out.update(_text_indicators(payload))
    return out


def _parse_cpf_items(
    payload: bytes, offset: int, count: int, *, decode_explicit_cip: bool
) -> tuple[list[dict[str, Any]], int, list[dict[str, Any]]]:
    if count > 256:
        raise ParseError("excessive CPF item count")
    items, findings = [], []
    for _ in range(count):
        _need(payload, offset, 4, "CPF item")
        item_type, item_length = _u16le(payload, offset), _u16le(payload, offset + 2)
        _need(payload, offset + 4, item_length, "CPF item data")
        raw = payload[offset + 4 : offset + 4 + item_length]
        item: dict[str, Any] = {"type": item_type, "length": item_length, "data": raw.hex()}
        cip_raw = raw
        if item_type == 0x00A1:
            if item_length != 4:
                raise ParseError("connected-address CPF item must be four bytes")
            item["connection_id"] = _u32le(raw, 0)
        elif item_type == 0x8002:
            if item_length != 8:
                raise ParseError("sequenced-address CPF item must be eight bytes")
            item.update(connection_id=_u32le(raw, 0), sequence=_u32le(raw, 4))
        elif item_type == 0x00B1 and len(raw) >= 2:
            item["sequence"] = _u16le(raw, 0)
            cip_raw = raw[2:]
        if decode_explicit_cip and item_type in (0x00B1, 0x00B2) and cip_raw:
            item["cip"] = parse_cip(cip_raw)
            findings.extend(item["cip"].get("findings", []))
        items.append(item)
        offset += 4 + item_length
    return items, offset, findings


def parse_enip(data: bytes) -> dict[str, Any]:
    """Parse one EtherNet/IP encapsulation message and embedded CPF/CIP items."""
    data = _blob(data)
    _need(data, 0, 24, "EtherNet/IP encapsulation")
    command, length = _u16le(data, 0), _u16le(data, 2)
    if length + 24 != len(data):
        raise ParseError("EtherNet/IP length mismatch")
    payload = data[24:]
    out: dict[str, Any] = {
        "protocol": "enip",
        "command": command,
        "command_name": ENIP_COMMANDS.get(command, f"Unknown 0x{command:04x}"),
        "length": length,
        "session": _u32le(data, 4),
        "status": _u32le(data, 8),
        "sender_context": data[12:20].hex(),
        "options": _u32le(data, 20),
        "findings": [],
    }
    if command == 0x0065:
        if len(payload) != 4:
            raise ParseError("RegisterSession payload length mismatch")
        out.update(protocol_version=_u16le(payload, 0), option_flags=_u16le(payload, 2))
    elif command in (0x006F, 0x0070):
        _need(payload, 0, 8, "CPF preamble")
        interface_handle, timeout, count = _u32le(payload, 0), _u16le(payload, 4), _u16le(payload, 6)
        items, offset, cpf_findings = _parse_cpf_items(payload, 8, count, decode_explicit_cip=True)
        if offset != len(payload):
            raise ParseError("CPF item count/length leaves undeclared trailing bytes")
        out["findings"].extend(cpf_findings)
        out.update(interface_handle=interface_handle, timeout=timeout, items=items)
    out.update(_text_indicators(data))
    return out


def parse_enip_io(data: bytes) -> dict[str, Any]:
    """Parse a saved UDP/2222 EtherNet/IP implicit-I/O datagram (no encapsulation header)."""
    data = _blob(data)
    out: dict[str, Any] = {"protocol": "enip", "variant": "implicit-io", "findings": []}
    cpf_types = {0x0000, 0x00A1, 0x00B1, 0x00B2, 0x8002}
    if len(data) >= 6:
        count = _u16le(data, 0)
        first_type = _u16le(data, 2)
        if count <= 256 and first_type in cpf_types:
            items, offset, findings = _parse_cpf_items(data, 2, count, decode_explicit_cip=False)
            if offset != len(data):
                raise ParseError("implicit-I/O CPF has undeclared trailing bytes")
            out.update(format="cpf", items=items)
            out["findings"].extend(findings)
            out.update(_text_indicators(data))
            return out
    _need(data, 0, 8, "implicit-I/O sequence header")
    out.update(
        format="raw-sequenced",
        connection_id=_u32le(data, 0),
        sequence=_u32le(data, 4),
        io_data=data[8:].hex(),
    )
    out.update(_text_indicators(data[8:]))
    return out


# --------------------------------------------------------------------------- IEC 60870-5-104

IEC104_TYPES = {
    1: "M_SP_NA_1 Single-point",
    2: "M_SP_TA_1 Single-point with CP24Time2a",
    3: "M_DP_NA_1 Double-point",
    4: "M_DP_TA_1 Double-point with CP24Time2a",
    5: "M_ST_NA_1 Step position",
    6: "M_ST_TA_1 Step position with CP24Time2a",
    7: "M_BO_NA_1 Bitstring",
    8: "M_BO_TA_1 Bitstring with CP24Time2a",
    9: "M_ME_NA_1 Normalized measured",
    10: "M_ME_TA_1 Normalized measured with CP24Time2a",
    11: "M_ME_NB_1 Scaled measured",
    12: "M_ME_TB_1 Scaled measured with CP24Time2a",
    13: "M_ME_NC_1 Short-float measured",
    14: "M_ME_TC_1 Short-float measured with CP24Time2a",
    15: "M_IT_NA_1 Integrated totals",
    16: "M_IT_TA_1 Integrated totals with CP24Time2a",
    30: "M_SP_TB_1 Timed single-point",
    31: "M_DP_TB_1 Timed double-point",
    32: "M_ST_TB_1 Timed step position",
    33: "M_BO_TB_1 Timed bitstring",
    34: "M_ME_TD_1 Timed normalized",
    35: "M_ME_TE_1 Timed scaled",
    36: "M_ME_TF_1 Timed short-float",
    37: "M_IT_TB_1 Timed integrated totals",
    45: "C_SC_NA_1 Single command",
    46: "C_DC_NA_1 Double command",
    47: "C_RC_NA_1 Regulating-step command",
    48: "C_SE_NA_1 Normalized setpoint",
    49: "C_SE_NB_1 Scaled setpoint",
    50: "C_SE_NC_1 Short-float setpoint",
    51: "C_BO_NA_1 Bitstring command",
    58: "C_SC_TA_1 Timed single command",
    59: "C_DC_TA_1 Timed double command",
    60: "C_RC_TA_1 Timed regulating-step command",
    61: "C_SE_TA_1 Timed normalized setpoint",
    62: "C_SE_TB_1 Timed scaled setpoint",
    63: "C_SE_TC_1 Timed short-float setpoint",
    64: "C_BO_TA_1 Timed bitstring command",
    100: "C_IC_NA_1 Interrogation",
    101: "C_CI_NA_1 Counter interrogation",
    103: "C_CS_NA_1 Clock synchronization",
    104: "C_TS_NA_1 Test command",
    105: "C_RP_NA_1 Reset process",
    107: "C_TS_TA_1 Timed test command",
}
IEC104_CAUSES = {
    1: "periodic",
    2: "background",
    3: "spontaneous",
    4: "initialized",
    5: "request",
    6: "activation",
    7: "activation-confirmation",
    8: "deactivation",
    9: "deactivation-confirmation",
    10: "activation-termination",
    20: "interrogated-by-station",
    44: "unknown-type",
    45: "unknown-cause",
    46: "unknown-common-address",
    47: "unknown-information-object-address",
}


def _cp24time2a(raw: bytes) -> dict[str, Any]:
    _need(raw, 0, 3, "CP24Time2a")
    milliseconds = _u16le(raw, 0)
    return {
        "milliseconds": milliseconds,
        "second": milliseconds // 1000,
        "minute": raw[2] & 0x3F,
        "invalid": bool(raw[2] & 0x80),
        "substituted": bool(raw[2] & 0x40),
    }


def _cp56time2a(raw: bytes) -> dict[str, Any]:
    _need(raw, 0, 7, "CP56Time2a")
    milliseconds = _u16le(raw, 0)
    minute, hour, day, month, year = raw[2] & 0x3F, raw[3] & 0x1F, raw[4] & 0x1F, raw[5] & 0x0F, raw[6] & 0x7F
    out: dict[str, Any] = {
        "milliseconds": milliseconds,
        "minute": minute,
        "hour": hour,
        "day": day,
        "month": month,
        "year": 2000 + year,
        "invalid": bool(raw[2] & 0x80),
        "summer_time": bool(raw[3] & 0x80),
    }
    try:
        out["iso"] = datetime(2000 + year, month, day, hour, minute, milliseconds // 1000, (milliseconds % 1000) * 1000).isoformat()
    except ValueError:
        pass
    return out


def _iec104_element_size(type_id: int) -> int | None:
    return {
        1: 1,
        2: 4,
        3: 1,
        4: 4,
        5: 2,
        6: 5,
        7: 5,
        8: 8,
        9: 3,
        10: 6,
        11: 3,
        12: 6,
        13: 5,
        14: 8,
        15: 5,
        16: 8,
        30: 8,
        31: 8,
        32: 9,
        33: 12,
        34: 10,
        35: 10,
        36: 12,
        37: 12,
        45: 1,
        46: 1,
        47: 1,
        48: 3,
        49: 3,
        50: 5,
        51: 5,
        58: 8,
        59: 8,
        60: 8,
        61: 10,
        62: 10,
        63: 12,
        64: 12,
        100: 1,
        101: 1,
        103: 7,
        104: 2,
        105: 1,
        107: 9,
    }.get(type_id)


def _iec104_value(type_id: int, raw: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"raw": raw.hex()}
    cp24_types = {2, 4, 6, 8, 10, 12, 14, 16}
    cp56_types = {30, 31, 32, 33, 34, 35, 36, 37, 58, 59, 60, 61, 62, 63, 64, 107}
    if type_id in cp24_types:
        value_raw = raw[:-3]
        out["time"] = _cp24time2a(raw[-3:])
    elif type_id in cp56_types:
        value_raw = raw[:-7]
        out["time"] = _cp56time2a(raw[-7:])
    else:
        value_raw = raw
    if type_id == 103:
        out["time"] = _cp56time2a(raw)
    elif type_id in (1, 2, 30):
        out.update(value=bool(value_raw[0] & 1), quality=value_raw[0] & 0xF0)
    elif type_id in (3, 4, 31):
        out.update(value=value_raw[0] & 3, quality=value_raw[0] & 0xF0)
    elif type_id in (5, 6, 32):
        position = value_raw[0] & 0x7F
        if position & 0x40:
            position -= 0x80
        out.update(value=position, transient=bool(value_raw[0] & 0x80), quality=value_raw[1])
    elif type_id in (9, 10, 34, 48, 61):
        raw_value = int.from_bytes(value_raw[:2], "little", signed=True)
        out.update(value=raw_value / 32768.0, quality_or_select=value_raw[2])
    elif type_id in (11, 12, 35, 49, 62):
        out.update(value=int.from_bytes(value_raw[:2], "little", signed=True), quality_or_select=value_raw[2])
    elif type_id in (13, 14, 36, 50, 63):
        out.update(value=struct.unpack("<f", value_raw[:4])[0], quality_or_select=value_raw[4])
    elif type_id in (7, 8, 33, 51, 64):
        out.update(value=_u32le(value_raw, 0), quality_or_select=value_raw[4])
    elif type_id in (15, 16, 37):
        out.update(value=int.from_bytes(value_raw[:4], "little", signed=True), sequence=value_raw[4])
    elif type_id in (45, 58):
        out.update(command=bool(value_raw[0] & 1), select=bool(value_raw[0] & 0x80), qualifier=(value_raw[0] >> 2) & 0x1F)
    elif type_id in (46, 59):
        out.update(command=value_raw[0] & 3, select=bool(value_raw[0] & 0x80), qualifier=(value_raw[0] >> 2) & 0x1F)
    elif type_id in (47, 60):
        out.update(command=value_raw[0] & 3, select=bool(value_raw[0] & 0x80), qualifier=(value_raw[0] >> 2) & 0x1F)
    elif type_id == 104:
        out["test_sequence"] = _u16le(value_raw, 0)
        out["test_pattern_valid"] = out["test_sequence"] == 0xAA55
    elif type_id == 107:
        out["test_sequence"] = _u16le(value_raw, 0)
        out["test_pattern_valid"] = out["test_sequence"] == 0xAA55
    elif type_id in (100, 101, 105):
        out["qualifier"] = value_raw[0]
    return out


def parse_iec104(data: bytes) -> dict[str, Any]:
    """Parse one IEC-104 APDU."""
    data = _blob(data)
    _need(data, 0, 6, "IEC-104 APCI")
    if data[0] != 0x68:
        raise ParseError("IEC-104 start byte is absent")
    length = data[1]
    if length + 2 != len(data) or length < 4:
        raise ParseError("IEC-104 APDU length mismatch")
    control = data[2:6]
    out: dict[str, Any] = {"protocol": "iec104", "length": length, "findings": []}
    if control[0] & 1 == 0:
        out.update(format="I", send_sequence=_u16le(control, 0) >> 1, receive_sequence=_u16le(control, 2) >> 1)
        asdu = data[6:]
    elif control[0] & 3 == 1:
        if length != 4:
            raise ParseError("IEC-104 S-format APDU must contain control bytes only")
        out.update(format="S", receive_sequence=_u16le(control, 2) >> 1)
        return out
    else:
        if length != 4:
            raise ParseError("IEC-104 U-format APDU must contain control bytes only")
        code = control[0] & 0xFC
        names = {
            0x04: "STARTDT act",
            0x08: "STARTDT con",
            0x10: "STOPDT act",
            0x20: "STOPDT con",
            0x40: "TESTFR act",
            0x80: "TESTFR con",
        }
        out.update(format="U", u_function=names.get(code, f"0x{code:02x}"))
        return out
    _need(asdu, 0, 6, "IEC-104 ASDU")
    type_id, vsq = asdu[0], asdu[1]
    count, sequence_addresses = vsq & 0x7F, bool(vsq & 0x80)
    cause_raw = asdu[2]
    asdu_out: dict[str, Any] = {
        "type_id": type_id,
        "type_name": IEC104_TYPES.get(type_id, f"Type {type_id}"),
        "count": count,
        "sequence_addresses": sequence_addresses,
        "cause": cause_raw & 0x3F,
        "cause_name": IEC104_CAUSES.get(cause_raw & 0x3F, "other"),
        "negative_confirm": bool(cause_raw & 0x40),
        "test": bool(cause_raw & 0x80),
        "originator": asdu[3],
        "common_address": _u16le(asdu, 4),
        "objects": [],
    }
    size = _iec104_element_size(type_id)
    offset, base_ioa = 6, None
    if count > MAX_ITEMS:
        raise ParseError("excessive IEC-104 object count")
    if size is None:
        asdu_out["undecoded"] = asdu[offset:].hex()
    else:
        for index in range(count):
            if not sequence_addresses or index == 0:
                _need(asdu, offset, 3, "IEC-104 IOA")
                base_ioa = _u24le(asdu, offset)
                offset += 3
            assert base_ioa is not None
            ioa = base_ioa + index if sequence_addresses else base_ioa
            _need(asdu, offset, size, "IEC-104 information element")
            raw = asdu[offset : offset + size]
            offset += size
            asdu_out["objects"].append({"ioa": ioa, **_iec104_value(type_id, raw)})
        if offset != len(asdu):
            raise ParseError("IEC-104 ASDU has undeclared trailing bytes")
    if type_id in set(range(45, 52)) | set(range(58, 65)) | {103, 104, 105, 107}:
        severity = "critical" if type_id in (45, 46, 47, 50, 51, 58, 59, 63, 105) else "high"
        out["findings"].append(_finding("iec104-control", severity, asdu_out["type_name"], type_id=type_id))
    asdu_out.update(_text_indicators(asdu))
    out["asdu"] = asdu_out
    out.update(_text_indicators(data))
    return out


# --------------------------------------------------------------------------- Dispatch and CLI

PORT_PROTOCOLS = {
    102: "s7comm",
    502: "modbus",
    2404: "iec104",
    20000: "dnp3",
    44818: "enip",
    2222: "enip",
    47808: "bacnet",
}


def detect_protocol(data: bytes, *, source_port: int | None = None, destination_port: int | None = None) -> str | None:
    data = _blob(data)
    if len(data) >= 2 and data[:2] == b"\x05\x64":
        return "dnp3"
    if len(data) >= 2 and data[:2] == b"\x03\x00":
        return "s7comm"
    if data[:1] == b"\x68":
        return "iec104"
    if data[:1] in (b"\x81", b"\x82"):
        return "bacnet"
    if len(data) >= 24 and _u16le(data, 0) in ENIP_COMMANDS and _u16le(data, 2) + 24 == len(data):
        return "enip"
    if len(data) >= 8 and data[2:4] == b"\x00\x00" and _u16be(data, 4) + 6 == len(data):
        return "modbus"
    for port in (destination_port, source_port):
        if port in PORT_PROTOCOLS:
            return PORT_PROTOCOLS[port]
    return None


def dissect(
    data: bytes,
    *,
    protocol: str | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    direction: str = "auto",
) -> dict[str, Any]:
    protocol = protocol or detect_protocol(data, source_port=source_port, destination_port=destination_port)
    if protocol == "modbus":
        return parse_modbus(data, direction=direction)
    if protocol == "dnp3":
        return parse_dnp3(data)
    if protocol == "s7comm":
        return parse_s7comm(data)
    if protocol == "bacnet":
        return parse_bacnet(data)
    if protocol == "enip":
        if 2222 in (source_port, destination_port) and not (
            len(data) >= 24 and _u16le(data, 2) + 24 == len(data)
        ):
            return parse_enip_io(data)
        return parse_enip(data)
    if protocol == "iec104":
        return parse_iec104(data)
    raise ParseError("unable to identify supported industrial protocol")


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline deep industrial-protocol payload dissector")
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument("--protocol", choices=["modbus", "dnp3", "s7comm", "bacnet", "enip", "iec104"])
    parser.add_argument("--direction", choices=["auto", "request", "response"], default="auto")
    args = parser.parse_args(argv)
    rows = []
    try:
        for path in args.artifacts:
            if path.stat().st_size > MAX_PAYLOAD:
                raise ParseError(f"{path}: artifact exceeds 32 MiB cap")
            rows.append({"path": str(path), "analysis": dissect(path.read_bytes(), protocol=args.protocol, direction=args.direction)})
    except (OSError, ParseError, ValueError, TypeError) as exc:
        print(f"ics_protocols: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(rows, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
