"""Bounded offline inventory for classic STEP 7 MC7 blocks and project tables.

This extends :mod:`ot_stuxnet_artifacts`, whose MC7 reader intentionally stops
at header/footer metadata. It splits documented MC7/SBB/ADD sections, parses
binary interfaces and scalar DB values, reads dBASE tables, and conservatively
inventories MDX/DBT companions. It never contacts a PLC, executes code, or
evaluates index expressions. Public parsers raise only ``S7DeepError``.
"""
from __future__ import annotations

import argparse
from datetime import date, timedelta
import functools
import hashlib
import json
import math
import os
from pathlib import PurePosixPath
import stat
import struct
import sys

import ot_stuxnet_artifacts


class S7DeepError(ValueError):
    """Malformed, unsupported, inaccessible, or over-limit STEP 7 artifact."""


class _UnresolvedDBLayout(Exception):
    """Internal stop signal when an interface lacks enough storage geometry."""

    def __init__(self, address, reason):
        super().__init__(reason)
        self.address = address


MAX_ARTIFACT = 8 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 512
MAX_FIELDS = 256
MAX_RECORDS = 20_000
MAX_DESCRIPTORS = 4096
MAX_VALUES = 4096
MAX_DEPTH = 32
MAX_INLINE = 4096
MAX_MDX_TAGS = 47

_TYPE_NAMES = {
    0x01: "BOOL", 0x02: "BYTE", 0x03: "CHAR", 0x04: "WORD",
    0x05: "INT", 0x06: "DWORD", 0x07: "DINT", 0x08: "REAL",
    0x09: "DATE", 0x0A: "TIME_OF_DAY", 0x0B: "TIME",
    0x0C: "S5TIME", 0x0E: "DATE_AND_TIME", 0x10: "ARRAY",
    0x11: "STRUCT", 0x13: "STRING", 0x14: "POINTER",
    0x15: "MULTI_INSTANCE_FB", 0x16: "ANY", 0x17: "BLOCK_FB",
    0x18: "BLOCK_FC", 0x19: "BLOCK_DB", 0x1A: "BLOCK_SDB",
    0x1B: "MULTI_INSTANCE_SFB", 0x1C: "COUNTER", 0x1D: "TIMER",
}
_PARAM_NAMES = {
    0x01: "IN", 0x09: "IN_INIT", 0x11: "IN_EXT", 0x19: "IN_EXT_INIT",
    0x02: "OUT", 0x0A: "OUT_INIT", 0x12: "OUT_EXT", 0x1A: "OUT_EXT_INIT",
    0x03: "IN_OUT", 0x0B: "IN_OUT_INIT", 0x13: "IN_OUT_EXT",
    0x1B: "IN_OUT_EXT_INIT", 0x04: "STATIC", 0x0C: "STATIC_INIT",
    0x14: "STATIC_EXT", 0x1C: "STATIC_EXT_INIT", 0x05: "TEMP",
    0x15: "TEMP_EXT", 0x06: "RET", 0x16: "RET_EXT",
}
_EXT_PARAMS = {0x11, 0x19, 0x12, 0x1A, 0x13, 0x1B, 0x14, 0x1C, 0x15, 0x16}
_INIT_PARAMS = {0x09, 0x19, 0x0A, 0x1A, 0x0B, 0x1B, 0x0C, 0x1C}
_START_TYPES = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0A, 0x0B, 0x0C, 0x0E, 0x13}
_MULTI_TYPES = {0x15, 0x1B}
_SCALAR_SIZES = {
    0x01: 1, 0x02: 1, 0x03: 1, 0x04: 2, 0x05: 2, 0x06: 4,
    0x07: 4, 0x08: 4, 0x09: 2, 0x0A: 4, 0x0B: 4, 0x0C: 2,
    0x0E: 8, 0x14: 6, 0x16: 10, 0x17: 2, 0x18: 2, 0x19: 2,
    0x1A: 2, 0x1C: 2, 0x1D: 2,
}
_INTERFACE_MARKERS = {
    0x01: "code-block", 0x05: "data-block", 0x0A: "instance-db-fb",
    0x0B: "instance-db-sfb", 0x10: "legacy-di-marker",
}
_BLOCK_TYPES = {0x08: "OB", 0x0A: "DB", 0x0B: "SDB", 0x0C: "FC",
                0x0D: "SFC", 0x0E: "FB", 0x0F: "SFB", 0x00: "UDT"}
_DBF_VERSIONS = {0x03, 0x04, 0x7B, 0x83, 0x8B}
_DBF_TYPES = set("CDFLMN")
_ENCODINGS = {0: "cp437", 1: "cp437", 2: "cp850", 3: "cp1252",
              4: "mac_roman", 0x57: "cp1252"}


def _fail_closed(function):
    @functools.wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except S7DeepError:
            raise
        except Exception as exc:
            raise S7DeepError(f"{function.__name__}: malformed input: {exc}") from exc
    return guarded


def _blob(data, cap=None, label="artifact"):
    if cap is None:
        cap = MAX_ARTIFACT
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise S7DeepError(f"{label} must be bytes")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > cap:
            raise S7DeepError(f"{label} exceeds byte limit")
        return bytes(data)
    except S7DeepError:
        raise
    except (TypeError, ValueError, BufferError) as exc:
        raise S7DeepError(f"invalid {label} buffer") from exc


def _u16be(data, offset):
    return int.from_bytes(data[offset:offset + 2], "big")


def _u16le(data, offset):
    return int.from_bytes(data[offset:offset + 2], "little")


def _u32le(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


def _text(raw, encoding="ascii"):
    raw = raw.split(b"\0", 1)[0]
    try:
        return raw.decode(encoding).rstrip(" \0")
    except (LookupError, UnicodeError) as exc:
        raise S7DeepError("invalid encoded text") from exc


def _region(data, offset=0):
    shown = data[:MAX_INLINE]
    return {"offset": offset, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "hex": shown.hex(),
            "hex_truncated": len(shown) != len(data)}


def _crc16_mc7(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (((crc << 1) ^ 0x9003) if crc & 0x8000 else crc << 1) & 0xFFFF
    return crc


def _take(data, position, amount, what):
    if amount < 0 or position < 0 or position + amount > len(data):
        raise S7DeepError(f"truncated {what}")
    return data[position:position + amount]


def _parameter(data, position):
    _take(data, position, 2, "interface descriptor")
    parameter = data[position + 1]
    if parameter not in _PARAM_NAMES:
        raise S7DeepError(f"unknown interface parameter type 0x{parameter:02x}")
    return parameter


def _parse_descriptor(data, position, depth, budget):
    if depth > MAX_DEPTH:
        raise S7DeepError("interface nesting limit exceeded")
    if budget[0] >= MAX_DESCRIPTORS:
        raise S7DeepError("interface descriptor limit exceeded")
    _take(data, position, 1, "interface descriptor")
    start = position
    datatype = data[position]
    if datatype not in _TYPE_NAMES:
        raise S7DeepError(f"unknown interface datatype 0x{datatype:02x}")
    budget[0] += 1
    item = {"offset": start, "data_type_code": datatype,
            "data_type": _TYPE_NAMES[datatype]}
    if datatype in _MULTI_TYPES:
        raw = _take(data, position, 3, "multi-instance descriptor")
        item.update(parameter_type="STATIC", parameter_type_code=0x04,
                    block_number=int.from_bytes(raw[1:3], "little"))
        position += 3
    else:
        parameter = _parameter(data, position)
        item.update(parameter_type_code=parameter,
                    parameter_type=_PARAM_NAMES[parameter],
                    has_initial_value=parameter in _INIT_PARAMS,
                    extended=parameter in _EXT_PARAMS)
        position += 2
        if parameter in _EXT_PARAMS:
            item["extended_flags"] = _take(data, position, 1, "extended descriptor")[0]
            position += 1
        if datatype == 0x13:
            item["max_length"] = _take(data, position, 1, "STRING descriptor")[0]
            position += 1
        elif datatype == 0x10:
            dimensions = _take(data, position, 1, "ARRAY dimensions")[0]
            position += 1
            if not 1 <= dimensions <= 6:
                raise S7DeepError("ARRAY dimension count is outside STEP 7 limits")
            bounds, elements = [], 1
            for _ in range(dimensions):
                raw = _take(data, position, 4, "ARRAY bounds")
                lower = int.from_bytes(raw[:2], "little", signed=True)
                upper = int.from_bytes(raw[2:], "little", signed=True)
                if upper < lower:
                    raise S7DeepError("ARRAY upper bound precedes lower bound")
                width = upper - lower + 1
                if elements > MAX_VALUES // width:
                    raise S7DeepError("ARRAY element limit exceeded")
                elements *= width
                bounds.append({"lower": lower, "upper": upper})
                position += 4
            child, position = _parse_descriptor(data, position, depth + 1, budget)
            item.update(dimensions=bounds, element_count=elements, element=child)
        elif datatype == 0x11:
            count = _take(data, position, 1, "STRUCT child count")[0]
            position += 1
            if count == 0xFF:
                count = _u16le(_take(data, position, 2, "extended STRUCT child count"), 0)
                position += 2
            if count > MAX_DESCRIPTORS - budget[0]:
                raise S7DeepError("STRUCT child limit exceeded")
            children = []
            for _ in range(count):
                child, position = _parse_descriptor(data, position, depth + 1, budget)
                children.append(child)
            item.update(child_count=count, children=children)
        elif datatype not in _SCALAR_SIZES:
            raise S7DeepError("unsupported interface datatype")
    item["encoded_size"] = position - start
    return item, position


def _decode_bcd_datetime(raw):
    if len(raw) != 8:
        return None
    values = []
    for byte in raw[:7]:
        high, low = byte >> 4, byte & 0x0F
        if high > 9 or low > 9:
            return None
        values.append(high * 10 + low)
    last_high = raw[7] >> 4
    if last_high > 9 or not 1 <= (raw[7] & 0x0F) <= 7:
        return None
    milliseconds = values[6] * 10 + last_high
    year = 2000 + values[0] if values[0] < 90 else 1900 + values[0]
    try:
        date(year, values[1], values[2])
        if values[3] > 23 or values[4] > 59 or values[5] > 59:
            return None
    except ValueError:
        return None
    return {"iso": (f"{year:04d}-{values[1]:02d}-{values[2]:02d}T"
                    f"{values[3]:02d}:{values[4]:02d}:{values[5]:02d}."
                    f"{milliseconds:03d}"), "weekday": raw[7] & 0x0F}


def _s5time(raw, endian):
    word = int.from_bytes(raw, endian)
    digits = ((word >> 8) & 0x0F, (word >> 4) & 0x0F, word & 0x0F)
    scale = (10, 100, 1000, 10_000)[(word >> 12) & 0x03]
    # Siemens documents bits 15-14 as ignored (don't-care); only the time base
    # (bits 13-12) and the three BCD digits are significant.
    if any(digit > 9 for digit in digits):
        return {"s5time_raw": raw.hex(), "valid": False}
    magnitude = digits[0] * 100 + digits[1] * 10 + digits[2]
    return {"milliseconds": magnitude * scale, "valid": True}


def _decode_scalar(raw, datatype, endian, descriptor=None, bit=0):
    if datatype == 0x01:
        return bool((raw[0] >> bit) & 1)
    if datatype == 0x02:
        return raw[0]
    if datatype == 0x03:
        return raw.decode("latin1")
    if datatype in (0x04, 0x06):
        return int.from_bytes(raw, endian)
    if datatype in (0x05, 0x07):
        return int.from_bytes(raw, endian, signed=True)
    if datatype == 0x08:
        value = struct.unpack((">" if endian == "big" else "<") + "f", raw)[0]
        return value if math.isfinite(value) else {"non_finite": repr(value)}
    if datatype == 0x09:
        days = int.from_bytes(raw, endian)
        return {"days_since_1990_01_01": days,
                "iso": (date(1990, 1, 1) + timedelta(days=days)).isoformat()}
    if datatype == 0x0A:
        value = int.from_bytes(raw, endian)
        return {"milliseconds_since_midnight": value, "valid": value < 86_400_000}
    if datatype == 0x0B:
        return {"milliseconds": int.from_bytes(raw, endian, signed=True)}
    if datatype == 0x0C:
        return _s5time(raw, endian)
    if datatype == 0x0E:
        decoded = _decode_bcd_datetime(raw)
        return decoded if decoded is not None else {"date_and_time_raw": raw.hex(), "valid": False}
    if datatype == 0x13:
        maximum, used = raw[0], raw[1]
        declared = descriptor.get("max_length", maximum) if descriptor else maximum
        if maximum > declared or used > maximum or 2 + used > len(raw):
            raise S7DeepError("invalid S7 STRING value")
        return {"maximum": maximum, "length": used,
                "text": raw[2:2 + used].decode("latin1")}
    if datatype in (0x17, 0x18, 0x19, 0x1A):
        return {"block": _TYPE_NAMES[datatype].removeprefix("BLOCK_")
                + str(int.from_bytes(raw, endian))}
    if datatype == 0x1C:
        return {"counter": int.from_bytes(raw, endian)}
    if datatype == 0x1D:
        return {"timer": int.from_bytes(raw, endian)}
    if datatype == 0x14:
        bits = int.from_bytes(raw[3:6], "big")
        return {"db_number": int.from_bytes(raw[:2], "big"), "area": raw[2],
                "byte_offset": bits >> 3, "bit_offset": bits & 7}
    if datatype == 0x16:
        element_type = raw[1]
        result = {"syntax_id": raw[0], "element_type": element_type,
                  "repeat": int.from_bytes(raw[2:4], "big")}
        # TIMER/COUNTER ANY pointers encode a timer/counter number in bytes
        # 8..9 (byte 6 repeats the type, byte 7 is zero) rather than a
        # DB/area byte.bit memory address.
        if element_type in (0x1C, 0x1D):
            result["parameter_type"] = {0x1C: "COUNTER", 0x1D: "TIMER"}[element_type]
            result["parameter_number"] = int.from_bytes(raw[8:10], "big")
            return result
        bits = int.from_bytes(raw[7:10], "big")
        result.update(db_number=int.from_bytes(raw[4:6], "big"), area=raw[6],
                      byte_offset=bits >> 3, bit_offset=bits & 7)
        return result
    return {"raw": raw.hex()}


def _descriptor_size(item):
    if item["data_type_code"] == 0x13:
        return item["max_length"] + 2
    return _SCALAR_SIZES.get(item["data_type_code"])


def _align_value(address, datatype, collection=False):
    byte, bit = address
    if bit and datatype != 0x01:
        byte, bit = byte + 1, 0
    if (collection or datatype not in (0x01, 0x02, 0x03)) and byte % 2:
        byte += 1
    return byte, bit


def _layout_values(item, path, actual, address, values, depth=0):
    if depth > MAX_DEPTH or len(values) >= MAX_VALUES:
        raise S7DeepError("DB value expansion limit exceeded")
    datatype = item["data_type_code"]
    parameter = item.get("parameter_type", "STATIC")
    if parameter.startswith(("TEMP", "RET")):
        raise _UnresolvedDBLayout(
            address, f"{parameter} is not persistent DB storage")
    if datatype == 0x11:
        byte, bit = _align_value(address, datatype, True)
        for index, child in enumerate(item["children"]):
            byte, bit = _layout_values(child, f"{path}.member[{index}]", actual,
                                       (byte, bit), values, depth + 1)
        if bit:
            byte, bit = byte + 1, 0
        if byte % 2:
            byte += 1
        return byte, bit
    if datatype == 0x10:
        byte, bit = _align_value(address, datatype, True)
        child = item["element"]
        bounds = item["dimensions"]
        widths = [bound["upper"] - bound["lower"] + 1 for bound in bounds]
        for ordinal in range(item["element_count"]):
            remainder, indices = ordinal, []
            for bound, width in zip(reversed(bounds), reversed(widths)):
                indices.append(bound["lower"] + remainder % width)
                remainder //= width
            index_text = ",".join(str(index) for index in reversed(indices))
            byte, bit = _layout_values(child, f"{path}[{index_text}]", actual,
                                       (byte, bit), values, depth + 1)
        if bit:
            byte, bit = byte + 1, 0
        if byte % 2:
            byte += 1
        return byte, bit
    if datatype in _MULTI_TYPES:
        raise _UnresolvedDBLayout(
            address, f"{item['data_type']} requires the referenced FB interface")
    byte, bit = _align_value(address, datatype)
    size = _descriptor_size(item)
    if size is None:
        return byte, bit
    raw = _take(actual, byte, size, "DB current value")
    values.append({"path": path, "data_type": item["data_type"],
                   "parameter_type": item.get("parameter_type"),
                   "byte_offset": byte, "bit_offset": bit, "size": size,
                   "raw_hex": raw.hex(),
                   "value": _decode_scalar(raw, datatype, "big", item, bit)})
    if datatype == 0x01:
        bit += 1
        if bit == 8:
            byte, bit = byte + 1, 0
    else:
        byte, bit = byte + size, 0
    return byte, bit


def _base_path(item, counts):
    parameter = item.get("parameter_type", "STATIC")
    if parameter.startswith("IN_OUT"):
        category = "IN_OUT"
    else:
        category = parameter.split("_", 1)[0]
    counts[category] = counts.get(category, 0) + 1
    return f"{category}[{counts[category] - 1}]"


def _decode_actual_values(descriptors, actual):
    values, address, counts = [], (0, 0), {}
    complete, reason = True, None
    try:
        for item in descriptors:
            address = _layout_values(
                item, _base_path(item, counts), actual, address, values)
    except _UnresolvedDBLayout as exc:
        address, complete, reason = exc.address, False, str(exc)
    byte, bit = address
    consumed = byte + (1 if bit else 0)
    if consumed > len(actual):
        raise S7DeepError("interface values exceed DB current-value bytes")
    return values, consumed, complete, reason


def _walk_start_items(item, path, output):
    datatype = item["data_type_code"]
    if datatype == 0x11:
        for index, child in enumerate(item["children"]):
            _walk_start_items(child, f"{path}.member[{index}]", output)
    elif datatype == 0x10:
        output.append((path, item, False))
    elif item.get("has_initial_value"):
        output.append((path, item, datatype in _START_TYPES))


def _decode_start_values(descriptors, raw):
    pending, counts = [], {}
    for item in descriptors:
        _walk_start_items(item, _base_path(item, counts), pending)
    position, decoded, complete = 0, [], True
    for path, item, supported in pending:
        if not supported:
            complete = False
            break
        if item["data_type_code"] == 0x13:
            header = _take(raw, position, 2, "STRING interface start value")
            maximum, used = header
            if maximum > item["max_length"] or used > maximum:
                raise S7DeepError("invalid compact STRING start value")
            amount = 2 + used
        else:
            amount = _descriptor_size(item)
        value_raw = _take(raw, position, amount, "interface start value")
        decoded.append({"path": path, "data_type": item["data_type"],
                        "offset": position, "size": amount,
                        "raw_hex": value_raw.hex(),
                        "value": _decode_scalar(value_raw, item["data_type_code"],
                                                "little", item)})
        position += amount
    if position != len(raw):
        complete = False
    return decoded, position, complete


def _parse_mc7_interface_impl(data, actual_values=None):
    data = _blob(data, label="MC7 SBB/interface")
    if len(data) < 7:
        raise S7DeepError("MC7 interface is shorter than its seven-byte header")
    marker = data[0]
    if marker not in _INTERFACE_MARKERS:
        raise S7DeepError(f"unsupported MC7 interface marker 0x{marker:02x}")
    descriptor_length, start_length = _u16le(data, 3), _u16le(data, 5)
    descriptor_end = 7 + descriptor_length
    start_end = descriptor_end + start_length
    if start_end > len(data):
        raise S7DeepError("MC7 interface/start-value lengths exceed SBB")
    descriptor_bytes = data[7:descriptor_end]
    descriptors, position, budget = [], 0, [0]
    while position < len(descriptor_bytes):
        item, position = _parse_descriptor(descriptor_bytes, position, 0, budget)
        descriptors.append(item)
    if position != len(descriptor_bytes):
        raise S7DeepError("interface descriptor length mismatch")
    start_raw = data[descriptor_end:start_end]
    starts, consumed, complete = _decode_start_values(descriptors, start_raw)
    result = {
        "marker_code": marker, "marker": _INTERFACE_MARKERS[marker],
        "reference_number": _u16le(data, 1),
        "descriptor_length": descriptor_length, "start_value_length": start_length,
        "descriptors": descriptors, "start_values": starts,
        "start_values_consumed": consumed, "start_values_complete": complete,
        "start_values_hex": start_raw[:MAX_INLINE].hex(),
        "start_values_hex_truncated": len(start_raw) > MAX_INLINE,
        "padding_hex": data[start_end:start_end + MAX_INLINE].hex(),
        "padding_hex_truncated": len(data) - start_end > MAX_INLINE,
        "padding_size": len(data) - start_end,
    }
    if marker == 0x10:
        result["warning"] = "legacy source labels decimal 10 as 0x10; marker retained"
    if actual_values is not None:
        actual = _blob(actual_values, label="DB current values")
        values, used, values_complete, stop_reason = _decode_actual_values(
            descriptors, actual)
        slack = actual[used:]
        result.update(db_values=values, db_values_consumed=used,
                      db_values_complete=values_complete,
                      db_value_slack_hex=slack[:MAX_INLINE].hex(),
                      db_value_slack_truncated=len(slack) > MAX_INLINE)
        if stop_reason is not None:
            result["db_values_stop_reason"] = stop_reason
    return result


@_fail_closed
def parse_mc7_interface(data, actual_values=None):
    """Parse one complete compiled SBB interface, optionally with DB values."""
    return _parse_mc7_interface_impl(data, actual_values)


def _segment_inventory(data, body_size, offset=0):
    result = _region(data, offset)
    if len(data) < 2:
        result.update(network_table_valid=False, network_count=None, network_offsets=[])
        return result
    count = _u16le(data, 0)
    needed = max(count, 1) * 2
    if count > MAX_VALUES or needed > len(data):
        result.update(network_table_valid=False, network_count=count, network_offsets=[])
        return result
    offsets = [] if count == 0 else [0]
    for index in range(1, count):
        offsets.append(_u16le(data, index * 2))
    valid = offsets == sorted(offsets) and all(offset <= body_size for offset in offsets)
    trailing = data[needed:]
    result.update(network_table_valid=valid, network_count=count,
                  network_offsets=offsets,
                  trailing_hex=trailing[:MAX_INLINE].hex(),
                  trailing_hex_truncated=len(trailing) > MAX_INLINE)
    return result


@_fail_closed
def parse_mc7_block(data):
    """Parse a complete classic online MC7 block with strict section geometry."""
    data = _blob(data, label="MC7 block")
    try:
        metadata = ot_stuxnet_artifacts.parse_mc7(data)
    except ot_stuxnet_artifacts.StuxnetError as exc:
        raise S7DeepError(str(exc)) from exc
    body_size, sbb_size, add_size = _u16be(data, 34), _u16be(data, 28), _u16be(data, 30)
    if len(data) != 72 + body_size + sbb_size + add_size:
        raise S7DeepError("MC7 body/SBB/ADD lengths do not exactly reach the footer")
    body_start, sbb_start = 36, 36 + body_size
    add_start, footer_start = sbb_start + sbb_size, sbb_start + sbb_size + add_size
    body, sbb = data[body_start:sbb_start], data[sbb_start:add_start]
    additional = data[add_start:footer_start]
    stored = _u16be(data, footer_start + 26)
    calculated = _crc16_mc7(bytes([data[5]]) + data[34:36] + body)
    metadata["checksum_verified"] = stored == calculated
    result = {
        "format": "step7-mc7-deep", "metadata": metadata,
        "sections": {
            "mc7_code_or_db_values": _region(body, body_start),
            "sbb": _region(sbb, sbb_start),
            "additional_info": _region(additional, add_start),
            "footer": _region(data[footer_start:], footer_start),
        },
        "checksum": {"stored": stored, "calculated": calculated,
                     "valid": stored == calculated},
        "interface": None,
        "segment_table": _segment_inventory(additional, body_size, add_start),
    }
    if sbb:
        result["interface"] = _parse_mc7_interface_impl(
            sbb, body if metadata["block_type"] in ("DB", "SDB") else None)
    if metadata["block_type"] in ("DB", "SDB"):
        result["db_values"] = (result["interface"] or {}).get("db_values", [])
    else:
        result["code"] = _region(body, body_start)
    return result


def _dbf_value(raw, field, encoding):
    kind = field["type"]
    if kind == "C":
        return raw.rstrip(b" \0").decode(encoding, errors="replace")
    if kind in ("N", "F"):
        text = raw.decode("ascii").strip()
        if not text:
            return None
        try:
            if kind == "N" and field["decimals"] == 0 and all(c not in text for c in ".eE"):
                return int(text, 10)
            value = float(text)
        except ValueError as exc:
            raise S7DeepError(f"invalid numeric DBF value in {field['name']}") from exc
        if not math.isfinite(value):
            raise S7DeepError("non-finite DBF numeric value")
        return value
    if kind == "L":
        if len(raw) != 1:
            raise S7DeepError("DBF logical field must be one byte")
        if raw in b"TtYy":
            return True
        if raw in b"FfNn":
            return False
        if raw in (b" ", b"?"):
            return None
        raise S7DeepError("invalid DBF logical value")
    if kind == "D":
        text = raw.decode("ascii").strip()
        if not text or text == "00000000":
            return None
        if len(text) != 8 or not text.isdigit():
            raise S7DeepError("invalid DBF date value")
        try:
            return date(int(text[:4]), int(text[4:6]), int(text[6:])).isoformat()
        except ValueError as exc:
            raise S7DeepError("invalid DBF calendar date") from exc
    if kind == "M":
        text = raw.decode("ascii").strip()
        if not text:
            return None
        try:
            pointer = int(text, 10)
        except ValueError as exc:
            raise S7DeepError("invalid DBF memo pointer") from exc
        if pointer < 0:
            raise S7DeepError("negative DBF memo pointer")
        return pointer
    return {"raw_hex": raw.hex()}


def _parse_dbf_impl(data):
    data = _blob(data, label="DBF table")
    if len(data) < 33 or data[0] not in _DBF_VERSIONS:
        raise S7DeepError("not a supported classic dBASE III/IV table")
    if data[15]:
        raise S7DeepError("encrypted DBF tables are unsupported")
    record_count = _u32le(data, 4)
    header_length, record_length = _u16le(data, 8), _u16le(data, 10)
    if record_count > MAX_RECORDS:
        raise S7DeepError("DBF record limit exceeded")
    if not 33 <= header_length <= len(data) or not 1 <= record_length <= 4000:
        raise S7DeepError("invalid DBF header/record length")
    fields, position, names = [], 32, set()
    while position < header_length and data[position] != 0x0D:
        if len(fields) >= MAX_FIELDS or position + 32 > header_length:
            raise S7DeepError("DBF field descriptor limit/geometry error")
        raw = data[position:position + 32]
        name = _text(raw[:11], "ascii")
        if not name or not all(32 < ord(char) < 127 for char in name):
            raise S7DeepError("invalid DBF field name")
        folded = name.casefold()
        if folded in names:
            raise S7DeepError("duplicate case-insensitive DBF field name")
        names.add(folded)
        kind = chr(raw[11])
        if kind not in _DBF_TYPES:
            raise S7DeepError(f"unsupported DBF field type {kind!r}")
        width, decimals = raw[16], raw[17]
        if width == 0:
            raise S7DeepError("zero-width DBF field")
        fields.append({"name": name, "type": kind, "length": width,
                       "decimals": decimals, "indexed": bool(raw[31] & 1),
                       "descriptor_offset": position})
        position += 32
    if position >= header_length or data[position] != 0x0D:
        raise S7DeepError("missing DBF field terminator")
    if 1 + sum(field["length"] for field in fields) != record_length:
        raise S7DeepError("DBF record length does not match field descriptors")
    records_end = header_length + record_count * record_length
    if records_end > len(data):
        raise S7DeepError("DBF records are truncated")
    encoding = _ENCODINGS.get(data[29], "cp1252")
    rows = []
    for index in range(record_count):
        start = header_length + index * record_length
        record = data[start:start + record_length]
        if record[:1] not in (b" ", b"*"):
            raise S7DeepError("invalid DBF deletion flag")
        values, cursor = {}, 1
        for field in fields:
            raw = record[cursor:cursor + field["length"]]
            values[field["name"]] = _dbf_value(raw, field, encoding)
            cursor += field["length"]
        rows.append({"index": index, "deleted": record[0] == 0x2A,
                     "raw_hex": record.hex(), "values": values})
    trailing = data[records_end:]
    eof = bool(trailing[:1] == b"\x1a")
    slack = trailing[1:] if eof else trailing
    year, month, day = data[1], data[2], data[3]
    update_date = None
    if year or month or day:
        try:
            update_date = date(1900 + year, month, day).isoformat()
        except ValueError:
            update_date = None
    warnings = []
    if data[14]:
        warnings.append("incomplete-transaction flag is set")
    if update_date is None and (year or month or day):
        warnings.append("invalid last-update date retained as raw bytes")
    return {
        "format": "dbase-table", "version": data[0],
        "last_update": update_date, "last_update_raw": [year, month, day],
        "record_count": record_count, "header_length": header_length,
        "record_length": record_length, "language_driver": data[29],
        "encoding": encoding, "production_mdx": bool(data[28] & 1),
        "fields": fields, "records": rows,
        "header_slack_hex": data[position + 1:min(header_length, position + 1 + MAX_INLINE)].hex(),
        "header_slack_truncated": header_length - position - 1 > MAX_INLINE,
        "eof_marker": eof, "section_slack_hex": slack[:MAX_INLINE].hex(),
        "section_slack_truncated": len(slack) > MAX_INLINE, "warnings": warnings,
    }


@_fail_closed
def parse_dbf(data):
    """Parse a bounded classic dBASE III/IV table and fixed-width values."""
    return _parse_dbf_impl(data)


def _extract_dbt_memo(data, pointer):
    if type(pointer) is not int or pointer <= 0:
        raise S7DeepError("DBT memo pointer must be a positive integer")
    if len(data) < 512:
        raise S7DeepError("truncated DBT header")
    if data[16] != 0:
        raise S7DeepError("only dBASE IV DBT memo framing is supported")
    block_size = _u16le(data, 20) or 512
    if block_size < 512 or block_size % 512 or block_size > 65024:
        raise S7DeepError("invalid DBT block size")
    if len(data) % block_size:
        raise S7DeepError("DBT file is not a whole number of blocks")
    blocks, next_free = len(data) // block_size, _u32le(data, 0)
    if not 1 <= next_free <= blocks or pointer >= next_free:
        raise S7DeepError("DBT memo pointer is outside the used block range")
    offset = pointer * block_size
    header = _take(data, offset, 8, "DBT memo header")
    start, total = _u16le(header, 2), _u32le(header, 4)
    if (header[:4] != b"\xff\xff\x08\x00" or total < start
            or offset + total > next_free * block_size):
        raise S7DeepError("invalid dBASE IV DBT memo header")
    return _take(data, offset + start, total - start, "DBT memo payload")


def _parse_dbt_impl(data):
    data = _blob(data, label="DBT memo file")
    if len(data) < 512:
        raise S7DeepError("truncated DBT memo file")
    if data[16] != 0:
        raise S7DeepError("only dBASE IV DBT memo framing is supported")
    block_size = _u16le(data, 20) or 512
    if block_size < 512 or block_size % 512 or block_size > 65024:
        raise S7DeepError("invalid DBT block size")
    if len(data) % block_size:
        raise S7DeepError("DBT file is not a whole number of blocks")
    blocks, memos, block = len(data) // block_size, [], 1
    next_free = _u32le(data, 0)
    if not 1 <= next_free <= blocks:
        raise S7DeepError("DBT next-free block is outside the file")
    while block < next_free:
        offset = block * block_size
        if data[offset:offset + 2] != b"\xff\xff":
            block += 1
            continue
        payload = _extract_dbt_memo(data, block)
        total = _u32le(data, offset + 4)
        used_blocks = max(1, (total + block_size - 1) // block_size)
        memos.append({"block": block,
                      "payload": _region(payload, offset + _u16le(data, offset + 2))})
        if len(memos) > MAX_RECORDS:
            raise S7DeepError("DBT memo count limit exceeded")
        block += used_blocks
    return {"format": "dbase-iv-memo", "version": data[16],
            "next_free_block": next_free, "block_size": block_size,
            "block_count": blocks, "file_name": _text(data[8:16], "latin1"),
            "memos": memos}


@_fail_closed
def parse_dbt(data):
    """Inventory bounded dBASE IV DBT memo groups without executing content."""
    return _parse_dbt_impl(data)


def _mdx_expression_strings(raw):
    values = []
    for part in raw[:MAX_INLINE].split(b"\0"):
        part = part.strip(b" \0")
        if not part:
            continue
        values.append(part[:256].decode("latin1"))
        if len(values) == 8:
            break
    return values


def _parse_mdx_impl(data):
    data = _blob(data, label="MDX index")
    if len(data) < 1024:
        raise S7DeepError("truncated MDX index")
    block_size = _u16le(data, 20)
    if block_size < 512 or block_size % 512 or len(data) % block_size:
        raise S7DeepError("invalid MDX block/page size")
    entry_capacity, entry_size = data[25], data[26]
    tag_count, declared_pages = _u16le(data, 28), _u32le(data, 32)
    actual_pages = len(data) // block_size
    if entry_size != 32 or tag_count > MAX_MDX_TAGS:
        raise S7DeepError("unsupported MDX tag table geometry")
    if entry_capacity and (entry_capacity > 48 or tag_count > entry_capacity):
        raise S7DeepError("MDX tag count/capacity is invalid")
    if declared_pages != actual_pages:
        raise S7DeepError("MDX declared page count does not match file")
    table_end = 544 + tag_count * entry_size
    if table_end > block_size:
        raise S7DeepError("MDX tag directory exceeds its header block")
    tags, names = [], set()
    for index in range(tag_count):
        offset = 544 + index * entry_size
        entry = data[offset:offset + entry_size]
        page = _u32le(entry, 0)
        name = _text(entry[4:15], "ascii")
        if not name or name.casefold() in names:
            raise S7DeepError("invalid or duplicate MDX tag name")
        names.add(name.casefold())
        if not 1 <= page < actual_pages:
            raise S7DeepError("MDX tag header page is out of bounds")
        key_format, entry_type = entry[15], chr(entry[20])
        if key_format not in (0x00, 0x10) or entry_type not in "CND":
            raise S7DeepError("unsupported MDX tag key format/type")
        header_offset = page * block_size
        header = data[header_offset:header_offset + block_size]
        root_page, subtree_pages = _u32le(header, 0), _u32le(header, 4)
        if root_page and (root_page >= actual_pages or root_page == page):
            raise S7DeepError("MDX root page is out of bounds")
        if subtree_pages > actual_pages:
            raise S7DeepError("MDX subtree page count is impossible")
        key_length, max_keys = _u16le(header, 12), _u16le(header, 14)
        if key_length > 4096 or max_keys > 4096:
            raise S7DeepError("MDX key geometry exceeds bounds")
        header_type, flags = chr(header[9]), header[8]
        if header_type not in "CND":
            raise S7DeepError("unsupported MDX tag-header key type")
        strings = _mdx_expression_strings(header[24:])
        tags.append({
            "index": index, "name": name, "entry_offset": offset,
            "header_page": page, "header_offset": header_offset,
            "entry_key_format": key_format, "entry_key_type": entry_type,
            "thread": {"forward_left": entry[16], "forward_right": entry[17],
                       "backward": entry[18]},
            "root_page": root_page, "subtree_pages": subtree_pages,
            "key_format_flags": flags, "key_type": header_type,
            "key_length": key_length, "max_keys_per_page": max_keys,
            "secondary_key_type": _u16le(header, 16),
            "key_item_length": _u16le(header, 18),
            "reserved_20_22_hex": header[20:23].hex(),
            "unique_flag": header[23], "descending": bool(flags & 0x08),
            "field_or_string": bool(flags & 0x10),
            "unique": bool(flags & 0x40 or header[23]),
            "key_expression": strings[0] if strings else "",
            "for_expression": strings[1] if len(strings) > 1 else "",
            "expression_strings": strings,
            "expression_area_truncated": len(header) - 24 > MAX_INLINE,
        })
    return {
        "format": "dbase-iv-mdx", "version": data[0],
        "created": {"year": data[1], "month": data[2], "day": data[3]},
        "file_name": _text(data[4:20], "latin1"), "block_size": block_size,
        "block_size_adder": _u16le(data, 22), "production_index": bool(data[24]),
        "tag_capacity": entry_capacity, "tag_entry_size": entry_size,
        "tag_count": tag_count, "page_count": declared_pages,
        "first_free_page": _u32le(data, 36), "available_blocks": _u32le(data, 40),
        "updated": {"year": data[44], "month": data[45], "day": data[46]},
        "tags": tags,
    }


@_fail_closed
def parse_mdx(data):
    """Inventory dBASE IV MDX headers/tags; never evaluate index expressions."""
    return _parse_mdx_impl(data)


def _entry_list(entries):
    if isinstance(entries, dict):
        source = [{"path": path, "data": data} for path, data in entries.items()]
    elif isinstance(entries, (list, tuple)):
        source = list(entries)
    else:
        raise S7DeepError("project entries must be a mapping or bounded list")
    if len(source) > MAX_FILES:
        raise S7DeepError("project file-count limit exceeded")
    prepared, seen, total = [], set(), 0
    for entry in source:
        if not isinstance(entry, dict) or set(entry) != {"path", "data"}:
            raise S7DeepError("each project entry requires only path and data")
        path = entry["path"]
        if not isinstance(path, str) or not path or len(path) > 2048 or "\0" in path:
            raise S7DeepError("invalid project path")
        path = path.replace("\\", "/")
        key = path.casefold()
        if key in seen:
            raise S7DeepError("duplicate case-insensitive project path")
        seen.add(key)
        data = _blob(entry["data"], label="project file")
        total += len(data)
        if total > MAX_TOTAL:
            raise S7DeepError("project byte limit exceeded")
        prepared.append((path, data))
    return sorted(prepared, key=lambda item: item[0].casefold()), total


def _kind(path, data):
    suffix = PurePosixPath(path).suffix.casefold()
    if data[:2] == b"pp":
        return "mc7"
    if suffix == ".dbf":
        return "dbf"
    if suffix == ".dbt":
        return "dbt"
    if suffix == ".mdx":
        return "mdx"
    return "unknown"


def _row_value(row, name):
    for key, value in row["values"].items():
        if key.casefold() == name.casefold():
            return value
    return None


def _has_fields(table, required):
    names = {field["name"].casefold() for field in table["fields"]}
    return all(name.casefold() in names for name in required)


def _artifact_key(path):
    pure = PurePosixPath(path)
    return str(pure.parent).casefold(), pure.stem.casefold(), pure.suffix.casefold()


def _step7_blocks(prepared, parsed):
    raw = {path.casefold(): data for path, data in prepared}
    by_key = {_artifact_key(path): (path, result) for path, result in parsed.items()}
    blocks = []
    for path, table in parsed.items():
        if (PurePosixPath(path).name.casefold() != "baustein.dbf"
                or table.get("format") != "dbase-table"):
            continue
        directory = str(PurePosixPath(path).parent).casefold()
        baustein_dbt_key = str(PurePosixPath(path).with_suffix(".dbt")).casefold()
        baustein_dbt_data = raw.get(baustein_dbt_key)
        sub_pair = by_key.get((directory, "subblk", ".dbf"))
        if not sub_pair or sub_pair[1].get("format") != "dbase-table":
            continue
        sub_path, subtable = sub_pair
        if (not _has_fields(table, ("ID", "TYP", "NUMMER"))
                or not _has_fields(subtable, ("OBJECTID", "SUBBLKTYP"))):
            continue
        dbt_key = str(PurePosixPath(sub_path).with_suffix(".dbt")).casefold()
        dbt_data = raw.get(dbt_key)
        for row in table["records"]:
            identifier, type_code, number = (_row_value(row, name)
                                             for name in ("ID", "TYP", "NUMMER"))
            if not all(type(value) is int for value in (identifier, type_code, number)):
                continue
            block = {"id": identifier, "block_type_code": type_code,
                     "block_type": _BLOCK_TYPES.get(type_code, "unknown"),
                     "block_number": number, "deleted": row["deleted"],
                     "source_table": path, "subblocks": []}
            uda_pointer = _row_value(row, "UDA")
            if baustein_dbt_data is not None and type(uda_pointer) is int and uda_pointer > 0:
                block["uda"] = _region(_extract_dbt_memo(baustein_dbt_data, uda_pointer))
            for subrow in subtable["records"]:
                if _row_value(subrow, "OBJECTID") != identifier:
                    continue
                subtype = _row_value(subrow, "SUBBLKTYP")
                record = {"row": subrow["index"], "subblock_type": subtype,
                          "deleted": subrow["deleted"]}
                for field in ("BLKLANG", "BLKNUMBER", "BLKTOTLEN", "MC5LEN",
                              "SSBLEN", "ADDLEN", "LOCDATALEN", "PASSWORD",
                              "USERNAME", "BLOCKFNAME", "BLOCKNAME", "VERSION",
                              "CHECKSUM", "TIMESTAMP1", "TIMESTAMP2"):
                    value = _row_value(subrow, field)
                    if value is not None:
                        record[field.casefold()] = value
                if type(record.get("version")) is int:
                    version = record["version"]
                    record["version_text"] = f"{version >> 4}.{version & 0x0f}"
                record["know_how_protected"] = (subtype in {8, 12, 14}
                                                  and record.get("password") == 3)
                payloads = {}
                if dbt_data is not None:
                    for field, length_field in (("MC5CODE", "MC5LEN"),
                                                ("SSBPART", "SSBLEN"),
                                                ("ADDINFO", "ADDLEN")):
                        pointer = _row_value(subrow, field)
                        if type(pointer) is not int or pointer == 0:
                            continue
                        payload = _extract_dbt_memo(dbt_data, pointer)
                        declared = _row_value(subrow, length_field)
                        if type(declared) is int:
                            if declared < 0 or declared > len(payload):
                                raise S7DeepError(f"{field} declared length exceeds DBT memo")
                            payload = payload[:declared]
                        payloads[field] = payload
                        record[field.casefold()] = _region(payload)
                if subtype in {8, 10, 12, 13, 14, 15} and payloads.get("SSBPART"):
                    try:
                        record["interface"] = _parse_mc7_interface_impl(
                            payloads["SSBPART"],
                            payloads.get("MC5CODE") if subtype == 10 else None)
                    except S7DeepError as exc:
                        record["interface_error"] = str(exc)
                block["subblocks"].append(record)
            blocks.append(block)
    blocks.sort(key=lambda item: (item["block_type"], item["block_number"], item["id"]))
    return blocks


@_fail_closed
def inventory_project(entries):
    """Inventory supplied in-memory project files and join STEP7 block tables."""
    prepared, total = _entry_list(entries)
    artifacts, parsed = [], {}
    for path, data in prepared:
        kind = _kind(path, data)
        if kind == "mc7":
            result = parse_mc7_block(data)
        elif kind == "dbf":
            result = _parse_dbf_impl(data)
        elif kind == "dbt":
            result = _parse_dbt_impl(data)
        elif kind == "mdx":
            result = _parse_mdx_impl(data)
        else:
            result = {"format": "unrecognized", "content": _region(data)}
        parsed[path] = result
        artifacts.append({"path": path, "kind": kind, "size": len(data),
                          "analysis": result})
    associations = []
    index = {_artifact_key(path): path for path, _ in prepared}
    for path, _ in prepared:
        pure = PurePosixPath(path)
        if pure.suffix.casefold() != ".dbf":
            continue
        directory, stem, _ = _artifact_key(path)
        association = {"table": path}
        memo = index.get((directory, stem, ".dbt"))
        mdx = index.get((directory, stem, ".mdx"))
        if memo:
            association["memo"] = memo
        if mdx:
            association["index"] = mdx
        associations.append(association)
    blocks = _step7_blocks(prepared, parsed)
    online = [item["analysis"]["metadata"] for item in artifacts
              if item["kind"] == "mc7"]
    return {"format": "step7-project-inventory", "file_count": len(artifacts),
            "total_bytes": total, "artifacts": artifacts,
            "associations": associations, "online_blocks": online,
            "project_blocks": blocks}


def _read_regular(path, remaining):
    if not isinstance(path, str) or not path or "\0" in path:
        raise S7DeepError("invalid input path")
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        cap = min(MAX_ARTIFACT, remaining)
        if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
            raise S7DeepError("input is not a bounded regular file")
        with os.fdopen(fd, "rb") as stream:
            fd = None
            data = stream.read(cap + 1)
        if len(data) > cap:
            raise S7DeepError("input grew beyond byte limit")
        return data
    except S7DeepError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise S7DeepError(f"cannot read {path!r}: {exc}") from exc
    finally:
        if fd is not None:
            os.close(fd)


def _parser():
    parser = argparse.ArgumentParser(
        description="Offline deep STEP7 MC7/project inventory")
    parser.add_argument("inputs", nargs="+", help="local MC7/DBF/DBT/MDX files")
    parser.add_argument("--kind",
                        choices=("auto", "mc7", "dbf", "dbt", "mdx", "project"),
                        default="auto")
    return parser


def main(argv=None):
    try:
        if argv is not None and (not isinstance(argv, (list, tuple))
                                 or any(not isinstance(value, str) for value in argv)):
            raise S7DeepError("arguments must be a list of strings")
        args = _parser().parse_args(argv)
        total, entries = 0, []
        for path in args.inputs:
            data = _read_regular(path, MAX_TOTAL - total)
            total += len(data)
            entries.append({"path": path, "data": data})
        if args.kind == "project" or (args.kind == "auto" and len(entries) > 1):
            result = inventory_project(entries)
        else:
            if len(entries) != 1:
                raise S7DeepError("an explicit artifact kind accepts one input")
            data, path = entries[0]["data"], entries[0]["path"]
            kind = _kind(path, data) if args.kind == "auto" else args.kind
            functions = {"mc7": parse_mc7_block, "dbf": parse_dbf,
                         "dbt": parse_dbt, "mdx": parse_mdx}
            if kind not in functions:
                raise S7DeepError("could not infer artifact kind")
            result = functions[kind](data)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except S7DeepError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
