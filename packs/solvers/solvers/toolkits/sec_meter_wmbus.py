#!/usr/bin/env python3
"""Passive EN 13757 wired/Wireless M-Bus and OMS telegram reader.

The reader accepts supplied bytes only.  It validates wired checksums and
Wireless M-Bus Format A/B CRC blocks, walks ELL/AFL/TPL layers, decodes bounded
DIF/VIF records, and can decrypt security modes 5, 7, and 9 with one explicitly
supplied AES-128 key.  It never searches for a key, demodulates RF, opens a
device, or transmits traffic.  Security mode 9 is labelled EN 13757-only: it is
not a current OMS security profile.

All public parsing functions either return a result or raise only
``SecMeterWMBusError``.
"""
from __future__ import annotations

import argparse
import functools
import json
import math
import struct
import sys
from pathlib import Path
from typing import Any, Callable

try:  # PyCryptodome is already part of the solver environment.
    from Crypto.Cipher import AES
    from Crypto.Hash import CMAC
except Exception:  # pragma: no cover - dependency failure is reported on use
    AES = None
    CMAC = None


MAX_INPUT = 64 * 1024
MAX_RECORDS = 4096
MAX_EXTENSIONS = 10


class SecMeterWMBusError(ValueError):
    """Malformed, unsupported, unauthenticated, or over-budget meter input."""


# Short compatibility spelling for callers; both names designate the one
# declared exception class rather than broadening the failure contract.
WMBusError = SecMeterWMBusError


def _guard(function: Callable) -> Callable:
    """Turn every ordinary implementation failure into the declared contract."""
    @functools.wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecMeterWMBusError:
            raise
        except Exception as exc:
            raise SecMeterWMBusError(f"{function.__name__} failed: {exc}") from exc
    return wrapped


def _blob(value: Any, *, what: str = "input") -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecMeterWMBusError(f"{what} must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > MAX_INPUT:
            raise SecMeterWMBusError(f"{what} exceeds {MAX_INPUT} bytes")
        out = bytes(value)
    except (TypeError, ValueError) as exc:
        raise SecMeterWMBusError(f"invalid {what}") from exc
    if len(out) > MAX_INPUT:
        raise SecMeterWMBusError(f"{what} exceeds {MAX_INPUT} bytes")
    return out


def _aes_key(value: Any) -> bytes | None:
    if value is None:
        return None
    key = _blob(value, what="key")
    if len(key) != 16:
        raise SecMeterWMBusError("the supplied meter key must be exactly 16 bytes")
    if AES is None or CMAC is None:
        raise SecMeterWMBusError("PyCryptodome is required for meter decryption")
    return key


def _public(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items()
                if not str(key).startswith("_")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


@_guard
def crc16_en13757(data: Any) -> int:
    """EN 13757 CRC-16: poly 0x3D65, init 0, xorout 0xFFFF, no reflection."""
    raw = _blob(data)
    crc = 0
    for byte in raw:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x3D65) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc ^ 0xFFFF


def _check_crc(block: bytes, supplied: bytes) -> None:
    if len(supplied) != 2:
        raise SecMeterWMBusError("truncated Wireless M-Bus CRC")
    expected = crc16_en13757(block)
    if int.from_bytes(supplied, "big") != expected:
        raise SecMeterWMBusError("Wireless M-Bus CRC mismatch")


def _strip_format_a(raw: bytes) -> bytes:
    if not raw:
        raise SecMeterWMBusError("empty Format A telegram")
    logical_length = raw[0] + 1
    if logical_length < 11:
        raise SecMeterWMBusError("Format A telegram is shorter than its DLL")
    out = bytearray()
    cursor = 0
    remaining = logical_length
    block_size = 10
    while remaining:
        take = min(block_size, remaining)
        if cursor + take + 2 > len(raw):
            raise SecMeterWMBusError("truncated Format A block")
        block = raw[cursor:cursor + take]
        _check_crc(block, raw[cursor + take:cursor + take + 2])
        out.extend(block)
        cursor += take + 2
        remaining -= take
        block_size = 16
    if cursor != len(raw):
        raise SecMeterWMBusError("undeclared bytes follow Format A telegram")
    return bytes(out)


def _strip_format_b(raw: bytes) -> tuple[bytes, int]:
    """Validate Format B, whose L includes its one or two CRC fields."""
    if len(raw) < 13 or raw[0] + 1 != len(raw):
        raise SecMeterWMBusError("Format B wire length mismatch")
    wire_length = raw[0]
    if len(raw) <= 128:
        body = raw[:-2]
        _check_crc(body, raw[-2:])
        logical = body
    else:
        first, first_crc = raw[:126], raw[126:128]
        second, second_crc = raw[128:-2], raw[-2:]
        if not second:
            raise SecMeterWMBusError("empty second Format B block")
        _check_crc(first, first_crc)
        _check_crc(second, second_crc)
        logical = first + second
    if not 11 <= len(logical) <= 256:
        raise SecMeterWMBusError("invalid Format B logical length")
    # Normalize L for the common CRC-stripped DLL parser.
    logical = bytes([len(logical) - 1]) + logical[1:]
    return logical, wire_length


_CONTROL_NAMES = {
    0x40: "SND-NKE", 0x44: "SND-NR", 0x46: "SND-IR", 0x47: "ACC-NR",
    0x48: "ACC-DMD", 0x53: "SND-UD", 0x73: "SND-UD",
    0x5A: "REQ-UD1", 0x7A: "REQ-UD1", 0x5B: "REQ-UD2", 0x7B: "REQ-UD2",
}

_DEVICE_TYPES = {
    0x00: "other", 0x02: "electricity", 0x03: "gas", 0x04: "heat",
    0x06: "warm-water", 0x07: "water", 0x08: "heat-cost-allocator",
    0x0A: "cooling-outlet", 0x0B: "cooling-inlet", 0x0C: "heat-inlet",
    0x0D: "heat-cooling", 0x15: "hot-water", 0x16: "cold-water",
    0x17: "dual-water", 0x19: "pressure", 0x1A: "A/D-converter",
}


def _manufacturer(raw: bytes) -> tuple[int, str | None]:
    number = int.from_bytes(raw, "little") & 0x7FFF
    parts = ((number >> 10) & 31, (number >> 5) & 31, number & 31)
    code = "".join(chr(64 + part) for part in parts) if all(1 <= part <= 26 for part in parts) else None
    return number, code


def _bcd_identifier(raw: bytes) -> str:
    if len(raw) != 4:
        raise SecMeterWMBusError("meter identification must contain four bytes")
    if any((byte >> 4) > 9 or (byte & 15) > 9 for byte in raw):
        raise SecMeterWMBusError("meter identification contains invalid packed BCD")
    return "".join(f"{byte:02X}" for byte in reversed(raw))


def _address(m_raw: bytes, id_raw: bytes, version: int, device_type: int) -> dict[str, Any]:
    manufacturer_number, code = _manufacturer(m_raw)
    return {
        "manufacturer": code,
        "manufacturer_code": manufacturer_number,
        "manufacturer_raw": m_raw.hex(),
        "identification": _bcd_identifier(id_raw),
        "identification_raw": id_raw.hex(),
        "version": version,
        "device_type": device_type,
        "device_type_name": _DEVICE_TYPES.get(device_type, f"type-0x{device_type:02x}"),
        "_m": m_raw,
        "_id": id_raw,
    }


def _need(data: bytes, offset: int, size: int, what: str) -> bytes:
    if size < 0 or offset < 0 or offset + size > len(data):
        raise SecMeterWMBusError(f"truncated {what}")
    return data[offset:offset + size]


def _bcd_value(raw: bytes, *, negative: bool = False) -> int:
    digits: list[str] = []
    for byte in reversed(raw):
        high, low = byte >> 4, byte & 15
        if high > 9 or low > 9:
            raise SecMeterWMBusError("record contains invalid packed BCD")
        digits.extend((str(high), str(low)))
    value = int("".join(digits) or "0")
    return -value if negative else value


def _date_value(raw: bytes) -> dict[str, int]:
    if len(raw) < 2:
        raise SecMeterWMBusError("truncated M-Bus date")
    day = raw[0] & 0x1F
    month = raw[1] & 0x0F
    year = 2000 + ((raw[0] >> 5) & 7) + ((raw[1] >> 1) & 0x78)
    if not 1 <= day <= 31 or not 1 <= month <= 12:
        raise SecMeterWMBusError("invalid M-Bus date")
    return {"year": year, "month": month, "day": day}


def _vif_details(vif: int) -> tuple[str, int | None, str]:
    value = vif & 0x7F
    if 0x00 <= value <= 0x07:
        return "Wh", value - 3, "energy"
    if 0x08 <= value <= 0x0F:
        return "J", value - 8, "energy"
    if 0x10 <= value <= 0x17:
        return "m3", value - 0x10 - 6, "volume"
    if 0x18 <= value <= 0x1F:
        return "kg", value - 0x18 - 3, "mass"
    if 0x20 <= value <= 0x23:
        return ("s", "min", "h", "d")[value - 0x20], 0, "on-time"
    if 0x24 <= value <= 0x27:
        return ("s", "min", "h", "d")[value - 0x24], 0, "operating-time"
    if 0x28 <= value <= 0x2F:
        return "W", value - 0x28 - 3, "power"
    if 0x30 <= value <= 0x37:
        return "J/h", value - 0x30, "power"
    if 0x38 <= value <= 0x3F:
        return "m3/h", value - 0x38 - 6, "volume-flow"
    if 0x40 <= value <= 0x47:
        return "m3/min", value - 0x40 - 7, "volume-flow"
    if 0x48 <= value <= 0x4F:
        return "m3/s", value - 0x48 - 9, "volume-flow"
    if 0x50 <= value <= 0x57:
        return "kg/h", value - 0x50 - 3, "mass-flow"
    if 0x58 <= value <= 0x5B:
        return "degC", value - 0x58 - 3, "flow-temperature"
    if 0x5C <= value <= 0x5F:
        return "degC", value - 0x5C - 3, "return-temperature"
    if 0x60 <= value <= 0x63:
        return "K", value - 0x60 - 3, "temperature-difference"
    if 0x64 <= value <= 0x67:
        return "degC", value - 0x64 - 3, "external-temperature"
    if 0x68 <= value <= 0x6B:
        return "bar", value - 0x68 - 3, "pressure"
    names = {0x6C: ("date", None, "date"), 0x6D: ("date-time", None, "date-time"),
             0x6E: ("HCA", 0, "heat-cost-allocator"),
             0x78: ("counter", 0, "fabrication-number"),
             0x79: ("counter", 0, "enhanced-identification")}
    return names.get(value, (f"vif-0x{value:02x}", None, "unknown"))


def _decode_record_value(kind: int, raw: bytes, unit_kind: str,
                         variable_kind: str | None = None) -> Any:
    if variable_kind == "ascii":
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SecMeterWMBusError("invalid ASCII variable record") from exc
    if variable_kind == "bcd-positive":
        return _bcd_value(raw)
    if variable_kind == "bcd-negative":
        return _bcd_value(raw, negative=True)
    if variable_kind == "binary":
        return int.from_bytes(raw, "little")
    if kind == 0:
        return None
    if kind in (1, 2, 3, 4, 6, 7):
        value: Any = int.from_bytes(raw, "little", signed=True)
    elif kind == 5:
        value = struct.unpack("<f", raw)[0]
        if not math.isfinite(value):
            raise SecMeterWMBusError("non-finite M-Bus float")
    elif kind in (9, 10, 11, 12, 14):
        value = _bcd_value(raw)
    elif kind == 8:
        value = None
    else:
        value = raw.hex()
    if unit_kind == "date":
        return _date_value(raw)
    if unit_kind == "date-time" and len(raw) >= 4:
        date = _date_value(raw[2:4])
        minute, hour = raw[0] & 0x3F, raw[1] & 0x1F
        if minute > 59 or hour > 23:
            raise SecMeterWMBusError("invalid M-Bus date-time")
        return {**date, "hour": hour, "minute": minute}
    return value


def _parse_records(data: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    lengths = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 4, 6: 6, 7: 8,
               8: 0, 9: 1, 10: 2, 11: 3, 12: 4, 14: 6}
    while offset < len(data):
        if len(rows) >= MAX_RECORDS:
            raise SecMeterWMBusError("DIF/VIF record cap exceeded")
        start = offset
        dif = data[offset]
        offset += 1
        if dif == 0x2F:  # legal filler
            continue
        if dif in (0x0F, 0x1F):
            rows.append({"offset": start, "dif": dif,
                         "kind": "manufacturer-specific" if dif == 0x0F else "manufacturer-continuation",
                         "raw_hex": data[offset:].hex()})
            offset = len(data)
            break
        difes: list[int] = []
        current = dif
        while current & 0x80:
            if len(difes) >= MAX_EXTENSIONS:
                raise SecMeterWMBusError("too many DIF extensions")
            current = _need(data, offset, 1, "DIFE")[0]
            offset += 1
            difes.append(current)
        vif = _need(data, offset, 1, "VIF")[0]
        offset += 1
        vifes: list[int] = []
        current = vif
        while current & 0x80:
            if len(vifes) >= MAX_EXTENSIONS:
                raise SecMeterWMBusError("too many VIF extensions")
            current = _need(data, offset, 1, "VIFE")[0]
            offset += 1
            vifes.append(current)
        unit, exponent, unit_kind = _vif_details(vif)
        if (vif & 0x7F) == 0x7C:
            text_length = _need(data, offset, 1, "text VIF length")[0]
            offset += 1
            text = _need(data, offset, text_length, "text VIF")[::-1]
            offset += text_length
            try:
                unit = text.decode("ascii")
            except UnicodeDecodeError as exc:
                raise SecMeterWMBusError("invalid text VIF") from exc
            exponent, unit_kind = None, "custom"
        kind = dif & 15
        variable_kind = None
        lvar = None
        if kind == 13:
            lvar = _need(data, offset, 1, "LVAR")[0]
            offset += 1
            if lvar <= 0xBF:
                length, variable_kind = lvar, "ascii"
            elif 0xC0 <= lvar <= 0xCF:
                length, variable_kind = lvar & 15, "bcd-positive"
            elif 0xD0 <= lvar <= 0xDF:
                length, variable_kind = lvar & 15, "bcd-negative"
            elif 0xE0 <= lvar <= 0xEF:
                length, variable_kind = lvar & 15, "binary"
            else:
                raise SecMeterWMBusError("reserved LVAR encoding")
        elif kind in lengths:
            length = lengths[kind]
        else:
            raise SecMeterWMBusError(f"unsupported DIF data type 0x{kind:x}")
        raw_value = _need(data, offset, length, "DIF/VIF value")
        offset += length
        value = _decode_record_value(kind, raw_value, unit_kind, variable_kind)
        row: dict[str, Any] = {
            "offset": start, "dif": dif, "difes": difes, "vif": vif,
            "vifes": vifes, "function": ("instantaneous", "maximum", "minimum", "error")[(dif >> 4) & 3],
            "storage_number": ((dif >> 6) & 1) | sum((item & 15) << (1 + 4 * index)
                                                    for index, item in enumerate(difes)),
            "tariff": sum(((item >> 4) & 3) << (2 * index)
                          for index, item in enumerate(difes)),
            "subunit": sum(((item >> 6) & 1) << index
                           for index, item in enumerate(difes)),
            "unit": unit, "exponent": exponent, "kind": unit_kind,
            "raw_hex": raw_value.hex(), "value": value,
        }
        if lvar is not None:
            row["lvar"] = lvar
        if exponent is not None and isinstance(value, (int, float)) and not isinstance(value, bool):
            row["scaled_value"] = value * (10 ** exponent)
        rows.append(row)
    return rows


@_guard
def parse_records(data: Any) -> list[dict[str, Any]]:
    """Parse one complete, bounded sequence of EN 13757 DIF/VIF records."""
    return _parse_records(_blob(data, what="record data"))


def _parse_ell(data: bytes, offset: int, link_address: dict[str, Any]) -> tuple[dict[str, Any], int]:
    ci = data[offset]
    if ci == 0x8C:
        raw = _need(data, offset, 3, "short ELL")
        cc = raw[1]
        return {"ci": ci, "kind": "short", "communication_control": cc,
                "communication_flags": {"B": bool(cc & 0x80), "D": bool(cc & 0x40),
                                        "S": bool(cc & 0x20), "H": bool(cc & 0x10),
                                        "A": bool(cc & 0x04), "R": bool(cc & 0x02)},
                "access_number": raw[2]}, offset + 3
    raw = _need(data, offset, 11, "long ELL")
    cc = raw[1]
    receiver = _address(raw[3:5], raw[5:9], raw[9], raw[10])
    return {"ci": ci, "kind": "long", "communication_control": cc,
            "communication_flags": {"B": bool(cc & 0x80), "D": bool(cc & 0x40),
                                    "S": bool(cc & 0x20), "H": bool(cc & 0x10),
                                    "A": bool(cc & 0x04), "R": bool(cc & 0x02)},
            "access_number": raw[2], "receiver": receiver}, offset + 11


def _parse_afl(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    _need(data, offset, 4, "AFL")
    afll = data[offset + 1]
    if afll < 2:
        raise SecMeterWMBusError("AFL length cannot contain its FCL")
    end = offset + 2 + afll
    _need(data, offset, 2 + afll, "AFL")
    fcl = int.from_bytes(data[offset + 2:offset + 4], "little")
    if fcl & 0x8100:  # bit 15 and bit 8 are reserved
        raise SecMeterWMBusError("reserved AFL fragment-control bit is set")
    cursor = offset + 4
    result: dict[str, Any] = {
        "ci": 0x90, "length": afll, "fragment_control": fcl,
        "more_fragments": bool(fcl & 0x4000), "fragment_id": fcl & 0xFF,
    }
    if result["more_fragments"] and result["fragment_id"] == 0:
        raise SecMeterWMBusError("unfragmented AFL identifier has more-fragments set")
    optional_mask = 0x1000 | 0x0800 | 0x0400 | 0x0200
    if fcl & optional_mask and not fcl & 0x2000:
        raise SecMeterWMBusError("AFL optional fields require message control")
    mcl = None
    mcl_raw = b""
    counter_raw = b""
    length_raw = b""
    if fcl & 0x2000:
        mcl = _need(data, cursor, 1, "AFL MCL")[0]
        cursor += 1
        if mcl & 0x80:
            raise SecMeterWMBusError("reserved AFL message-control bit is set")
        mirrors = ((0x40, 0x1000, "message length"),
                   (0x20, 0x0800, "message counter"),
                   (0x10, 0x0200, "key information"))
        fragmented = result["fragment_id"] != 0 or result["more_fragments"]
        for mcl_bit, fcl_bit, name in mirrors:
            # MCL describes the complete message; FCL describes this fragment.
            # A fragment may therefore omit a globally-present field, but may
            # never introduce a field that MCL says the message lacks.
            if fcl & fcl_bit and not mcl & mcl_bit:
                raise SecMeterWMBusError(f"AFL {name} presence disagrees between MCL and FCL")
            if not fragmented and bool(mcl & mcl_bit) != bool(fcl & fcl_bit):
                raise SecMeterWMBusError(f"AFL {name} presence disagrees between MCL and FCL")
        if fcl & 0x0400 and not mcl & 0x0F:
            raise SecMeterWMBusError("AFL authentication type disagrees with MAC presence")
        if not fragmented and bool(mcl & 0x0F) != bool(fcl & 0x0400):
            raise SecMeterWMBusError("AFL authentication type disagrees with MAC presence")
        result["message_control"] = mcl
        result["authentication_type"] = mcl & 15
        mcl_raw = bytes([mcl])
    if fcl & 0x0200:
        key_info = _need(data, cursor, 2, "AFL key information")
        cursor += 2
        key_info_value = int.from_bytes(key_info, "little")
        if key_info_value & 0x00C0:
            raise SecMeterWMBusError("reserved AFL key-information bit is set")
        result.update(key_version=(key_info_value >> 8) & 0xFF,
                      key_derivation=(key_info_value >> 4) & 3,
                      key_id=key_info_value & 15,
                      key_information=key_info_value)
    if fcl & 0x0800:
        counter_raw = _need(data, cursor, 4, "AFL message counter")
        cursor += 4
        result["message_counter"] = int.from_bytes(counter_raw, "little")
        result["message_counter_raw"] = counter_raw.hex()
        result["_counter"] = counter_raw
    if fcl & 0x0400:
        if mcl is None:
            raise SecMeterWMBusError("AFL MAC has no MCL authentication type")
        tag_length = {5: 8, 6: 12, 7: 16}.get(mcl & 15)
        if tag_length is None:
            raise SecMeterWMBusError("unsupported AFL authentication tag type")
        tag = _need(data, cursor, tag_length, "AFL authentication tag")
        cursor += tag_length
        result["authentication_tag_hex"] = tag.hex()
        result["_tag"] = tag
    if fcl & 0x1000:
        length_raw = _need(data, cursor, 2, "AFL message length")
        cursor += 2
        result["message_length"] = int.from_bytes(length_raw, "little")
        if result["message_length"] > 16 * 1024:
            raise SecMeterWMBusError("AFL message length exceeds the OMS 16 KiB limit")
    if cursor != end:
        raise SecMeterWMBusError("AFL flags do not account for AFLL bytes")
    # OMS profile B authenticates MCL || MCR || optional ML || TPDU.  KI is
    # intentionally not part of this CMAC transcript.
    result["_oms_auth_fields"] = mcl_raw + counter_raw + length_raw
    return result, end


def _tpl_address(data: bytes, offset: int) -> tuple[dict[str, Any], int]:
    raw = _need(data, offset, 8, "long TPL address")
    return _address(raw[4:6], raw[:4], raw[6], raw[7]), offset + 8


def _parse_tpl(data: bytes, offset: int, link_address: dict[str, Any] | None) -> tuple[dict[str, Any], int]:
    ci = data[offset]
    cursor = offset + 1
    result: dict[str, Any] = {"ci": ci, "kind": "short" if ci in (0x7A, 0x5A) else "long",
                              "direction": "downlink" if ci in (0x5A, 0x5B) else "uplink",
                              "_start": offset}
    address = link_address
    if ci in (0x72, 0x5B):
        address, cursor = _tpl_address(data, cursor)
        result["address"] = address
    header = _need(data, cursor, 4, "TPL header")
    result.update(access_number=header[0], status=header[1],
                  configuration=int.from_bytes(header[2:4], "little"))
    cursor += 4
    result["security_mode"] = (result["configuration"] >> 8) & 0x1F
    result["encrypted_block_count"] = (result["configuration"] >> 4) & 15
    result["_payload"] = cursor
    result["_address"] = address
    return result, cursor


def _cmac(key: bytes, data: bytes) -> bytes:
    try:
        mac = CMAC.new(key, ciphermod=AES)
        mac.update(data)
        return mac.digest()
    except (TypeError, ValueError, KeyError) as exc:
        raise SecMeterWMBusError("AES-CMAC operation failed") from exc


def _cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 16:
        raise SecMeterWMBusError("AES-CBC ciphertext is not complete blocks")
    try:
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
    except (TypeError, ValueError, KeyError) as exc:
        raise SecMeterWMBusError("AES-CBC operation failed") from exc


def _encrypted_length(blocks: int, available: int) -> int:
    if blocks == 0:
        return 0
    if blocks == 15:
        if available == 0 or available % 16:
            raise SecMeterWMBusError("N=15 requires the entire remaining payload in complete AES blocks")
        return available
    length = blocks * 16
    if length > available:
        raise SecMeterWMBusError("TPL encrypted block count exceeds payload")
    return length


def _meter_address(tpl: dict[str, Any], link_address: dict[str, Any] | None) -> dict[str, Any]:
    address = tpl.get("_address") or link_address
    if address is None:
        raise SecMeterWMBusError("security mode requires a meter address")
    return address


def _mode5(data: bytes, tpl: dict[str, Any], link_address: dict[str, Any] | None,
           key: bytes | None) -> tuple[dict[str, Any], bytes | None]:
    payload = data[tpl["_payload"]:]
    blocks = tpl["encrypted_block_count"]
    encrypted_length = _encrypted_length(blocks, len(payload))
    security: dict[str, Any] = {"mode": 5, "profile": "OMS-A", "authenticated": False,
                                "deprecated": True, "encrypted_bytes": encrypted_length}
    if encrypted_length == 0:
        return security | {"decrypted": True}, payload
    if key is None:
        security["decrypted"] = False
        security["ciphertext_hex"] = payload[:encrypted_length].hex()
        return security, None
    address = _meter_address(tpl, link_address)
    iv = (address["_m"] + address["_id"] + bytes([address["version"], address["device_type"]])
          + bytes([tpl["access_number"]]) * 8)
    plaintext = _cbc_decrypt(key, iv, payload[:encrypted_length]) + payload[encrypted_length:]
    if not plaintext.startswith(b"\x2f\x2f"):
        raise SecMeterWMBusError("mode 5 plaintext lacks the 2F2F verification marker")
    security.update(decrypted=True, marker_verified=True, iv_hex=iv.hex())
    return security, plaintext


def _kdf_a(csk: bytes, direction_constant: int, counter: bytes, identification: bytes) -> bytes:
    if len(counter) != 4 or len(identification) != 4:
        raise SecMeterWMBusError("invalid KDF-A context")
    return _cmac(csk, bytes([direction_constant]) + counter + identification + b"\x07" * 7)


def _mode7(data: bytes, tpl: dict[str, Any], link_address: dict[str, Any] | None,
           afl: dict[str, Any] | None, key: bytes | None) -> tuple[dict[str, Any], bytes | None]:
    if afl is None or "_counter" not in afl or "_tag" not in afl:
        raise SecMeterWMBusError("OMS profile B requires AFL counter and authentication tag")
    if afl.get("authentication_type") != 5 or len(afl["_tag"]) != 8:
        raise SecMeterWMBusError("OMS profile B requires AFL authentication type 5")
    cursor = tpl["_payload"]
    cfe = _need(data, cursor, 1, "mode 7 configuration extension")[0]
    cursor += 1
    if cfe & 0x80:
        raise SecMeterWMBusError("reserved mode 7 CFE bit is set")
    key_version = None
    if cfe & 0x40:
        key_version = _need(data, cursor, 1, "mode 7 key version")[0]
        cursor += 1
    kdf = (cfe >> 4) & 3
    security: dict[str, Any] = {
        "mode": 7, "profile": "OMS-B", "authenticated": False,
        "configuration_extension": cfe, "kdf": kdf, "key_id": cfe & 15,
        "message_counter": afl["message_counter"],
    }
    if key_version is not None:
        security["key_version"] = key_version
    if kdf != 1:
        raise SecMeterWMBusError("mode 7 requires KDF-A")
    if "key_information" in afl:
        if afl["key_derivation"] != kdf or afl["key_id"] != (cfe & 15):
            raise SecMeterWMBusError("AFL key information disagrees with mode 7 CFE")
        if key_version is not None and afl["key_version"] != key_version:
            raise SecMeterWMBusError("AFL key version disagrees with mode 7 CFE")
    payload = data[cursor:]
    encrypted_length = _encrypted_length(tpl["encrypted_block_count"], len(payload))
    security["encrypted_bytes"] = encrypted_length
    tpdu = data[tpl["_start"]:]
    if "message_length" in afl:
        declared = afl["message_length"]
        if afl["fragment_id"] == 0 and not afl["more_fragments"]:
            if declared != len(tpdu):
                raise SecMeterWMBusError("AFL message length disagrees with unfragmented TPDU")
        elif declared < len(tpdu):
            raise SecMeterWMBusError("AFL message length is shorter than this TPDU fragment")
    if key is None:
        security.update(decrypted=False, ciphertext_hex=payload[:encrypted_length].hex())
        return security, None
    address = _meter_address(tpl, link_address)
    direction = 0x10 if tpl["direction"] == "downlink" else 0x00
    enc_key = _kdf_a(key, direction, afl["_counter"], address["_id"])
    mac_key = _kdf_a(key, direction + 1, afl["_counter"], address["_id"])
    authenticated = afl["_oms_auth_fields"] + tpdu
    expected = _cmac(mac_key, authenticated)[:len(afl["_tag"])]
    if expected != afl["_tag"]:
        raise SecMeterWMBusError("mode 7 AFL authentication tag mismatch")
    if encrypted_length == 0:
        if tpl["configuration"] & 0x0008:
            raise SecMeterWMBusError("mode 7 declares padding without encrypted blocks")
        security.update(authenticated=True, decrypted=True,
                        authentication_tag_hex=afl["_tag"].hex())
        return security, payload
    decrypted = _cbc_decrypt(enc_key, bytes(16), payload[:encrypted_length])
    if tpl["configuration"] & 0x0008:
        padding_length = decrypted[-1] if decrypted else 0
        if not 1 <= padding_length <= 16 or decrypted[-padding_length:] != bytes([padding_length]) * padding_length:
            raise SecMeterWMBusError("mode 7 TPL padding is invalid")
        decrypted = decrypted[:-padding_length]
        security["padding_removed"] = padding_length
    plaintext = decrypted + payload[encrypted_length:]
    if not plaintext.startswith(b"\x2f\x2f"):
        raise SecMeterWMBusError("mode 7 plaintext lacks the 2F2F verification marker")
    security.update(authenticated=True, decrypted=True, marker_verified=True,
                    authentication_tag_hex=afl["_tag"].hex())
    return security, plaintext


def _mode9(data: bytes, tpl: dict[str, Any], link_address: dict[str, Any] | None,
           key: bytes | None) -> tuple[dict[str, Any], bytes | None]:
    cf = tpl["configuration"]
    if cf & 0x8000:
        raise SecMeterWMBusError("reserved mode 9 configuration bit is set")
    cursor = tpl["_payload"]
    key_version = None
    optional = bytearray()
    if cf & 0x4000:
        key_version = _need(data, cursor, 1, "mode 9 key version")[0]
        optional.append(key_version)
        cursor += 1
    e_width, u_width = (2 if cf & 0x0040 else 1), (2 if cf & 0x0080 else 1)
    e_raw = _need(data, cursor, e_width, "mode 9 encrypted length")
    cursor += e_width
    u_raw = _need(data, cursor, u_width, "mode 9 unencrypted length")
    cursor += u_width
    optional.extend(e_raw)
    optional.extend(u_raw)
    encrypted_length, clear_length = int.from_bytes(e_raw, "little"), int.from_bytes(u_raw, "little")
    counter_raw = _need(data, cursor, 4, "mode 9 message counter")
    cursor += 4
    tag_length = 12 if cf & 0x2000 else 0
    required = encrypted_length + clear_length + tag_length
    body = _need(data, cursor, required, "mode 9 protected body")
    if cursor + required != len(data):
        raise SecMeterWMBusError("mode 9 lengths leave undeclared bytes")
    ciphertext = body[:encrypted_length]
    clear = body[encrypted_length:encrypted_length + clear_length]
    tag = body[-tag_length:] if tag_length else b""
    kdf = (cf >> 4) & 3
    security: dict[str, Any] = {
        "mode": 9, "profile": None, "standard_scope": "EN-13757-7",
        "authenticated": False, "kdf": kdf, "key_id": cf & 15,
        "message_counter": int.from_bytes(counter_raw, "little"),
        "encrypted_length": encrypted_length, "unencrypted_length": clear_length,
        "tag_present": bool(tag),
    }
    if key_version is not None:
        security["key_version"] = key_version
    if key is None:
        security.update(decrypted=False, ciphertext_hex=ciphertext.hex(),
                        unencrypted_hex=clear.hex())
        return security, None
    if not tag:
        security.update(decrypted=False, reason="mode 9 has no authentication tag")
        return security, None
    address = _meter_address(tpl, link_address)
    direction = 0x10 if tpl["direction"] == "downlink" else 0x00
    if kdf == 1:
        enc_key = _kdf_a(key, direction, counter_raw, address["_id"])
    elif kdf == 0:
        enc_key = key
    else:
        raise SecMeterWMBusError("unsupported mode 9 KDF selector")
    nonce = (address["_m"] + address["_id"] + bytes([address["version"], address["device_type"]])
             + int.from_bytes(counter_raw, "little").to_bytes(4, "big"))
    fixed_aad = (bytes([tpl["ci"], tpl["access_number"], tpl["status"]])
                 + cf.to_bytes(2, "little"))
    aad = fixed_aad + bytes(optional) + clear
    try:
        cipher = AES.new(enc_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        cipher.update(aad)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except (TypeError, ValueError, KeyError) as exc:
        raise SecMeterWMBusError("mode 9 AES-GCM authentication failed") from exc
    security.update(authenticated=True, decrypted=True, nonce_hex=nonce.hex(),
                    aad_hex=aad.hex(), authentication_tag_hex=tag.hex())
    return security, plaintext + clear


def _mode10_metadata(data: bytes, tpl: dict[str, Any]) -> dict[str, Any]:
    """Validate the mandatory OMS-D CFE/counter/tag envelope without decrypting it."""
    cf = tpl["configuration"]
    if not cf & 0x2000:
        raise SecMeterWMBusError("OMS mode 10 requires its four-byte TPL message counter")
    cursor = tpl["_payload"]
    cfe_raw = _need(data, cursor, 2, "mode 10 configuration extension")
    cursor += 2
    cfe = int.from_bytes(cfe_raw, "little")
    if cfe & 0xC080:
        raise SecMeterWMBusError("reserved mode 10 CFE bit is set")
    authentication_size = (cfe >> 8) & 3
    kdf = (cfe >> 4) & 3
    if authentication_size != 1 or kdf != 1:
        raise SecMeterWMBusError("OMS mode 10 requires KDF-A and an eight-byte tag")
    key_version = None
    if cfe & 0x0040:
        key_version = _need(data, cursor, 1, "mode 10 key version")[0]
        cursor += 1
    counter_raw = _need(data, cursor, 4, "mode 10 message counter")
    cursor += 4
    protected = data[cursor:]
    if len(protected) < 8:
        raise SecMeterWMBusError("mode 10 is missing its authentication tag")
    declared = cf & 0xFF
    encrypted_length = len(protected) - 8 if declared == 0xFF else declared
    if encrypted_length > len(protected) - 8:
        raise SecMeterWMBusError("mode 10 encrypted-byte count exceeds payload")
    clear_length = len(protected) - 8 - encrypted_length
    result: dict[str, Any] = {
        "mode": 10, "profile": "OMS-D", "algorithm": "AES-CCM",
        "authenticated": False, "decryption_supported": False,
        "configuration_extension": cfe, "content_index": (cfe >> 10) & 15,
        "authentication_tag_size": 8, "kdf": kdf, "key_id": cfe & 15,
        "message_counter": int.from_bytes(counter_raw, "little"),
        "encrypted_length": encrypted_length, "unencrypted_length": clear_length,
        "authentication_tag_hex": protected[-8:].hex(),
    }
    if key_version is not None:
        result["key_version"] = key_version
    return result


def _mode13_metadata(data: bytes, tpl: dict[str, Any]) -> dict[str, Any]:
    """Validate the mandatory OMS-C protocol selector and TLS record header."""
    cf = tpl["configuration"]
    if cf & 0x2000 or (cf & 0xFF) != 0xFF:
        raise SecMeterWMBusError("OMS mode 13 requires reserved Z=0 and N=0xFF")
    cursor = tpl["_payload"]
    cfe = _need(data, cursor, 1, "mode 13 configuration extension")[0]
    cursor += 1
    if cfe & 0xF0 or (cfe & 15) not in (0, 1):
        raise SecMeterWMBusError("invalid mode 13 protocol type or reserved CFE bits")
    protocol_type = cfe & 15
    body = data[cursor:]
    result: dict[str, Any] = {
        "mode": 13, "profile": "OMS-C", "algorithm": "TLS-1.2",
        "authenticated": False, "decryption_supported": False,
        "configuration_extension": cfe, "protocol_type": protocol_type,
        "protocol_name": "TLSCHAN" if protocol_type == 0 else "TLSPROT",
    }
    if protocol_type == 1:
        header = _need(body, 0, 5, "TLS record header")
        content_type = header[0]
        if content_type not in (0x14, 0x15, 0x16, 0x17) or header[1:3] != b"\x03\x03":
            raise SecMeterWMBusError("mode 13 does not contain an OMS TLS 1.2 record header")
        record_length = int.from_bytes(header[3:5], "big")
        if len(body) != 5 + record_length:
            raise SecMeterWMBusError("mode 13 TLS record length mismatch")
        result.update(tls_content_type=content_type, tls_version="1.2",
                      tls_record_length=record_length)
    else:
        if not body or body[0] != 0:
            raise SecMeterWMBusError("mode 13 TLSCHAN header is missing")
        result["channel_request_hex"] = body.hex()
    return result


def _parse_chain(data: bytes, offset: int, link_address: dict[str, Any] | None,
                 key: bytes | None) -> dict[str, Any]:
    if offset >= len(data):
        raise SecMeterWMBusError("telegram has no CI/application layer")
    out: dict[str, Any] = {"layers": []}
    if data[offset] in (0x8C, 0x8E):
        if link_address is None:
            raise SecMeterWMBusError("ELL requires a wireless link address")
        ell, offset = _parse_ell(data, offset, link_address)
        out["ell"] = ell
        out["layers"].append("ELL")
    afl = None
    if offset < len(data) and data[offset] == 0x90:
        afl, offset = _parse_afl(data, offset)
        out["afl"] = afl
        out["layers"].append("AFL")
    if offset >= len(data):
        raise SecMeterWMBusError("layer chain ends before TPL/application data")
    ci = data[offset]
    if ci == 0x78:  # no TPL header; raw application records follow CI
        application = data[offset + 1:]
        out.update(application_ci=ci, application_hex=application.hex(),
                   records=_parse_records(application), security={"mode": 0, "authenticated": False})
        out["layers"].append("APL")
        return out
    if ci not in (0x72, 0x7A, 0x5A, 0x5B):
        out.update(application_ci=ci, application_hex=data[offset + 1:].hex(),
                   records=[], security={"mode": None, "authenticated": False})
        out["layers"].append("unknown-CI")
        return out
    tpl, _ = _parse_tpl(data, offset, link_address)
    out["tpl"] = tpl
    out["layers"].append("TPL")
    mode = tpl["security_mode"]
    application: bytes | None
    if mode == 0:
        application = data[tpl["_payload"]:]
        security = {"mode": 0, "profile": "none", "authenticated": False,
                    "decrypted": True}
    elif mode == 5:
        security, application = _mode5(data, tpl, link_address, key)
    elif mode == 7:
        security, application = _mode7(data, tpl, link_address, afl, key)
    elif mode == 9:
        security, application = _mode9(data, tpl, link_address, key)
    elif mode == 10:
        security, application = _mode10_metadata(data, tpl), None
    elif mode == 13:
        security, application = _mode13_metadata(data, tpl), None
    else:
        security, application = ({"mode": mode, "profile": None, "authenticated": False,
                                  "decryption_supported": False}, None)
    out["security"] = security
    if application is not None:
        out["application_hex"] = application.hex()
        out["records"] = _parse_records(application)
        out["layers"].append("APL")
    else:
        out["records"] = []
    return out


@_guard
def parse_wired(data: Any, *, key: Any = None) -> dict[str, Any]:
    """Parse one complete wired M-Bus ACK, short, or long/control frame."""
    raw = _blob(data)
    aes_key = _aes_key(key)
    if raw == b"\xE5":
        return {"protocol": "m-bus", "frame_type": "ack", "raw_hex": "e5"}
    if not raw:
        raise SecMeterWMBusError("empty wired M-Bus frame")
    if raw[0] == 0x10:
        if len(raw) != 5 or raw[-1] != 0x16:
            raise SecMeterWMBusError("invalid wired M-Bus short frame length/stop")
        control, address, checksum = raw[1], raw[2], raw[3]
        if ((control + address) & 0xFF) != checksum:
            raise SecMeterWMBusError("wired M-Bus short checksum mismatch")
        return {"protocol": "m-bus", "frame_type": "short", "control": control,
                "control_name": _CONTROL_NAMES.get(control), "address": address,
                "checksum": checksum, "checksum_valid": True}
    if raw[0] != 0x68 or len(raw) < 9:
        raise SecMeterWMBusError("not a wired M-Bus frame")
    length = raw[1]
    if raw[2] != length or raw[3] != 0x68 or len(raw) != length + 6 or raw[-1] != 0x16:
        raise SecMeterWMBusError("invalid wired M-Bus long frame envelope")
    body = raw[4:4 + length]
    if (sum(body) & 0xFF) != raw[-2]:
        raise SecMeterWMBusError("wired M-Bus long checksum mismatch")
    if length < 3:
        raise SecMeterWMBusError("wired M-Bus long body lacks C/A/CI")
    result: dict[str, Any] = {
        "protocol": "m-bus", "frame_type": "long", "length": length,
        "control": body[0], "control_name": _CONTROL_NAMES.get(body[0]),
        "address": body[1], "primary_address": body[1],
        "checksum": raw[-2], "checksum_valid": True,
        "ci": body[2], "data_hex": body[3:].hex(),
    }
    result.update(_parse_chain(body, 2, None, aes_key))
    return _public(result)


@_guard
def parse_wmbus(data: Any, *, framing: str = "auto", key: Any = None,
                radio_mode: str | None = None) -> dict[str, Any]:
    """Parse one complete supplied Wireless M-Bus telegram.

    ``framing`` is ``stripped`` (L through application, no CRC), ``format-a``,
    ``format-b``, or strict ``auto``.  ``radio_mode`` is optional capture
    metadata (S/T/C/N); it is never inferred from bytes.
    """
    raw = _blob(data)
    aes_key = _aes_key(key)
    framing = str(framing).lower()
    if framing not in ("auto", "stripped", "format-a", "format-b"):
        raise SecMeterWMBusError("framing must be auto, stripped, format-a, or format-b")
    if radio_mode is not None:
        radio_mode = str(radio_mode).upper()
        if radio_mode not in ("S", "T", "C", "N"):
            raise SecMeterWMBusError("radio mode metadata must be S, T, C, or N")
    wire_length = None
    if framing == "stripped":
        logical, used = raw, "stripped"
    elif framing == "format-a":
        logical, used = _strip_format_a(raw), "format-a"
    elif framing == "format-b":
        logical, wire_length = _strip_format_b(raw)
        used = "format-b"
    elif raw and raw[0] + 1 == len(raw):
        # Format B deliberately counts its CRC bytes in L, so it has the same
        # outer length relation as a CRC-stripped telegram.  Give a valid B CRC
        # the first claim; only a CRC failure permits the stripped reading.
        try:
            logical, wire_length = _strip_format_b(raw)
            used = "format-b"
        except SecMeterWMBusError:
            logical, used = raw, "stripped"
    else:
        try:
            logical, used = _strip_format_a(raw), "format-a"
        except SecMeterWMBusError as first:
            try:
                logical, wire_length = _strip_format_b(raw)
                used = "format-b"
            except SecMeterWMBusError as second:
                raise SecMeterWMBusError(f"telegram is neither Format A nor Format B: {first}; {second}") from second
    if len(logical) < 11 or logical[0] + 1 != len(logical):
        raise SecMeterWMBusError("Wireless M-Bus DLL length mismatch")
    control = logical[1]
    address = _address(logical[2:4], logical[4:8], logical[8], logical[9])
    dll: dict[str, Any] = {
        "length": logical[0], "control": control,
        "control_name": _CONTROL_NAMES.get(control), "ci": logical[10], **address,
    }
    result: dict[str, Any] = {
        "protocol": "wireless-m-bus", "framing": used, "dll": dll,
        "raw_logical_hex": logical.hex(),
    }
    if wire_length is not None:
        result["wire_length_field"] = wire_length
    if radio_mode is not None:
        result["radio_mode"] = radio_mode
        result["radio_mode_source"] = "supplied-metadata"
    result.update(_parse_chain(logical, 10, address, aes_key))
    return _public(result)


@_guard
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="local telegram file")
    parser.add_argument("--kind", choices=("wmbus", "wired"), default="wmbus")
    parser.add_argument("--framing", choices=("auto", "stripped", "format-a", "format-b"), default="auto")
    parser.add_argument("--radio-mode", choices=("S", "T", "C", "N"))
    parser.add_argument("--key", help="explicit AES-128 key as 32 hexadecimal digits")
    parser.add_argument("--hex", action="store_true", help="input file contains hexadecimal text")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        path = Path(args.input)
        if not path.is_file() or path.stat().st_size > MAX_INPUT:
            raise SecMeterWMBusError("input is absent or exceeds the file cap")
        with path.open("rb") as source:
            raw = source.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise SecMeterWMBusError("input exceeds the file cap")
        if args.hex:
            try:
                raw = bytes.fromhex(raw.decode("ascii"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise SecMeterWMBusError("input is not hexadecimal ASCII") from exc
        try:
            key = bytes.fromhex(args.key) if args.key is not None else None
        except ValueError as exc:
            raise SecMeterWMBusError("key is not hexadecimal") from exc
        result = (parse_wired(raw, key=key) if args.kind == "wired" else
                  parse_wmbus(raw, framing=args.framing, key=key, radio_mode=args.radio_mode))
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0
    except (SecMeterWMBusError, OSError) as exc:
        print(f"sec_meter_wmbus: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
