#!/usr/bin/env python3
"""Passive ANSI C12.18/C12.19/C12.22 smart-meter artifact reader.

The module accepts supplied bytes only.  It validates C12.18 link framing and
CRC, decodes common PSEM services and C12.19 tables 0/1, and parses the
documented C12.22 ACSE/EPSEM envelope used on native TCP/UDP port 1153.  It
does not open sockets, discover meters, brute-force credentials, or decrypt
traffic.  Authenticated data is explicitly reported as unverified unless an
external verifier has already established its integrity.

Wire references: ANSI C12.18-2006 (R2023), ANSI C12.19-2021, ANSI
C12.22-2012/2026 core ASN.1, IEEE 1703, and RFC 6142.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import functools
import json
from pathlib import Path
import sys


MAX_INPUT = 2 * 1024 * 1024
MAX_SERVICE = 65535
MAX_SERVICES = 256
MAX_BER_DEPTH = 16
MAX_BER_NODES = 4096
C1222_PORT = 1153


class SecMeterC12Error(ValueError):
    """Malformed, unsupported, or over-limit ANSI C12 artifact."""


def _closed(function):
    """Normalize all ordinary parser failures to the declared exception."""

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecMeterC12Error:
            raise
        except Exception as exc:
            raise SecMeterC12Error(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from None

    return wrapper


def _blob(value, label="input", maximum=MAX_INPUT):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecMeterC12Error(f"{label} must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > maximum:
            raise SecMeterC12Error(f"{label} exceeds {maximum} bytes")
        raw = bytes(value)
    except (BufferError, TypeError, ValueError) as exc:
        raise SecMeterC12Error(f"invalid {label}") from exc
    if len(raw) > maximum:
        raise SecMeterC12Error(f"{label} exceeds {maximum} bytes")
    return raw


class _Reader:
    def __init__(self, data, label="input"):
        self.data = _blob(data, label)
        self.at = 0

    @property
    def remaining(self):
        return len(self.data) - self.at

    def take(self, size, label="field"):
        if type(size) is not int or size < 0 or size > self.remaining:
            raise SecMeterC12Error(f"truncated {label}")
        out = self.data[self.at:self.at + size]
        self.at += size
        return out

    def uint(self, size=1, label="integer"):
        return int.from_bytes(self.take(size, label), "big")

    def end(self):
        if self.remaining:
            raise SecMeterC12Error("undeclared trailing bytes")


def _crc16_c1218(raw):
    # Reflected x^16+x^12+x^5+1, init/xorout FFFF (CRC-16/IBM-SDLC).
    value = 0xFFFF
    for octet in raw:
        value ^= octet
        for _ in range(8):
            value = (value >> 1) ^ 0x8408 if value & 1 else value >> 1
    return value ^ 0xFFFF


@_closed
def crc16_c1218(data):
    """Return the ANSI C12.18 CRC as a 16-bit integer.

    On the wire the low byte is transmitted first.  For the published
    ``EE000000000120`` identification request this returns ``0x1013``.
    """

    return _crc16_c1218(_blob(data, "CRC input"))


def _table_id(value):
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise SecMeterC12Error("table identifier must be a 16-bit integer")
    if value & 0xC000:
        raise SecMeterC12Error("reserved table identifier flags are set")
    number = value & 0x07FF
    manufacturer = bool(value & 0x0800)
    pending = bool(value & 0x1000)
    user_defined = bool(value & 0x2000)
    if manufacturer and user_defined:
        raise SecMeterC12Error("table cannot be both manufacturer and user-defined")
    kind = "user_defined" if user_defined else "manufacturer" if manufacturer else "standard"
    prefix = ("PUDT" if pending and user_defined else
              "UDT" if user_defined else
              "PMT" if pending and manufacturer else
              "PST" if pending else "MT" if manufacturer else "ST")
    return {
        "raw": value,
        "number": number,
        "manufacturer": manufacturer,
        "user_defined": user_defined,
        "pending": pending,
        "kind": kind,
        "label": prefix + str(number),
    }


@_closed
def decode_table_id(value):
    """Decode the C12 PSEM table number and manufacturer/pending flags."""

    return _table_id(value)


_PSEM_NAMES = {
    0x20: "identify",
    0x21: "terminate",
    0x22: "disconnect",
    0x30: "full_read",
    0x3E: "default_read",
    0x3F: "partial_read",
    0x40: "full_write",
    0x4E: "default_write",
    0x4F: "partial_write",
    0x50: "logon",
    0x51: "security",
    0x52: "logoff",
    0x53: "authenticate",
    0x70: "wait",
    0x71: "timing_setup",
}


def _psem_name(command):
    if 0x60 <= command <= 0x6B:
        return "negotiate"
    return _PSEM_NAMES.get(command)


def _fixed_text(raw):
    # C12 character format is selected by ST0.  ASCII is the common format;
    # latin-1 preserves every supplied octet without a decoding failure.
    return raw.decode("latin-1").rstrip("\x00 ")


def _checksum(data, checksum):
    if (sum(data) + checksum) & 0xFF:
        raise SecMeterC12Error("invalid PSEM two's-complement checksum")


def _write_body(reader, partial=False, default=False):
    out = {}
    if not default:
        out["table"] = _table_id(reader.uint(2, "table identifier"))
    if partial:
        out["offset"] = reader.uint(3, "table offset")
    count = reader.uint(2, "write count")
    if count > MAX_SERVICE:
        raise SecMeterC12Error("write count exceeds limit")
    data = reader.take(count, "write data")
    checksum = reader.uint(1, "write checksum")
    reader.end()
    _checksum(data, checksum)
    out.update(count=count, data_hex=data.hex(), checksum=checksum,
               checksum_valid=True)
    return out


def _parse_psem_request(raw):
    reader = _Reader(raw, "PSEM request")
    command = reader.uint(1, "PSEM command")
    service = _psem_name(command)
    if service is None:
        raise SecMeterC12Error(f"unsupported PSEM command 0x{command:02x}")
    out = {"protocol": "psem", "direction": "request",
           "command": command, "service": service}

    if command in (0x20, 0x21, 0x22, 0x3E, 0x52):
        reader.end()
    elif command == 0x30:
        out["table"] = _table_id(reader.uint(2, "table identifier"))
        reader.end()
    elif command == 0x3F:
        out["table"] = _table_id(reader.uint(2, "table identifier"))
        out["offset"] = reader.uint(3, "table offset")
        out["count"] = reader.uint(2, "read count")
        reader.end()
    elif command == 0x40:
        out.update(_write_body(reader))
    elif command == 0x4E:
        # Default write omits a table ID but retains count/data/checksum.
        out.update(_write_body(reader, default=True))
    elif command == 0x4F:
        out.update(_write_body(reader, partial=True))
    elif command == 0x50:
        if reader.remaining not in (12, 14):
            raise SecMeterC12Error("logon must contain user ID, 10-byte user, and optional timeout")
        out["user_id"] = reader.uint(2, "user identifier")
        user = reader.take(10, "user name")
        out.update(user=_fixed_text(user), user_hex=user.hex())
        if reader.remaining:
            out["session_idle_timeout"] = reader.uint(2, "session idle timeout")
        reader.end()
    elif command == 0x51:
        if reader.remaining not in (20, 22):
            raise SecMeterC12Error("security must contain a 20-byte password and optional user ID")
        password = reader.take(20, "password")
        out.update(password=_fixed_text(password), password_hex=password.hex())
        if reader.remaining:
            out["user_id"] = reader.uint(2, "user identifier")
        reader.end()
    elif command == 0x53:
        count = reader.uint(1, "authentication length")
        value = reader.take(count, "authentication data")
        reader.end()
        out.update(authentication_length=count, authentication_hex=value.hex())
    elif 0x60 <= command <= 0x6B:
        baud_count = command & 0x0F
        if reader.remaining != 3 + baud_count:
            raise SecMeterC12Error("negotiate baud-count does not match command")
        out.update(packet_size=reader.uint(2, "packet size"),
                   maximum_packets=reader.uint(1, "maximum packets"),
                   baud_indices=list(reader.take(baud_count, "baud indices")))
        reader.end()
    elif command == 0x70:
        out["seconds"] = reader.uint(1, "wait interval")
        reader.end()
    elif command == 0x71:
        if reader.remaining != 4:
            raise SecMeterC12Error("timing setup requires four timing octets")
        values = list(reader.take(4, "timing parameters"))
        out["timing_parameters"] = values
        reader.end()
    else:  # pragma: no cover - exhaustive map above
        raise SecMeterC12Error("unsupported PSEM request")
    return out


@_closed
def parse_psem_request(data):
    """Parse one complete C12 PSEM request and validate data checksums."""

    return _parse_psem_request(_blob(data, "PSEM request", MAX_SERVICE + 16))


_PSEM_STATUS = {
    0x00: "ok",
    0x01: "error",
    0x02: "service_not_supported",
    0x03: "insufficient_security_clearance",
    0x04: "operation_not_possible",
    0x05: "inappropriate_action_requested",
    0x06: "device_busy",
    0x07: "data_not_ready",
    0x08: "data_locked",
    0x09: "renegotiate_request",
    0x0A: "invalid_service_sequence_state",
    0x0B: "security_mechanism_error",
    0x0C: "unknown_application_title",
    0x0D: "network_timeout",
    0x0E: "node_not_reachable",
    0x0F: "request_too_large",
    0x10: "response_too_large",
    0x11: "segmentation_not_possible",
    0x12: "segmentation_error",
}


def _parse_psem_response(raw, request_command):
    if type(request_command) is not int or _psem_name(request_command) is None:
        raise SecMeterC12Error("a supported request command is required for a response")
    reader = _Reader(raw, "PSEM response")
    status = reader.uint(1, "PSEM status")
    out = {"protocol": "psem", "direction": "response",
           "request_command": request_command,
           "request_service": _psem_name(request_command),
           "status": status,
           "status_name": _PSEM_STATUS.get(status, "reserved_or_vendor")}
    if status:
        # Error replies contain only their response code.  This prevents an
        # error payload from being presented as successful table data.
        reader.end()
        return out
    if request_command in (0x30, 0x3E, 0x3F):
        count = reader.uint(2, "read count")
        if count > MAX_SERVICE:
            raise SecMeterC12Error("read count exceeds limit")
        value = reader.take(count, "read data")
        checksum = reader.uint(1, "read checksum")
        reader.end()
        _checksum(value, checksum)
        out.update(count=count, data_hex=value.hex(), checksum=checksum,
                   checksum_valid=True)
    else:
        # Identify/negotiate responses are implementation/version dependent;
        # retain their bounded bytes without assigning unverified semantics.
        value = reader.take(reader.remaining, "response data")
        out["data_hex"] = value.hex()
    return out


@_closed
def parse_psem_response(data, request_command):
    """Parse a PSEM response using the corresponding request command."""

    return _parse_psem_response(
        _blob(data, "PSEM response", MAX_SERVICE + 4), request_command
    )


def _bitmap(raw):
    return {"hex": raw.hex(),
            "set_indices": [8 * index + bit
                            for index, octet in enumerate(raw)
                            for bit in range(8) if octet & (1 << bit)]}


def _parse_st0(raw):
    if len(raw) < 19:
        raise SecMeterC12Error("C12.19 ST0 is shorter than its fixed header")
    dim_std, dim_mfg = raw[13], raw[14]
    dim_std_proc, dim_mfg_proc = raw[15], raw[16]
    expected = 19 + 2 * dim_std + 2 * dim_mfg + dim_std_proc + dim_mfg_proc
    if len(raw) != expected:
        raise SecMeterC12Error(
            f"C12.19 ST0 bitmap dimensions require {expected} bytes, got {len(raw)}"
        )
    fc1, fc2, fc3 = raw[:3]
    out = {
        "protocol": "c12.19", "table": "ST0", "length": len(raw),
        "format_control_1": fc1,
        "data_order": "most_significant_byte_first" if fc1 & 1 else "least_significant_byte_first",
        "character_format": (fc1 >> 1) & 0x07,
        "model_select": (fc1 >> 4) & 0x07,
        "format_control_1_reserved": bool(fc1 & 0x80),
        "format_control_2": fc2,
        "time_format": fc2 & 0x07,
        "data_access_method": (fc2 >> 3) & 0x03,
        "id_form": "bcd" if fc2 & 0x20 else "string",
        "integer_format": (fc2 >> 6) & 0x03,
        "format_control_3": fc3,
        "noninteger_format_1": fc3 & 0x0F,
        "noninteger_format_2": (fc3 >> 4) & 0x0F,
        "device_class_hex": raw[3:7].hex(),
        "nameplate_type": raw[7],
        "default_set_used": raw[8],
        "max_procedure_parameter_length": raw[9],
        "max_response_data_length": raw[10],
        "standard_version": raw[11],
        "standard_revision": raw[12],
        "dimensions": {
            "standard_tables": dim_std,
            "manufacturer_tables": dim_mfg,
            "standard_procedures": dim_std_proc,
            "manufacturer_procedures": dim_mfg_proc,
            "manufacturer_status": raw[17],
        },
        "pending_count": raw[18],
    }
    at = 19
    fields = (
        ("standard_tables_used", dim_std),
        ("manufacturer_tables_used", dim_mfg),
        ("standard_procedures_used", dim_std_proc),
        ("manufacturer_procedures_used", dim_mfg_proc),
        ("standard_tables_writable", dim_std),
        ("manufacturer_tables_writable", dim_mfg),
    )
    bitmaps = {}
    for name, size in fields:
        bitmaps[name] = _bitmap(raw[at:at + size])
        at += size
    out["bitmaps"] = bitmaps
    return out


@_closed
def parse_c1219_st0(data):
    """Decode the exact fixed header and dimensioned bitmaps of C12.19 ST0."""

    return _parse_st0(_blob(data, "C12.19 ST0", MAX_SERVICE))


def _bcd(raw):
    digits = []
    for octet in raw:
        high, low = octet >> 4, octet & 0x0F
        if high > 9 or low > 9:
            raise SecMeterC12Error("invalid BCD manufacturer serial number")
        digits.extend((str(high), str(low)))
    return "".join(digits)


def _parse_st1(raw, id_form=False):
    if type(id_form) is not bool:
        raise SecMeterC12Error("id_form must be boolean")
    expected = 20 if id_form else 32
    if len(raw) != expected:
        raise SecMeterC12Error(f"C12.19 ST1 requires exactly {expected} bytes")
    out = {
        "protocol": "c12.19", "table": "ST1", "length": len(raw),
        "manufacturer": _fixed_text(raw[0:4]),
        "model": _fixed_text(raw[4:12]),
        "hardware_version_number": raw[12],
        "hardware_revision_number": raw[13],
        "firmware_version_number": raw[14],
        "firmware_revision_number": raw[15],
        "hardware_version": f"{raw[12]}.{raw[13]}",
        "firmware_version": f"{raw[14]}.{raw[15]}",
        "serial_format": "bcd" if id_form else "string",
        "serial_number": _bcd(raw[16:20]) if id_form else _fixed_text(raw[16:32]),
    }
    return out


@_closed
def parse_c1219_st1(data, id_form=False):
    """Decode C12.19 ST1 manufacturer/model/version/serial fields."""

    return _parse_st1(_blob(data, "C12.19 ST1", 32), id_form)


@_closed
def parse_c1219_table(table_id, data, *, id_form=False):
    """Dispatch standard table 0 or 1 after decoding PSEM table flags."""

    table = _table_id(table_id)
    if table["manufacturer"] or table["user_defined"] or table["pending"]:
        raise SecMeterC12Error("ST0/ST1 decoder requires a current standard table")
    raw = _blob(data, "C12.19 table", MAX_SERVICE)
    if table["number"] == 0:
        parsed = _parse_st0(raw)
    elif table["number"] == 1:
        parsed = _parse_st1(raw, id_form)
    else:
        raise SecMeterC12Error("only C12.19 ST0 and ST1 are supported")
    parsed["table_id"] = table
    return parsed


@dataclass(frozen=True)
class _BERNode:
    cls: int
    constructed: bool
    number: int
    content: bytes
    children: tuple
    encoded: bytes


def _ber_identifier(data, at, end):
    if at >= end:
        raise SecMeterC12Error("truncated BER identifier")
    first = data[at]
    at += 1
    cls, constructed, number = first >> 6, bool(first & 0x20), first & 0x1F
    if number != 0x1F:
        return cls, constructed, number, at
    number = 0
    count = 0
    while True:
        if at >= end or count >= 4:
            raise SecMeterC12Error("truncated or excessive BER high tag")
        octet = data[at]
        at += 1
        if count == 0 and octet == 0x80:
            raise SecMeterC12Error("non-minimal BER high tag")
        number = (number << 7) | (octet & 0x7F)
        count += 1
        if not octet & 0x80:
            break
    if number < 31:
        raise SecMeterC12Error("non-minimal BER high tag")
    return cls, constructed, number, at


def _ber_length(data, at, end, maximum=MAX_INPUT):
    if at >= end:
        raise SecMeterC12Error("truncated BER length")
    first = data[at]
    at += 1
    if first < 0x80:
        return first, at
    count = first & 0x7F
    if count == 0:
        raise SecMeterC12Error("indefinite BER lengths are not accepted")
    if count > 4 or at + count > end:
        raise SecMeterC12Error("truncated or excessive BER length")
    if data[at] == 0:
        raise SecMeterC12Error("non-minimal BER length")
    length = int.from_bytes(data[at:at + count], "big")
    at += count
    if length < 0x80:
        raise SecMeterC12Error("non-minimal BER length")
    if length > maximum:
        raise SecMeterC12Error("BER value exceeds size limit")
    return length, at


def _ber_node(data, at, end, depth, budget):
    if depth > MAX_BER_DEPTH or budget[0] <= 0:
        raise SecMeterC12Error("BER nesting/node budget exceeded")
    start = at
    cls, constructed, number, at = _ber_identifier(data, at, end)
    length, at = _ber_length(data, at, end)
    stop = at + length
    if stop > end:
        raise SecMeterC12Error("BER value overruns its container")
    budget[0] -= 1
    children = []
    if constructed:
        child_at = at
        while child_at < stop:
            child, child_at = _ber_node(data, child_at, stop, depth + 1, budget)
            children.append(child)
        if child_at != stop:
            raise SecMeterC12Error("BER children do not fill their container")
    return (_BERNode(cls, constructed, number, data[at:stop], tuple(children),
                     data[start:stop]), stop)


def _ber_tree(raw):
    if not raw:
        raise SecMeterC12Error("empty BER input")
    node, at = _ber_node(raw, 0, len(raw), 0, [MAX_BER_NODES])
    if at != len(raw):
        raise SecMeterC12Error("trailing bytes after BER APDU")
    return node


def _expect(node, cls, number, constructed=None, label="BER field"):
    if node.cls != cls or node.number != number:
        raise SecMeterC12Error(f"unexpected {label} tag")
    if constructed is not None and node.constructed != constructed:
        raise SecMeterC12Error(f"wrong {label} primitive/constructed form")
    return node


def _only(node, label):
    if len(node.children) != 1:
        raise SecMeterC12Error(f"{label} must contain exactly one value")
    return node.children[0]


def _integer(node, label="INTEGER"):
    _expect(node, 0, 2, False, label)
    raw = node.content
    if not raw:
        raise SecMeterC12Error(f"empty {label}")
    if len(raw) > 1 and ((raw[0] == 0 and raw[1] < 0x80) or
                         (raw[0] == 0xFF and raw[1] >= 0x80)):
        raise SecMeterC12Error(f"non-minimal {label}")
    return int.from_bytes(raw, "big", signed=True)


def _base128(raw, label):
    if not raw:
        raise SecMeterC12Error(f"empty {label}")
    values, value, start = [], 0, True
    for octet in raw:
        if start and octet == 0x80:
            raise SecMeterC12Error(f"non-minimal {label}")
        value = (value << 7) | (octet & 0x7F)
        if value.bit_length() > 128:
            raise SecMeterC12Error(f"oversized {label} arc")
        if not octet & 0x80:
            values.append(value)
            value, start = 0, True
        else:
            start = False
    if not start:
        raise SecMeterC12Error(f"truncated {label}")
    return values


def _oid_content(raw):
    values = _base128(raw, "OBJECT IDENTIFIER")
    first = values.pop(0)
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    arcs.extend(values)
    return ".".join(str(value) for value in arcs)


def _oid(node):
    _expect(node, 0, 6, False, "OBJECT IDENTIFIER")
    return _oid_content(node.content)


def _relative_oid_content(raw):
    return ".".join(str(value) for value in _base128(raw, "RELATIVE-OID"))


def _explicit_integer(node, label):
    value = _integer(_only(node, label), label)
    if value < 0:
        raise SecMeterC12Error(f"negative {label}")
    return value


def _title(node, label):
    choice = _only(node, label)
    if choice.cls == 0 and choice.number == 6 and not choice.constructed:
        return {"form": "absolute", "oid": _oid(choice)}
    if choice.cls == 2 and choice.number == 0 and not choice.constructed:
        return {"form": "relative", "oid": _relative_oid_content(choice.content)}
    raise SecMeterC12Error(f"invalid {label}")


def _authentication(node):
    sequence = _expect(_only(node, "authentication value"), 2, 2, True,
                       "authentication sequence")
    children = list(sequence.children)
    indirect = 0
    if children and children[0].cls == 0 and children[0].number == 2:
        indirect = _integer(children.pop(0), "authentication indirect reference")
        if indirect < 0:
            raise SecMeterC12Error("negative authentication indirect reference")
    if len(children) != 1:
        raise SecMeterC12Error("authentication requires exactly one encoding")
    encoding = children[0]
    out = {"indirect_reference": indirect}
    if encoding.cls == 2 and encoding.number == 1 and not encoding.constructed:
        out.update(encoding="octet_aligned", value_hex=encoding.content.hex())
        return out
    _expect(encoding, 2, 0, True, "single-ASN.1 authentication")
    choice = _only(encoding, "single-ASN.1 authentication")
    if choice.cls == 2 and choice.number == 1 and choice.constructed:
        fields = {}
        for field in choice.children:
            if field.cls != 2 or field.constructed or field.number not in (0, 1):
                raise SecMeterC12Error("invalid C12.22 authentication element")
            if field.number in fields:
                raise SecMeterC12Error("duplicate C12.22 authentication element")
            fields[field.number] = field.content
        if 0 in fields and len(fields[0]) != 1:
            raise SecMeterC12Error("C12.22 key ID must be one octet")
        if 1 in fields and len(fields[1]) != 4:
            raise SecMeterC12Error("C12.22 IV must be four octets")
        out.update(encoding="single_asn1", mechanism="c12.22")
        if 0 in fields:
            out.update(key_id=fields[0][0], key_id_hex=fields[0].hex())
        if 1 in fields:
            out["iv_hex"] = fields[1].hex()
        return out
    if choice.cls == 2 and choice.number == 0 and choice.constructed:
        out.update(encoding="single_asn1", mechanism="c12.21",
                   value_hex=choice.content.hex())
        return out
    raise SecMeterC12Error("unsupported authentication choice")


def _external(node):
    external = _expect(_only(node, "user-information"), 0, 8, True,
                       "EXTERNAL user-information")
    result = {}
    encoding = None
    for child in external.children:
        if child.cls == 0 and child.number == 6 and not child.constructed:
            if "direct_reference" in result:
                raise SecMeterC12Error("duplicate EXTERNAL direct-reference")
            result["direct_reference"] = _oid(child)
        elif child.cls == 0 and child.number == 2 and not child.constructed:
            if "indirect_reference" in result:
                raise SecMeterC12Error("duplicate EXTERNAL indirect-reference")
            result["indirect_reference"] = _integer(child, "EXTERNAL indirect-reference")
        elif child.cls == 2 and child.number == 1 and not child.constructed:
            if encoding is not None:
                raise SecMeterC12Error("duplicate EXTERNAL encoding")
            encoding = child.content
        elif child.cls == 0:
            # Data-value-descriptor is legal but not needed to decode EPSEM.
            result.setdefault("descriptor_hex", child.encoded.hex())
        else:
            raise SecMeterC12Error("unsupported EXTERNAL field")
    if encoding is None:
        raise SecMeterC12Error("EXTERNAL lacks octet-aligned EPSEM")
    result["encoding"] = "octet_aligned"
    return result, encoding


def _service_length(data, at, end):
    return _ber_length(data, at, end, MAX_SERVICE)


def _epsem_service(raw):
    command = raw[0]
    if _psem_name(command) is not None:
        return _parse_psem_request(raw)
    # A response cannot be associated with its request from one isolated
    # EPSEM alone.  Preserve it and avoid guessing a read-response schema.
    return {"protocol": "psem", "direction": "response_unassociated",
            "status": command,
            "status_name": _PSEM_STATUS.get(command, "reserved_or_vendor"),
            "body_hex": raw[1:].hex()}


def _epsem_services(data):
    services, at = [], 0
    while at < len(data):
        if len(services) >= MAX_SERVICES:
            raise SecMeterC12Error("too many EPSEM services")
        length, at = _service_length(data, at, len(data))
        if length == 0 or at + length > len(data):
            raise SecMeterC12Error("invalid or truncated EPSEM service length")
        raw = data[at:at + length]
        at += length
        services.append({"length": length, "raw_hex": raw.hex(),
                         "psem": _epsem_service(raw)})
    if not services:
        raise SecMeterC12Error("EPSEM contains no services")
    return services


def _parse_epsem(raw):
    if not raw:
        raise SecMeterC12Error("empty EPSEM")
    control = raw[0]
    if not control & 0x80:
        raise SecMeterC12Error("EPSEM control required bit is clear")
    security = (control >> 2) & 0x03
    response = control & 0x03
    if security == 3:
        raise SecMeterC12Error("reserved EPSEM security mode")
    if response == 3:
        raise SecMeterC12Error("reserved EPSEM response control")
    names = ("clear", "clear_authenticated", "encrypted_authenticated")
    response_names = ("always", "exception_only", "never")
    out = {
        "protocol": "c12.22-epsem", "control": control,
        "recovery_session": bool(control & 0x40),
        "proxy_used": bool(control & 0x20),
        "ed_class_included": bool(control & 0x10),
        "security_mode": security,
        "security_mode_name": names[security],
        "response_control": response,
        "response_control_name": response_names[response],
    }
    at = 1
    stop = len(raw)
    if security in (1, 2):
        if stop - at < 4:
            raise SecMeterC12Error("authenticated EPSEM lacks its four-byte MAC")
        stop -= 4
        out.update(mac_hex=raw[stop:].hex(), integrity_applicable=True,
                   integrity_verified=False)
    if security == 2:
        # Encryption covers the ED class (when present) and service sequence;
        # do not mislabel the first four ciphertext bytes as a clear ED class.
        body = raw[at:stop]
        if not body:
            raise SecMeterC12Error("encrypted EPSEM has no ciphertext")
        out.update(ciphertext_hex=body.hex(), services=[], plaintext_available=False,
                   ed_class_encrypted=bool(control & 0x10))
        return out
    if control & 0x10:
        if stop < at + 4:
            raise SecMeterC12Error("truncated EPSEM ED class")
        ed_class = raw[at:at + 4]
        # ED_CLASS is the four-octet C12.19 ST0 DEVICE_CLASS value, not an
        # inherently textual field.  Add a convenience rendering only when
        # every supplied octet is printable ASCII.
        out["ed_class_hex"] = ed_class.hex()
        if all(0x20 <= octet <= 0x7E for octet in ed_class):
            out["ed_class"] = ed_class.decode("ascii")
        at += 4
    body = raw[at:stop]
    out["services"] = _epsem_services(body)
    out["plaintext_available"] = True
    if security == 0:
        # Clear EPSEM has no MAC to verify.  "Readable" is not the same
        # as authenticated, so never report a positive integrity claim.
        out.update(integrity_applicable=False, integrity_verified=False)
    return out


@_closed
def parse_epsem(data):
    """Parse one C12.22 EPSEM; encrypted service bytes remain opaque."""

    return _parse_epsem(_blob(data, "EPSEM", MAX_SERVICE * 4))


def _parse_c1222(raw):
    root = _expect(_ber_tree(raw), 1, 0, True, "C12.22 MESSAGE")
    known = {1, 2, 4, 6, 7, 8, 11, 12, 30}
    fields = {}
    extensions = []
    last_known = -1
    for child in root.children:
        if child.cls != 2:
            raise SecMeterC12Error("C12.22 MESSAGE fields must be context-specific")
        if child.number in known:
            if child.number in fields:
                raise SecMeterC12Error("duplicate C12.22 MESSAGE field")
            if child.number < last_known:
                raise SecMeterC12Error("out-of-order C12.22 MESSAGE field")
            fields[child.number] = child
            last_known = child.number
        else:
            extensions.append({"tag": child.number,
                               "constructed": child.constructed,
                               "encoded_hex": child.encoded.hex()})
    if 8 not in fields or 30 not in fields:
        raise SecMeterC12Error("C12.22 MESSAGE lacks required invocation ID or user-information")
    out = {"protocol": "c12.22", "ber_length": len(raw)}
    if 1 in fields:
        node = _expect(_only(fields[1], "ASO context"), 0, 6, False,
                       "ASO context OID")
        out["application_context_oid"] = _oid(node)
        out["known_application_context"] = out["application_context_oid"] == "2.16.124.113620.1.22"
    if 2 in fields:
        out["called_ap_title"] = _title(fields[2], "called AP title")
    if 4 in fields:
        out["called_ap_invocation_id"] = _explicit_integer(fields[4], "called AP invocation ID")
    if 6 in fields:
        out["calling_ap_title"] = _title(fields[6], "calling AP title")
    if 7 in fields:
        out["calling_ae_qualifier"] = _explicit_integer(fields[7], "calling AE qualifier")
    out["calling_ap_invocation_id"] = _explicit_integer(fields[8], "calling AP invocation ID")
    if 11 in fields:
        _expect(fields[11], 2, 11, False, "mechanism name")
        out["mechanism_name_oid"] = _oid_content(fields[11].content)
    if 12 in fields:
        out["authentication"] = _authentication(fields[12])
    external, epsem = _external(fields[30])
    out["user_information"] = external
    out["epsem"] = _parse_epsem(epsem)
    if extensions:
        out["extension_fields"] = extensions
    return out


@_closed
def parse_c1222_apdu(data):
    """Parse one complete canonical-definite BER C12.22 ACSE MESSAGE."""

    return _parse_c1222(_blob(data, "C12.22 APDU"))


@_closed
def classify_c1222_payload(data, *, transport, source_port, destination_port):
    """Classify a supplied native TCP/UDP payload; never opens a socket."""

    if not isinstance(transport, str) or transport.lower() not in ("tcp", "udp"):
        raise SecMeterC12Error("transport must be tcp or udp")
    transport = transport.lower()
    for name, port in (("source", source_port), ("destination", destination_port)):
        if type(port) is not int or not 0 <= port <= 65535:
            raise SecMeterC12Error(f"invalid {name} port")
    if transport == "udp" and source_port == 0:
        raise SecMeterC12Error("RFC 6142 forbids UDP source port zero")
    raw = _blob(data, "native C12.22 payload")
    if C1222_PORT not in (source_port, destination_port):
        return {"protocol": "c12.22-ip", "transport": transport,
                "source_port": source_port, "destination_port": destination_port,
                "is_c1222": False, "reason": "neither port is 1153"}
    return {"protocol": "c12.22-ip", "transport": transport,
            "source_port": source_port, "destination_port": destination_port,
            "is_c1222": True, "apdu": _parse_c1222(raw)}


def _parse_frame_payload(payload, data_format, direction, request_command):
    if data_format == 0:
        if direction == "request":
            return _parse_psem_request(payload)
        if direction == "response":
            return _parse_psem_response(payload, request_command)
        if direction != "auto":
            raise SecMeterC12Error("direction must be auto, request, or response")
        if payload and _psem_name(payload[0]) is not None:
            return _parse_psem_request(payload)
        if request_command is not None:
            return _parse_psem_response(payload, request_command)
        return {"protocol": "psem", "direction": "unknown",
                "raw_hex": payload.hex()}
    if data_format == 1:
        return _parse_epsem(payload)
    raise SecMeterC12Error("reserved C12.18 data format")


@_closed
def parse_c1218_frame(data, *, direction="auto", request_command=None):
    """Parse one standalone ACK/NAK or complete C12.18 0xEE link frame."""

    raw = _blob(data, "C12.18 frame", 65543)
    if raw in (b"\x06", b"\x15"):
        return {"protocol": "c12.18", "frame_type": "ack" if raw == b"\x06" else "nak",
                "code": raw[0]}
    if len(raw) < 9 or raw[0] != 0xEE:
        raise SecMeterC12Error("not a complete C12.18 EE frame")
    declared = int.from_bytes(raw[4:6], "big")
    if declared == 0:
        raise SecMeterC12Error("C12.18 data length must be nonzero")
    if len(raw) != 8 + declared:
        raise SecMeterC12Error("C12.18 declared length does not match frame")
    actual_crc = int.from_bytes(raw[-2:], "little")
    expected_crc = _crc16_c1218(raw[:-2])
    if actual_crc != expected_crc:
        raise SecMeterC12Error("C12.18 CRC mismatch")
    control = raw[2]
    if control & 0x1C:
        raise SecMeterC12Error("reserved C12.18 control bits are set")
    multiple = bool(control & 0x80)
    first = bool(control & 0x40)
    if first and not multiple:
        raise SecMeterC12Error("C12.18 first-packet flag without multipart flag")
    if first and raw[3] == 0:
        raise SecMeterC12Error("multipart first packet must announce a continuation")
    data_format = control & 0x03
    if data_format not in (0, 1):
        raise SecMeterC12Error("reserved C12.18 data format")
    payload = raw[6:-2]
    out = {
        "protocol": "c12.18", "frame_type": "data", "identity": raw[1],
        "control": control, "sequence": raw[3], "data_length": declared,
        "multiple_packets": multiple, "first_packet": first,
        "toggle": bool(control & 0x20), "data_format": data_format,
        "data_format_name": "psem" if data_format == 0 else "epsem" if data_format == 1 else "reserved",
        "payload_hex": payload.hex(), "crc": actual_crc, "crc_wire_hex": raw[-2:].hex(),
        "crc_valid": True,
    }
    if multiple:
        out["payload_status"] = "fragment_not_reassembled"
    else:
        out["payload"] = _parse_frame_payload(payload, data_format, direction,
                                               request_command)
    return out


@_closed
def analyze(data, *, kind="auto", table_id=None, id_form=False,
            direction="auto", request_command=None,
            transport="tcp", source_port=C1222_PORT,
            destination_port=C1222_PORT):
    """Dispatch one supplied artifact without performing any I/O."""

    raw = _blob(data)
    if kind == "auto":
        if raw[:1] in (b"\xEE", b"\x06", b"\x15"):
            kind = "c1218"
        elif raw[:1] == b"\x60":
            try:
                return _parse_c1222(raw)
            except SecMeterC12Error:
                kind = "psem-request"
        else:
            kind = "psem-request"
    if kind == "c1218":
        return parse_c1218_frame(raw, direction=direction,
                                 request_command=request_command)
    if kind == "psem-request":
        return _parse_psem_request(raw)
    if kind == "psem-response":
        return _parse_psem_response(raw, request_command)
    if kind == "st0":
        return _parse_st0(raw)
    if kind == "st1":
        return _parse_st1(raw, id_form)
    if kind == "table":
        if table_id is None:
            raise SecMeterC12Error("table kind requires table_id")
        return parse_c1219_table(table_id, raw, id_form=id_form)
    if kind == "epsem":
        return _parse_epsem(raw)
    if kind == "c1222":
        return _parse_c1222(raw)
    if kind == "c1222-ip":
        return classify_c1222_payload(
            raw, transport=transport, source_port=source_port,
            destination_port=destination_port
        )
    raise SecMeterC12Error("unsupported analysis kind")


def _integer_argument(value):
    try:
        return int(value, 0)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("expected an integer") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="local binary file, or hexadecimal bytes with --hex")
    parser.add_argument("--hex", action="store_true", help="interpret input as hexadecimal bytes")
    parser.add_argument("--format", dest="kind", default="auto", choices=(
        "auto", "c1218", "psem-request", "psem-response", "st0", "st1",
        "table", "epsem", "c1222", "c1222-ip"))
    parser.add_argument("--table-id", type=_integer_argument)
    parser.add_argument("--id-form", choices=("string", "bcd"), default="string")
    parser.add_argument("--direction", choices=("auto", "request", "response"), default="auto")
    parser.add_argument("--request-command", type=_integer_argument)
    parser.add_argument("--transport", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--source-port", type=int, default=C1222_PORT)
    parser.add_argument("--destination-port", type=int, default=C1222_PORT)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception:
        return 2
    try:
        if args.hex:
            if len(args.input) > MAX_INPUT * 3:
                raise SecMeterC12Error("hexadecimal input exceeds limit")
            try:
                data = bytes.fromhex(args.input)
            except ValueError as exc:
                raise SecMeterC12Error("invalid hexadecimal input") from exc
        else:
            with Path(args.input).open("rb") as source:
                data = source.read(MAX_INPUT + 1)
            if len(data) > MAX_INPUT:
                raise SecMeterC12Error("input file exceeds limit")
        result = analyze(
            data, kind=args.kind, table_id=args.table_id,
            id_form=args.id_form == "bcd", direction=args.direction,
            request_command=args.request_command, transport=args.transport,
            source_port=args.source_port, destination_port=args.destination_port,
        )
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True))
        return 0
    except Exception as exc:
        print(f"ANSI C12 parse error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
