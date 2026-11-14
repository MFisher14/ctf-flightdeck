#!/usr/bin/env python3
"""Passive US PTC, ITCM/EMP, WIU, and legacy ATCS decoder.

This module inventories supplied bytes only.  It does not implement a radio,
open a connection, or generate traffic.  Public AAR S-9354/S-9361/S-9362 and
S-5800 fields are decoded; controlled Meteorcomm/Wabtec radio internals remain
opaque rather than being guessed.
"""
from __future__ import annotations

import argparse
import binascii
import functools
import hashlib
import hmac
import json
from pathlib import Path
import sys


MAX_EMP = 16 * 1024 * 1024
MAX_ATCS = 1024
MAX_STATUS_BITS = 1944


class SecRailPTCError(ValueError):
    """Malformed, unsupported, or over-limit PTC/ATCS artifact."""


def _closed(function):
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecRailPTCError:
            raise
        except Exception as exc:
            raise SecRailPTCError(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from None
    return wrapper


def _bytes(value, label="input", maximum=MAX_EMP):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecRailPTCError(f"{label} must be bytes")
    if len(value) > maximum:
        raise SecRailPTCError(f"{label} exceeds {maximum}-byte limit")
    return bytes(value)


def _u16(data, at):
    if at + 2 > len(data):
        raise SecRailPTCError("truncated 16-bit field")
    return int.from_bytes(data[at:at + 2], "big")


def _u24(data, at):
    if at + 3 > len(data):
        raise SecRailPTCError("truncated 24-bit field")
    return int.from_bytes(data[at:at + 3], "big")


def _u32(data, at):
    if at + 4 > len(data):
        raise SecRailPTCError("truncated 32-bit field")
    return int.from_bytes(data[at:at + 4], "big")


def _ascii(data, label, allow_space=True):
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise SecRailPTCError(f"non-ASCII {label}") from None
    low = 0x20 if allow_space else 0x21
    if any(not low <= ord(char) <= 0x7E for char in text):
        raise SecRailPTCError(f"non-printable {label}")
    return text


_MESSAGE_NAMES = {
    1041: "bulletin dataset",
    1051: "movement authority",
    1053: "movement authority void",
    1060: "crew message",
    2051: "request movement authority dataset",
    2052: "confirmation movement authority",
    2053: "confirmation movement authority void",
    2080: "locomotive position report",
    2083: "enforcement/braking notification",
    2084: "emergency-brake report",
    2090: "legacy control-point request / proposed FMB occupancy report",
    5100: "periodic WIU status",
    5101: "WIU status response",
    5200: "beacon request",
    5201: "GET WIU status",
    0xFFFF: "self-describing message",
}


def _parse_scac(raw):
    if len(raw) != 4:
        raise SecRailPTCError("SCAC must be four bytes")
    text = _ascii(raw, "SCAC")
    if not text.strip():
        raise SecRailPTCError("empty SCAC")
    return text


def _request_authority(data):
    if len(data) < 7:
        raise SecRailPTCError("truncated 02051 request")
    count = data[6]
    if count > 99 or len(data) != 7 + count * 4:
        raise SecRailPTCError("invalid 02051 authority-reference count")
    subdivision = _u16(data, 4)
    if subdivision == 0:
        raise SecRailPTCError("02051 subdivision must be 1..65535")
    return {
        "SCAC": _parse_scac(data[:4]),
        "subdivision": subdivision,
        "authority_count": count,
        "authority_references": [_u32(data, 7 + 4 * index)
                                 for index in range(count)],
    }


def _confirm_authority(data):
    if len(data) < 5:
        raise SecRailPTCError("truncated 02052 confirmation")
    count = data[4]
    if not 1 <= count <= 25 or len(data) != 5 + count * 11:
        raise SecRailPTCError("invalid 02052 subdivision count")
    rows = []
    for index in range(count):
        at = 5 + index * 11
        subdivision = _u16(data, at)
        if subdivision == 0:
            raise SecRailPTCError("02052 subdivision must be 1..65535")
        ack = data[at + 10]
        if ack not in (1, 2, 4, 5, 6):
            raise SecRailPTCError("reserved 02052 acknowledgement code")
        rows.append({"subdivision": subdivision,
                     "authority_reference": _u32(data, at + 2),
                     "authority_crc32": f"{_u32(data, at + 6):08x}",
                     "acknowledgement": ack})
    return {"SCAC": _parse_scac(data[:4]), "subdivision_count": count,
            "confirmations": rows}


def _void_confirmation(data):
    if len(data) != 15:
        raise SecRailPTCError("02053 confirmation must be 15 bytes")
    ack = data[14]
    if ack not in (1, 2, 3, 4):
        raise SecRailPTCError("reserved 02053 acknowledgement code")
    subdivision = _u16(data, 4)
    if subdivision == 0:
        raise SecRailPTCError("02053 subdivision must be 1..65535")
    return {"SCAC": _parse_scac(data[:4]), "subdivision": subdivision,
            "authority_reference": _u32(data, 6),
            "authority_crc32": f"{_u32(data, 10):08x}",
            "acknowledgement": ack}


def _movement_authority_prefix(data):
    """Extract the stable S-9361 prefix; retain evolving segment bytes."""
    if len(data) < 13:
        raise SecRailPTCError("truncated 01051 movement authority")
    reason, crew_action = data[0], data[1]
    if reason not in (0, 1, 2):
        raise SecRailPTCError("reserved movement-authority reason")
    display_length = data[10]
    at = 11
    if display_length > 127 or at + display_length + 2 > len(data):
        raise SecRailPTCError("invalid display-reference length")
    display = _ascii(data[at:at + display_length], "display reference")
    at += display_length
    authority_type, subdivision_count = data[at], data[at + 1]
    at += 2
    if not 1 <= subdivision_count <= 25 or at + 2 * subdivision_count + 8 > len(data):
        raise SecRailPTCError("invalid movement-authority subdivision count")
    subdivisions = [_u16(data, at + 2 * index)
                    for index in range(subdivision_count)]
    if any(value == 0 for value in subdivisions):
        raise SecRailPTCError("movement-authority subdivision must be 1..65535")
    at += 2 * subdivision_count
    timestamp = data[at:at + 7]
    at += 7
    void_count = data[at]
    at += 1
    if void_count > 9 or at + 4 * void_count + 2 > len(data):
        raise SecRailPTCError("invalid movement-authority void count")
    voids = [_u32(data, at + 4 * index) for index in range(void_count)]
    at += 4 * void_count
    segment_count = _u16(data, at)
    if segment_count > 304:
        raise SecRailPTCError("movement-authority segment count exceeds 304")
    at += 2
    return {
        "reason": reason, "crew_action": crew_action,
        "SCAC": _parse_scac(data[2:6]),
        "authority_reference": _u32(data, 6),
        "display_reference": display, "authority_type": authority_type,
        "subdivisions": subdivisions, "timestamp_hex": timestamp.hex(),
        "void_authority_references": voids, "segment_count": segment_count,
        "segment_data_hex": data[at:].hex(),
        "segment_data_note": "bounded opaque evolving S-9361 segment records",
    }


_STATUS_WIDTHS = {"switch": 2, "signal": 5, "hazard": 1}
_SWITCH_NAMES = {0: "unknown", 1: "reverse", 2: "normal", 3: "error"}
_PUBLIC_MESSAGE_VERSIONS = {
    1051: 4, 2051: 1, 2052: 3, 2053: 1,
    5100: 0, 5101: 0, 5200: 0, 5201: 0,
}


@_closed
def parse_wiu_status(data, device_schema=None):
    """Decode the published S-9362 WIUStatus header and optional status schema."""
    raw = _bytes(data, "WIU status", 256)
    if not 13 <= len(raw) <= 8 + (MAX_STATUS_BITS + 7) // 8 + 4:
        raise SecRailPTCError("invalid WIUStatus length")
    word = _u16(raw, 5)
    vital_type = (word >> 9) & 0x3F
    vital_version = (word >> 4) & 0x1F
    if vital_type not in (1, 2):
        raise SecRailPTCError("unsupported WIU vital-message type")
    if vital_version != 0:
        raise SecRailPTCError("unsupported WIU vital-message version")
    status = raw[8:-4]
    result = {
        "format": "S-9362 WIUStatus",
        "WIU_ID": int.from_bytes(raw[:5], "big"),
        "TTL_indicator": (word >> 15) & 1,
        "vital_message_type": vital_type,
        "vital_message_version": vital_version,
        "modulo_16_time": word & 0xF,
        "sequence": raw[7],
        "device_status_hex": status.hex(),
        "vital_integrity_hex": raw[-4:].hex(),
        "vital_integrity_verified": None,
    }
    if device_schema is not None:
        if (not isinstance(device_schema, (list, tuple)) or not device_schema or
                len(device_schema) > MAX_STATUS_BITS):
            raise SecRailPTCError("device schema must be a bounded nonempty list")
        if any(type(kind) is not str or kind not in _STATUS_WIDTHS
               for kind in device_schema):
            raise SecRailPTCError("unknown WIU device kind")
        needed = sum(_STATUS_WIDTHS[kind] for kind in device_schema)
        if needed > MAX_STATUS_BITS or len(status) != (needed + 7) // 8:
            raise SecRailPTCError("WIU schema does not match status byte count")
        integer = int.from_bytes(status, "little")
        devices, offset = [], 0
        for kind in device_schema:
            width = _STATUS_WIDTHS[kind]
            value = (integer >> offset) & ((1 << width) - 1)
            item = {"kind": kind, "code": value}
            if kind == "switch":
                item["state"] = _SWITCH_NAMES[value]
            elif kind == "hazard":
                item["condition"] = "none" if value else "present"
            devices.append(item)
            offset += width
        if integer >> needed:
            raise SecRailPTCError("nonzero WIU status padding bits")
        result["devices"] = devices
        result["device_status_bits"] = needed
    return result


@_closed
def parse_itcm_message(message_type, data, message_version=None, device_schema=None):
    """Decode a public S-9361/S-9362 body; preserve unknown bodies verbatim."""
    if type(message_type) is not int or not 0 <= message_type <= 0xFFFF:
        raise SecRailPTCError("message type must be an unsigned 16-bit integer")
    if message_version is not None and (type(message_version) is not int or
                                        not 0 <= message_version <= 255):
        raise SecRailPTCError("message version must be an unsigned byte")
    schema_version = _PUBLIC_MESSAGE_VERSIONS.get(message_type)
    if (message_version is not None and schema_version is not None and
            message_version != schema_version):
        raise SecRailPTCError(
            f"message {message_type} requires public schema version {schema_version}"
        )
    raw = _bytes(data, "ITCM message body")
    result = {"message_type": message_type,
              "message_name": _MESSAGE_NAMES.get(message_type, "unknown/private extension"),
              "message_version": message_version, "schema_version": schema_version,
              "body_length": len(raw)}
    if message_type == 2051:
        result["decoded"] = _request_authority(raw)
    elif message_type == 2052:
        result["decoded"] = _confirm_authority(raw)
    elif message_type == 2053:
        result["decoded"] = _void_confirmation(raw)
    elif message_type == 1051:
        result["decoded"] = _movement_authority_prefix(raw)
    elif message_type in (5100, 5101):
        result["decoded"] = parse_wiu_status(raw, device_schema)
        expected_vital_type = 1 if message_type == 5100 else 2
        if result["decoded"]["vital_message_type"] != expected_vital_type:
            raise SecRailPTCError("S-9362 outer message type disagrees with vital type")
    elif message_type in (5200, 5201):
        if raw:
            raise SecRailPTCError("S-9362 request body must be empty")
        result["decoded"] = {}
    else:
        result["body_hex"] = raw.hex()
    if message_type == 2090:
        result["version_context"] = (
            "legacy S-9361 control-point request; FRA FMB research proposes "
            "occupancy/broken-rail semantics in a redline"
        )
    return result


def _nul_string(data, start, end, label):
    if start >= end:
        raise SecRailPTCError(f"missing {label}")
    nul = data.find(b"\x00", start, end)
    if nul < 0 or nul - start > 64:
        raise SecRailPTCError(f"unterminated or oversized {label}")
    return _ascii(data[start:nul], label), nul + 1


_NETWORK_NAMES = {
    0: "no preference", 1: "ITC 220 MHz", 6: "not 220 MHz",
    7: "all available transports",
}


@_closed
def parse_emp(data, integrity_key=None, device_schema=None):
    """Parse and verify one AAR S-9354 Edge Message Protocol envelope."""
    raw = _bytes(data, "EMP envelope", MAX_EMP)
    if len(raw) < 21:
        raise SecRailPTCError("truncated EMP envelope")
    protocol_version = raw[0]
    if protocol_version != 4:
        raise SecRailPTCError("unsupported EMP protocol version")
    message_type, message_version, flags = _u16(raw, 1), raw[3], raw[4]
    if flags & 0xE0:
        raise SecRailPTCError("nonzero reserved EMP flag bits")
    data_length = _u24(raw, 5)
    message_number, message_time = _u32(raw, 8), _u32(raw, 12)
    variable_size = raw[16]
    expected = 17 + variable_size + data_length + 4
    if expected != len(raw):
        raise SecRailPTCError("EMP length fields do not match envelope")
    integrity_method = (flags >> 3) & 3
    if integrity_method == 3:
        raise SecRailPTCError("reserved EMP integrity method")
    variable = raw[17:17 + variable_size]
    routing = None
    if variable_size:
        if variable_size < 6:
            raise SecRailPTCError("truncated EMP variable header")
        ttl, qos = _u16(variable, 0), _u16(variable, 2)
        source, at = _nul_string(variable, 4, len(variable), "EMP source")
        destination, at = _nul_string(variable, at, len(variable), "EMP destination")
        if at != len(variable):
            raise SecRailPTCError("undeclared EMP variable-header bytes")
        network = (qos >> 6) & 7
        routing = {
            "TTL_seconds": ttl, "QoS": qos, "class": qos & 7,
            "priority": (qos >> 3) & 7, "network_preference": network,
            "network_preference_name": _NETWORK_NAMES.get(network, "reserved"),
            "special_handling": (qos >> 9) & 0xF,
            "service_requests": (qos >> 13) & 7,
            "source": source, "destination": destination,
        }
    payload_start = 17 + variable_size
    payload = raw[payload_start:payload_start + data_length]
    transmitted = raw[-4:]
    verified = None
    method_name = ("none", "CRC-32/ISO-HDLC", "application-specific")[integrity_method]
    if integrity_method == 0:
        if transmitted != b"\x00\x00\x00\x00":
            raise SecRailPTCError("EMP no-integrity DIV must be zero")
    elif integrity_method == 1:
        expected_crc = binascii.crc32(raw[:-4]) & 0xFFFFFFFF
        verified = hmac.compare_digest(expected_crc.to_bytes(4, "big"), transmitted)
        if not verified:
            raise SecRailPTCError("EMP CRC-32 mismatch")
        if integrity_key is not None:
            raise SecRailPTCError("integrity key is not used by EMP CRC-32")
    elif integrity_method == 2 and integrity_key is not None:
        key = _bytes(integrity_key, "EMP application integrity key", 4096)
        if not key:
            raise SecRailPTCError("empty EMP application integrity key")
        expected_tag = hmac.new(key, raw[:-4], hashlib.sha1).digest()[:4]
        verified = hmac.compare_digest(expected_tag, transmitted)
        if not verified:
            raise SecRailPTCError("EMP application integrity mismatch")
    elif integrity_method != 2 and integrity_key is not None:
        raise SecRailPTCError("integrity key supplied for non-application method")
    result = {
        "format": "AAR Edge Message Protocol",
        "protocol_version": protocol_version, "message_type": message_type,
        "message_name": _MESSAGE_NAMES.get(message_type, "unknown/private extension"),
        "message_version": message_version, "flags": flags,
        "absolute_timestamp": bool(flags & 1),
        "encrypted": bool(flags & 2), "compressed": bool(flags & 4),
        "data_length": data_length, "message_number": message_number,
        "message_time": message_time, "routing": routing,
        "integrity_method": method_name, "integrity_hex": transmitted.hex(),
        "integrity_verified": verified,
    }
    if flags & 6:
        result["payload_hex"] = payload.hex()
        result["payload_note"] = "encrypted/compressed payload left opaque"
    else:
        result["payload"] = parse_itcm_message(
            message_type, payload, message_version, device_schema
        )
    return result


def _decode_bcd_address(nibbles, label):
    digits = []
    for nibble in nibbles:
        if nibble == 0xA:
            digits.append("0")
        elif 1 <= nibble <= 9:
            digits.append(str(nibble))
        else:
            raise SecRailPTCError(f"invalid BCD nibble in {label}")
    return "".join(digits)


def _read_bounded(path, maximum):
    try:
        if path.stat().st_size > maximum:
            raise SecRailPTCError(f"input exceeds {maximum}-byte limit")
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
    except OSError as exc:
        raise SecRailPTCError(f"cannot read input: {exc}") from None
    if len(data) > maximum:
        raise SecRailPTCError(f"input exceeds {maximum}-byte limit")
    return data


@_closed
def parse_atcs_packet(data):
    """Decode one public AAR S-5800 ATCS layer-3/4 data packet."""
    raw = _bytes(data, "ATCS packet", MAX_ATCS)
    if len(raw) < 12:
        raise SecRailPTCError("truncated ATCS packet")
    first = raw[0]
    if first & 0x30 != 0x20:
        raise SecRailPTCError("ATCS fixed header bits are not 10")
    q_bit = (first >> 7) & 1
    if q_bit == 0 and raw[1:4] != b"\x00\x00\x00":
        raise SecRailPTCError("origin ATCS packet has nonzero reserved octets")
    source_count, destination_count = raw[4] >> 4, raw[4] & 0xF
    if not source_count or not destination_count:
        raise SecRailPTCError("ATCS address digit count must be nonzero")
    total_digits = source_count + destination_count
    address_bytes = (total_digits + 1) // 2
    if 5 + address_bytes + 1 + 5 > len(raw):
        raise SecRailPTCError("truncated ATCS addressing")
    packed = raw[5:5 + address_bytes]
    nibbles = []
    for byte in packed:
        nibbles.extend((byte >> 4, byte & 0xF))
    if total_digits % 2:
        if nibbles[-1] != 0:
            raise SecRailPTCError("invalid ATCS address pad nibble")
        nibbles.pop()
    destination = _decode_bcd_address(nibbles[:destination_count], "destination")
    source = _decode_bcd_address(nibbles[destination_count:], "source")
    at = 5 + address_bytes
    facility_length = raw[at]
    at += 1
    if at + facility_length + 5 > len(raw):
        raise SecRailPTCError("truncated ATCS facility/transport header")
    facility = raw[at:at + facility_length]
    at += facility_length
    transport = raw[at:at + 5]
    at += 5
    message_number, more = transport[0] >> 1, transport[0] & 1
    part_number, acknowledgement = transport[1] >> 1, transport[1] & 1
    total_parts, vital = transport[2] >> 1, transport[2] & 1
    if not 1 <= part_number <= total_parts <= 127:
        raise SecRailPTCError("invalid ATCS multipart numbering")
    if bool(more) != (part_number < total_parts):
        raise SecRailPTCError("ATCS MORE flag disagrees with part numbering")
    label = int.from_bytes(transport[3:5], "big")
    layer7 = raw[at:]
    redundancy = None
    if vital:
        if len(layer7) < 4:
            raise SecRailPTCError("truncated ATCS vital redundancy code")
        redundancy, layer7 = layer7[-4:], layer7[:-4]
        if redundancy[0] & 0x80:
            raise SecRailPTCError("ATCS redundancy code high bit must be zero")
        if len(layer7) > 119:
            raise SecRailPTCError("ATCS vital Layer-7 data exceeds 119 octets")
    elif len(layer7) > 251:
        raise SecRailPTCError("ATCS nonvital Layer-7 data exceeds 251 octets")
    return {
        "format": "AAR ATCS data packet", "Q": q_bit,
        "originating_packet": q_bit == 0,
        "delivery_confirmation_requested": bool(first & 0x40),
        "priority": (first >> 1) & 7, "ARQ_disabled": bool(first & 1),
        "source": source, "destination": destination,
        "facility_hex": facility.hex(), "message_number": message_number,
        "more": bool(more), "part_number": part_number,
        "end_to_end_ack_requested": bool(acknowledgement),
        "total_parts": total_parts, "vital": bool(vital),
        "message_label": label, "function": label >> 9,
        "message_type": (label >> 6) & 7, "specifier": label & 63,
        "extended_size_candidate": not vital and len(layer7) > 123,
        "layer7_hex": layer7.hex(),
        "redundancy_code_hex": redundancy.hex() if redundancy else None,
        "redundancy_verified": None,
    }


@_closed
def reassemble_atcs_packets(packets):
    """Reassemble a complete, consistent set of supplied ATCS fragments."""
    if not isinstance(packets, (list, tuple)) or not 1 <= len(packets) <= 127:
        raise SecRailPTCError("expected 1..127 ATCS packet byte strings")
    decoded = [parse_atcs_packet(packet) for packet in packets]
    first = decoded[0]
    keys = ("source", "destination", "message_number", "message_label",
            "vital", "total_parts")
    if any(any(item[key] != first[key] for key in keys) for item in decoded[1:]):
        raise SecRailPTCError("inconsistent ATCS fragment set")
    if len(decoded) != first["total_parts"]:
        raise SecRailPTCError("incomplete ATCS fragment set")
    by_part = {item["part_number"]: item for item in decoded}
    if len(by_part) != len(decoded) or set(by_part) != set(range(1, len(decoded) + 1)):
        raise SecRailPTCError("duplicate or missing ATCS fragment")
    payload = b"".join(bytes.fromhex(by_part[index]["layer7_hex"])
                       for index in range(1, len(decoded) + 1))
    return {"source": first["source"], "destination": first["destination"],
            "message_number": first["message_number"],
            "message_label": first["message_label"],
            "vital": first["vital"], "part_count": len(decoded),
            "layer7_hex": payload.hex()}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Passive US PTC/ATCS decoder")
    sub = parser.add_subparsers(dest="mode", required=True)
    emp = sub.add_parser("emp", help="decode an S-9354 EMP envelope")
    emp.add_argument("file", type=Path)
    emp.add_argument("--key", help="hex application-integrity key")
    emp.add_argument("--devices", help="comma-separated switch,signal,hazard schema")
    atcs = sub.add_parser("atcs", help="decode an S-5800 ATCS packet")
    atcs.add_argument("file", type=Path)
    wiu = sub.add_parser("wiu", help="decode an S-9362 WIUStatus body")
    wiu.add_argument("file", type=Path)
    wiu.add_argument("--devices", help="comma-separated switch,signal,hazard schema")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        limits = {"emp": MAX_EMP, "atcs": MAX_ATCS, "wiu": 256}
        raw = _read_bounded(args.file, limits[args.mode])
        devices = (args.devices.split(",") if getattr(args, "devices", None)
                   else None)
        if args.mode == "emp":
            try:
                key = bytes.fromhex(args.key) if args.key is not None else None
            except ValueError:
                raise SecRailPTCError("key must be hexadecimal") from None
            result = parse_emp(raw, key, devices)
        elif args.mode == "atcs":
            result = parse_atcs_packet(raw)
        else:
            result = parse_wiu_status(raw, devices)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, SecRailPTCError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
