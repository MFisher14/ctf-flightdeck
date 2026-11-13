#!/usr/bin/env python3
"""Bounded, offline DDSI-RTPS 2.x and DDS-XRCE 1.0 evidence decoder.

The module parses supplied transport payload bytes only.  It never opens a socket,
discovers participants, creates DDS entities, or deserializes application objects.
Schema-less CDR data is limited to an encapsulation/scalar/text preview.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


MAX_INPUT = 16 * 1024 * 1024
MAX_SUBMESSAGES = 4096
MAX_PARAMETERS = 4096
MAX_LOCATORS = 8
MAX_PREVIEW = 128


class SecDDSRTPSError(ValueError):
    """Malformed, unsupported, ambiguous, or over-budget RTPS/XRCE evidence."""


_VENDORS = {
    "0101": "RTI Connext DDS",
    "0103": "OpenDDS",
    "010f": "eProsima Fast DDS",
    "0110": "Eclipse Cyclone DDS",
}

_RTPS_KINDS = {
    0x00: "RTPS_HE",
    0x01: "PAD",
    0x06: "ACKNACK",
    0x07: "HEARTBEAT",
    0x08: "GAP",
    0x09: "INFO_TS",
    0x0C: "INFO_SRC",
    0x0D: "INFO_REPLY_IP4",
    0x0E: "INFO_DST",
    0x0F: "INFO_REPLY",
    0x12: "NACK_FRAG",
    0x13: "HEARTBEAT_FRAG",
    0x15: "DATA",
    0x16: "DATA_FRAG",
    0x30: "SEC_BODY",
    0x31: "SEC_PREFIX",
    0x32: "SEC_POSTFIX",
    0x33: "SRTPS_PREFIX",
    0x34: "SRTPS_POSTFIX",
}

_XRCE_KINDS = {
    0: "CREATE_CLIENT",
    1: "CREATE",
    2: "GET_INFO",
    3: "DELETE",
    4: "STATUS_AGENT",
    5: "STATUS",
    6: "INFO",
    7: "WRITE_DATA",
    8: "READ_DATA",
    9: "DATA",
    10: "ACKNACK",
    11: "HEARTBEAT",
    12: "RESET",
    13: "FRAGMENT",
    14: "TIMESTAMP",
    15: "TIMESTAMP_REPLY",
}

_REPRESENTATIONS = {
    b"\x00\x00": ("CDR_BE", "big"),
    b"\x00\x01": ("CDR_LE", "little"),
    b"\x00\x02": ("PL_CDR_BE", "big"),
    b"\x00\x03": ("PL_CDR_LE", "little"),
    b"\x00\x04": ("XML", None),
    b"\x00\x10": ("CDR2_BE", "big"),
    b"\x00\x11": ("CDR2_LE", "little"),
    b"\x00\x12": ("PL_CDR2_BE", "big"),
    b"\x00\x13": ("PL_CDR2_LE", "little"),
    b"\x00\x14": ("D_CDR2_BE", "big"),
    b"\x00\x15": ("D_CDR2_LE", "little"),
}

_PARAMETERS = {
    0x0000: "PID_PAD",
    0x0001: "PID_SENTINEL",
    0x0005: "PID_TOPIC_NAME",
    0x0007: "PID_TYPE_NAME",
    0x0015: "PID_PROTOCOL_VERSION",
    0x0016: "PID_VENDOR_ID",
    0x002F: "PID_UNICAST_LOCATOR",
    0x0030: "PID_MULTICAST_LOCATOR",
    0x0050: "PID_PARTICIPANT_GUID",
    0x0058: "PID_ENDPOINT_GUID",
    0x0070: "PID_KEY_HASH",
    0x0071: "PID_STATUS_INFO",
}


def _blob(value: Any) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecDDSRTPSError("input must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > MAX_INPUT:
            raise SecDDSRTPSError("input exceeds 16 MiB limit")
        data = bytes(value)
    except SecDDSRTPSError:
        raise
    except Exception as exc:
        raise SecDDSRTPSError("cannot copy input bytes") from exc
    if not data:
        raise SecDDSRTPSError("input is empty")
    return data


def _need(data: bytes, offset: int, size: int, label: str) -> None:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        raise SecDDSRTPSError(f"truncated {label} at offset {offset}")


def _uint(data: bytes, offset: int, size: int, endian: str, label: str) -> int:
    _need(data, offset, size, label)
    return int.from_bytes(data[offset:offset + size], endian)


def _sint(data: bytes, offset: int, size: int, endian: str, label: str) -> int:
    _need(data, offset, size, label)
    return int.from_bytes(data[offset:offset + size], endian, signed=True)


def _opaque(data: bytes) -> dict[str, Any]:
    preview = data[:MAX_PREVIEW]
    return {
        "length": len(data),
        "preview_hex": preview.hex(),
        "preview_ascii": "".join(chr(x) if 0x20 <= x <= 0x7E else "." for x in preview),
        "preview_truncated": len(data) > len(preview),
    }


def _entity(raw: bytes) -> dict[str, Any]:
    _need(raw, 0, 4, "EntityId")
    return {"hex": raw[:4].hex(), "key_hex": raw[:3].hex(), "kind": raw[3]}


def _sequence(data: bytes, offset: int, endian: str, label: str) -> tuple[dict[str, Any], int]:
    high = _sint(data, offset, 4, endian, label + " high")
    low = _uint(data, offset + 4, 4, endian, label + " low")
    value = high * (1 << 32) + low
    return {"high": high, "low": low, "value": value}, offset + 8


def _sequence_set(data: bytes, offset: int, endian: str, label: str) -> tuple[dict[str, Any], int]:
    base, cursor = _sequence(data, offset, endian, label + " base")
    if base["value"] < 1:
        raise SecDDSRTPSError(label + " base must be positive")
    num_bits = _uint(data, cursor, 4, endian, label + " numBits")
    cursor += 4
    if num_bits > 256:
        raise SecDDSRTPSError(label + " numBits exceeds 256")
    count = (num_bits + 31) // 32
    _need(data, cursor, count * 4, label + " bitmap")
    words = [_uint(data, cursor + 4 * i, 4, endian, label + " bitmap word") for i in range(count)]
    selected = []
    for index in range(num_bits):
        if words[index // 32] & (1 << (31 - index % 32)):
            selected.append(base["value"] + index)
    return {
        "bitmap_base": base,
        "num_bits": num_bits,
        "bitmap_words": [f"0x{word:08x}" for word in words],
        "selected": selected,
    }, cursor + count * 4


def _parameter_list(data: bytes, offset: int, endian: str) -> tuple[list[dict[str, Any]], int]:
    start = offset
    parameters: list[dict[str, Any]] = []
    while True:
        if len(parameters) >= MAX_PARAMETERS:
            raise SecDDSRTPSError("ParameterList item limit exceeded")
        if (offset - start) % 4:
            raise SecDDSRTPSError("ParameterList item is not four-byte aligned")
        _need(data, offset, 4, "ParameterList header")
        pid = _uint(data, offset, 2, endian, "parameter id")
        length = _uint(data, offset + 2, 2, endian, "parameter length")
        offset += 4
        if pid == 0x0001:
            parameters.append({"id": pid, "name": "PID_SENTINEL", "length": length})
            return parameters, offset
        if length % 4:
            raise SecDDSRTPSError("parameter length is not a multiple of four")
        _need(data, offset, length, "parameter value")
        value = data[offset:offset + length]
        parameters.append({
            "id": pid,
            "id_hex": f"0x{pid:04x}",
            "name": _PARAMETERS.get(pid, "UNKNOWN"),
            "length": length,
            "must_understand": bool(pid & 0x4000),
            "vendor_specific": bool(pid & 0x8000),
            "value": _opaque(value),
        })
        offset += length


def _serialized_payload(data: bytes) -> dict[str, Any]:
    _need(data, 0, 4, "SerializedPayload header")
    identifier = data[:2]
    known = _REPRESENTATIONS.get(identifier)
    result: dict[str, Any] = {
        "representation_id_hex": identifier.hex(),
        "representation": known[0] if known else "UNKNOWN",
        "options_hex": data[2:4].hex(),
        "data": _opaque(data[4:]),
        "schema_required": True,
    }
    if not known:
        result["finding"] = "unknown serialized-payload representation"
        return result
    name, endian = known
    body = data[4:]
    if name in {"PL_CDR_BE", "PL_CDR_LE"}:
        parameters, end = _parameter_list(body, 0, endian or "big")
        if end != len(body):
            result["trailing"] = _opaque(body[end:])
        result["parameters"] = parameters
    elif name == "XML":
        result["text_preview"] = body[:MAX_PREVIEW].decode("utf-8", "replace")
    elif name.startswith(("PL_CDR2_", "D_CDR2_")) and endian and len(body) >= 4:
        # XCDR2 mutable/delimited encodings use DHEADER/EMHEADER records, not the
        # RTPS/XCDR1 ParameterList grammar.  Without type metadata only the
        # leading delimiter is sound to expose.
        result["delimiter_size"] = int.from_bytes(body[:4], endian)
    elif endian and len(body) >= 4:
        result["scalar_preview"] = {
            "u32": int.from_bytes(body[:4], endian),
            "i32": int.from_bytes(body[:4], endian, signed=True),
        }
        if len(body) >= 8:
            result["scalar_preview"]["u64"] = int.from_bytes(body[:8], endian)
    return result


def _locator_list(data: bytes, offset: int, endian: str, label: str) -> tuple[list[dict[str, Any]], int]:
    count = _uint(data, offset, 4, endian, label + " count")
    offset += 4
    if count > MAX_LOCATORS:
        raise SecDDSRTPSError(label + " exceeds the eight-locator bound")
    _need(data, offset, count * 24, label)
    values = []
    for _ in range(count):
        kind = _sint(data, offset, 4, endian, "locator kind")
        port = _uint(data, offset + 4, 4, endian, "locator port")
        address = data[offset + 8:offset + 24]
        item = {"kind": kind, "port": port, "address_hex": address.hex()}
        if kind == 1:
            item["ipv4"] = ".".join(str(x) for x in address[-4:])
        values.append(item)
        offset += 24
    return values, offset


def _exact(body: bytes, size: int, label: str) -> None:
    if len(body) != size:
        raise SecDDSRTPSError(f"{label} body must be {size} bytes, got {len(body)}")


def _rtps_body(kind: int, flags: int, body: bytes, endian: str) -> dict[str, Any]:
    if kind == 0x06:  # ACKNACK
        _need(body, 0, 20, "ACKNACK fixed fields")
        state, cursor = _sequence_set(body, 8, endian, "ACKNACK reader state")
        _need(body, cursor, 4, "ACKNACK count")
        if cursor + 4 != len(body):
            raise SecDDSRTPSError("ACKNACK has trailing bytes")
        return {"final": bool(flags & 2), "reader_id": _entity(body[:4]),
                "writer_id": _entity(body[4:8]), "reader_state": state,
                "count": _sint(body, cursor, 4, endian, "ACKNACK count")}
    if kind == 0x07:  # HEARTBEAT
        _need(body, 0, 28, "HEARTBEAT")
        first, _ = _sequence(body, 8, endian, "HEARTBEAT firstSN")
        last, _ = _sequence(body, 16, endian, "HEARTBEAT lastSN")
        if first["value"] < 1 or last["value"] < 0 or last["value"] < first["value"] - 1:
            raise SecDDSRTPSError("invalid HEARTBEAT sequence range")
        out: dict[str, Any] = {"final": bool(flags & 2), "liveliness": bool(flags & 4),
            "group_info": bool(flags & 8), "reader_id": _entity(body[:4]),
            "writer_id": _entity(body[4:8]), "first_sn": first, "last_sn": last,
            "count": _sint(body, 24, 4, endian, "HEARTBEAT count")}
        cursor = 28
        if flags & 8:
            _need(body, cursor, 24, "HEARTBEAT group sequence fields")
            for key in ("current_gsn", "first_gsn", "last_gsn"):
                out[key], cursor = _sequence(body, cursor, endian, "HEARTBEAT " + key)
        if cursor < len(body):
            out["trailing"] = _opaque(body[cursor:])
        return out
    if kind == 0x08:  # GAP
        _need(body, 0, 28, "GAP")
        gap_start, _ = _sequence(body, 8, endian, "GAP start")
        if gap_start["value"] < 1:
            raise SecDDSRTPSError("GAP start must be positive")
        gap_list, cursor = _sequence_set(body, 16, endian, "GAP list")
        out = {"group_info": bool(flags & 2), "filtered_count_present": bool(flags & 4),
            "reader_id": _entity(body[:4]), "writer_id": _entity(body[4:8]),
            "gap_start": gap_start, "gap_list": gap_list}
        if flags & 2:
            out["gap_start_gsn"], cursor = _sequence(body, cursor, endian, "GAP start GSN")
            out["gap_end_gsn"], cursor = _sequence(body, cursor, endian, "GAP end GSN")
        if flags & 4:
            high = _sint(body, cursor, 4, endian, "GAP filtered count high")
            low = _uint(body, cursor + 4, 4, endian, "GAP filtered count low")
            out["filtered_count"] = {"high": high, "low": low, "value": high * (1 << 32) + low}
            cursor += 8
        if cursor != len(body):
            raise SecDDSRTPSError("GAP has trailing bytes")
        return out
    if kind == 0x09:  # INFO_TS
        invalid = bool(flags & 2)
        _exact(body, 0 if invalid else 8, "INFO_TS")
        if invalid:
            return {"invalidated": True}
        seconds = _sint(body, 0, 4, endian, "timestamp seconds")
        fraction = _uint(body, 4, 4, endian, "timestamp fraction")
        return {"invalidated": False, "seconds": seconds, "fraction": fraction,
                "nanoseconds_approx": (fraction * 1_000_000_000) >> 32}
    if kind == 0x0C:  # INFO_SRC
        _exact(body, 20, "INFO_SRC")
        return {"unused": _uint(body, 0, 4, endian, "INFO_SRC unused"),
                "protocol_version": {"major": body[4], "minor": body[5]},
                "vendor_id": body[6:8].hex(), "guid_prefix": body[8:20].hex()}
    if kind == 0x0E:  # INFO_DST
        _exact(body, 12, "INFO_DST")
        return {"guid_prefix": body.hex()}
    if kind == 0x0D:  # INFO_REPLY_IP4
        expected = 16 if flags & 2 else 8
        _exact(body, expected, "INFO_REPLY_IP4")
        locators = []
        for offset in range(0, expected, 8):
            raw = body[offset:offset + 4]
            locators.append({"address_hex": raw.hex(), "ipv4": ".".join(str(x) for x in raw),
                             "port": _uint(body, offset + 4, 4, endian, "IPv4 locator port")})
        return {"multicast_present": bool(flags & 2), "unicast": locators[0],
                **({"multicast": locators[1]} if len(locators) == 2 else {})}
    if kind == 0x0F:  # INFO_REPLY
        unicast, cursor = _locator_list(body, 0, endian, "unicast LocatorList")
        out = {"multicast_present": bool(flags & 2), "unicast_locators": unicast}
        if flags & 2:
            out["multicast_locators"], cursor = _locator_list(body, cursor, endian, "multicast LocatorList")
        if cursor != len(body):
            raise SecDDSRTPSError("INFO_REPLY has trailing bytes")
        return out
    if kind == 0x15:  # DATA
        _need(body, 0, 20, "DATA fixed fields")
        extra = _uint(body, 0, 2, endian, "DATA extraFlags")
        skip = _uint(body, 2, 2, endian, "DATA octetsToInlineQos")
        if skip < 16 or 4 + skip > len(body):
            raise SecDDSRTPSError("DATA octetsToInlineQos is outside the body")
        writer_sn, _ = _sequence(body, 12, endian, "DATA writerSN")
        if writer_sn["value"] < 1:
            raise SecDDSRTPSError("DATA writerSN must be positive")
        q, d, k, n = bool(flags & 2), bool(flags & 4), bool(flags & 8), bool(flags & 16)
        if d and k:
            raise SecDDSRTPSError("DATA cannot set both data and key flags")
        cursor = 4 + skip
        out: dict[str, Any] = {"extra_flags": extra, "octets_to_inline_qos": skip,
            "inline_qos_present": q, "data_present": d, "key_present": k,
            "nonstandard_payload": n, "reader_id": _entity(body[4:8]),
            "writer_id": _entity(body[8:12]), "writer_sn": writer_sn}
        if skip > 16:
            out["header_extension"] = _opaque(body[20:cursor])
        if q:
            out["inline_qos"], cursor = _parameter_list(body, cursor, endian)
        if d or k:
            payload = body[cursor:]
            if not payload:
                raise SecDDSRTPSError("DATA payload flag is set but payload is empty")
            out["payload_kind"] = "key" if k else "data"
            out["serialized_payload"] = _opaque(payload) if n else _serialized_payload(payload)
            cursor = len(body)
        if cursor < len(body):
            out["trailing"] = _opaque(body[cursor:])
        return out
    if kind == 0x16:  # DATA_FRAG
        _need(body, 0, 32, "DATA_FRAG fixed fields")
        skip = _uint(body, 2, 2, endian, "DATA_FRAG octetsToInlineQos")
        if skip < 28 or 4 + skip > len(body):
            raise SecDDSRTPSError("DATA_FRAG octetsToInlineQos is outside the body")
        writer_sn, _ = _sequence(body, 12, endian, "DATA_FRAG writerSN")
        if writer_sn["value"] < 1:
            raise SecDDSRTPSError("DATA_FRAG writerSN must be positive")
        cursor = 4 + skip
        out = {"inline_qos_present": bool(flags & 2), "key_present": bool(flags & 4),
            "nonstandard_payload": bool(flags & 8), "reader_id": _entity(body[4:8]),
            "writer_id": _entity(body[8:12]), "writer_sn": writer_sn,
            "fragment_starting_number": _uint(body, 20, 4, endian, "fragment start"),
            "fragments_in_submessage": _uint(body, 24, 2, endian, "fragment count"),
            "fragment_size": _uint(body, 26, 2, endian, "fragment size"),
            "sample_size": _uint(body, 28, 4, endian, "sample size")}
        if flags & 2:
            out["inline_qos"], cursor = _parameter_list(body, cursor, endian)
        out["fragment_payload"] = _opaque(body[cursor:])
        return out
    if kind == 0x12:  # NACK_FRAG
        _need(body, 0, 28, "NACK_FRAG")
        writer_sn, _ = _sequence(body, 8, endian, "NACK_FRAG writerSN")
        state, cursor = _fragment_set(body, 16, endian, "NACK_FRAG state")
        _need(body, cursor, 4, "NACK_FRAG count")
        if cursor + 4 != len(body):
            raise SecDDSRTPSError("NACK_FRAG has trailing bytes")
        return {"reader_id": _entity(body[:4]), "writer_id": _entity(body[4:8]),
                "writer_sn": writer_sn, "fragment_state": state,
                "count": _sint(body, cursor, 4, endian, "NACK_FRAG count")}
    if kind == 0x13:  # HEARTBEAT_FRAG
        _exact(body, 24, "HEARTBEAT_FRAG")
        writer_sn, _ = _sequence(body, 8, endian, "HEARTBEAT_FRAG writerSN")
        return {"reader_id": _entity(body[:4]), "writer_id": _entity(body[4:8]),
                "writer_sn": writer_sn,
                "last_fragment_number": _uint(body, 16, 4, endian, "last fragment"),
                "count": _sint(body, 20, 4, endian, "HEARTBEAT_FRAG count")}
    return {"opaque": _opaque(body)}


def _fragment_set(data: bytes, offset: int, endian: str, label: str) -> tuple[dict[str, Any], int]:
    base = _uint(data, offset, 4, endian, label + " base")
    num_bits = _uint(data, offset + 4, 4, endian, label + " numBits")
    if base < 1 or num_bits > 256:
        raise SecDDSRTPSError("invalid FragmentNumberSet")
    count = (num_bits + 31) // 32
    _need(data, offset + 8, count * 4, label + " bitmap")
    words = [_uint(data, offset + 8 + i * 4, 4, endian, label + " word") for i in range(count)]
    selected = [base + i for i in range(num_bits) if words[i // 32] & (1 << (31 - i % 32))]
    return {"bitmap_base": base, "num_bits": num_bits,
            "bitmap_words": [f"0x{x:08x}" for x in words], "selected": selected}, offset + 8 + count * 4


def _parse_rtps(data: bytes) -> dict[str, Any]:
    _need(data, 0, 20, "RTPS header")
    if data[:4] != b"RTPS":
        raise SecDDSRTPSError("RTPS magic is missing")
    if data[4] != 2:
        raise SecDDSRTPSError("unsupported RTPS major version")
    if len(data) == 20:
        raise SecDDSRTPSError("RTPS message has no submessages")
    vendor = data[6:8].hex()
    result: dict[str, Any] = {"format": "DDSI-RTPS", "length": len(data),
        "header": {"magic": "RTPS", "protocol_version": {"major": data[4], "minor": data[5]},
                   "vendor_id": vendor, "vendor_name": _VENDORS.get(vendor, "unknown"),
                   "guid_prefix": data[8:20].hex()}, "submessages": [], "findings": []}
    offset = 20
    while offset < len(data):
        if len(result["submessages"]) >= MAX_SUBMESSAGES:
            raise SecDDSRTPSError("RTPS submessage limit exceeded")
        if offset % 4:
            raise SecDDSRTPSError("RTPS submessage header is not four-byte aligned")
        _need(data, offset, 4, "RTPS submessage header")
        kind, flags = data[offset], data[offset + 1]
        endian = "little" if flags & 1 else "big"
        length = _uint(data, offset + 2, 2, endian, "octetsToNextHeader")
        if length == 0 and kind not in (0x01, 0x09):
            end = len(data)
        else:
            end = offset + 4 + length
            _need(data, offset + 4, length, "RTPS submessage body")
        if end < len(data) and end % 4:
            raise SecDDSRTPSError("next RTPS submessage is not four-byte aligned")
        body = data[offset + 4:end]
        item = {"offset": offset, "id": kind, "id_hex": f"0x{kind:02x}",
                "name": _RTPS_KINDS.get(kind, "VENDOR_SPECIFIC" if kind >= 0x80 else "UNKNOWN"),
                "flags": flags, "endianness": endian, "body_length": len(body),
                "declared_length": length}
        item.update(_rtps_body(kind, flags, body, endian))
        result["submessages"].append(item)
        offset = end
    if result["header"]["protocol_version"]["minor"] > 5:
        result["findings"].append("future RTPS 2.x minor version; unknown extensions may be opaque")
    return result


def parse_rtps(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one raw DDSI-RTPS message."""
    try:
        return _parse_rtps(_blob(data))
    except SecDDSRTPSError:
        raise
    except Exception as exc:
        raise SecDDSRTPSError("malformed RTPS message") from exc


_XRCE_DATA_FORMATS = {
    0x0: "FORMAT_DATA", 0x1: "FORMAT_DATA", 0x2: "FORMAT_SAMPLE", 0x3: "FORMAT_SAMPLE",
    0x8: "FORMAT_DATA_SEQ", 0x9: "FORMAT_DATA_SEQ", 0xA: "FORMAT_SAMPLE_SEQ",
    0xB: "FORMAT_SAMPLE_SEQ", 0xE: "FORMAT_PACKED_SAMPLES", 0xF: "FORMAT_PACKED_SAMPLES",
}


def _xrce_time(data: bytes, offset: int, endian: str, label: str) -> dict[str, Any]:
    seconds = _sint(data, offset, 4, endian, label + " seconds")
    nanoseconds = _uint(data, offset + 4, 4, endian, label + " nanoseconds")
    return {"seconds": seconds, "nanoseconds": nanoseconds,
            "valid_nanoseconds": nanoseconds < 1_000_000_000}


def _xrce_body(kind: int, flags: int, body: bytes, endian: str, stream: int) -> dict[str, Any]:
    if kind == 0:  # CREATE_CLIENT
        _need(body, 0, 14, "CREATE_CLIENT")
        if body[:4] != b"XRCE":
            raise SecDDSRTPSError("CREATE_CLIENT XRCE cookie is missing")
        present = body[13]
        if present not in (0, 1):
            raise SecDDSRTPSError("invalid CREATE_CLIENT properties presence flag")
        out = {"cookie": "XRCE", "xrce_version": {"major": body[4], "minor": body[5]},
               "vendor_id": body[6:8].hex(), "client_key": body[8:12].hex(),
               "requested_session_id": body[12], "properties_present": bool(present)}
        rest = body[14:]
        if not present and len(rest) == 2:
            out["eprosima_mtu_extension"] = int.from_bytes(rest, endian)
        elif rest:
            out["properties_or_extension"] = _opaque(rest)
        return out
    if kind in (7, 9):  # WRITE_DATA / DATA
        _need(body, 0, 4, _XRCE_KINDS[kind])
        fmt = flags & 0x0F
        if fmt not in _XRCE_DATA_FORMATS:
            raise SecDDSRTPSError("invalid XRCE data-format flags")
        return {"data_format": _XRCE_DATA_FORMATS[fmt], "request_id": body[:2].hex(),
                "object_id": body[2:4].hex(), "serialized_data": _opaque(body[4:])}
    if kind == 10:  # ACKNACK
        if stream != 0:
            raise SecDDSRTPSError("XRCE ACKNACK must use stream 0")
        _exact(body, 5, "XRCE ACKNACK")
        first = int.from_bytes(body[:2], endian)
        bitmap = int.from_bytes(body[2:4], "big")
        return {"first_unacked": first, "nack_bitmap_hex": body[2:4].hex(),
                "missing": [(first + i) & 0xFFFF for i in range(16) if bitmap & (1 << i)],
                "target_stream_id": body[4]}
    if kind == 11:  # HEARTBEAT
        if stream != 0:
            raise SecDDSRTPSError("XRCE HEARTBEAT must use stream 0")
        _exact(body, 5, "XRCE HEARTBEAT")
        return {"first_unacked": int.from_bytes(body[:2], endian),
                "last_unacked": int.from_bytes(body[2:4], endian), "target_stream_id": body[4]}
    if kind == 12:
        _exact(body, 0, "XRCE RESET")
        return {}
    if kind == 13:
        if stream < 0x80:
            raise SecDDSRTPSError("XRCE FRAGMENT requires a reliable stream")
        return {"last_fragment": bool(flags & 2), "fragment": _opaque(body)}
    if kind == 14:
        if stream != 0:
            raise SecDDSRTPSError("XRCE TIMESTAMP must use stream 0")
        _exact(body, 8, "XRCE TIMESTAMP")
        return {"transmit_timestamp": _xrce_time(body, 0, endian, "TIMESTAMP")}
    if kind == 15:
        if stream != 0:
            raise SecDDSRTPSError("XRCE TIMESTAMP_REPLY must use stream 0")
        _exact(body, 24, "XRCE TIMESTAMP_REPLY")
        return {"transmit_timestamp": _xrce_time(body, 0, endian, "TIMESTAMP_REPLY transmit"),
                "receive_timestamp": _xrce_time(body, 8, endian, "TIMESTAMP_REPLY receive"),
                "originate_timestamp": _xrce_time(body, 16, endian, "TIMESTAMP_REPLY originate")}
    return {"opaque": _opaque(body)}


def _parse_xrce(data: bytes) -> dict[str, Any]:
    _need(data, 0, 4, "XRCE message header")
    session, stream = data[0], data[1]
    header_size = 8 if session <= 0x7F else 4
    _need(data, 0, header_size, "XRCE keyed message header")
    if len(data) == header_size:
        raise SecDDSRTPSError("XRCE message has no submessages")
    result: dict[str, Any] = {"format": "DDS-XRCE", "length": len(data),
        "header": {"session_id": session, "stream_id": stream,
                   "stream_reliability": "none" if stream == 0 else "reliable" if stream >= 0x80 else "best-effort",
                   "sequence_number": int.from_bytes(data[2:4], "little"),
                   "client_key": data[4:8].hex() if header_size == 8 else None,
                   "header_size": header_size}, "submessages": []}
    offset = header_size
    while offset < len(data):
        if len(result["submessages"]) >= MAX_SUBMESSAGES:
            raise SecDDSRTPSError("XRCE submessage limit exceeded")
        if offset % 4:
            raise SecDDSRTPSError("XRCE submessage header is not four-byte aligned")
        _need(data, offset, 4, "XRCE submessage header")
        kind, flags = data[offset], data[offset + 1]
        length = int.from_bytes(data[offset + 2:offset + 4], "little")
        end = offset + 4 + length
        _need(data, offset + 4, length, "XRCE submessage payload")
        endian = "little" if flags & 1 else "big"
        item = {"offset": offset, "id": kind, "name": _XRCE_KINDS.get(kind, "UNKNOWN"),
                "flags": flags, "endianness": endian, "payload_length": length}
        item.update(_xrce_body(kind, flags, data[offset + 4:end], endian, stream))
        padded = (end + 3) & ~3
        if end < len(data):
            _need(data, end, padded - end, "XRCE inter-submessage padding")
            item["padding_hex"] = data[end:padded].hex()
            if padded >= len(data) and padded != len(data):
                raise SecDDSRTPSError("XRCE padding consumes the end of the message")
            offset = padded
        else:
            offset = end
        result["submessages"].append(item)
    return result


def parse_xrce(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one DDS-XRCE 1.0 message."""
    try:
        return _parse_xrce(_blob(data))
    except SecDDSRTPSError:
        raise
    except Exception as exc:
        raise SecDDSRTPSError("malformed XRCE message") from exc


def analyze(data: bytes | bytearray | memoryview, *, protocol: str = "auto") -> dict[str, Any]:
    """Decode one supplied artifact as RTPS or XRCE."""
    try:
        if protocol not in {"auto", "rtps", "xrce"}:
            raise SecDDSRTPSError("protocol must be auto, rtps, or xrce")
        raw = _blob(data)
        selected = "rtps" if protocol == "auto" and raw.startswith(b"RTPS") else "xrce" if protocol == "auto" else protocol
        return _parse_rtps(raw) if selected == "rtps" else _parse_xrce(raw)
    except SecDDSRTPSError:
        raise
    except Exception as exc:
        raise SecDDSRTPSError("cannot analyze DDS evidence") from exc


def analyze_file(path: str | Path, *, protocol: str = "auto") -> dict[str, Any]:
    """Read and analyze one bounded local file."""
    try:
        if not isinstance(path, (str, Path)):
            raise SecDDSRTPSError("path must be text or pathlib.Path")
        with open(path, "rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise SecDDSRTPSError("input exceeds 16 MiB limit")
        return analyze(data, protocol=protocol)
    except SecDDSRTPSError:
        raise
    except Exception as exc:
        raise SecDDSRTPSError("cannot read DDS evidence") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="raw RTPS or XRCE transport payload")
    parser.add_argument("--protocol", choices=("auto", "rtps", "xrce"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        print(json.dumps(analyze_file(args.input, protocol=args.protocol), indent=2, sort_keys=True))
        return 0
    except SecDDSRTPSError as exc:
        print(f"sec_dds_rtps: {exc}", file=sys.stderr)
        return 2


__all__ = ["SecDDSRTPSError", "analyze", "analyze_file", "main", "parse_rtps", "parse_xrce"]


if __name__ == "__main__":
    raise SystemExit(main())
