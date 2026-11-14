#!/usr/bin/env python3
"""Passive KNX Classic, KNXnet/IP, and KNX IoT wire decoder.

The module accepts only supplied bytes.  It never opens a socket, emits a KNX
telegram, executes an artifact, or claims to decrypt KNX Secure/OSCORE data.

Public byte parsers raise :class:`SecBasKNXError` exclusively on malformed,
unsupported, or excessive input.  DPT decoding is deliberately caller-selected:
the datapoint type is ETS/project metadata and cannot be inferred from the wire.

CLI examples::

    ./.venv/bin/python solvers/toolkits/sec_bas_knx.py knxnetip frame.bin
    ./.venv/bin/python solvers/toolkits/sec_bas_knx.py cemi frame.hex --hex --dpt 1
    ./.venv/bin/python solvers/toolkits/sec_bas_knx.py coap datagram.bin
"""

from __future__ import annotations

import argparse
import datetime as _datetime
import functools
import json
import math
from pathlib import Path
import struct
import sys
from typing import Any


MAX_INPUT = 4 * 1024 * 1024
MAX_COAP_OPTIONS = 256


class SecBasKNXError(ValueError):
    """Malformed, unsupported, or over-limit KNX evidence."""


def _closed(function):
    """Translate every ordinary implementation failure to the public error."""

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except SecBasKNXError:
            raise
        except Exception as exc:
            raise SecBasKNXError(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from None

    return wrapper


def _bytes(value: object, label: str = "input", limit: int = MAX_INPUT) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecBasKNXError(f"{label} must be bytes")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > limit:
            raise SecBasKNXError(f"{label} exceeds {limit}-byte limit")
        return bytes(value)
    except SecBasKNXError:
        raise
    except Exception as exc:
        raise SecBasKNXError(f"invalid {label} buffer") from exc


def _need(data: bytes, offset: int, size: int, label: str) -> None:
    if type(offset) is not int or type(size) is not int or offset < 0 or size < 0:
        raise SecBasKNXError(f"invalid {label} bounds")
    if offset > len(data) or size > len(data) - offset:
        raise SecBasKNXError(f"truncated {label}")


def _u16(data: bytes, offset: int) -> int:
    _need(data, offset, 2, "16-bit field")
    return int.from_bytes(data[offset : offset + 2], "big")


def _individual_address(value: int) -> str:
    return f"{(value >> 12) & 15}.{(value >> 8) & 15}.{value & 255}"


def _group_addresses(value: int) -> dict[str, object]:
    return {
        "raw": value,
        "three_level": f"{(value >> 11) & 31}/{(value >> 8) & 7}/{value & 255}",
        "two_level": f"{(value >> 11) & 31}/{value & 0x7ff}",
        "free": value,
        "broadcast": value == 0,
    }


_CEMI_CODES = {
    0x11: "L_Data.req",
    0x29: "L_Data.ind",
    0x2E: "L_Data.con",
}
_PRIORITIES = {0: "system", 1: "normal", 2: "urgent", 3: "low"}
_TPCI_TYPES = {
    0: "unnumbered-data",
    1: "numbered-data",
    2: "unnumbered-control",
    3: "numbered-control",
}
_GROUP_APCI = {
    0x000: "GroupValueRead",
    0x040: "GroupValueResponse",
    0x080: "GroupValueWrite",
}


def _parse_additional_information(raw: bytes) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    offset = 0
    while offset < len(raw):
        if len(rows) >= 64:
            raise SecBasKNXError("too many cEMI additional-information blocks")
        _need(raw, offset, 2, "cEMI additional-information header")
        info_type, length = raw[offset], raw[offset + 1]
        offset += 2
        _need(raw, offset, length, "cEMI additional-information value")
        value = raw[offset : offset + length]
        offset += length
        rows.append({"type": info_type, "length": length, "value_hex": value.hex()})
    return rows


def _dpt_payload(tpdu: bytes, dpt: str) -> bytes:
    """Select the DPT bytes without pretending the DPT came from the wire."""

    ident = _normalise_dpt(dpt)
    family = ident.split(".", 1)[0]
    if family in {"1", "2", "3"}:
        return bytes((tpdu[1] & 0x3F,))
    if len(tpdu) <= 2:
        raise SecBasKNXError(f"DPT {dpt} requires an extended group-value payload")
    if tpdu[1] & 0x3F:
        raise SecBasKNXError("nonzero short-data bits before extended DPT payload")
    return tpdu[2:]


def _parse_data_secure(tpdu: bytes) -> dict[str, object]:
    if len(tpdu) < 13:  # two APCI octets + SCF + SeqNr(6) + at least MAC(4)
        raise SecBasKNXError("truncated KNX Data Secure APDU")
    body = tpdu[2:]
    scf = body[0]
    sai = (scf >> 4) & 7
    if sai not in (0, 1):
        raise SecBasKNXError("reserved KNX Data Secure algorithm identifier")
    subtype = scf & 7
    if subtype not in (0, 2, 3):
        raise SecBasKNXError("reserved KNX Data Secure service subtype")
    return {
        "kind": "knx-data-secure",
        "security_control": scf,
        "tool_access": bool(scf & 0x80),
        "algorithm": "aes-ccm-authentication" if sai == 0 else "aes-ccm-authentication-confidentiality",
        "system_broadcast": bool(scf & 0x08),
        "service": {0: "S-A_Data", 2: "S-A_Sync_Req", 3: "S-A_Sync_Res"}[subtype],
        "sequence_number": int.from_bytes(body[1:7], "big"),
        "protected_data_hex": body[7:-4].hex(),
        "mac_hex": body[-4:].hex(),
        "authenticated": None,
        "decrypted": False,
        "note": "ciphertext/authentication metadata only; no key or security context was applied",
    }


@_closed
def parse_cemi(data: bytes, *, dpt: str | None = None) -> dict[str, object]:
    """Parse one exact cEMI L_Data request, indication, or confirmation."""

    raw = _bytes(data, "cEMI frame")
    _need(raw, 0, 10, "cEMI L_Data frame")
    code = raw[0]
    if code not in _CEMI_CODES:
        raise SecBasKNXError(f"unsupported cEMI message code 0x{code:02x}")
    additional_length = raw[1]
    control_offset = 2 + additional_length
    _need(raw, control_offset, 8, "cEMI L_Data body")
    control1, control2 = raw[control_offset], raw[control_offset + 1]
    source = _u16(raw, control_offset + 2)
    destination = _u16(raw, control_offset + 4)
    npdu_length = raw[control_offset + 6]
    expected = control_offset + 8 + npdu_length
    if len(raw) != expected:
        raise SecBasKNXError("cEMI NPDU length does not match standalone frame")
    tpdu = raw[control_offset + 7 :]
    if not tpdu:
        raise SecBasKNXError("empty cEMI TPDU")
    group = bool(control2 & 0x80)
    result: dict[str, object] = {
        "protocol": "knx-cemi",
        "message_code": code,
        "message": _CEMI_CODES[code],
        "additional_information": _parse_additional_information(raw[2:control_offset]),
        "control1": {
            "raw": control1,
            "standard_frame": bool(control1 & 0x80),
            "reserved_bit": bool(control1 & 0x40),
            "repeat": not bool(control1 & 0x20),
            "domain_broadcast": bool(control1 & 0x10),
            "priority": _PRIORITIES[(control1 >> 2) & 3],
            "ack_requested": bool(control1 & 0x02),
            "confirmation_error": bool(control1 & 0x01),
        },
        "control2": {
            "raw": control2,
            "destination_type": "group" if group else "individual",
            "hop_count": (control2 >> 4) & 7,
            "extended_frame_format": control2 & 15,
        },
        "source": {"raw": source, "individual": _individual_address(source)},
        "destination": _group_addresses(destination)
        if group
        else {"raw": destination, "individual": _individual_address(destination)},
        "npdu_length": npdu_length,
        "tpdu_hex": tpdu.hex(),
        "tpci": {
            "raw": tpdu[0] & 0xFC,
            "type": _TPCI_TYPES[tpdu[0] >> 6],
        },
    }
    if len(tpdu) >= 2:
        raw_apci = ((tpdu[0] & 3) << 8) | tpdu[1]
        service_key = raw_apci & 0x3C0
        apci: dict[str, object] = {"raw": raw_apci}
        if service_key in _GROUP_APCI:
            if not group:
                raise SecBasKNXError("group-value APCI requires a group destination")
            apci.update(
                service=_GROUP_APCI[service_key],
                short_data=tpdu[1] & 0x3F,
                extended_data_hex=tpdu[2:].hex(),
            )
        elif raw_apci == 0x3F1:
            apci["service"] = "SecureService"
            result["data_secure"] = _parse_data_secure(tpdu)
        else:
            apci["service"] = f"APCI-0x{raw_apci:03x}"
        result["apci"] = apci
        if dpt is not None:
            if service_key not in _GROUP_APCI:
                raise SecBasKNXError("DPT decoding requires a group-value APDU")
            if _GROUP_APCI[service_key] == "GroupValueRead":
                raise SecBasKNXError("GroupValueRead carries no datapoint value")
            result["dpt"] = decode_dpt(_dpt_payload(tpdu, dpt), dpt)
    elif dpt is not None:
        raise SecBasKNXError("DPT decoding requires a two-octet APDU")
    return result


def _normalise_dpt(dpt: object) -> str:
    if not isinstance(dpt, str):
        raise SecBasKNXError("DPT identifier must be a string")
    value = dpt.strip().upper()
    if value.startswith("DPT"):
        value = value[3:].lstrip(" -_")
    if not value or len(value) > 16 or any(ch not in "0123456789." for ch in value):
        raise SecBasKNXError("invalid DPT identifier")
    pieces = value.split(".")
    if len(pieces) > 2 or any(not part for part in pieces):
        raise SecBasKNXError("invalid DPT identifier")
    main = int(pieces[0], 10)
    if not 0 < main <= 999:
        raise SecBasKNXError("DPT family is out of range")
    if len(pieces) == 1:
        return str(main)
    subtype = int(pieces[1], 10)
    if subtype > 999:
        raise SecBasKNXError("DPT subtype is out of range")
    return f"{main}.{subtype:03d}"


@_closed
def decode_dpt(data: bytes, dpt: str) -> dict[str, object]:
    """Decode one explicitly selected common KNX datapoint value."""

    raw = _bytes(data, "DPT value", 1024)
    ident = _normalise_dpt(dpt)
    family = ident.split(".", 1)[0]
    result: dict[str, object] = {"dpt": ident, "raw_hex": raw.hex()}

    if family == "1":
        if len(raw) != 1 or raw[0] & 0xFE:
            raise SecBasKNXError("DPT 1 requires one canonical Boolean bit")
        result.update(type="boolean", value=bool(raw[0]))
    elif family == "2":
        if len(raw) != 1 or raw[0] & 0xFC:
            raise SecBasKNXError("DPT 2 requires two canonical bits")
        result.update(type="controlled-boolean", control=bool(raw[0] & 2), value=bool(raw[0] & 1))
    elif family == "3":
        if len(raw) != 1 or raw[0] & 0xF0:
            raise SecBasKNXError("DPT 3 requires four canonical bits")
        result.update(type="control-step", control=bool(raw[0] & 8), step=raw[0] & 7)
    elif family == "5":
        if ident not in ("5", "5.001"):
            raise SecBasKNXError("only DPT 5.001 scaling is supported")
        if len(raw) != 1:
            raise SecBasKNXError("DPT 5.001 requires one octet")
        result.update(type="scaling", value=raw[0] * 100.0 / 255.0, unit="percent")
    elif family == "6":
        if len(raw) != 1:
            raise SecBasKNXError("DPT 6 requires one octet")
        result.update(type="signed-8", value=int.from_bytes(raw, "big", signed=True))
    elif family in ("7", "8"):
        if len(raw) != 2:
            raise SecBasKNXError(f"DPT {family} requires two octets")
        result.update(
            type="unsigned-16" if family == "7" else "signed-16",
            value=int.from_bytes(raw, "big", signed=family == "8"),
        )
    elif family == "9":
        if len(raw) != 2:
            raise SecBasKNXError("DPT 9 requires two octets")
        word = int.from_bytes(raw, "big")
        if word == 0x7FFF:
            result.update(type="knx-float16", value=None, invalid=True)
        else:
            exponent = (word >> 11) & 15
            mantissa = word & 0x7FF
            if word & 0x8000:
                mantissa -= 2048
            result.update(
                type="knx-float16",
                exponent=exponent,
                mantissa=mantissa,
                value=0.01 * mantissa * (1 << exponent),
            )
    elif family == "10":
        if len(raw) != 3 or raw[1] & 0xC0 or raw[2] & 0xC0:
            raise SecBasKNXError("invalid DPT 10 time encoding")
        weekday, hour, minute, second = raw[0] >> 5, raw[0] & 31, raw[1] & 63, raw[2] & 63
        if weekday > 7 or hour > 23 or minute > 59 or second > 59:
            raise SecBasKNXError("DPT 10 time field out of range")
        result.update(type="time", weekday=weekday, hour=hour, minute=minute, second=second,
                      value=f"{hour:02d}:{minute:02d}:{second:02d}")
    elif family == "11":
        if len(raw) != 3 or raw[0] & 0xE0 or raw[1] & 0xF0 or raw[2] & 0x80:
            raise SecBasKNXError("invalid DPT 11 date encoding")
        day, month, encoded_year = raw[0] & 31, raw[1] & 15, raw[2] & 127
        if encoded_year > 99:
            raise SecBasKNXError("reserved DPT 11 year encoding")
        year = 1900 + encoded_year if encoded_year >= 90 else 2000 + encoded_year
        date = _datetime.date(year, month, day)
        result.update(type="date", year=year, month=month, day=day, value=date.isoformat())
    elif family in ("12", "13"):
        if len(raw) != 4:
            raise SecBasKNXError(f"DPT {family} requires four octets")
        result.update(
            type="unsigned-32" if family == "12" else "signed-32",
            value=int.from_bytes(raw, "big", signed=family == "13"),
        )
    elif family == "14":
        if len(raw) != 4:
            raise SecBasKNXError("DPT 14 requires four octets")
        value = struct.unpack(">f", raw)[0]
        if not math.isfinite(value):
            raise SecBasKNXError("non-finite DPT 14 value")
        result.update(type="ieee-float32", value=value)
    elif family == "16":
        if len(raw) != 14:
            raise SecBasKNXError("DPT 16 requires fourteen octets")
        if ident in ("16", "16.000"):
            codec = "ascii"
        elif ident == "16.001":
            codec = "latin-1"
        else:
            raise SecBasKNXError("only DPT 16.000 and 16.001 text are supported")
        try:
            text = raw.rstrip(b"\x00").decode(codec)
        except UnicodeDecodeError as exc:
            raise SecBasKNXError(f"invalid DPT 16 {codec} text") from exc
        result.update(type="fixed-text", encoding=codec, value=text)
    elif family == "17":
        if len(raw) != 1 or raw[0] & 0xC0:
            raise SecBasKNXError("invalid DPT 17 scene number")
        result.update(type="scene", value=raw[0] & 63)
    elif family == "18":
        if len(raw) != 1 or raw[0] & 0x40:
            raise SecBasKNXError("invalid DPT 18 scene control")
        result.update(type="scene-control", control=bool(raw[0] & 0x80), scene=raw[0] & 63)
    elif family == "20":
        if len(raw) != 1:
            raise SecBasKNXError("DPT 20 requires one octet")
        result.update(type="enumeration", value=raw[0])
    elif family == "232":
        if len(raw) != 3:
            raise SecBasKNXError("DPT 232 RGB requires three octets")
        result.update(type="rgb", red=raw[0], green=raw[1], blue=raw[2])
    else:
        raise SecBasKNXError(f"unsupported DPT family {family}")
    return result


_KNXIP_SERVICES = {
    0x0201: "SEARCH_REQUEST",
    0x0202: "SEARCH_RESPONSE",
    0x0203: "DESCRIPTION_REQUEST",
    0x0204: "DESCRIPTION_RESPONSE",
    0x0205: "CONNECT_REQUEST",
    0x0206: "CONNECT_RESPONSE",
    0x0207: "CONNECTIONSTATE_REQUEST",
    0x0208: "CONNECTIONSTATE_RESPONSE",
    0x0209: "DISCONNECT_REQUEST",
    0x020A: "DISCONNECT_RESPONSE",
    0x0310: "DEVICE_CONFIGURATION_REQUEST",
    0x0311: "DEVICE_CONFIGURATION_ACK",
    0x0420: "TUNNELLING_REQUEST",
    0x0421: "TUNNELLING_ACK",
    0x0422: "TUNNELLING_FEATURE_GET",
    0x0423: "TUNNELLING_FEATURE_RESPONSE",
    0x0424: "TUNNELLING_FEATURE_SET",
    0x0425: "TUNNELLING_FEATURE_INFO",
    0x0530: "ROUTING_INDICATION",
    0x0531: "ROUTING_LOST_MESSAGE",
    0x0532: "ROUTING_BUSY",
    0x0533: "ROUTING_SYSTEM_BROADCAST",
    0x0950: "SECURE_WRAPPER",
    0x0951: "SESSION_REQUEST",
    0x0952: "SESSION_RESPONSE",
    0x0953: "SESSION_AUTHENTICATE",
    0x0954: "SESSION_STATUS",
    0x0955: "TIMER_NOTIFY",
}


def _parse_hpai(raw: bytes) -> dict[str, object]:
    if len(raw) != 8 or raw[0] != 8:
        raise SecBasKNXError("invalid KNXnet/IP HPAI")
    return {
        "structure_length": raw[0],
        "host_protocol": raw[1],
        "ipv4": ".".join(str(value) for value in raw[2:6]),
        "port": int.from_bytes(raw[6:8], "big"),
        "route_back": raw[2:] == b"\x00" * 6,
    }


def _secure_knxip(service: int, body: bytes) -> dict[str, object]:
    if service == 0x0950:
        if len(body) < 38:  # fixed 16 + inner >= 6 + MAC 16
            raise SecBasKNXError("truncated KNX IP Secure wrapper")
        session_id = int.from_bytes(body[0:2], "big")
        tag = int.from_bytes(body[14:16], "big")
        if session_id != 0 and tag != 0:
            raise SecBasKNXError("secure-session wrapper requires a zero message tag")
        return {
            "session_id": session_id,
            "mode": "secure-routing-multicast" if session_id == 0 else "secure-session-unicast",
            "sequence_information": int.from_bytes(body[2:8], "big"),
            "serial_number_hex": body[8:14].hex(),
            "message_tag": tag,
            "encrypted_inner_hex": body[16:-16].hex(),
            "encrypted_mac_hex": body[-16:].hex(),
            "authenticated": None,
            "decrypted": False,
            "note": "AES-CCM protected bytes retained; no key/session state was applied",
        }
    if service == 0x0951:
        if len(body) != 40:
            raise SecBasKNXError("SESSION_REQUEST must have a 40-byte body")
        hpai = _parse_hpai(body[:8])
        if hpai["host_protocol"] != 2 or not hpai["route_back"]:
            raise SecBasKNXError("SESSION_REQUEST requires a TCP route-back HPAI")
        return {"hpai": hpai, "client_public_key_hex": body[8:].hex(),
                "key_agreement": "Curve25519"}
    if service == 0x0952:
        if len(body) != 50:
            raise SecBasKNXError("SESSION_RESPONSE must have a 50-byte body")
        return {"session_id": int.from_bytes(body[:2], "big"),
                "server_public_key_hex": body[2:34].hex(), "ccm_mac_hex": body[34:].hex(),
                "key_agreement": "Curve25519", "authenticated": None}
    if service == 0x0953:
        if len(body) != 18 or body[0] != 0:
            raise SecBasKNXError("invalid SESSION_AUTHENTICATE body")
        user = body[1]
        return {"reserved": 0, "user_id": user,
                "user_class": "management" if user == 1 else "user" if 2 <= user <= 0x7F else "reserved",
                "ccm_mac_hex": body[2:].hex(), "authenticated": None,
                "expected_transport": "inside SECURE_WRAPPER"}
    if service == 0x0954:
        if len(body) != 2 or body[1] != 0:
            raise SecBasKNXError("invalid SESSION_STATUS body")
        statuses = {0: "success", 1: "authentication-failed", 2: "unauthenticated",
                    3: "timeout", 4: "keepalive", 5: "close"}
        if body[0] not in statuses:
            raise SecBasKNXError("reserved SESSION_STATUS value")
        return {"status": body[0], "status_name": statuses[body[0]], "reserved": 0}
    if service == 0x0955:
        if len(body) != 30:
            raise SecBasKNXError("TIMER_NOTIFY must have a 30-byte body")
        return {"timer": int.from_bytes(body[:6], "big"), "serial_number_hex": body[6:12].hex(),
                "message_tag": int.from_bytes(body[12:14], "big"), "ccm_mac_hex": body[14:].hex(),
                "authenticated": None}
    raise SecBasKNXError("not a KNX IP Secure service")


@_closed
def parse_knxnetip(data: bytes, *, dpt: str | None = None) -> dict[str, object]:
    """Parse one exact KNXnet/IP packet, including secure-service inventory."""

    raw = _bytes(data, "KNXnet/IP frame")
    _need(raw, 0, 6, "KNXnet/IP header")
    header_length, version = raw[0], raw[1]
    if header_length != 6 or version != 0x10:
        raise SecBasKNXError("unsupported KNXnet/IP header length or version")
    service, total = _u16(raw, 2), _u16(raw, 4)
    if total != len(raw) or total < 6:
        raise SecBasKNXError("KNXnet/IP total length mismatch")
    if dpt is not None and service not in (0x0420, 0x0530, 0x0533):
        raise SecBasKNXError("DPT decoding is not applicable to this KNXnet/IP service")
    body = raw[6:]
    result: dict[str, object] = {
        "protocol": "knxnet-ip",
        "header_length": header_length,
        "version": "1.0",
        "service_type": service,
        "service": _KNXIP_SERVICES.get(service, f"UNKNOWN_0x{service:04x}"),
        "total_length": total,
    }
    if service == 0x0420:
        _need(body, 0, 5, "tunneling request")
        if body[0] != 4 or body[3] != 0:
            raise SecBasKNXError("invalid tunneling connection header")
        result["connection"] = {"structure_length": 4, "channel_id": body[1],
                                "sequence_counter": body[2], "reserved": 0}
        result["cemi"] = parse_cemi(body[4:], dpt=dpt)
    elif service == 0x0421:
        if len(body) != 4 or body[0] != 4:
            raise SecBasKNXError("TUNNELLING_ACK must have a four-byte connection header")
        result["connection"] = {"structure_length": 4, "channel_id": body[1],
                                "sequence_counter": body[2], "status": body[3]}
    elif service in (0x0530, 0x0533):
        result["cemi"] = parse_cemi(body, dpt=dpt)
    elif service in (0x0531, 0x0532):
        if not body:
            raise SecBasKNXError("empty KNXnet/IP routing status body")
        result["routing_status_hex"] = body.hex()
        result["note"] = "service identified; implementation-specific/status structure retained verbatim"
    elif 0x0950 <= service <= 0x0955:
        result["secure"] = _secure_knxip(service, body)
    else:
        result["body_hex"] = body.hex()
    return result


_COAP_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
_COAP_OPTION_NAMES = {
    1: "If-Match", 3: "Uri-Host", 4: "ETag", 5: "If-None-Match", 6: "Observe",
    7: "Uri-Port", 8: "Location-Path", 9: "OSCORE", 11: "Uri-Path",
    12: "Content-Format", 14: "Max-Age", 15: "Uri-Query", 17: "Accept",
    20: "Location-Query", 23: "Block2", 27: "Block1", 28: "Size2",
    35: "Proxy-Uri", 39: "Proxy-Scheme", 60: "Size1", 258: "No-Response",
}
_COAP_UINT_OPTIONS = {6, 7, 12, 14, 17, 23, 27, 28, 60, 258}
_COAP_TEXT_OPTIONS = {3, 8, 11, 15, 20, 35, 39}


def _coap_extended(raw: bytes, offset: int, nibble: int, label: str) -> tuple[int, int]:
    if nibble < 13:
        return nibble, offset
    if nibble == 13:
        _need(raw, offset, 1, label)
        return raw[offset] + 13, offset + 1
    if nibble == 14:
        _need(raw, offset, 2, label)
        return int.from_bytes(raw[offset : offset + 2], "big") + 269, offset + 2
    raise SecBasKNXError(f"reserved CoAP {label} nibble")


def _oscore(raw: bytes) -> dict[str, object]:
    if not raw:
        return {"flags": 0, "partial_iv_hex": "", "kid_context_hex": None, "kid_hex": None}
    flags = raw[0]
    if flags & 0xE0:
        raise SecBasKNXError("reserved OSCORE flag bits are nonzero")
    piv_length = flags & 7
    if piv_length > 5:
        raise SecBasKNXError("reserved OSCORE Partial IV length")
    kid_present, context_present = bool(flags & 0x08), bool(flags & 0x10)
    offset = 1
    _need(raw, offset, piv_length, "OSCORE Partial IV")
    partial_iv = raw[offset : offset + piv_length]
    offset += piv_length
    context: bytes | None = None
    if context_present:
        _need(raw, offset, 1, "OSCORE kid-context length")
        size = raw[offset]
        offset += 1
        _need(raw, offset, size, "OSCORE kid context")
        context = raw[offset : offset + size]
        offset += size
    kid: bytes | None = None
    if kid_present:
        kid = raw[offset:]
        offset = len(raw)
    if offset != len(raw):
        raise SecBasKNXError("trailing bytes in OSCORE option without kid flag")
    return {
        "flags": flags,
        "partial_iv_hex": partial_iv.hex(),
        "kid_context_hex": None if context is None else context.hex(),
        "kid_hex": None if kid is None else kid.hex(),
    }


@_closed
def parse_oscore_option(data: bytes) -> dict[str, object]:
    """Parse RFC 8613 OSCORE option metadata without decrypting its payload."""

    return _oscore(_bytes(data, "OSCORE option", 1024))


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


@_closed
def parse_coap(data: bytes, *, decode_plaintext_cbor: bool = True) -> dict[str, object]:
    """Parse one exact RFC 7252 datagram and inventory KNX IoT/OSCORE evidence."""

    raw = _bytes(data, "CoAP datagram")
    _need(raw, 0, 4, "CoAP header")
    first, code = raw[0], raw[1]
    version, kind, token_length = first >> 6, (first >> 4) & 3, first & 15
    if version != 1 or token_length > 8:
        raise SecBasKNXError("invalid CoAP version or token length")
    if code >> 5 in (1, 6, 7):
        raise SecBasKNXError("reserved CoAP code class")
    if code == 0 and (token_length != 0 or len(raw) != 4):
        raise SecBasKNXError("empty CoAP message must contain only its four-byte header")
    _need(raw, 4, token_length, "CoAP token")
    offset = 4 + token_length
    option_number = 0
    options: list[dict[str, object]] = []
    payload = b""
    while offset < len(raw):
        if raw[offset] == 0xFF:
            offset += 1
            if offset == len(raw):
                raise SecBasKNXError("CoAP payload marker without payload")
            payload = raw[offset:]
            offset = len(raw)
            break
        if len(options) >= MAX_COAP_OPTIONS:
            raise SecBasKNXError("too many CoAP options")
        head = raw[offset]
        offset += 1
        delta, offset = _coap_extended(raw, offset, head >> 4, "option delta")
        length, offset = _coap_extended(raw, offset, head & 15, "option length")
        option_number += delta
        _need(raw, offset, length, "CoAP option value")
        value = raw[offset : offset + length]
        offset += length
        row: dict[str, object] = {
            "number": option_number,
            "name": _COAP_OPTION_NAMES.get(option_number, f"Option-{option_number}"),
            "length": length,
            "value_hex": value.hex(),
        }
        if option_number in _COAP_UINT_OPTIONS:
            if len(value) > 4:
                raise SecBasKNXError("oversized CoAP integer option")
            if value[:1] == b"\x00":
                raise SecBasKNXError("non-minimal CoAP integer option")
            row["value"] = int.from_bytes(value, "big") if value else 0
        elif option_number in _COAP_TEXT_OPTIONS:
            try:
                row["value"] = value.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SecBasKNXError("invalid UTF-8 CoAP URI option") from exc
        elif option_number == 9:
            row["oscore"] = _oscore(value)
        options.append(row)
    paths = [str(row["value"]) for row in options if row["number"] == 11]
    uri_path = "/" + "/".join(paths) if paths else "/"
    oscore_rows = [row["oscore"] for row in options if row["number"] == 9]
    if len(oscore_rows) > 1:
        raise SecBasKNXError("multiple OSCORE options")
    knx_iot = (
        uri_path == "/.well-known/core"
        or uri_path.startswith("/.well-known/knx")
        or uri_path == "/.knx"
        or uri_path.startswith("/.knx/")
        or uri_path.startswith("/dev/")
        or uri_path.startswith("/auth/")
        or uri_path.startswith("/p/")
    )
    result: dict[str, object] = {
        "protocol": "coap",
        "version": version,
        "type": _COAP_TYPES[kind],
        "code": code,
        "code_text": f"{code >> 5}.{code & 31:02d}",
        "message_id": int.from_bytes(raw[2:4], "big"),
        "token_hex": raw[4 : 4 + token_length].hex(),
        "options": options,
        "uri_path": uri_path,
        "payload_hex": payload.hex(),
        "knx_iot_candidate": knx_iot,
        "transport_context": "CoAP over UDP/IPv6; Thread is one possible IPv6 bearer",
    }
    if oscore_rows:
        result["oscore"] = oscore_rows[0]
        result["encrypted"] = True
        result["decrypted"] = False
        result["note"] = "OSCORE ciphertext retained; no security context was applied"
    elif decode_plaintext_cbor and payload:
        formats = [row.get("value") for row in options if row["number"] == 12]
        if formats and formats[-1] == 60:
            try:
                from wire_decode import decode_cbor

                result["cbor"] = _json_safe(decode_cbor(payload))
            except Exception as exc:
                raise SecBasKNXError(f"invalid plaintext CBOR payload: {exc}") from None
    return result


@_closed
def analyze(data: bytes, *, format: str = "auto", dpt: str | None = None) -> dict[str, object]:
    """Decode supplied bytes as KNXnet/IP, cEMI, CoAP, or an explicit DPT."""

    raw = _bytes(data)
    if not isinstance(format, str):
        raise SecBasKNXError("format must be a string")
    mode = format.strip().lower()
    if mode == "auto":
        if len(raw) >= 6 and raw[:2] == b"\x06\x10":
            mode = "knxnetip"
        elif raw[:1] and raw[0] in _CEMI_CODES:
            mode = "cemi"
        elif len(raw) >= 4 and raw[0] >> 6 == 1:
            mode = "coap"
        else:
            raise SecBasKNXError("unable to identify KNX/cEMI/CoAP evidence")
    if mode in ("knxnetip", "knxnet/ip", "ip"):
        return parse_knxnetip(raw, dpt=dpt)
    if mode == "cemi":
        return parse_cemi(raw, dpt=dpt)
    if mode in ("coap", "iot"):
        if dpt is not None:
            raise SecBasKNXError("--dpt is not applicable to CoAP")
        return parse_coap(raw)
    if mode == "dpt":
        if dpt is None:
            raise SecBasKNXError("DPT mode requires a DPT identifier")
        return decode_dpt(raw, dpt)
    raise SecBasKNXError(f"unsupported format {format!r}")


def _read(path: Path, hexadecimal: bool) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
    except OSError as exc:
        raise SecBasKNXError(f"cannot read {path}: {exc}") from exc
    if len(raw) > MAX_INPUT:
        raise SecBasKNXError("input file exceeds 4 MiB limit")
    if hexadecimal:
        try:
            text = raw.decode("ascii")
            compact = "".join(text.split())
            if len(compact) % 2:
                raise ValueError("odd hexadecimal length")
            raw = bytes.fromhex(compact)
        except (UnicodeDecodeError, ValueError) as exc:
            raise SecBasKNXError(f"invalid hexadecimal input: {exc}") from None
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive KNX Classic/KNXnet-IP/KNX IoT decoder")
    parser.add_argument("mode", choices=("auto", "knxnetip", "cemi", "coap", "dpt"))
    parser.add_argument("file", type=Path, help="supplied raw or hexadecimal artifact")
    parser.add_argument("--hex", action="store_true", help="file contains whitespace-separated hexadecimal")
    parser.add_argument("--dpt", help="caller-selected datapoint type, for example 1, 5.001, or 9")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = analyze(_read(args.file, args.hex), format=args.mode, dpt=args.dpt)
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except SecBasKNXError as exc:
        print(f"sec_bas_knx: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_INPUT",
    "SecBasKNXError",
    "analyze",
    "decode_dpt",
    "main",
    "parse_cemi",
    "parse_coap",
    "parse_knxnetip",
    "parse_oscore_option",
]
