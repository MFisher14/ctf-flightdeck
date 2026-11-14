#!/usr/bin/env python3
"""Passive IEC 62351-6 and routed IEC 61850 GOOSE/SV analyzer.

This module deliberately composes :mod:`power_iec61850` for the already
implemented base GOOSE and Sampled Value APDUs.  Its new scope is the appended
IEC 62351-6 Layer-2 authentication extension and the IEC 61850 routed-session
envelope used by R-GOOSE/R-SV.  Input is supplied bytes only; no socket or live
capture interface is imported.

Current Annex-J session version 2 is decoded structurally.  The older TR
61850-90-5 version-1 header and HMAC trailer require ``legacy=True``.  A
separate ``libiec_compat=True`` switch recognizes libiec61850's documented
version-1 wire divergences; the default remains the IEC TR layout.  Secure
version-2 padding/trailer verification is intentionally unsupported without a
published interoperable vector; it is retained as raw evidence rather than
guessed.  Encrypted routed payloads require ``encrypted=True`` and remain
opaque.

All public parsing functions raise only :class:`GridGooseError` for malformed,
unsupported, or excessive input.
"""
from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import hmac
import json
from pathlib import Path
import sys
from typing import Any


MAX_FRAME = 65_599
MAX_CAPTURE = 32 << 20
MAX_PACKETS = 100_000
MAX_EXTENSION = 0x0FFF
MAX_BER_ITEMS = 64

ETHERTYPE_GOOSE = 0x88B8
ETHERTYPE_SV = 0x88BA
_ETHERTYPES = {ETHERTYPE_GOOSE: "goose", ETHERTYPE_SV: "sv"}
_SESSION_IDENTIFIERS = {0xA0: "tunnel", 0xA1: "r-goose", 0xA2: "r-sv", 0xA3: "management"}
_PAYLOAD_TAGS = {0x81: "goose", 0x82: "sv", 0x83: "tunnel", 0x84: "management"}
_LEGACY_SIGNATURES = {
    0: ("none", None, 0),
    1: ("hmac-sha256-80", "sha256", 10),
    2: ("hmac-sha256-128", "sha256", 16),
    3: ("hmac-sha256-256", "sha256", 32),
    4: ("aes-gmac-64", None, 8),
    5: ("aes-gmac-128", None, 16),
}


class GridGooseError(ValueError):
    """Malformed, unsupported, ambiguous, or over-budget grid-security input."""


def _guard(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except GridGooseError:
            raise
        except Exception as exc:
            raise GridGooseError(f"{function.__name__}: {type(exc).__name__}") from None

    return wrapped


def _blob(data: Any, *, maximum: int = MAX_FRAME, empty: bool = False) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise GridGooseError("input must be bytes-like")
    if isinstance(data, memoryview) and (data.ndim != 1 or not data.contiguous):
        raise GridGooseError("input memoryview must be contiguous and one-dimensional")
    raw = bytes(data)
    if (not empty and not raw) or len(raw) > maximum:
        raise GridGooseError("input is empty or exceeds the size cap")
    return raw


def _key(value: Any) -> bytes:
    raw = _blob(value, maximum=64)
    return raw


def _normal_algorithm(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise GridGooseError("authentication algorithm must be a string")
    name = value.lower().replace("_", "-")
    aliases = {
        "hmac": "hmac-sha256",
        "sha256": "hmac-sha256",
        "hmac-sha-256": "hmac-sha256",
        "hmac-sha256": "hmac-sha256",
        "gmac": "aes-gmac",
        "aes-gmac": "aes-gmac",
    }
    if name not in aliases:
        raise GridGooseError("authentication algorithm must be hmac-sha256 or aes-gmac")
    return aliases[name]


def _crc16_iso_hdlc(data: bytes) -> int:
    crc = 0xFFFF
    for octet in data:
        crc ^= octet
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF


def _read_tlv(data: bytes, offset: int, end: int) -> tuple[int, int, int, int]:
    if offset < 0 or end > len(data) or offset + 2 > end:
        raise GridGooseError("truncated BER identifier/length")
    tag = data[offset]
    if tag == 0 or tag & 0x1F == 0x1F:
        raise GridGooseError("unsupported BER identifier")
    first = data[offset + 1]
    cursor = offset + 2
    if first & 0x80:
        width = first & 0x7F
        if width == 0 or width > 2 or cursor + width > end:
            raise GridGooseError("indefinite or excessive BER length")
        if data[cursor] == 0:
            raise GridGooseError("non-minimal BER length")
        size = int.from_bytes(data[cursor : cursor + width], "big")
        if size < 128:
            raise GridGooseError("non-minimal BER long length")
        cursor += width
    else:
        size = first
    stop = cursor + size
    if stop > end:
        raise GridGooseError("BER value overruns its container")
    return tag, cursor, stop, stop


def _ber_integer(raw: bytes, *, signed: bool, bits: int = 32) -> int:
    if not raw or len(raw) > bits // 8 + 1:
        raise GridGooseError("invalid BER INTEGER width")
    if len(raw) > 1 and ((raw[0] == 0 and not raw[1] & 0x80) or (raw[0] == 0xFF and raw[1] & 0x80)):
        raise GridGooseError("non-minimal BER INTEGER")
    if not signed and raw[0] & 0x80:
        raise GridGooseError("negative value in unsigned BER INTEGER")
    value = int.from_bytes(raw, "big", signed=signed)
    low = -(1 << (bits - 1)) if signed else 0
    high = (1 << (bits - (1 if signed else 0))) - 1
    if not low <= value <= high:
        raise GridGooseError("BER INTEGER is out of range")
    return value


def _authentication_value(raw: bytes) -> dict[str, Any]:
    offset, previous, fields = 0, -1, {}
    while offset < len(raw):
        if len(fields) >= 5:
            raise GridGooseError("too many AuthenticationValue fields")
        tag, start, stop, offset = _read_tlv(raw, offset, len(raw))
        if tag not in {0x80, 0x81, 0x82, 0x83, 0x84} or tag in fields or tag <= previous:
            raise GridGooseError("unknown, duplicate, or unordered AuthenticationValue field")
        previous = tag
        fields[tag] = raw[start:stop]
    if not {0x80, 0x81, 0x82, 0x84} <= fields.keys():
        raise GridGooseError("AuthenticationValue lacks a mandatory field")
    version = _ber_integer(fields[0x80], signed=False, bits=32)
    if version != 1:
        raise GridGooseError("unsupported IEC 62351-6 extension version")
    result: dict[str, Any] = {
        "version": version,
        "time_of_current_key": _ber_integer(fields[0x81], signed=False, bits=32),
        "time_to_next_key": _ber_integer(fields[0x82], signed=True, bits=32),
        "key_id": _ber_integer(fields[0x84], signed=False, bits=32),
    }
    if 0x83 in fields:
        if len(fields[0x83]) != 16:
            raise GridGooseError("IEC 62351-6 initialization vector must contain 16 octets")
        result["initialization_vector"] = fields[0x83].hex()
    return result


def _parse_extension(raw: bytes) -> tuple[dict[str, Any], int]:
    tag, start, stop, next_offset = _read_tlv(raw, 0, len(raw))
    if tag != 0xA0 or next_offset != len(raw):
        raise GridGooseError("security extension must be one complete constructed [0] value")
    offset, previous, count = start, -1, 0
    result: dict[str, Any] = {"encoded_hex": raw.hex()}
    mac_offset = -1
    while offset < stop:
        if count >= MAX_BER_ITEMS:
            raise GridGooseError("security extension item limit exceeded")
        item_offset = offset
        item_tag, value_start, value_stop, offset = _read_tlv(raw, offset, stop)
        if item_tag not in {0xA1, 0x82, 0x83, 0xA4, 0x85} or item_tag in result:
            raise GridGooseError("unknown or duplicate security-extension element")
        order = {0xA1: 1, 0x82: 2, 0x83: 3, 0xA4: 4, 0x85: 5}[item_tag]
        if order <= previous:
            raise GridGooseError("unordered security-extension element")
        previous, count = order, count + 1
        value = raw[value_start:value_stop]
        if item_tag == 0xA1:
            if not value:
                raise GridGooseError("empty reserved security extension is non-conformant")
            result["reserved_hex"] = value.hex()
        elif item_tag == 0x82:
            if not value:
                raise GridGooseError("empty private security extension is non-conformant")
            result["private_hex"] = value.hex()
        elif item_tag == 0x83:
            raise GridGooseError("reserved-do-not-use security element is present")
        elif item_tag == 0xA4:
            result["authentication_value"] = _authentication_value(value)
        else:
            if offset != stop:
                raise GridGooseError("mAC must be the final extension element")
            if not 8 <= len(value) <= 32:
                raise GridGooseError("mAC length must be between 8 and 32 octets")
            result["mac"] = value.hex()
            mac_offset = item_offset
    if "authentication_value" in result and "mac" not in result:
        raise GridGooseError("AuthenticationValue is present without mAC")
    return result, mac_offset


def _verify_l2_auth(extension: dict[str, Any], domain: bytes, *, key: bytes | None,
                    algorithm: str | None) -> dict[str, Any]:
    mac_hex = extension.get("mac")
    auth_value = extension.get("authentication_value")
    if mac_hex is None:
        return {"status": "not_checked", "reason": "extension contains no mAC"}
    if auth_value is None:
        return {"status": "not_checked", "reason": "mAC has no AuthenticationValue metadata"}
    normalized = _normal_algorithm(algorithm)
    if key is None:
        return {"status": "not_checked", "algorithm": normalized,
                "reason": "no authentication key supplied"}
    supplied_key = _key(key)
    if normalized is None:
        raise GridGooseError("an explicit authentication algorithm is required with a supplied key")
    mac = bytes.fromhex(mac_hex)
    if normalized == "hmac-sha256":
        if len(mac) > hashlib.sha256().digest_size:
            raise GridGooseError("HMAC-SHA256 mAC exceeds the digest length")
        expected = hmac.new(supplied_key, domain, hashlib.sha256).digest()[: len(mac)]
    else:
        if len(supplied_key) not in (16, 32):
            raise GridGooseError("AES-GMAC requires a 16- or 32-octet key")
        if not 8 <= len(mac) <= 16:
            raise GridGooseError("AES-GMAC tag must contain 8 to 16 octets")
        iv_hex = auth_value.get("initialization_vector")
        if iv_hex is None:
            raise GridGooseError("AES-GMAC AuthenticationValue lacks its IV")
        from Crypto.Cipher import AES

        cipher = AES.new(supplied_key, AES.MODE_GCM, nonce=bytes.fromhex(iv_hex), mac_len=len(mac))
        cipher.update(domain)
        expected = cipher.digest()
    verified = hmac.compare_digest(expected, mac)
    return {"status": "verified" if verified else "invalid", "algorithm": normalized,
            "tag_length": len(mac), "verified": verified}


def _ethernet_envelope(data: bytes) -> tuple[int, bytes, dict[str, Any]] | None:
    if len(data) < 14:
        return None
    ethertype, offset, vlans = int.from_bytes(data[12:14], "big"), 14, []
    while ethertype in (0x8100, 0x88A8, 0x9100):
        if len(vlans) >= 4 or offset + 4 > len(data):
            raise GridGooseError("truncated or excessive Ethernet VLAN stack")
        tci = int.from_bytes(data[offset : offset + 2], "big")
        vlans.append({"tpid": ethertype, "id": tci & 0x0FFF, "priority": tci >> 13,
                      "dei": bool(tci & 0x1000)})
        ethertype = int.from_bytes(data[offset + 2 : offset + 4], "big")
        offset += 4
    if ethertype not in _ETHERTYPES:
        return None
    return ethertype, data[offset:], {
        "source": data[6:12].hex(":"), "destination": data[:6].hex(":"), "vlans": vlans
    }


def _base_apdu(payload: bytes, ethertype: int, decode_9_2le: bool) -> dict[str, Any]:
    try:
        import power_iec61850 as base

        if ethertype == ETHERTYPE_GOOSE:
            return base.parse_goose(payload)
        return base.parse_sv(payload, decode_9_2le=decode_9_2le)
    except Exception as exc:
        raise GridGooseError(f"base GOOSE/SV decoder rejected input: {type(exc).__name__}") from None


@_guard
def parse_l2(data: bytes, *, ethertype: int | None = None, key: bytes | None = None,
             auth_algorithm: str | None = None, decode_9_2le: bool = False) -> dict[str, Any]:
    """Parse one Layer-2 GOOSE/SV frame or bare protocol payload.

    A full Ethernet frame and a bare ``EtherType || APPID...`` value are
    autodetected.  A bare ``APPID...`` value requires the explicit ``ethertype``
    argument.  The base IEC ``Length`` excludes an appended security extension.
    """
    raw = _blob(data)
    if not isinstance(decode_9_2le, bool):
        raise GridGooseError("decode_9_2le must be boolean")
    explicit = ethertype is not None
    ethernet = _ethernet_envelope(raw) if not explicit else None
    exact = True
    if ethernet is not None:
        selected, app, ethernet_meta = ethernet
        exact = False
    elif not explicit and len(raw) >= 2 and int.from_bytes(raw[:2], "big") in _ETHERTYPES:
        selected, app, ethernet_meta = int.from_bytes(raw[:2], "big"), raw[2:], None
    else:
        if not isinstance(ethertype, int) or ethertype not in _ETHERTYPES:
            raise GridGooseError("bare APPID payload requires GOOSE/SV ethertype")
        selected, app, ethernet_meta = ethertype, raw, None
    if explicit and _ethernet_envelope(raw) is not None:
        raise GridGooseError("do not combine an explicit ethertype with a full Ethernet frame")
    if len(app) < 10:
        raise GridGooseError("truncated APPID header or application PDU")
    declared = int.from_bytes(app[2:4], "big")
    if declared < 10 or declared > len(app):
        raise GridGooseError("invalid or truncated base APPID length")
    reserved1, reserved2 = int.from_bytes(app[4:6], "big"), int.from_bytes(app[6:8], "big")
    extension_length = reserved1 & MAX_EXTENSION
    if reserved1 & 0x7000:
        raise GridGooseError("reserved IEC 62351-6 header bits are nonzero")
    extension_end = declared + extension_length
    if extension_end > len(app):
        raise GridGooseError("security extension overruns supplied bytes")
    trailer = app[extension_end:]
    if exact and trailer:
        raise GridGooseError("trailing bytes after bare Layer-2 protocol value")
    base_payload = app[:declared]
    result: dict[str, Any] = {
        "protocol": "iec61850-secure-l2",
        "message_type": _ETHERTYPES[selected],
        "ethertype": selected,
        "appid": int.from_bytes(app[:2], "big"),
        "base_length": declared,
        "simulation": bool(reserved1 & 0x8000),
        "extension_length": extension_length,
        "reserved2": reserved2,
        "base": _base_apdu(base_payload, selected, decode_9_2le),
        "trailer_hex": trailer.hex(),
    }
    if ethernet_meta is not None:
        result["ethernet"] = ethernet_meta
    if not extension_length:
        if reserved2:
            raise GridGooseError("Reserved2 must be zero without a security extension")
        result["security"] = {"present": False, "authentication": {"status": "not_present"}}
        if key is not None:
            raise GridGooseError("authentication key supplied for an unsecured frame")
        return result
    crc_input = selected.to_bytes(2, "big") + app[:6]
    calculated_crc = _crc16_iso_hdlc(crc_input)
    if calculated_crc != reserved2:
        raise GridGooseError("IEC 62351-6 header CRC mismatch")
    extension_raw = app[declared:extension_end]
    extension, mac_offset = _parse_extension(extension_raw)
    domain = selected.to_bytes(2, "big") + app[:declared]
    if mac_offset >= 0:
        domain += extension_raw[:mac_offset]
    else:
        domain += extension_raw
    authentication = _verify_l2_auth(extension, domain, key=key, algorithm=auth_algorithm)
    result["security"] = {
        "present": True,
        "crc_valid": True,
        "crc": reserved2,
        "mac_domain_hex": domain.hex(),
        "extension": extension,
        "authentication": authentication,
    }
    return result


def _take(data: bytes, offset: int, size: int, end: int, name: str) -> tuple[bytes, int]:
    if size < 0 or offset < 0 or offset + size > end:
        raise GridGooseError(f"truncated routed-session {name}")
    return data[offset : offset + size], offset + size


def _routed_payloads(payload: bytes, session_identifier: int,
                     libiec_compat: bool = False) -> list[dict[str, Any]]:
    rows, offset = [], 0
    while offset < len(payload):
        if len(rows) >= 1024:
            raise GridGooseError("routed payload count exceeds cap")
        header, offset = _take(payload, offset, 6, len(payload), "payload header")
        tag, simulation = header[0], header[1]
        if tag not in (0x81, 0x82) or simulation not in (0, 1):
            raise GridGooseError("unsupported or malformed routed payload record")
        if (session_identifier, tag) not in {(0xA1, 0x81), (0xA2, 0x82)}:
            raise GridGooseError("session identifier and payload type disagree")
        appid = int.from_bytes(header[2:4], "big")
        declared_apdu_length = int.from_bytes(header[4:6], "big")
        if declared_apdu_length < 2:
            raise GridGooseError("routed APDU is too short")
        apdu_length = declared_apdu_length
        adjusted = False
        remaining = len(payload) - offset
        if (libiec_compat and declared_apdu_length == remaining + 2):
            # libiec61850 writes payloadSize + 2.  Accept only on the last
            # record, where the true boundary is independently known.
            apdu_length, adjusted = remaining, True
        apdu, offset = _take(payload, offset, apdu_length, len(payload), "APDU")
        expected_tag = 0x61 if tag == 0x81 else 0x60
        if apdu[0] != expected_tag:
            raise GridGooseError("routed payload carries the wrong application PDU")
        app_header = appid.to_bytes(2, "big") + (8 + apdu_length).to_bytes(2, "big") + b"\0\0\0\0"
        base = _base_apdu(app_header + apdu, ETHERTYPE_GOOSE if tag == 0x81 else ETHERTYPE_SV, False)
        row = {"type": _PAYLOAD_TAGS[tag], "simulation": bool(simulation), "appid": appid,
               "apdu_length": declared_apdu_length, "apdu_hex": apdu.hex(), "base": base}
        if adjusted:
            row.update(apdu_length_effective=apdu_length,
                       apdu_length_profile="libiec61850-last-record-plus-two")
        rows.append(row)
    if not rows:
        raise GridGooseError("routed session has no payload records")
    return rows


def _legacy_authentication(data: bytes, payload_end: int, trailer: bytes, signature: int,
                           key: bytes | None, libiec_compat: bool) -> dict[str, Any]:
    if signature not in _LEGACY_SIGNATURES:
        raise GridGooseError("unknown legacy routed signature algorithm")
    name, digest, expected_length = _LEGACY_SIGNATURES[signature]
    if signature == 0:
        if trailer:
            raise GridGooseError("unsigned legacy session has an authentication trailer")
        if key is not None:
            raise GridGooseError("authentication key supplied for an unsigned routed session")
        return {"status": "not_present", "algorithm": name}
    if len(trailer) < 2 or trailer[0] != 0x85 or trailer[1] != len(trailer) - 2:
        raise GridGooseError("malformed legacy routed authentication trailer")
    mac = trailer[2:]
    if len(mac) != expected_length:
        raise GridGooseError("legacy routed authentication length disagrees with its algorithm")
    if key is None:
        return {"status": "not_checked", "algorithm": name, "tag_length": len(mac),
                "reason": "no authentication key supplied"}
    supplied_key = _key(key)
    if digest is None:
        return {"status": "not_checked", "algorithm": name, "tag_length": len(mac),
                "reason": "legacy GMAC nonce derivation is not inferred"}
    # IEC TR 61850-90-5 11.3.4 covers Session Identifier through user payload.
    # libiec61850 instead starts at the preceding RFC 1240 octets (01 40).
    domain = data[:payload_end] if libiec_compat else data[2:payload_end]
    expected = hmac.new(supplied_key, domain, digest).digest()[:expected_length]
    verified = hmac.compare_digest(expected, mac)
    return {"status": "verified" if verified else "invalid", "algorithm": name,
            "tag_length": len(mac), "verified": verified, "mac_domain_hex": domain.hex(),
            "mac_domain_profile": "libiec61850" if libiec_compat else "iec-tr-61850-90-5"}


@_guard
def parse_rsession(data: bytes, *, legacy: bool = False, encrypted: bool = False,
                   key: bytes | None = None, libiec_compat: bool = False) -> dict[str, Any]:
    """Parse a supplied R-GOOSE/R-SV UDP payload.

    ``legacy=True`` is mandatory for version 1.  ``libiec_compat=True`` opts in
    to libiec61850's non-normative v1 common-header and HMAC boundaries.  Current
    version 2 is structural only.  ``encrypted=True`` preserves the routed user
    payload as opaque bytes.
    """
    raw = _blob(data)
    if (not isinstance(legacy, bool) or not isinstance(encrypted, bool)
            or not isinstance(libiec_compat, bool)):
        raise GridGooseError("legacy/encrypted/libiec_compat switches must be boolean")
    if len(raw) < 10 or raw[:2] != b"\x01\x40":
        raise GridGooseError("missing RFC 1240 routed-session marker")
    session_identifier, session_header_length = raw[2], raw[3]
    if session_identifier not in _SESSION_IDENTIFIERS:
        raise GridGooseError("unknown routed-session identifier")
    if session_identifier not in (0xA1, 0xA2):
        raise GridGooseError("only non-tunnelled R-GOOSE/R-SV is supported")
    header_end = 4 + session_header_length
    if session_header_length < 6 or header_end + 4 > len(raw):
        raise GridGooseError("invalid routed session-header length")
    if raw[4] != 0x80:
        raise GridGooseError("unsupported routed common-header identifier")
    common_length_indicator = raw[5]
    spdu_length = int.from_bytes(raw[6:10], "big")
    spdu_number = int.from_bytes(raw[10:14], "big") if header_end >= 16 else None
    version = int.from_bytes(raw[14:16], "big") if header_end >= 16 else None
    if version not in (1, 2):
        raise GridGooseError("unsupported routed-session version")
    if version == 1 and not legacy:
        raise GridGooseError("version-1 routed sessions require legacy=True")
    if version == 2 and legacy:
        raise GridGooseError("legacy=True is valid only for routed-session version 1")
    if version == 2 and libiec_compat:
        raise GridGooseError("libiec_compat is valid only for routed-session version 1")
    if version == 1:
        if session_header_length != 24 or header_end != 28:
            raise GridGooseError("legacy routed session header must contain 24 octets")
        expected_common_length = 0x12 if libiec_compat else 0x16
        if common_length_indicator != expected_common_length:
            raise GridGooseError(
                f"legacy routed common-header length must be 0x{expected_common_length:02x}"
            )
        current_key_time = int.from_bytes(raw[16:20], "big")
        next_key_time = int.from_bytes(raw[20:22], "big", signed=True)
        encryption_algorithm, signature_algorithm = raw[22], raw[23]
        if encryption_algorithm not in (0, 1, 2):
            raise GridGooseError("unknown legacy routed encryption algorithm")
        key_id = int.from_bytes(raw[24:28], "big")
        iv = b""
        opaque = encrypted or encryption_algorithm != 0
    else:
        if common_length_indicator != 0x0A:
            raise GridGooseError("current routed common-header length indicator must be 0x0a")
        if header_end < 27:
            raise GridGooseError("current routed session header is truncated")
        current_key_time = int.from_bytes(raw[16:20], "big")
        next_key_time = int.from_bytes(raw[20:22], "big", signed=True)
        key_id = int.from_bytes(raw[22:26], "big")
        iv_length = raw[26]
        if 27 + iv_length != header_end or iv_length > 233:
            raise GridGooseError("current routed-session IV/header length mismatch")
        iv = raw[27:header_end]
        encryption_algorithm = signature_algorithm = None
        opaque = encrypted
    payload_length = int.from_bytes(raw[header_end : header_end + 4], "big")
    payload_start, payload_end = header_end + 4, header_end + 4 + payload_length
    if payload_length > MAX_FRAME or payload_end > len(raw):
        raise GridGooseError("routed payload length exceeds supplied bytes")
    payload, trailer = raw[payload_start:payload_end], raw[payload_end:]
    result: dict[str, Any] = {
        "protocol": _SESSION_IDENTIFIERS[session_identifier],
        "wire_profile": ("libiec61850-v1" if libiec_compat else
                         "iec-tr-61850-90-5-v1" if version == 1 else
                         "iec-61850-annex-j-v2"),
        "session_identifier": session_identifier,
        "session_header_length": session_header_length,
        "common_length_indicator": common_length_indicator,
        "spdu_length": spdu_length,
        "spdu_number": spdu_number,
        "version": version,
        "time_of_current_key": current_key_time,
        "time_to_next_key": next_key_time,
        "key_id": key_id,
        "iv_hex": iv.hex(),
        "payload_length": payload_length,
        "trailer_hex": trailer.hex(),
        # Some deployed v1 implementations historically disagreed on this
        # length convention.  Preserve the evidence instead of rejecting it.
        "spdu_length_observed_after_field": len(raw) - 10,
        "spdu_length_consistent": spdu_length == len(raw) - 10,
    }
    if version == 1:
        result.update(encryption_algorithm=encryption_algorithm,
                      signature_algorithm=signature_algorithm,
                      signature_algorithm_name=_LEGACY_SIGNATURES.get(
                          signature_algorithm, ("unknown", None, 0))[0])
        result["authentication"] = _legacy_authentication(
            raw, payload_end, trailer, signature_algorithm, key, libiec_compat
        )
    else:
        if key is not None:
            raise GridGooseError("current routed-session authentication verification is not supported")
        result["authentication"] = {
            "status": "not_checked",
            "reason": "current Annex-J v2 secure padding/trailer is retained, not inferred",
        }
    if opaque:
        result["payload_status"] = "opaque_encrypted"
        result["payload_hex"] = payload.hex()
    else:
        result["payload_status"] = "decoded"
        result["payloads"] = _routed_payloads(payload, session_identifier, libiec_compat)
    return result


@_guard
def analyze_capture(data: bytes, *, key: bytes | None = None, auth_algorithm: str | None = None,
                    decode_9_2le: bool = False, legacy: bool = False,
                    encrypted: bool = False, libiec_compat: bool = False) -> dict[str, Any]:
    """Analyze L2 GOOSE/SV and UDP/102 routed sessions in supplied captures.

    ``legacy`` opts version-1 records into decoding.  ``encrypted`` retains
    routed payloads as opaque ciphertext.  A malformed routed candidate is a
    per-packet finding and cannot suppress later valid records.
    """
    raw = _blob(data, maximum=MAX_CAPTURE)
    if (not isinstance(decode_9_2le, bool) or not isinstance(legacy, bool)
            or not isinstance(encrypted, bool) or not isinstance(libiec_compat, bool)):
        raise GridGooseError("capture switches must be boolean")
    if libiec_compat and not legacy:
        raise GridGooseError("capture libiec_compat requires legacy=True")
    supplied_key = _key(key) if key is not None else None
    normalized_algorithm = _normal_algorithm(auth_algorithm)
    try:
        import ics_capture

        records, findings, total = [], [], 0
        last_spdu: dict[tuple[Any, ...], int] = {}
        for packet in ics_capture.iter_capture(raw):
            total += 1
            if total > MAX_PACKETS:
                raise GridGooseError("capture packet count exceeds local cap")
            frame = packet.get("data")
            if not isinstance(frame, bytes):
                raise GridGooseError("capture yielded a non-byte packet")
            linktype = packet.get("linktype")
            envelope = _ethernet_envelope(frame) if linktype == 1 else None
            transport = None
            if envelope is not None:
                try:
                    parsed = parse_l2(frame, key=supplied_key,
                                      auth_algorithm=normalized_algorithm,
                                      decode_9_2le=decode_9_2le)
                except GridGooseError as exc:
                    findings.append({"kind": "l2-parse-error", "severity": "warning",
                                     "packet_index": packet.get("index"), "detail": str(exc)})
                    continue
            else:
                try:
                    transport = ics_capture._transport_packet(packet)
                except Exception as exc:
                    findings.append({"kind": "packet-parse-error", "severity": "warning",
                                     "packet_index": packet.get("index"),
                                     "detail": f"transport parser rejected packet: {type(exc).__name__}"})
                    continue
                if (transport is None or transport.get("transport") != "udp"
                        or 102 not in (transport.get("source_port"),
                                      transport.get("destination_port"))):
                    continue
                routed = transport.get("payload")
                if not isinstance(routed, bytes) or not routed.startswith(b"\x01\x40"):
                    continue
                routed_version = int.from_bytes(routed[14:16], "big") if len(routed) >= 16 else None
                try:
                    parsed = parse_rsession(
                        routed,
                        legacy=legacy and routed_version == 1,
                        encrypted=encrypted,
                        key=supplied_key if routed_version == 1 else None,
                        libiec_compat=libiec_compat and routed_version == 1,
                    )
                except GridGooseError as exc:
                    findings.append({"kind": "routed-session-parse-error",
                                     "severity": "warning",
                                     "packet_index": packet.get("index"), "detail": str(exc)})
                    continue
            record: dict[str, Any] = {
                "packet_index": packet.get("index"),
                "timestamp": packet.get("timestamp"),
                "analysis": parsed,
            }
            if transport is not None:
                record["transport"] = {
                    name: transport.get(name)
                    for name in ("source", "destination", "source_port", "destination_port")
                }
                number = parsed.get("spdu_number")
                if isinstance(number, int):
                    flow = (transport.get("source"), transport.get("destination"),
                            parsed.get("session_identifier"), parsed.get("key_id"))
                    previous = last_spdu.get(flow)
                    if previous is not None:
                        expected = (previous + 1) & 0xFFFFFFFF
                        if number == previous:
                            findings.append({"kind": "routed-spdu-duplicate",
                                             "severity": "warning",
                                             "packet_index": packet.get("index"),
                                             "spdu_number": number})
                        elif number != expected:
                            delta = (number - previous) & 0xFFFFFFFF
                            kind = ("routed-spdu-gap" if 1 < delta < 0x80000000
                                    else "routed-spdu-out-of-order")
                            findings.append({"kind": kind, "severity": "warning",
                                             "packet_index": packet.get("index"),
                                             "previous": previous, "current": number})
                    if previous is None or 0 < ((number - previous) & 0xFFFFFFFF) < 0x80000000:
                        last_spdu[flow] = number
            records.append(record)
        return {"protocol": "iec61850-capture", "packets_seen": total,
                "matching_packets": len(records), "records": records,
                "findings": findings}
    except GridGooseError:
        raise
    except Exception as exc:
        raise GridGooseError(f"capture parser rejected input: {type(exc).__name__}") from None


@_guard
def analyze(data: bytes, *, kind: str = "auto", ethertype: int | None = None,
            key: bytes | None = None, auth_algorithm: str | None = None,
            decode_9_2le: bool = False, legacy: bool = False,
            encrypted: bool = False, libiec_compat: bool = False) -> dict[str, Any]:
    """Dispatch supplied bytes to Layer-2, routed-session, or capture analysis."""
    raw = _blob(data, maximum=MAX_CAPTURE)
    if kind not in {"auto", "l2", "rsession", "pcap"}:
        raise GridGooseError("kind must be auto, l2, rsession, or pcap")
    selected = kind
    if selected == "auto":
        if raw.startswith((b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                           b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a")):
            selected = "pcap"
        elif raw.startswith(b"\x01\x40"):
            selected = "rsession"
        else:
            selected = "l2"
    if selected == "pcap":
        return analyze_capture(raw, key=key, auth_algorithm=auth_algorithm,
                               decode_9_2le=decode_9_2le, legacy=legacy,
                               encrypted=encrypted, libiec_compat=libiec_compat)
    if selected == "rsession":
        return parse_rsession(raw, legacy=legacy, encrypted=encrypted, key=key,
                              libiec_compat=libiec_compat)
    return parse_l2(raw, ethertype=ethertype, key=key, auth_algorithm=auth_algorithm,
                    decode_9_2le=decode_9_2le)


def _ethertype(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("ethertype must be an integer") from exc
    if parsed not in _ETHERTYPES:
        raise argparse.ArgumentTypeError("ethertype must be 0x88b8 or 0x88ba")
    return parsed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="supplied raw frame/datagram/capture file")
    parser.add_argument("--kind", choices=("auto", "l2", "rsession", "pcap"), default="auto")
    parser.add_argument("--hex", action="store_true", help="input file contains hexadecimal text")
    parser.add_argument("--ethertype", type=_ethertype, help="required for a bare APPID payload")
    parser.add_argument("--key-hex", help="explicit authentication key (hexadecimal)")
    parser.add_argument("--auth-alg", choices=("hmac-sha256", "aes-gmac"))
    parser.add_argument("--legacy-rsession", action="store_true", help="allow TR 61850-90-5 v1")
    parser.add_argument("--libiec-rsession", action="store_true",
                        help="recognize explicit libiec61850 v1 wire divergences")
    parser.add_argument("--encrypted", action="store_true", help="retain routed payload as opaque ciphertext")
    parser.add_argument("--le", action="store_true", help="opt in to 64-byte 9-2LE sample decoding")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        limit = MAX_CAPTURE * 3 if args.hex else MAX_CAPTURE
        with Path(args.input).open("rb") as handle:
            data = handle.read(limit + 1)
        if len(data) > limit:
            raise GridGooseError("input file exceeds cap")
        if args.hex:
            data = bytes.fromhex(data.decode("ascii"))
        key = bytes.fromhex(args.key_hex) if args.key_hex is not None else None
        report = analyze(data, kind=args.kind, ethertype=args.ethertype, key=key,
                         auth_algorithm=args.auth_alg, decode_9_2le=args.le,
                         legacy=args.legacy_rsession, encrypted=args.encrypted,
                         libiec_compat=args.libiec_rsession)
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True))
        return 0
    except (GridGooseError, OSError, ValueError, UnicodeError) as exc:
        print(f"sec_gridsec_goose: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
