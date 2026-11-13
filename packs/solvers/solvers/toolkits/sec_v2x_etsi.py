#!/usr/bin/env python3
"""Passive ETSI cooperative-V2X artifact decoder.

The reader accepts saved bytes only.  It covers the ETSI ITS-G5 GeoNetworking
Basic/Common/extended headers (including the Release-2 C-V2X single-hop
profile), BTP-A/B, established protocolVersion-1 CAM/DENM and
intersection/IVI UPER PDUs, the fixed header inventory of current
protocolVersion-2 facilities PDUs, IEEE 1609.2 / ETSI TS 103 097 secured-message
envelopes, and the fixed or configuration-derived fields of 3GPP NR sidelink
SCI 1-A/2-A/2-B.
It never opens an interface, transmits traffic, verifies a signature, or
attempts PHY demodulation.

CLI examples::

  ./.venv/bin/python solvers/toolkits/sec_v2x_etsi.py geonet frame.bin --profile auto
  ./.venv/bin/python solvers/toolkits/sec_v2x_etsi.py its cam.uper --message-type cam
  ./.venv/bin/python solvers/toolkits/sec_v2x_etsi.py security secured.coer
  ./.venv/bin/python solvers/toolkits/sec_v2x_etsi.py nr-sci sci.bin --sci-format 2-a
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from threading import RLock
from typing import Any


MAX_INPUT = 1 << 20
MAX_NODES = 100_000
MAX_DEPTH = 64
try:
    import pycrate_asn1rt.codecs as _pycrate_codecs
except Exception:
    _ASN1_LOCK = RLock()
else:
    _ASN1_LOCK = getattr(_pycrate_codecs, "_csctf_v2x_codec_lock", None)
    if _ASN1_LOCK is None:
        _ASN1_LOCK = RLock()
        setattr(_pycrate_codecs, "_csctf_v2x_codec_lock", _ASN1_LOCK)
    del _pycrate_codecs


class V2XETSIError(ValueError):
    """Malformed, unsupported, over-limit, or undecodable saved V2X data."""


_GN_NEXT = {0: "any", 1: "common", 2: "secured-packet"}
_COMMON_NEXT = {0: "any", 1: "btp-a", 2: "btp-b", 3: "ipv6"}
_HEADER_TYPES = {
    0: "any", 1: "beacon", 2: "geo-unicast", 3: "geo-anycast",
    4: "geo-broadcast", 5: "topologically-scoped-broadcast", 6: "location-service",
    7: "topologically-scoped-unicast", 8: "topologically-scoped-groupcast",
}
_FACILITY_PORTS = {
    2001: "cam", 2002: "denm", 2003: "mapem", 2004: "spatem",
    2006: "ivim", 2009: "cpm",
}
_ITS_IDS = {1: "denm", 2: "cam", 4: "spatem", 5: "mapem", 6: "ivim"}
_CTC_MAX_ERROR_US = (5.0, 4.0, 3.0, 2.0, 1.0, 0.5, 0.4, 0.3)


def _bounded(data: Any, *, minimum: int = 1, label: str = "input") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise V2XETSIError(f"{label} must be bytes-like")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if not minimum <= size <= MAX_INPUT:
        raise V2XETSIError(f"{label} size must be {minimum}..{MAX_INPUT} bytes")
    try:
        return bytes(data)
    except Exception as exc:
        raise V2XETSIError(f"{label} cannot be materialized") from exc


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise V2XETSIError("truncated 16-bit field")
    return int.from_bytes(data[offset:offset + 2], "big")


def _u32(data: bytes, offset: int, *, signed: bool = False) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise V2XETSIError("truncated 32-bit field")
    return int.from_bytes(data[offset:offset + 4], "big", signed=signed)


def _position_address(raw: bytes) -> dict[str, Any]:
    if len(raw) != 8:
        raise V2XETSIError("GeoNetworking address must be eight octets")
    head = int.from_bytes(raw[:2], "big")
    return {
        "raw_hex": raw.hex(),
        "manually_configured": bool(head & 0x8000),
        "station_type": (head >> 10) & 0x1F,
        # Older GeoNetworking editions used these bits as the station country
        # code; later editions reserve them.  Retain evidence without guessing
        # which edition supplied an otherwise release-ambiguous packet.
        "low_10_bits": head & 0x03FF,
        "legacy_station_country_code": head & 0x03FF,
        "mid_hex": raw[2:].hex(),
    }


def _parse_lpv(data: bytes, offset: int) -> dict[str, Any]:
    if offset < 0 or offset + 24 > len(data):
        raise V2XETSIError("truncated GeoNetworking long position vector")
    speed_field = _u16(data, offset + 20)
    speed = speed_field & 0x7FFF
    if speed & 0x4000:
        speed -= 0x8000
    latitude = _u32(data, offset + 12, signed=True)
    longitude = _u32(data, offset + 16, signed=True)
    heading = _u16(data, offset + 22)
    address = data[offset:offset + 8]
    timestamp = _u32(data, offset + 8)
    return {
        "gn_address": address,
        "gn_address_fields": _position_address(address),
        "timestamp": timestamp,
        "timestamp_ms": timestamp,
        "latitude": latitude,
        "longitude": longitude,
        "latitude_raw": latitude,
        "longitude_raw": longitude,
        "latitude_degrees": latitude / 10_000_000,
        "longitude_degrees": longitude / 10_000_000,
        "position_accurate": bool(speed_field & 0x8000),
        "speed": speed,
        "speed_raw": speed,
        "speed_mps": speed / 100,
        "heading": heading,
        "heading_raw": heading,
        "heading_degrees": heading / 10,
    }


def _parse_spv(data: bytes, offset: int) -> dict[str, Any]:
    if offset < 0 or offset + 20 > len(data):
        raise V2XETSIError("truncated GeoNetworking short position vector")
    latitude = _u32(data, offset + 12, signed=True)
    longitude = _u32(data, offset + 16, signed=True)
    address = data[offset:offset + 8]
    timestamp = _u32(data, offset + 8)
    return {
        "gn_address": address,
        "gn_address_fields": _position_address(address),
        "timestamp": timestamp,
        "timestamp_ms": timestamp,
        "latitude": latitude,
        "longitude": longitude,
        "latitude_raw": latitude,
        "longitude_raw": longitude,
        "latitude_degrees": latitude / 10_000_000,
        "longitude_degrees": longitude / 10_000_000,
    }


def _geonet_profile(profile: Any) -> str:
    if not isinstance(profile, str):
        raise V2XETSIError("GeoNetworking profile must be text")
    selected = profile.lower().replace("_", "-")
    aliases = {
        "auto": "auto",
        "release1": "release1", "release-1": "release1", "r1": "release1",
        "release2": "release2", "release-2": "release2", "r2": "release2",
    }
    try:
        return aliases[selected]
    except KeyError as exc:
        raise V2XETSIError(
            "GeoNetworking profile must be auto, release1, or release2"
        ) from exc


def _release2_media_dependent(data: bytes, offset: int) -> dict[str, Any]:
    """Validate TS 103 836-4-3's four-octet C-V2X media word."""
    word = _u32(data, offset)
    version = word >> 28
    dependent = word & 0x0FFFFFFF
    result: dict[str, Any] = {
        "raw": word,
        "raw_hex": data[offset:offset + 4].hex(),
        "version": version,
    }
    if version == 0:
        if dependent:
            raise V2XETSIError(
                "Release-2 media-dependent version 0 requires zero dependent data"
            )
        result.update({"ctc": None, "reserved_zero": True})
    elif version == 1:
        ctc = (word >> 24) & 0x0F
        if word & 0x00FFFFFF:
            raise V2XETSIError("Release-2 media-dependent reserved octets are non-zero")
        if ctc > 7:
            raise V2XETSIError("Release-2 media-dependent CTC value is reserved")
        result.update({
            "ctc": ctc,
            "ctc_max_time_error_microseconds_exclusive": _CTC_MAX_ERROR_US[ctc],
            "ctc_confidence_percent": 95,
            "reserved_zero": True,
        })
    else:
        raise V2XETSIError("unsupported Release-2 media-dependent data version")
    return result


def parse_btp(data: bytes | bytearray | memoryview, variant: str) -> dict[str, Any]:
    """Decode one four-octet BTP-A or BTP-B header and retain its payload."""
    try:
        raw = _bounded(data, minimum=4, label="BTP packet")
        if not isinstance(variant, str) or variant.upper() not in {"A", "B"}:
            raise V2XETSIError("BTP variant must be A or B")
        kind = variant.upper()
        destination = _u16(raw, 0)
        result: dict[str, Any] = {
            "variant": kind,
            "destination_port": destination,
            "facility_hint": _FACILITY_PORTS.get(destination),
            "payload": raw[4:],
        }
        if kind == "A":
            result["source_port"] = _u16(raw, 2)
        else:
            result["destination_port_info"] = _u16(raw, 2)
        return result
    except V2XETSIError:
        raise
    except Exception as exc:
        raise V2XETSIError("BTP decoding failed") from exc


def parse_geonetworking(
    data: bytes | bytearray | memoryview, profile: str = "auto",
) -> dict[str, Any]:
    """Decode one Release-1/Release-2 ETSI GeoNetworking packet.

    The releases deliberately share Basic Header protocol version 1.  ``auto``
    therefore reports an ambiguous profile unless a Release-2-only header or a
    Release-1-only field value provides evidence; callers with capture metadata
    can select ``release1`` or ``release2`` explicitly.
    """
    try:
        raw = _bounded(data, minimum=4, label="GeoNetworking packet")
        requested_profile = _geonet_profile(profile)
        version, next_header = raw[0] >> 4, raw[0] & 0x0F
        if version != 1:
            raise V2XETSIError(f"unsupported GeoNetworking version {version}")
        if next_header not in (1, 2):
            raise V2XETSIError("Basic Header does not identify a common or secured header")
        if raw[1] != 0:
            raise V2XETSIError("GeoNetworking Basic Header reserved octet is non-zero")
        lifetime_raw = raw[2]
        multiplier, base_code = lifetime_raw >> 2, lifetime_raw & 3
        base_seconds = (0.05, 1.0, 10.0, 100.0)[base_code]
        basic = {
            "version": version,
            "next_header": next_header,
            "next_header_name": _GN_NEXT[next_header],
            "lifetime_raw": lifetime_raw,
            "lifetime_multiplier": multiplier,
            "lifetime_base_seconds": base_seconds,
            "lifetime_seconds": multiplier * base_seconds,
            "remaining_hop_limit": raw[3],
        }
        if next_header == 2:
            secured = parse_secured_envelope(raw[4:])
            return {
                "protocol": "ETSI GeoNetworking",
                "profile": (
                    "release1-or-release2" if requested_profile == "auto" else requested_profile
                ),
                "profile_requested": requested_profile,
                "basic": basic,
                "security": secured,
                "payload": secured.get("payload"),
                "validation_scope": "Basic Header and exact COER envelope framing; no signature verification",
            }

        if len(raw) < 12:
            raise V2XETSIError("truncated GeoNetworking Common Header")
        c = raw[4:12]
        upper, reserved_nibble = c[0] >> 4, c[0] & 0x0F
        header_type, subtype = c[1] >> 4, c[1] & 0x0F
        if upper not in _COMMON_NEXT:
            raise V2XETSIError("unsupported Common Header next-header value")
        if header_type not in _HEADER_TYPES:
            raise V2XETSIError("unsupported GeoNetworking header type")
        if reserved_nibble or c[7] != 0 or (c[3] & 0x7F):
            raise V2XETSIError("GeoNetworking Common Header reserved bits are non-zero")
        if requested_profile == "release1" and header_type in (7, 8):
            raise V2XETSIError("GeoNetworking header type is defined only by Release 2")
        if header_type in (7, 8):
            resolved_profile = "release2"
        elif requested_profile == "auto":
            # Release 1 defines bit 6 as channel-offload; Release 2 reserves it.
            resolved_profile = (
                "release1" if (c[2] & 0x40) or (c[2] & 0x3F) > 7
                else "release1-or-release2"
            )
        else:
            resolved_profile = requested_profile
        if resolved_profile == "release2":
            if c[2] & 0x40:
                raise V2XETSIError("Release-2 Traffic Class reserved bit is non-zero")
            if (c[2] & 0x3F) > 7:
                raise V2XETSIError("Release-2 Traffic Class ID has no defined PPPP mapping")
        payload_length = _u16(c, 4)
        common = {
            "next_header": upper,
            "next_header_name": _COMMON_NEXT[upper],
            "header_type": header_type,
            "header_type_name": _HEADER_TYPES[header_type],
            "header_subtype": subtype,
            "traffic_class": c[2],
            "store_carry_forward": bool(c[2] & 0x80),
            "channel_offload_release1": bool(c[2] & 0x40),
            "release2_reserved_bit_set": bool(c[2] & 0x40),
            "traffic_class_id": c[2] & 0x3F,
            "mobile": bool(c[3] & 0x80),
            "payload_length": payload_length,
            "maximum_hop_limit": c[6],
        }
        extended: dict[str, Any]
        end: int
        if header_type == 1:
            if subtype != 0:
                raise V2XETSIError("invalid Beacon subtype")
            extended = {"kind": "beacon", "source_position": _parse_lpv(raw, 12)}
            end = 36
        elif header_type == 2:
            if subtype != 0:
                raise V2XETSIError("invalid GeoUnicast subtype")
            if len(raw) < 60:
                raise V2XETSIError("truncated GeoUnicast extended header")
            if _u16(raw, 14):
                raise V2XETSIError("GeoUnicast reserved field is non-zero")
            extended = {
                "kind": "geo-unicast", "sequence_number": _u16(raw, 12),
                "source_position": _parse_lpv(raw, 16),
                "destination_position": _parse_spv(raw, 40),
            }
            end = 60
        elif header_type in (3, 4):
            if subtype not in (0, 1, 2):
                raise V2XETSIError("invalid GeoAnycast/GeoBroadcast shape subtype")
            if len(raw) < 56:
                raise V2XETSIError("truncated geographical-area extended header")
            if _u16(raw, 14) or _u16(raw, 54):
                raise V2XETSIError("geographical-area reserved field is non-zero")
            latitude = _u32(raw, 40, signed=True)
            longitude = _u32(raw, 44, signed=True)
            extended = {
                "kind": "geo-anycast" if header_type == 3 else "geo-broadcast",
                "shape": ("circle", "rectangle", "ellipse")[subtype],
                "sequence_number": _u16(raw, 12),
                "source_position": _parse_lpv(raw, 16),
                "area": {
                    "latitude_raw": latitude, "longitude_raw": longitude,
                    "latitude_degrees": latitude / 10_000_000,
                    "longitude_degrees": longitude / 10_000_000,
                    "distance_a_m": _u16(raw, 48), "distance_b_m": _u16(raw, 50),
                    "angle_degrees": _u16(raw, 52),
                },
            }
            end = 56
        elif header_type == 5 and subtype == 0:
            if len(raw) < 40:
                raise V2XETSIError("truncated SHB extended header")
            media_dependent = _u32(raw, 36)
            extended = {
                "kind": "shb", "source_position": _parse_lpv(raw, 12),
                "media_dependent": media_dependent,
                "media_dependent_data_hex": raw[36:40].hex(),
            }
            if resolved_profile in ("release2", "release1-or-release2"):
                try:
                    extended["release2_media_dependent"] = _release2_media_dependent(raw, 36)
                except V2XETSIError:
                    if resolved_profile == "release2":
                        raise
                    resolved_profile = "release1"
            end = 40
        elif header_type == 5 and subtype == 1:
            if len(raw) < 40:
                raise V2XETSIError("truncated TSB extended header")
            if _u16(raw, 14):
                raise V2XETSIError("TSB reserved field is non-zero")
            extended = {
                "kind": "multi-hop-tsb", "sequence_number": _u16(raw, 12),
                "source_position": _parse_lpv(raw, 16),
            }
            end = 40
        elif header_type == 6 and subtype == 0:
            if len(raw) < 48:
                raise V2XETSIError("truncated Location Service Request header")
            if _u16(raw, 14):
                raise V2XETSIError("Location Service Request reserved field is non-zero")
            extended = {
                "kind": "location-service-request", "sequence_number": _u16(raw, 12),
                "source_position": _parse_lpv(raw, 16),
                "requested_address": _position_address(raw[40:48]),
            }
            end = 48
        elif header_type == 6 and subtype == 1:
            if len(raw) < 60:
                raise V2XETSIError("truncated Location Service Reply header")
            if _u16(raw, 14):
                raise V2XETSIError("Location Service Reply reserved field is non-zero")
            extended = {
                "kind": "location-service-reply", "sequence_number": _u16(raw, 12),
                "source_position": _parse_lpv(raw, 16),
                "destination_position": _parse_spv(raw, 40),
            }
            end = 60
        elif header_type in (7, 8) and subtype == 0:
            if len(raw) < 40:
                raise V2XETSIError("truncated Release-2 single-hop extended header")
            media = _release2_media_dependent(raw, 36)
            extended = {
                "kind": "single-hop-unicast" if header_type == 7 else "single-hop-groupcast",
                "source_position": _parse_lpv(raw, 12),
                "media_dependent": _u32(raw, 36),
                "media_dependent_data_hex": raw[36:40].hex(),
                "release2_media_dependent": media,
            }
            end = 40
        elif header_type in (7, 8) and subtype == 1:
            raise V2XETSIError(
                "Release-2 multi-hop TSU/TSG extended-header layout is not supported"
            )
        elif header_type == 0:
            raise V2XETSIError("unspecified GeoNetworking extended-header type")
        else:
            raise V2XETSIError("invalid GeoNetworking header type/subtype combination")

        if payload_length != len(raw) - end:
            raise V2XETSIError("Common Header payload length does not match packet framing")
        if header_type == 1 and payload_length:
            raise V2XETSIError("Beacon packet unexpectedly carries a payload")
        payload = raw[end:]
        if resolved_profile == "release1":
            common["channel_offload"] = common["channel_offload_release1"]
        else:
            common["release2_pppp"] = (c[2] & 0x3F) + 1
        result: dict[str, Any] = {
            "protocol": "ETSI GeoNetworking", "basic": basic, "common": common,
            "extended": extended, "payload": payload,
            "profile": resolved_profile,
            "profile_requested": requested_profile,
            "validation_scope": (
                "EN 302 636-4-1 / TS 103 836-4-1 structure, selected reserved fields, "
                "and exact payload framing"
            ),
        }
        if upper in (1, 2):
            result["btp"] = parse_btp(payload, "A" if upper == 1 else "B")
            result["payload"] = result["btp"]["payload"]
        return result
    except V2XETSIError:
        raise
    except Exception as exc:
        raise V2XETSIError("GeoNetworking decoding failed") from exc


def _normalise(value: Any, budget: list[int], depth: int = 0) -> Any:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise V2XETSIError("decoded ASN.1 object exceeds structural limits")
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    if isinstance(value, tuple):
        if len(value) == 2 and isinstance(value[0], str):
            return {value[0]: _normalise(value[1], budget, depth + 1)}
        if len(value) == 2 and all(isinstance(item, int) for item in value):
            return {"value": value[0], "bit_length": value[1]}
        return [_normalise(item, budget, depth + 1) for item in value]
    if isinstance(value, list):
        return [_normalise(item, budget, depth + 1) for item in value]
    if isinstance(value, dict):
        return {str(key): _normalise(item, budget, depth + 1) for key, item in value.items()}
    if value is None or isinstance(value, (str, int, bool, float)):
        return value
    raise V2XETSIError(f"unexpected ASN.1 value type {type(value).__name__}")


def _decode_uper(schema: Any, data: bytes) -> Any:
    try:
        from pycrate_asn1rt.codecs import ASN1CodecPER
        from pycrate_core.charpy import Charpy
    except ImportError as exc:
        raise V2XETSIError("UPER decoding needs the optional pycrate package") from exc
    try:
        with _ASN1_LOCK:
            saved_offsets, saved_aligned = list(ASN1CodecPER._off), ASN1CodecPER.ALIGNED
            try:
                obj = copy.deepcopy(schema)
                buf = Charpy(data)
                obj.from_uper(buf)
                remaining = buf.len_bit()
                if remaining > 7 or (remaining and buf.to_uint() != 0):
                    raise V2XETSIError("trailing non-padding bits after UPER PDU")
                if obj.to_uper() != data:
                    raise V2XETSIError("non-canonical ITS UPER encoding")
                return obj.get_val()
            finally:
                ASN1CodecPER._off[:] = saved_offsets
                ASN1CodecPER.ALIGNED = saved_aligned
    except V2XETSIError:
        raise
    except Exception as exc:
        raise V2XETSIError("invalid ITS UPER encoding") from exc


def _its_schema(message_type: str) -> Any:
    try:
        if message_type == "cam":
            from pycrate_asn1dir import ITS_CAM_2
            return ITS_CAM_2.CAM_PDU_Descriptions.CAM
        if message_type == "denm":
            from pycrate_asn1dir import ITS_DENM_3
            return ITS_DENM_3.DENM_PDU_Descriptions.DENM
        from pycrate_asn1dir import ITS_IS
        return {
            "spatem": ITS_IS.SPATEM_PDU_Descriptions.SPATEM,
            "mapem": ITS_IS.MAPEM_PDU_Descriptions.MAPEM,
            "ivim": ITS_IS.IVIM_PDU_Descriptions.IVIM,
        }[message_type]
    except (ImportError, AttributeError, KeyError) as exc:
        raise V2XETSIError("ITS UPER decoding needs pycrate with compiled ITS schemas") from exc


def parse_its_pdu(
    data: bytes | bytearray | memoryview, message_type: str | None = None,
) -> dict[str, Any]:
    """Decode a legacy facilities PDU or inventory a current facilities PDU.

    Protocol version 1 is decoded against pycrate's established ETSI schemas.
    Current protocol version 2 uses newer, separately published ASN.1 modules
    that pycrate does not ship; its fixed six-octet ``ItsPduHeader`` is returned
    with the body explicitly opaque instead of being mis-decoded as Release 1.
    """
    try:
        raw = _bounded(data, minimum=6, label="ITS PDU")
        protocol_version, message_id = raw[0], raw[1]
        detected = _ITS_IDS.get(message_id)
        if message_type is None:
            if detected is None:
                raise V2XETSIError(f"unsupported ITS message ID {message_id}")
            selected = detected
        else:
            if not isinstance(message_type, str):
                raise V2XETSIError("message_type must be text")
            selected = message_type.lower()
            if selected not in set(_ITS_IDS.values()):
                raise V2XETSIError("message_type must be cam, denm, spatem, mapem, or ivim")
            expected = next(key for key, name in _ITS_IDS.items() if name == selected)
            if message_id != expected:
                raise V2XETSIError(
                    f"ITS header message ID {message_id} does not match requested {selected}"
                )
        station_id = _u32(raw, 2)
        header_result = {
            "protocol_version": protocol_version,
            "message_id": message_id,
            "station_id": station_id,
        }
        if protocol_version == 2:
            return {
                "protocol": "ETSI ITS facilities",
                "encoding": "unaligned PER",
                "message_type": selected,
                "protocol_version": protocol_version,
                "message_id": message_id,
                "station_id": station_id,
                "header": header_result,
                "opaque_body": raw[6:],
                "opaque_body_length": len(raw) - 6,
                "schema": None,
                "schema_decoded": False,
                "validation_scope": (
                    "fixed Release-2 ItsPduHeader only; the facilities body is opaque "
                    "and has not been ASN.1-validated"
                ),
            }
        if protocol_version != 1:
            raise V2XETSIError(
                f"unsupported ITS facilities protocol version {protocol_version}"
            )
        decoded = _decode_uper(_its_schema(selected), raw)
        if not isinstance(decoded, dict) or not isinstance(decoded.get("header"), dict):
            raise V2XETSIError("decoded ITS PDU lacks its mandatory header")
        header = decoded["header"]
        if header.get("messageID") != message_id or header.get("protocolVersion") != protocol_version:
            raise V2XETSIError("decoded ITS header disagrees with the on-wire prefix")
        return {
            "protocol": "ETSI ITS facilities",
            "encoding": "unaligned PER",
            "message_type": selected,
            "protocol_version": protocol_version,
            "message_id": message_id,
            "station_id": station_id,
            "header": header_result,
            "fields": _normalise({key: value for key, value in decoded.items() if key != "header"}, [MAX_NODES]),
            "schema": "pycrate ETSI protocolVersion-1 compiled ASN.1 modules",
            "schema_decoded": True,
            "validation_scope": "ASN.1 constraints and whole-PDU framing; no application-state validation",
        }
    except V2XETSIError:
        raise
    except Exception as exc:
        raise V2XETSIError("ITS UPER decoding failed") from exc


def _find_unsecured(value: Any, depth: int = 0) -> bytes | None:
    if depth > 12:
        return None
    if isinstance(value, dict):
        content = value.get("content")
        if isinstance(content, tuple) and len(content) == 2 and content[0] == "unsecuredData":
            return content[1] if isinstance(content[1], bytes) else None
        for key in ("data", "payload", "tbsData"):
            if key in value:
                found = _find_unsecured(value[key], depth + 1)
                if found is not None:
                    return found
    if isinstance(value, tuple) and len(value) == 2:
        if value[0] == "unsecuredData" and isinstance(value[1], bytes):
            return value[1]
        return _find_unsecured(value[1], depth + 1)
    return None


def parse_secured_envelope(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one COER IEEE 1609.2 / ETSI TS 103 097 envelope, without trust claims."""
    try:
        raw = _bounded(data, label="secured envelope")
        try:
            from pycrate_asn1dir import ITS_IEEE1609_2
            from pycrate_core.charpy import Charpy
        except ImportError as exc:
            raise V2XETSIError("security-envelope decoding needs the optional pycrate package") from exc
        with _ASN1_LOCK:
            obj = copy.deepcopy(ITS_IEEE1609_2.Ieee1609Dot2.Ieee1609Dot2Data)
            buf = Charpy(raw)
            obj.from_coer(buf)
            if buf.len_bit():
                raise V2XETSIError("trailing data after secured envelope")
            if obj.to_coer() != raw:
                raise V2XETSIError("non-canonical IEEE 1609.2 COER encoding")
            decoded = obj.get_val()
        if not isinstance(decoded, dict) or not isinstance(decoded.get("content"), tuple):
            raise V2XETSIError("invalid Ieee1609Dot2Data structure")
        if decoded.get("protocolVersion") != 3:
            raise V2XETSIError("unsupported Ieee1609Dot2Data protocol version")
        content_type = decoded["content"][0]
        return {
            "protocol": "IEEE 1609.2 / ETSI TS 103 097",
            "encoding": "COER",
            "protocol_version": decoded.get("protocolVersion"),
            "content_type": content_type,
            "schema_profile": "pycrate IEEE 1609.2 module OID major 2 minor 3",
            "payload": _find_unsecured(decoded),
            "decoded": _normalise(decoded, [MAX_NODES]),
            "signature_verified": False,
            "decryption_performed": False,
            "validation_scope": "COER structure and exact framing only; certificates and signatures are not trusted or verified",
        }
    except V2XETSIError:
        raise
    except Exception as exc:
        raise V2XETSIError("secured-envelope decoding failed") from exc


class _Bits:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, width: int) -> int:
        if not isinstance(width, int) or width < 0 or self.offset + width > 8 * len(self.data):
            raise V2XETSIError("truncated NR sidelink SCI field")
        value = 0
        for _ in range(width):
            value = (value << 1) | ((self.data[self.offset // 8] >> (7 - self.offset % 8)) & 1)
            self.offset += 1
        return value

    def finish_zero_padding(self) -> int:
        remaining = 8 * len(self.data) - self.offset
        if remaining > 7 or self.read(remaining):
            raise V2XETSIError("NR sidelink SCI has trailing non-padding bits")
        return remaining


def _width_for_count(count: int) -> int:
    if not isinstance(count, int) or count < 1:
        raise V2XETSIError("SCI configured choice count must be positive")
    return (count - 1).bit_length()


def parse_nr_sidelink_sci(
    data: bytes | bytearray | memoryview,
    fmt: str,
    *,
    num_subchannels: int | None = None,
    max_num_per_reserve: int = 2,
    resource_reservation_period_count: int = 1,
    dmrs_pattern_count: int = 1,
    additional_mcs_tables: int = 0,
    psfch_period: int = 0,
    reserved_bits: int = 0,
    nr_release: int = 16,
) -> dict[str, Any]:
    """Decode supplied 3GPP TS 38.212 NR-PC5 SCI information bits.

    SCI 1-A has configuration-dependent widths, so its relevant RRC resource-pool
    counts must be supplied.  This parses already recovered information bits; it
    does not demodulate PSCCH/PSSCH or infer missing radio configuration.
    """
    try:
        raw = _bounded(data, label="NR sidelink SCI")
        if type(nr_release) is not int or nr_release != 16:
            raise V2XETSIError(
                "only NR Release 16 SCI is supported; later releases need additional RRC context"
            )
        if not isinstance(fmt, str):
            raise V2XETSIError("SCI format must be text")
        selected = fmt.lower().replace("sci-", "").replace("_", "-")
        bits = _Bits(raw)
        if selected == "2a":
            selected = "2-a"
        if selected == "2b":
            selected = "2-b"
        if selected == "1a":
            selected = "1-a"
        if selected == "2-a":
            cast_raw: int
            fields = {
                "harq_process_number": bits.read(4),
                "new_data_indicator": bits.read(1),
                "redundancy_version": bits.read(2),
                "source_id": bits.read(8),
                "destination_id": bits.read(16),
                "harq_feedback_enabled": bool(bits.read(1)),
            }
            cast_raw = bits.read(2)
            fields["cast_type_raw"] = cast_raw
            fields["cast_type"] = (
                "broadcast", "groupcast-ack-nack", "unicast", "groupcast-nack-only"
            )[cast_raw]
            fields["csi_request"] = bool(bits.read(1))
        elif selected == "2-b":
            fields = {
                "harq_process_number": bits.read(4),
                "new_data_indicator": bits.read(1),
                "redundancy_version": bits.read(2),
                "source_id": bits.read(8),
                "destination_id": bits.read(16),
                "harq_feedback_enabled": bool(bits.read(1)),
                "zone_id": bits.read(12),
                "communication_range_requirement": bits.read(4),
            }
        elif selected == "1-a":
            if not isinstance(num_subchannels, int) or not 1 <= num_subchannels <= 1024:
                raise V2XETSIError("SCI 1-A needs num_subchannels in 1..1024")
            if max_num_per_reserve not in (2, 3):
                raise V2XETSIError("max_num_per_reserve must be 2 or 3")
            if not isinstance(additional_mcs_tables, int) or additional_mcs_tables not in (0, 1, 2):
                raise V2XETSIError("additional_mcs_tables must be 0, 1, or 2")
            if psfch_period not in (0, 1, 2, 4):
                raise V2XETSIError("psfch_period must be 0, 1, 2, or 4")
            if not isinstance(reserved_bits, int) or not 0 <= reserved_bits <= 64:
                raise V2XETSIError("reserved_bits must be 0..64")
            if max_num_per_reserve == 2:
                frequency_choices = num_subchannels * (num_subchannels + 1) // 2
                time_width = 5
            else:
                frequency_choices = (
                    num_subchannels * (num_subchannels + 1) * (2 * num_subchannels + 1) // 6
                )
                time_width = 9
            fields = {
                "priority": bits.read(3) + 1,
                "frequency_resource_assignment": bits.read(_width_for_count(frequency_choices)),
                "time_resource_assignment": bits.read(time_width),
                "resource_reservation_period": bits.read(
                    _width_for_count(resource_reservation_period_count)
                ),
                "dmrs_pattern": bits.read(_width_for_count(dmrs_pattern_count)),
            }
            second = bits.read(2)
            if second > 1:
                raise V2XETSIError("reserved Release-16 second-stage SCI format")
            second_names = ("2-A", "2-B")
            fields.update({
                "second_stage_format_raw": second,
                "second_stage_format": second_names[second],
                "beta_offset_indicator": bits.read(2),
                "number_of_dmrs_ports": bits.read(1) + 1,
                "modulation_and_coding_scheme": bits.read(5),
                "additional_mcs_table_indicator": bits.read(additional_mcs_tables),
            })
            if psfch_period in (2, 4):
                fields["psfch_overhead_indication"] = bits.read(1)
            reserved = bits.read(reserved_bits)
            if reserved:
                raise V2XETSIError("SCI 1-A reserved bits are non-zero")
            fields["reserved_bits"] = reserved_bits
        else:
            raise V2XETSIError("SCI format must be 1-A, 2-A, or 2-B")
        consumed = bits.offset
        padding = bits.finish_zero_padding()
        return {
            "protocol": "3GPP NR sidelink SCI",
            "bearer": "NR-PC5",
            "nr_release": nr_release,
            "format": selected.upper(),
            "information_bits": consumed,
            "padding_bits": padding,
            "fields": fields,
            "validation_scope": "TS 38.212 field layout only; no PHY decoding or resource-validity claim",
        }
    except V2XETSIError:
        raise
    except Exception as exc:
        raise V2XETSIError("NR sidelink SCI decoding failed") from exc


def analyze(
    data: bytes | bytearray | memoryview,
    *,
    layer: str = "auto",
    message_type: str | None = None,
    profile: str = "auto",
) -> dict[str, Any]:
    """Peel a supplied ETSI V2X artifact without guessing through malformed layers."""
    try:
        raw = _bounded(data)
        if not isinstance(layer, str):
            raise V2XETSIError("layer must be text")
        selected = layer.lower()
        if selected == "geonet":
            return parse_geonetworking(raw, profile=profile)
        if selected == "btp-a":
            return parse_btp(raw, "A")
        if selected == "btp-b":
            return parse_btp(raw, "B")
        if selected == "its":
            return parse_its_pdu(raw, message_type)
        if selected == "security":
            return parse_secured_envelope(raw)
        if selected != "auto":
            raise V2XETSIError("layer must be auto, geonet, btp-a, btp-b, its, or security")

        if raw[0] >> 4 == 1 and (raw[0] & 0x0F) in (1, 2):
            outer = parse_geonetworking(raw, profile=profile)
            payload = outer.get("payload")
            if isinstance(payload, bytes) and payload:
                try:
                    security = parse_secured_envelope(payload)
                    outer["inner_security"] = security
                    payload = security.get("payload")
                except V2XETSIError:
                    pass
                if isinstance(payload, bytes) and len(payload) >= 6:
                    try:
                        outer["its"] = parse_its_pdu(payload, message_type)
                    except V2XETSIError:
                        pass
            return outer
        try:
            security = parse_secured_envelope(raw)
            payload = security.get("payload")
            if isinstance(payload, bytes) and len(payload) >= 6:
                try:
                    security["its"] = parse_its_pdu(payload, message_type)
                except V2XETSIError:
                    pass
            return security
        except V2XETSIError:
            return parse_its_pdu(raw, message_type)
    except V2XETSIError:
        raise
    except Exception as exc:
        raise V2XETSIError("V2X analysis failed") from exc


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="passive ETSI cooperative-V2X artifact decoder")
    parser.add_argument("mode", choices=("auto", "geonet", "btp-a", "btp-b", "its", "security", "nr-sci"))
    parser.add_argument("artifact", help="saved binary artifact (or hexadecimal text with --hex)")
    parser.add_argument("--hex", action="store_true", help="artifact contains hexadecimal text")
    parser.add_argument("--message-type", choices=tuple(_ITS_IDS.values()))
    parser.add_argument(
        "--profile", choices=("auto", "release1", "release2"), default="auto",
        help="GeoNetworking standards profile (the on-wire version is ambiguous)",
    )
    parser.add_argument("--sci-format", choices=("1-a", "2-a", "2-b"), default="2-a")
    parser.add_argument("--num-subchannels", type=int)
    parser.add_argument("--max-num-per-reserve", type=int, default=2)
    parser.add_argument("--reservation-period-count", type=int, default=1)
    parser.add_argument("--dmrs-pattern-count", type=int, default=1)
    parser.add_argument("--additional-mcs-tables", type=int, default=0)
    parser.add_argument("--psfch-period", type=int, default=0)
    parser.add_argument("--reserved-bits", type=int, default=0)
    parser.add_argument("--nr-release", type=int, default=16)
    try:
        args = parser.parse_args(argv)
        limit = 2 * MAX_INPUT + 4096 if args.hex else MAX_INPUT + 1
        with Path(args.artifact).open("rb") as handle:
            raw = handle.read(limit)
        if args.hex:
            raw = bytes.fromhex(raw.decode("ascii"))
        if args.mode == "nr-sci":
            result = parse_nr_sidelink_sci(
                raw, args.sci_format,
                num_subchannels=args.num_subchannels,
                max_num_per_reserve=args.max_num_per_reserve,
                resource_reservation_period_count=args.reservation_period_count,
                dmrs_pattern_count=args.dmrs_pattern_count,
                additional_mcs_tables=args.additional_mcs_tables,
                psfch_period=args.psfch_period,
                reserved_bits=args.reserved_bits,
                nr_release=args.nr_release,
            )
        else:
            result = analyze(
                raw, layer=args.mode, message_type=args.message_type, profile=args.profile
            )
        print(json.dumps(result, indent=2, sort_keys=True, default=_json_default))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (V2XETSIError, OSError, UnicodeError, ValueError) as exc:
        print(f"sec_v2x_etsi: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
