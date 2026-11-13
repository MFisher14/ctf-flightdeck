#!/usr/bin/env python3
"""Passive US cooperative-V2X artifact decoder.

This module decodes supplied IEEE 1609.3 WSMP v3 frames, SAE J2735-2024
MessageFrame UPER (BSM, SPaT, MAP, TIM, SRM, and SSM), IEEE 1609.2 secured
message envelopes, and already-recovered 3GPP NR sidelink SCI information
bits.  It is an offline parser: it does not open a radio/socket/interface,
craft traffic, execute input, verify certificates/signatures, or demodulate a
PC5 waveform.

CLI examples::

  ./.venv/bin/python solvers/toolkits/sec_v2x_j2735.py wsmp wsm.bin
  ./.venv/bin/python solvers/toolkits/sec_v2x_j2735.py j2735 bsm.uper --message-type bsm
  ./.venv/bin/python solvers/toolkits/sec_v2x_j2735.py security secured.coer
  ./.venv/bin/python solvers/toolkits/sec_v2x_j2735.py nr-sci sci.bin --sci-format 2-a
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
MAX_INFORMATION_ELEMENTS = 64
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


class V2XJ2735Error(ValueError):
    """Malformed, unsupported, over-limit, or undecodable saved V2X data."""


_IE_NAMES = {
    4: "transmit_power", 15: "channel_number", 16: "data_rate",
    25: "compact_time_confidence",
}
_IE_FIXED_LENGTHS = {identifier: 1 for identifier in _IE_NAMES}
_MESSAGE_IDS = {18: "map", 19: "spat", 20: "bsm", 29: "srm", 30: "ssm", 31: "tim"}
_CHOICE_NAMES = {
    "map": "MapData", "spat": "SPAT", "bsm": "BasicSafetyMessage",
    "srm": "SignalRequestMessage", "ssm": "SignalStatusMessage",
    "tim": "TravelerInformation",
}


def _bounded(data: Any, *, minimum: int = 1, label: str = "input") -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise V2XJ2735Error(f"{label} must be bytes-like")
    size = data.nbytes if isinstance(data, memoryview) else len(data)
    if not minimum <= size <= MAX_INPUT:
        raise V2XJ2735Error(f"{label} size must be {minimum}..{MAX_INPUT} bytes")
    try:
        return bytes(data)
    except Exception as exc:
        raise V2XJ2735Error(f"{label} cannot be materialized") from exc


class _Cursor:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, count: int) -> bytes:
        if not isinstance(count, int) or count < 0 or self.offset + count > len(self.data):
            raise V2XJ2735Error("truncated WSMP field")
        value = self.data[self.offset:self.offset + count]
        self.offset += count
        return value

    def octet(self) -> int:
        return self.take(1)[0]

    def remaining(self) -> int:
        return len(self.data) - self.offset


def _wsmp_count(cursor: _Cursor, what: str) -> int:
    first = cursor.octet()
    if first < 0x80:
        return first
    if first & 0xC0 != 0x80:
        raise V2XJ2735Error(f"invalid WSMP {what} determinant")
    value = ((first & 0x3F) << 8) | cursor.octet()
    if value < 128:
        raise V2XJ2735Error(f"non-canonical two-octet WSMP {what}")
    return value


def _wsmp_psid(cursor: _Cursor) -> tuple[int, int]:
    first = cursor.octet()
    if first & 0x80 == 0:
        return first, 1
    if first & 0xC0 == 0x80:
        raw = (first << 8) | cursor.octet()
        return (raw & 0x7FFF) + 0x80, 2
    if first & 0xE0 == 0xC0:
        raw = (first << 16) | int.from_bytes(cursor.take(2), "big")
        return (raw & 0x3FFFFF) + 0x4080, 3
    if first & 0xF0 == 0xE0:
        raw = (first << 24) | int.from_bytes(cursor.take(3), "big")
        return (raw & 0x1FFFFFFF) + 0x204080, 4
    raise V2XJ2735Error("reserved IEEE 1609.12 PSID prefix")


def _wsmp_information_elements(cursor: _Cursor) -> list[dict[str, Any]]:
    count = _wsmp_count(cursor, "information-element count")
    if count > MAX_INFORMATION_ELEMENTS:
        raise V2XJ2735Error("WSMP information-element count exceeds cap")
    elements = []
    for _ in range(count):
        identifier = cursor.octet()
        length = _wsmp_count(cursor, "information-element length")
        expected = _IE_FIXED_LENGTHS.get(identifier)
        if expected is not None and length != expected:
            raise V2XJ2735Error(
                f"WSMP information element {identifier} must be {expected} octet"
            )
        elements.append({
            "id": identifier,
            "name": _IE_NAMES.get(identifier, "unknown"),
            "data": cursor.take(length),
        })
    return elements


def parse_wsmp(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode exactly one IEEE 1609.3 WSMP version-3 WAVE Short Message."""
    try:
        raw = _bounded(data, minimum=4, label="WSMP message")
        cursor = _Cursor(raw)
        first = cursor.octet()
        subtype, option_indicator, version = first >> 4, bool(first & 0x08), first & 0x07
        if version != 3:
            raise V2XJ2735Error(f"unsupported WSMP version {version}")
        if subtype != 0:
            raise V2XJ2735Error("reserved WSMP networking subtype")
        information_elements = _wsmp_information_elements(cursor) if option_indicator else []
        transport = cursor.octet()
        # IEEE 1609.3 models ShortMsgTpdus as a 128-way CHOICE followed by
        # the optional-field bitmap of ShortMsgBcPDU.  UPER therefore puts
        # the seven-bit TPID before the one-bit T-extension indicator.
        tpid = transport >> 1
        transport_extension_indicator = bool(transport & 0x01)
        result: dict[str, Any] = {
            "protocol": "IEEE 1609.3 WSMP",
            "version": version,
            "subtype": subtype,
            "option_indicator": option_indicator,
            "transport_extension_indicator": transport_extension_indicator,
            "tpid": tpid,
            "information_elements": information_elements,
        }
        if transport_extension_indicator:
            raise V2XJ2735Error("WSMP transport extensions are not supported")
        if tpid != 0:
            raise V2XJ2735Error("reserved WSMP TPID")
        psid, encoded_length = _wsmp_psid(cursor)
        result.update({"psid": psid, "psid_encoded_length": encoded_length})
        payload_length = _wsmp_count(cursor, "payload length")
        if payload_length != cursor.remaining():
            raise V2XJ2735Error("WSMP payload length does not match exact message framing")
        result["payload_length"] = payload_length
        result["payload"] = cursor.take(payload_length)
        result["validation_scope"] = "IEEE 1609.3 header syntax, canonical determinants, and exact framing"
        return result
    except V2XJ2735Error:
        raise
    except Exception as exc:
        raise V2XJ2735Error("WSMP decoding failed") from exc


def _normalise(value: Any, budget: list[int], depth: int = 0) -> Any:
    budget[0] -= 1
    if budget[0] < 0 or depth > MAX_DEPTH:
        raise V2XJ2735Error("decoded ASN.1 object exceeds structural limits")
    if isinstance(value, bytes):
        return value.hex()
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
    raise V2XJ2735Error(f"unexpected ASN.1 value type {type(value).__name__}")


def _decode_uper(schema: Any, data: bytes) -> Any:
    try:
        from pycrate_asn1rt.codecs import ASN1CodecPER
        from pycrate_core.charpy import Charpy
    except ImportError as exc:
        raise V2XJ2735Error("J2735 UPER decoding needs the optional pycrate package") from exc
    try:
        with _ASN1_LOCK:
            saved_offsets, saved_aligned = list(ASN1CodecPER._off), ASN1CodecPER.ALIGNED
            try:
                obj = copy.deepcopy(schema)
                buf = Charpy(data)
                obj.from_uper(buf)
                remaining = buf.len_bit()
                if remaining > 7 or (remaining and buf.to_uint() != 0):
                    raise V2XJ2735Error("trailing non-padding bits after J2735 UPER PDU")
                if obj.to_uper() != data:
                    raise V2XJ2735Error("non-canonical J2735 UPER encoding")
                return obj.get_val()
            finally:
                ASN1CodecPER._off[:] = saved_offsets
                ASN1CodecPER.ALIGNED = saved_aligned
    except V2XJ2735Error:
        raise
    except Exception as exc:
        raise V2XJ2735Error("invalid J2735 UPER encoding") from exc


def _j2735_module() -> Any:
    try:
        import j2735_202409
        return j2735_202409
    except ImportError as exc:
        raise V2XJ2735Error(
            "J2735 decoding needs the USDOT/FHWA j2735_202409 schema package"
        ) from exc


def _direct_schema(module: Any, message_type: str) -> Any:
    try:
        class_name = _CHOICE_NAMES[message_type]
        namespace = getattr(module, class_name)
        return getattr(namespace, class_name)
    except (KeyError, AttributeError) as exc:
        raise V2XJ2735Error(f"J2735 schema lacks {message_type}") from exc


def parse_j2735_message(
    data: bytes | bytearray | memoryview, message_type: str | None = None,
) -> dict[str, Any]:
    """Decode one SAE J2735-2024 MessageFrame (or a requested direct PDU)."""
    try:
        raw = _bounded(data, label="J2735 PDU")
        selected: str | None
        if message_type is not None:
            if not isinstance(message_type, str) or message_type.lower() not in set(_MESSAGE_IDS.values()):
                raise V2XJ2735Error("message_type must be bsm, spat, map, tim, srm, or ssm")
            selected = message_type.lower()
        else:
            selected = None
        module = _j2735_module()
        framed = True
        try:
            decoded = _decode_uper(module.MessageFrame.MessageFrame, raw)
        except V2XJ2735Error as exc:
            frame_error: V2XJ2735Error | None = exc
        else:
            frame_error = None
            if not isinstance(decoded, dict) or not isinstance(decoded.get("messageId"), int):
                frame_error = V2XJ2735Error("decoded MessageFrame lacks messageId")
        if frame_error is None:
            message_id = decoded["messageId"]
            detected = _MESSAGE_IDS.get(message_id)
            if detected is None:
                raise V2XJ2735Error(f"unsupported J2735 message ID {message_id}")
            if selected is not None and detected != selected:
                raise V2XJ2735Error(
                    f"MessageFrame ID {message_id} is {detected}, not requested {selected}"
                )
            selected = detected
            choice = decoded.get("value")
            if not isinstance(choice, tuple) or len(choice) != 2 or choice[0] != _CHOICE_NAMES[selected]:
                raise V2XJ2735Error("MessageFrame open type does not match its message ID")
            fields = choice[1]
        else:
            if selected is None:
                raise frame_error
            # Direct message PDUs occur in extracted logs.  A direct decode is
            # attempted only when the caller supplies its type explicitly.
            try:
                fields = _decode_uper(_direct_schema(module, selected), raw)
            except V2XJ2735Error:
                raise frame_error
            framed = False
            message_id = next(key for key, name in _MESSAGE_IDS.items() if name == selected)
        if not isinstance(fields, dict):
            raise V2XJ2735Error("decoded J2735 message body is not a mapping")
        rendered = _normalise(fields, [MAX_NODES])
        result: dict[str, Any] = {
            "protocol": "SAE J2735",
            "encoding": "unaligned PER",
            "schema": "J2735_202409",
            "message_type": selected,
            "message_id": message_id,
            "message_frame": framed,
            "fields": rendered,
            "validation_scope": "J2735 ASN.1 constraints and whole-PDU framing; no application-state validation",
        }
        if selected == "bsm":
            core = fields.get("coreData")
            if isinstance(core, dict):
                latitude = core.get("lat")
                longitude = core.get("long")
                speed = core.get("speed")
                heading = core.get("heading")
                result["summary"] = {
                    "temporary_id_hex": core.get("id", b"").hex() if isinstance(core.get("id"), bytes) else None,
                    "latitude_degrees": (
                        latitude / 10_000_000
                        if isinstance(latitude, int) and latitude != 900_000_001 else None
                    ),
                    "longitude_degrees": (
                        longitude / 10_000_000
                        if isinstance(longitude, int) and longitude != 1_800_000_001 else None
                    ),
                    "speed_mps": (
                        speed * 0.02 if isinstance(speed, int) and speed != 8191 else None
                    ),
                    "heading_degrees": (
                        heading * 0.0125
                        if isinstance(heading, int) and heading != 28800 else None
                    ),
                }
        return result
    except V2XJ2735Error:
        raise
    except Exception as exc:
        raise V2XJ2735Error("J2735 UPER decoding failed") from exc


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
    """Decode one COER IEEE 1609.2 envelope without verifying trust or signatures."""
    try:
        raw = _bounded(data, label="secured envelope")
        try:
            from pycrate_asn1dir import ITS_IEEE1609_2
            from pycrate_core.charpy import Charpy
        except ImportError as exc:
            raise V2XJ2735Error("security-envelope decoding needs the optional pycrate package") from exc
        with _ASN1_LOCK:
            obj = copy.deepcopy(ITS_IEEE1609_2.Ieee1609Dot2.Ieee1609Dot2Data)
            buf = Charpy(raw)
            obj.from_coer(buf)
            if buf.len_bit():
                raise V2XJ2735Error("trailing data after secured envelope")
            if obj.to_coer() != raw:
                raise V2XJ2735Error("non-canonical IEEE 1609.2 COER encoding")
            decoded = obj.get_val()
        if not isinstance(decoded, dict) or not isinstance(decoded.get("content"), tuple):
            raise V2XJ2735Error("invalid Ieee1609Dot2Data structure")
        if decoded.get("protocolVersion") != 3:
            raise V2XJ2735Error("unsupported Ieee1609Dot2Data protocol version")
        return {
            "protocol": "IEEE 1609.2",
            "encoding": "COER",
            "protocol_version": decoded.get("protocolVersion"),
            "content_type": decoded["content"][0],
            "schema_profile": "pycrate IEEE 1609.2 module OID major 2 minor 3",
            "payload": _find_unsecured(decoded),
            "decoded": _normalise(decoded, [MAX_NODES]),
            "signature_verified": False,
            "decryption_performed": False,
            "validation_scope": "COER structure and exact framing only; certificates and signatures are not trusted or verified",
        }
    except V2XJ2735Error:
        raise
    except Exception as exc:
        raise V2XJ2735Error("secured-envelope decoding failed") from exc


class _Bits:
    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def read(self, width: int) -> int:
        if not isinstance(width, int) or width < 0 or self.offset + width > 8 * len(self.data):
            raise V2XJ2735Error("truncated NR sidelink SCI field")
        value = 0
        for _ in range(width):
            value = (value << 1) | ((self.data[self.offset // 8] >> (7 - self.offset % 8)) & 1)
            self.offset += 1
        return value

    def finish_zero_padding(self) -> int:
        remaining = 8 * len(self.data) - self.offset
        if remaining > 7 or self.read(remaining):
            raise V2XJ2735Error("NR sidelink SCI has trailing non-padding bits")
        return remaining


def _width_for_count(count: int) -> int:
    if not isinstance(count, int) or count < 1:
        raise V2XJ2735Error("SCI configured choice count must be positive")
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
    """Decode supplied TS 38.212 NR-PC5 SCI 1-A, 2-A, or 2-B bits."""
    try:
        raw = _bounded(data, label="NR sidelink SCI")
        if type(nr_release) is not int or nr_release != 16:
            raise V2XJ2735Error(
                "only NR Release 16 SCI is supported; later releases need additional RRC context"
            )
        if not isinstance(fmt, str):
            raise V2XJ2735Error("SCI format must be text")
        selected = fmt.lower().replace("sci-", "").replace("_", "-")
        selected = {"1a": "1-a", "2a": "2-a", "2b": "2-b"}.get(selected, selected)
        bits = _Bits(raw)
        if selected == "2-a":
            fields: dict[str, Any] = {
                "harq_process_number": bits.read(4),
                "new_data_indicator": bits.read(1),
                "redundancy_version": bits.read(2),
                "source_id": bits.read(8),
                "destination_id": bits.read(16),
                "harq_feedback_enabled": bool(bits.read(1)),
            }
            cast = bits.read(2)
            fields["cast_type_raw"] = cast
            fields["cast_type"] = (
                "broadcast", "groupcast-ack-nack", "unicast", "groupcast-nack-only"
            )[cast]
            fields["cast_type_name"] = fields["cast_type"]
            fields["csi_request"] = bits.read(1)
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
                raise V2XJ2735Error("SCI 1-A needs num_subchannels in 1..1024")
            if max_num_per_reserve not in (2, 3):
                raise V2XJ2735Error("max_num_per_reserve must be 2 or 3")
            if not isinstance(additional_mcs_tables, int) or additional_mcs_tables not in (0, 1, 2):
                raise V2XJ2735Error("additional_mcs_tables must be 0, 1, or 2")
            if psfch_period not in (0, 1, 2, 4):
                raise V2XJ2735Error("psfch_period must be 0, 1, 2, or 4")
            if not isinstance(reserved_bits, int) or not 0 <= reserved_bits <= 64:
                raise V2XJ2735Error("reserved_bits must be 0..64")
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
                "resource_reservation_period": bits.read(_width_for_count(resource_reservation_period_count)),
                "dmrs_pattern": bits.read(_width_for_count(dmrs_pattern_count)),
            }
            second = bits.read(2)
            if second > 1:
                raise V2XJ2735Error("reserved Release-16 second-stage SCI format")
            second_names = ("2-A", "2-B")
            fields.update({
                "second_stage_format": second_names[second],
                "second_stage_format_raw": second,
                "beta_offset_indicator": bits.read(2),
                "number_of_dmrs_ports": bits.read(1) + 1,
                "modulation_and_coding_scheme": bits.read(5),
                "additional_mcs_table_indicator": bits.read(additional_mcs_tables),
            })
            if psfch_period in (2, 4):
                fields["psfch_overhead_indication"] = bits.read(1)
            if bits.read(reserved_bits):
                raise V2XJ2735Error("SCI 1-A reserved bits are non-zero")
            fields["reserved_bits"] = reserved_bits
        else:
            raise V2XJ2735Error("SCI format must be 1-A, 2-A, or 2-B")
        consumed = bits.offset
        padding = bits.finish_zero_padding()
        return {
            "protocol": "3GPP NR sidelink SCI",
            "bearer": "NR-PC5",
            "nr_release": nr_release,
            "format": selected.upper(),
            "information_bits": consumed,
            "padding_bits": padding,
            **fields,
            "fields": fields,
            "validation_scope": "TS 38.212 field layout only; no PHY decoding or resource-validity claim",
        }
    except V2XJ2735Error:
        raise
    except Exception as exc:
        raise V2XJ2735Error("NR sidelink SCI decoding failed") from exc


def analyze(
    data: bytes | bytearray | memoryview,
    *,
    layer: str = "auto",
    message_type: str | None = None,
) -> dict[str, Any]:
    """Peel one supplied WAVE/J2735 artifact without treating it as live traffic."""
    try:
        raw = _bounded(data)
        if not isinstance(layer, str):
            raise V2XJ2735Error("layer must be text")
        selected = layer.lower()
        if selected == "wsmp":
            return parse_wsmp(raw)
        if selected == "j2735":
            return parse_j2735_message(raw, message_type)
        if selected == "security":
            return parse_secured_envelope(raw)
        if selected != "auto":
            raise V2XJ2735Error("layer must be auto, wsmp, j2735, or security")
        if raw[0] & 7 == 3:
            try:
                outer = parse_wsmp(raw)
            except V2XJ2735Error:
                outer = None
            if outer is not None:
                payload = outer["payload"]
                try:
                    security = parse_secured_envelope(payload)
                    outer["security"] = security
                    payload = security.get("payload")
                except V2XJ2735Error:
                    pass
                if isinstance(payload, bytes) and payload:
                    try:
                        outer["j2735"] = parse_j2735_message(payload, message_type)
                    except V2XJ2735Error:
                        pass
                return outer
        try:
            security = parse_secured_envelope(raw)
            payload = security.get("payload")
            if isinstance(payload, bytes) and payload:
                try:
                    security["j2735"] = parse_j2735_message(payload, message_type)
                except V2XJ2735Error:
                    pass
            return security
        except V2XJ2735Error:
            return parse_j2735_message(raw, message_type)
    except V2XJ2735Error:
        raise
    except Exception as exc:
        raise V2XJ2735Error("V2X analysis failed") from exc


def _json_default(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"hex": value.hex()}
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="passive US WAVE/J2735 V2X artifact decoder")
    parser.add_argument("mode", choices=("auto", "wsmp", "j2735", "security", "nr-sci"))
    parser.add_argument("artifact", help="saved binary artifact (or hexadecimal text with --hex)")
    parser.add_argument("--hex", action="store_true", help="artifact contains hexadecimal text")
    parser.add_argument("--message-type", choices=tuple(_CHOICE_NAMES))
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
            result = analyze(raw, layer=args.mode, message_type=args.message_type)
        print(json.dumps(result, indent=2, sort_keys=True, default=_json_default))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (V2XJ2735Error, OSError, UnicodeError, ValueError) as exc:
        print(f"sec_v2x_j2735: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
