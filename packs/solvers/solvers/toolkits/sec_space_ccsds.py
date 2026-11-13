#!/usr/bin/env python3
"""Passive CCSDS/ECSS space-link artifact decoder.

The module consumes already captured bytes.  It implements the CCSDS Space
Packet primary header, TM and TC transfer frames, ECSS PUS-C secondary
headers, USLP transfer frames, and structural SDLS fields.  Mission-managed
options (FECF presence, TC segmentation, insert zones, and SDLS field sizes)
are always supplied by the caller; encrypted/authenticated data is never
claimed to be verified without keys.

References: CCSDS 133.0-B-2, 132.0-B-3, 232.0-B-4, 732.1-B-3,
355.0-B-2/355.1-B-1, and ECSS-E-ST-70-41C.
"""

from __future__ import annotations

import argparse
from functools import wraps
import json
from pathlib import Path
import sys
from typing import Any, Callable


MAX_INPUT = 1024 * 1024
MAX_PACKET = 65542
MAX_TC_FRAME = 1024
MAX_USLP_FRAME = 65536
MAX_PACKETS = 65536


class SecSpaceCCSDSError(ValueError):
    """Malformed, unsupported, contradictory, or excessive CCSDS input."""


def _declared(function: Callable[..., Any]) -> Callable[..., Any]:
    """Keep every public decoding entry point on the declared-error contract."""
    @wraps(function)
    def guarded(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except SecSpaceCCSDSError:
            raise
        except Exception as exc:
            raise SecSpaceCCSDSError(f"invalid {function.__name__} input") from exc
    return guarded


def _bytes(value: object, name: str, *, minimum: int = 0,
           maximum: int = MAX_INPUT, exact: int | None = None) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecSpaceCCSDSError(f"{name} must be a byte buffer")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        raw = bytes(value)
    except (BufferError, TypeError, ValueError) as exc:
        raise SecSpaceCCSDSError(f"invalid {name} byte buffer") from exc
    if size != len(raw):
        raise SecSpaceCCSDSError(f"non-contiguous {name} byte buffer")
    if exact is not None and len(raw) != exact:
        raise SecSpaceCCSDSError(f"{name} must be exactly {exact} bytes")
    if not minimum <= len(raw) <= maximum:
        raise SecSpaceCCSDSError(
            f"{name} length must be {minimum}..{maximum} bytes")
    return raw


def _small_uint(value: object, name: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise SecSpaceCCSDSError(f"{name} must be an integer in 0..{maximum}")
    return value


@_declared
def crc16_fecf(data: object) -> int:
    """CCSDS FECF CRC-16/IBM-3740 (poly 0x1021, init 0xffff)."""
    raw = _bytes(data, "CRC input", maximum=MAX_INPUT)
    crc = 0xFFFF
    for octet in raw:
        crc ^= octet << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xFFFF
    return crc


_SEQ_FLAGS = {
    0: "continuation", 1: "first_segment", 2: "last_segment", 3: "unsegmented",
}


@_declared
def parse_pus_secondary(data: object, direction: object, *,
                        time_length: object = 0) -> dict[str, Any]:
    """Decode one PUS-C secondary header and retain remaining application data.

    ``direction`` is ``"tc"`` or ``"tm"``.  TM time-code size is mission
    managed and therefore explicit.  The function parses the supplied buffer
    as a secondary header followed by application data.
    """
    raw = _bytes(data, "PUS data", minimum=1, maximum=MAX_PACKET)
    if not isinstance(direction, str) or direction not in ("tc", "tm"):
        raise SecSpaceCCSDSError("PUS direction must be tc or tm")
    time_size = _small_uint(time_length, "PUS time length", 64)
    if direction == "tc" and time_size:
        raise SecSpaceCCSDSError("PUS TC does not use a mission time field")
    fixed = 5 if direction == "tc" else 7
    needed = fixed + (time_size if direction == "tm" else 0)
    if len(raw) < needed:
        raise SecSpaceCCSDSError("truncated PUS secondary header")
    version = raw[0] >> 4
    if version != 2:
        raise SecSpaceCCSDSError("unsupported PUS secondary-header version")
    result: dict[str, Any] = {
        "protocol": "ecss-pus-c",
        "direction": direction,
        "version": version,
        "service": raw[1],
        "subtype": raw[2],
        "secondary_header_length": needed,
    }
    if direction == "tc":
        result.update({
            "acknowledgement_flags": raw[0] & 0x0F,
            "source_id": int.from_bytes(raw[3:5], "big"),
        })
    else:
        result.update({
            "time_reference_status": raw[0] & 0x0F,
            "message_type_counter": int.from_bytes(raw[3:5], "big"),
            "destination_id": int.from_bytes(raw[5:7], "big"),
            "time_code_hex": raw[7:needed].hex(),
        })
    result["application_data_hex"] = raw[needed:].hex()
    return result


@_declared
def parse_space_packet(data: object, *, pus: object = None,
                       pus_time_length: object = 0) -> dict[str, Any]:
    """Parse exactly one CCSDS Space Packet (133.0 primary header)."""
    raw = _bytes(data, "space packet", minimum=7, maximum=MAX_PACKET)
    packet_id = int.from_bytes(raw[:2], "big")
    version = packet_id >> 13
    if version != 0:
        raise SecSpaceCCSDSError("unsupported Space Packet version")
    sequence_control = int.from_bytes(raw[2:4], "big")
    data_size = int.from_bytes(raw[4:6], "big") + 1
    total = 6 + data_size
    if len(raw) != total:
        raise SecSpaceCCSDSError("Space Packet data-length field mismatch")
    packet_type = (packet_id >> 12) & 1
    secondary = bool(packet_id & 0x0800)
    result: dict[str, Any] = {
        "protocol": "ccsds-space-packet",
        "version": version,
        "packet_type": packet_type,
        "direction": "tc" if packet_type else "tm",
        "secondary_header_present": secondary,
        "apid": packet_id & 0x07FF,
        "idle_packet": (packet_id & 0x07FF) == 0x07FF,
        "sequence_flags": sequence_control >> 14,
        "sequence_flag_name": _SEQ_FLAGS[sequence_control >> 14],
        "sequence_count": sequence_control & 0x3FFF,
        "packet_data_length_field": data_size - 1,
        "packet_data_length": data_size,
        "total_length": total,
        "data_hex": raw[6:].hex(),
    }
    if pus is not None:
        if not secondary:
            raise SecSpaceCCSDSError("PUS requested without secondary-header flag")
        if not isinstance(pus, str) or pus not in ("tc", "tm"):
            raise SecSpaceCCSDSError("PUS profile must be tc, tm, or None")
        if pus != result["direction"]:
            raise SecSpaceCCSDSError("PUS profile contradicts Space Packet type")
        result["pus"] = parse_pus_secondary(
            raw[6:], pus, time_length=pus_time_length)
    else:
        if _small_uint(pus_time_length, "PUS time length", 64):
            raise SecSpaceCCSDSError("PUS time length supplied without a PUS profile")
    return result


@_declared
def parse_space_packet_stream(data: object, *, pus: object = None,
                              pus_time_length: object = 0) -> list[dict[str, Any]]:
    """Walk an exact concatenation of Space Packets without resynchronizing."""
    raw = _bytes(data, "space packet stream", minimum=7, maximum=MAX_INPUT)
    packets: list[dict[str, Any]] = []
    offset = 0
    while offset < len(raw):
        if len(packets) >= MAX_PACKETS or len(raw) - offset < 6:
            raise SecSpaceCCSDSError("truncated or excessive Space Packet stream")
        size = 7 + int.from_bytes(raw[offset + 4:offset + 6], "big")
        if size > len(raw) - offset:
            raise SecSpaceCCSDSError("truncated Space Packet in stream")
        packet = parse_space_packet(
            raw[offset:offset + size], pus=pus, pus_time_length=pus_time_length)
        packet["stream_offset"] = offset
        packets.append(packet)
        offset += size
    return packets


_TM_SEGMENT_LENGTH = {value: f"managed_code_{value}" for value in range(4)}


@_declared
def parse_tm_frame(data: object, *, has_fecf: object = False) -> dict[str, Any]:
    """Parse one CCSDS TM Transfer Frame with managed FECF presence."""
    raw = _bytes(data, "TM transfer frame", minimum=6, maximum=65536)
    if type(has_fecf) is not bool:
        raise SecSpaceCCSDSError("has_fecf must be boolean")
    if has_fecf and len(raw) < 8:
        raise SecSpaceCCSDSError("truncated TM FECF")
    content = raw[:-2] if has_fecf else raw
    received_fecf = int.from_bytes(raw[-2:], "big") if has_fecf else None
    if has_fecf and crc16_fecf(content) != received_fecf:
        raise SecSpaceCCSDSError("TM FECF mismatch")
    first = int.from_bytes(content[:2], "big")
    if first >> 14 != 0:
        raise SecSpaceCCSDSError("unsupported TM transfer-frame version")
    ocf_present = bool(first & 1)
    control = int.from_bytes(content[4:6], "big")
    secondary_present = bool(control & 0x8000)
    sync_flag = bool(control & 0x4000)
    order_flag = bool(control & 0x2000)
    segment_id = (control >> 11) & 3
    first_header_pointer = control & 0x07FF
    start = 6
    secondary: dict[str, Any] | None = None
    if secondary_present:
        if start >= len(content):
            raise SecSpaceCCSDSError("truncated TM secondary header")
        descriptor = content[start]
        sec_version = descriptor >> 6
        sec_length = (descriptor & 0x3F) + 1
        if sec_version != 0 or sec_length > len(content) - start:
            raise SecSpaceCCSDSError("invalid TM secondary header")
        secondary = {
            "version": sec_version,
            "length": sec_length,
            "data_hex": content[start:start + sec_length].hex(),
        }
        start += sec_length
    end = len(content)
    ocf_hex = None
    if ocf_present:
        if end - start < 4:
            raise SecSpaceCCSDSError("truncated TM operational-control field")
        end -= 4
        ocf_hex = content[end:end + 4].hex()
    data_field = content[start:end]
    if (first_header_pointer not in (0x07FE, 0x07FF)
            and first_header_pointer >= len(data_field)):
        raise SecSpaceCCSDSError("TM first-header pointer exceeds data field")
    return {
        "protocol": "ccsds-tm-transfer-frame",
        "version": 0,
        "spacecraft_id": (first >> 4) & 0x03FF,
        "virtual_channel_id": (first >> 1) & 7,
        "ocf_present": ocf_present,
        "master_channel_frame_count": content[2],
        "virtual_channel_frame_count": content[3],
        "secondary_header_present": secondary_present,
        "synchronization_flag": sync_flag,
        "packet_order_flag": order_flag,
        "segment_length_id": segment_id,
        "segment_length_name": _TM_SEGMENT_LENGTH[segment_id],
        "first_header_pointer": first_header_pointer,
        "first_header_pointer_kind": (
            "idle_data" if first_header_pointer == 0x07FE else
            "no_packet_start" if first_header_pointer == 0x07FF else "offset"),
        "secondary_header": secondary,
        "data_field_hex": data_field.hex(),
        "ocf_hex": ocf_hex,
        "fecf_present": has_fecf,
        "fecf": received_fecf,
        "fecf_valid": True if has_fecf else None,
        "total_length": len(raw),
    }


@_declared
def parse_tc_frame(data: object, *, has_fecf: object = False,
                   segmented: object = False) -> dict[str, Any]:
    """Parse one CCSDS TC Transfer Frame with explicit managed options."""
    raw = _bytes(data, "TC transfer frame", minimum=5, maximum=MAX_TC_FRAME)
    if type(has_fecf) is not bool or type(segmented) is not bool:
        raise SecSpaceCCSDSError("has_fecf and segmented must be boolean")
    if has_fecf and len(raw) < 7:
        raise SecSpaceCCSDSError("truncated TC FECF")
    content = raw[:-2] if has_fecf else raw
    received_fecf = int.from_bytes(raw[-2:], "big") if has_fecf else None
    if has_fecf and crc16_fecf(content) != received_fecf:
        raise SecSpaceCCSDSError("TC FECF mismatch")
    first = int.from_bytes(content[:2], "big")
    version = first >> 14
    bypass = bool(first & 0x2000)
    control_command = bool(first & 0x1000)
    reserved = (first >> 10) & 3
    if version != 0 or reserved:
        raise SecSpaceCCSDSError("unsupported TC version or nonzero reserved bits")
    if control_command and not bypass:
        raise SecSpaceCCSDSError("TC control command requires bypass mode")
    vc_length = int.from_bytes(content[2:4], "big")
    virtual_channel = vc_length >> 10
    declared_total = (vc_length & 0x03FF) + 1
    if declared_total != len(raw):
        raise SecSpaceCCSDSError("TC transfer-frame length mismatch")
    if segmented and control_command:
        raise SecSpaceCCSDSError("TC control command cannot have segment header")
    start = 5
    segment: dict[str, Any] | None = None
    if segmented:
        if start >= len(content):
            raise SecSpaceCCSDSError("truncated TC segment header")
        descriptor = content[start]
        sequence_flags = descriptor >> 6
        segment = {
            "sequence_flags": sequence_flags,
            "sequence_flag_name": _SEQ_FLAGS[sequence_flags],
            "map_id": descriptor & 0x3F,
        }
        start += 1
    if start > len(content):
        raise SecSpaceCCSDSError("truncated TC data field")
    return {
        "protocol": "ccsds-tc-transfer-frame",
        "version": version,
        "bypass_flag": bypass,
        "control_command_flag": control_command,
        "service_type": "type-b" if bypass else "type-a",
        "spacecraft_id": first & 0x03FF,
        "virtual_channel_id": virtual_channel,
        "frame_length_field": declared_total - 1,
        "total_length": len(raw),
        "frame_sequence_number": content[4],
        "segment_header": segment,
        "data_field_hex": content[start:].hex(),
        "fecf_present": has_fecf,
        "fecf": received_fecf,
        "fecf_valid": True if has_fecf else None,
    }


_USLP_RULES = {
    0: "fixed_packets_first_header_pointer",
    1: "fixed_start_complete_mapa_vca",
    2: "fixed_continuing_mapa_vca",
    3: "variable_octet_stream",
    4: "start_segment",
    5: "continuing_segment",
    6: "last_segment",
    7: "complete_no_segmentation",
}


@_declared
def parse_uslp_frame(data: object, *, has_fecf: object = False,
                     insert_zone_length: object = 0,
                     tfdf_pointer_present: object = False) -> dict[str, Any]:
    """Parse a CCSDS USLP frame, including the truncated-header form."""
    raw = _bytes(data, "USLP frame", minimum=4, maximum=MAX_USLP_FRAME)
    if type(has_fecf) is not bool:
        raise SecSpaceCCSDSError("has_fecf must be boolean")
    if type(tfdf_pointer_present) is not bool:
        raise SecSpaceCCSDSError("tfdf_pointer_present must be boolean")
    insert_size = _small_uint(insert_zone_length, "USLP insert-zone length", 255)
    primary = int.from_bytes(raw[:4], "big")
    version = primary >> 28
    if version != 0xC:
        raise SecSpaceCCSDSError("unsupported USLP transfer-frame version")
    end_of_header = bool(primary & 1)
    common: dict[str, Any] = {
        "protocol": "ccsds-uslp-transfer-frame",
        "version": version,
        "spacecraft_id": (primary >> 12) & 0xFFFF,
        "source_destination": (primary >> 11) & 1,
        "virtual_channel_id": (primary >> 5) & 0x3F,
        "map_id": (primary >> 1) & 0x0F,
        "end_of_header": end_of_header,
        "truncated": end_of_header,
        "total_length": len(raw),
    }
    if end_of_header:
        if has_fecf or insert_size or not 6 <= len(raw) <= 32:
            raise SecSpaceCCSDSError("invalid managed option/length for truncated USLP")
        tfdf = raw[4:]
        construction_rule = tfdf[0] >> 5
        upid = tfdf[0] & 0x1F
        tfdf_header_size = 1
        pointer = None
        if tfdf_pointer_present:
            if construction_rule not in (0, 1, 2) or len(tfdf) < 3:
                raise SecSpaceCCSDSError("invalid truncated USLP TFDF pointer profile")
            pointer = int.from_bytes(tfdf[1:3], "big")
            tfdf_header_size = 3
        elif construction_rule in (3, 4, 5, 6, 7):
            pass
        payload = tfdf[tfdf_header_size:]
        if not payload:
            raise SecSpaceCCSDSError("truncated USLP has no expedited user data")
        if pointer is not None and pointer != 0xFFFF and pointer >= len(payload):
            raise SecSpaceCCSDSError("truncated USLP TFDF pointer exceeds payload")
        common.update({
            "header_length": 4,
            "tfdf": {
                "construction_rule": construction_rule,
                "construction_rule_name": _USLP_RULES[construction_rule],
                "upid": upid,
                "pointer": pointer,
                "header_length": tfdf_header_size,
                "payload_hex": payload.hex(),
            },
            "fecf_present": False,
            "ocf_present": False,
        })
        return common
    if len(raw) < 8:
        raise SecSpaceCCSDSError("truncated USLP primary header")
    declared_total = int.from_bytes(raw[4:6], "big") + 1
    if declared_total != len(raw):
        raise SecSpaceCCSDSError("USLP transfer-frame length mismatch")
    control = raw[6]
    bypass = bool(control & 0x80)
    protocol_control = bool(control & 0x40)
    reserved = (control >> 4) & 3
    ocf_present = bool(control & 0x08)
    counter_size = control & 7
    if reserved:
        raise SecSpaceCCSDSError("nonzero USLP reserved bits")
    if protocol_control and not bypass:
        raise SecSpaceCCSDSError("USLP protocol-control frame requires bypass mode")
    header_end = 7 + counter_size
    if header_end + insert_size >= len(raw):
        raise SecSpaceCCSDSError("truncated USLP counter/insert/data field")
    counter = (int.from_bytes(raw[7:header_end], "big")
               if counter_size else None)
    insert_zone = raw[header_end:header_end + insert_size]
    content_end = len(raw)
    received_fecf = None
    if has_fecf:
        if content_end - (header_end + insert_size) < 2:
            raise SecSpaceCCSDSError("truncated USLP FECF")
        content_end -= 2
        received_fecf = int.from_bytes(raw[content_end:], "big")
        if crc16_fecf(raw[:content_end]) != received_fecf:
            raise SecSpaceCCSDSError("USLP FECF mismatch")
    ocf_hex = None
    if ocf_present:
        if content_end - (header_end + insert_size) < 5:
            raise SecSpaceCCSDSError("truncated USLP operational-control/TFDF field")
        content_end -= 4
        ocf_hex = raw[content_end:content_end + 4].hex()
    tfdf = raw[header_end + insert_size:content_end]
    if not tfdf:
        raise SecSpaceCCSDSError("missing USLP transfer-frame data-field header")
    construction_rule = tfdf[0] >> 5
    upid = tfdf[0] & 0x1F
    tfdf_header_size = 1
    pointer = None
    if tfdf_pointer_present:
        if construction_rule not in (0, 1, 2):
            raise SecSpaceCCSDSError("USLP TFDF pointer forbidden for construction rule")
        if len(tfdf) < 3:
            raise SecSpaceCCSDSError("truncated USLP TFDF pointer")
        pointer = int.from_bytes(tfdf[1:3], "big")
        tfdf_header_size = 3
        if pointer != 0xFFFF and pointer >= len(tfdf) - tfdf_header_size:
            raise SecSpaceCCSDSError("USLP TFDF pointer exceeds payload")
    common.update({
        "frame_length_field": declared_total - 1,
        "bypass_flag": bypass,
        "protocol_command_control_flag": protocol_control,
        "ocf_present": ocf_present,
        "virtual_channel_frame_count_length": counter_size,
        "virtual_channel_frame_count": counter,
        "header_length": header_end,
        "insert_zone_hex": insert_zone.hex(),
        "tfdf": {
            "construction_rule": construction_rule,
            "construction_rule_name": _USLP_RULES[construction_rule],
            "upid": upid,
            "pointer": pointer,
            "header_length": tfdf_header_size,
            "payload_hex": tfdf[tfdf_header_size:].hex(),
        },
        "ocf_hex": ocf_hex,
        "fecf_present": has_fecf,
        "fecf": received_fecf,
        "fecf_valid": True if has_fecf else None,
    })
    return common


def _sdls_sizes(sequence_length: object, iv_length: object,
                pad_length_field_length: object, mac_length: object = 0) -> tuple[int, int, int, int]:
    sequence = _small_uint(sequence_length, "SDLS sequence length", 8)
    iv = _small_uint(iv_length, "SDLS IV length", 32)
    pad = _small_uint(pad_length_field_length, "SDLS pad-length field size", 2)
    mac = _small_uint(mac_length, "SDLS MAC length", 64)
    if sequence not in (0, 2, 3, 4, 5, 6, 7, 8):
        raise SecSpaceCCSDSError("SDLS sequence length must be zero or 2..8")
    if pad not in (0, 1, 2):
        raise SecSpaceCCSDSError("SDLS pad-length field must be zero, one, or two")
    if mac and mac < 8:
        raise SecSpaceCCSDSError("SDLS MAC length must be zero or 8..64")
    if 2 + sequence + iv + pad > 64:
        raise SecSpaceCCSDSError("SDLS security header exceeds 64 bytes")
    return sequence, iv, pad, mac


@_declared
def parse_sdls_header(data: object, *, sequence_length: object = 0,
                      iv_length: object = 0,
                      pad_length_field_length: object = 0,
                      exact: object = True) -> dict[str, Any]:
    """Decode a profile-sized SDLS header (SPI, IV, sequence, pad length)."""
    sequence, iv, pad, _ = _sdls_sizes(
        sequence_length, iv_length, pad_length_field_length)
    if type(exact) is not bool:
        raise SecSpaceCCSDSError("exact must be boolean")
    needed = 2 + sequence + iv + pad
    raw = _bytes(data, "SDLS security header", minimum=needed, maximum=MAX_INPUT)
    if exact and len(raw) != needed:
        raise SecSpaceCCSDSError("undeclared bytes after SDLS security header")
    spi = int.from_bytes(raw[:2], "big")
    if spi in (0, 0xFFFF):
        raise SecSpaceCCSDSError("reserved SDLS security-parameter index")
    offset = 2
    iv_raw = raw[offset:offset + iv]
    offset += iv
    sequence_raw = raw[offset:offset + sequence]
    offset += sequence
    pad_raw = raw[offset:offset + pad]
    return {
        "protocol": "ccsds-sdls",
        "security_parameter_index": spi,
        "sequence_number_length": sequence,
        "sequence_number": int.from_bytes(sequence_raw, "big") if sequence else None,
        "sequence_number_hex": sequence_raw.hex(),
        "iv_length": iv,
        "iv_hex": iv_raw.hex(),
        "pad_length_field_length": pad,
        "pad_length": int.from_bytes(pad_raw, "big") if pad else 0,
        "header_length": needed,
        "authentication_verified": False,
    }


@_declared
def parse_sdls_fields(data: object, *, sequence_length: object = 0,
                      iv_length: object = 0,
                      pad_length_field_length: object = 0,
                      mac_length: object = 0) -> dict[str, Any]:
    """Split an SDLS security header, protected data, padding, and MAC trailer."""
    sequence, iv, pad, mac = _sdls_sizes(
        sequence_length, iv_length, pad_length_field_length, mac_length)
    header_size = 2 + sequence + iv + pad
    raw = _bytes(data, "SDLS secured data", minimum=header_size + mac,
                 maximum=MAX_INPUT)
    header = parse_sdls_header(
        raw[:header_size], sequence_length=sequence, iv_length=iv,
        pad_length_field_length=pad, exact=True)
    payload_end = len(raw) - mac
    protected = raw[header_size:payload_end]
    pad_size = header["pad_length"]
    if pad_size > len(protected):
        raise SecSpaceCCSDSError("SDLS padding exceeds protected data")
    payload = protected[:-pad_size] if pad_size else protected
    padding = protected[-pad_size:] if pad_size else b""
    result = dict(header)
    result.update({
        "protected_data_hex": payload.hex(),
        "padding_hex": padding.hex(),
        "mac_length": mac,
        "mac_hex": raw[payload_end:].hex(),
        "authentication_verified": False,
        "verification_note": "structural decode only; cryptographic verification requires mission keys/profile",
    })
    return result


@_declared
def parse_sdls_ep_pdu(data: object) -> dict[str, Any]:
    """Parse one SDLS Extended Procedures command/reply PDU."""
    raw = _bytes(data, "SDLS EP PDU", minimum=3, maximum=8195)
    bit_length = int.from_bytes(raw[1:3], "big")
    if bit_length & 7:
        raise SecSpaceCCSDSError("SDLS EP data length is not octet aligned")
    if len(raw) != 3 + bit_length // 8:
        raise SecSpaceCCSDSError("SDLS EP data-length field mismatch")
    tag = raw[0]
    return {
        "protocol": "ccsds-sdls-extended-procedures",
        "reply": bool(tag & 0x80),
        "user_flag": bool(tag & 0x40),
        "procedure_group": (tag >> 4) & 3,
        "procedure_identifier": tag & 0x0F,
        "data_length_bits": bit_length,
        "data_hex": raw[3:].hex(),
    }


@_declared
def parse_sdls_fsr(data: object) -> dict[str, Any]:
    """Parse the four-octet SDLS Frame Security Report."""
    raw = _bytes(data, "SDLS frame security report", exact=4)
    version = (raw[0] >> 4) & 7
    if raw[0] >> 4 != 0xC:
        raise SecSpaceCCSDSError("unsupported SDLS frame-security-report version")
    return {
        "protocol": "ccsds-sdls-frame-security-report",
        "control_type": bool(raw[0] & 0x80),
        "version": version,
        "alarm_flags": raw[0] & 0x0F,
        "alarm": bool(raw[0] & 0x08),
        "bad_sequence_number": bool(raw[0] & 0x04),
        "bad_mac": bool(raw[0] & 0x02),
        "bad_security_association": bool(raw[0] & 0x01),
        "last_spi": int.from_bytes(raw[1:3], "big"),
        "last_arsn": raw[3],
    }


def _read(path: str) -> bytes:
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise SecSpaceCCSDSError("input exceeds size limit")
    return raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="passive CCSDS/ECSS frame decoder")
    sub = parser.add_subparsers(dest="kind", required=True)
    packet = sub.add_parser("packet")
    packet.add_argument("input")
    packet.add_argument("--pus", choices=("tc", "tm"))
    packet.add_argument("--pus-time-length", type=int, default=0)
    stream = sub.add_parser("packet-stream")
    stream.add_argument("input")
    stream.add_argument("--pus", choices=("tc", "tm"))
    stream.add_argument("--pus-time-length", type=int, default=0)
    tm = sub.add_parser("tm")
    tm.add_argument("input")
    tm.add_argument("--fecf", action="store_true")
    tc = sub.add_parser("tc")
    tc.add_argument("input")
    tc.add_argument("--fecf", action="store_true")
    tc.add_argument("--segmented", action="store_true")
    uslp = sub.add_parser("uslp")
    uslp.add_argument("input")
    uslp.add_argument("--fecf", action="store_true")
    uslp.add_argument("--insert-zone-length", type=int, default=0)
    uslp.add_argument("--tfdf-pointer-present", action="store_true")
    pus = sub.add_parser("pus")
    pus.add_argument("direction", choices=("tc", "tm"))
    pus.add_argument("input")
    pus.add_argument("--time-length", type=int, default=0)
    sdls = sub.add_parser("sdls")
    sdls.add_argument("input")
    sdls.add_argument("--sequence-length", type=int, default=0)
    sdls.add_argument("--iv-length", type=int, default=0)
    sdls.add_argument("--pad-length-field-length", type=int, default=0)
    sdls.add_argument("--mac-length", type=int, default=0)
    for name in ("sdls-ep", "sdls-fsr", "crc"):
        command = sub.add_parser(name)
        command.add_argument("input")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (TypeError, ValueError, OverflowError) as exc:
        print(f"sec_space_ccsds: {exc}", file=sys.stderr)
        return 2
    try:
        raw = _read(args.input)
        if args.kind == "packet":
            result = parse_space_packet(raw, pus=args.pus,
                                        pus_time_length=args.pus_time_length)
        elif args.kind == "packet-stream":
            result = parse_space_packet_stream(raw, pus=args.pus,
                                               pus_time_length=args.pus_time_length)
        elif args.kind == "tm":
            result = parse_tm_frame(raw, has_fecf=args.fecf)
        elif args.kind == "tc":
            result = parse_tc_frame(raw, has_fecf=args.fecf,
                                    segmented=args.segmented)
        elif args.kind == "uslp":
            result = parse_uslp_frame(raw, has_fecf=args.fecf,
                                      insert_zone_length=args.insert_zone_length,
                                      tfdf_pointer_present=args.tfdf_pointer_present)
        elif args.kind == "pus":
            result = parse_pus_secondary(raw, args.direction,
                                         time_length=args.time_length)
        elif args.kind == "sdls":
            result = parse_sdls_fields(
                raw, sequence_length=args.sequence_length,
                iv_length=args.iv_length,
                pad_length_field_length=args.pad_length_field_length,
                mac_length=args.mac_length)
        elif args.kind == "sdls-ep":
            result = parse_sdls_ep_pdu(raw)
        elif args.kind == "sdls-fsr":
            result = parse_sdls_fsr(raw)
        else:
            result = {"crc16_fecf": crc16_fecf(raw),
                      "crc16_fecf_hex": f"{crc16_fecf(raw):04x}"}
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (SecSpaceCCSDSError, OSError, UnicodeError, ValueError,
            TypeError, OverflowError) as exc:
        print(f"sec_space_ccsds: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_INPUT", "SecSpaceCCSDSError", "crc16_fecf", "main",
    "parse_pus_secondary", "parse_sdls_ep_pdu", "parse_sdls_fields",
    "parse_sdls_fsr", "parse_sdls_header", "parse_space_packet",
    "parse_space_packet_stream", "parse_tc_frame", "parse_tm_frame",
    "parse_uslp_frame",
]
