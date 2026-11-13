#!/usr/bin/env python3
"""Bounded offline Bluetooth LE/HCI and IEEE 802.15.4/Zigbee decoding.

Inputs are saved packet bytes, btsnoop logs, or pcap files.  The module never
opens a radio, HCI socket, serial port, or network interface.  Zigbee AES-CCM
decryption is attempted only with an explicitly supplied key and a complete
authenticated frame; unauthenticated plaintext is never returned.
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except Exception:  # pragma: no cover - optional dependency
    AESCCM = None


MAX_FILE = 64 * 1024 * 1024
MAX_PACKETS = 500_000
MAX_PACKET = 1 << 20
MAX_ITEMS = 100_000


class RadioError(ValueError):
    pass


_AD_TYPES = {
    0x01: "flags", 0x02: "incomplete_uuid16", 0x03: "complete_uuid16",
    0x06: "incomplete_uuid128", 0x07: "complete_uuid128", 0x08: "short_name",
    0x09: "complete_name", 0x0A: "tx_power", 0x16: "service_data_uuid16",
    0x19: "appearance", 0x20: "service_data_uuid32", 0x21: "service_data_uuid128",
    0x24: "uri", 0xFF: "manufacturer_data",
}
_ADV_TYPES = {0: "ADV_IND", 1: "ADV_DIRECT_IND", 2: "ADV_NONCONN_IND", 3: "SCAN_REQ",
              4: "SCAN_RSP", 5: "CONNECT_IND", 6: "ADV_SCAN_IND", 7: "ADV_EXT_IND"}


def _address(raw: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in reversed(raw))


def parse_ad_structures(data: bytes) -> list[dict[str, Any]]:
    if not isinstance(data, bytes) or len(data) > 255:
        raise RadioError("advertising data must contain at most 255 bytes")
    rows, offset = [], 0
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length < 1 or offset + length > len(data):
            raise RadioError("advertising structure overruns its PDU")
        kind, value = data[offset], data[offset + 1:offset + length]
        offset += length
        row: dict[str, Any] = {"type": kind, "name": _AD_TYPES.get(kind, f"type_0x{kind:02x}"),
                               "raw": value}
        if kind in (0x08, 0x09, 0x24):
            row["text"] = value.decode("utf-8", "replace")
        elif kind == 0x01 and len(value) == 1:
            row["flags"] = value[0]
        elif kind in (0x02, 0x03) and len(value) % 2 == 0:
            row["uuids"] = [f"{int.from_bytes(value[i:i + 2], 'little'):04x}"
                            for i in range(0, len(value), 2)]
        elif kind in (0x06, 0x07) and len(value) % 16 == 0:
            row["uuids"] = [value[i:i + 16][::-1].hex() for i in range(0, len(value), 16)]
        elif kind == 0x0A and len(value) == 1:
            row["dbm"] = int.from_bytes(value, "little", signed=True)
        elif kind == 0x16 and len(value) >= 2:
            row["uuid"] = f"{int.from_bytes(value[:2], 'little'):04x}"
            row["service_data"] = value[2:]
        elif kind == 0xFF and len(value) >= 2:
            row["company_id"] = int.from_bytes(value[:2], "little")
            row["manufacturer_data"] = value[2:]
        rows.append(row)
        if len(rows) > MAX_ITEMS:
            raise RadioError("advertising item cap exceeded")
    if any(data[offset:]):
        raise RadioError("non-zero bytes follow the advertising terminator")
    return rows


def parse_ble_advertising(pdu: bytes) -> dict[str, Any] | None:
    """Parse a BLE advertising-channel LL PDU (without preamble/CRC)."""
    if not isinstance(pdu, bytes) or not 2 <= len(pdu) <= 260:
        return None
    header, declared = pdu[0], pdu[1] & 0x3F
    if declared != len(pdu) - 2:
        return None
    pdu_type = header & 0x0F
    if pdu_type not in _ADV_TYPES:
        return None
    payload = pdu[2:]
    out: dict[str, Any] = {"protocol": "ble-advertising", "pdu_type": pdu_type,
                           "pdu_name": _ADV_TYPES[pdu_type], "tx_address_random": bool(header & 0x40),
                           "rx_address_random": bool(header & 0x80), "length": declared}
    try:
        if pdu_type in (0, 2, 4, 6) and len(payload) >= 6:
            out["advertiser"] = _address(payload[:6])
            out["advertising_data"] = parse_ad_structures(payload[6:])
        elif pdu_type == 1 and len(payload) == 12:  # ADV_DIRECT_IND: AdvA, TargetA
            out["advertiser"] = _address(payload[:6])
            out["target"] = _address(payload[6:12])
        elif pdu_type == 3 and len(payload) == 12:  # SCAN_REQ: ScanA, AdvA
            out["scanner"] = _address(payload[:6])
            out["advertiser"] = _address(payload[6:12])
        elif pdu_type == 5 and len(payload) == 34:
            out.update(initiator=_address(payload[:6]), advertiser=_address(payload[6:12]),
                       access_address=int.from_bytes(payload[12:16], "little"),
                       crc_init=int.from_bytes(payload[16:19], "little"),
                       window_size=payload[19], window_offset=int.from_bytes(payload[20:22], "little"),
                       interval=int.from_bytes(payload[22:24], "little"),
                       latency=int.from_bytes(payload[24:26], "little"),
                       timeout=int.from_bytes(payload[26:28], "little"), channel_map=payload[28:33],
                       hop=payload[33] & 0x1F, sca=payload[33] >> 5)
        else:
            out["raw_payload"] = payload
    except RadioError:
        return None
    return out


_ATT = {0x01: "ErrorResponse", 0x02: "ExchangeMTURequest", 0x03: "ExchangeMTUResponse",
        0x08: "ReadByTypeRequest", 0x09: "ReadByTypeResponse", 0x0A: "ReadRequest",
        0x0B: "ReadResponse", 0x0C: "ReadBlobRequest", 0x0D: "ReadBlobResponse",
        0x10: "ReadByGroupTypeRequest", 0x11: "ReadByGroupTypeResponse", 0x12: "WriteRequest",
        0x13: "WriteResponse", 0x1B: "HandleValueNotification", 0x1D: "HandleValueIndication",
        0x1E: "HandleValueConfirmation", 0x52: "WriteCommand", 0xD2: "SignedWriteCommand"}


def parse_att(data: bytes) -> dict[str, Any] | None:
    if not data:
        return None
    opcode = data[0]
    out: dict[str, Any] = {"protocol": "att", "opcode": opcode,
                           "operation": _ATT.get(opcode, f"opcode_0x{opcode:02x}")}
    if opcode == 0x01 and len(data) >= 5:
        out.update(request_opcode=data[1], handle=int.from_bytes(data[2:4], "little"), error=data[4])
    elif opcode in (0x02, 0x03) and len(data) == 3:
        out["mtu"] = int.from_bytes(data[1:3], "little")
    elif opcode in (0x0A, 0x0C, 0x12, 0x52, 0x1B, 0x1D) and len(data) >= 3:
        out["handle"] = int.from_bytes(data[1:3], "little")
        if opcode == 0x0C and len(data) >= 5:
            out["offset"] = int.from_bytes(data[3:5], "little")
            out["value"] = data[5:]
        else:
            out["value"] = data[3:]
    elif opcode in (0x08, 0x10) and len(data) >= 7:
        out.update(start_handle=int.from_bytes(data[1:3], "little"),
                   end_handle=int.from_bytes(data[3:5], "little"), uuid=data[5:][::-1].hex())
    else:
        out["value"] = data[1:]
    return out


def parse_hci_acl(packet: bytes) -> dict[str, Any] | None:
    if not isinstance(packet, (bytes, bytearray)) or len(packet) < 4:
        return None
    flags_handle, length = struct.unpack_from("<HH", packet)
    if length != len(packet) - 4:
        return None
    payload = packet[4:]
    out: dict[str, Any] = {"protocol": "hci-acl", "handle": flags_handle & 0x0FFF,
                           "packet_boundary": (flags_handle >> 12) & 3,
                           "broadcast": (flags_handle >> 14) & 3, "payload": payload}
    if len(payload) >= 4:
        l2_length, cid = struct.unpack_from("<HH", payload)
        if l2_length <= len(payload) - 4:
            body = payload[4:4 + l2_length]
            out["l2cap"] = {"length": l2_length, "cid": cid, "payload": body}
            if cid == 4:
                out["l2cap"]["att"] = parse_att(body)
            elif cid == 6 and body:
                out["l2cap"]["smp"] = {"command": body[0], "parameters": body[1:]}
    return out


def parse_h4_stream(data: bytes) -> list[dict[str, Any]]:
    """Parse concatenated Bluetooth HCI H:4 packets."""
    if not isinstance(data, (bytes, bytearray)):
        raise RadioError("H:4 stream requires bytes")
    rows, offset = [], 0
    while offset < len(data):
        packet_type, start = data[offset], offset
        offset += 1
        if packet_type == 1:  # command: opcode + parameter length
            if offset + 3 > len(data):
                raise RadioError("truncated HCI command")
            length = data[offset + 2]
            end = offset + 3 + length
            if end > len(data):
                raise RadioError("HCI command length past end")
            opcode = int.from_bytes(data[offset:offset + 2], "little")
            row = {"protocol": "hci-command", "opcode": opcode,
                   "ogf": opcode >> 10, "ocf": opcode & 0x3FF,
                   "parameters": data[offset + 3:end]}
        elif packet_type == 2:  # ACL
            if offset + 4 > len(data):
                raise RadioError("truncated HCI ACL header")
            length = int.from_bytes(data[offset + 2:offset + 4], "little")
            end = offset + 4 + length
            if end > len(data):
                raise RadioError("HCI ACL length past end")
            row = parse_hci_acl(data[offset:end])
        elif packet_type == 4:  # event
            if offset + 2 > len(data):
                raise RadioError("truncated HCI event")
            length = data[offset + 1]
            end = offset + 2 + length
            if end > len(data):
                raise RadioError("HCI event length past end")
            row = {"protocol": "hci-event", "event": data[offset],
                   "parameters": data[offset + 2:end]}
        else:
            raise RadioError(f"unsupported H:4 packet type 0x{packet_type:02x} at {start}")
        if row is not None:
            row["offset"] = start
            rows.append(row)
        offset = end
        if len(rows) > MAX_PACKETS:
            raise RadioError("HCI packet cap exceeded")
    return rows


def parse_btsnoop(data: bytes) -> list[dict[str, Any]]:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 16 or data[:8] != b"btsnoop\x00":
        raise RadioError("not a btsnoop file")
    version, datalink = struct.unpack_from(">II", data, 8)
    if version != 1:
        raise RadioError("unsupported btsnoop version")
    rows, offset = [], 16
    while offset < len(data):
        if offset + 24 > len(data):
            raise RadioError("truncated btsnoop record header")
        original, included, flags, drops, timestamp = struct.unpack_from(">IIIIQ", data, offset)
        offset += 24
        if included > MAX_PACKET or included > original or offset + included > len(data):
            raise RadioError("invalid btsnoop record length")
        raw, offset = data[offset:offset + included], offset + included
        decoded = parse_h4_stream(raw) if datalink in (1002, 1003) else []
        rows.append({"original_length": original, "included_length": included,
                     "flags": flags, "drops": drops, "timestamp": timestamp,
                     "datalink": datalink, "packets": decoded, "raw": raw})
        if len(rows) > MAX_PACKETS:
            raise RadioError("btsnoop record cap exceeded")
    return rows


_MAC_FRAME = {0: "beacon", 1: "data", 2: "ack", 3: "command", 5: "multipurpose", 7: "extended"}


def _mac_address(data: bytes, offset: int, mode: int):
    size = {0: 0, 2: 2, 3: 8}.get(mode)
    if size is None or offset + size > len(data):
        return None
    if size == 0:
        return None, offset
    raw = data[offset:offset + size]
    return _address(raw) if size == 8 else f"0x{int.from_bytes(raw, 'little'):04x}", offset + size


def parse_ieee802154(frame: bytes, *, has_fcs: bool = False,
                     network_key: bytes | None = None) -> dict[str, Any] | None:
    """Parse one IEEE 802.15.4 MAC frame and nested Zigbee NWK/APS/ZCL."""
    if not isinstance(frame, bytes) or not 3 <= len(frame) <= MAX_PACKET:
        return None
    data = frame[:-2] if has_fcs and len(frame) >= 5 else frame
    fcf = int.from_bytes(data[:2], "little")
    frame_type, dest_mode, src_mode = fcf & 7, (fcf >> 10) & 3, (fcf >> 14) & 3
    if frame_type not in _MAC_FRAME or dest_mode == 1 or src_mode == 1:
        return None
    sequence_suppressed, pan_compression = bool(fcf & 0x0100), bool(fcf & 0x0040)
    offset = 2
    sequence = None
    if not sequence_suppressed:
        if offset >= len(data):
            return None
        sequence, offset = data[offset], offset + 1
    out: dict[str, Any] = {"protocol": "ieee802.15.4", "frame_control": fcf,
                           "frame_type": _MAC_FRAME[frame_type], "sequence": sequence,
                           "security": bool(fcf & 8), "ack_request": bool(fcf & 0x20),
                           "pan_compression": pan_compression, "version": (fcf >> 12) & 3}
    try:
        if dest_mode:
            if offset + 2 > len(data):
                return None
            out["destination_pan"] = f"0x{int.from_bytes(data[offset:offset + 2], 'little'):04x}"
            offset += 2
            got = _mac_address(data, offset, dest_mode)
            if got is None:
                return None
            out["destination"], offset = got
        if src_mode:
            if not pan_compression or not dest_mode:
                if offset + 2 > len(data):
                    return None
                out["source_pan"] = f"0x{int.from_bytes(data[offset:offset + 2], 'little'):04x}"
                offset += 2
            else:
                out["source_pan"] = out.get("destination_pan")
            got = _mac_address(data, offset, src_mode)
            if got is None:
                return None
            out["source"], offset = got
    except (IndexError, ValueError):
        return None
    out["mac_payload"] = data[offset:]
    if frame_type == 1 and data[offset:]:
        nwk = parse_zigbee_nwk(data[offset:], network_key=network_key)
        if nwk is not None:
            out["zigbee"] = nwk
    return out


def _zigbee_aux(data: bytes, offset: int, source_hint: bytes | None):
    if offset + 5 > len(data):
        return None
    control, frame_counter = data[offset], int.from_bytes(data[offset + 1:offset + 5], "little")
    start, offset = offset, offset + 5
    extended_nonce = bool(control & 0x20)
    if extended_nonce:
        if offset + 8 > len(data):
            return None
        source = data[offset:offset + 8]
        offset += 8
    else:
        source = source_hint
    key_id = (control >> 3) & 3
    key_sequence = None
    if key_id == 1:
        if offset >= len(data):
            return None
        key_sequence, offset = data[offset], offset + 1
    elif key_id in (2, 3):
        extra = 5 if key_id == 2 else 9
        if offset + extra > len(data):
            return None
        offset += extra
    return {"security_control": control, "security_level": control & 7,
            "frame_counter": frame_counter, "extended_nonce": extended_nonce,
            "source_raw": source, "source": _address(source) if source else None,
            "key_id": key_id, "key_sequence": key_sequence,
            "start": start, "end": offset}


def parse_zigbee_nwk(data: bytes, *, network_key: bytes | None = None) -> dict[str, Any] | None:
    if not isinstance(data, bytes) or len(data) < 8 or len(data) > MAX_PACKET:
        return None
    fcf = int.from_bytes(data[:2], "little")
    version = (fcf >> 2) & 0x0F
    if version > 3:
        return None
    offset = 8
    out: dict[str, Any] = {"protocol": "zigbee-nwk", "frame_control": fcf,
                           "frame_type": {0: "data", 1: "command", 2: "interpan"}.get(fcf & 3, "reserved"),
                           "protocol_version": version,
                           "destination": f"0x{int.from_bytes(data[2:4], 'little'):04x}",
                           "source": f"0x{int.from_bytes(data[4:6], 'little'):04x}",
                           "radius": data[6], "sequence": data[7], "security": bool(fcf & 0x0200)}
    destination_ieee = source_ieee = None
    if fcf & 0x0800:
        if offset + 8 > len(data):
            return None
        destination_ieee, offset = data[offset:offset + 8], offset + 8
        out["destination_ieee"] = _address(destination_ieee)
    if fcf & 0x1000:
        if offset + 8 > len(data):
            return None
        source_ieee, offset = data[offset:offset + 8], offset + 8
        out["source_ieee"] = _address(source_ieee)
    if fcf & 0x0400:  # source route subframe
        if offset + 2 > len(data):
            return None
        relay_count, relay_index = data[offset], data[offset + 1]
        offset += 2
        if relay_count > 64 or offset + relay_count * 2 > len(data):
            return None
        out["source_route"] = {"relay_index": relay_index,
                               "relays": [f"0x{int.from_bytes(data[i:i + 2], 'little'):04x}"
                                          for i in range(offset, offset + relay_count * 2, 2)]}
        offset += relay_count * 2
    payload = data[offset:]
    if out["security"]:
        aux = _zigbee_aux(data, offset, source_ieee)
        if aux is None:
            return None
        out["auxiliary_security"] = {key: value for key, value in aux.items()
                                     if key not in {"start", "end", "source_raw"}}
        level = aux["security_level"]
        mic_length = {0: 0, 1: 4, 2: 8, 3: 16, 4: 0, 5: 4, 6: 8, 7: 16}[level]
        encrypted = level >= 4
        payload = data[aux["end"]:]
        if network_key is not None:
            if not isinstance(network_key, bytes) or len(network_key) != 16:
                raise RadioError("Zigbee network key must be exactly 16 bytes")
            if AESCCM is None:
                raise RadioError("cryptography AESCCM is unavailable")
            if not encrypted or mic_length == 0 or aux["source_raw"] is None or len(payload) < mic_length:
                out["decryption"] = {"verified": False, "reason": "frame lacks authenticated encryption metadata"}
            else:
                nonce = aux["source_raw"] + aux["frame_counter"].to_bytes(4, "little") + bytes([aux["security_control"]])
                aad = data[:aux["end"]]
                try:
                    payload = AESCCM(network_key, tag_length=mic_length).decrypt(nonce, payload, aad)
                    out["decryption"] = {"verified": True, "mic_length": mic_length}
                except Exception:
                    out["decryption"] = {"verified": False, "reason": "AES-CCM authentication failed"}
                    out["encrypted_payload"] = data[aux["end"]:]
                    return out
        elif encrypted:
            out["encrypted_payload"] = payload
            return out
    out["nwk_payload"] = payload
    aps = parse_zigbee_aps(payload)
    if aps is not None:
        out["aps"] = aps
    return out


def parse_zigbee_aps(data: bytes) -> dict[str, Any] | None:
    if not data:
        return None
    control, frame_type = data[0], data[0] & 3
    out: dict[str, Any] = {"protocol": "zigbee-aps", "frame_control": control,
                           "frame_type": {0: "data", 1: "command", 2: "ack", 3: "interpan"}[frame_type],
                           "delivery_mode": (control >> 2) & 3, "security": bool(control & 0x20),
                           "ack_request": bool(control & 0x40)}
    if out["security"]:
        out["encrypted_payload"] = data[1:]
        return out
    if frame_type == 0:
        if len(data) < 8:
            return None
        out.update(destination_endpoint=data[1], cluster=int.from_bytes(data[2:4], "little"),
                   profile=int.from_bytes(data[4:6], "little"), source_endpoint=data[6], counter=data[7])
        payload = data[8:]
        out["payload"] = payload
        zcl = parse_zcl(payload)
        if zcl is not None:
            out["zcl"] = zcl
    elif frame_type == 1:
        if len(data) < 3:
            return None
        out.update(counter=data[1], command=data[2], payload=data[3:])
    else:
        out["payload"] = data[1:]
    return out


_ZCL_COMMANDS = {0x00: "ReadAttributes", 0x01: "ReadAttributesResponse", 0x02: "WriteAttributes",
                 0x04: "WriteAttributesResponse", 0x06: "ConfigureReporting", 0x07: "ConfigureReportingResponse",
                 0x0A: "ReportAttributes", 0x0B: "DefaultResponse", 0x0C: "DiscoverAttributes",
                 0x0D: "DiscoverAttributesResponse"}


def parse_zcl(data: bytes) -> dict[str, Any] | None:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 3:
        return None
    control, offset = data[0], 1
    out: dict[str, Any] = {"protocol": "zigbee-zcl", "frame_control": control,
                           "frame_type": control & 3, "manufacturer_specific": bool(control & 4),
                           "direction": "server_to_client" if control & 8 else "client_to_server",
                           "disable_default_response": bool(control & 0x10)}
    if control & 4:
        if offset + 2 > len(data):
            return None
        out["manufacturer_code"] = int.from_bytes(data[offset:offset + 2], "little")
        offset += 2
    if offset + 2 > len(data):
        return None
    out["transaction_sequence"], command = data[offset], data[offset + 1]
    offset += 2
    out["command"] = command
    out["command_name"] = _ZCL_COMMANDS.get(command, f"command_0x{command:02x}")
    payload = data[offset:]
    if command in (0x00, 0x0C) and len(payload) % 2 == 0:
        out["attribute_ids"] = [int.from_bytes(payload[i:i + 2], "little")
                                for i in range(0, len(payload), 2)]
    else:
        out["payload"] = payload
    return out


def pcap_records(data: bytes) -> tuple[int, list[bytes]]:
    if not isinstance(data, (bytes, bytearray)) or len(data) < 24:
        raise RadioError("pcap is truncated")
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise RadioError("only classic pcap is accepted by this radio reader")
    _magic, major, minor, _zone, _sig, snaplen, linktype = struct.unpack_from(endian + "IHHiIII", data)
    if major != 2 or minor != 4 or not 1 <= snaplen <= MAX_PACKET:
        raise RadioError("invalid pcap header")
    rows, offset = [], 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise RadioError("truncated pcap record")
        _sec, _frac, included, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if included > original or included > snaplen or offset + included > len(data):
            raise RadioError("invalid pcap record length")
        rows.append(data[offset:offset + included])
        offset += included
        if len(rows) > MAX_PACKETS:
            raise RadioError("pcap packet cap exceeded")
    return linktype, rows


def analyze(data: bytes, *, kind: str = "auto", network_key: bytes | None = None) -> dict[str, Any]:
    if not isinstance(data, bytes) or not data or len(data) > MAX_FILE:
        raise RadioError("input is empty or over the file cap")
    if kind == "auto":
        if data.startswith(b"btsnoop\x00"):
            kind = "hci"
        elif data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            kind = "pcap"
        else:
            kind = "ble" if parse_ble_advertising(data) is not None else "zigbee"
    if kind == "hci":
        rows = parse_btsnoop(data) if data.startswith(b"btsnoop\x00") else parse_h4_stream(data)
        return {"kind": "hci", "records": rows, "offline": True}
    if kind == "ble":
        row = parse_ble_advertising(data)
        if row is None:
            raise RadioError("input is not a valid BLE advertising PDU")
        return {"kind": "ble", "records": [row], "offline": True}
    if kind == "zigbee":
        row = parse_ieee802154(data, network_key=network_key)
        if row is None:
            raise RadioError("input is not a valid IEEE 802.15.4 frame")
        return {"kind": "zigbee", "records": [row], "offline": True}
    if kind == "pcap":
        linktype, packets = pcap_records(data)
        rows = []
        for packet in packets:
            row = None
            if linktype in (195, 230):
                row = parse_ieee802154(packet, has_fcs=linktype == 195, network_key=network_key)
            elif linktype == 251 and len(packet) >= 7:  # access address (4) + PDU + CRC (3)
                row = parse_ble_advertising(packet[4:-3])
            elif linktype == 256 and len(packet) >= 17:  # BTLE_RF phdr (10) + AA (4) + PDU + CRC (3)
                row = parse_ble_advertising(packet[14:-3])
            if row is not None:
                rows.append(row)
        if linktype not in (195, 230, 251, 256):
            raise RadioError(f"unsupported radio pcap link type {linktype}")
        return {"kind": "pcap", "linktype": linktype, "records": rows, "offline": True}
    raise RadioError("kind must be auto, ble, hci, zigbee, or pcap")


def _json_default(value: Any):
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    raise TypeError(type(value).__name__)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover
        raise RadioError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="radio_capture.py")
    parser.add_argument("input")
    parser.add_argument("--kind", choices=("auto", "ble", "hci", "zigbee", "pcap"), default="auto")
    parser.add_argument("--zigbee-key", help="explicit 16-byte network key in hex")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        path = Path(args.input)
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise RadioError("input is absent or exceeds the file cap")
        key = bytes.fromhex(args.zigbee_key) if args.zigbee_key else None
        result = analyze(path.read_bytes(), kind=args.kind, network_key=key)
        print(json.dumps(result, sort_keys=True, default=_json_default, indent=2 if args.json else None))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 0
    except Exception as exc:
        print(f"radio_capture: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
