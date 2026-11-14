#!/usr/bin/env python3
"""Offline PCAP/PCAPNG transport extraction and ICS session analysis.

Only bytes from a supplied capture are read.  The module contains no networking imports and never
opens a device, interface or live target.  It understands classic PCAP and the common PCAPNG block
set, decodes bounded Ethernet/Linux-cooked/raw IPv4 and IPv6 traffic, reassembles captured TCP
segments, splits industrial application frames, calls ics_protocols, and correlates request /
response identifiers and sequence anomalies.
"""
from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

try:
    from .ics_protocols import PORT_PROTOCOLS, ParseError, dissect, parse_dnp3_application
except ImportError:  # direct script execution
    from ics_protocols import PORT_PROTOCOLS, ParseError, dissect, parse_dnp3_application


MAX_CAPTURE = 256 << 20
MAX_PACKETS = 2_000_000
MAX_PACKET = 16 << 20
MAX_STREAM = 128 << 20
MAX_MESSAGES = 1_000_000


def _need(data: bytes, offset: int, length: int, what: str) -> None:
    if offset < 0 or length < 0 or offset + length > len(data):
        raise ParseError(f"truncated {what} at offset {offset}")


def _address(raw: bytes) -> str:
    if len(raw) == 4:
        return ".".join(str(value) for value in raw)
    if len(raw) == 16:
        words = [int.from_bytes(raw[i : i + 2], "big") for i in range(0, 16, 2)]
        # A deterministic, dependency-free RFC 5952-like compression.
        best_start = best_length = -1
        start = 0
        while start < 8:
            if words[start] != 0:
                start += 1
                continue
            end = start
            while end < 8 and words[end] == 0:
                end += 1
            if end - start > best_length and end - start >= 2:
                best_start, best_length = start, end - start
            start = end
        if best_start >= 0:
            left = ":".join(f"{word:x}" for word in words[:best_start])
            right = ":".join(f"{word:x}" for word in words[best_start + best_length :])
            return (left + "::" + right) or "::"
        return ":".join(f"{word:x}" for word in words)
    return raw.hex()


def _iter_pcap(data: bytes) -> Iterable[dict[str, Any]]:
    _need(data, 0, 24, "PCAP global header")
    magics = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if data[:4] not in magics:
        raise ParseError("unsupported PCAP magic")
    endian, resolution = magics[data[:4]]
    version_major, version_minor = struct.unpack_from(endian + "HH", data, 4)
    if version_major != 2:
        raise ParseError(f"unsupported PCAP version {version_major}.{version_minor}")
    snaplen, linktype = struct.unpack_from(endian + "II", data, 16)
    if snaplen > MAX_PACKET:
        raise ParseError("PCAP snap length exceeds 16 MiB cap")
    offset, index = 24, 0
    while offset < len(data):
        if index >= MAX_PACKETS:
            raise ParseError("PCAP packet count exceeds cap")
        _need(data, offset, 16, "PCAP packet header")
        seconds, fraction, captured, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if captured > MAX_PACKET:
            raise ParseError("captured packet exceeds 16 MiB cap")
        _need(data, offset, captured, "PCAP packet data")
        packet = data[offset : offset + captured]
        offset += captured
        yield {
            "index": index,
            "timestamp": seconds + fraction / resolution,
            "captured_length": captured,
            "original_length": original,
            "linktype": linktype,
            "data": packet,
        }
        index += 1


def _pcapng_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = defaultdict(list)
    offset = 0
    while offset + 4 <= len(data):
        code, length = struct.unpack_from(endian + "HH", data, offset)
        offset += 4
        if code == 0:
            break
        _need(data, offset, length, "PCAPNG option")
        options[code].append(data[offset : offset + length])
        offset += (length + 3) & ~3
    return dict(options)


def _iter_pcapng(data: bytes) -> Iterable[dict[str, Any]]:
    offset = index = 0
    endian: str | None = None
    interfaces: list[dict[str, Any]] = []
    while offset < len(data):
        if index >= MAX_PACKETS:
            raise ParseError("PCAPNG packet count exceeds cap")
        _need(data, offset, 12, "PCAPNG block")
        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            _need(data, offset, 28, "PCAPNG section header")
            bom = data[offset + 8 : offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ParseError("invalid PCAPNG byte-order magic")
            block_length = struct.unpack_from(endian + "I", data, offset + 4)[0]
            if block_length < 28 or block_length & 3:
                raise ParseError("invalid PCAPNG section length")
            _need(data, offset, block_length, "PCAPNG section")
            if struct.unpack_from(endian + "I", data, offset + block_length - 4)[0] != block_length:
                raise ParseError("PCAPNG section trailing length mismatch")
            interfaces = []
            offset += block_length
            continue
        if endian is None:
            raise ParseError("PCAPNG block precedes section header")
        block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or block_length & 3:
            raise ParseError("invalid PCAPNG block length")
        _need(data, offset, block_length, "PCAPNG block")
        if struct.unpack_from(endian + "I", data, offset + block_length - 4)[0] != block_length:
            raise ParseError("PCAPNG trailing length mismatch")
        body = data[offset + 8 : offset + block_length - 4]
        if block_type == 1:
            _need(body, 0, 8, "interface description")
            linktype, snaplen = struct.unpack_from(endian + "HxxI", body, 0)
            if snaplen > MAX_PACKET:
                raise ParseError("PCAPNG snap length exceeds cap")
            options = _pcapng_options(body[8:], endian)
            resolution = 1_000_000
            if 9 in options and options[9] and options[9][0]:
                value = options[9][0][0]
                resolution = (2 ** (value & 0x7F)) if value & 0x80 else (10 ** value)
                if resolution <= 0 or resolution > 10**18:
                    raise ParseError("invalid PCAPNG timestamp resolution")
            offset_option = 0
            if 14 in options and options[14] and len(options[14][0]) == 8:
                offset_option = struct.unpack(endian + "q", options[14][0])[0]
            interfaces.append(
                {"linktype": linktype, "snaplen": snaplen, "resolution": resolution, "time_offset": offset_option}
            )
        elif block_type == 6:
            _need(body, 0, 20, "enhanced packet block")
            interface_id, time_high, time_low, captured, original = struct.unpack_from(endian + "IIIII", body, 0)
            if interface_id >= len(interfaces):
                raise ParseError("PCAPNG packet references unknown interface")
            if captured > MAX_PACKET:
                raise ParseError("PCAPNG captured packet exceeds cap")
            _need(body, 20, captured, "enhanced packet data")
            interface = interfaces[interface_id]
            ticks = (time_high << 32) | time_low
            yield {
                "index": index,
                "timestamp": interface["time_offset"] + ticks / interface["resolution"],
                "captured_length": captured,
                "original_length": original,
                "linktype": interface["linktype"],
                "interface_id": interface_id,
                "data": body[20 : 20 + captured],
            }
            index += 1
        elif block_type == 3:
            _need(body, 0, 4, "simple packet block")
            if not interfaces:
                raise ParseError("PCAPNG simple packet lacks an interface")
            original = struct.unpack_from(endian + "I", body, 0)[0]
            captured = min(original, len(body) - 4, interfaces[0]["snaplen"])
            if captured > MAX_PACKET:
                raise ParseError("PCAPNG simple packet exceeds cap")
            yield {
                "index": index,
                "timestamp": None,
                "captured_length": captured,
                "original_length": original,
                "linktype": interfaces[0]["linktype"],
                "interface_id": 0,
                "data": body[4 : 4 + captured],
            }
            index += 1
        offset += block_length


def iter_capture(data: bytes) -> Iterable[dict[str, Any]]:
    """Yield bounded packet records from classic PCAP or PCAPNG bytes."""
    if not isinstance(data, bytes):
        raise TypeError("capture must be bytes")
    if len(data) > MAX_CAPTURE:
        raise ParseError("capture exceeds 256 MiB cap")
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        yield from _iter_pcapng(data)
    else:
        yield from _iter_pcap(data)


def _network_payload(frame: bytes, linktype: int) -> tuple[int, bytes, dict[str, Any]]:
    metadata: dict[str, Any] = {}
    if linktype == 1:  # Ethernet
        _need(frame, 0, 14, "Ethernet header")
        metadata.update(destination_mac=frame[0:6].hex(":"), source_mac=frame[6:12].hex(":"))
        ethertype, offset = int.from_bytes(frame[12:14], "big"), 14
        vlan = []
        while ethertype in (0x8100, 0x88A8, 0x9100):
            _need(frame, offset, 4, "VLAN header")
            tci = int.from_bytes(frame[offset : offset + 2], "big")
            vlan.append({"id": tci & 0x0FFF, "priority": tci >> 13})
            ethertype = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        if vlan:
            metadata["vlan"] = vlan
        return ethertype, frame[offset:], metadata
    if linktype == 113:  # Linux cooked v1
        _need(frame, 0, 16, "Linux cooked header")
        return int.from_bytes(frame[14:16], "big"), frame[16:], metadata
    if linktype == 276:  # Linux cooked v2
        _need(frame, 0, 20, "Linux cooked v2 header")
        return int.from_bytes(frame[0:2], "big"), frame[20:], metadata
    if linktype in (101, 228, 229):  # raw IP / explicit IPv4 / explicit IPv6
        version = frame[0] >> 4 if frame else 0
        return (0x0800 if version == 4 else 0x86DD), frame, metadata
    if linktype == 0:  # BSD null/loopback
        _need(frame, 0, 4, "null header")
        family_le = int.from_bytes(frame[:4], "little")
        family_be = int.from_bytes(frame[:4], "big")
        family = family_le if family_le in (2, 24, 28, 30) else family_be
        return (0x0800 if family == 2 else 0x86DD), frame[4:], metadata
    raise ParseError(f"unsupported capture linktype {linktype}")


def _decode_transport(out: dict[str, Any], protocol: int, transport: bytes) -> dict[str, Any]:
    out = dict(out)
    out["protocol"] = protocol
    if protocol == 6:
        _need(transport, 0, 20, "TCP header")
        header_length = (transport[12] >> 4) * 4
        if header_length < 20:
            raise ParseError("invalid TCP data offset")
        _need(transport, 0, header_length, "TCP options")
        out.update(
            transport="tcp",
            source_port=int.from_bytes(transport[0:2], "big"),
            destination_port=int.from_bytes(transport[2:4], "big"),
            sequence=int.from_bytes(transport[4:8], "big"),
            acknowledgment=int.from_bytes(transport[8:12], "big"),
            tcp_flags=((transport[12] & 1) << 8) | transport[13],
            payload=transport[header_length:],
        )
    elif protocol == 17:
        _need(transport, 0, 8, "UDP header")
        length = int.from_bytes(transport[4:6], "big")
        if length < 8 or length > len(transport):
            raise ParseError("invalid/truncated UDP length")
        out.update(
            transport="udp",
            source_port=int.from_bytes(transport[0:2], "big"),
            destination_port=int.from_bytes(transport[2:4], "big"),
            payload=transport[8:length],
        )
    else:
        out["payload"] = transport
    return out


def _transport_packet(packet: dict[str, Any]) -> dict[str, Any] | None:
    ethertype, data, link = _network_payload(packet["data"], packet["linktype"])
    out: dict[str, Any] = {
        "packet_index": packet["index"],
        "timestamp": packet.get("timestamp"),
        **link,
    }
    if ethertype == 0x0800:
        _need(data, 0, 20, "IPv4 header")
        version, ihl = data[0] >> 4, (data[0] & 0x0F) * 4
        if version != 4 or ihl < 20:
            raise ParseError("invalid IPv4 header")
        _need(data, 0, ihl, "IPv4 options")
        total = int.from_bytes(data[2:4], "big")
        if total < ihl or total > len(data):
            raise ParseError("invalid/truncated IPv4 total length")
        fragment = int.from_bytes(data[6:8], "big")
        out.update(
            ip_version=4,
            source=_address(data[12:16]),
            destination=_address(data[16:20]),
            ip_id=int.from_bytes(data[4:6], "big"),
            fragment_offset=(fragment & 0x1FFF) * 8,
            more_fragments=bool(fragment & 0x2000),
        )
        protocol, transport = data[9], data[ihl:total]
        if out["fragment_offset"] or out["more_fragments"]:
            out.update(protocol=protocol, fragmented=True, payload=transport)
            return out
    elif ethertype == 0x86DD:
        _need(data, 0, 40, "IPv6 header")
        if data[0] >> 4 != 6:
            raise ParseError("invalid IPv6 header")
        payload_length = int.from_bytes(data[4:6], "big")
        if payload_length and 40 + payload_length > len(data):
            raise ParseError("truncated IPv6 payload")
        end = 40 + payload_length if payload_length else len(data)
        next_header, offset = data[6], 40
        out.update(ip_version=6, source=_address(data[8:24]), destination=_address(data[24:40]))
        extension_count = 0
        while next_header in (0, 43, 44, 51, 60):
            extension_count += 1
            if extension_count > 16:
                raise ParseError("excessive IPv6 extension headers")
            _need(data, offset, 2, "IPv6 extension")
            if next_header == 44:
                _need(data, offset, 8, "IPv6 fragment header")
                fragment = int.from_bytes(data[offset + 2 : offset + 4], "big")
                out.update(
                    ip_id=int.from_bytes(data[offset + 4 : offset + 8], "big"),
                    fragment_offset=((fragment >> 3) & 0x1FFF) * 8,
                    more_fragments=bool(fragment & 1),
                    fragmented=True,
                )
                next_header, offset = data[offset], offset + 8
                if out["fragment_offset"] or out["more_fragments"]:
                    out.update(protocol=next_header, payload=data[offset:end])
                    return out
            else:
                size = (data[offset + 1] + (2 if next_header == 51 else 1)) * (4 if next_header == 51 else 8)
                _need(data, offset, size, "IPv6 extension body")
                next_header, offset = data[offset], offset + size
        protocol, transport = next_header, data[offset:end]
    else:
        return None
    return _decode_transport(out, protocol, transport)


def extract_transports(
    data: bytes, *, include_count: bool = False
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]] | tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    """Return decoded transport packets plus bounded per-packet parse findings."""
    packets, findings, packet_count = [], [], 0
    fragments: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for packet in iter_capture(data):
        packet_count += 1
        try:
            decoded = _transport_packet(packet)
            if decoded is not None:
                if decoded.get("fragmented"):
                    key = (
                        decoded.get("ip_version"),
                        decoded.get("source"),
                        decoded.get("destination"),
                        decoded.get("ip_id"),
                        decoded.get("protocol"),
                    )
                    fragments[key].append(decoded)
                else:
                    packets.append(decoded)
        except ParseError as exc:
            findings.append(
                {
                    "kind": "packet-parse-error",
                    "severity": "warning",
                    "packet_index": packet["index"],
                    "detail": str(exc),
                }
            )
    for key, rows in fragments.items():
        final_ends = {
            row["fragment_offset"] + len(row["payload"])
            for row in rows
            if not row["more_fragments"]
        }
        if len(final_ends) != 1 or not any(row["fragment_offset"] == 0 for row in rows):
            findings.append(
                {
                    "kind": "incomplete-ip-fragments",
                    "severity": "warning",
                    "packet_indices": [row["packet_index"] for row in rows],
                    "detail": "fragment set lacks a unique final size or offset-zero fragment",
                }
            )
            continue
        total = next(iter(final_ends))
        if total > MAX_PACKET:
            findings.append(
                {
                    "kind": "oversized-ip-fragments",
                    "severity": "warning",
                    "packet_indices": [row["packet_index"] for row in rows],
                    "detail": "reassembled IP payload exceeds cap",
                }
            )
            continue
        assembled, covered = bytearray(total), bytearray(total)
        conflict = False
        for row in sorted(rows, key=lambda item: (item["fragment_offset"], item["packet_index"])):
            start, payload = row["fragment_offset"], row["payload"]
            if start + len(payload) > total:
                conflict = True
                break
            for index, value in enumerate(payload, start):
                if covered[index] and assembled[index] != value:
                    conflict = True
                assembled[index], covered[index] = value, 1
        if conflict or not all(covered):
            findings.append(
                {
                    "kind": "conflicting-ip-fragments" if conflict else "incomplete-ip-fragments",
                    "severity": "warning",
                    "packet_indices": [row["packet_index"] for row in rows],
                    "detail": "IP fragment bytes conflict or leave a gap",
                }
            )
            continue
        first = min(rows, key=lambda row: row["packet_index"])
        base = {
            name: value
            for name, value in first.items()
            if name not in {"fragmented", "fragment_offset", "more_fragments", "payload", "protocol"}
        }
        base["packet_index"] = min(row["packet_index"] for row in rows)
        base["fragment_packet_indices"] = [row["packet_index"] for row in rows]
        try:
            packets.append(_decode_transport(base, key[4], bytes(assembled)))
        except ParseError as exc:
            findings.append(
                {
                    "kind": "reassembled-transport-parse-error",
                    "severity": "warning",
                    "packet_indices": base["fragment_packet_indices"],
                    "detail": str(exc),
                }
            )
    packets.sort(key=lambda row: row["packet_index"])
    if include_count:
        return packets, findings, packet_count
    return packets, findings


def _payload_protocol(data: bytes) -> str | None:
    if data.startswith(b"\x03\x00"):
        return "s7comm"
    if data.startswith(b"\x05\x64"):
        return "dnp3"
    if data.startswith(b"\x68"):
        return "iec104"
    if data[:1] in (b"\x81", b"\x82"):
        return "bacnet"
    if len(data) >= 4 and int.from_bytes(data[:2], "little") in {
        0x0001, 0x0004, 0x0063, 0x0064, 0x0065, 0x0066, 0x006F, 0x0070
    }:
        return "enip"
    if len(data) >= 8 and data[2:4] == b"\x00\x00":
        length = int.from_bytes(data[4:6], "big")
        if 2 <= length <= len(data) - 6:
            return "modbus"
    return None


def _known_protocol(source_port: int, destination_port: int, payload: bytes = b"") -> str | None:
    source_protocol, destination_protocol = PORT_PROTOCOLS.get(source_port), PORT_PROTOCOLS.get(destination_port)
    signature = _payload_protocol(payload)
    candidates = {value for value in (source_protocol, destination_protocol) if value}
    if signature:
        return signature
    if len(candidates) == 1:
        return next(iter(candidates))
    return None


def _direction(protocol: str, source_port: int, destination_port: int) -> str:
    source_server = PORT_PROTOCOLS.get(source_port) == protocol
    destination_server = PORT_PROTOCOLS.get(destination_port) == protocol
    if destination_server and not source_server:
        return "request"
    if source_server and not destination_server:
        return "response"
    return "auto"


def reassemble_tcp(packets: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reassemble each directional TCP byte stream, preserving gaps as separate chunks."""
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    sessions: dict[tuple[Any, ...], int] = defaultdict(int)
    ordered_packets = sorted(
        (packet for packet in packets if packet.get("transport") == "tcp"),
        key=lambda packet: packet["packet_index"],
    )
    for packet in ordered_packets:
        endpoints = tuple(sorted(
            ((packet["source"], packet["source_port"]), (packet["destination"], packet["destination_port"]))
        ))
        flags = packet.get("tcp_flags", 0)
        if flags & 0x002 and not flags & 0x010:
            sessions[endpoints] += 1
        if packet.get("payload"):
            key = (
                packet["source"],
                packet["source_port"],
                packet["destination"],
                packet["destination_port"],
                sessions[endpoints],
            )
            groups[key].append(packet)
    streams = []
    for key, rows in groups.items():
        rows_by_capture = sorted(rows, key=lambda row: row["packet_index"])
        anchor = rows_by_capture[0]["sequence"]
        unwrapped = []
        for row in rows:
            sequence = (row["sequence"] - anchor) & 0xFFFFFFFF
            if sequence >= 0x80000000:
                sequence -= 0x100000000
            unwrapped.append((sequence, row))
        unwrapped.sort(key=lambda pair: (pair[0], pair[1]["packet_index"]))
        chunks: list[dict[str, Any]] = []
        current = bytearray()
        base = expected = None
        packet_indices: list[int] = []
        # segment_offsets[k] is where packet_indices[k]'s new bytes start inside the chunk, so a frame's
        # byte span can be mapped back to the capture packets that carried it (B-082).
        segment_offsets: list[int] = []
        retransmitted = conflicting = gaps = 0
        for sequence, row in unwrapped:
            payload = row["payload"]
            if base is None:
                base = expected = sequence
            assert expected is not None
            if sequence > expected:
                if current:
                    chunks.append(
                        {
                            "sequence": (anchor + base) & 0xFFFFFFFF,
                            "data": bytes(current),
                            "packet_indices": packet_indices,
                            "segment_offsets": segment_offsets,
                        }
                    )
                gaps += 1
                base = expected = sequence
                current, packet_indices, segment_offsets = bytearray(), [], []
            overlap = max(0, expected - sequence)
            if overlap:
                overlap_length = min(overlap, len(payload))
                retransmitted += overlap_length
                start = sequence - base
                if start >= 0:
                    existing = bytes(current[start : start + overlap_length])
                    conflicting += sum(left != right for left, right in zip(existing, payload[:overlap_length]))
            if overlap < len(payload):
                segment_offsets.append(len(current))
                current.extend(payload[overlap:])
                expected += len(payload) - overlap
                packet_indices.append(row["packet_index"])
            if len(current) > MAX_STREAM:
                raise ParseError("reassembled TCP stream exceeds 128 MiB cap")
        if current:
            chunks.append({
                "sequence": (anchor + base) & 0xFFFFFFFF,
                "data": bytes(current),
                "packet_indices": packet_indices,
                "segment_offsets": segment_offsets,
            })
        protocol = _known_protocol(key[1], key[3], chunks[0]["data"] if chunks else b"")
        streams.append(
            {
                "source": key[0],
                "source_port": key[1],
                "destination": key[2],
                "destination_port": key[3],
                "session": key[4],
                "protocol": protocol,
                "chunks": chunks,
                "gaps": gaps,
                "retransmitted_bytes": retransmitted,
                "conflicting_retransmitted_bytes": conflicting,
            }
        )
    return streams


def split_frames(protocol: str, data: bytes) -> tuple[list[bytes], bytes]:
    """Split complete application frames from one contiguous directional stream."""
    frames, offset = [], 0
    while offset < len(data):
        if len(frames) >= MAX_MESSAGES:
            raise ParseError("application frame count exceeds cap")
        remaining = len(data) - offset
        length: int | None = None
        if protocol == "modbus":
            if remaining < 6:
                break
            length = 6 + int.from_bytes(data[offset + 4 : offset + 6], "big")
            if length < 8:
                raise ParseError("invalid Modbus stream frame length")
        elif protocol == "s7comm":
            if remaining < 4:
                break
            if data[offset : offset + 2] != b"\x03\x00":
                raise ParseError("S7 stream lost TPKT framing")
            length = int.from_bytes(data[offset + 2 : offset + 4], "big")
            if length < 7:
                raise ParseError("invalid TPKT stream frame length")
        elif protocol == "dnp3":
            if remaining < 3:
                break
            if data[offset : offset + 2] != b"\x05\x64":
                raise ParseError("DNP3 stream lost framing")
            user_length = data[offset + 2] - 5
            if user_length < 0:
                raise ParseError("invalid DNP3 stream length")
            length = 10 + user_length + 2 * math.ceil(user_length / 16)
        elif protocol == "enip":
            if remaining < 4:
                break
            length = 24 + int.from_bytes(data[offset + 2 : offset + 4], "little")
            if length < 24:
                raise ParseError("invalid EtherNet/IP stream length")
        elif protocol == "iec104":
            if remaining < 2:
                break
            if data[offset] != 0x68:
                raise ParseError("IEC-104 stream lost framing")
            length = 2 + data[offset + 1]
            if length < 6:
                raise ParseError("invalid IEC-104 stream length")
        elif protocol == "bacnet":
            if remaining < 4:
                break
            length = int.from_bytes(data[offset + 2 : offset + 4], "big")
            if length < 4:
                raise ParseError("invalid BACnet stream length")
        else:
            return [], data
        if length > MAX_PACKET:
            raise ParseError("application frame exceeds 16 MiB cap")
        if remaining < length:
            break
        frames.append(data[offset : offset + length])
        offset += length
    return frames, data[offset:]


def _s7_cotp_piece(frame: bytes) -> tuple[bytes | None, bool]:
    _need(frame, 0, 7, "segmented S7 TPKT")
    if frame[:2] != b"\x03\x00" or int.from_bytes(frame[2:4], "big") != len(frame):
        raise ParseError("invalid segmented S7 TPKT")
    cotp_length = frame[4]
    _need(frame, 5, cotp_length, "segmented S7 COTP header")
    cotp = frame[5 : 5 + cotp_length]
    if not cotp or cotp[0] & 0xF0 != 0xF0:
        return None, True
    _need(cotp, 1, 1, "segmented S7 COTP flags")
    return frame[5 + cotp_length :], bool(cotp[1] & 0x80)


def _s7_reassembled_tpkt(payload: bytes) -> bytes:
    total = 7 + len(payload)
    if total > 0xFFFF:
        raise ParseError("reassembled S7 TPKT exceeds 16-bit length")
    return b"\x03\x00" + total.to_bytes(2, "big") + b"\x02\xf0\x80" + payload


def _walk_flags(value: Any, output: list[str]) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "flags" and isinstance(child, list):
                for item in child:
                    if isinstance(item, str) and item not in output:
                        output.append(item)
            _walk_flags(child, output)
    elif isinstance(value, list):
        for child in value:
            _walk_flags(child, output)


def _walk_protocol_findings(value: Any, output: list[dict[str, Any]]) -> None:
    if isinstance(value, dict):
        rows = value.get("findings")
        if isinstance(rows, list):
            output.extend(row for row in rows if isinstance(row, dict))
        for key, child in value.items():
            if key != "findings":
                _walk_protocol_findings(child, output)
    elif isinstance(value, list):
        for child in value:
            _walk_protocol_findings(child, output)


def _message_key(message: dict[str, Any]) -> tuple[Any, ...]:
    return (
        message["source"],
        message["source_port"],
        message["destination"],
        message["destination_port"],
    )


def _correlate(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    transactions, findings = [], []
    pending_modbus: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    pending_s7: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    dnp_sequences: dict[tuple[Any, ...], int] = {}
    iec_sequences: dict[tuple[Any, ...], int] = {}
    for index, message in enumerate(messages):
        decoded, protocol = message.get("decoded", {}), message["protocol"]
        key, reverse = _message_key(message), (
            message["destination"],
            message["destination_port"],
            message["source"],
            message["source_port"],
        )
        if protocol == "modbus" and "transaction_id" in decoded:
            transaction = (decoded["transaction_id"], decoded.get("unit_id"))
            if message["direction"] == "request":
                pending_modbus[(key, transaction)].append(index)
            else:
                request_rows = pending_modbus.get((reverse, transaction), [])
                if request_rows:
                    request_index = request_rows.pop(0)
                    transactions.append(
                        {"protocol": protocol, "request": request_index, "response": index, "id": transaction[0]}
                    )
                else:
                    findings.append(
                        {
                            "kind": "orphan-response",
                            "severity": "warning",
                            "protocol": protocol,
                            "message": index,
                            "detail": "Modbus response has no captured request",
                        }
                    )
        elif protocol == "s7comm" and "s7" in decoded:
            reference = decoded["s7"].get("pdu_reference")
            rosctr = decoded["s7"].get("rosctr")
            if rosctr == 1:
                pending_s7[(key, reference)].append(index)
            elif rosctr in (2, 3):
                request_rows = pending_s7.get((reverse, reference), [])
                if request_rows:
                    transactions.append(
                        {"protocol": protocol, "request": request_rows.pop(0), "response": index, "id": reference}
                    )
        elif protocol == "dnp3" and "transport" in decoded:
            sequence = decoded["transport"]["sequence"]
            sequence_key = key + (decoded.get("source"), decoded.get("destination"))
            previous = dnp_sequences.get(sequence_key)
            if previous is not None and sequence != (previous + 1) & 0x3F:
                findings.append(
                    {
                        "kind": "sequence-gap",
                        "severity": "warning",
                        "protocol": protocol,
                        "message": index,
                        "detail": f"DNP3 transport sequence {previous} -> {sequence}",
                    }
                )
            dnp_sequences[sequence_key] = sequence
        elif protocol == "iec104" and decoded.get("format") == "I":
            sequence = decoded["send_sequence"]
            previous = iec_sequences.get(key)
            if previous is not None and sequence != (previous + 1) & 0x7FFF:
                findings.append(
                    {
                        "kind": "sequence-gap",
                        "severity": "warning",
                        "protocol": protocol,
                        "message": index,
                        "detail": f"IEC-104 send sequence {previous} -> {sequence}",
                    }
                )
            iec_sequences[key] = sequence
    for (_key, transaction), rows in pending_modbus.items():
        for row in rows:
            findings.append(
                {
                    "kind": "orphan-request",
                    "severity": "info",
                    "protocol": "modbus",
                    "message": row,
                    "detail": f"Modbus transaction {transaction[0]} has no captured response",
                }
            )
    return transactions, findings


def _reassemble_dnp3_applications(
    messages: list[dict[str, Any]], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Join DNP3 transport fragments per captured direction and link address pair."""
    active: dict[tuple[Any, ...], dict[str, Any]] = {}
    completed = []
    for index, message in enumerate(messages):
        if message.get("protocol") != "dnp3":
            continue
        decoded = message.get("decoded", {})
        transport = decoded.get("transport")
        if not transport or "fragment" not in transport:
            continue
        key = (
            message["source"],
            message["source_port"],
            message["destination"],
            message["destination_port"],
            decoded.get("source"),
            decoded.get("destination"),
        )
        sequence = transport["sequence"]
        try:
            fragment = bytes.fromhex(transport["fragment"])
        except (TypeError, ValueError):
            continue
        if transport["first"] and transport["final"]:
            continue
        if transport["first"]:
            if key in active:
                findings.append(
                    {
                        "kind": "dnp3-abandoned-fragment",
                        "severity": "warning",
                        "protocol": "dnp3",
                        "message": index,
                        "detail": "new FIR arrived before prior transport fragment completed",
                    }
                )
            active[key] = {
                "first_message": index,
                "last_message": index,
                "next_sequence": (sequence + 1) & 0x3F,
                "data": bytearray(fragment),
                "messages": [index],
            }
        else:
            state = active.get(key)
            if state is None:
                findings.append(
                    {
                        "kind": "dnp3-orphan-fragment",
                        "severity": "warning",
                        "protocol": "dnp3",
                        "message": index,
                        "detail": "transport continuation has no captured FIR",
                    }
                )
                continue
            if sequence != state["next_sequence"]:
                findings.append(
                    {
                        "kind": "dnp3-fragment-sequence-gap",
                        "severity": "warning",
                        "protocol": "dnp3",
                        "message": index,
                        "detail": f"expected transport sequence {state['next_sequence']}, got {sequence}",
                    }
                )
                active.pop(key, None)
                continue
            state["data"].extend(fragment)
            state["last_message"] = index
            state["messages"].append(index)
            state["next_sequence"] = (sequence + 1) & 0x3F
            if len(state["data"]) > MAX_STREAM:
                raise ParseError("DNP3 reassembled application fragment exceeds cap")
        state = active.get(key)
        if state is not None and transport["final"]:
            try:
                parsed = parse_dnp3_application(bytes(state["data"]))
                messages[index]["decoded"]["reassembled_application"] = parsed["application"]
                messages[index]["decoded"].setdefault("findings", []).extend(parsed["findings"])
                completed.append(
                    {
                        "first_message": state["first_message"],
                        "last_message": index,
                        "messages": state["messages"],
                        "byte_length": len(state["data"]),
                    }
                )
            except ParseError as exc:
                findings.append(
                    {
                        "kind": "dnp3-reassembly-parse-error",
                        "severity": "warning",
                        "protocol": "dnp3",
                        "message": index,
                        "detail": str(exc),
                    }
                )
            active.pop(key, None)
    for state in active.values():
        findings.append(
            {
                "kind": "dnp3-incomplete-fragment",
                "severity": "warning",
                "protocol": "dnp3",
                "message": state["last_message"],
                "detail": "capture ended before DNP3 FIN",
            }
        )
    return completed


def analyze_capture(data: bytes, *, force_protocol: str | None = None) -> dict[str, Any]:
    """Dissect supported ICS application traffic from a supplied capture."""
    packets, findings, packet_count = extract_transports(data, include_count=True)
    streams = reassemble_tcp(packets)
    messages: list[dict[str, Any]] = []
    flow_summaries = []
    for stream in streams:
        protocol = force_protocol or stream["protocol"]
        summary = {key: value for key, value in stream.items() if key != "chunks"}
        summary["chunk_count"] = len(stream["chunks"])
        summary["trailing_bytes"] = 0
        if stream["conflicting_retransmitted_bytes"]:
            findings.append(
                {
                    "kind": "conflicting-tcp-retransmission",
                    "severity": "warning",
                    "protocol": protocol,
                    "flow": len(flow_summaries),
                    "detail": f"{stream['conflicting_retransmitted_bytes']} overlapping bytes disagree",
                }
            )
        if not protocol:
            flow_summaries.append(summary)
            continue
        direction = _direction(protocol, stream["source_port"], stream["destination_port"])
        s7_pending = bytearray()
        s7_pending_packets: list[int] = []
        for chunk_index, chunk in enumerate(stream["chunks"]):
            if chunk_index and s7_pending:
                findings.append(
                    {
                        "kind": "s7-cotp-segmentation-gap",
                        "severity": "warning",
                        "protocol": "s7comm",
                        "flow": len(flow_summaries),
                        "packet_indices": list(dict.fromkeys(s7_pending_packets)),
                        "detail": "TCP gap interrupted segmented S7 COTP payload",
                    }
                )
                s7_pending.clear()
                s7_pending_packets.clear()
            try:
                frames, trailing = split_frames(protocol, chunk["data"])
                summary["trailing_bytes"] += len(trailing)
                if trailing:
                    findings.append(
                        {
                            "kind": "trailing-stream-bytes",
                            "severity": "warning",
                            "protocol": protocol,
                            "flow": len(flow_summaries),
                            "detail": f"{len(trailing)} incomplete/undecoded bytes",
                        }
                    )
                for frame in frames:
                    try:
                        message_packet_indices = list(chunk["packet_indices"])
                        if protocol == "s7comm":
                            piece, eot = _s7_cotp_piece(frame)
                            if piece is not None and (s7_pending or not eot):
                                s7_pending.extend(piece)
                                s7_pending_packets.extend(chunk["packet_indices"])
                                if len(s7_pending) > MAX_STREAM:
                                    raise ParseError("segmented S7 payload exceeds stream cap")
                                if not eot:
                                    continue
                                frame = _s7_reassembled_tpkt(bytes(s7_pending))
                                message_packet_indices = list(dict.fromkeys(s7_pending_packets))
                                s7_pending.clear()
                                s7_pending_packets.clear()
                        decoded = dissect(
                            frame,
                            protocol=protocol,
                            source_port=stream["source_port"],
                            destination_port=stream["destination_port"],
                            direction=direction,
                        )
                        messages.append(
                            {
                                "protocol": protocol,
                                "transport": "tcp",
                                "source": stream["source"],
                                "source_port": stream["source_port"],
                                "destination": stream["destination"],
                                "destination_port": stream["destination_port"],
                                "direction": direction,
                                "packet_indices": message_packet_indices,
                                "decoded": decoded,
                            }
                        )
                    except (ParseError, ValueError, TypeError) as exc:
                        findings.append(
                            {
                                "kind": "application-parse-error",
                                "severity": "warning",
                                "protocol": protocol,
                                "detail": str(exc),
                            }
                        )
            except ParseError as exc:
                findings.append(
                    {
                        "kind": "stream-framing-error",
                        "severity": "warning",
                        "protocol": protocol,
                        "detail": str(exc),
                    }
                )
        if s7_pending:
            findings.append(
                {
                    "kind": "incomplete-s7-cotp-segmentation",
                    "severity": "warning",
                    "protocol": "s7comm",
                    "flow": len(flow_summaries),
                    "packet_indices": list(dict.fromkeys(s7_pending_packets)),
                    "detail": f"capture ended with {len(s7_pending)} reassembled S7 bytes before COTP EOT",
                }
            )
        flow_summaries.append(summary)
    for packet in packets:
        if packet.get("transport") != "udp" or not packet.get("payload"):
            continue
        protocol = force_protocol or _known_protocol(
            packet["source_port"], packet["destination_port"], packet["payload"]
        )
        if not protocol:
            continue
        direction = _direction(protocol, packet["source_port"], packet["destination_port"])
        frames = [packet["payload"]]
        if protocol in ("dnp3", "bacnet"):
            try:
                frames, trailing = split_frames(protocol, packet["payload"])
                if trailing:
                    findings.append(
                        {
                            "kind": "udp-trailing-bytes",
                            "severity": "warning",
                            "protocol": protocol,
                            "packet_index": packet["packet_index"],
                            "detail": f"{len(trailing)} undecoded bytes",
                        }
                    )
            except ParseError as exc:
                findings.append(
                    {
                        "kind": "datagram-framing-error",
                        "severity": "warning",
                        "protocol": protocol,
                        "packet_index": packet["packet_index"],
                        "detail": str(exc),
                    }
                )
                continue
        for frame in frames:
            try:
                decoded = dissect(
                    frame,
                    protocol=protocol,
                    source_port=packet["source_port"],
                    destination_port=packet["destination_port"],
                    direction=direction,
                )
                messages.append(
                    {
                        "protocol": protocol,
                        "transport": "udp",
                        "source": packet["source"],
                        "source_port": packet["source_port"],
                        "destination": packet["destination"],
                        "destination_port": packet["destination_port"],
                        "direction": direction,
                        "packet_indices": [packet["packet_index"]],
                        "decoded": decoded,
                    }
                )
            except (ParseError, ValueError, TypeError) as exc:
                findings.append(
                    {
                        "kind": "application-parse-error",
                        "severity": "warning",
                        "protocol": protocol,
                        "packet_index": packet["packet_index"],
                        "detail": str(exc),
                    }
                )
    dnp3_reassemblies = _reassemble_dnp3_applications(messages, findings)
    for message_index, message in enumerate(messages):
        protocol_findings: list[dict[str, Any]] = []
        _walk_protocol_findings(message.get("decoded", {}), protocol_findings)
        for protocol_finding in protocol_findings:
            findings.append(
                {
                    **protocol_finding,
                    "protocol": message["protocol"],
                    "message": message_index,
                }
            )
    transactions, correlation_findings = _correlate(messages)
    findings.extend(correlation_findings)
    flags: list[str] = []
    _walk_flags(messages, flags)
    protocol_counts: dict[str, int] = defaultdict(int)
    for message in messages:
        protocol_counts[message["protocol"]] += 1
    return {
        "format": "pcapng" if data.startswith(b"\x0a\x0d\x0d\x0a") else "pcap",
        "packet_count": packet_count,
        "transport_packet_count": len(packets),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "flows": flow_summaries,
        "messages": messages,
        "dnp3_reassemblies": dnp3_reassemblies,
        "transactions": transactions,
        "findings": findings,
        "flags": flags,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline PCAP/PCAPNG ICS protocol and session analyzer")
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--protocol", choices=sorted(set(PORT_PROTOCOLS.values())))
    args = parser.parse_args(argv)
    output = []
    try:
        for path in args.captures:
            if path.stat().st_size > MAX_CAPTURE:
                raise ParseError(f"{path}: capture exceeds 256 MiB cap")
            output.append({"path": str(path), "analysis": analyze_capture(path.read_bytes(), force_protocol=args.protocol)})
    except (OSError, ParseError, ValueError, TypeError) as exc:
        print(f"ics_capture: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
