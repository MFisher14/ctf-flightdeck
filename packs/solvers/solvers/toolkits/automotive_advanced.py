#!/usr/bin/env python3
"""Stateful, bounded, offline automotive capture analysis.

Supported saved artifacts include candump text, Classical CAN/CAN-FD ISO-TP, UDS messages,
J1939-21 TP and fast-packet transports, DM1 diagnostics, and keyless rolling-code sequences.
No function opens a CAN adapter, vehicle interface, radio, socket, or subprocess; there are no
transmit or key-search paths.
"""
from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any, Iterable, Sequence


MAX_INPUT = 64 << 20
MAX_FRAMES = 500_000
MAX_ISOTP_PAYLOAD = 16 << 20
MAX_J1939_PAYLOAD = 1785
CANFD_DLC_LENGTHS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64)


class AutomotiveParseError(ValueError):
    """A saved automotive artifact is malformed, inconsistent, or exceeds a bound."""


def _data_bytes(value: bytes | bytearray | memoryview | str) -> bytes:
    if isinstance(value, str):
        compact = "".join(value.split())
        if len(compact) & 1 or not re.fullmatch(r"[0-9a-fA-F]*", compact):
            raise AutomotiveParseError("CAN data must contain complete hexadecimal octets")
        return bytes.fromhex(compact)
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("CAN data must be bytes-like or hexadecimal")
    return bytes(value)


def can_fd_dlc_length(dlc: int) -> int:
    if not isinstance(dlc, int) or not 0 <= dlc <= 15:
        raise AutomotiveParseError("CAN DLC must be 0..15")
    return CANFD_DLC_LENGTHS[dlc]


def can_fd_length_dlc(length: int) -> int:
    if not isinstance(length, int) or not 0 <= length <= 64:
        raise AutomotiveParseError("CAN payload length must be 0..64")
    return next(index for index, capacity in enumerate(CANFD_DLC_LENGTHS) if capacity >= length)


_CANDUMP_COMPACT = re.compile(
    r"^\s*(?:\((?P<time>[-+0-9.eE]+)\)\s+)?(?:(?P<iface>[A-Za-z0-9_.:-]+)\s+)?"
    r"(?P<id>[0-9A-Fa-f]{3,8})(?P<sep>##|#)(?P<body>[0-9A-Fa-f]*)\s*$"
)
_CANDUMP_VERBOSE = re.compile(
    r"^\s*(?:\((?P<time>[-+0-9.eE]+)\)\s+)?(?P<iface>[A-Za-z0-9_.:-]+)\s+"
    r"(?P<id>[0-9A-Fa-f]{3,8})\s+\[(?P<length>\d{1,2})\]\s*(?P<body>(?:[0-9A-Fa-f]{2}\s*)*)$"
)


def parse_candump_line(line: str, *, index: int = 0) -> dict[str, Any]:
    """Parse common compact/verbose candump serialization without touching an interface."""
    if not isinstance(line, str) or len(line) > 16_384:
        raise AutomotiveParseError("candump line is not bounded text")
    match = _CANDUMP_COMPACT.fullmatch(line)
    fd, flags = False, 0
    if match:
        body = match.group("body")
        if match.group("sep") == "##":
            if not body:
                raise AutomotiveParseError("CAN-FD compact frame lacks flags nibble")
            fd, flags, body = True, int(body[0], 16), body[1:]
        data = _data_bytes(body)
        declared = len(data)
    else:
        match = _CANDUMP_VERBOSE.fullmatch(line)
        if not match:
            raise AutomotiveParseError("unrecognized candump line")
        data = _data_bytes(match.group("body"))
        declared = int(match.group("length"))
        if declared != len(data):
            raise AutomotiveParseError("candump declared length mismatch")
    if len(data) > (64 if fd else 8):
        raise AutomotiveParseError("CAN payload exceeds frame capacity")
    can_id = int(match.group("id"), 16)
    if can_id > 0x1FFFFFFF:
        raise AutomotiveParseError("CAN identifier exceeds 29 bits")
    time_text = match.group("time")
    timestamp = float(time_text) if time_text is not None else None
    if timestamp is not None and not math.isfinite(timestamp):
        raise AutomotiveParseError("non-finite candump timestamp")
    return {
        "index": index, "timestamp": timestamp, "interface": match.groupdict().get("iface"),
        "can_id": can_id, "extended": can_id > 0x7FF or len(match.group("id")) > 3,
        "fd": fd, "fd_flags": flags, "bit_rate_switch": bool(flags & 1),
        "error_state_indicator": bool(flags & 2), "data": data,
        "length": declared, "dlc": can_fd_length_dlc(len(data)) if fd else len(data),
    }


def parse_candump(data: bytes | str) -> list[dict[str, Any]]:
    if isinstance(data, bytes):
        if len(data) > MAX_INPUT:
            raise AutomotiveParseError("candump artifact exceeds cap")
        try:
            text = data.decode("utf-8")
        except UnicodeError as exc:
            raise AutomotiveParseError(f"candump is not UTF-8: {exc}") from exc
    elif isinstance(data, str) and len(data.encode("utf-8")) <= MAX_INPUT:
        text = data
    else:
        raise AutomotiveParseError("candump artifact must be bounded bytes/text")
    frames = []
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("//", ";")):
            continue
        if len(frames) >= MAX_FRAMES:
            raise AutomotiveParseError("candump frame cap exceeded")
        try:
            frames.append(parse_candump_line(stripped, index=len(frames)))
        except AutomotiveParseError as exc:
            raise AutomotiveParseError(f"line {line_number}: {exc}") from exc
    return frames


def _frame_data(frame: dict[str, Any]) -> bytes:
    if not isinstance(frame, dict) or "can_id" not in frame or "data" not in frame:
        raise AutomotiveParseError("CAN frame lacks identifier/data")
    data = _data_bytes(frame["data"])
    if len(data) > (64 if frame.get("fd") else 8):
        raise AutomotiveParseError("CAN frame data exceeds declared bus format")
    return data


# ------------------------------------------------------------------ ISO-TP and UDS

def _stmin_seconds(value: int) -> float | None:
    if 0 <= value <= 0x7F:
        return value / 1000.0
    if 0xF1 <= value <= 0xF9:
        return (value - 0xF0) / 10_000.0
    return None


def reassemble_isotp(
    frames: Iterable[dict[str, Any]], *, address_byte: int | None = None,
    timeout: float = 1.0, max_payload: int = MAX_ISOTP_PAYLOAD,
) -> dict[str, Any]:
    """Statefully reassemble Classical CAN and CAN-FD ISO-TP streams by CAN ID/address."""
    if address_byte is not None and not 0 <= address_byte <= 0xFF:
        raise AutomotiveParseError("ISO-TP extended address must be one byte")
    if not math.isfinite(timeout) or timeout <= 0 or not 1 <= max_payload <= MAX_ISOTP_PAYLOAD:
        raise AutomotiveParseError("invalid ISO-TP bounds")
    sessions: dict[tuple[int, int | None], dict[str, Any]] = {}
    messages, controls, issues = [], [], []
    for fallback_index, frame in enumerate(frames):
        if fallback_index >= MAX_FRAMES:
            raise AutomotiveParseError("ISO-TP frame cap exceeded")
        data = _frame_data(frame)
        can_id = int(frame["can_id"])
        index = int(frame.get("index", fallback_index))
        timestamp = frame.get("timestamp")
        if timestamp is not None:
            timestamp = float(timestamp)
            if not math.isfinite(timestamp):
                raise AutomotiveParseError("non-finite ISO-TP timestamp")
        cursor, address = 0, None
        if address_byte is not None:
            if not data:
                issues.append({"kind": "empty-addressed-frame", "frame": index})
                continue
            address, cursor = data[0], 1
            if address != address_byte:
                continue
        if cursor >= len(data):
            issues.append({"kind": "missing-pci", "frame": index})
            continue
        key = can_id, address
        active = sessions.get(key)
        if active is not None and timestamp is not None and active["last_time"] is not None and timestamp - active["last_time"] > timeout:
            issues.append({"kind": "timeout", "frame": index, "can_id": can_id,
                           "received": len(active["payload"]), "expected": active["length"]})
            sessions.pop(key, None)
            active = None
        pci, kind = data[cursor], data[cursor] >> 4
        if kind == 0:  # Single Frame, including CAN-FD escape SF_DL.
            length = pci & 0x0F
            header = cursor + 1
            if length == 0:
                if not frame.get("fd"):
                    issues.append({"kind": "invalid-single-frame-escape", "frame": index})
                    continue
                if header >= len(data):
                    issues.append({"kind": "truncated-single-frame-length", "frame": index})
                    continue
                length, header = data[header], header + 1
                if length <= 15:
                    issues.append({"kind": "noncanonical-single-frame-length", "frame": index, "length": length})
            if header + length > len(data):
                issues.append({"kind": "truncated-single-frame", "frame": index, "length": length})
                continue
            if active is not None:
                issues.append({"kind": "session-replaced-by-single", "frame": index, "can_id": can_id})
                sessions.pop(key, None)
            messages.append({"can_id": can_id, "address": address, "data": data[header:header + length],
                             "frame_indices": [index], "start_time": timestamp, "end_time": timestamp,
                             "padding": data[header + length:]})
        elif kind == 1:  # First Frame, 12-bit or CAN-FD 32-bit escape length.
            if cursor + 2 > len(data):
                issues.append({"kind": "truncated-first-frame", "frame": index})
                continue
            length = ((pci & 0x0F) << 8) | data[cursor + 1]
            header = cursor + 2
            if length == 0:
                if cursor + 6 > len(data):
                    issues.append({"kind": "truncated-first-frame-escape", "frame": index})
                    continue
                length, header = int.from_bytes(data[cursor + 2:cursor + 6], "big"), cursor + 6
                if length <= 0xFFF:
                    issues.append({"kind": "noncanonical-first-frame-length", "frame": index, "length": length})
            if not 1 <= length <= max_payload:
                issues.append({"kind": "payload-length-out-of-range", "frame": index, "length": length})
                continue
            single_limit = (61 if address_byte is not None else 62) if frame.get("fd") else (6 if address_byte is not None else 7)
            if length <= single_limit:
                issues.append({"kind": "noncanonical-first-frame", "frame": index, "length": length,
                               "single_frame_limit": single_limit})
                continue
            if key in sessions:
                issues.append({"kind": "session-restarted", "frame": index, "can_id": can_id})
            sessions[key] = {"length": length, "payload": bytearray(data[header:]), "next_sequence": 1,
                             "frames": [index], "start_time": timestamp, "last_time": timestamp}
            if len(sessions[key]["payload"]) >= length:
                payload = bytes(sessions[key]["payload"][:length])
                messages.append({"can_id": can_id, "address": address, "data": payload,
                                 "frame_indices": [index], "start_time": timestamp, "end_time": timestamp,
                                 "padding": bytes(sessions[key]["payload"][length:])})
                sessions.pop(key)
        elif kind == 2:  # Consecutive Frame.
            sequence = pci & 0x0F
            if active is None:
                issues.append({"kind": "orphan-consecutive-frame", "frame": index, "sequence": sequence})
                continue
            if sequence != active["next_sequence"]:
                issues.append({"kind": "sequence-mismatch", "frame": index, "expected": active["next_sequence"], "actual": sequence})
                sessions.pop(key, None)
                continue
            active["payload"].extend(data[cursor + 1:])
            active["frames"].append(index)
            active["next_sequence"] = (sequence + 1) & 0x0F
            active["last_time"] = timestamp
            if len(active["payload"]) >= active["length"]:
                payload = bytes(active["payload"][:active["length"]])
                messages.append({"can_id": can_id, "address": address, "data": payload,
                                 "frame_indices": list(active["frames"]), "start_time": active["start_time"],
                                 "end_time": timestamp, "padding": bytes(active["payload"][active["length"]:])})
                sessions.pop(key, None)
        elif kind == 3:  # Flow Control.
            if cursor + 3 > len(data):
                issues.append({"kind": "truncated-flow-control", "frame": index})
                continue
            status = pci & 0x0F
            controls.append({"frame": index, "can_id": can_id, "address": address, "status": status,
                             "status_name": {0: "continue-to-send", 1: "wait", 2: "overflow"}.get(status, "reserved"),
                             "block_size": data[cursor + 1], "stmin_raw": data[cursor + 2],
                             "stmin_seconds": _stmin_seconds(data[cursor + 2])})
        else:
            issues.append({"kind": "unknown-pci", "frame": index, "pci": pci})
    for (can_id, address), active in sessions.items():
        issues.append({"kind": "incomplete-message", "can_id": can_id, "address": address,
                       "received": len(active["payload"]), "expected": active["length"],
                       "frame_indices": active["frames"]})
    return {"messages": messages, "flow_controls": controls, "issues": issues}


UDS_SERVICES = {
    0x10: "DiagnosticSessionControl", 0x11: "ECUReset", 0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation", 0x22: "ReadDataByIdentifier", 0x23: "ReadMemoryByAddress",
    0x27: "SecurityAccess", 0x28: "CommunicationControl", 0x2E: "WriteDataByIdentifier",
    0x2F: "InputOutputControlByIdentifier", 0x31: "RoutineControl", 0x34: "RequestDownload",
    0x35: "RequestUpload", 0x36: "TransferData", 0x37: "RequestTransferExit",
    0x3D: "WriteMemoryByAddress", 0x3E: "TesterPresent", 0x85: "ControlDTCSetting",
}
UDS_NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat", 0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect",
    0x24: "requestSequenceError", 0x31: "requestOutOfRange", 0x33: "securityAccessDenied",
    0x35: "invalidKey", 0x36: "exceedNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended", 0x72: "generalProgrammingFailure",
    0x73: "wrongBlockSequenceCounter", 0x78: "responsePending",
}


def _address_length(data: bytes, offset: int) -> dict[str, Any]:
    if offset >= len(data):
        raise AutomotiveParseError("UDS address/length format is truncated")
    fmt = data[offset]
    address_bytes, length_bytes = fmt & 0x0F, fmt >> 4
    cursor = offset + 1
    if not 1 <= address_bytes <= 8 or not 1 <= length_bytes <= 8 or cursor + address_bytes + length_bytes > len(data):
        raise AutomotiveParseError("UDS address/length format is invalid")
    return {"format": fmt, "address_bytes": address_bytes, "length_bytes": length_bytes,
            "memory_address": int.from_bytes(data[cursor:cursor + address_bytes], "big"),
            "memory_size": int.from_bytes(data[cursor + address_bytes:cursor + address_bytes + length_bytes], "big"),
            "consumed": 1 + address_bytes + length_bytes}


def parse_uds_message(data: bytes | str, *, direction: str = "auto") -> dict[str, Any]:
    raw = _data_bytes(data)
    if not raw:
        raise AutomotiveParseError("empty UDS message")
    if direction not in {"auto", "request", "response"}:
        raise ValueError("UDS direction must be auto, request or response")
    sid = raw[0]
    if sid == 0x7F:
        if len(raw) != 3:
            raise AutomotiveParseError("UDS negative response must be exactly three bytes")
        return {"direction": "response", "negative": True, "service": raw[1],
                "service_name": UDS_SERVICES.get(raw[1], f"Unknown_{raw[1]:02X}"),
                "nrc": raw[2], "nrc_name": UDS_NRC.get(raw[2], f"unknown_{raw[2]:02X}"), "raw": raw.hex()}
    positive = direction == "response" or (direction == "auto" and sid >= 0x40 and (sid - 0x40) in UDS_SERVICES)
    service = sid - 0x40 if positive else sid
    out: dict[str, Any] = {"direction": "response" if positive else "request", "negative": False,
                           "sid": sid, "service": service,
                           "service_name": UDS_SERVICES.get(service, f"Unknown_{service:02X}"), "raw": raw.hex()}
    body = raw[1:]
    if service in (0x10, 0x11, 0x27, 0x28, 0x3E, 0x85):
        if not body:
            raise AutomotiveParseError("UDS subfunction is missing")
        out.update(subfunction=body[0] & 0x7F, suppress_positive_response=bool(body[0] & 0x80), data=body[1:].hex())
        if service == 0x27:
            out["security_access_kind"] = "key" if (body[0] & 0x7F) % 2 == 0 else "seed"
    elif service in (0x22, 0x2E, 0x2F):
        if len(body) < 2:
            raise AutomotiveParseError("UDS DID is truncated")
        out.update(did=int.from_bytes(body[:2], "big"), data=body[2:].hex())
    elif service == 0x31:
        if len(body) < 3:
            raise AutomotiveParseError("UDS routine control is truncated")
        out.update(subfunction=body[0] & 0x7F, routine_id=int.from_bytes(body[1:3], "big"), data=body[3:].hex())
    elif service in (0x34, 0x35):
        if positive:
            if not body:
                raise AutomotiveParseError("UDS download/upload response is truncated")
            length_bytes = body[0] >> 4
            if length_bytes < 1 or 1 + length_bytes > len(body):
                raise AutomotiveParseError("UDS max-block-length format is invalid")
            out["max_block_length"] = int.from_bytes(body[1:1 + length_bytes], "big")
        else:
            if len(body) < 2:
                raise AutomotiveParseError("UDS download/upload request is truncated")
            out.update(data_format_identifier=body[0], **_address_length(body, 1))
    elif service == 0x36:
        if not body:
            raise AutomotiveParseError("UDS transfer-data sequence is missing")
        out.update(block_sequence_counter=body[0], data=body[1:].hex())
    elif service == 0x37:
        out["data"] = body.hex()
    elif service in (0x23, 0x3D) and not positive:
        out.update(**_address_length(body, 0))
        consumed = out["consumed"]
        out["data"] = body[consumed:].hex()
    elif service == 0x14:
        if len(body) != 3:
            raise AutomotiveParseError("UDS clear-DTC group must be three bytes")
        out["dtc_group"] = int.from_bytes(body, "big")
    elif service == 0x19:
        if not body:
            raise AutomotiveParseError("UDS DTC subfunction is missing")
        out.update(subfunction=body[0] & 0x7F, data=body[1:].hex())
    else:
        out["data"] = body.hex()
    return out


def analyze_uds(
    frames: Iterable[dict[str, Any]], *, request_ids: Sequence[int], response_ids: Sequence[int],
    address_byte: int | None = None,
) -> dict[str, Any]:
    request_set, response_set = {int(value) for value in request_ids}, {int(value) for value in response_ids}
    if not request_set or not response_set or request_set & response_set:
        raise AutomotiveParseError("UDS request/response CAN IDs must be nonempty and disjoint")
    transport = reassemble_isotp(frames, address_byte=address_byte)
    messages, findings, transactions, pending = [], [], [], []
    for message_index, message in enumerate(transport["messages"]):
        if message["can_id"] in request_set:
            direction = "request"
        elif message["can_id"] in response_set:
            direction = "response"
        else:
            continue
        try:
            decoded = parse_uds_message(message["data"], direction=direction)
        except AutomotiveParseError as exc:
            decoded = {"error": str(exc), "raw": message["data"].hex(), "direction": direction}
        row = {**message, "message_index": message_index, "decoded": decoded}
        messages.append(row)
        if "error" in decoded:
            findings.append({"kind": "malformed-uds", "severity": "medium", "message": message_index, "detail": decoded["error"]})
            continue
        if direction == "request":
            pending.append((message_index, decoded["service"]))
            service = decoded["service"]
            kind = None
            if service == 0x27 and decoded.get("security_access_kind") == "key": kind = "security-key-attempt"
            elif service in (0x2E, 0x2F, 0x3D): kind = "diagnostic-write"
            elif service == 0x31 and decoded.get("subfunction") in (1, 2): kind = "routine-control"
            elif service in (0x34, 0x35, 0x36, 0x37): kind = "firmware-transfer"
            elif service == 0x11: kind = "ecu-reset"
            if kind:
                findings.append({"kind": kind, "severity": "high", "message": message_index,
                                 "service": decoded["service_name"]})
        else:
            service = decoded["service"]
            match = next((position for position, (_, expected) in enumerate(pending) if expected == service), None)
            if match is not None:
                request_index, _ = pending.pop(match)
                transactions.append({"request": request_index, "response": message_index, "service": service,
                                     "negative": decoded.get("negative", False), "nrc": decoded.get("nrc")})
    return {"transport": transport, "messages": messages, "transactions": transactions,
            "unanswered_requests": [index for index, _ in pending], "findings": findings}


# ------------------------------------------------------------------ J1939 transports/diagnostics

J1939_TP_CM = 0xEC00
J1939_TP_DT = 0xEB00


def parse_j1939_id(can_id: int) -> dict[str, Any]:
    if not isinstance(can_id, int) or not 0 <= can_id <= 0x1FFFFFFF:
        raise AutomotiveParseError("J1939 identifier must be a 29-bit integer")
    priority = (can_id >> 26) & 7
    reserved, data_page = (can_id >> 25) & 1, (can_id >> 24) & 1
    pdu_format, pdu_specific, source = (can_id >> 16) & 0xFF, (can_id >> 8) & 0xFF, can_id & 0xFF
    pgn = (reserved << 17) | (data_page << 16) | (pdu_format << 8) | (pdu_specific if pdu_format >= 240 else 0)
    return {"priority": priority, "reserved": reserved, "data_page": data_page,
            "pdu_format": pdu_format, "pdu_specific": pdu_specific, "source": source,
            "destination": pdu_specific if pdu_format < 240 else 0xFF, "pgn": pgn}


def j1939_id(pgn: int, source: int, *, destination: int = 0xFF, priority: int = 6) -> int:
    if not 0 <= pgn <= 0x3FFFF or not 0 <= source <= 0xFF or not 0 <= destination <= 0xFF or not 0 <= priority <= 7:
        raise AutomotiveParseError("invalid J1939 ID fields")
    reserved, data_page, pf = (pgn >> 17) & 1, (pgn >> 16) & 1, (pgn >> 8) & 0xFF
    ps = (pgn & 0xFF) if pf >= 240 else destination
    return (priority << 26) | (reserved << 25) | (data_page << 24) | (pf << 16) | (ps << 8) | source


def reassemble_j1939_tp(frames: Iterable[dict[str, Any]], *, timeout: float = 1.5) -> dict[str, Any]:
    sessions: dict[tuple[int, int], dict[str, Any]] = {}
    messages, controls, issues = [], [], []
    for fallback_index, frame in enumerate(frames):
        if fallback_index >= MAX_FRAMES:
            raise AutomotiveParseError("J1939 frame cap exceeded")
        fields, data = parse_j1939_id(int(frame["can_id"])), _frame_data(frame)
        index, timestamp = int(frame.get("index", fallback_index)), frame.get("timestamp")
        timestamp = float(timestamp) if timestamp is not None else None
        if fields["pgn"] == J1939_TP_CM:
            if len(data) != 8:
                issues.append({"kind": "invalid-tp-cm-length", "frame": index})
                continue
            control = data[0]
            target_pgn = int.from_bytes(data[5:8], "little")
            key = fields["source"], fields["destination"]
            row = {"frame": index, "control": control,
                   "control_name": {0x10: "RTS", 0x11: "CTS", 0x13: "EOM_ACK", 0x20: "BAM", 0xFF: "ABORT"}.get(control, "reserved"),
                   "source": fields["source"], "destination": fields["destination"], "target_pgn": target_pgn}
            controls.append(row)
            if control in (0x10, 0x20):
                size, packets = int.from_bytes(data[1:3], "little"), data[3]
                if (not 1 <= size <= MAX_J1939_PAYLOAD or packets != (size + 6) // 7
                        or not 0 <= target_pgn <= 0x3FFFF):
                    issues.append({"kind": "invalid-tp-announcement", "frame": index, "size": size, "packets": packets})
                    continue
                if key in sessions:
                    issues.append({"kind": "tp-session-restarted", "frame": index,
                                   "source": key[0], "destination": key[1]})
                sessions[key] = {"size": size, "packets": packets, "target_pgn": target_pgn,
                                 "next_sequence": 1, "payload": bytearray(), "frames": [index],
                                 "start_time": timestamp, "last_time": timestamp, "mode": row["control_name"]}
            elif control == 0xFF:
                sessions.pop(key, None)
        elif fields["pgn"] == J1939_TP_DT:
            if len(data) != 8:
                issues.append({"kind": "invalid-tp-dt-length", "frame": index})
                continue
            key = fields["source"], fields["destination"]
            active = sessions.get(key)
            if active is None:
                issues.append({"kind": "orphan-tp-data", "frame": index})
                continue
            if timestamp is not None and active["last_time"] is not None and timestamp - active["last_time"] > timeout:
                issues.append({"kind": "tp-timeout", "frame": index, "source": key[0], "destination": key[1]})
                sessions.pop(key)
                continue
            sequence = data[0]
            if sequence != active["next_sequence"]:
                issues.append({"kind": "tp-sequence-mismatch", "frame": index,
                               "expected": active["next_sequence"], "actual": sequence})
                sessions.pop(key)
                continue
            active["payload"].extend(data[1:])
            active["frames"].append(index)
            active["next_sequence"] += 1
            active["last_time"] = timestamp
            if sequence == active["packets"]:
                payload = bytes(active["payload"][:active["size"]])
                messages.append({"source": key[0], "destination": key[1], "pgn": active["target_pgn"],
                                 "data": payload, "frame_indices": active["frames"], "mode": active["mode"],
                                 "start_time": active["start_time"], "end_time": timestamp})
                sessions.pop(key)
    for key, active in sessions.items():
        issues.append({"kind": "incomplete-tp", "source": key[0], "destination": key[1],
                       "received_packets": active["next_sequence"] - 1, "expected_packets": active["packets"]})
    return {"messages": messages, "controls": controls, "issues": issues}


def reassemble_j1939_fast_packets(frames: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Reassemble NMEA-2000/J1939 fast-packet records (up to 223 bytes)."""
    sessions, messages, issues = {}, [], []
    for fallback_index, frame in enumerate(frames):
        if fallback_index >= MAX_FRAMES:
            raise AutomotiveParseError("J1939 fast-packet frame cap exceeded")
        fields, data = parse_j1939_id(int(frame["can_id"])), _frame_data(frame)
        index = int(frame.get("index", fallback_index))
        if len(data) != 8:
            issues.append({"kind": "invalid-fast-packet-length", "frame": index})
            continue
        sequence_id, counter = data[0] >> 5, data[0] & 0x1F
        key = fields["source"], fields["destination"], fields["pgn"], sequence_id
        if counter == 0:
            length = data[1]
            if not 1 <= length <= 223:
                issues.append({"kind": "invalid-fast-packet-size", "frame": index, "size": length})
                continue
            sessions[key] = {"length": length, "next": 1, "payload": bytearray(data[2:]), "frames": [index]}
        else:
            active = sessions.get(key)
            if active is None:
                issues.append({"kind": "orphan-fast-packet", "frame": index})
                continue
            if counter != active["next"]:
                issues.append({"kind": "fast-packet-sequence", "frame": index,
                               "expected": active["next"], "actual": counter})
                sessions.pop(key)
                continue
            active["payload"].extend(data[1:])
            active["frames"].append(index)
            active["next"] += 1
        active = sessions.get(key)
        if active is not None and len(active["payload"]) >= active["length"]:
            messages.append({"source": key[0], "destination": key[1], "pgn": key[2], "sequence_id": key[3],
                             "data": bytes(active["payload"][:active["length"]]), "frame_indices": active["frames"]})
            sessions.pop(key)
    for key, active in sessions.items():
        issues.append({"kind": "incomplete-fast-packet", "source": key[0], "pgn": key[2],
                       "received": len(active["payload"]), "expected": active["length"]})
    return {"messages": messages, "issues": issues}


def parse_j1939_dm1(data: bytes | str) -> dict[str, Any]:
    raw = _data_bytes(data)
    original = raw
    while len(raw) >= 2 and (len(raw) - 2) % 4 and raw.endswith(b"\xff"):
        raw = raw[:-1]
    if len(raw) < 2 or (len(raw) - 2) % 4:
        raise AutomotiveParseError("J1939 DM1 must contain two lamp bytes plus complete DTCs")
    lamp_names = ("malfunction", "red_stop", "amber_warning", "protect")
    lamps = {name: (raw[0] >> (index * 2)) & 3 for index, name in enumerate(lamp_names)}
    flashes = {name: (raw[1] >> (index * 2)) & 3 for index, name in enumerate(lamp_names)}
    dtcs = []
    for offset in range(2, len(raw), 4):
        first, second, third, fourth = raw[offset:offset + 4]
        if raw[offset:offset + 4] == b"\xff" * 4:
            continue
        dtcs.append({"spn": first | (second << 8) | ((third & 0xE0) << 11),
                     "fmi": third & 0x1F, "occurrence_count": fourth & 0x7F,
                     "conversion_method": bool(fourth & 0x80), "raw": raw[offset:offset + 4].hex()})
    return {"pgn": 0xFECA, "lamps": lamps, "lamp_flashes": flashes, "dtcs": dtcs,
            "padding": original[len(raw):].hex()}


# ------------------------------------------------------------------ rolling/keyless capture analysis

KEELOQ_NLF = 0x3A5C742E


def _integer_code(value: Any, what: str) -> int:
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0)
        except ValueError:
            if re.fullmatch(r"[0-9A-Fa-f]+", text):
                return int(text, 16)
            raise AutomotiveParseError(f"invalid {what}") from None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        raise AutomotiveParseError(f"invalid {what}") from None


def keeloq_encrypt(plaintext: int, key: int) -> int:
    """Encrypt one supplied 32-bit KeeLoq hopping value with a supplied 64-bit key."""
    if not 0 <= plaintext <= 0xFFFFFFFF or not 0 <= key <= 0xFFFFFFFFFFFFFFFF:
        raise AutomotiveParseError("KeeLoq plaintext/key width exceeded")
    state = plaintext
    for round_index in range(528):
        nlf_index = ((state >> 1) & 1) | ((state >> 8) & 2) | ((state >> 18) & 4) | ((state >> 23) & 8) | ((state >> 27) & 16)
        bit = ((state >> 0) ^ (state >> 16) ^ (key >> (round_index & 63)) ^ (KEELOQ_NLF >> nlf_index)) & 1
        state = ((state >> 1) | (bit << 31)) & 0xFFFFFFFF
    return state


def keeloq_decrypt(ciphertext: int, key: int) -> int:
    if not 0 <= ciphertext <= 0xFFFFFFFF or not 0 <= key <= 0xFFFFFFFFFFFFFFFF:
        raise AutomotiveParseError("KeeLoq ciphertext/key width exceeded")
    state = ciphertext
    for round_index in range(528):
        nlf_index = ((state >> 0) & 1) | ((state >> 7) & 2) | ((state >> 17) & 4) | ((state >> 22) & 8) | ((state >> 26) & 16)
        bit = ((state >> 31) ^ (state >> 15) ^ (key >> ((15 - round_index) & 63)) ^ (KEELOQ_NLF >> nlf_index)) & 1
        state = ((state << 1) | bit) & 0xFFFFFFFF
    return state


def parse_keeloq_plaintext(value: int) -> dict[str, Any]:
    if not 0 <= value <= 0xFFFFFFFF:
        raise AutomotiveParseError("KeeLoq plaintext must be 32 bits")
    return {"counter": value & 0xFFFF, "discrimination": (value >> 16) & 0x3FF,
            "function": (value >> 26) & 0xF, "overflow": (value >> 30) & 3, "raw": f"{value:08x}"}


def analyze_rolling_codes(
    records: Iterable[dict[str, Any]], *, counter_bits: int = 16,
    forward_window: int = 16, resync_window: int = 32_768,
) -> dict[str, Any]:
    """Analyze supplied keyless sequences for replay, rollback, clone, and window anomalies."""
    if not 4 <= counter_bits <= 32:
        raise AutomotiveParseError("rolling counter width must be 4..32 bits")
    modulus = 1 << counter_bits
    if not 0 < forward_window < resync_window < modulus:
        raise AutomotiveParseError("rolling-code windows must be ordered within the modulus")
    rows = []
    for index, source in enumerate(records):
        if index >= MAX_FRAMES or not isinstance(source, dict):
            raise AutomotiveParseError("invalid or excessive rolling-code records")
        if "serial" not in source:
            raise AutomotiveParseError("rolling-code record lacks serial")
        row = dict(source)
        row["_index"] = index
        row["serial"] = str(row["serial"])
        row["button"] = str(row.get("button", "*"))
        if "counter" in row:
            row["counter"] = int(row["counter"])
            if not 0 <= row["counter"] < modulus:
                raise AutomotiveParseError("rolling counter exceeds configured width")
        if "hopping_code" in row:
            row["hopping_code"] = _integer_code(row["hopping_code"], "hopping code")
            if not 0 <= row["hopping_code"] <= 0xFFFFFFFFFFFFFFFF:
                raise AutomotiveParseError("hopping code exceeds 64 bits")
        rows.append(row)
    findings, groups = [], {}
    seen_codes: dict[tuple[str, int], dict[str, Any]] = {}
    for row in rows:
        if "hopping_code" in row:
            code_key = row["serial"], row["hopping_code"]
            previous = seen_codes.get(code_key)
            if previous is not None:
                findings.append({"kind": "replayed-hopping-code", "severity": "high", "serial": row["serial"],
                                 "first_index": previous["_index"], "second_index": row["_index"],
                                 "hopping_code": row["hopping_code"]})
                if previous.get("button") != row.get("button") or previous.get("counter") != row.get("counter"):
                    findings.append({"kind": "code-field-collision", "severity": "high", "serial": row["serial"],
                                     "indices": [previous["_index"], row["_index"]]})
            else:
                seen_codes[code_key] = row
        groups.setdefault((row["serial"], row["button"]), []).append(row)
    sequences = []
    for (serial, button), group in sorted(groups.items()):
        counters = [row for row in group if "counter" in row]
        deltas = []
        for previous, current in zip(counters, counters[1:]):
            delta = (current["counter"] - previous["counter"]) % modulus
            deltas.append(delta)
            if delta == 0:
                findings.append({"kind": "duplicate-counter", "severity": "high", "serial": serial, "button": button,
                                 "indices": [previous["_index"], current["_index"]], "counter": current["counter"]})
            elif delta > modulus // 2:
                findings.append({"kind": "counter-rollback", "severity": "high", "serial": serial, "button": button,
                                 "from": previous["counter"], "to": current["counter"], "indices": [previous["_index"], current["_index"]]})
            elif delta > resync_window:
                findings.append({"kind": "outside-resync-window", "severity": "high", "serial": serial,
                                 "button": button, "delta": delta, "index": current["_index"]})
            elif delta > forward_window:
                findings.append({"kind": "resynchronization-gap", "severity": "medium", "serial": serial,
                                 "button": button, "delta": delta, "index": current["_index"]})
        codes = {row.get("hopping_code") for row in group if "hopping_code" in row}
        fixed = len(codes) == 1 and len(group) > 1
        if fixed:
            findings.append({"kind": "fixed-code-behavior", "severity": "medium", "serial": serial,
                             "button": button, "observations": len(group)})
        sequences.append({"serial": serial, "button": button, "observations": len(group),
                          "counters": [row["counter"] for row in counters], "deltas": deltas,
                          "fixed_code": fixed})
    return {"record_count": len(rows), "sequences": sequences, "findings": findings}


def analyze_keeloq_frames(records: Iterable[dict[str, Any]], key: int) -> dict[str, Any]:
    decoded = []
    for index, source in enumerate(records):
        if not isinstance(source, dict) or "hopping_code" not in source:
            raise AutomotiveParseError("KeeLoq record lacks hopping_code")
        cipher = _integer_code(source["hopping_code"], "KeeLoq hopping code")
        plain = keeloq_decrypt(cipher, key)
        row = {**source, **parse_keeloq_plaintext(plain), "hopping_code": cipher, "index": index}
        decoded.append(row)
    analysis = analyze_rolling_codes(decoded)
    return {"decoded": decoded, "sequence_analysis": analysis}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="offline automotive capture analyzer")
    parser.add_argument("mode", choices=("candump", "isotp", "uds", "j1939", "rolling"))
    parser.add_argument("artifact")
    parser.add_argument("--request-id", type=lambda value: int(value, 0), action="append")
    parser.add_argument("--response-id", type=lambda value: int(value, 0), action="append")
    args = parser.parse_args(argv)
    try:
        raw = Path(args.artifact).read_bytes()
        if len(raw) > MAX_INPUT:
            raise AutomotiveParseError("artifact exceeds cap")
        if args.mode == "rolling":
            result: Any = analyze_rolling_codes(json.loads(raw.decode("utf-8")))
        else:
            frames = parse_candump(raw)
            if args.mode == "candump": result = frames
            elif args.mode == "isotp": result = reassemble_isotp(frames)
            elif args.mode == "uds": result = analyze_uds(frames, request_ids=args.request_id or [0x7E0], response_ids=args.response_id or [0x7E8])
            else: result = reassemble_j1939_tp(frames)
        print(json.dumps(result, indent=2, sort_keys=True, default=lambda value: value.hex() if isinstance(value, bytes) else str(value)))
        return 0
    except (OSError, UnicodeError, json.JSONDecodeError, AutomotiveParseError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
