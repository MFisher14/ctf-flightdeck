#!/usr/bin/env python3
"""Offline ISO-TP/UDS analysis for saved CAN traces.

The older :mod:`transport` reader already handles candump syntax, CAN/J1939
identifiers and single-frame OBD-II.  This module deliberately fills the two
stateful automotive gaps: ISO 15765-2 multi-frame reassembly (including CAN-FD
extended lengths) and ISO 14229 UDS service decoding.  It never opens a CAN
socket or sends a diagnostic request.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_FILE = 32 * 1024 * 1024
MAX_FRAMES = 1_000_000
MAX_MESSAGE = 16 * 1024 * 1024
MAX_MESSAGES = 100_000


class AutomotiveError(ValueError):
    """Malformed or over-limit offline input."""


_CANDUMP = re.compile(
    r"^\s*(?:\((?P<ts>\d+(?:\.\d+)?)\)\s*)?(?:(?P<iface>[\w.-]+)\s+)?"
    r"(?P<id>[0-9A-Fa-f]{3,8})#(?P<data>[0-9A-Fa-f]*)\s*$"
)


def parse_candump(text: str) -> list[dict[str, Any]]:
    """Parse bounded ``candump -L``/compact lines without touching SocketCAN."""
    if not isinstance(text, str) or len(text.encode("utf-8", "surrogatepass")) > MAX_FILE:
        raise AutomotiveError("candump input exceeds the file cap")
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith(("#", ";")):
            continue
        match = _CANDUMP.fullmatch(line)
        if match is None:
            # Also accept ``can0 123 [8] 01 02 ...``.
            parts = line.split()
            try:
                bracket = next(i for i, part in enumerate(parts) if re.fullmatch(r"\[\d+\]", part))
                can_id = int(parts[bracket - 1], 16)
                raw = bytes.fromhex("".join(parts[bracket + 1:]))
            except (StopIteration, ValueError, IndexError):
                raise AutomotiveError(f"line {line_no}: unsupported candump syntax") from None
            declared = int(parts[bracket][1:-1])
            if declared != len(raw):
                raise AutomotiveError(f"line {line_no}: DLC does not match payload")
            row = {"can_id": can_id, "data": raw, "line": line_no}
        else:
            encoded = match.group("data")
            if len(encoded) & 1:
                raise AutomotiveError(f"line {line_no}: odd-length CAN hex")
            raw = bytes.fromhex(encoded)
            row = {"can_id": int(match.group("id"), 16), "data": raw, "line": line_no}
            if match.group("ts") is not None:
                row["timestamp"] = float(match.group("ts"))
            if match.group("iface") is not None:
                row["interface"] = match.group("iface")
        if len(raw) > 64:
            raise AutomotiveError(f"line {line_no}: CAN/CAN-FD payload exceeds 64 bytes")
        rows.append(row)
        if len(rows) > MAX_FRAMES:
            raise AutomotiveError("CAN frame cap exceeded")
    return rows


def _normalise_frame(frame: Any, index: int) -> tuple[int, bytes, dict[str, Any]]:
    if isinstance(frame, dict):
        can_id, data = frame.get("can_id"), frame.get("data")
        meta = {key: value for key, value in frame.items() if key not in {"can_id", "data"}}
    elif isinstance(frame, (tuple, list)) and len(frame) >= 2:
        can_id, data = frame[0], frame[1]
        meta = {}
    else:
        raise AutomotiveError(f"frame {index}: expected mapping or (id, data)")
    if not isinstance(can_id, int) or not 0 <= can_id <= 0x1FFFFFFF:
        raise AutomotiveError(f"frame {index}: invalid CAN identifier")
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError as exc:
            raise AutomotiveError(f"frame {index}: data is not hexadecimal") from exc
    if not isinstance(data, (bytes, bytearray)) or not 1 <= len(data) <= 64:
        raise AutomotiveError(f"frame {index}: payload must contain 1..64 bytes")
    return can_id, bytes(data), meta


def reassemble_isotp(frames: Iterable[Any], *, include_incomplete: bool = True,
                     max_messages: int = MAX_MESSAGES) -> dict[str, Any]:
    """Reassemble ISO-TP independently for each CAN identifier.

    Sequence errors terminate only their affected conversation and are returned
    as structured diagnostics.  Completed payloads are emitted only when the
    advertised length is present exactly; padding bytes are never included.
    """
    if not isinstance(max_messages, int) or not 1 <= max_messages <= MAX_MESSAGES:
        raise AutomotiveError("invalid message cap")
    active: dict[int, dict[str, Any]] = {}
    messages: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    def emit_error(can_id: int, index: int, reason: str) -> None:
        errors.append({"can_id": can_id, "frame_index": index, "reason": reason})

    for index, raw_frame in enumerate(frames):
        if index >= MAX_FRAMES:
            raise AutomotiveError("CAN frame cap exceeded")
        can_id, data, meta = _normalise_frame(raw_frame, index)
        kind = data[0] >> 4
        if kind == 0:  # Single Frame; CAN-FD uses a zero nibble plus one-byte SF_DL.
            length = data[0] & 0x0F
            offset = 1
            if length == 0:
                if len(data) < 2:
                    emit_error(can_id, index, "truncated CAN-FD single-frame length")
                    continue
                length, offset = data[1], 2
            if length > len(data) - offset:
                emit_error(can_id, index, "single-frame length exceeds payload")
                continue
            if can_id in active:
                emit_error(can_id, index, "single frame replaced an unfinished transfer")
                active.pop(can_id, None)
            messages.append({"can_id": can_id, "payload": data[offset:offset + length],
                             "frame_count": 1, "first_frame_index": index,
                             "last_frame_index": index, "complete": True, **meta})
        elif kind == 1:  # First Frame, 12-bit or CAN-FD 32-bit FF_DL.
            if len(data) < 2:
                emit_error(can_id, index, "truncated first-frame length")
                continue
            length = ((data[0] & 0x0F) << 8) | data[1]
            offset = 2
            if length == 0:
                if len(data) < 6:
                    emit_error(can_id, index, "truncated 32-bit first-frame length")
                    continue
                length, offset = int.from_bytes(data[2:6], "big"), 6
            if length <= len(data) - offset or length > MAX_MESSAGE:
                emit_error(can_id, index, "invalid first-frame advertised length")
                continue
            if can_id in active:
                emit_error(can_id, index, "new first frame replaced an unfinished transfer")
            active[can_id] = {"length": length, "buffer": bytearray(data[offset:]),
                              "next_sequence": 1, "frame_count": 1,
                              "first_frame_index": index, "last_frame_index": index,
                              "meta": meta}
        elif kind == 2:  # Consecutive Frame.
            state = active.get(can_id)
            if state is None:
                emit_error(can_id, index, "orphan consecutive frame")
                continue
            sequence = data[0] & 0x0F
            if sequence != state["next_sequence"]:
                emit_error(can_id, index,
                           f"sequence mismatch: expected {state['next_sequence']}, got {sequence}")
                active.pop(can_id, None)
                continue
            state["next_sequence"] = (sequence + 1) & 0x0F
            state["buffer"].extend(data[1:])
            state["frame_count"] += 1
            state["last_frame_index"] = index
            if len(state["buffer"]) >= state["length"]:
                messages.append({"can_id": can_id,
                                 "payload": bytes(state["buffer"][:state["length"]]),
                                 "frame_count": state["frame_count"],
                                 "first_frame_index": state["first_frame_index"],
                                 "last_frame_index": index, "complete": True,
                                 **state["meta"]})
                active.pop(can_id, None)
        elif kind == 3:  # Flow Control is useful evidence but carries no application bytes.
            status = data[0] & 0x0F
            controls.append({"can_id": can_id, "frame_index": index,
                             "flow_status": {0: "continue", 1: "wait", 2: "overflow"}.get(status, "reserved"),
                             "block_size": data[1] if len(data) > 1 else None,
                             "st_min": data[2] if len(data) > 2 else None, **meta})
        else:
            emit_error(can_id, index, f"reserved ISO-TP PCI type {kind}")
        if len(messages) > max_messages:
            raise AutomotiveError("ISO-TP message cap exceeded")

    incomplete: list[dict[str, Any]] = []
    if include_incomplete:
        for can_id, state in active.items():
            incomplete.append({"can_id": can_id, "advertised_length": state["length"],
                               "captured_length": len(state["buffer"]),
                               "frame_count": state["frame_count"],
                               "first_frame_index": state["first_frame_index"],
                               "last_frame_index": state["last_frame_index"]})
    return {"messages": messages, "flow_control": controls, "errors": errors,
            "incomplete": incomplete}


_SERVICES = {
    0x10: "DiagnosticSessionControl", 0x11: "ECUReset", 0x14: "ClearDiagnosticInformation",
    0x19: "ReadDTCInformation", 0x22: "ReadDataByIdentifier", 0x23: "ReadMemoryByAddress",
    0x24: "ReadScalingDataByIdentifier", 0x27: "SecurityAccess", 0x28: "CommunicationControl",
    0x29: "Authentication", 0x2A: "ReadDataByPeriodicIdentifier", 0x2C: "DynamicallyDefineDataIdentifier",
    0x2E: "WriteDataByIdentifier", 0x2F: "InputOutputControlByIdentifier",
    0x31: "RoutineControl", 0x34: "RequestDownload", 0x35: "RequestUpload",
    0x36: "TransferData", 0x37: "RequestTransferExit", 0x38: "RequestFileTransfer",
    0x3D: "WriteMemoryByAddress", 0x3E: "TesterPresent", 0x85: "ControlDTCSetting",
}
_NRC = {
    0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported",
    0x13: "incorrectMessageLengthOrInvalidFormat", 0x14: "responseTooLong",
    0x21: "busyRepeatRequest", 0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
    0x25: "noResponseFromSubnetComponent", 0x26: "failurePreventsExecution",
    0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x35: "invalidKey",
    0x36: "exceedNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
    0x70: "uploadDownloadNotAccepted", 0x71: "transferDataSuspended",
    0x72: "generalProgrammingFailure", 0x73: "wrongBlockSequenceCounter",
    0x78: "requestCorrectlyReceivedResponsePending", 0x7E: "subFunctionNotSupportedInActiveSession",
    0x7F: "serviceNotSupportedInActiveSession", 0x81: "rpmTooHigh", 0x82: "rpmTooLow",
    0x83: "engineIsRunning", 0x84: "engineIsNotRunning", 0x92: "voltageTooHigh",
    0x93: "voltageTooLow",
}


def _dtc(raw: bytes) -> str:
    if len(raw) != 3:
        raise AutomotiveError("DTC must contain three bytes")
    family = "PCBU"[raw[0] >> 6]
    return family + f"{(raw[0] >> 4) & 3:X}{raw[0] & 0x0F:X}{raw[1]:02X}{raw[2]:02X}"


def decode_uds(payload: bytes) -> dict[str, Any] | None:
    """Decode deterministic UDS service fields from one reassembled payload."""
    if not isinstance(payload, (bytes, bytearray)) or not payload or len(payload) > MAX_MESSAGE:
        return None
    data = bytes(payload)
    sid = data[0]
    if sid == 0x7F:
        if len(data) != 3:
            return None
        requested, nrc = data[1], data[2]
        return {"kind": "negative_response", "service_id": requested,
                "service": _SERVICES.get(requested, f"service_0x{requested:02x}"),
                "negative_response_code": nrc,
                "negative_response": _NRC.get(nrc, f"nrc_0x{nrc:02x}")}
    positive = sid >= 0x40 and (sid - 0x40) in _SERVICES
    request_sid = sid - 0x40 if positive else sid
    if request_sid not in _SERVICES:
        return {"kind": "unknown", "service_id": sid, "raw": data}
    out: dict[str, Any] = {"kind": "positive_response" if positive else "request",
                           "service_id": request_sid, "wire_service_id": sid,
                           "service": _SERVICES[request_sid]}
    body = data[1:]
    if request_sid in (0x10, 0x11, 0x19, 0x27, 0x28, 0x29, 0x2A, 0x3E, 0x85) and body:
        out["subfunction"] = body[0] & 0x7F
        out["suppress_positive_response"] = bool(body[0] & 0x80) and not positive
    if request_sid in (0x22, 0x24, 0x2E, 0x2F) and len(body) >= 2:
        out["data_identifier"] = int.from_bytes(body[:2], "big")
        out["data"] = body[2:]
    elif request_sid == 0x27 and body:
        out["security_level"] = (body[0] + 1) // 2
        out["security_operation"] = "seed" if body[0] & 1 else "key"
        out["security_data"] = body[1:]
    elif request_sid == 0x31 and len(body) >= 3:
        out["routine_control_type"] = body[0] & 0x7F
        out["routine_identifier"] = int.from_bytes(body[1:3], "big")
        out["routine_data"] = body[3:]
    elif request_sid == 0x36 and body:
        out["block_sequence_counter"] = body[0]
        out["transfer_data"] = body[1:]
    elif request_sid == 0x19 and positive and len(body) >= 2:
        # Common 0x59 response layouts carry availability/status followed by
        # four-byte (DTC,status) tuples.  Keep any non-tuple tail explicit.
        start = 2 if body[0] in (1, 2, 7, 8, 9, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F) else 1
        records = []
        for at in range(start, len(body) - 3, 4):
            records.append({"dtc": _dtc(body[at:at + 3]), "status": body[at + 3]})
        if records:
            out["dtcs"] = records
            out["tail"] = body[start + 4 * len(records):]
    elif request_sid in (0x34, 0x35) and body:
        out["data_format_identifier"] = body[0]
        if len(body) >= 2:
            address_len, size_len = body[1] & 0x0F, body[1] >> 4
            if address_len and size_len and 2 + address_len + size_len <= len(body):
                out["memory_address"] = int.from_bytes(body[2:2 + address_len], "big")
                out["memory_size"] = int.from_bytes(body[2 + address_len:2 + address_len + size_len], "big")
    if "data" not in out and body and request_sid not in (0x27, 0x31, 0x36):
        out["raw_parameters"] = body
    return out


def analyze(frames: Iterable[Any]) -> dict[str, Any]:
    result = reassemble_isotp(frames)
    for message in result["messages"]:
        message["uds"] = decode_uds(message["payload"])
        message["flag_strings"] = [match.group().decode("ascii") for match in
                                   flagfmt.BYTES.finditer(message["payload"])]
    result["offline"] = True
    return result


def _json_default(value: Any):
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    raise TypeError(type(value).__name__)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised through main
        raise AutomotiveError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="automotive_depth.py")
    parser.add_argument("input", help="saved candump text")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        path = Path(args.input)
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise AutomotiveError("input is absent or exceeds the file cap")
        report = analyze(parse_candump(path.read_text("utf-8", errors="strict")))
        print(json.dumps(report, sort_keys=True, default=_json_default, indent=2 if args.json else None))
        return 0
    except Exception as exc:
        print(f"automotive_depth: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
