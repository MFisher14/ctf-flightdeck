#!/usr/bin/env python3
"""Bounded, offline TriStation/UDP forensic decoder and program carver.

TriStation is the proprietary UDP/1502 protocol used by Triconex safety
controllers.  The framing implemented here follows the reverse-engineered
layouts published by Mandiant and Nozomi Networks.  The threat context follows
CISA MAR-17-352-01 and Dragos's TRISIS research.

This module is deliberately evidence-only.  It reads supplied bytes or packet
captures, never opens a socket, never constructs traffic, and never executes a
carved controller program.  A command-29 observation is contextual evidence,
not an attribution verdict: public sources disagree because 29 is both shown
as ``Get MP status`` in recovered command tables and described by Dragos as the
jump-table slot repurposed by the TRISIS implant.

Malformed public inputs raise only :class:`TriStationError`.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import stat
import sys
import zlib
from collections import Counter, defaultdict
from functools import wraps
from pathlib import Path
from typing import Any, Callable, TypeVar

try:
    from .ics_capture import extract_transports
except ImportError:  # direct execution / flat solver sys.path
    from ics_capture import extract_transports


TRISTATION_PORT = 1502
MAX_DATAGRAM = 65_535
MAX_CAPTURE = 64 * 1024 * 1024
MAX_FRAMES = 200_000
MAX_PROGRAM = 32 * 1024 * 1024
MAX_TEXT_FIELD = 255

MANDIANT_URL = (
    "https://cloud.google.com/blog/topics/threat-intelligence/"
    "totally-tubular-treatise-triton-and-tristation"
)
CISA_URL = (
    "https://www.cisa.gov/sites/default/files/documents/"
    "MAR-17-352-01%20HatMan%20-%20Safety%20System%20Targeted%20Malware%20"
    "%28Update%20B%29.pdf"
)
DRAGOS_URL = (
    "https://www.dragos.com/blog/industry-news/"
    "trisis-takeaways-defensive-techniques-and-trench-building-for-the-blue-team/"
)
NOZOMI_URL = "https://github.com/NozomiNetworks/tricotools/blob/master/TriStation.lua"
MIDNIGHT_BLUE_URL = "https://www.midnightblue.nl/blog/analyzing-the-triton-industrial-malware"


class TriStationError(ValueError):
    """Malformed, unsupported, ambiguous, or out-of-bounds supplied evidence."""


_F = TypeVar("_F", bound=Callable[..., Any])


def _guard(function: _F) -> _F:
    """Normalize ordinary implementation/library failures to the public error."""

    @wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except TriStationError:
            raise
        except Exception as exc:
            raise TriStationError("malformed or unsupported TriStation evidence") from exc

    return wrapped  # type: ignore[return-value]


TCM_TYPES: dict[int, str] = {
    1: "connection_request",
    2: "connection_response",
    # Mandiant and the Nozomi dissector reverse the request/reply labels for
    # values 3 and 4, so neutral names avoid asserting an uncertain direction.
    3: "disconnect_type_3",
    4: "disconnect_type_4",
    5: "execution_command",
    6: "ping",
    7: "connection_limit_reached",
    8: "not_connected",
    9: "main_processors_dead",
    10: "access_denied",
    11: "connection_failed",
}

# Function-code strings recovered from the public TS_cnames table.  The
# program-changing and matching response codes are intentionally complete;
# unlisted codes remain numeric rather than being guessed.
TS_COMMANDS: dict[int, str] = {
    0: "Start download all",
    1: "Start download change",
    2: "Update configuration",
    3: "Upload configuration",
    4: "Set I/O addresses",
    5: "Allocate network",
    6: "Load vector table",
    7: "Set calendar",
    8: "Get calendar",
    9: "Set scan time",
    10: "End download all",
    11: "End download change",
    12: "Cancel download change",
    13: "Attach TRICON",
    14: "Set I/O address limits",
    15: "Configure module",
    16: "Set multiple point values",
    17: "Enable all points",
    18: "Upload vector table",
    19: "Get CP status",
    20: "Run program",
    21: "Halt program",
    22: "Pause program",
    23: "Do single scan",
    24: "Get chassis status",
    25: "Get minimum scan time",
    26: "Set node number",
    27: "Set I/O point values",
    28: "Get I/O point values",
    29: "Get MP status",
    30: "Set retentive values",
    31: "Adjust clock calendar",
    32: "Clear module alarms",
    33: "Get event log",
    34: "Set SOE block",
    35: "Record event log",
    36: "Get SOE data",
    37: "Enable OVD",
    38: "Disable OVD",
    39: "Enable all OVDs",
    40: "Disable all OVDs",
    41: "Process MODBUS",
    42: "Upload network",
    43: "Set label",
    44: "Configure system variables",
    45: "Deconfigure module",
    46: "Get system variables",
    47: "Get module types",
    48: "Begin conversion table download",
    49: "Continue conversion table download",
    50: "End conversion table download",
    51: "Get conversion table",
    52: "Set ICM status",
    53: "Broadcast SOE data available",
    54: "Get module versions",
    55: "Allocate program",
    56: "Allocate function",
    57: "Clear retentives",
    58: "Set initial values",
    59: "Start TS2 program download",
    60: "Set TS2 data area",
    61: "Get TS2 data",
    62: "Set TS2 data",
    63: "Set program information",
    64: "Get program information",
    65: "Upload program",
    66: "Upload function",
    67: "Get point groups",
    68: "Allocate symbol table",
    69: "Get I/O address",
    70: "Resend I/O address",
    71: "Get program timing",
    72: "Allocate multiple functions",
    73: "Get node number",
    74: "Get symbol table",
    80: "Go to DOWNLOAD mode",
    100: "Command rejected",
    101: "Download all permitted",
    102: "Download change permitted",
    103: "Modification accepted",
    104: "Download cancelled",
    105: "Program accepted",
    106: "TRICON attached",
    108: "Get CP status response",
    109: "Program is running",
    110: "Program is halted",
    111: "Program is paused",
    112: "End of single scan",
    113: "Get chassis configuration response",
    114: "Scan period modified",
    119: "Get chassis status response",
    127: "Get MP status response",
    153: "Allocate program response",
    154: "Allocate function response",
    157: "Set TS2 data area response",
    158: "Get TS2 data response",
    159: "Set TS2 data response",
    160: "Set program information response",
    161: "Get program information response",
    162: "Upload program response",
    163: "Upload function response",
    165: "Allocate symbol table response",
    168: "Allocate multiple functions response",
    200: "Wrong command",
    201: "Load is in progress",
    203: "Control program not halted",
    204: "Control program checksum error",
    205: "No memory available",
    206: "Control program not valid",
    207: "Not loading a control program",
    209: "Not enough arguments",
    211: "Download time mismatch",
    212: "Key setting prohibits this operation",
    213: "Bad control program version",
    214: "Command not in correct sequence",
    223: "Program name is invalid",
    233: "Load is busy",
    241: "Command not allowed",
    242: "Invalid sequence number",
    244: "No free TriStation ports",
    246: "Invalid TriStation 1131 command",
    252: "Invalid length",
    255: "LOADER_CONNECT",
}

PROGRAM_ACTIVITY: dict[int, str] = {
    0: "start-download-all",
    1: "start-download-change",
    2: "update-configuration",
    10: "end-download-all",
    11: "end-download-change",
    12: "cancel-download-change",
    20: "run-program",
    21: "halt-program",
    22: "pause-program",
    55: "allocate-program-data",
    56: "allocate-function-data",
    59: "start-ts2-program-download",
    60: "set-ts2-data-area",
    62: "set-ts2-data",
    63: "set-program-information",
    68: "allocate-symbol-table",
    72: "allocate-multiple-functions",
    80: "enter-download-mode",
}

# Nozomi's published passive dissector compares the first final-trailer word
# with CRC32(program) XOR this constant.  A match is an IOC relationship, not
# proof of attribution or successful compromise.
NOZOMI_TRITON_XOR = 2_068_988_371
HATMAN_SUBCOMMANDS = {
    0x17: "read-memory",
    0x41: "write-memory",
    0xF9: "execute-address",
}


def _blob(data: Any, maximum: int, what: str) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TriStationError(f"{what} must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size == 0:
            raise TriStationError(f"{what} is empty")
        if size > maximum:
            raise TriStationError(f"{what} exceeds the {maximum}-byte limit")
        value = bytes(data)
    except TriStationError:
        raise
    except Exception as exc:
        raise TriStationError(f"invalid {what} buffer") from exc
    if len(value) != size:
        raise TriStationError(f"unstable {what} buffer")
    return value


def _port(value: Any, name: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 65_535:
        raise TriStationError(f"{name} must be a 16-bit integer or None")
    return value


def _text(value: Any, name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > MAX_TEXT_FIELD or "\x00" in value:
        raise TriStationError(f"{name} must be short non-NUL text or None")
    return value


def _program_chunk(payload: bytes) -> dict[str, Any]:
    """Decode the command-55 body documented by Nozomi's dissector."""
    if len(payload) < 10:
        raise TriStationError("truncated Allocate program body")
    program_id = int.from_bytes(payload[0:2], "little")
    next_id = int.from_bytes(payload[2:4], "little")
    total_blocks = int.from_bytes(payload[4:6], "little")
    block_offset = int.from_bytes(payload[6:8], "little")
    block_count = int.from_bytes(payload[8:10], "little")
    if total_blocks == 0 or block_count == 0:
        raise TriStationError("Allocate program has a zero block count")
    if total_blocks * 4 > MAX_PROGRAM + 8:
        raise TriStationError("declared program exceeds carving limit")
    if block_offset > total_blocks or block_count > total_blocks - block_offset:
        raise TriStationError("Allocate program block range exceeds declared total")
    data_size = block_count * 4
    if len(payload) != 10 + data_size:
        raise TriStationError("Allocate program block count does not consume its body")
    block_data = payload[10:]
    final = block_offset + block_count == total_blocks
    if final and len(block_data) < 8:
        raise TriStationError("final Allocate program chunk lacks its 8-byte trailer")
    fragment = block_data[:-8] if final else block_data
    result: dict[str, Any] = {
        "program_id": program_id,
        "next_id": next_id,
        "total_blocks": total_blocks,
        "block_offset": block_offset,
        "block_count": block_count,
        "block_offset_bytes": block_offset * 4,
        "final": final,
        "program_fragment_hex": fragment.hex(),
        "program_fragment_size": len(fragment),
    }
    if final:
        result["signature_word_little"] = int.from_bytes(block_data[-8:-4], "little")
        result["signature_word_hex"] = block_data[-8:-4].hex()
        # The published dissector reads the signature word little-endian but
        # renders the following CRC32 word in network (big-endian) order.
        result["crc32_word_big"] = int.from_bytes(block_data[-4:], "big")
        result["crc32_word_hex"] = block_data[-4:].hex()
    return result


def _ts2_download(payload: bytes) -> dict[str, Any]:
    """Decode the fixed command-59 metadata fields published by Nozomi."""
    if len(payload) < 26:
        raise TriStationError("truncated Start TS2 program download body")
    project_raw = payload[10:20]
    project = project_raw.split(b"\x00", 1)[0].decode("ascii", "replace")
    return {
        "unknown_prefix_hex": payload[0:6].hex(),
        "timestamp_raw_little": int.from_bytes(payload[6:10], "little"),
        "project_raw_hex": project_raw.hex(),
        "project": project,
        "function_count": int.from_bytes(payload[20:22], "little"),
        "program_count": int.from_bytes(payload[22:24], "little"),
        "unknown_suffix_hex": payload[24:26].hex(),
        "trailing_hex": payload[26:].hex(),
    }


def _parse_datagram(
    data: bytes,
    *,
    source_port: int | None,
    destination_port: int | None,
) -> dict[str, Any]:
    if len(data) < 6:
        raise TriStationError("truncated TCM header or trailer")
    message_type, channel = data[0], data[1]
    body_length = int.from_bytes(data[2:4], "little")
    if len(data) != 4 + body_length + 2:
        raise TriStationError("TCM length does not consume the complete datagram")
    standard_port = None
    if source_port is not None or destination_port is not None:
        standard_port = TRISTATION_PORT in (source_port, destination_port)
    report: dict[str, Any] = {
        "protocol": "tristation",
        "source_port": source_port,
        "destination_port": destination_port,
        "standard_port_1502": standard_port,
        "tcm": {
            "message_type": message_type,
            "message_type_name": TCM_TYPES.get(message_type, "unknown"),
            "channel": channel,
            "body_length": body_length,
            "trailer_hex": data[-2:].hex(),
            "trailer_interpretation": "published as CRC-16; algorithm not verified",
            "trailer_verified": False,
        },
        "evidence": [],
    }
    if message_type in (3, 4):
        report["tcm"]["label_note"] = (
            "Mandiant and Nozomi reverse the request/reply labels for message types 3 and 4"
        )
    body = data[4:-2]
    if message_type != 5:
        report["tcm_payload_hex"] = body.hex()
        return report
    if body_length < 10:
        raise TriStationError("truncated execution-command header")
    direction, cid, command, sequence = body[0:4]
    if direction not in (0, 1):
        direction_name = "unknown"
    else:
        direction_name = "workstation_to_controller" if direction == 0 else "controller_to_workstation"
    declared_length = int.from_bytes(body[8:10], "little")
    if declared_length != body_length:
        raise TriStationError("TS length disagrees with the TCM body length")
    payload = body[10:]
    ts: dict[str, Any] = {
        "direction": direction,
        "direction_name": direction_name,
        "controller_id": cid,
        "command": command,
        "command_name": TS_COMMANDS.get(command, "Unknown TS command"),
        "sequence": sequence,
        "unknown_word_hex": body[4:6].hex(),
        "checksum_word_hex": body[6:8].hex(),
        "declared_length": declared_length,
        "payload_length": len(payload),
        "payload_hex": payload.hex(),
    }
    report["ts"] = ts
    if command in PROGRAM_ACTIVITY:
        report["evidence"].append(
            {
                "kind": "program-activity-command",
                "action": PROGRAM_ACTIVITY[command],
                "confidence": "protocol-semantic",
                "assessment": "Program activity is not by itself malicious.",
            }
        )
    if command == 29:
        command29_evidence: dict[str, Any] = {
            "kind": "trisis-command-29-context",
            "confidence": "contextual-only",
            "assessment": (
                "Dragos documented command 29 as the TRISIS-added implant command, while the "
                "recovered normal command table labels 29 'Get MP status'; observation alone is "
                "not proof of infection, exploitation, or attribution."
            ),
            "reference": DRAGOS_URL,
        }
        if len(payload) >= 2:
            subcommand, mp = payload[0], payload[1]
            known_subcommand = HATMAN_SUBCOMMANDS.get(subcommand)
            ts["command29_body"] = {
                "subcommand": subcommand,
                "subcommand_name": known_subcommand or "unrecognized",
                "mp": mp,
                "argument_hex": payload[2:].hex(),
                "documented_implant_shape": known_subcommand is not None,
                "executed": False,
            }
            if known_subcommand is not None:
                command29_evidence.update(
                    documented_body_shape=True,
                    implant_subcommand=known_subcommand,
                    body_reference=MIDNIGHT_BLUE_URL,
                    assessment=(
                        "Command 29 has the published [subcommand][MP][arguments] implant shape; "
                        "this remains passive IOC evidence, not proof of infection, successful "
                        "execution, or attribution."
                    ),
                )
        report["evidence"].append(command29_evidence)
    if command == 55:
        ts["program_chunk"] = _program_chunk(payload)
    elif command == 59:
        ts["download_metadata"] = _ts2_download(payload)
    return report


@_guard
def parse_datagram(
    data: bytes | bytearray | memoryview,
    *,
    source_port: int | None = None,
    destination_port: int | None = None,
) -> dict[str, Any]:
    """Decode one complete TriStation UDP payload (without the UDP header)."""
    blob = _blob(data, MAX_DATAGRAM, "datagram")
    source_port = _port(source_port, "source_port")
    destination_port = _port(destination_port, "destination_port")
    return _parse_datagram(blob, source_port=source_port, destination_port=destination_port)


def _endpoint(address: str | None, port: int | None) -> tuple[str, int]:
    return address or "?", port if port is not None else -1


def _flow_key(record: dict[str, Any]) -> tuple[tuple[str, int], tuple[str, int]]:
    endpoints = sorted(
        (_endpoint(record.get("source"), record.get("source_port")),
         _endpoint(record.get("destination"), record.get("destination_port")))
    )
    return endpoints[0], endpoints[1]


def _session_label(key: tuple[Any, ...]) -> str:
    left, right, channel = key
    left_port = "?" if left[1] < 0 else str(left[1])
    right_port = "?" if right[1] < 0 else str(right[1])
    return f"{left[0]}:{left_port}<->{right[0]}:{right_port}|channel={channel}"


def _carve_programs(frames: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[tuple[Any, ...], list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    generation: dict[tuple[Any, ...], int] = defaultdict(int)
    active: dict[tuple[Any, ...], int] = {}
    active_members: dict[tuple[Any, ...], list[tuple[Any, dict[str, Any]]]] = {}
    for frame_index, frame in enumerate(frames):
        ts = frame.get("ts")
        if not isinstance(ts, dict) or not isinstance(ts.get("program_chunk"), dict):
            continue
        chunk = ts["program_chunk"]
        sequence = ts.get("sequence")
        flow = _flow_key(frame)
        base = (
            flow,
            frame["tcm"]["channel"],
            ts["controller_id"],
            chunk["program_id"],
            ts["direction"],
        )
        # A byte-identical, same-sequence command-55 datagram is a benign
        # retransmission of a frame already in the active transfer, not a new
        # transfer: fold it into the current carving (the offset de-dup below
        # collapses it) instead of starting a spurious one.
        retransmission = base in active and (sequence, chunk) in active_members.get(base, ())
        # A program slot may be overwritten more than once in one capture (the
        # CISA-described cleanup does exactly this).  A new offset-zero chunk
        # starts a distinct transfer instead of corrupting the prior carving.
        if (chunk["block_offset"] == 0 or base not in active) and not retransmission:
            generation[base] += 1
            active[base] = generation[base]
            active_members[base] = []
        key = (*base, active[base])
        groups[key].append((frame_index, chunk))
        active_members.setdefault(base, []).append((sequence, chunk))
        if chunk["final"]:
            active.pop(base, None)
            active_members.pop(base, None)

    carvings: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    for key in sorted(groups, key=lambda item: repr(item)):
        rows = sorted(groups[key], key=lambda item: (item[1]["block_offset"], item[0]))
        totals = {row[1]["total_blocks"] for row in rows}
        program_id = key[3]
        transfer_index = key[5]
        frame_indices = [row[0] for row in rows]
        reasons: list[str] = []
        if len(totals) != 1:
            reasons.append("inconsistent declared total_blocks")
            total_blocks = max(totals)
        else:
            total_blocks = next(iter(totals))
        unique: list[tuple[int, dict[str, Any]]] = []
        offsets: dict[int, dict[str, Any]] = {}
        for frame_index, chunk in rows:
            prior = offsets.get(chunk["block_offset"])
            if prior is None:
                offsets[chunk["block_offset"]] = chunk
                unique.append((frame_index, chunk))
            elif prior != chunk:
                reasons.append(f"conflicting chunks at block offset {chunk['block_offset']}")
        expected = 0
        fragments: list[bytes] = []
        final_chunks: list[dict[str, Any]] = []
        for _, chunk in unique:
            if chunk["block_offset"] != expected:
                reasons.append(
                    f"block gap/reorder: expected offset {expected}, saw {chunk['block_offset']}"
                )
                expected = chunk["block_offset"]
            fragment = bytes.fromhex(chunk["program_fragment_hex"])
            fragments.append(fragment)
            expected = chunk["block_offset"] + chunk["block_count"]
            if chunk["final"]:
                final_chunks.append(chunk)
        if len(final_chunks) != 1:
            reasons.append("transfer does not have exactly one final chunk")
        if expected != total_blocks:
            reasons.append(f"transfer ends at block {expected}, declared {total_blocks}")
        program = b"".join(fragments)
        if len(program) > MAX_PROGRAM:
            reasons.append("reassembled program exceeds carving limit")
        complete = not reasons
        carving: dict[str, Any] = {
            "program_id": program_id,
            "transfer_index": transfer_index,
            "controller_id": key[2],
            "channel": key[1],
            "total_blocks": total_blocks,
            "frame_indices": frame_indices,
            "complete": complete,
            "incomplete_reasons": reasons,
            "program_size": len(program),
            "program_sha256": hashlib.sha256(program).hexdigest(),
            "program_hex": program.hex(),
            "executed": False,
        }
        if final_chunks:
            final = final_chunks[-1]
            crc32 = zlib.crc32(program) & 0xFFFF_FFFF
            signature = final["signature_word_little"]
            trailer_crc = final["crc32_word_big"]
            signature_relation = signature == (crc32 ^ NOZOMI_TRITON_XOR)
            carving.update(
                crc32_computed=crc32,
                crc32_trailer_big=trailer_crc,
                crc32_matches=trailer_crc == crc32,
                signature_word_little=signature,
                nozomi_triton_signature_relation=signature_relation,
                indicator_assessment=(
                    "Published Nozomi XOR signature relation matched; this is an IOC relationship, "
                    "not proof of compromise or attribution."
                    if signature_relation
                    else "Published Nozomi XOR signature relation did not match."
                ),
            )
        carvings.append(carving)
        if reasons:
            findings.append(
                {
                    "kind": "incomplete-program-transfer",
                    "severity": "warning",
                    "program_id": program_id,
                    "frame_indices": frame_indices,
                    "detail": "; ".join(reasons),
                }
            )
    return carvings, findings


def _analyse_frames(
    frames: list[dict[str, Any]],
    *,
    input_format: str,
    packet_count: int,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    sessions: dict[tuple[Any, ...], dict[str, Any]] = {}
    pending: dict[tuple[Any, ...], list[int]] = defaultdict(list)
    transactions: list[dict[str, Any]] = []
    command29_count = program_activity_count = 0
    for frame_index, frame in enumerate(frames):
        flow = _flow_key(frame)
        channel = frame["tcm"]["channel"]
        session_key = (flow[0], flow[1], channel)
        session = sessions.setdefault(
            session_key,
            {
                "session_id": _session_label(session_key),
                "channel": channel,
                "frame_indices": [],
                "controller_ids": set(),
                "tcm_type_counts": Counter(),
                "command_counts": Counter(),
                "program_activity_count": 0,
                "command29_context_count": 0,
            },
        )
        session["frame_indices"].append(frame_index)
        session["tcm_type_counts"][str(frame["tcm"]["message_type"])] += 1
        ts = frame.get("ts")
        if not isinstance(ts, dict):
            continue
        session["controller_ids"].add(ts["controller_id"])
        session["command_counts"][str(ts["command"])] += 1
        actions = [item for item in frame["evidence"] if item["kind"] == "program-activity-command"]
        command29 = any(item["kind"] == "trisis-command-29-context" for item in frame["evidence"])
        if actions:
            session["program_activity_count"] += 1
            program_activity_count += 1
        if command29:
            session["command29_context_count"] += 1
            command29_count += 1
        transaction_key = (session_key, ts["controller_id"], ts["sequence"])
        if ts["direction"] == 0:
            pending[transaction_key].append(frame_index)
        elif ts["direction"] == 1 and pending.get(transaction_key):
            request_index = pending[transaction_key].pop(0)
            transactions.append(
                {
                    "request_frame": request_index,
                    "response_frame": frame_index,
                    "controller_id": ts["controller_id"],
                    "sequence": ts["sequence"],
                    "request_command": frames[request_index]["ts"]["command"],
                    "response_command": ts["command"],
                }
            )

    session_rows: list[dict[str, Any]] = []
    for key in sorted(sessions, key=_session_label):
        row = sessions[key]
        row["controller_ids"] = sorted(row["controller_ids"])
        row["tcm_type_counts"] = dict(sorted(row["tcm_type_counts"].items(), key=lambda item: int(item[0])))
        row["command_counts"] = dict(sorted(row["command_counts"].items(), key=lambda item: int(item[0])))
        session_rows.append(row)
    orphan_requests = sorted(index for indices in pending.values() for index in indices)
    carvings, carve_findings = _carve_programs(frames)
    findings.extend(carve_findings)
    return {
        "format": input_format,
        "packet_count": packet_count,
        "tristation_frame_count": len(frames),
        "frames": frames,
        "sessions": session_rows,
        "transactions": transactions,
        "orphan_request_frames": orphan_requests,
        "program_carvings": carvings,
        "findings": findings,
        "summary": {
            "session_count": len(session_rows),
            "transaction_count": len(transactions),
            "program_activity_frame_count": program_activity_count,
            "command29_context_count": command29_count,
            "complete_program_carving_count": sum(row["complete"] for row in carvings),
        },
        "assessment": (
            "Passive protocol evidence only; no finding establishes compromise, successful "
            "controller manipulation, or attribution. Carved bytes were never executed."
        ),
        "references": {
            "mandiant_packet_layout": MANDIANT_URL,
            "nozomi_dissector_layout": NOZOMI_URL,
            "cisa_hatman_mar": CISA_URL,
            "dragos_command29_context": DRAGOS_URL,
            "midnight_blue_command29_body": MIDNIGHT_BLUE_URL,
        },
    }


def _record_value(record: dict[str, Any], index: int) -> dict[str, Any]:
    allowed = {
        "data", "source", "destination", "source_port", "destination_port",
        "timestamp", "packet_index",
    }
    if set(record) - allowed:
        raise TriStationError("datagram record contains unsupported fields")
    if "data" not in record:
        raise TriStationError("datagram record lacks data")
    source = _text(record.get("source"), "source")
    destination = _text(record.get("destination"), "destination")
    source_port = _port(record.get("source_port"), "source_port")
    destination_port = _port(record.get("destination_port"), "destination_port")
    timestamp = record.get("timestamp")
    if timestamp is not None and (
        isinstance(timestamp, bool)
        or not isinstance(timestamp, (int, float))
        or not math.isfinite(timestamp)
    ):
        raise TriStationError("timestamp must be a finite number or None")
    packet_index = record.get("packet_index", index)
    if type(packet_index) is not int or packet_index < 0:
        raise TriStationError("packet_index must be a non-negative integer")
    frame = parse_datagram(
        record["data"], source_port=source_port, destination_port=destination_port
    )
    frame.update(
        source=source,
        destination=destination,
        timestamp=timestamp,
        packet_index=packet_index,
    )
    return frame


@_guard
def analyze_datagrams(records: list[dict[str, Any]] | tuple[dict[str, Any], ...]) -> dict[str, Any]:
    """Correlate supplied raw datagrams and carve complete command-55 programs."""
    if not isinstance(records, (list, tuple)):
        raise TriStationError("records must be a list or tuple")
    if not records:
        raise TriStationError("records are empty")
    if len(records) > MAX_FRAMES:
        raise TriStationError("datagram count exceeds limit")
    frames: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise TriStationError("each datagram record must be a dictionary")
        frames.append(_record_value(record, index))
    return _analyse_frames(
        frames, input_format="datagrams", packet_count=len(records), findings=[]
    )


@_guard
def analyze_capture(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Extract and analyze UDP/1502 datagrams from a classic PCAP or PCAPNG."""
    blob = _blob(data, MAX_CAPTURE, "capture")
    packets, capture_findings, packet_count = extract_transports(blob, include_count=True)
    frames: list[dict[str, Any]] = []
    findings = [dict(row) for row in capture_findings]
    for packet in packets:
        if packet.get("transport") != "udp":
            continue
        source_port = packet.get("source_port")
        destination_port = packet.get("destination_port")
        if TRISTATION_PORT not in (source_port, destination_port):
            continue
        if len(frames) >= MAX_FRAMES:
            raise TriStationError("TriStation frame count exceeds limit")
        try:
            frame = parse_datagram(
                packet.get("payload"),
                source_port=source_port,
                destination_port=destination_port,
            )
        except TriStationError as exc:
            findings.append(
                {
                    "kind": "malformed-tristation-datagram",
                    "severity": "warning",
                    "packet_index": packet.get("packet_index"),
                    "detail": str(exc),
                }
            )
            continue
        frame.update(
            source=packet.get("source"),
            destination=packet.get("destination"),
            timestamp=packet.get("timestamp"),
            packet_index=packet.get("packet_index"),
        )
        frames.append(frame)
    capture_format = "pcapng" if blob.startswith(b"\x0a\x0d\x0d\x0a") else "pcap"
    return _analyse_frames(
        frames,
        input_format=capture_format,
        packet_count=packet_count,
        findings=findings,
    )


@_guard
def analyze_bytes(
    data: bytes | bytearray | memoryview,
    *,
    input_format: str = "auto",
    source_port: int | None = None,
    destination_port: int | None = None,
) -> dict[str, Any]:
    """Analyze either a raw TriStation datagram or a PCAP/PCAPNG byte stream."""
    if input_format not in ("auto", "raw", "capture"):
        raise TriStationError("input_format must be auto, raw, or capture")
    blob = _blob(data, MAX_CAPTURE, "input")
    capture_magic = blob[:4] in {
        b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    }
    selected = "capture" if input_format == "auto" and capture_magic else input_format
    if selected == "auto":
        selected = "raw"
    if selected == "capture":
        if source_port is not None or destination_port is not None:
            raise TriStationError("capture flow ports come from packet headers")
        return analyze_capture(blob)
    source_port = _port(source_port, "source_port")
    destination_port = _port(destination_port, "destination_port")
    result = analyze_datagrams(
        [{
            "data": blob,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_index": 0,
        }]
    )
    result["format"] = "raw"
    return result


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint: print JSON for a supplied raw datagram or packet capture."""
    if argv is not None and (
        not isinstance(argv, (list, tuple)) or any(not isinstance(item, str) for item in argv)
    ):
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--format", choices=("auto", "raw", "capture"), default="auto")
    parser.add_argument("--source-port", type=int)
    parser.add_argument("--destination-port", type=int)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if not stat.S_ISREG(args.artifact.stat().st_mode):
            raise TriStationError("artifact must be a regular file")
        with args.artifact.open("rb") as stream:
            data = stream.read(MAX_CAPTURE + 1)
        result = analyze_bytes(
            data,
            input_format=args.format,
            source_port=args.source_port,
            destination_port=args.destination_port,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, TriStationError) as exc:
        print(f"ot_tristation_wire: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
