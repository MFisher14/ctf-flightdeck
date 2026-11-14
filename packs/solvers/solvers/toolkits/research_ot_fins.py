#!/usr/bin/env python3
"""Statically decode bounded Omron FINS/UDP and FINS/TCP artifacts.

The layouts follow Omron W342 (FINS commands) and W421 (FINS/TCP framing).
This module only parses supplied bytes: it has no sockets, discovery, replay, or
controller-operation code.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


MAX_FINS_FRAME = 2_012
MAX_UDP_FRAME = MAX_FINS_FRAME
MAX_TCP_FRAME = 8 * 1024 * 1024
MAX_STREAM = 16 * 1024 * 1024
MAX_STREAM_FRAMES = 100_000


class FINSParseError(ValueError):
    """Input is malformed, unsupported, ambiguous, or exceeds a bound."""


_COMMANDS = {
    0x0101: "memory-area-read",
    0x0102: "memory-area-write",
    0x0103: "memory-area-fill",
    0x0104: "multiple-memory-area-read",
    0x0401: "run",
    0x0402: "stop",
}

_MEMORY_AREAS = {
    0x02: "DM-bit",
    0x30: "CIO-bit",
    0x31: "WR-bit",
    0x32: "HR-bit",
    0x33: "AR-bit",
    0x82: "DM-word",
    0xB0: "CIO-word",
    0xB1: "WR-word",
    0xB2: "HR-word",
    0xB3: "AR-word",
}

_TCP_COMMANDS = {
    0: "node-address-request",
    1: "node-address-response",
    2: "fins-frame",
    3: "fins-frame-error",
    6: "connection-confirmation",
}

# W342 lists many model-specific end codes. Keep the raw bytes authoritative;
# these stable common values are labels, never a reason to discard an artifact.
_END_CODES = {
    0x0000: "normal-completion",
    0x0001: "service-canceled",
    0x0101: "local-node-not-in-network",
    0x0102: "token-timeout",
    0x0103: "retries-failed",
    0x0201: "destination-node-not-in-network",
    0x0401: "undefined-command",
    0x1001: "command-too-long",
    0x1002: "command-too-short",
    0x1101: "area-classification-missing",
    0x1103: "address-range-error",
    0x2101: "read-not-possible",
    0x2102: "write-not-possible",
    0x2201: "not-executable-in-current-mode",
}


def _blob(value: Any, *, limit: int, label: str) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise FINSParseError(f"{label} must be bytes-like")
    try:
        data = bytes(value)
    except Exception as exc:
        raise FINSParseError(f"cannot copy {label}") from exc
    if not data:
        raise FINSParseError(f"{label} is empty")
    if len(data) > limit:
        raise FINSParseError(f"{label} exceeds size limit")
    return data


def _need(data: bytes, offset: int, length: int, label: str) -> None:
    if offset < 0 or length < 0 or offset > len(data) or length > len(data) - offset:
        raise FINSParseError(f"truncated {label}")


def _u16be(data: bytes, offset: int, label: str) -> int:
    _need(data, offset, 2, label)
    return int.from_bytes(data[offset:offset + 2], "big")


def _u32be(data: bytes, offset: int, label: str) -> int:
    _need(data, offset, 4, label)
    return int.from_bytes(data[offset:offset + 4], "big")


def _memory_address(data: bytes, offset: int) -> dict[str, Any]:
    _need(data, offset, 4, "FINS memory address")
    area = data[offset]
    return {
        "area_code": area,
        "area_code_hex": f"0x{area:02x}",
        "area_name": _MEMORY_AREAS.get(area, "unknown"),
        "word": _u16be(data, offset + 1, "FINS memory word"),
        "bit": data[offset + 3],
    }


def _decode_request(command: int, body: bytes) -> dict[str, Any]:
    if command == 0x0101:
        if len(body) != 6:
            raise FINSParseError("memory-area-read request must contain 6 data bytes")
        return {
            "memory": _memory_address(body, 0),
            "item_count": _u16be(body, 4, "FINS memory item count"),
        }
    if command == 0x0102:
        if len(body) < 7:
            raise FINSParseError("memory-area-write request has no write data")
        result = {
            "memory": _memory_address(body, 0),
            "item_count": _u16be(body, 4, "FINS memory item count"),
            "write_data_hex": body[6:].hex(),
            "write_data_length": len(body) - 6,
        }
        if body[0] in {0x02, 0x30, 0x31, 0x32, 0x33}:
            width = 1
        elif body[0] in {0x82, 0xB0, 0xB1, 0xB2, 0xB3}:
            width = 2
        else:
            width = None
        if width is not None and result["write_data_length"] != result["item_count"] * width:
            raise FINSParseError("memory-area-write data length does not match area and item count")
        return result
    if command == 0x0104:
        if not body or len(body) % 4:
            raise FINSParseError("multiple-memory-area-read request must contain 4-byte addresses")
        return {
            "addresses": [_memory_address(body, offset) for offset in range(0, len(body), 4)],
            "address_count": len(body) // 4,
        }
    if command == 0x0401:
        # W342 permits omission of the default program/mode.  When present the
        # program selector is FFFF and an optional mode is 02 or 04.
        if not body:
            return {"defaults_omitted": True}
        if len(body) not in (2, 3) or body[:2] != b"\xff\xff":
            raise FINSParseError("RUN request has an invalid program selector")
        result = {"program_number": 0xFFFF}
        if len(body) == 3:
            if body[2] not in (0x02, 0x04):
                raise FINSParseError("RUN request has an invalid operating mode")
            result["operating_mode"] = body[2]
        return result
    if command == 0x0402:
        if not body:
            return {"defaults_omitted": True}
        if body != b"\xff\xff":
            raise FINSParseError("STOP request has an invalid program selector")
        return {"program_number": 0xFFFF}
    return {"data_hex": body.hex(), "data_length": len(body)}


def _decode_response(command: int, body: bytes) -> dict[str, Any]:
    _need(body, 0, 2, "FINS response end code")
    end_code = _u16be(body, 0, "FINS response end code")
    data = body[2:]
    if command in (0x0102, 0x0401, 0x0402) and end_code == 0 and data:
        raise FINSParseError("successful write/RUN/STOP response has unexpected data")
    result = {
        "end_code": end_code,
        "end_code_hex": f"0x{end_code:04x}",
        "end_code_name": _END_CODES.get(end_code, "unknown"),
        "main_response_code": body[0],
        "sub_response_code": body[1],
        "ok": end_code == 0,
        "data_hex": data.hex(),
        "data_length": len(data),
    }
    # A 0104 response's values cannot be assigned widths without its request;
    # retain the bytes instead of guessing from value bytes that may resemble
    # memory-area codes.
    return result


def _parse_fins_frame(data: bytes) -> dict[str, Any]:
    _need(data, 0, 12, "FINS frame header and command")
    icf = data[0]
    is_response = bool(icf & 0x40)
    command = _u16be(data, 10, "FINS command code")
    header = {
        "icf": icf,
        "response": is_response,
        "gateway_use": bool(icf & 0x80),
        "response_required": not bool(icf & 0x01),
        "reserved": data[1],
        "gateway_count": data[2],
        "destination": {"network": data[3], "node": data[4], "unit": data[5]},
        "source": {"network": data[6], "node": data[7], "unit": data[8]},
        "service_id": data[9],
    }
    decoded = _decode_response(command, data[12:]) if is_response else _decode_request(command, data[12:])
    return {
        "transport": "fins",
        "length": len(data),
        "direction": "response" if is_response else "command",
        "header": header,
        "command": {
            "code": command,
            "code_hex": f"0x{command:04x}",
            "name": _COMMANDS.get(command, "unknown"),
        },
        "body": decoded,
    }


def parse_fins_frame(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one FINS frame (the payload used directly by FINS/UDP).

    Every ordinary failure is normalized to :class:`FINSParseError`.
    """
    try:
        return _parse_fins_frame(_blob(data, limit=MAX_UDP_FRAME, label="FINS frame"))
    except FINSParseError:
        raise
    except Exception as exc:
        raise FINSParseError("malformed FINS frame") from exc


def parse_udp(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one FINS/UDP datagram payload."""
    try:
        out = _parse_fins_frame(_blob(data, limit=MAX_UDP_FRAME, label="FINS/UDP frame"))
        out["transport"] = "udp"
        return out
    except FINSParseError:
        raise
    except Exception as exc:
        raise FINSParseError("malformed FINS/UDP frame") from exc


def _parse_tcp_frame(data: bytes) -> dict[str, Any]:
    _need(data, 0, 16, "FINS/TCP envelope")
    if data[:4] != b"FINS":
        raise FINSParseError("FINS/TCP magic is missing")
    declared = _u32be(data, 4, "FINS/TCP length")
    if declared < 8:
        raise FINSParseError("FINS/TCP length is smaller than command and error fields")
    if declared > MAX_TCP_FRAME - 8:
        raise FINSParseError("FINS/TCP declared length exceeds limit")
    total = declared + 8
    if total != len(data):
        raise FINSParseError("FINS/TCP declared length does not match frame")
    command = _u32be(data, 8, "FINS/TCP command")
    error = _u32be(data, 12, "FINS/TCP error")
    if command not in _TCP_COMMANDS:
        raise FINSParseError("unsupported FINS/TCP command")
    payload = data[16:]
    out: dict[str, Any] = {
        "transport": "tcp",
        "length": len(data),
        "declared_length": declared,
        "tcp_command": command,
        "tcp_command_name": _TCP_COMMANDS[command],
        "tcp_error": error,
        "tcp_error_hex": f"0x{error:08x}",
        "ok": error == 0,
    }
    if command == 0:
        if len(payload) != 4:
            raise FINSParseError("node-address request must contain one node address")
        out["client_node"] = _u32be(payload, 0, "FINS/TCP client node")
    elif command == 1:
        if len(payload) != 8:
            raise FINSParseError("node-address response must contain two node addresses")
        out["client_node"] = _u32be(payload, 0, "FINS/TCP client node")
        out["server_node"] = _u32be(payload, 4, "FINS/TCP server node")
    elif command == 2:
        if not payload:
            raise FINSParseError("FINS/TCP frame command has no FINS payload")
        if len(payload) > MAX_FINS_FRAME:
            raise FINSParseError("FINS/TCP embedded FINS frame exceeds protocol limit")
        out["fins"] = _parse_fins_frame(payload)
    else:
        if payload:
            raise FINSParseError("FINS/TCP notification/confirmation must not contain data")
    return out


def parse_tcp_frame(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode exactly one FINS/TCP envelope."""
    try:
        return _parse_tcp_frame(_blob(data, limit=MAX_TCP_FRAME, label="FINS/TCP frame"))
    except FINSParseError:
        raise
    except Exception as exc:
        raise FINSParseError("malformed FINS/TCP frame") from exc


def parse_tcp_stream(data: bytes | bytearray | memoryview) -> list[dict[str, Any]]:
    """Split and decode a bounded concatenated FINS/TCP byte stream."""
    try:
        stream = _blob(data, limit=MAX_STREAM, label="FINS/TCP stream")
        frames: list[dict[str, Any]] = []
        offset = 0
        while offset < len(stream):
            if len(frames) >= MAX_STREAM_FRAMES:
                raise FINSParseError("FINS/TCP stream frame limit exceeded")
            _need(stream, offset, 8, "FINS/TCP stream header")
            if stream[offset:offset + 4] != b"FINS":
                raise FINSParseError("FINS/TCP stream lost framing")
            declared = _u32be(stream, offset + 4, "FINS/TCP stream length")
            if declared < 8 or declared > MAX_TCP_FRAME - 8:
                raise FINSParseError("invalid FINS/TCP stream frame length")
            total = declared + 8
            _need(stream, offset, total, "FINS/TCP stream frame")
            frames.append(_parse_tcp_frame(stream[offset:offset + total]))
            offset += total
        return frames
    except FINSParseError:
        raise
    except Exception as exc:
        raise FINSParseError("malformed FINS/TCP stream") from exc


def analyze(data: bytes | bytearray | memoryview, *, transport: str = "auto") -> Any:
    """Decode one supplied artifact as UDP, TCP, or a TCP stream."""
    try:
        if transport not in {"auto", "udp", "tcp", "tcp-stream"}:
            raise FINSParseError("unsupported FINS transport")
        blob = _blob(data, limit=MAX_STREAM, label="FINS artifact")
        if transport == "auto":
            transport = "tcp" if blob.startswith(b"FINS") else "udp"
        if transport == "udp":
            return parse_udp(blob)
        if transport == "tcp":
            return parse_tcp_frame(blob)
        return parse_tcp_stream(blob)
    except FINSParseError:
        raise
    except Exception as exc:
        raise FINSParseError("cannot analyze FINS artifact") from exc


def analyze_file(path: str | Path, *, transport: str = "auto") -> Any:
    """Read and decode one bounded local artifact."""
    try:
        if not isinstance(path, (str, Path)):
            raise FINSParseError("path must be text or pathlib.Path")
        with open(path, "rb") as handle:
            data = handle.read(MAX_STREAM + 1)
        if len(data) > MAX_STREAM:
            raise FINSParseError("FINS artifact exceeds size limit")
        return analyze(data, transport=transport)
    except FINSParseError:
        raise
    except Exception as exc:
        raise FINSParseError("cannot read FINS artifact") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="raw FINS payload or FINS/TCP stream")
    parser.add_argument("--transport", choices=("auto", "udp", "tcp", "tcp-stream"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        print(json.dumps(analyze_file(args.file, transport=args.transport), indent=2, sort_keys=True))
        return 0
    except FINSParseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "FINSParseError",
    "analyze",
    "analyze_file",
    "main",
    "parse_fins_frame",
    "parse_tcp_frame",
    "parse_tcp_stream",
    "parse_udp",
]


if __name__ == "__main__":
    raise SystemExit(main())
