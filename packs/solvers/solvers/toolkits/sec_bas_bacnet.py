#!/usr/bin/env python3
"""Passive BACnet/IP and BACnet Secure Connect evidence decoder.

Classic BACnet/IP is deliberately delegated to :mod:`ics_protocols`, which
already implements BVLC, NPDU, APDU, tags, objects, properties, Who-Is/I-Am,
and ReadProperty.  This module adds the repository's missing BACnet/SC Annex
AB boundary: its general BVLL header, VMACs, header options, functions, and
supplied RFC 6455 binary-message extraction.

Only caller-supplied bytes are inspected.  No socket is opened, no WebSocket
or TLS session is created, and no BACnet response is produced.  TLS records
must first be decrypted by an independent evidence workflow.

References: ANSI/ASHRAE 135-2016 Addendum bj (BACnet/SC), 135-2020 Addenda
cf/cp, RFC 6455, and ANSI/ASHRAE 135 Annex J for the in-memory adapter used to
delegate an encapsulated NPDU to the existing decoder.
"""
from __future__ import annotations

import argparse
import functools
import json
import uuid
from pathlib import Path
import sys
from typing import Any, Callable, TypeVar, cast


MAX_INPUT = 16 * 1024 * 1024
MAX_SC_MESSAGE = 65535
MAX_OPTIONS = 64


class SecBasBACnetError(ValueError):
    """Malformed, unsupported, or excessive supplied BACnet evidence."""


_F = TypeVar("_F", bound=Callable[..., Any])


def _closed(function: _F) -> _F:
    """Translate every ordinary implementation failure to the public error."""

    @functools.wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return function(*args, **kwargs)
        except SecBasBACnetError:
            raise
        except Exception as exc:
            raise SecBasBACnetError(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from None

    return cast(_F, wrapper)


def _bytes(value: object, label: str = "input", limit: int = MAX_INPUT) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise SecBasBACnetError(f"{label} must be bytes-like")
    try:
        size = value.nbytes if isinstance(value, memoryview) else len(value)
        if size > limit:
            raise SecBasBACnetError(f"{label} exceeds {limit}-byte limit")
        return bytes(value)
    except SecBasBACnetError:
        raise
    except Exception as exc:
        raise SecBasBACnetError(f"invalid {label}: {exc}") from None


def _need(raw: bytes, offset: int, size: int, label: str) -> None:
    if type(offset) is not int or type(size) is not int or offset < 0 or size < 0:
        raise SecBasBACnetError(f"invalid {label} extent")
    if size > len(raw) - offset:
        raise SecBasBACnetError(f"truncated {label} at offset {offset}")


def _hex_colons(raw: bytes) -> str:
    return ":".join(f"{value:02x}" for value in raw)


def _vmac(raw: bytes) -> dict[str, object]:
    if len(raw) != 6:
        raise SecBasBACnetError("VMAC must contain six octets")
    kind = "unicast"
    if raw == b"\xff" * 6:
        kind = "local-broadcast"
    elif raw == b"\x00" * 6:
        kind = "unknown-or-uninitialized"
    return {"raw": raw.hex(), "text": _hex_colons(raw), "kind": kind}


SC_FUNCTIONS = {
    0x00: "BVLC-Result",
    0x01: "Encapsulated-NPDU",
    0x02: "Address-Resolution",
    0x03: "Address-Resolution-ACK",
    0x04: "Advertisement",
    0x05: "Advertisement-Solicitation",
    0x06: "Connect-Request",
    0x07: "Connect-Accept",
    0x08: "Disconnect-Request",
    0x09: "Disconnect-ACK",
    0x0A: "Heartbeat-Request",
    0x0B: "Heartbeat-ACK",
    0x0C: "Proprietary-Message",
}

# Low-nibble flags permitted by Addendum bj's per-function format tables.
# Encapsulated-NPDU permits every optional field.  Connect/disconnect/heartbeat
# messages can carry destination options but no VMAC or data-option fields.
_SC_ALLOWED_CONTROL = {
    0x00: 0x0E,
    0x01: 0x0F,
    0x02: 0x0E,
    0x03: 0x0E,
    0x04: 0x0E,
    0x05: 0x0E,
    0x06: 0x02,
    0x07: 0x02,
    0x08: 0x02,
    0x09: 0x02,
    0x0A: 0x02,
    0x0B: 0x02,
    0x0C: 0x0E,
}

SC_OPTION_TYPES = {
    1: "Secure-Path",
    2: "Hello",
    3: "Identity",
    4: "Hint",
    5: "Token",
    31: "Proprietary",
}


def _decode_option(marker: int, data: bytes | None, kind: str) -> dict[str, object]:
    option_type = marker & 0x1F
    if option_type == 0:
        raise SecBasBACnetError("reserved BACnet/SC option type zero")
    result: dict[str, object] = {
        "marker": marker,
        "more": bool(marker & 0x80),
        "data_present": bool(marker & 0x20),
        "type": option_type,
        "type_name": SC_OPTION_TYPES.get(option_type, f"Unknown-{option_type}"),
    }
    if kind == "destination":
        result["must_understand"] = bool(marker & 0x40)
    else:
        # Addendum cf renamed this bit for DATA options.
        result["every_segment"] = bool(marker & 0x40)
    if data is not None:
        result.update(length=len(data), data_hex=data.hex())

    violations: list[str] = []
    if option_type == 1:
        if data is not None:
            raise SecBasBACnetError("Secure-Path option must not contain header data")
        if kind != "data":
            violations.append("Secure-Path is defined as a data option")
        elif not (marker & 0x40):
            # Addendum bj's published figures use 0x01; current cf uses 0x41.
            violations.append("historical Secure-Path marker lacks current Every-Segment bit")
    elif option_type == 2:
        if kind != "destination":
            violations.append("Hello is defined as a destination option")
        if data is None or len(data) != 1:
            raise SecBasBACnetError("Hello option requires exactly one data octet")
        result["identity_relay_supported"] = bool(data[0] & 0x01)
        if data[0] & 0xFE:
            violations.append("Hello capability reserved bits are nonzero")
    elif option_type == 3:
        if kind != "data":
            violations.append("Identity is defined as a data option")
        if data is None or len(data) != 3:
            raise SecBasBACnetError("Identity option requires a three-octet device instance")
        instance = int.from_bytes(data, "big")
        result["device_instance"] = instance
        if instance > 0x3FFFFF:
            violations.append("Identity device instance exceeds the 22-bit BACnet domain")
    elif option_type == 4:
        if kind != "data":
            violations.append("Hint is defined as a data option")
        if data is None or len(data) < 5:
            raise SecBasBACnetError("Hint option requires at least five data octets")
        result["asn1_scope_hex"] = data.hex()
    elif option_type == 5:
        if kind != "data":
            violations.append("Token is defined as a data option")
        if data is None or not data:
            raise SecBasBACnetError("Token option requires data")
        result["access_token_hex"] = data.hex()
    elif option_type == 31:
        if data is None or len(data) < 3:
            raise SecBasBACnetError(
                "Proprietary option requires vendor and proprietary-option identifiers"
            )
        result["vendor_id"] = int.from_bytes(data[:2], "big")
        result["vendor_data_hex"] = data[2:].hex()
        result["proprietary_option_type"] = data[2]
        result["proprietary_data_hex"] = data[3:].hex()
    elif kind == "destination" and marker & 0x40:
        violations.append("unknown must-understand destination option")
    if violations:
        result["violations"] = violations
    return result


def _options(raw: bytes, offset: int, kind: str) -> tuple[list[dict[str, object]], int]:
    options: list[dict[str, object]] = []
    while True:
        if len(options) >= MAX_OPTIONS:
            raise SecBasBACnetError("BACnet/SC option count exceeds cap")
        _need(raw, offset, 1, f"{kind} option marker")
        marker = raw[offset]
        offset += 1
        data: bytes | None = None
        if marker & 0x20:
            _need(raw, offset, 2, f"{kind} option data length")
            length = int.from_bytes(raw[offset:offset + 2], "big")
            offset += 2
            _need(raw, offset, length, f"{kind} option data")
            data = raw[offset:offset + length]
            offset += length
        options.append(_decode_option(marker, data, kind))
        if not (marker & 0x80):
            return options, offset


def _classic_decoder(raw: bytes) -> dict[str, object]:
    try:
        try:
            from . import ics_protocols  # type: ignore
        except ImportError:
            import ics_protocols  # type: ignore
        result = ics_protocols.parse_bacnet(raw)
    except Exception as exc:
        raise SecBasBACnetError(f"classic BACnet decoder rejected input: {exc}") from None
    if not isinstance(result, dict):
        raise SecBasBACnetError("classic BACnet decoder returned an invalid result")
    return result


@_closed
def parse_bacnet_ip(data: bytes | bytearray | memoryview) -> dict[str, object]:
    """Delegate one exact classic BACnet/IP BVLC message to the existing engine."""

    raw = _bytes(data, "BACnet/IP message")
    if not raw:
        raise SecBasBACnetError("empty BACnet/IP message")
    return _classic_decoder(raw)


def _decode_npdu(npdu: bytes) -> dict[str, object]:
    if not npdu:
        raise SecBasBACnetError("Encapsulated-NPDU has an empty payload")
    total = 4 + len(npdu)
    if total > 0xFFFF:
        raise SecBasBACnetError("encapsulated NPDU exceeds Annex-J adapter length")
    # This wrapper exists in memory only and is never emitted.  It lets the
    # established parser consume the exact NPDU/APDU grammar without copying it.
    wrapper = b"\x81\x0a" + total.to_bytes(2, "big") + npdu
    decoded = _classic_decoder(wrapper)
    decoded.pop("bvlc_type", None)
    decoded.pop("bvlc_function", None)
    decoded.pop("bvlc_function_name", None)
    decoded.pop("length", None)
    decoded["decoder_reuse"] = "ics_protocols.parse_bacnet via in-memory Annex-J envelope"
    return decoded


def _payload_details(function: int, payload: bytes) -> dict[str, object]:
    details: dict[str, object] = {"payload_hex": payload.hex(), "payload_length": len(payload)}
    if function == 0x00:
        _need(payload, 0, 2, "BVLC-Result payload")
        details["result_for_function"] = payload[0]
        details["result_for_function_name"] = SC_FUNCTIONS.get(payload[0], f"Unknown-{payload[0]}")
        details["result_code"] = payload[1]
        if payload[1] == 0:
            if len(payload) != 2:
                raise SecBasBACnetError("BVLC-Result ACK has unexpected error fields")
            details["result"] = "ACK"
        elif payload[1] == 1:
            _need(payload, 2, 5, "BVLC-Result NAK error fields")
            details.update(
                result="NAK",
                error_header_marker=payload[2],
                error_class=int.from_bytes(payload[3:5], "big"),
                error_code=int.from_bytes(payload[5:7], "big"),
                error_details_hex=payload[7:].hex(),
            )
            try:
                details["error_details"] = payload[7:].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SecBasBACnetError("BVLC-Result error details are not UTF-8") from exc
        else:
            raise SecBasBACnetError("reserved BVLC-Result result code")
    elif function == 0x01:
        details["npdu"] = _decode_npdu(payload)
    elif function == 0x03:
        try:
            uri_text = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecBasBACnetError("Address-Resolution-ACK URI list is not UTF-8") from exc
        if uri_text and (uri_text.startswith(" ") or uri_text.endswith(" ") or "  " in uri_text):
            raise SecBasBACnetError("Address-Resolution-ACK URIs require single-space separators")
        details["websocket_uris"] = [] if not uri_text else uri_text.split(" ")
    elif function == 0x04:
        if len(payload) != 6:
            raise SecBasBACnetError("Advertisement payload must contain six octets")
        if payload[0] not in (0, 1, 2) or payload[1] not in (0, 1):
            raise SecBasBACnetError("Advertisement status parameter is out of range")
        details.update(
            hub_connection_status=payload[0],
            hub_connection_status_name={
                0: "no-hub-connection",
                1: "primary-hub",
                2: "failover-hub",
            }[payload[0]],
            accept_direct_connections=bool(payload[1]),
            maximum_bvlc_length=int.from_bytes(payload[2:4], "big"),
            maximum_npdu_length=int.from_bytes(payload[4:6], "big"),
        )
    elif function in (0x06, 0x07):
        if len(payload) != 26:
            raise SecBasBACnetError("Connect payload must contain 26 octets")
        details.update(
            connection_vmac=_vmac(payload[:6]),
            device_uuid=str(uuid.UUID(bytes=payload[6:22])),
            device_uuid_hex=payload[6:22].hex(),
            maximum_bvlc_length=int.from_bytes(payload[22:24], "big"),
            maximum_npdu_length=int.from_bytes(payload[24:26], "big"),
        )
    elif function == 0x0C:
        _need(payload, 0, 3, "Proprietary-Message payload")
        details["vendor_id"] = int.from_bytes(payload[:2], "big")
        details["proprietary_function"] = payload[2]
        details["proprietary_data_hex"] = payload[3:].hex()
    elif function in (0x02, 0x05, 0x08, 0x09, 0x0A, 0x0B) and payload:
        raise SecBasBACnetError(f"{SC_FUNCTIONS[function]} must not contain a payload")
    return details


@_closed
def parse_sc_bvll(data: bytes | bytearray | memoryview) -> dict[str, object]:
    """Parse one reassembled BACnet/SC BVLL WebSocket message."""

    raw = _bytes(data, "BACnet/SC message", MAX_SC_MESSAGE)
    _need(raw, 0, 4, "BACnet/SC general header")
    function, control = raw[0], raw[1]
    if function not in SC_FUNCTIONS:
        raise SecBasBACnetError(f"unknown BACnet/SC function 0x{function:02x}")
    if control & 0xF0:
        raise SecBasBACnetError("reserved BACnet/SC control bits are nonzero")
    offset = 4
    result: dict[str, object] = {
        "protocol": "bacnet-sc",
        "function": function,
        "function_name": SC_FUNCTIONS[function],
        "control": control,
        "message_id": int.from_bytes(raw[2:4], "big"),
        "originating_vmac_present": bool(control & 0x08),
        "destination_vmac_present": bool(control & 0x04),
        "destination_options_present": bool(control & 0x02),
        "data_options_present": bool(control & 0x01),
    }
    if control & 0x08:
        _need(raw, offset, 6, "originating VMAC")
        result["originating_vmac"] = _vmac(raw[offset:offset + 6])
        offset += 6
    if control & 0x04:
        _need(raw, offset, 6, "destination VMAC")
        result["destination_vmac"] = _vmac(raw[offset:offset + 6])
        offset += 6
    if control & 0x02:
        options, offset = _options(raw, offset, "destination")
        result["destination_options"] = options
    if control & 0x01:
        options, offset = _options(raw, offset, "data")
        result["data_options"] = options
    payload = raw[offset:]
    result.update(_payload_details(function, payload))
    violations: list[str] = []
    unexpected = control & ~_SC_ALLOWED_CONTROL[function]
    if unexpected:
        violations.append(
            f"{SC_FUNCTIONS[function]} has unexpected control flags 0x{unexpected:02x}"
        )
    if function == 0x00 and unexpected & 0x01:
        # Keep an explicit, stable label for historical Addendum-bj Figure YY-6.
        violations.append("BVLC-Result carries historical data-options flag")
    if violations:
        result["violations"] = violations
    return result


@_closed
def parse_sc_websocket(
    data: bytes | bytearray | memoryview, *, from_client: bool
) -> dict[str, object]:
    """Extract and decode BACnet/SC messages from supplied RFC 6455 frames.

    ``from_client`` is required because RFC 6455 requires client frames to be
    masked and server frames to be unmasked.  The existing strict WebSocket
    decoder handles framing and fragmentation; every application message must
    be binary and contain one complete BACnet/SC BVLL message.
    """

    raw = _bytes(data, "WebSocket frame stream")
    if not isinstance(from_client, bool):
        raise SecBasBACnetError("from_client must be bool")
    if not raw:
        raise SecBasBACnetError("empty WebSocket frame stream")
    try:
        try:
            from . import network_forensics  # type: ignore
        except ImportError:
            import network_forensics  # type: ignore
        transcript = network_forensics.decode_websocket_stream(raw, from_client=from_client)
    except Exception as exc:
        raise SecBasBACnetError(f"WebSocket decoder failed: {exc}") from None
    if transcript is None:
        raise SecBasBACnetError("invalid or incomplete RFC 6455 frame stream")
    if not transcript.messages:
        raise SecBasBACnetError("WebSocket stream contains no BACnet/SC message")
    messages: list[dict[str, object]] = []
    for message in transcript.messages:
        if message.opcode != 2 or message.text is not None:
            raise SecBasBACnetError("BACnet/SC requires WebSocket binary messages")
        messages.append(parse_sc_bvll(message.data))
    return {
        "protocol": "bacnet-sc-websocket",
        "direction": "client-to-server" if from_client else "server-to-client",
        "messages": messages,
        "pings": [item.hex() for item in transcript.pings],
        "pongs": [item.hex() for item in transcript.pongs],
        "close_code": transcript.close_code,
        "close_reason": transcript.close_reason,
        "tls": "not inspected; input is supplied post-TLS WebSocket framing",
    }


@_closed
def analyze(
    data: bytes | bytearray | memoryview,
    *,
    format: str = "auto",
    from_client: bool | None = None,
) -> dict[str, object]:
    """Analyze classic BACnet/IP, raw SC BVLL, or supplied WebSocket frames."""

    raw = _bytes(data)
    if format not in {"auto", "bacnet-ip", "sc", "websocket"}:
        raise SecBasBACnetError("format must be auto, bacnet-ip, sc, or websocket")
    chosen = format
    if chosen == "auto":
        if (
            len(raw) >= 4
            and raw[0] in (0x81, 0x82)
            and int.from_bytes(raw[2:4], "big") == len(raw)
        ):
            chosen = "bacnet-ip"
        elif raw and raw[0] & 0xF0 == 0x80 and raw[0] & 0x0F in (0, 1, 2, 8, 9, 10):
            chosen = "websocket"
        else:
            chosen = "sc"
    if chosen == "bacnet-ip":
        return parse_bacnet_ip(raw)
    if chosen == "sc":
        return parse_sc_bvll(raw)
    if from_client is None:
        _need(raw, 0, 2, "WebSocket header")
        from_client = bool(raw[1] & 0x80)
    return parse_sc_websocket(raw, from_client=from_client)


def _read(path: Path, hexadecimal: bool) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise SecBasBACnetError("input file exceeds 16 MiB limit")
        if hexadecimal:
            try:
                raw = bytes.fromhex(raw.decode("ascii"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise SecBasBACnetError(f"invalid hexadecimal input: {exc}") from None
        return raw
    except SecBasBACnetError:
        raise
    except OSError as exc:
        raise SecBasBACnetError(f"cannot read input: {exc}") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Passive BACnet/IP and BACnet/SC supplied-byte decoder"
    )
    parser.add_argument("input", type=Path, help="raw message or RFC 6455 frame stream")
    parser.add_argument(
        "--format", choices=("auto", "bacnet-ip", "sc", "websocket"), default="auto"
    )
    parser.add_argument("--hex", action="store_true", help="input file contains hexadecimal text")
    direction = parser.add_mutually_exclusive_group()
    direction.add_argument("--from-client", action="store_true", help="masked client WebSocket frames")
    direction.add_argument("--from-server", action="store_true", help="unmasked server WebSocket frames")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        from_client = True if args.from_client else False if args.from_server else None
        result = analyze(
            _read(args.input, args.hex), format=args.format, from_client=from_client
        )
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except SecBasBACnetError as exc:
        print(f"sec_bas_bacnet: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_INPUT",
    "SC_FUNCTIONS",
    "SC_OPTION_TYPES",
    "SecBasBACnetError",
    "analyze",
    "main",
    "parse_bacnet_ip",
    "parse_sc_bvll",
    "parse_sc_websocket",
]
