#!/usr/bin/env python3
"""Bounded offline Bluetooth LE advertising-PHY verification.

``radio_capture`` already understands de-whitened advertising PDUs.  This
module adds only the missing over-the-air layer for saved LE 1M bytes:
preamble, the fixed advertising access address, channel whitening, and the
24-bit advertising CRC.  It never opens a radio or network interface.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import radio_capture


MAX_FRAME = 512
ADV_ACCESS_ADDRESS = 0x8E89BED6
ADV_CRC_INIT = 0x555555


class RF2BLEError(ValueError):
    """The saved BLE PHY frame is malformed, unsupported, or fails CRC."""


def _bounded_bytes(value: object, name: str, maximum: int = MAX_FRAME) -> bytes:
    if not isinstance(value, bytes) or not value or len(value) > maximum:
        raise RF2BLEError(f"{name} must be 1..{maximum} immutable bytes")
    return value


def _channel(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value not in (37, 38, 39):
        raise RF2BLEError("advertising channel must be 37, 38, or 39")
    return value


def _reverse_byte(value: int) -> int:
    result = 0
    for bit in range(8):
        result |= ((value >> bit) & 1) << (7 - bit)
    return result


def ble_crc24(pdu: bytes) -> bytes:
    """Return the three on-air CRC octets for an advertising-channel PDU.

    Bits within every octet are processed least-significant bit first, as in
    Bluetooth Core Vol 6, Part B.  The advertising CRCInit is ``0x555555``.
    """
    data = _bounded_bytes(pdu, "PDU", 260)
    state = sum(_reverse_byte((ADV_CRC_INIT >> shift) & 0xFF) << shift
                for shift in (0, 8, 16))
    for octet in data:
        current = octet
        for _ in range(8):
            feedback = (state ^ current) & 1
            current >>= 1
            state >>= 1
            if feedback:
                state = (state | (1 << 23)) ^ 0x5A6000
    return state.to_bytes(3, "little")


def ble_whiten(data: bytes, channel: int) -> bytes:
    """Apply or remove the LE whitening sequence for primary channel 37..39."""
    raw = _bounded_bytes(data, "whitening input")
    index = _channel(channel)
    lfsr = index | 0x40
    output = bytearray()
    for octet in raw:
        transformed = 0
        for bit_index in range(8):
            whitening_bit = lfsr & 1
            transformed |= (((octet >> bit_index) & 1) ^ whitening_bit) << bit_index
            lfsr = (lfsr >> 1) ^ (0x44 if whitening_bit else 0)
        output.append(transformed)
    return bytes(output)


def decode_advertising_phy(
    frame: bytes,
    channel: int,
    *,
    whitened: bool = True,
    include_preamble: bool = True,
) -> dict[str, Any]:
    """Validate and decode one saved LE advertising physical-channel packet.

    ``frame`` uses ordinary byte packing for the LSB-first transmitted bits:
    optional one-byte LE 1M preamble, four little-endian Access Address bytes,
    then PDU and CRC.  PDU+CRC are de-whitened when ``whitened`` is true.
    """
    raw = _bounded_bytes(frame, "BLE frame")
    index = _channel(channel)
    if not isinstance(whitened, bool) or not isinstance(include_preamble, bool):
        raise RF2BLEError("whitened/include_preamble must be booleans")
    minimum = 1 + 4 + 2 + 3 if include_preamble else 4 + 2 + 3
    if len(raw) < minimum:
        raise RF2BLEError("BLE advertising frame is truncated")
    offset = 0
    preamble = None
    if include_preamble:
        preamble, offset = raw[0], 1
    access_raw = raw[offset:offset + 4]
    offset += 4
    access_address = int.from_bytes(access_raw, "little")
    if access_address != ADV_ACCESS_ADDRESS:
        raise RF2BLEError("not the fixed advertising access address")
    if preamble is not None:
        expected = 0xAA if not (access_raw[0] & 1) else 0x55
        if preamble != expected:
            raise RF2BLEError("invalid LE 1M preamble for the access address")
    coded = raw[offset:]
    body = ble_whiten(coded, index) if whitened else coded
    if len(body) < 5:
        raise RF2BLEError("BLE PDU/CRC body is truncated")
    if body[1] & 0xC0:
        raise RF2BLEError("reserved advertising length bits are non-zero")
    payload_length = body[1] & 0x3F
    pdu_length = 2 + payload_length
    if len(body) != pdu_length + 3:
        raise RF2BLEError("advertising header length does not match the PHY frame")
    pdu, received_crc = body[:pdu_length], body[pdu_length:]
    computed_crc = ble_crc24(pdu)
    if received_crc != computed_crc:
        raise RF2BLEError("advertising CRC-24 mismatch")
    try:
        advertising = radio_capture.parse_ble_advertising(pdu)
    except Exception as exc:  # keep the public exception contract closed
        raise RF2BLEError(f"advertising PDU parser failed: {exc}") from exc
    report = {
        "protocol": "ble-advertising-phy",
        "channel": index,
        "preamble": preamble,
        "access_address": f"0x{access_address:08x}",
        "whitened_input": whitened,
        "pdu": pdu,
        "crc": received_crc,
        "crc_ok": True,
        "advertising": advertising,
    }
    if advertising is None:
        # The SIG's PHY sample intentionally uses arbitrary AdvData bytes that
        # are not a complete AD-structure sequence.  Preserve a CRC-verified
        # link-layer record without pretending those bytes parsed.
        report["advertising_parse_error"] = "link payload is not a supported complete advertising structure"
    return report


def _json_default(value: object) -> object:
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a saved BLE advertising PHY frame")
    parser.add_argument("input", help="raw saved LE 1M packet")
    parser.add_argument("--channel", type=int, required=True, choices=(37, 38, 39))
    parser.add_argument("--dewhitened", action="store_true", help="input PDU+CRC is already de-whitened")
    parser.add_argument("--no-preamble", action="store_true")
    try:
        args = parser.parse_args(argv)
        path = Path(args.input)
        if not path.is_file() or path.stat().st_size > MAX_FRAME:
            raise RF2BLEError("input is absent or exceeds the frame cap")
        report = decode_advertising_phy(
            path.read_bytes(), args.channel,
            whitened=not args.dewhitened,
            include_preamble=not args.no_preamble,
        )
        print(json.dumps(report, sort_keys=True, default=_json_default))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (OSError, RF2BLEError, TypeError, ValueError, OverflowError) as exc:
        print(f"rf2_ble_phy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ADV_ACCESS_ADDRESS", "ADV_CRC_INIT", "MAX_FRAME", "RF2BLEError",
    "ble_crc24", "ble_whiten", "decode_advertising_phy", "main",
]
