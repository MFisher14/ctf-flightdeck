#!/usr/bin/env python3
"""Offline IEEE 802.15.4 2.4-GHz PPDU and FCS validation.

The existing ``radio_capture`` engine decodes MAC and Zigbee layers but treats
an attached FCS as opaque.  This module adds the missing classic O-QPSK PHY
framing: four-octet preamble, SFD 0xA7, seven-bit PHR length, and the verified
CRC-16/KERMIT FCS.  It consumes saved bytes only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import radio_capture


MAX_PSDU = 127
MAX_PPDU = 4 + 1 + 1 + MAX_PSDU
PREAMBLE = b"\x00" * 4
SFD = 0xA7


class RF2IEEE802154Error(ValueError):
    """A saved IEEE 802.15.4 PHY frame is malformed or fails its FCS."""


def _bytes(value: object, name: str, maximum: int) -> bytes:
    if not isinstance(value, bytes) or not value or len(value) > maximum:
        raise RF2IEEE802154Error(f"{name} must be 1..{maximum} immutable bytes")
    return value


def ieee802154_fcs(mac_frame: bytes) -> bytes:
    """Return the little-endian CRC-16/KERMIT FCS for a MAC frame."""
    data = _bytes(mac_frame, "MAC frame", MAX_PSDU - 2)
    crc = 0
    for octet in data:
        low = (crc ^ octet) & 0x0F
        crc = (crc >> 4) ^ (low * 0x1081)
        high = (crc ^ (octet >> 4)) & 0x0F
        crc = (crc >> 4) ^ (high * 0x1081)
    return (crc & 0xFFFF).to_bytes(2, "little")


def decode_psdu(psdu: bytes) -> dict[str, Any]:
    """Validate one PSDU (MAC bytes followed by its two-octet FCS)."""
    raw = _bytes(psdu, "PSDU", MAX_PSDU)
    if len(raw) < 5:
        raise RF2IEEE802154Error("PSDU is too short for a MAC header and FCS")
    mac, received = raw[:-2], raw[-2:]
    computed = ieee802154_fcs(mac)
    if received != computed:
        raise RF2IEEE802154Error("IEEE 802.15.4 FCS mismatch")
    try:
        decoded = radio_capture.parse_ieee802154(raw, has_fcs=True)
    except Exception as exc:  # preserve this module's declared public contract
        raise RF2IEEE802154Error(f"MAC/Zigbee parser failed: {exc}") from exc
    if decoded is None:
        raise RF2IEEE802154Error("unsupported or malformed IEEE 802.15.4 MAC frame")
    return {
        "protocol": "ieee802.15.4-psdu",
        "length": len(raw),
        "mac": mac,
        "fcs": received,
        "fcs_ok": True,
        "decoded": decoded,
    }


def decode_ppdu(ppdu: bytes) -> dict[str, Any]:
    """Validate the classic 2.4-GHz PPDU and decode its PSDU/Zigbee layers."""
    raw = _bytes(ppdu, "PPDU", MAX_PPDU)
    if len(raw) < 11:
        raise RF2IEEE802154Error("PPDU is truncated")
    if raw[:4] != PREAMBLE:
        raise RF2IEEE802154Error("invalid four-octet PHY preamble")
    if raw[4] != SFD:
        raise RF2IEEE802154Error("invalid 0xA7 start-of-frame delimiter")
    phr = raw[5]
    if phr & 0x80:
        raise RF2IEEE802154Error("reserved PHR bit is non-zero")
    declared = phr & 0x7F
    if not 5 <= declared <= MAX_PSDU or declared != len(raw) - 6:
        raise RF2IEEE802154Error("PHR PSDU length does not match the saved frame")
    report = decode_psdu(raw[6:])
    return {
        "protocol": "ieee802.15.4-ppdu",
        "preamble": raw[:4],
        "sfd": raw[4],
        "phr": phr,
        "psdu_length": declared,
        "psdu": report,
    }


def _json_default(value: object) -> object:
    if isinstance(value, bytes):
        return {"hex": value.hex(), "ascii": value.decode("utf-8", "replace")}
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a saved IEEE 802.15.4 PPDU/FCS")
    parser.add_argument("input")
    parser.add_argument("--psdu", action="store_true", help="input starts at MAC and includes FCS")
    try:
        args = parser.parse_args(argv)
        path = Path(args.input)
        cap = MAX_PSDU if args.psdu else MAX_PPDU
        if not path.is_file() or path.stat().st_size > cap:
            raise RF2IEEE802154Error("input is absent or exceeds the frame cap")
        report = decode_psdu(path.read_bytes()) if args.psdu else decode_ppdu(path.read_bytes())
        print(json.dumps(report, sort_keys=True, default=_json_default))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (OSError, RF2IEEE802154Error, TypeError, ValueError, OverflowError) as exc:
        print(f"rf2_ieee802154_phy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "MAX_PPDU", "MAX_PSDU", "PREAMBLE", "RF2IEEE802154Error", "SFD",
    "decode_ppdu", "decode_psdu", "ieee802154_fcs", "main",
]
