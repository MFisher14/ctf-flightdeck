#!/usr/bin/env python3
"""Bounded offline LoRa PHY payload recovery for aligned saved symbols/IQ.

This module fills the packet-layer gap above :mod:`rf_demod_full`: that engine
already performs chirp FFT demodulation, timing/preamble acquisition, and basic
coding helpers.  Here the raw FFT bins are mapped according to the Tapparel
``gr-lora_sdr`` receive chain, the special SF-2/CR4 first block is decoded,
explicit headers are checked, payload bytes are dewhitened, and the optional
LoRa CRC is verified.  Implicit-header captures require the caller to supply
the payload length, coding rate, and CRC setting.

Inputs are inert arrays or JSON files.  Nothing is transmitted, executed, or
opened except the explicitly named input file used by the CLI.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
from pathlib import Path
import sys
from typing import Any, Iterable, Sequence

import rf_demod_full as _rf


MAX_SYMBOLS = 16_384
MAX_PAYLOAD = 255
MAX_JSON = 8 * 1024 * 1024
MAX_IQ_SAMPLES = 2_000_000
PROFILE = "tapparel-gr-lora-sdr"


class RF2LoRaError(ValueError):
    """The aligned LoRa artifact is malformed, inconsistent, or unbounded."""


@dataclass(frozen=True)
class LoRaPacket:
    payload: bytes
    spreading_factor: int
    coding_rate: int
    crc_present: bool
    crc_received: int | None
    crc_computed: int | None
    implicit_header: bool
    low_data_rate_optimization: bool
    symbols_consumed: int
    corrected_codewords: int
    header_checksum: int | None
    profile: str = PROFILE

    def as_dict(self) -> dict[str, Any]:
        return {
            "payload_hex": self.payload.hex(),
            "payload_ascii": self.payload.decode("utf-8", "replace"),
            "payload_length": len(self.payload),
            "spreading_factor": self.spreading_factor,
            "coding_rate": self.coding_rate,
            "rate": f"4/{4 + self.coding_rate}",
            "crc_present": self.crc_present,
            "crc_received": None if self.crc_received is None else f"0x{self.crc_received:04x}",
            "crc_computed": None if self.crc_computed is None else f"0x{self.crc_computed:04x}",
            "crc_ok": True if self.crc_present else None,
            "implicit_header": self.implicit_header,
            "low_data_rate_optimization": self.low_data_rate_optimization,
            "symbols_consumed": self.symbols_consumed,
            "corrected_codewords": self.corrected_codewords,
            "header_checksum": None if self.header_checksum is None else f"0x{self.header_checksum:02x}",
            "profile": self.profile,
            "offline": True,
        }


def _exact_int(value: object, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RF2LoRaError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _exact_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise RF2LoRaError(f"{name} must be boolean")
    return value


def _bounded_symbols(values: Iterable[object]) -> list[int]:
    if isinstance(values, (str, bytes, bytearray, dict)):
        raise RF2LoRaError("symbols must be an iterable of integers")
    try:
        iterator = iter(values)
    except (TypeError, ValueError) as exc:
        raise RF2LoRaError("symbols must be iterable") from exc
    out: list[int] = []
    try:
        for value in iterator:
            if len(out) >= MAX_SYMBOLS:
                raise RF2LoRaError("symbol cap exceeded")
            if isinstance(value, bool) or not isinstance(value, int):
                raise RF2LoRaError("each symbol must be an integer")
            out.append(value)
    except RF2LoRaError:
        raise
    except Exception as exc:
        raise RF2LoRaError("symbol iteration failed") from exc
    if not out:
        raise RF2LoRaError("symbol stream is empty")
    return out


def whitening_sequence(length: int) -> bytes:
    """Return the LoRa payload whitening sequence (x^8+x^6+x^5+x^4+1)."""
    length = _exact_int(length, "whitening length", 0, MAX_PAYLOAD)
    state = 0xFF
    output = bytearray()
    for _ in range(length):
        output.append(state)
        feedback = ((state >> 7) ^ (state >> 5) ^ (state >> 4) ^ (state >> 3)) & 1
        state = ((state << 1) & 0xFF) | feedback
    return bytes(output)


def _crc16_step(crc: int, byte: int) -> int:
    crc ^= byte << 8
    for _ in range(8):
        crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def payload_crc(payload: bytes) -> int:
    """Compute LoRa's two-byte payload CRC value (Tapparel/SX127x profile)."""
    if not isinstance(payload, bytes) or len(payload) > MAX_PAYLOAD:
        raise RF2LoRaError("payload CRC input must be bounded bytes")
    # The published implementation defines this construction over the first
    # N-2 bytes followed by an XOR with the final two bytes.  It indexes both
    # final bytes, so N<2 has no defined Tapparel-profile value.
    if len(payload) < 2:
        raise RF2LoRaError("Tapparel payload CRC requires at least two bytes")
    crc = 0
    for byte in payload[:-2]:
        crc = _crc16_step(crc, byte)
    return crc ^ payload[-1] ^ (payload[-2] << 8)


def _header_checksum_parts(first: int, second: int, flags: int) -> tuple[int, int]:
    c4 = ((first >> 3) ^ (first >> 2) ^ (first >> 1) ^ first) & 1
    c3 = ((first >> 3) ^ (second >> 3) ^ (second >> 2) ^ (second >> 1) ^ flags) & 1
    c2 = ((first >> 2) ^ (second >> 3) ^ second ^ (flags >> 3) ^ (flags >> 1)) & 1
    c1 = ((first >> 1) ^ (second >> 2) ^ second ^ (flags >> 2) ^ (flags >> 1) ^ flags) & 1
    c0 = (first ^ (second >> 1) ^ (flags >> 3) ^ (flags >> 2) ^ (flags >> 1) ^ flags) & 1
    return c4, (c3 << 3) | (c2 << 2) | (c1 << 1) | c0


def header_checksum(length: int, coding_rate: int, crc_present: bool) -> int:
    """Return the five-bit explicit-header checksum in its on-air nibble form."""
    length = _exact_int(length, "payload length", 1, MAX_PAYLOAD)
    coding_rate = _exact_int(coding_rate, "coding rate", 1, 4)
    crc_present = _exact_bool(crc_present, "CRC presence")
    high, low = length >> 4, length & 0x0F
    c4, rest = _header_checksum_parts(high, low, (coding_rate << 1) | int(crc_present))
    return (c4 << 4) | rest


def _encode_candidate(nibble: int, coding_rate: int) -> int:
    d0, d1, d2, d3 = ((nibble >> bit) & 1 for bit in range(4))
    if coding_rate == 1:
        parity = d0 ^ d1 ^ d2 ^ d3
        return (d0 << 4) | (d1 << 3) | (d2 << 2) | (d3 << 1) | parity
    p0, p1 = d0 ^ d1 ^ d2, d1 ^ d2 ^ d3
    p2, p3 = d0 ^ d1 ^ d3, d0 ^ d2 ^ d3
    full = ((d0 << 7) | (d1 << 6) | (d2 << 5) | (d3 << 4) |
            (p0 << 3) | (p1 << 2) | (p2 << 1) | p3)
    return full >> (4 - coding_rate)


def _decode_codeword(codeword: int, coding_rate: int) -> tuple[int, int]:
    candidates = [((codeword ^ _encode_candidate(nibble, coding_rate)).bit_count(), nibble)
                  for nibble in range(16)]
    distance = min(item[0] for item in candidates)
    matches = [nibble for candidate_distance, nibble in candidates if candidate_distance == distance]
    correctable = distance == 0 or (coding_rate >= 3 and distance == 1 and len(matches) == 1)
    if not correctable or len(matches) != 1:
        raise RF2LoRaError("uncorrectable or ambiguous LoRa codeword")
    return matches[0], distance


def _deinterleave(block: Sequence[int], sf_app: int, coding_rate: int) -> list[int]:
    width = coding_rate + 4
    if len(block) != width:
        raise RF2LoRaError("incomplete LoRa interleaver block")
    codewords = [0] * sf_app
    for row, word in enumerate(block):
        if not 0 <= word < (1 << sf_app):
            raise RF2LoRaError("mapped symbol exceeds interleaver width")
        for column in range(sf_app):
            bit = (word >> (sf_app - 1 - column)) & 1
            target = (row - column - 1) % sf_app
            codewords[target] |= bit << (width - 1 - row)
    return codewords


def _map_raw_bin(raw: int, spreading_factor: int, *, reduced: bool) -> int:
    limit = 1 << spreading_factor
    if not 0 <= raw < limit:
        raise RF2LoRaError("raw symbol is outside its spreading-factor range")
    # fft_demod_impl.cc performs the mandatory -1-bin correction before both
    # the reduced-rate division and Gray mapping.  The ordering matters: a
    # valid reduced-rate FFT bin need not itself be divisible by four.
    shifted = (raw - 1) % limit
    if reduced:
        normalized, width = shifted // 4, spreading_factor - 2
    else:
        normalized, width = shifted, spreading_factor
    mapped = normalized ^ (normalized >> 1)
    if mapped >= 1 << width:
        raise RF2LoRaError("mapped symbol exceeds effective spreading factor")
    return mapped


def _decode_block(raw: Sequence[int], spreading_factor: int, coding_rate: int,
                  *, reduced: bool) -> tuple[list[int], int]:
    sf_app = spreading_factor - 2 if reduced else spreading_factor
    mapped = [_map_raw_bin(value, spreading_factor, reduced=reduced) for value in raw]
    codewords = _deinterleave(mapped, sf_app, coding_rate)
    nibbles: list[int] = []
    corrected = 0
    for codeword in codewords:
        nibble, distance = _decode_codeword(codeword, coding_rate)
        nibbles.append(nibble)
        corrected += int(distance == 1)
    return nibbles, corrected


def _decode_symbols_impl(
    symbols: Iterable[object],
    spreading_factor: int,
    *,
    implicit: bool,
    coding_rate: int | None,
    payload_length: int | None,
    crc_present: bool | None,
    ldro: bool,
    allow_trailing: bool,
) -> LoRaPacket:
    spreading_factor = _exact_int(spreading_factor, "spreading factor", 6, 12)
    implicit = _exact_bool(implicit, "implicit-header setting")
    ldro = _exact_bool(ldro, "LDRO setting")
    allow_trailing = _exact_bool(allow_trailing, "allow_trailing")
    values = _bounded_symbols(symbols)
    if any(value >= 1 << spreading_factor or value < 0 for value in values):
        raise RF2LoRaError("symbol is outside its spreading-factor range")
    if len(values) < 8:
        raise RF2LoRaError("LoRa frame is shorter than its first coding block")

    first_nibbles, corrected = _decode_block(
        values[:8], spreading_factor, 4, reduced=True
    )
    checksum: int | None = None
    if implicit:
        if coding_rate is None or payload_length is None or crc_present is None:
            raise RF2LoRaError("implicit mode requires coding rate, payload length, and CRC setting")
        coding_rate = _exact_int(coding_rate, "coding rate", 1, 4)
        payload_length = _exact_int(payload_length, "payload length", 1, MAX_PAYLOAD)
        crc_present = _exact_bool(crc_present, "CRC presence")
        data_nibbles = list(first_nibbles)
    else:
        if coding_rate is not None or payload_length is not None or crc_present is not None:
            raise RF2LoRaError("explicit mode obtains length, coding rate, and CRC from its header")
        if len(first_nibbles) < 5:
            raise RF2LoRaError("spreading factor cannot carry the explicit header")
        high, low, flags, check_high, check_low = first_nibbles[:5]
        payload_length = (high << 4) | low
        coding_rate, crc_present = flags >> 1, bool(flags & 1)
        if not 1 <= payload_length <= MAX_PAYLOAD or not 1 <= coding_rate <= 4:
            raise RF2LoRaError("explicit header contains invalid length or coding rate")
        wanted_high, wanted_low = _header_checksum_parts(high, low, flags)
        checksum = (check_high << 4) | check_low
        if check_high != wanted_high or check_low != wanted_low:
            raise RF2LoRaError("explicit LoRa header checksum mismatch")
        data_nibbles = list(first_nibbles[5:])

    required_data_nibbles = payload_length * 2 + (4 if crc_present else 0)
    remaining = max(0, required_data_nibbles - len(data_nibbles))
    sf_app = spreading_factor - 2 if ldro else spreading_factor
    blocks = math.ceil(remaining / sf_app)
    expected_symbols = 8 + blocks * (coding_rate + 4)
    if len(values) < expected_symbols:
        raise RF2LoRaError("LoRa symbol stream is truncated")
    if len(values) > expected_symbols and not allow_trailing:
        raise RF2LoRaError("unexpected symbols follow the complete LoRa frame")

    at = 8
    for _ in range(blocks):
        width = coding_rate + 4
        block_nibbles, block_corrected = _decode_block(
            values[at:at + width], spreading_factor, coding_rate, reduced=ldro
        )
        data_nibbles.extend(block_nibbles)
        corrected += block_corrected
        at += width
    if len(data_nibbles) < required_data_nibbles:
        raise RF2LoRaError("decoded LoRa payload is incomplete")
    data_nibbles = data_nibbles[:required_data_nibbles]
    packed = bytes(data_nibbles[index] | (data_nibbles[index + 1] << 4)
                   for index in range(0, len(data_nibbles), 2))
    whitened, trailer = packed[:payload_length], packed[payload_length:]
    sequence = whitening_sequence(payload_length)
    payload = bytes(value ^ sequence[index] for index, value in enumerate(whitened))

    received = computed = None
    if crc_present:
        if payload_length < 2:
            raise RF2LoRaError("Tapparel payload CRC requires at least two payload bytes")
        if len(trailer) != 2:
            raise RF2LoRaError("LoRa CRC trailer is truncated")
        received = int.from_bytes(trailer, "little")
        computed = payload_crc(payload)
        if received != computed:
            raise RF2LoRaError(
                f"LoRa payload CRC mismatch: received {received:#06x}, computed {computed:#06x}"
            )
    return LoRaPacket(
        payload=payload,
        spreading_factor=spreading_factor,
        coding_rate=coding_rate,
        crc_present=crc_present,
        crc_received=received,
        crc_computed=computed,
        implicit_header=implicit,
        low_data_rate_optimization=ldro,
        symbols_consumed=expected_symbols,
        corrected_codewords=corrected,
        header_checksum=checksum,
    )


def decode_symbols(
    symbols: Iterable[object],
    spreading_factor: int,
    *,
    implicit: bool = False,
    coding_rate: int | None = None,
    payload_length: int | None = None,
    crc_present: bool | None = None,
    ldro: bool = False,
    allow_trailing: bool = False,
) -> LoRaPacket:
    """Decode aligned raw FFT-bin symbols and verify header/FEC/whitening/CRC."""
    try:
        return _decode_symbols_impl(
            symbols, spreading_factor, implicit=implicit,
            coding_rate=coding_rate, payload_length=payload_length,
            crc_present=crc_present, ldro=ldro,
            allow_trailing=allow_trailing,
        )
    except RF2LoRaError:
        raise
    except Exception as exc:
        raise RF2LoRaError(f"LoRa symbol decoding failed: {exc}") from exc


def decode_iq(
    iq: Sequence[complex],
    spreading_factor: int,
    *,
    samples_per_chip: int = 1,
    offset: int = 0,
    **kwargs: Any,
) -> LoRaPacket:
    """Demodulate an aligned complex-IQ frame using the existing bounded FFT stage."""
    try:
        spreading_factor = _exact_int(spreading_factor, "spreading factor", 6, 12)
        samples_per_chip = _exact_int(samples_per_chip, "samples per chip", 1, 64)
        offset = _exact_int(offset, "IQ offset", 0, MAX_IQ_SAMPLES)
        count = len(iq)
        width = (1 << spreading_factor) * samples_per_chip
        if count > MAX_IQ_SAMPLES or offset >= count or (count - offset) % width:
            raise RF2LoRaError("IQ must contain bounded, whole aligned LoRa symbols")
        bins = _rf.lora_symbol_bins(
            iq, spreading_factor, samples_per_chip=samples_per_chip, offset=offset
        )
        return decode_symbols(bins, spreading_factor, **kwargs)
    except RF2LoRaError:
        raise
    except Exception as exc:
        raise RF2LoRaError(f"LoRa IQ demodulation failed: {exc}") from exc


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise RF2LoRaError(message)


def _load_json(path: str) -> dict[str, Any]:
    item = Path(path)
    if not item.is_file() or item.stat().st_size > MAX_JSON:
        raise RF2LoRaError("input is absent or exceeds the JSON cap")
    try:
        value = json.loads(item.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RF2LoRaError(f"invalid input JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise RF2LoRaError("input JSON root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="rf2_lora_phy.py")
    parser.add_argument("input", help="JSON object containing raw symbols or [I,Q] pairs")
    parser.add_argument("--json", action="store_true", help="pretty-print JSON")
    try:
        args = parser.parse_args(argv)
        config = _load_json(args.input)
        sf = config.get("spreading_factor")
        options = {
            "implicit": config.get("implicit", False),
            "coding_rate": config.get("coding_rate"),
            "payload_length": config.get("payload_length"),
            "crc_present": config.get("crc_present"),
            "ldro": config.get("ldro", False),
            "allow_trailing": config.get("allow_trailing", False),
        }
        if "symbols" in config:
            result = decode_symbols(config["symbols"], sf, **options)
        elif "iq" in config:
            raw = config["iq"]
            if not isinstance(raw, list) or len(raw) > MAX_IQ_SAMPLES:
                raise RF2LoRaError("IQ JSON must be a bounded array")
            try:
                iq = [complex(pair[0], pair[1]) for pair in raw
                      if isinstance(pair, list) and len(pair) == 2]
            except (TypeError, ValueError, OverflowError) as exc:
                raise RF2LoRaError("IQ entries must be finite [real, imaginary] pairs") from exc
            if len(iq) != len(raw) or any(not math.isfinite(x.real) or not math.isfinite(x.imag) for x in iq):
                raise RF2LoRaError("IQ entries must be finite [real, imaginary] pairs")
            result = decode_iq(
                iq, sf,
                samples_per_chip=config.get("samples_per_chip", 1),
                offset=config.get("offset", 0),
                **options,
            )
        else:
            raise RF2LoRaError("input JSON must contain symbols or iq")
        print(json.dumps(result.as_dict(), sort_keys=True, indent=2 if args.json else None))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (RF2LoRaError, OSError, TypeError, ValueError, OverflowError,
            RecursionError, MemoryError) as exc:
        print(f"rf2_lora_phy: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "LoRaPacket", "PROFILE", "RF2LoRaError", "decode_iq", "decode_symbols",
    "header_checksum", "main", "payload_crc", "whitening_sequence",
]
