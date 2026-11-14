#!/usr/bin/env python3
"""Explicit-parameter direct-sequence spread-spectrum recovery from PCM WAV.

Each symbol occupies one caller-declared PN chip sequence.  Every chip spans a
fixed number of samples; positive correlation maps to bit 1 and negative
correlation to bit 0.  This is a bounded matched correlator, not a blind key or
synchronization search.  Result bytes are unverified candidates.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

try:
    import stegodepth_echo as _pcm
except ImportError:  # pragma: no cover - package-style import
    from . import stegodepth_echo as _pcm


MAX_CHIPS = 4096
MAX_SAMPLES_PER_CHIP = 65_536
MAX_BITS = 65_536
MAX_ANALYSIS_SAMPLES = 8_000_000
MAX_SYMBOL_SAMPLES = 1_000_000
MAX_CHIP_TEXT = 65_536


class StegodepthSpreadError(ValueError):
    """The only exception intentionally raised by public DSSS APIs."""


@dataclass(frozen=True, slots=True)
class SpreadResult:
    bits: tuple[int, ...]
    payload_msb: bytes
    payload_lsb: bytes
    correlations: tuple[float, ...]
    confident: int
    median_absolute_correlation: float
    chips: tuple[int, ...]
    samples_per_chip: int
    offset_samples: int
    channel: int
    sample_rate: int


def parse_chips(value: object) -> tuple[int, ...]:
    """Normalize explicit PN chips to -1/+1, raising only the declared error."""

    try:
        if isinstance(value, str):
            if len(value) > MAX_CHIP_TEXT:
                raise StegodepthSpreadError(
                    f"chip text exceeds the {MAX_CHIP_TEXT}-character cap"
                )
            normalized = []
            mapping = {"+": 1, "-": -1, "1": 1, "0": -1}
            for character in value:
                if character.isspace() or character == ",":
                    continue
                if character not in mapping:
                    raise StegodepthSpreadError(
                        "chips text may contain only +, -, 1, 0 and separators"
                    )
                normalized.append(mapping[character])
                if len(normalized) > MAX_CHIPS:
                    raise StegodepthSpreadError(
                        f"chip sequence exceeds {MAX_CHIPS} chips"
                    )
            if not normalized:
                raise StegodepthSpreadError("chip sequence is empty")
            chips = tuple(normalized)
        else:
            if not isinstance(value, Sequence):
                raise StegodepthSpreadError("chips must be text or a bounded sequence")
            count = len(value)
            if count > MAX_CHIPS:
                raise StegodepthSpreadError(f"chip sequence exceeds {MAX_CHIPS} chips")
            normalized = []
            for index in range(count):
                chip = value[index]
                if isinstance(chip, bool):
                    chip = int(chip)
                if not isinstance(chip, int) or chip not in (-1, 0, 1):
                    raise StegodepthSpreadError("chips must contain -1/+1 (or 0/1)")
                normalized.append(1 if chip == 1 else -1)
            chips = tuple(normalized)
        if not 4 <= len(chips) <= MAX_CHIPS:
            raise StegodepthSpreadError(f"chip sequence length must be 4..{MAX_CHIPS}")
        if len(set(chips)) != 2:
            raise StegodepthSpreadError("chip sequence must contain both signs")
        return chips
    except StegodepthSpreadError:
        raise
    except Exception as exc:
        raise StegodepthSpreadError("chip sequence is malformed") from exc


def _integer(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise StegodepthSpreadError(f"{name} must be an integer in {low}..{high}")
    return value


def _finite(value: object, name: str, low: float, high: float) -> float:
    try:
        result = float(value)
    except Exception as exc:
        raise StegodepthSpreadError(f"{name} must be a finite number") from exc
    if not math.isfinite(result) or not low <= result <= high:
        raise StegodepthSpreadError(f"{name} must be in {low}..{high}")
    return result


def _sample(info: _pcm.PCMInfo, channel: int, frame: int) -> float:
    width = info.bits_per_sample // 8
    offset = frame * info.block_align + channel * width
    if info.bits_per_sample == 8:
        return (info.samples[offset] - 128) / 128.0
    value = int.from_bytes(info.samples[offset:offset + width], "little", signed=True)
    return value / float(1 << (info.bits_per_sample - 1))


def _pack(bits: Sequence[int], msb_first: bool) -> bytes:
    output = bytearray(len(bits) // 8)
    for index in range(len(output) * 8):
        shift = 7 - (index & 7) if msb_first else index & 7
        output[index >> 3] |= bits[index] << shift
    return bytes(output)


def extract_dsss(
    data: object,
    *,
    chips: object,
    samples_per_chip: int,
    channel: int = 0,
    offset_samples: int = 0,
    max_bits: int = 8192,
    min_correlation: float = 0.10,
) -> SpreadResult | None:
    """Recover an explicitly synchronized baseband DSSS candidate stream.

    Malformed/unsupported WAV input and an input without one complete symbol
    return ``None``. Parameter errors raise :class:`StegodepthSpreadError`.
    """

    sequence = parse_chips(chips)
    span = _integer(samples_per_chip, "samples_per_chip", 1, MAX_SAMPLES_PER_CHIP)
    selected_channel = _integer(channel, "channel", 0, 31)
    offset = _integer(offset_samples, "offset_samples", 0, MAX_ANALYSIS_SAMPLES)
    limit = _integer(max_bits, "max_bits", 1, MAX_BITS)
    threshold = _finite(min_correlation, "min_correlation", 0.0, 1.0)
    symbol_samples = len(sequence) * span
    if symbol_samples > MAX_SYMBOL_SAMPLES:
        raise StegodepthSpreadError(
            f"one spread-spectrum symbol exceeds the {MAX_SYMBOL_SAMPLES}-sample cap"
        )

    info = _pcm.parse_pcm_wav(data)
    if info is None or selected_channel >= info.channels or offset >= info.frames:
        return None
    available = (info.frames - offset) // symbol_samples
    symbols = min(available, limit, MAX_ANALYSIS_SAMPLES // symbol_samples)
    if symbols < 1:
        return None

    reference_mean = math.fsum(sequence) / len(sequence)
    centered_reference = tuple(value - reference_mean for value in sequence)
    reference_energy = span * math.fsum(
        value * value for value in centered_reference
    )
    if reference_energy <= 0.0:
        raise StegodepthSpreadError("chip reference has no usable energy")

    bits: list[int] = []
    correlations: list[float] = []
    confident = 0
    try:
        for symbol in range(symbols):
            start = offset + symbol * symbol_samples
            total = squared = numerator = 0.0
            sample_index = 0
            for reference_value in centered_reference:
                for _ in range(span):
                    value = _sample(info, selected_channel, start + sample_index)
                    total += value
                    squared += value * value
                    numerator += value * reference_value
                    sample_index += 1
            energy = max(0.0, squared - (total * total) / symbol_samples)
            denominator = math.sqrt(energy * reference_energy)
            correlation = numerator / denominator if denominator > 1e-30 else 0.0
            if not math.isfinite(correlation):
                return None
            correlations.append(correlation)
            bits.append(int(correlation >= 0.0))
            confident += abs(correlation) >= threshold
        absolute = sorted(abs(value) for value in correlations)
        middle = len(absolute) // 2
        median = (absolute[middle] if len(absolute) & 1 else
                  (absolute[middle - 1] + absolute[middle]) / 2.0)
        frozen = tuple(bits)
        return SpreadResult(
            frozen, _pack(frozen, True), _pack(frozen, False), tuple(correlations),
            confident, median, sequence, span, offset, selected_channel, info.rate,
        )
    except StegodepthSpreadError:
        raise
    except Exception as exc:
        raise StegodepthSpreadError("DSSS analysis failed within the declared bounds") from exc


def _ascii_prefix(value: bytes) -> str | None:
    head = value.split(b"\x00", 1)[0]
    return head.decode("ascii") if len(head) >= 4 and all(32 <= byte <= 126 for byte in head) else None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegodepth_spread.py",
        description="Offline explicit-PN baseband audio DSSS correlator",
    )
    parser.add_argument("input")
    parser.add_argument("--chips", required=True,
                        help="explicit PN sequence using +/- or 1/0 (commas/space allowed)")
    parser.add_argument("--samples-per-chip", required=True, type=int)
    parser.add_argument("--channel", type=int, default=0)
    parser.add_argument("--offset-samples", type=int, default=0)
    parser.add_argument("--max-bits", type=int, default=8192)
    parser.add_argument("--min-correlation", type=float, default=0.10)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        path = Path(args.input)
        with path.open("rb") as stream:
            raw = stream.read(_pcm.MAX_INPUT_BYTES + 1)
        if len(raw) > _pcm.MAX_INPUT_BYTES:
            raise StegodepthSpreadError(
                f"input exceeds {_pcm.MAX_INPUT_BYTES}-byte cap"
            )
        result = extract_dsss(
            raw, chips=args.chips, samples_per_chip=args.samples_per_chip,
            channel=args.channel, offset_samples=args.offset_samples,
            max_bits=args.max_bits, min_correlation=args.min_correlation,
        )
        if result is None:
            output = {"input": str(path), "decoded": False,
                      "note": "unsupported/malformed PCM WAV or no complete symbol"}
        else:
            output = {
                "input": str(path), "decoded": True, "verified": False,
                "note": "candidate bits from explicit PN/timing; no message framing was assumed",
                "sample_rate": result.sample_rate, "channel": result.channel,
                "bits": len(result.bits), "confident_bits": result.confident,
                "median_absolute_correlation": result.median_absolute_correlation,
                "payload_msb_hex": result.payload_msb.hex(),
                "payload_lsb_hex": result.payload_lsb.hex(),
                "payload_msb_ascii": _ascii_prefix(result.payload_msb),
                "payload_lsb_ascii": _ascii_prefix(result.payload_lsb),
            }
        print(json.dumps(output, sort_keys=True))
        return 0
    except (OSError, StegodepthSpreadError, MemoryError) as exc:
        print(f"stegodepth_spread: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "StegodepthSpreadError", "SpreadResult", "parse_chips", "extract_dsss", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
