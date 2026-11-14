#!/usr/bin/env python3
"""Bounded, offline extraction of explicitly parameterized PCM echo hiding.

Classic echo hiding represents each bit by adding a short delayed copy of an
audio window.  This module compares normalized autocorrelation at two delays
provided by the caller.  It does not search for a key, infer a framing scheme,
decode a codec, or claim that the resulting bit stream is a verified message.

Only integer PCM in a bounded RIFF/WAVE container is read.  All parsing and
signal work is pure Python and no supplied content is executed.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


MAX_INPUT_BYTES = 128 << 20
MAX_ANALYSIS_SAMPLES = 8_000_000
MAX_BITS = 65_536
MAX_WINDOW_SAMPLES = 1_000_000
PCM_SUBFORMAT = bytes.fromhex("0100000000001000800000aa00389b71")


class StegodepthEchoError(ValueError):
    """The only exception intentionally raised by public echo APIs."""


@dataclass(frozen=True, slots=True)
class PCMInfo:
    rate: int
    channels: int
    bits_per_sample: int
    block_align: int
    frames: int
    samples: bytes


@dataclass(frozen=True, slots=True)
class EchoResult:
    """A deterministic reading for the caller-supplied echo parameters.

    ``scores`` contains ``(delay_zero_score, delay_one_score)`` for each
    window. ``confident`` counts windows whose absolute score difference met
    ``min_margin``. The payload views are candidates, never verification.
    """

    bits: tuple[int, ...]
    payload_msb: bytes
    payload_lsb: bytes
    scores: tuple[tuple[float, float], ...]
    confident: int
    median_margin: float
    delay_zero: int
    delay_one: int
    window_samples: int
    offset_samples: int
    channel: int
    sample_rate: int


def _bytes(data: object) -> bytes | None:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
        if size > MAX_INPUT_BYTES:
            return None
        raw = bytes(data)
    except Exception:
        return None
    return raw if len(raw) <= MAX_INPUT_BYTES else None


def parse_pcm_wav(data: object) -> PCMInfo | None:
    """Parse bounded integer PCM RIFF/WAVE, returning ``None`` on malformation.

    PCM (format 1) and WAVE_FORMAT_EXTENSIBLE carrying the PCM subtype are
    supported at 8, 16, 24, or 32 bits. The first data chunk is used.
    """

    raw = _bytes(data)
    if raw is None or len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
        return None
    try:
        declared_end = 8 + struct.unpack_from("<I", raw, 4)[0]
        if declared_end < 12 or declared_end > len(raw):
            return None
        position = 12
        fmt = None
        sample_bytes = None
        chunks = 0
        while position < declared_end:
            if position + 8 > declared_end:
                return None
            kind = raw[position:position + 4]
            size = struct.unpack_from("<I", raw, position + 4)[0]
            body_start = position + 8
            body_end = body_start + size
            padded_end = body_end + (size & 1)
            if body_end > declared_end or padded_end > declared_end:
                return None
            body = raw[body_start:body_end]
            if kind == b"fmt " and fmt is None:
                fmt = body
            elif kind == b"data" and sample_bytes is None:
                sample_bytes = body
            position = padded_end
            chunks += 1
            if chunks > 100_000:
                return None
        if position != declared_end or fmt is None or sample_bytes is None or len(fmt) < 16:
            return None
        tag, channels, rate, byte_rate, align, bits = struct.unpack_from("<HHIIHH", fmt, 0)
        if tag == 0xFFFE:
            if len(fmt) < 40 or struct.unpack_from("<H", fmt, 16)[0] < 22:
                return None
            if fmt[24:40] != PCM_SUBFORMAT:
                return None
        elif tag != 1:
            return None
        if channels < 1 or channels > 32 or rate < 1 or rate > 768_000:
            return None
        if bits not in (8, 16, 24, 32):
            return None
        width = bits // 8
        expected_align = channels * width
        if align != expected_align or byte_rate != rate * align:
            return None
        if len(sample_bytes) % align:
            return None
        frames = len(sample_bytes) // align
        return PCMInfo(rate, channels, bits, align, frames, sample_bytes)
    except (struct.error, IndexError, OverflowError, MemoryError, ValueError, TypeError):
        return None


def _integer(value: object, name: str, low: int, high: int) -> int:
    if type(value) is not int or not low <= value <= high:
        raise StegodepthEchoError(f"{name} must be an integer in {low}..{high}")
    return value


def _finite(value: object, name: str, low: float, high: float) -> float:
    try:
        result = float(value)
    except Exception as exc:
        raise StegodepthEchoError(f"{name} must be a finite number") from exc
    if not math.isfinite(result) or not low <= result <= high:
        raise StegodepthEchoError(f"{name} must be in {low}..{high}")
    return result


def _sample(raw: bytes, offset: int, bits: int) -> float:
    if bits == 8:
        return (raw[offset] - 128) / 128.0
    width = bits // 8
    value = int.from_bytes(raw[offset:offset + width], "little", signed=True)
    return value / float(1 << (bits - 1))


def _window(info: PCMInfo, channel: int, start: int, count: int) -> list[float]:
    width = info.bits_per_sample // 8
    base = start * info.block_align + channel * width
    return [
        _sample(info.samples, base + index * info.block_align, info.bits_per_sample)
        for index in range(count)
    ]


def _normalized_autocorrelation(values: Sequence[float], delay: int) -> float:
    count = len(values) - delay
    if count < 2:
        return 0.0
    mean = math.fsum(values) / len(values)
    numerator = left_energy = right_energy = 0.0
    for index in range(count):
        left = values[index] - mean
        right = values[index + delay] - mean
        numerator += left * right
        left_energy += left * left
        right_energy += right * right
    denominator = math.sqrt(left_energy * right_energy)
    return numerator / denominator if denominator > 1e-30 else 0.0


def pack_bits(bits: Sequence[int], *, msb_first: bool = True) -> bytes:
    """Pack complete bytes from a supplied 0/1 sequence.

    Bad values raise only :class:`StegodepthEchoError`.
    """

    try:
        length = len(bits)
        if length > MAX_BITS:
            raise StegodepthEchoError(f"bit sequence exceeds {MAX_BITS}-bit cap")
        normalized = bytearray(length)
        for index in range(length):
            bit = bits[index]
            if isinstance(bit, bool):
                bit = int(bit)
            if not isinstance(bit, int) or bit not in (0, 1):
                raise StegodepthEchoError("bits must contain only 0 and 1")
            normalized[index] = bit
        count = length // 8
        out = bytearray(count)
        for index in range(count * 8):
            shift = 7 - (index & 7) if msb_first else index & 7
            out[index >> 3] |= normalized[index] << shift
        return bytes(out)
    except StegodepthEchoError:
        raise
    except Exception as exc:
        raise StegodepthEchoError("bits must be a bounded indexable sequence") from exc


def extract_echo(
    data: object,
    *,
    delay_zero: int,
    delay_one: int,
    window_samples: int,
    channel: int = 0,
    offset_samples: int = 0,
    max_bits: int = 8192,
    min_margin: float = 0.02,
) -> EchoResult | None:
    """Read one bit per window by comparing two declared echo delays.

    A malformed/unsupported WAV or a carrier with no whole window returns
    ``None``. Invalid parameters raise :class:`StegodepthEchoError`.
    """

    zero = _integer(delay_zero, "delay_zero", 1, MAX_WINDOW_SAMPLES - 1)
    one = _integer(delay_one, "delay_one", 1, MAX_WINDOW_SAMPLES - 1)
    window = _integer(window_samples, "window_samples", 4, MAX_WINDOW_SAMPLES)
    selected_channel = _integer(channel, "channel", 0, 31)
    offset = _integer(offset_samples, "offset_samples", 0, MAX_ANALYSIS_SAMPLES)
    limit = _integer(max_bits, "max_bits", 1, MAX_BITS)
    margin_floor = _finite(min_margin, "min_margin", 0.0, 1.0)
    if zero == one:
        raise StegodepthEchoError("delay_zero and delay_one must differ")
    if max(zero, one) >= window - 1:
        raise StegodepthEchoError("both delays must leave at least two paired samples per window")

    info = parse_pcm_wav(data)
    if info is None:
        return None
    if selected_channel >= info.channels or offset >= info.frames:
        return None
    available = (info.frames - offset) // window
    windows = min(available, limit, MAX_ANALYSIS_SAMPLES // window)
    if windows < 1:
        return None

    scores: list[tuple[float, float]] = []
    bits: list[int] = []
    margins: list[float] = []
    confident = 0
    try:
        for index in range(windows):
            values = _window(info, selected_channel, offset + index * window, window)
            score_zero = _normalized_autocorrelation(values, zero)
            score_one = _normalized_autocorrelation(values, one)
            if not math.isfinite(score_zero) or not math.isfinite(score_one):
                return None
            bit = int(score_one > score_zero)
            difference = abs(score_one - score_zero)
            scores.append((score_zero, score_one))
            bits.append(bit)
            margins.append(difference)
            confident += difference >= margin_floor
        ordered = sorted(margins)
        middle = len(ordered) // 2
        median = (ordered[middle] if len(ordered) & 1 else
                  (ordered[middle - 1] + ordered[middle]) / 2.0)
        frozen_bits = tuple(bits)
        return EchoResult(
            frozen_bits,
            pack_bits(frozen_bits, msb_first=True),
            pack_bits(frozen_bits, msb_first=False),
            tuple(scores),
            confident,
            median,
            zero,
            one,
            window,
            offset,
            selected_channel,
            info.rate,
        )
    except StegodepthEchoError:
        raise
    except Exception as exc:
        raise StegodepthEchoError("echo analysis failed within the declared bounds") from exc


def _printable_prefix(value: bytes) -> str | None:
    head = value.split(b"\x00", 1)[0]
    if len(head) < 4 or any(byte < 32 or byte > 126 for byte in head):
        return None
    return head.decode("ascii")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stegodepth_echo.py",
        description="Offline explicit-delay PCM echo-hiding extractor",
    )
    parser.add_argument("input")
    parser.add_argument("--delay-zero", type=int, required=True)
    parser.add_argument("--delay-one", type=int, required=True)
    parser.add_argument("--window-samples", type=int, required=True)
    parser.add_argument("--channel", type=int, default=0)
    parser.add_argument("--offset-samples", type=int, default=0)
    parser.add_argument("--max-bits", type=int, default=8192)
    parser.add_argument("--min-margin", type=float, default=0.02)
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
            raw = stream.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise StegodepthEchoError(f"input exceeds {MAX_INPUT_BYTES}-byte cap")
        result = extract_echo(
            raw,
            delay_zero=args.delay_zero,
            delay_one=args.delay_one,
            window_samples=args.window_samples,
            channel=args.channel,
            offset_samples=args.offset_samples,
            max_bits=args.max_bits,
            min_margin=args.min_margin,
        )
        if result is None:
            output = {"input": str(path), "decoded": False,
                      "note": "unsupported/malformed PCM WAV or no complete window"}
        else:
            output = {
                "input": str(path),
                "decoded": True,
                "verified": False,
                "note": "candidate bits from caller-supplied delays; no message framing was assumed",
                "sample_rate": result.sample_rate,
                "channel": result.channel,
                "bits": len(result.bits),
                "confident_bits": result.confident,
                "median_margin": result.median_margin,
                "payload_msb_hex": result.payload_msb.hex(),
                "payload_lsb_hex": result.payload_lsb.hex(),
                "payload_msb_ascii": _printable_prefix(result.payload_msb),
                "payload_lsb_ascii": _printable_prefix(result.payload_lsb),
            }
        print(json.dumps(output, sort_keys=True))
        return 0
    except (OSError, StegodepthEchoError, MemoryError) as exc:
        print(f"stegodepth_echo: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "StegodepthEchoError", "PCMInfo", "EchoResult", "parse_pcm_wav",
    "pack_bits", "extract_echo", "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
