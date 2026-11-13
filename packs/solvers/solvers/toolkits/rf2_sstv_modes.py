#!/usr/bin/env python3
"""Bounded offline SSTV decoders for Scottie, Robot, and PD colour modes.

The existing :mod:`signal_stego_depth` engine owns PCM/WAV parsing and the
standard leader/VIS/parity check.  This module begins only after that validated
910 ms header and implements the mode-specific pixel layouts which that engine
does not decode.  It never opens an audio device, invokes a subprocess, or
contacts a network endpoint.

Timings and colour equations follow J. L. Barber, N7CXI, "Proposal for SSTV
Mode Specifications" (Dayton, 2000).  Supported modes are Scottie S1/S2/DX,
Robot 36/72, and PD50/90/120; Martin remains in signal_stego_depth.
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

import signal_stego_depth as base


MAX_FILE = 128 << 20
MAX_LINES = 512
MAX_DEMOD_SAMPLES = 20_000_000
HEADER_MS = 910.0


class RF2SSTVError(ValueError):
    """The supplied recording or requested SSTV decode is malformed/unbounded."""


@dataclass(frozen=True)
class ModeSpec:
    name: str
    vis: int
    family: str
    width: int
    height: int
    scan_ms: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "vis": self.vis, "family": self.family,
            "width": self.width, "height": self.height,
            "scan_ms": self.scan_ms,
        }


@dataclass(frozen=True)
class SSTVFrame:
    mode: ModeSpec
    pixels: np.ndarray
    sample_rate: int
    complete: bool

    @property
    def width(self) -> int:
        return self.mode.width

    @property
    def height(self) -> int:
        return int(self.pixels.shape[0])

    def ppm(self) -> bytes:
        header = f"P6\n{self.width} {self.height}\n255\n".encode("ascii")
        return header + self.pixels.tobytes(order="C")

    def as_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.name, "vis": self.mode.vis,
            "width": self.width, "height": self.height,
            "sample_rate": self.sample_rate, "complete": self.complete,
        }


MODES: dict[int, ModeSpec] = {
    60: ModeSpec("Scottie S1", 60, "scottie", 320, 256, 138.240),
    56: ModeSpec("Scottie S2", 56, "scottie", 320, 256, 88.064),
    76: ModeSpec("Scottie DX", 76, "scottie", 320, 256, 345.600),
    8: ModeSpec("Robot 36", 8, "robot36", 320, 240, 88.000),
    12: ModeSpec("Robot 72", 12, "robot72", 320, 240, 138.000),
    93: ModeSpec("PD50", 93, "pd", 320, 256, 91.520),
    99: ModeSpec("PD90", 99, "pd", 320, 256, 170.240),
    95: ModeSpec("PD120", 95, "pd", 640, 496, 121.600),
}
_MODE_NAMES = {spec.name.lower().replace(" ", "").replace("-", ""): spec
               for spec in MODES.values()}


def mode_spec(value: int | str) -> ModeSpec:
    """Resolve a supported VIS number or normalized mode name."""
    try:
        if isinstance(value, bool):
            raise RF2SSTVError("mode must be a VIS integer or name")
        if isinstance(value, int):
            spec = MODES.get(value)
        elif isinstance(value, str) and len(value) <= 32:
            key = value.strip().lower().replace(" ", "").replace("-", "")
            spec = _MODE_NAMES.get(key)
            if spec is None and key.isdigit():
                spec = MODES.get(int(key))
        else:
            spec = None
        if spec is None:
            raise RF2SSTVError("unsupported SSTV mode; use Scottie S1/S2/DX, Robot 36/72, or PD50/90/120")
        return spec
    except RF2SSTVError:
        raise
    except Exception as exc:
        raise RF2SSTVError("invalid SSTV mode") from exc


def _sample_bounds(rate: int, start_ms: float, duration_ms: float) -> tuple[int, int]:
    start = int(round(rate * start_ms / 1000.0))
    end = int(round(rate * (start_ms + duration_ms) / 1000.0))
    return start, end


def _slice(samples: np.ndarray, rate: int, start_ms: float, duration_ms: float) -> np.ndarray:
    left, right = _sample_bounds(rate, start_ms, duration_ms)
    if left < 0 or right <= left or right > samples.size:
        raise RF2SSTVError("SSTV scanline is truncated")
    return samples[left:right]


def _tone_is(samples: np.ndarray, rate: int, start_ms: float, duration_ms: float,
             expected: float) -> bool:
    piece = _slice(samples, rate, start_ms, duration_ms)
    if piece.size < 8 or float(np.sqrt(np.mean(piece * piece))) < 0.02:
        return False
    frequency, residual = _sinusoid_frequency(piece, rate)
    # The shortest documented porches contain only 2.25 cycles.  A DFT-bin
    # comparison is consequently too coarse; the sinusoid recurrence below is
    # phase-independent and still discriminates the signalling tones.
    return abs(frequency - expected) <= 75.0 and residual <= 0.25


def _sinusoid_frequency(samples: np.ndarray, rate: int) -> tuple[float, float]:
    """Estimate one real sinusoid using x[n+1]+x[n-1]=2*cos(w)*x[n]."""
    if samples.size < 4:
        raise RF2SSTVError("tone is too short")
    middle = samples[1:-1].astype(np.float64, copy=False)
    neighbours = samples[:-2] + samples[2:]
    denominator = 2.0 * float(np.dot(middle, middle))
    if denominator <= 1e-12:
        raise RF2SSTVError("tone has no measurable energy")
    cosine = float(np.dot(middle, neighbours)) / denominator
    if not math.isfinite(cosine) or cosine < -1.001 or cosine > 1.001:
        raise RF2SSTVError("tone is not a finite sinusoid")
    cosine = min(1.0, max(-1.0, cosine))
    frequency = math.acos(cosine) * float(rate) / (2.0 * np.pi)
    residual = neighbours - 2.0 * cosine * middle
    scale = max(1e-12, float(np.sqrt(np.mean(neighbours * neighbours))))
    return frequency, float(np.sqrt(np.mean(residual * residual))) / scale


def _analytic_frequency(samples: np.ndarray, rate: int) -> np.ndarray:
    """Return per-sample instantaneous frequency for one bounded video scan."""
    count = samples.size
    if count < 8:
        raise RF2SSTVError("SSTV video scan is too short")
    spectrum = np.fft.fft(samples)
    multiplier = np.zeros(count, dtype=np.float64)
    multiplier[0] = 1.0
    if count % 2 == 0:
        multiplier[1:count // 2] = 2.0
        multiplier[count // 2] = 1.0
    else:
        multiplier[1:(count + 1) // 2] = 2.0
    analytic = np.fft.ifft(spectrum * multiplier)
    phase_step = np.angle(analytic[1:] * np.conjugate(analytic[:-1]))
    return phase_step * float(rate) / (2.0 * np.pi)


def _video_scan(samples: np.ndarray, rate: int, start_ms: float, duration_ms: float,
                width: int) -> np.ndarray:
    piece = _slice(samples, rate, start_ms, duration_ms)
    # Flat fields are common in test cards and title panels.  Detecting their
    # single sinusoid directly avoids Hilbert-transform edge artefacts at the
    # first and last picture elements.
    flat_frequency, flat_residual = _sinusoid_frequency(piece, rate)
    probe_frequencies: list[float] = []
    probe_residuals: list[float] = []
    for probe in np.array_split(piece, 16):
        probe_frequency, probe_residual = _sinusoid_frequency(probe, rate)
        probe_frequencies.append(probe_frequency)
        probe_residuals.append(probe_residual)
    is_flat = (flat_residual <= 0.002
               and max(probe_residuals) <= 0.01
               and max(probe_frequencies) - min(probe_frequencies) <= 2.0)
    if is_flat:
        if flat_frequency < 1350.0 or flat_frequency > 2450.0:
            raise RF2SSTVError("video tone lies outside the SSTV luminance band")
        value = np.uint8(np.clip(round((flat_frequency - 1500.0) * 255.0 / 800.0), 0, 255))
        return np.full(width, value, dtype=np.uint8)

    # SSTV encoders hold one tone for each picture element.  Estimate those
    # short sinusoids at the documented absolute pixel boundaries.  This is
    # exact for phase-continuous digital captures and avoids smearing narrow
    # stripes.  The analytic-signal estimate remains a fallback for noisy or
    # smoothly varying analogue scans which do not satisfy the recurrence.
    scan_left, _ = _sample_bounds(rate, start_ms, duration_ms)
    analytic: np.ndarray | None = None
    values = np.empty(width, dtype=np.uint8)
    for column in range(width):
        left, right = _sample_bounds(
            rate, start_ms + duration_ms * column / width,
            duration_ms / width,
        )
        tone = samples[left:right]
        frequency = math.nan
        if tone.size >= 4:
            try:
                candidate, residual = _sinusoid_frequency(tone, rate)
                if residual <= 0.05:
                    frequency = candidate
            except RF2SSTVError:
                pass
        if not math.isfinite(frequency):
            if analytic is None:
                analytic = _analytic_frequency(piece, rate)
                if analytic.size < width:
                    raise RF2SSTVError("sample rate is too low for the requested SSTV width")
            local_left = max(0, left - scan_left)
            local_right = min(analytic.size, max(local_left + 1, right - scan_left - 1))
            cell = analytic[local_left:local_right]
            if cell.size >= 5:
                cell = cell[1:-1]
            frequency = float(np.median(cell))
        if not math.isfinite(frequency) or frequency < 1350.0 or frequency > 2450.0:
            raise RF2SSTVError("video tone lies outside the SSTV luminance band")
        values[column] = np.uint8(np.clip(round((frequency - 1500.0) * 255.0 / 800.0), 0, 255))
    return values


def _yuv(y: np.ndarray, red_y: np.ndarray, blue_y: np.ndarray) -> np.ndarray:
    yf, cr, cb = y.astype(np.float64), red_y.astype(np.float64), blue_y.astype(np.float64)
    red = 0.003906 * (298.082 * (yf - 16.0) + 408.583 * (cr - 128.0))
    green = 0.003906 * (298.082 * (yf - 16.0) - 100.291 * (cb - 128.0)
                        - 208.120 * (cr - 128.0))
    blue = 0.003906 * (298.082 * (yf - 16.0) + 516.411 * (cb - 128.0))
    return np.clip(np.rint(np.stack((red, green, blue), axis=1)), 0, 255).astype(np.uint8)


def _decode_scottie(audio: base.Audio, spec: ModeSpec, max_lines: int) -> tuple[list[np.ndarray], float]:
    rows: list[np.ndarray] = []
    at = HEADER_MS
    for line in range(min(max_lines, spec.height)):
        if line == 0:
            if not _tone_is(audio.samples, audio.rate, at, 9.0, 1200.0):
                raise RF2SSTVError("Scottie starting sync is absent")
            at += 9.0
        if not _tone_is(audio.samples, audio.rate, at, 1.5, 1500.0):
            raise RF2SSTVError("Scottie green separator is invalid")
        at += 1.5
        green = _video_scan(audio.samples, audio.rate, at, spec.scan_ms, spec.width)
        at += spec.scan_ms
        if not _tone_is(audio.samples, audio.rate, at, 1.5, 1500.0):
            raise RF2SSTVError("Scottie blue separator is invalid")
        at += 1.5
        blue = _video_scan(audio.samples, audio.rate, at, spec.scan_ms, spec.width)
        at += spec.scan_ms
        if not _tone_is(audio.samples, audio.rate, at, 9.0, 1200.0):
            raise RF2SSTVError("Scottie line sync is invalid")
        at += 9.0
        if not _tone_is(audio.samples, audio.rate, at, 1.5, 1500.0):
            raise RF2SSTVError("Scottie red porch is invalid")
        at += 1.5
        red = _video_scan(audio.samples, audio.rate, at, spec.scan_ms, spec.width)
        at += spec.scan_ms
        rows.append(np.stack((red, green, blue), axis=1))
        # Partial saved captures are useful; stop cleanly before attempting a
        # line whose shortest prefix is not present.
        if line + 1 < max_lines and int(round(audio.rate * (at + 3.0) / 1000.0)) > audio.samples.size:
            break
    return rows, at


def _decode_robot36(audio: base.Audio, spec: ModeSpec, max_lines: int) -> tuple[list[np.ndarray], float]:
    rows: list[np.ndarray] = []
    at = HEADER_MS
    pending: tuple[np.ndarray, np.ndarray] | None = None
    target = min(max_lines, spec.height)
    for line in range(target):
        if not _tone_is(audio.samples, audio.rate, at, 9.0, 1200.0):
            raise RF2SSTVError("Robot 36 line sync is invalid")
        at += 9.0
        if not _tone_is(audio.samples, audio.rate, at, 3.0, 1500.0):
            raise RF2SSTVError("Robot 36 sync porch is invalid")
        at += 3.0
        y = _video_scan(audio.samples, audio.rate, at, 88.0, spec.width)
        at += 88.0
        separator = 1500.0 if line % 2 == 0 else 2300.0
        if not _tone_is(audio.samples, audio.rate, at, 4.5, separator):
            raise RF2SSTVError("Robot 36 alternating chroma separator is invalid")
        at += 4.5
        if not _tone_is(audio.samples, audio.rate, at, 1.5, 1900.0):
            raise RF2SSTVError("Robot 36 chroma porch is invalid")
        at += 1.5
        chroma = _video_scan(audio.samples, audio.rate, at, 44.0, spec.width)
        at += 44.0
        if line % 2 == 0:
            pending = y, chroma
        else:
            if pending is None:
                raise RF2SSTVError("Robot 36 chroma pair is incomplete")
            y0, red_y = pending
            rows.extend((_yuv(y0, red_y, chroma), _yuv(y, red_y, chroma)))
            pending = None
        if line + 1 < target and int(round(audio.rate * (at + 9.0) / 1000.0)) > audio.samples.size:
            break
    if pending is not None:
        raise RF2SSTVError("Robot 36 requires a complete two-line chroma pair")
    return rows[:target], at


def _decode_robot72(audio: base.Audio, spec: ModeSpec, max_lines: int) -> tuple[list[np.ndarray], float]:
    rows: list[np.ndarray] = []
    at = HEADER_MS
    for line in range(min(max_lines, spec.height)):
        if not _tone_is(audio.samples, audio.rate, at, 9.0, 1200.0):
            raise RF2SSTVError("Robot 72 line sync is invalid")
        at += 9.0
        if not _tone_is(audio.samples, audio.rate, at, 3.0, 1500.0):
            raise RF2SSTVError("Robot 72 sync porch is invalid")
        at += 3.0
        y = _video_scan(audio.samples, audio.rate, at, 138.0, spec.width)
        at += 138.0
        if not _tone_is(audio.samples, audio.rate, at, 4.5, 1500.0):
            raise RF2SSTVError("Robot 72 R-Y separator is invalid")
        at += 4.5
        if not _tone_is(audio.samples, audio.rate, at, 1.5, 1900.0):
            raise RF2SSTVError("Robot 72 R-Y porch is invalid")
        at += 1.5
        red_y = _video_scan(audio.samples, audio.rate, at, 69.0, spec.width)
        at += 69.0
        if not _tone_is(audio.samples, audio.rate, at, 4.5, 2300.0):
            raise RF2SSTVError("Robot 72 B-Y separator is invalid")
        at += 4.5
        if not _tone_is(audio.samples, audio.rate, at, 1.5, 1500.0):
            raise RF2SSTVError("Robot 72 B-Y porch is invalid")
        at += 1.5
        blue_y = _video_scan(audio.samples, audio.rate, at, 69.0, spec.width)
        at += 69.0
        rows.append(_yuv(y, red_y, blue_y))
        if line + 1 < max_lines and int(round(audio.rate * (at + 9.0) / 1000.0)) > audio.samples.size:
            break
    return rows, at


def _decode_pd(audio: base.Audio, spec: ModeSpec, max_lines: int) -> tuple[list[np.ndarray], float]:
    rows: list[np.ndarray] = []
    at = HEADER_MS
    target = min(max_lines, spec.height)
    while len(rows) + 2 <= target:
        if not _tone_is(audio.samples, audio.rate, at, 20.0, 1200.0):
            raise RF2SSTVError("PD superline sync is invalid")
        at += 20.0
        if not _tone_is(audio.samples, audio.rate, at, 2.08, 1500.0):
            raise RF2SSTVError("PD superline porch is invalid")
        at += 2.08
        scans = []
        for _ in range(4):
            scans.append(_video_scan(audio.samples, audio.rate, at, spec.scan_ms, spec.width))
            at += spec.scan_ms
        y0, red_y, blue_y, y1 = scans
        rows.extend((_yuv(y0, red_y, blue_y), _yuv(y1, red_y, blue_y)))
        if len(rows) + 2 <= target and int(round(audio.rate * (at + 20.0) / 1000.0)) > audio.samples.size:
            break
    if not rows:
        raise RF2SSTVError("PD mode requires one complete two-row superline")
    return rows, at


def decode_sstv(source: Any, *, sample_rate: int | None = None,
                expected_mode: int | str | None = None,
                max_lines: int = MAX_LINES) -> SSTVFrame:
    """Decode a validated non-Martin SSTV recording into an RGB frame.

    Partial captures containing one or more complete scanlines are returned with
    ``complete=False``. Robot 36 and PD require complete two-row units.
    """
    try:
        if isinstance(max_lines, bool) or not isinstance(max_lines, int) or not 1 <= max_lines <= MAX_LINES:
            raise RF2SSTVError(f"max_lines must be 1..{MAX_LINES}")
        audio = base.read_audio(source, sample_rate=sample_rate)
        if audio is None or audio.rate < 8000:
            raise RF2SSTVError("input is not bounded finite mono audio at >=8 kHz")
        detected = base.detect_sstv_vis(audio)
        if detected is None:
            raise RF2SSTVError("standard SSTV leader/VIS/parity check failed")
        spec = mode_spec(int(detected["vis"]))
        if expected_mode is not None and mode_spec(expected_mode).vis != spec.vis:
            raise RF2SSTVError("detected VIS does not match expected_mode")
        requested = min(max_lines, spec.height)
        estimated = requested * spec.width * (4 if spec.family == "pd" else 3)
        if estimated > MAX_DEMOD_SAMPLES:
            raise RF2SSTVError("requested SSTV demodulation exceeds work cap")
        if spec.family == "scottie":
            rows, _ = _decode_scottie(audio, spec, requested)
        elif spec.family == "robot36":
            rows, _ = _decode_robot36(audio, spec, requested)
        elif spec.family == "robot72":
            rows, _ = _decode_robot72(audio, spec, requested)
        else:
            rows, _ = _decode_pd(audio, spec, requested)
        if not rows:
            raise RF2SSTVError("recording contains no complete SSTV scanline")
        pixels = np.stack(rows).astype(np.uint8, copy=False)
        pixels.setflags(write=False)
        return SSTVFrame(spec, pixels, audio.rate, pixels.shape[0] == spec.height)
    except RF2SSTVError:
        raise
    except Exception as exc:
        raise RF2SSTVError(f"malformed SSTV input: {exc}") from exc


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # pragma: no cover - exercised through main
        raise RF2SSTVError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="rf2_sstv_modes.py")
    parser.add_argument("input", help="saved PCM WAV recording")
    parser.add_argument("--mode", help="expected mode name or VIS number")
    parser.add_argument("--max-lines", type=int, default=MAX_LINES)
    parser.add_argument("--output", help="write decoded binary PPM")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        path = Path(args.input)
        if not path.is_file() or path.stat().st_size > MAX_FILE:
            raise RF2SSTVError("input is absent or exceeds the file cap")
        frame = decode_sstv(path.read_bytes(), expected_mode=args.mode,
                            max_lines=args.max_lines)
        if args.output:
            Path(args.output).write_bytes(frame.ppm())
        if args.json or not args.output:
            print(json.dumps(frame.as_dict(), sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (RF2SSTVError, OSError, ValueError, TypeError, OverflowError,
            MemoryError, RecursionError) as exc:
        print(f"rf2_sstv_modes: {exc}", file=sys.stderr)
        return 2


__all__ = [
    "MAX_LINES", "MODES", "ModeSpec", "RF2SSTVError", "SSTVFrame",
    "decode_sstv", "main", "mode_spec",
]


if __name__ == "__main__":
    raise SystemExit(main())
