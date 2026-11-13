#!/usr/bin/env python3
"""CRC-gated steganography decoders for caller-supplied video frames.

The existing toolkit can extract frames in a networkless sandbox.  This module
starts *after* extraction and accepts arrays or frame-like objects.  It covers
spatial bit planes, one-bit-per-frame pixels, global-luminance ASK, parity of
inter-frame changes, and duplicate-frame run lengths.  Proven-payload APIs
require an ``R5V1`` length/CRC envelope.  Parallel candidate APIs can surface
ordinary flag-shaped or wholly printable streams, explicitly marked unproven.
"""
from __future__ import annotations

import binascii
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

import numpy as np


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAGIC = b"R5V1"
MAX_FRAMES = 100_000
MAX_PIXELS_PER_FRAME = 20_000_000
MAX_TOTAL_PIXELS = 100_000_000
MAX_PAYLOAD = 1 << 20
MAX_CARRIER_BITS = 8_500_000
MAX_CANDIDATES = 32
_FLAG = flagfmt.BYTES


@dataclass(frozen=True)
class VideoCandidate:
    method: str
    payload: bytes
    check: str
    proven: bool = False


def checked_frame(payload: bytes) -> bytes:
    payload = bytes(payload)
    if len(payload) > 0xFFFF:
        raise ValueError("payload too large")
    return MAGIC + struct.pack(">HI", len(payload), binascii.crc32(payload) & 0xFFFFFFFF) + payload


def _arrays(frames: Iterable) -> list[np.ndarray] | None:
    out: list[np.ndarray] = []
    total = 0
    try:
        iterator = iter(frames)
    except TypeError:
        return None
    for item in iterator:
        if len(out) >= MAX_FRAMES:
            return None
        try:
            if hasattr(item, "pixels") and hasattr(item, "width") and hasattr(item, "height"):
                channels = int(getattr(item, "channels", 1))
                arr = np.frombuffer(item.pixels, dtype=np.uint8).reshape(item.height, item.width, channels)
            else:
                arr = np.asarray(item)
        except (TypeError, ValueError, OverflowError):
            return None
        if arr.ndim == 2:
            arr = arr[:, :, None]
        if arr.ndim != 3 or arr.shape[2] not in (1, 2, 3, 4) or arr.dtype != np.uint8:
            return None
        pixels = int(arr.shape[0] * arr.shape[1])
        total += pixels
        if pixels <= 0 or pixels > MAX_PIXELS_PER_FRAME or total > MAX_TOTAL_PIXELS:
            return None
        out.append(np.ascontiguousarray(arr))
    return out or None


def _bits_bytes(bits: Sequence[int]) -> bytes:
    out = bytearray()
    for at in range(0, len(bits) - 7, 8):
        value = 0
        for bit in bits[at:at + 8]:
            value = (value << 1) | (int(bit) & 1)
        out.append(value)
    return bytes(out)


def _payload(bits: Sequence[int]) -> bytes | None:
    magic = tuple((b >> shift) & 1 for b in MAGIC for shift in range(7, -1, -1))
    for start in range(0, len(bits) - 80 + 1):
        if tuple(bits[start:start + 32]) != magic:
            continue
        header = _bits_bytes(bits[start:start + 80])
        length, expected = struct.unpack_from(">HI", header, 4)
        end = start + (10 + length) * 8
        if length > MAX_PAYLOAD or end > len(bits):
            continue
        blob = _bits_bytes(bits[start:end])
        body = blob[10:10 + length]
        if binascii.crc32(body) & 0xFFFFFFFF == expected:
            return body
    return None


def _bits_bytes_lsb(bits: Sequence[int]) -> bytes:
    out = bytearray()
    for at in range(0, len(bits) - 7, 8):
        out.append(sum((int(bit) & 1) << shift for shift, bit in enumerate(bits[at:at + 8])))
    return bytes(out)


def _candidates(method: str, bits: Sequence[int]) -> list[VideoCandidate]:
    if len(bits) < 24 or len(bits) > MAX_CARRIER_BITS:
        return []
    out: list[VideoCandidate] = []
    seen: set[tuple[bytes, str]] = set()

    def add(payload: bytes, check: str, proven: bool = False) -> None:
        key = (payload, check)
        if payload and key not in seen and len(out) < MAX_CANDIDATES:
            seen.add(key)
            out.append(VideoCandidate(method, payload, check, proven))

    proven = _payload(bits)
    if proven is not None:
        add(proven, "R5V1 length+CRC32", True)
    for inverted in (False, True):
        stream = [int(bit) ^ int(inverted) for bit in bits]
        polarity = "inverted " if inverted else ""
        for shift in range(8):
            aligned = stream[shift:]
            for order, pack in (("MSB", _bits_bytes), ("LSB", _bits_bytes_lsb)):
                blob = pack(aligned)
                for match in _FLAG.finditer(blob):
                    add(match.group(), f"{polarity}{order}-first flag shape")
                stripped = blob.rstrip(b"\x00\r\n")
                if len(stripped) >= 6 and all(0x20 <= byte <= 0x7E for byte in stripped):
                    add(stripped, f"{polarity}{order}-first wholly printable stream")
    return out


def decode_spatial_lsb(
    frames: Iterable,
    *,
    bit: int = 0,
    channels: Sequence[int] | None = None,
) -> bytes | None:
    """Concatenate selected spatial bit planes in frame/row/pixel/channel order."""
    arrays = _arrays(frames)
    if arrays is None or bit not in range(8):
        return None
    bits: list[int] = []
    for arr in arrays:
        chosen = tuple(range(arr.shape[2])) if channels is None else tuple(channels)
        if not chosen or any(c < 0 or c >= arr.shape[2] for c in chosen):
            return None
        plane = arr[:, :, chosen].reshape(-1)
        if len(bits) + plane.size > MAX_CARRIER_BITS:
            return None
        bits.extend(((plane >> bit) & 1).tolist())
    return _payload(bits)


def spatial_lsb_candidates(frames: Iterable, *, bit: int = 0,
                           channels: Sequence[int] | None = None) -> list[VideoCandidate]:
    arrays = _arrays(frames)
    if arrays is None or bit not in range(8):
        return []
    bits: list[int] = []
    for arr in arrays:
        chosen = tuple(range(arr.shape[2])) if channels is None else tuple(channels)
        if not chosen or any(c < 0 or c >= arr.shape[2] for c in chosen):
            return []
        plane = arr[:, :, chosen].reshape(-1)
        if len(bits) + plane.size > MAX_CARRIER_BITS:
            return []
        bits.extend(((plane >> bit) & 1).tolist())
    return _candidates("spatial-lsb", bits)


def decode_temporal_pixel(
    frames: Iterable,
    *,
    x: int = 0,
    y: int = 0,
    channel: int = 0,
    bit: int = 0,
) -> bytes | None:
    """Read one bit from a fixed pixel/channel in every frame."""
    arrays = _arrays(frames)
    if arrays is None or min(x, y, channel, bit) < 0 or bit > 7:
        return None
    bits = []
    for arr in arrays:
        if y >= arr.shape[0] or x >= arr.shape[1] or channel >= arr.shape[2]:
            return None
        bits.append((int(arr[y, x, channel]) >> bit) & 1)
    return _payload(bits)


def temporal_pixel_candidates(frames: Iterable, *, x: int = 0, y: int = 0,
                              channel: int = 0, bit: int = 0) -> list[VideoCandidate]:
    arrays = _arrays(frames)
    if arrays is None or min(x, y, channel, bit) < 0 or bit > 7:
        return []
    bits = []
    for arr in arrays:
        if y >= arr.shape[0] or x >= arr.shape[1] or channel >= arr.shape[2]:
            return []
        bits.append((int(arr[y, x, channel]) >> bit) & 1)
    return _candidates("temporal-pixel", bits)


def _two_means(values: np.ndarray) -> tuple[float, float] | None:
    if values.size < 8 or not np.all(np.isfinite(values)):
        return None
    low, high = float(values.min()), float(values.max())
    if high <= low + 1e-12:
        return None
    for _ in range(20):
        mid = (low + high) / 2
        a, b = values[values <= mid], values[values > mid]
        if not a.size or not b.size:
            return None
        nlow, nhigh = float(a.mean()), float(b.mean())
        if max(abs(nlow - low), abs(nhigh - high)) < 1e-9:
            low, high = nlow, nhigh
            break
        low, high = nlow, nhigh
    return low, high


def decode_mean_luma_ask(frames: Iterable, *, separation: float = 8.0) -> bytes | None:
    """Decode one bit per frame from two well-separated mean-luminance levels."""
    arrays = _arrays(frames)
    if arrays is None:
        return None
    means = np.asarray([float(arr[:, :, :min(3, arr.shape[2])].mean()) for arr in arrays])
    centers = _two_means(means)
    if centers is None or centers[1] - centers[0] < separation:
        return None
    threshold = sum(centers) / 2
    margin = (centers[1] - centers[0]) / 6
    if np.any(np.abs(means - threshold) < margin):
        return None
    return _payload((means > threshold).astype(np.uint8).tolist())


def mean_luma_candidates(frames: Iterable, *, separation: float = 8.0) -> list[VideoCandidate]:
    arrays = _arrays(frames)
    if arrays is None:
        return []
    means = np.asarray([float(arr[:, :, :min(3, arr.shape[2])].mean()) for arr in arrays])
    centers = _two_means(means)
    if centers is None or centers[1] - centers[0] < separation:
        return []
    threshold, margin = sum(centers) / 2, (centers[1] - centers[0]) / 6
    if np.any(np.abs(means - threshold) < margin):
        return []
    return _candidates("mean-luma-ask", (means > threshold).astype(np.uint8).tolist())


def decode_interframe_change_parity(
    frames: Iterable,
    *,
    channel: int = 0,
    max_changed: int = 64,
) -> bytes | None:
    """Use odd/even counts of changed channel samples between adjacent frames.

    Every transition must change between one and ``max_changed`` samples.  This
    check rejects static frames and ordinary high-motion video before CRC gating.
    """
    arrays = _arrays(frames)
    if arrays is None or len(arrays) < 2 or channel < 0 or max_changed < 1:
        return None
    shape = arrays[0].shape
    if any(arr.shape != shape or channel >= arr.shape[2] for arr in arrays):
        return None
    bits = []
    for previous, current in zip(arrays, arrays[1:]):
        changed = int(np.count_nonzero(previous[:, :, channel] != current[:, :, channel]))
        if changed < 1 or changed > max_changed:
            return None
        bits.append(changed & 1)
    return _payload(bits)


def interframe_change_candidates(frames: Iterable, *, channel: int = 0,
                                 max_changed: int = 64) -> list[VideoCandidate]:
    arrays = _arrays(frames)
    if arrays is None or len(arrays) < 2 or channel < 0 or max_changed < 1:
        return []
    shape = arrays[0].shape
    if any(arr.shape != shape or channel >= arr.shape[2] for arr in arrays):
        return []
    bits = []
    for previous, current in zip(arrays, arrays[1:]):
        changed = int(np.count_nonzero(previous[:, :, channel] != current[:, :, channel]))
        if changed < 1 or changed > max_changed:
            return []
        bits.append(changed & 1)
    return _candidates("interframe-change-parity", bits)


def decode_duplicate_runs(frames: Iterable) -> bytes | None:
    """Decode distinct-frame run lengths: one copy is 0, two copies is 1."""
    arrays = _arrays(frames)
    if arrays is None:
        return None
    shape = arrays[0].shape
    if any(arr.shape != shape for arr in arrays):
        return None
    lengths: list[int] = []
    run = 1
    for previous, current in zip(arrays, arrays[1:]):
        if np.array_equal(previous, current):
            run += 1
            if run > 2:
                return None
        else:
            lengths.append(run)
            run = 1
    lengths.append(run)
    if len(lengths) < 80 or any(length not in (1, 2) for length in lengths):
        return None
    return _payload([length - 1 for length in lengths])


def duplicate_run_candidates(frames: Iterable) -> list[VideoCandidate]:
    arrays = _arrays(frames)
    if arrays is None:
        return []
    shape = arrays[0].shape
    if any(arr.shape != shape for arr in arrays):
        return []
    lengths, run = [], 1
    for previous, current in zip(arrays, arrays[1:]):
        if np.array_equal(previous, current):
            run += 1
            if run > 2:
                return []
        else:
            lengths.append(run)
            run = 1
    lengths.append(run)
    if len(lengths) < 24 or any(length not in (1, 2) for length in lengths):
        return []
    return _candidates("duplicate-runs", [length - 1 for length in lengths])


def decode_video_depth(frames: Iterable) -> list[dict]:
    """Run a conservative battery; mark CRC results proven and others candidates."""
    arrays = _arrays(frames)
    if arrays is None:
        return []
    found: list[dict] = []
    seen: set[bytes] = set()

    def add(method: str, value: bytes | None, **parameters) -> None:
        if value is not None and value not in seen:
            seen.add(value)
            found.append({"method": method, "payload": value, "validated": "length+crc32", **parameters})

    def add_labeled(candidates: Sequence[VideoCandidate], **parameters) -> None:
        for candidate in candidates:
            if candidate.payload not in seen:
                seen.add(candidate.payload)
                found.append({"method": candidate.method, "payload": candidate.payload,
                              "validated": "length+crc32" if candidate.proven else False,
                              "check": candidate.check, **parameters})

    for bit in range(4):
        add("spatial-lsb", decode_spatial_lsb(arrays, bit=bit), bit=bit, channels="all")
        add_labeled(spatial_lsb_candidates(arrays, bit=bit), bit=bit, channels="all")
        for channel in range(arrays[0].shape[2]):
            add("spatial-lsb", decode_spatial_lsb(arrays, bit=bit, channels=(channel,)),
                bit=bit, channels=(channel,))
            add_labeled(spatial_lsb_candidates(arrays, bit=bit, channels=(channel,)),
                        bit=bit, channels=(channel,))
    for channel in range(arrays[0].shape[2]):
        for bit in range(2):
            add("temporal-pixel", decode_temporal_pixel(arrays, channel=channel, bit=bit),
                x=0, y=0, channel=channel, bit=bit)
            add_labeled(temporal_pixel_candidates(arrays, channel=channel, bit=bit),
                        x=0, y=0, channel=channel, bit=bit)
        add("interframe-change-parity", decode_interframe_change_parity(arrays, channel=channel),
            channel=channel)
        add_labeled(interframe_change_candidates(arrays, channel=channel), channel=channel)
    add("mean-luma-ask", decode_mean_luma_ask(arrays))
    add_labeled(mean_luma_candidates(arrays))
    add("duplicate-runs", decode_duplicate_runs(arrays))
    add_labeled(duplicate_run_candidates(arrays))
    return found


__all__ = [
    "VideoCandidate", "checked_frame", "decode_spatial_lsb", "spatial_lsb_candidates",
    "decode_temporal_pixel", "temporal_pixel_candidates", "decode_mean_luma_ask",
    "mean_luma_candidates", "decode_interframe_change_parity", "interframe_change_candidates",
    "decode_duplicate_runs", "duplicate_run_candidates", "decode_video_depth",
]
