"""Deterministic positive and corrupt/decline tests for video_stego_depth."""
from __future__ import annotations

import sys
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import video_stego_depth as video  # noqa: E402


def _bits(data: bytes) -> list[int]:
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _spatial(payload: bytes, *, corrupt: bool = False) -> list[np.ndarray]:
    rng = np.random.default_rng(20261104)
    frame = rng.integers(0, 256, (32, 32, 3), dtype=np.uint8)
    bits = _bits(video.checked_frame(payload))
    if corrupt:
        bits[-5] ^= 1
    flat = frame.reshape(-1)
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    return [frame]


def test_spatial_bitplane_checked_and_corrupt_declines():
    payload = b"spatial-video-lsb"
    assert video.decode_spatial_lsb(_spatial(payload)) == payload
    assert video.decode_spatial_lsb(_spatial(payload, corrupt=True)) is None
    assert video.decode_spatial_lsb([np.zeros((2, 2, 3), dtype=np.uint8)]) is None


def _temporal(payload: bytes, *, corrupt: bool = False) -> list[np.ndarray]:
    bits = _bits(video.checked_frame(payload))
    if corrupt:
        bits[-1] ^= 1
    frames = []
    for bit in bits:
        frame = np.full((2, 2, 3), 80, dtype=np.uint8)
        frame[1, 1, 2] = (frame[1, 1, 2] & 0xFE) | bit
        frames.append(frame)
    return frames


def test_temporal_fixed_pixel_checked_and_corrupt_declines():
    payload = b"pixel-clock"
    assert video.decode_temporal_pixel(_temporal(payload), x=1, y=1, channel=2) == payload
    assert video.decode_temporal_pixel(_temporal(payload, corrupt=True), x=1, y=1, channel=2) is None
    assert video.decode_temporal_pixel(_temporal(payload), x=99) is None


def _mean_frames(payload: bytes, *, corrupt: bool = False) -> list[np.ndarray]:
    bits = _bits(video.checked_frame(payload))
    if corrupt:
        bits[-8] ^= 1
    return [np.full((4, 4, 3), 210 if bit else 35, dtype=np.uint8) for bit in bits]


def test_frame_mean_ask_checked_and_corrupt_declines():
    payload = b"luma-ask"
    assert video.decode_mean_luma_ask(_mean_frames(payload)) == payload
    assert video.decode_mean_luma_ask(_mean_frames(payload, corrupt=True)) is None
    assert video.decode_mean_luma_ask([np.full((4, 4), 90, dtype=np.uint8)] * 100) is None


def _change_frames(payload: bytes, *, corrupt: bool = False) -> list[np.ndarray]:
    bits = _bits(video.checked_frame(payload))
    if corrupt:
        bits[-3] ^= 1
    current = np.zeros((8, 8, 1), dtype=np.uint8)
    frames = [current.copy()]
    for bit in bits:
        current = current.copy()
        count = 1 if bit else 2
        current.reshape(-1)[:count] ^= 1
        frames.append(current)
    return frames


def test_interframe_change_parity_checked_and_corrupt_declines():
    payload = b"motion-parity"
    assert video.decode_interframe_change_parity(_change_frames(payload)) == payload
    assert video.decode_interframe_change_parity(_change_frames(payload, corrupt=True)) is None
    static = [np.zeros((8, 8, 1), dtype=np.uint8) for _ in range(100)]
    assert video.decode_interframe_change_parity(static) is None


def _run_frames(payload: bytes, *, corrupt: bool = False) -> list[np.ndarray]:
    bits = _bits(video.checked_frame(payload))
    if corrupt:
        bits[-2] ^= 1
    frames = []
    for index, bit in enumerate(bits):
        frame = np.full((2, 2, 1), index & 0xFF, dtype=np.uint8)
        # Keep adjacent carriers distinct even at uint8 wrap.
        frame[0, 0, 0] = (index * 73) & 0xFF
        frames.extend([frame.copy()] * (bit + 1))
    return frames


def test_duplicate_run_channel_checked_and_corrupt_declines():
    payload = b"run-length"
    assert video.decode_duplicate_runs(_run_frames(payload)) == payload
    assert video.decode_duplicate_runs(_run_frames(payload, corrupt=True)) is None
    malformed = _run_frames(payload)
    malformed.insert(0, malformed[0].copy())  # first run now has three copies
    assert video.decode_duplicate_runs(malformed) is None


def test_depth_orchestrator_only_reports_validated_payloads():
    payload = b"battery-result"
    results = video.decode_video_depth(_spatial(payload))
    assert any(item["payload"] == payload and item["validated"] == "length+crc32" for item in results)
    assert video.decode_video_depth([np.zeros((8, 8, 3), dtype=np.uint8)]) == []


def test_real_flag_streams_surface_only_as_labeled_candidates():
    flag = b"CSCTF{VIDEO_RAW}"
    bits = _bits(flag)

    spatial = np.random.default_rng(17).integers(0, 256, (16, 16, 1), dtype=np.uint8)
    flat = spatial.reshape(-1)
    flat[:len(bits)] = (flat[:len(bits)] & 0xFE) | bits
    got = video.spatial_lsb_candidates([spatial])
    assert any(c.payload == flag and not c.proven and "flag shape" in c.check for c in got)
    assert video.decode_spatial_lsb([spatial]) is None

    temporal = []
    for bit in bits:
        frame = np.zeros((1, 1, 1), dtype=np.uint8)
        frame[0, 0, 0] = bit
        temporal.append(frame)
    assert any(c.payload == flag and not c.proven for c in video.temporal_pixel_candidates(temporal))
    assert video.decode_temporal_pixel(temporal) is None

    means = [np.full((2, 2, 1), 220 if bit else 20, dtype=np.uint8) for bit in bits]
    assert any(c.payload == flag for c in video.mean_luma_candidates(means))

    current = np.zeros((4, 4, 1), dtype=np.uint8)
    changes = [current.copy()]
    for bit in bits:
        current = current.copy()
        current.reshape(-1)[:1 if bit else 2] ^= 1
        changes.append(current)
    assert any(c.payload == flag for c in video.interframe_change_candidates(changes))

    runs = []
    for index, bit in enumerate(bits):
        frame = np.full((2, 2, 1), index & 0xFF, dtype=np.uint8)
        frame[0, 0, 0] = index * 73 & 0xFF
        runs.extend([frame.copy()] * (bit + 1))
    assert any(c.payload == flag for c in video.duplicate_run_candidates(runs))
    assert video.duplicate_run_candidates([np.zeros((2, 2, 1), dtype=np.uint8)] * 30) == []


def test_invalid_frame_types_and_caps_decline():
    assert video.decode_spatial_lsb([np.zeros((2, 2, 3), dtype=np.float64)]) is None
    assert video.decode_temporal_pixel([]) is None
    assert video.decode_duplicate_runs([np.zeros((2, 2), dtype=np.uint8),
                                        np.zeros((3, 2), dtype=np.uint8)]) is None
