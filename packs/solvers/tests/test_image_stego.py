"""Deterministic checked-carrier tests for image_stego.

Every decoder gets a positive carrier and an integrity-corrupt carrier which must
decline.  JPEG fixtures exercise the repository's independent entropy parser;
all other fixtures are lossless PNGs built in memory.
"""

from __future__ import annotations

import io
import struct
import zlib

import numpy as np
from PIL import Image

import f5_stego as shipped_f5
import jpeg_stego as shipped_jpeg
import image_stego as stego
from test_day26_stego_f5 import f5_carrier
from test_wave3_stego import jsteg_encode


PAYLOAD = b"r5e-checked-image"


def _container(payload=PAYLOAD):
    return struct.pack(">II", len(payload), zlib.crc32(payload) & 0xFFFFFFFF) + payload


def _corrupt(container):
    damaged = bytearray(container)
    damaged[7] ^= 0x01  # CRC field only: length and payload remain plausible
    return bytes(damaged)


def _bits(data):
    return [(byte >> shift) & 1 for byte in data for shift in range(7, -1, -1)]


def _png(array):
    buf = io.BytesIO()
    Image.fromarray(np.asarray(array, dtype=np.uint8)).save(buf, "PNG")
    return buf.getvalue()


def _payloads(candidates):
    return {candidate.payload for candidate in candidates}


def _dwt_carrier(container, wavelet="haar"):
    h = w = 64
    coeff = np.zeros((h, w), dtype=np.int32)
    coeff[: h // 2, : w // 2] = 128
    # Non-message details are even.  The HH coefficient parity is the stream.
    coeff[: h // 2, w // 2:] = 2
    coeff[h // 2:, : w // 2] = -2
    coeff[h // 2:, w // 2:] = 2
    hh = coeff[h // 2:, w // 2:].copy().reshape(-1)
    stream = _bits(container)
    assert len(stream) <= len(hh)
    for i, bit in enumerate(stream):
        hh[i] = 2 | bit
    coeff[h // 2:, w // 2:] = hh.reshape(h // 2, w // 2)
    inverse = {"haar": stego.haar_inverse2d, "cdf53": stego.cdf53_inverse2d}[wavelet]
    forward = {"haar": stego.haar_forward2d, "cdf53": stego.cdf53_forward2d}[wavelet]
    pixels = inverse(coeff)
    assert pixels is not None and pixels.min() >= 0 and pixels.max() <= 255
    # The independent forward transform must recover every integer coefficient.
    assert np.array_equal(forward(pixels), coeff)
    return _png(pixels)


def _spread_carrier(container, key=b"unit-key", chips=32):
    image = np.full((96, 96), 128, dtype=np.uint8)
    order, signs = stego.spread_layout(image.size, key, chips)
    stream = _bits(container)
    assert len(stream) * chips <= len(order)
    flat = image.reshape(-1)
    for bit_index, bit in enumerate(stream):
        polarity = 1 if bit else -1
        lo = bit_index * chips
        for j in range(chips):
            flat[order[lo + j]] = 128 + polarity * signs[lo + j] * 20
    return _png(image)


def _adaptive_carrier(container, seed=31337):
    rng = np.random.default_rng(seed)
    image = (rng.integers(24, 232, size=(80, 96), dtype=np.uint8) & 0xFE)
    coords = stego.adaptive_indices(image, 24)
    stream = _bits(container)
    assert len(stream) <= len(coords)
    for (y, x), bit in zip(coords, stream):
        image[y, x] = (int(image[y, x]) & 0xFE) | bit
    # Carrier selection is invariant under bit-zero changes.
    assert stego.adaptive_indices(image, 24) == coords
    return _png(image)


def _lsb_matching_carrier(container, seed=404, *, traversal="bottom-up",
                          channels=(2, 1, 0), nchannels=3):
    rng = np.random.default_rng(seed)
    image = rng.integers(8, 247, size=(48, 64, nchannels), dtype=np.uint8)
    indices = stego.spatial_indices(48, 64, nchannels, traversal, channels)
    stream = _bits(container)
    assert len(stream) <= len(indices)
    flat = image.reshape(-1)
    for index, bit in zip(indices, stream):
        value = int(flat[index])
        if (value & 1) != bit:
            flat[index] = value + 1 if value < 255 else value - 1
    return _png(image)


def test_dct_jsteg_checked_and_corrupt_declines():
    good = jsteg_encode(_container(), W=40, H=32)
    reference = shipped_jpeg.extract_jsteg(good)
    assert reference is not None and reference.startswith(_container())
    assert PAYLOAD in _payloads(stego.decode_dct(good))

    bad = jsteg_encode(_corrupt(_container()), W=40, H=32)
    assert PAYLOAD not in _payloads(stego.decode_dct(bad))
    assert stego.decode_dct(good[:len(good) // 2]) == []
    assert stego.decode_dct(b"not a jpeg") == []


def test_f5_matrix_checked_corrupt_and_library_crosscheck():
    # Cross-check the pure matrix operation against the shipped independent one.
    carriers = [((i * 11 + 3) >> (i % 5)) & 1 for i in range(500)]
    for k in range(1, 8):
        ours = stego.matrix_decode_bits(carriers, k)
        reference = shipped_f5.matrix_decode(carriers, k, max_bytes=len(ours) // 8)
        ours_bytes = stego._bits_to_bytes(ours, msb_first=True)
        assert ours_bytes[:len(reference)] == reference

    good = f5_carrier(_container(), 3, seed=19, nb=300)
    assert PAYLOAD in _payloads(stego.decode_f5(good))
    bad = f5_carrier(_corrupt(_container()), 3, seed=20, nb=300)
    assert PAYLOAD not in _payloads(stego.decode_f5(bad))
    assert stego.decode_f5(good[:len(good) // 2]) == []
    assert stego.decode_f5(b"\xff\xd8truncated") == []


def test_dwt_checked_and_corrupt_declines():
    for wavelet in ("haar", "cdf53"):
        good = _dwt_carrier(_container(), wavelet)
        assert PAYLOAD in _payloads(stego.decode_dwt(good))
        assert PAYLOAD not in _payloads(
            stego.decode_dwt(_dwt_carrier(_corrupt(_container()), wavelet))
        )
        assert stego.decode_dwt(good[:len(good) // 2]) == []
    assert stego.decode_dwt(b"not an image") == []


def test_spread_spectrum_checked_wrong_key_and_corrupt_decline():
    key = b"spread-test-key"
    good = _spread_carrier(_container(), key)
    hits = stego.decode_spread_spectrum(good, key)
    assert PAYLOAD in _payloads(hits)
    assert hits and hits[0].score > 0.9
    assert stego.decode_spread_spectrum(good, b"wrong-key") == []
    bad = _spread_carrier(_corrupt(_container()), key)
    assert PAYLOAD not in _payloads(stego.decode_spread_spectrum(bad, key))
    assert stego.decode_spread_spectrum(good[:len(good) // 2], key) == []


def test_adaptive_checked_and_corrupt_declines():
    good = _adaptive_carrier(_container())
    assert PAYLOAD in _payloads(stego.decode_adaptive(good))
    bad = _adaptive_carrier(_corrupt(_container()), seed=31338)
    assert PAYLOAD not in _payloads(stego.decode_adaptive(bad))
    assert stego.decode_adaptive(good[:len(good) // 2]) == []
    assert stego.decode_adaptive(np.zeros((2, 2), dtype=np.uint8)) == []


def test_lsb_matching_orders_checked_and_corrupt_decline():
    good = _lsb_matching_carrier(_container())
    assert PAYLOAD in _payloads(stego.decode_lsb_matching(good))
    bad = _lsb_matching_carrier(_corrupt(_container()), seed=405)
    assert PAYLOAD not in _payloads(stego.decode_lsb_matching(bad))
    assert stego.decode_lsb_matching(good[:len(good) // 2]) == []
    assert stego.decode_lsb_matching(b"broken") == []


def test_unverified_candidates_are_structural_and_labeled():
    raw_flag = b"CSCTF{r5e_Raw_LSB}"
    flag_carrier = _lsb_matching_carrier(
        raw_flag, seed=501, traversal="yx-reverse", channels=(3, 1), nchannels=4
    )
    flag_hits = [c for c in stego.decode_lsb_matching(flag_carrier)
                 if c.payload == raw_flag]
    assert flag_hits and all(not c.verified for c in flag_hits)
    assert all("flag syntax" in c.evidence for c in flag_hits)

    text = b"structured text candidate"
    framed_text = struct.pack(">I", len(text)) + text
    text_hits = [c for c in stego.decode_lsb_matching(
        _lsb_matching_carrier(framed_text, seed=502)
    ) if c.payload == text]
    assert text_hits and all(not c.verified for c in text_hits)
    assert all("length-prefixed" in c.evidence for c in text_hits)

    embedded_png = _png(np.array([[0, 255], [255, 0]], dtype=np.uint8))
    file_hits = [c for c in stego.decode_lsb_matching(
        _lsb_matching_carrier(embedded_png, seed=503)
    ) if c.payload == embedded_png]
    assert file_hits and all(not c.verified for c in file_hits)
    assert all("complete structure" in c.evidence for c in file_hits)


def test_parameter_guards_bounds_and_determinism():
    assert stego.matrix_decode_bits([0, 1], None) == bytearray()
    assert stego.matrix_decode_bits([0, 1], 8) == bytearray()
    assert stego.decode_dwt(np.zeros((8, 8), dtype=np.uint8), max_levels="bad") == []
    assert stego.decode_spread_spectrum(
        np.zeros((16, 16), dtype=np.uint8), b"k", chips_per_bit=3
    ) == []
    assert stego.decode_spread_spectrum(
        np.zeros((16, 16), dtype=np.uint8), b"k", min_correlation=float("nan")
    ) == []
    assert stego.decode_adaptive(
        np.zeros((8, 8), dtype=np.uint8), thresholds=[24] * 33
    ) == []
    assert stego.spatial_indices(3, 3, 3, "bad", (0,)) == []
    assert stego.spatial_indices(3, 3, 3, "xy", (4,)) == []
    assert len(stego.spatial_indices(100, 100, 3, "xy", (0, 1, 2), limit=17)) == 17

    first_order, first_signs = stego.spread_layout(4096, b"deterministic", 31)
    second_order, second_signs = stego.spread_layout(4096, b"deterministic", 31)
    assert list(first_order[:200]) == list(second_order[:200])
    assert list(first_signs[:200]) == list(second_signs[:200])
    assert len(set(first_order[:1000])) == 1000

    good = _adaptive_carrier(_container())
    assert stego.decode_adaptive(good) == stego.decode_adaptive(good)


def test_decode_all_deduplicates_and_never_claims_clean_noise():
    good = _adaptive_carrier(_container())
    hits = stego.decode_all(good)
    assert PAYLOAD in _payloads(hits)
    for seed in range(7, 11):
        noise = _png(np.random.default_rng(seed).integers(0, 256, (40, 40, 3), dtype=np.uint8))
        assert stego.decode_all(noise, spread_keys=(b"k",)) == []
