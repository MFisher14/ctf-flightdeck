#!/usr/bin/env python3
"""Checked, offline image-steganography extractors for the r5e lane.

The functions in this module are deliberately conservative.  A carrier stream is
only returned when :func:`stego_containers.validate_container` proves it with a
length/CRC pair or a checksum-bearing file container.  JPEG syntax, a large
correlation, or printable bytes alone are *not* payload evidence.

Covered families:

* baseline-JPEG DCT coefficient parity/sign streams (JSteg-style included),
* F5 negative-coefficient mapping and matrix decoding for k=1..7,
* reversible integer-Haar DWT detail-band parity,
* keyed direct-sequence spread spectrum,
* edge-adaptive spatial LSB streams, and
* exhaustive spatial-LSB/LSB-matching orders (matching and replacement have the
  same decoder).

All inputs are supplied bytes/paths/Pillow images/NumPy arrays; nothing is
executed and no file is written.  Optional image dependencies decline cleanly.
"""

from __future__ import annotations

import hashlib
import io
import itertools
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, Sequence

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

try:
    import numpy as np
except Exception:  # pragma: no cover - exercised on minimal deployments
    np = None

try:
    from PIL import Image
except Exception:  # pragma: no cover - exercised on minimal deployments
    Image = None

try:
    from . import jpeg_stego as _jpeg
    from . import stego_containers as _containers
except Exception:  # modules are commonly loaded directly from solvers/toolkits
    try:
        import jpeg_stego as _jpeg
        import stego_containers as _containers
    except Exception:  # pragma: no cover - graceful optional integration
        _jpeg = None
        _containers = None


MAX_PIXELS = 16_000_000
MAX_SOURCE_BYTES = 128 << 20
MAX_STREAM_BYTES = 1 << 20
MAX_JPEG_COEFFICIENTS = 16_000_000
MAX_CARRIER_BITS = MAX_STREAM_BYTES * 8 + 7
PROBE_BITS = 512 * 8 + 7
_TRAVERSALS = (
    "xy", "xy-reverse", "bottom-up", "reverse",
    "yx", "yx-bottom-up", "right-left", "yx-reverse",
)


@dataclass(frozen=True)
class StegoCandidate:
    """A checked payload or a clearly labeled structural candidate."""

    scheme: str
    payload: bytes
    evidence: str
    score: float = 1.0
    verified: bool = True


def _raw_bytes(source) -> bytes | None:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
        return data if len(data) <= MAX_SOURCE_BYTES else None
    if isinstance(source, (str, Path)):
        try:
            path = Path(source)
            if path.stat().st_size > MAX_SOURCE_BYTES:
                return None
            data = path.read_bytes()
            return data if len(data) <= MAX_SOURCE_BYTES else None
        except (OSError, ValueError, TypeError):
            return None
    return None


def _load_image(source):
    """Return (uint8 HxWxC array, mode, raw bytes or None), or None."""
    if np is None:
        return None
    if isinstance(source, np.ndarray):
        try:
            arr = np.asarray(source)
            raw = None
            if arr.ndim == 2:
                arr = arr[:, :, None]
                mode = "L"
            elif arr.ndim == 3 and arr.shape[2] in (1, 3, 4):
                mode = {1: "L", 3: "RGB", 4: "RGBA"}[arr.shape[2]]
            else:
                return None
            if arr.dtype != np.uint8:
                if arr.size and (int(arr.min()) < 0 or int(arr.max()) > 255):
                    return None
                arr = arr.astype(np.uint8)
        except (TypeError, ValueError, OverflowError):
            return None
    else:
        if Image is None:
            return None
        raw = _raw_bytes(source)
        try:
            if raw is not None:
                im = Image.open(io.BytesIO(raw))
            elif isinstance(source, Image.Image):
                im = source
            else:
                return None
            if im.width < 1 or im.height < 1 or im.width * im.height > MAX_PIXELS:
                return None
            if im.mode not in ("L", "RGB", "RGBA"):
                im = im.convert("RGB")
            im.load()
            mode = im.mode
            arr = np.asarray(im, dtype=np.uint8)
            if arr.ndim == 2:
                arr = arr[:, :, None]
        except Exception:
            return None
    if arr.shape[0] * arr.shape[1] > MAX_PIXELS or min(arr.shape[:2]) < 1:
        return None
    return np.ascontiguousarray(arr), mode, raw


def _bits_to_bytes(bits: Sequence[int], *, msb_first: bool, offset: int = 0) -> bytes:
    try:
        offset = int(offset)
    except (TypeError, ValueError, OverflowError):
        return b""
    if offset < 0:
        return b""
    available = max(0, min(len(bits) - offset, MAX_STREAM_BYTES * 8))
    nbytes = available // 8
    out = bytearray(nbytes)
    for i in range(nbytes * 8):
        b = int(bits[offset + i]) & 1
        if msb_first:
            out[i >> 3] |= b << (7 - (i & 7))
        else:
            out[i >> 3] |= b << (i & 7)
    return bytes(out)


_FLAG_PREFIX = flagfmt.BYTES


def _flag_prefix(blob: bytes) -> bytes | None:
    """Return an anchored event-format flag, including length-framed text."""
    starts = [blob]
    if len(blob) >= 4:
        for byteorder in ("big", "little"):
            length = int.from_bytes(blob[:4], byteorder)
            if 1 <= length <= min(512, len(blob) - 4):
                starts.append(blob[4:4 + length])
    for start in starts:
        match = _FLAG_PREFIX.match(start)
        if match:
            return bytes(match.group(0))
    return None


def _structured_text(blob: bytes, value) -> tuple[bytes, str] | None:
    try:
        text = value.encode("ascii") if isinstance(value, str) else bytes(value)
    except (UnicodeEncodeError, TypeError, ValueError):
        return None
    if not 4 <= len(text) <= 4096:
        return None
    if len(blob) >= len(text) + 4:
        for byteorder in ("big", "little"):
            if (int.from_bytes(blob[:4], byteorder) == len(text)
                    and blob[4:4 + len(text)] == text):
                return text, f"length-prefixed text ({byteorder}-endian; unverified)"
    if blob.startswith(text + b"\0"):
        return text, "NUL-terminated text (unverified)"
    return None


def _checked(blob: bytes, scheme: str, *, score: float = 1.0) -> StegoCandidate | None:
    if _containers is None or len(blob) < 8:
        return None
    try:
        finding = _containers.validate_container(blob)
    except Exception:
        return None
    if finding.plain is not None and finding.validated:
        return StegoCandidate(
            scheme, bytes(finding.plain), finding.method, float(score), verified=True
        )
    flag = _flag_prefix(blob)
    if flag is not None:
        return StegoCandidate(
            scheme, flag, "anchored CSCTF/CTF flag syntax (unverified)",
            float(score) * 0.75, verified=False,
        )
    for name, value in finding.candidates or ():
        if name == "carved_file" and isinstance(value, (bytes, bytearray, memoryview)):
            return StegoCandidate(
                scheme, bytes(value), f"{finding.method}; complete structure (unverified)",
                float(score) * 0.5, verified=False,
            )
        if name == "decoded_text":
            structured = _structured_text(blob, value)
            if structured is not None:
                payload, evidence = structured
                return StegoCandidate(
                    scheme, payload, evidence, float(score) * 0.5, verified=False
                )
    # A generic printable prefix is deliberately not enough across hundreds of
    # surveyed streams; it would produce routine false-positive candidates.
    return None


def _check_bits(bits: Sequence[int], scheme: str, *, score: float = 1.0,
                offsets: Iterable[int] = range(8)) -> list[StegoCandidate]:
    out = []
    for off in offsets:
        if len(bits) - off < 64:
            continue
        for msb in (True, False):
            hit = _checked(
                _bits_to_bytes(bits, msb_first=msb, offset=off),
                f"{scheme}; bit-offset={off}; {'msb' if msb else 'lsb'}-first",
                score=score,
            )
            if hit is not None:
                out.append(hit)
    return _dedupe(out)


_FILE_MAGICS = (
    b"\x1f\x8b", b"PK\x03\x04", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff",
    b"GIF87a", b"GIF89a", b"%PDF-", b"7z\xbc\xaf\x27\x1c", b"\x7fELF", b"MZ", b"RIFF",
)


def _needed_carrier_bits(bits: Sequence[int]) -> int:
    """Bounded second-stage length for a promising extracted prefix."""
    needed = min(len(bits), PROBE_BITS)
    for off in range(8):
        if len(bits) - off < 64:
            continue
        for msb in (True, False):
            blob = _bits_to_bytes(bits, msb_first=msb, offset=off)
            if blob.startswith(_FILE_MAGICS):
                needed = MAX_CARRIER_BITS
            if len(blob) >= 8:
                for byteorder in ("big", "little"):
                    length = int.from_bytes(blob[:4], byteorder)
                    if 1 <= length <= MAX_STREAM_BYTES:
                        needed = max(needed, off + (length + 12) * 8)
    return min(needed, MAX_CARRIER_BITS)


def _check_bit_iterator(bit_values: Iterable[int], scheme: str, *,
                        score: float = 1.0) -> list[StegoCandidate]:
    """Probe cheaply and consume a large stream only after a plausible header."""
    stream = iter(bit_values)
    bits = bytearray((int(value) & 1) for value in itertools.islice(stream, PROBE_BITS))
    hits = _check_bits(bits, scheme, score=score)
    if hits:
        return hits
    needed = _needed_carrier_bits(bits)
    if needed > len(bits):
        bits.extend((int(value) & 1) for value in itertools.islice(stream, needed - len(bits)))
        return _check_bits(bits, scheme, score=score)
    return []


def _dedupe(candidates: Iterable[StegoCandidate]) -> list[StegoCandidate]:
    best: dict[tuple[str, bytes], StegoCandidate] = {}
    for cand in candidates:
        key = (cand.scheme.split("; bit-offset=", 1)[0], cand.payload)
        old = best.get(key)
        if old is None or cand.score > old.score:
            best[key] = cand
    return sorted(best.values(), key=lambda c: (-c.score, c.scheme, c.payload))


# --- DCT / JPEG ---------------------------------------------------------------------------------


def _jpeg_blocks(raw: bytes):
    # A decoded prefix is not enough: the entropy helper intentionally returns
    # partial coefficients on truncation.  Require a real EOI marker before
    # considering any checked payload (trailing polyglot bytes remain allowed).
    if (_jpeg is None or not raw.startswith(b"\xff\xd8")
            or raw.find(b"\xff\xd9", 2) < 0):
        return None
    tags: list[int] = []
    try:
        coeffs = _jpeg._decode_coeffs(
            raw, limit_bits=MAX_JPEG_COEFFICIENTS, comp_out=tags
        )
    except Exception:
        return None
    nblocks = min(len(tags), len(coeffs) // 64)
    if nblocks < 1:
        return None
    return [coeffs[i * 64:(i + 1) * 64] for i in range(nblocks)], tags[:nblocks]


def decode_dct(source) -> list[StegoCandidate]:
    """Decode checked parity/sign streams from a baseline sequential JPEG.

    Progressive/arithmetic JPEGs and malformed entropy data decline.  Component
    splits, AC-only streams, JSteg's exact carrier rule, non-zero rules, parity,
    F5 sign-adjusted parity, and sign-only streams are surveyed.
    """
    raw = _raw_bytes(source)
    parsed = _jpeg_blocks(raw or b"")
    if parsed is None:
        return []
    blocks, tags = parsed
    results: list[StegoCandidate] = []
    comps = [("all", None)] + [(f"component-{i}", i) for i in sorted(set(tags))]
    rules = (
        ("jsteg", lambda c: c != 0 and c != 1),
        ("abs>1", lambda c: abs(c) > 1),
        ("nonzero", lambda c: c != 0),
    )
    for cname, comp in comps:
        for ac_only in (False, True):
            for rname, keep in rules:
                def selected_coefficients():
                    count = 0
                    for block, tag in zip(blocks, tags):
                        if comp is not None and tag != comp:
                            continue
                        start = 1 if ac_only else 0
                        for coefficient in block[start:]:
                            if keep(coefficient):
                                yield coefficient
                                count += 1
                                if count >= MAX_CARRIER_BITS:
                                    return

                mappings = (
                    ("parity", lambda c: c & 1),
                    ("f5-parity", lambda c: (c & 1) if c > 0 else 1 - (c & 1)),
                    ("sign", lambda c: 1 if c < 0 else 0),
                )
                for mname, mapping in mappings:
                    tag = f"dct/{cname}/{'ac' if ac_only else 'all'}/{rname}/{mname}"
                    results.extend(_check_bit_iterator(
                        (mapping(c) for c in selected_coefficients()), tag
                    ))
    return _dedupe(results)


def matrix_decode_bits(carrier_bits: Sequence[int], k: int, *, offset: int = 0,
                       max_bits: int = MAX_CARRIER_BITS) -> bytearray:
    """Decode F5's (1, n, k) matrix syndrome into message bits."""
    try:
        k, offset, size, max_bits = int(k), int(offset), len(carrier_bits), int(max_bits)
    except (TypeError, ValueError, OverflowError):
        return bytearray()
    if not 1 <= k <= 7 or offset < 0 or max_bits < 0:
        return bytearray()
    max_bits = min(max_bits, MAX_CARRIER_BITS)
    n = (1 << k) - 1
    groups = min(max(0, (size - offset) // n), (max_bits + k - 1) // k)
    out = bytearray()
    for group in range(groups):
        base = offset + group * n
        syndrome = 0
        for pos in range(n):
            try:
                if int(carrier_bits[base + pos]) & 1:
                    syndrome ^= pos + 1
            except (TypeError, ValueError, OverflowError, IndexError):
                return bytearray()
        out.extend((syndrome >> shift) & 1 for shift in range(k - 1, -1, -1))
        if len(out) >= max_bits:
            break
    return out[:max_bits]


def _keyed_permutation(size: int, key: bytes) -> list[int]:
    """Stable SHA-256-seeded Fisher-Yates permutation.

    This is useful for CTF variants.  Original Java-F5 password permutations can
    instead be supplied explicitly via ``permutation=``; we do not silently claim
    that a Python PRNG is Java SHA1PRNG compatible.
    """
    # A hash-counter Fisher-Yates is stable across Python versions.  Rejection
    # sampling avoids modulo bias; the bounded coefficient count caps memory.
    counter = 0
    pool = bytearray()

    def word64():
        nonlocal counter, pool
        if len(pool) < 8:
            pool.extend(hashlib.sha256(
                b"r5e-f5-shuffle\0" + key + counter.to_bytes(8, "big")
            ).digest())
            counter += 1
        value = int.from_bytes(pool[:8], "big")
        del pool[:8]
        return value

    def below(bound):
        ceiling = (1 << 64) - ((1 << 64) % bound)
        while True:
            value = word64()
            if value < ceiling:
                return value % bound

    order = list(range(size))
    for i in range(size - 1, 0, -1):
        j = below(i + 1)
        order[i], order[j] = order[j], order[i]
    return order


def decode_f5(source, *, key: bytes | str | None = None,
              permutation: Sequence[int] | None = None) -> list[StegoCandidate]:
    """Decode checked F5 matrix streams for k=1..7 from baseline JPEG ACs.

    The default is the unpermuted coefficient order.  A caller with an original
    F5/Java password permutation may pass its indices explicitly.  ``key`` opts
    into the documented r5e SHA-256 variant used by some CTF generators.
    """
    raw = _raw_bytes(source)
    parsed = _jpeg_blocks(raw or b"")
    if parsed is None:
        return []
    blocks, tags = parsed
    results: list[StegoCandidate] = []
    comps = [("all", None)] + [(f"component-{i}", i) for i in sorted(set(tags))]
    for cname, comp in comps:
        bits = bytearray()
        for block, tag in zip(blocks, tags):
            if comp is not None and tag != comp:
                continue
            for c in block[1:]:
                if c:
                    bits.append((c & 1) if c > 0 else 1 - (c & 1))
            if len(bits) >= MAX_JPEG_COEFFICIENTS:
                del bits[MAX_JPEG_COEFFICIENTS:]
                break
        if permutation is not None:
            try:
                if len(permutation) != len(bits):
                    continue
                order = []
                seen = bytearray(len(bits))
                for raw_index in permutation:
                    index = int(raw_index)
                    if index < 0 or index >= len(bits) or seen[index]:
                        order = []
                        break
                    seen[index] = 1
                    order.append(index)
                if len(order) != len(bits):
                    continue
                bits = [bits[i] for i in order]
                ptag = "explicit-permutation"
            except Exception:
                continue
        elif key is not None:
            try:
                kb = key.encode() if isinstance(key, str) else bytes(key)
            except (TypeError, ValueError, OverflowError):
                return []
            bits = [bits[i] for i in _keyed_permutation(len(bits), kb)]
            ptag = "r5e-sha256-permutation"
        else:
            ptag = "unpermuted"
        for k in range(1, 8):
            for skip in (0, 32):
                scheme = f"f5/{cname}/k={k}/{ptag}/skip={skip}"
                decoded = matrix_decode_bits(bits, k, offset=skip, max_bits=PROBE_BITS)
                hits = _check_bits(decoded, scheme)
                if hits:
                    results.extend(hits)
                    continue
                needed = _needed_carrier_bits(decoded)
                if needed > len(decoded):
                    decoded = matrix_decode_bits(bits, k, offset=skip, max_bits=needed)
                    results.extend(_check_bits(decoded, scheme))
    return _dedupe(results)


# --- reversible integer Haar DWT ----------------------------------------------------------------


def haar_forward2d(channel):
    """One-level reversible 2-D integer Haar lifting transform."""
    if np is None:
        return None
    src = np.asarray(channel, dtype=np.int32)
    if src.ndim != 2 or min(src.shape) < 2:
        return None
    h, w = src.shape[0] & ~1, src.shape[1] & ~1
    src = src[:h, :w].copy()
    row = np.empty_like(src)
    a, b = src[:, 0::2], src[:, 1::2]
    d = b - a
    row[:, :w // 2] = a + (d >> 1)
    row[:, w // 2:] = d
    out = np.empty_like(row)
    a, b = row[0::2, :], row[1::2, :]
    d = b - a
    out[:h // 2, :] = a + (d >> 1)
    out[h // 2:, :] = d
    return out


def haar_inverse2d(coefficients):
    """Inverse of :func:`haar_forward2d` (returns int32 values)."""
    if np is None:
        return None
    src = np.asarray(coefficients, dtype=np.int32)
    if src.ndim != 2 or min(src.shape) < 2 or any(n & 1 for n in src.shape):
        return None
    h, w = src.shape
    col = np.empty_like(src)
    s, d = src[:h // 2, :], src[h // 2:, :]
    a = s - (d >> 1)
    col[0::2, :], col[1::2, :] = a, d + a
    out = np.empty_like(col)
    s, d = col[:, :w // 2], col[:, w // 2:]
    a = s - (d >> 1)
    out[:, 0::2], out[:, 1::2] = a, d + a
    return out


def _cdf53_forward_1d(values):
    src = np.asarray(values, dtype=np.int32)
    even = src[0::2].copy()
    odd = src[1::2].copy()
    right = np.concatenate((even[1:], even[-1:]))
    detail = odd - ((even + right) >> 1)
    left_detail = np.concatenate((detail[:1], detail[:-1]))
    smooth = even + ((left_detail + detail + 2) >> 2)
    return np.concatenate((smooth, detail))


def _cdf53_inverse_1d(values):
    src = np.asarray(values, dtype=np.int32)
    half = len(src) // 2
    smooth, detail = src[:half], src[half:]
    left_detail = np.concatenate((detail[:1], detail[:-1]))
    even = smooth - ((left_detail + detail + 2) >> 2)
    right = np.concatenate((even[1:], even[-1:]))
    odd = detail + ((even + right) >> 1)
    out = np.empty_like(src)
    out[0::2], out[1::2] = even, odd
    return out


def cdf53_forward2d(channel):
    """One-level reversible CDF 5/3 integer transform (JPEG 2000 family)."""
    if np is None:
        return None
    src = np.asarray(channel, dtype=np.int32)
    if src.ndim != 2 or min(src.shape) < 2:
        return None
    h, w = src.shape[0] & ~1, src.shape[1] & ~1
    src = src[:h, :w]
    rows = np.vstack([_cdf53_forward_1d(row) for row in src])
    return np.vstack([_cdf53_forward_1d(rows[:, x]) for x in range(w)]).T


def cdf53_inverse2d(coefficients):
    """Inverse of :func:`cdf53_forward2d`."""
    if np is None:
        return None
    src = np.asarray(coefficients, dtype=np.int32)
    if src.ndim != 2 or min(src.shape) < 2 or any(n & 1 for n in src.shape):
        return None
    cols = np.vstack([_cdf53_inverse_1d(src[:, x]) for x in range(src.shape[1])]).T
    return np.vstack([_cdf53_inverse_1d(row) for row in cols])


def decode_dwt(source, *, max_levels: int = 3) -> list[StegoCandidate]:
    """Decode checked detail streams from multi-level Haar and CDF 5/3 DWTs."""
    loaded = _load_image(source)
    if loaded is None:
        return []
    try:
        max_levels = int(max_levels)
    except (TypeError, ValueError, OverflowError):
        return []
    if not 1 <= max_levels <= 16:
        return []
    arr, _mode, _raw = loaded
    results: list[StegoCandidate] = []
    for channel in range(arr.shape[2]):
        for wavelet, transform in (("haar", haar_forward2d), ("cdf53", cdf53_forward2d)):
            work = arr[:, :, channel].astype(np.int32)
            h, w = work.shape
            for level in range(1, max_levels + 1):
                h, w = h & ~1, w & ~1
                if min(h, w) < 2:
                    break
                coeff = transform(work[:h, :w])
                if coeff is None:
                    break
                work[:h, :w] = coeff
                bands = {
                    "HL": coeff[:h // 2, w // 2:],
                    "LH": coeff[h // 2:, :w // 2],
                    "HH": coeff[h // 2:, w // 2:],
                    "details": np.concatenate((coeff[:h // 2, w // 2:].ravel(),
                                                 coeff[h // 2:, :w // 2].ravel(),
                                                 coeff[h // 2:, w // 2:].ravel())),
                }
                for bname, band in bands.items():
                    values = np.asarray(band).ravel()[:MAX_CARRIER_BITS]
                    for name, bit_values in (
                        ("parity", (int(v) & 1 for v in values)),
                        ("nonzero-parity", (
                            int(v) & 1 for v in values if int(v) != 0
                        )),
                        ("sign", (1 if int(v) < 0 else 0 for v in values)),
                    ):
                        results.extend(_check_bit_iterator(
                            bit_values,
                            f"dwt/{wavelet}/level-{level}/channel-{channel}/{bname}/{name}",
                        ))
                h, w = h // 2, w // 2
    return _dedupe(results)


# --- keyed direct-sequence spread spectrum -------------------------------------------------------


class _AffineOrder(Sequence[int]):
    """O(1)-memory keyed permutation prefix over ``range(modulus)``."""

    def __init__(self, length: int, modulus: int, key: bytes):
        digest = hashlib.sha256(b"r5e-spread-order\0" + key).digest()
        candidate = int.from_bytes(digest[:8], "big") % modulus
        candidate = candidate or 1
        while math.gcd(candidate, modulus) != 1:
            candidate = (candidate + 1) % modulus or 1
        self._a = candidate
        self._b = int.from_bytes(digest[8:16], "big") % modulus
        self._length = length
        self._modulus = modulus

    def __len__(self):
        return self._length

    def __getitem__(self, item):
        if isinstance(item, slice):
            return [self[i] for i in range(*item.indices(self._length))]
        index = int(item)
        if index < 0:
            index += self._length
        if not 0 <= index < self._length:
            raise IndexError(index)
        return (self._a * index + self._b) % self._modulus


class _BalancedSigns(Sequence[int]):
    """O(1)-memory keyed, group-balanced PN chip sequence."""

    def __init__(self, length: int, chips_per_bit: int, key: bytes):
        self._length = length
        self._chips = chips_per_bit
        self._key = key
        self._last_group = -1
        self._last_params = (0, 0, 1)

    def __len__(self):
        return self._length

    def _params(self, group: int):
        if group != self._last_group:
            digest = hashlib.sha256(
                b"r5e-spread-sign\0" + self._key + group.to_bytes(8, "big")
            ).digest()
            self._last_group = group
            self._last_params = (
                int.from_bytes(digest[:4], "big") % self._chips,
                digest[4] & 1,
                1 if digest[5] & 1 else -1,
            )
        return self._last_params

    def __getitem__(self, item):
        if isinstance(item, slice):
            return [self[i] for i in range(*item.indices(self._length))]
        index = int(item)
        if index < 0:
            index += self._length
        if not 0 <= index < self._length:
            raise IndexError(index)
        group, local = divmod(index, self._chips)
        rotation, invert, odd_sign = self._params(group)
        position = (local + rotation) % self._chips
        half = self._chips // 2
        if position < half:
            sign = 1
        elif position < 2 * half:
            sign = -1
        else:
            sign = odd_sign
        return -sign if invert else sign


def spread_layout(size: int, key: bytes | str, chips_per_bit: int = 32):
    """Return the deterministic carrier order and balanced +/-1 chip signs."""
    try:
        size, chips_per_bit = int(size), int(chips_per_bit)
        kb = key.encode() if isinstance(key, str) else bytes(key)
    except (TypeError, ValueError, OverflowError):
        return [], []
    if not 4 <= chips_per_bit <= 4096 or not chips_per_bit <= size <= MAX_PIXELS:
        return [], []
    usable = (size // chips_per_bit) * chips_per_bit
    return _AffineOrder(usable, size, kb), _BalancedSigns(usable, chips_per_bit, kb)


def decode_spread_spectrum(source, key: bytes | str, *, chips_per_bit: int = 32,
                           min_correlation: float = 0.12) -> list[StegoCandidate]:
    """Decode a keyed DSSS stream from each image channel.

    Bits occupy non-overlapping pseudorandom pixels and use balanced PN chips.
    Besides the payload CRC, a median normalized correlation floor must hold.
    """
    loaded = _load_image(source)
    try:
        chips_per_bit = int(chips_per_bit)
        min_correlation = float(min_correlation)
    except (TypeError, ValueError, OverflowError):
        return []
    if (loaded is None or not 4 <= chips_per_bit <= 4096
            or not math.isfinite(min_correlation) or not 0.0 <= min_correlation <= 1.0):
        return []
    arr, _mode, _raw = loaded
    results: list[StegoCandidate] = []
    for channel in range(arr.shape[2]):
        flat = arr[:, :, channel].astype(np.int16).ravel()
        order, signs = spread_layout(len(flat), key, chips_per_bit)
        if not order:
            continue
        center = float(np.median(flat))
        max_groups = min(len(order) // chips_per_bit, MAX_STREAM_BYTES * 8)
        bits = bytearray()
        quality_prefix: list[float] = []

        def decode_groups(stop):
            start = len(bits)
            for group in range(start, min(stop, max_groups)):
                lo, hi = group * chips_per_bit, (group + 1) * chips_per_bit
                vals = flat[np.asarray(order[lo:hi], dtype=np.int64)] - center
                pn = np.asarray(signs[lo:hi], dtype=np.float64)
                corr = float(np.dot(vals, pn))
                denom = float(np.abs(vals).sum()) + 1e-9
                bits.append(1 if corr >= 0 else 0)
                if group < 64:
                    quality_prefix.append(abs(corr) / denom)

        decode_groups(PROBE_BITS)
        if len(bits) < 64:
            continue
        # The checked stream is prefix-framed; unused capacity after the payload is
        # cover noise and must not dilute a short message's correlation score.
        quality = float(np.median(quality_prefix))
        if not math.isfinite(quality) or quality < min_correlation:
            continue
        scheme = f"spread/dsss/channel-{channel}/chips={chips_per_bit}"
        hits = _check_bits(bits, scheme, score=quality)
        if hits:
            results.extend(hits)
            continue
        needed = _needed_carrier_bits(bits)
        if needed > len(bits):
            decode_groups(needed)
            results.extend(_check_bits(bits, scheme, score=quality))
    return _dedupe(results)


# --- spatial adaptive / LSB matching --------------------------------------------------------------


def _coordinates(height: int, width: int, traversal: str) -> Iterator[tuple[int, int]]:
    if traversal == "xy":
        yield from ((y, x) for y in range(height) for x in range(width))
    elif traversal == "xy-reverse":
        yield from ((y, x) for y in range(height) for x in range(width - 1, -1, -1))
    elif traversal == "yx":
        yield from ((y, x) for x in range(width) for y in range(height))
    elif traversal == "yx-bottom-up":
        yield from ((y, x) for x in range(width) for y in range(height - 1, -1, -1))
    elif traversal == "right-left":
        yield from ((y, x) for x in range(width - 1, -1, -1) for y in range(height))
    elif traversal == "yx-reverse":
        yield from ((y, x) for x in range(width - 1, -1, -1)
                    for y in range(height - 1, -1, -1))
    elif traversal == "reverse":
        yield from ((y, x) for y in range(height - 1, -1, -1)
                    for x in range(width - 1, -1, -1))
    elif traversal == "bottom-up":
        yield from ((y, x) for y in range(height - 1, -1, -1) for x in range(width))
    else:
        return


def _channel_orders(nchannels: int) -> list[tuple[int, ...]]:
    usable = min(4, nchannels)
    out: list[tuple[int, ...]] = []
    for length in range(1, usable + 1):
        out.extend(itertools.permutations(range(usable), length))
    return out


def spatial_indices(height: int, width: int, nchannels: int, traversal: str,
                    channels: Sequence[int], *, limit: int = MAX_CARRIER_BITS) -> list[int]:
    """Return a bounded spatial order; invalid shapes/orders decline with ``[]``."""
    try:
        height, width, nchannels, limit = (
            int(height), int(width), int(nchannels), int(limit)
        )
        selected = tuple(int(c) for c in channels)
    except (TypeError, ValueError, OverflowError):
        return []
    if (height < 1 or width < 1 or not 1 <= nchannels <= 4
            or traversal not in _TRAVERSALS or not selected
            or any(c < 0 or c >= nchannels for c in selected)
            or len(set(selected)) != len(selected) or limit < 0):
        return []
    stream = (((y * width + x) * nchannels + c)
              for y, x in _coordinates(height, width, traversal) for c in selected)
    return list(itertools.islice(stream, min(limit, MAX_CARRIER_BITS)))


def decode_lsb_matching(source) -> list[StegoCandidate]:
    """Survey LSB-matching/replacement streams across channel and scan orders."""
    loaded = _load_image(source)
    if loaded is None:
        return []
    arr, _mode, _raw = loaded
    h, w, nc = arr.shape
    flat = arr.ravel()
    results: list[StegoCandidate] = []
    for traversal in _TRAVERSALS:
        for channels in _channel_orders(nc):
            def samples():
                for y, x in _coordinates(h, w, traversal):
                    base = (y * w + x) * nc
                    for channel in channels:
                        yield int(flat[base + channel]) & 1

            stream = samples()
            bits = bytearray(itertools.islice(stream, PROBE_BITS))
            ctag = "".join(str(c) for c in channels)
            scheme = f"lsb-matching/{traversal}/channels={ctag}"
            hits = _check_bits(bits, scheme)
            if hits:
                results.extend(hits)
                continue
            needed = _needed_carrier_bits(bits)
            if needed > len(bits):
                bits.extend(itertools.islice(stream, needed - len(bits)))
                results.extend(_check_bits(bits, scheme))
    return _dedupe(results)


def adaptive_indices(channel, threshold: int = 24, *,
                     limit: int = MAX_CARRIER_BITS) -> list[tuple[int, int]]:
    """Stable edge carrier locations; gradients ignore bit 0."""
    if np is None:
        return []
    try:
        threshold, limit = int(threshold), int(limit)
        plane = np.asarray(channel, dtype=np.uint8)
    except (TypeError, ValueError, OverflowError):
        return []
    if plane.ndim != 2 or min(plane.shape) < 3:
        return []
    if not 0 <= threshold <= 1020 or limit < 0:
        return []
    limit = min(limit, MAX_CARRIER_BITS)
    stable = (plane & np.uint8(0xFE)).astype(np.int16)
    gx = np.abs(stable[:, 2:] - stable[:, :-2])
    gy = np.abs(stable[2:, :] - stable[:-2, :])
    score = np.zeros_like(stable, dtype=np.int16)
    score[:, 1:-1] += gx
    score[1:-1, :] += gy
    out: list[tuple[int, int]] = []
    for y in range(score.shape[0]):
        xs = np.flatnonzero(score[y] >= threshold)
        take = min(len(xs), limit - len(out))
        out.extend((y, int(x)) for x in xs[:take])
        if len(out) >= limit:
            break
    return out


def decode_adaptive(source, *, thresholds: Sequence[int] = (8, 16, 24, 32, 48, 64)) \
        -> list[StegoCandidate]:
    """Decode edge-adaptive bit-0 streams using LSB-stable gradients."""
    loaded = _load_image(source)
    if loaded is None:
        return []
    arr, _mode, _raw = loaded
    try:
        requested = list(thresholds)
        if len(requested) > 32:
            return []
        valid_thresholds = []
        for value in requested:
            threshold = int(value)
            if 0 <= threshold <= 1020 and threshold not in valid_thresholds:
                valid_thresholds.append(threshold)
    except (TypeError, ValueError, OverflowError):
        return []
    if not valid_thresholds:
        return []
    results: list[StegoCandidate] = []
    for channel in range(arr.shape[2]):
        plane = arr[:, :, channel]
        for threshold in valid_thresholds:
            coords = adaptive_indices(plane, threshold, limit=PROBE_BITS)
            bits = bytearray(int(plane[y, x]) & 1 for y, x in coords)
            scheme = f"adaptive/edge/channel-{channel}/threshold={threshold}"
            hits = _check_bits(bits, scheme)
            if hits:
                results.extend(hits)
                continue
            needed = _needed_carrier_bits(bits)
            if needed > len(bits):
                coords = adaptive_indices(plane, threshold, limit=needed)
                bits = bytearray(int(plane[y, x]) & 1 for y, x in coords)
                results.extend(_check_bits(bits, scheme))
    return _dedupe(results)


def decode_all(source, *, spread_keys: Sequence[bytes | str] = ()) -> list[StegoCandidate]:
    """Run every keyless decoder plus explicitly supplied spread-spectrum keys."""
    results: list[StegoCandidate] = []
    for decoder in (decode_dct, decode_f5, decode_dwt, decode_adaptive, decode_lsb_matching):
        try:
            results.extend(decoder(source))
        except Exception:
            continue
    for key in spread_keys:
        try:
            results.extend(decode_spread_spectrum(source, key))
        except Exception:
            continue
    return _dedupe(results)


__all__ = [
    "StegoCandidate", "decode_dct", "decode_f5", "decode_dwt",
    "decode_spread_spectrum", "decode_adaptive", "decode_lsb_matching",
    "decode_all", "matrix_decode_bits", "haar_forward2d", "haar_inverse2d",
    "cdf53_forward2d", "cdf53_inverse2d",
    "spread_layout", "spatial_indices", "adaptive_indices",
]
