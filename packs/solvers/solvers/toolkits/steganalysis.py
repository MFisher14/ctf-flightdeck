"""Bounded, offline image steganalysis over caller-supplied artifacts.

This module answers *which decoder should a human try?*; it never claims to have
recovered a payload.  Its public detectors validate the complete supplied image,
apply a named statistical/structural test, and return :class:`SteganalysisFinding`
only when that test crosses a conservative threshold.  Clean, malformed,
undersized, ambiguous, or resource-exhausting inputs return ``None``.

The spatial tests cover pairs-of-values chi-square, RS flipping, a conditional
sample-pair test, histogram pair equalisation, and visual LSB-plane structure.
JPEG tests cover recompression error localisation (ELA) and quantised DCT
coefficient anomalies.  Inputs are bytes, bytearray/memoryview, Pillow images, or
uint8 NumPy arrays already supplied by the caller; paths, subprocesses, temporary
files, and network access are intentionally absent.
"""

from __future__ import annotations

import io
import math
import numbers
from dataclasses import dataclass
from typing import Iterable

try:
    import numpy as np
except Exception:  # pragma: no cover - optional deployment dependency
    np = None

try:
    from PIL import Image
except Exception:  # pragma: no cover - optional deployment dependency
    Image = None

try:
    from . import jpeg_stego as _jpeg
except Exception:  # direct import under the test path
    try:
        import jpeg_stego as _jpeg  # type: ignore
    except Exception:  # pragma: no cover
        _jpeg = None


MAX_SOURCE_BYTES = 128 << 20
MAX_PIXELS = 16_000_000
MAX_DCT_COEFFICIENTS = 16_000_000
MAX_PREVIEW_SIDE = 64
MIN_STAT_SAMPLES = 2_048
MIN_DCT_SAMPLES = 1_024

_JPEG_LUMA_Q50 = (
    16, 11, 10, 16, 24, 40, 51, 61,
    12, 12, 14, 19, 26, 58, 60, 55,
    14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62,
    18, 22, 37, 56, 68, 109, 103, 77,
    24, 35, 55, 64, 81, 104, 113, 92,
    49, 64, 78, 87, 103, 121, 120, 101,
    72, 92, 95, 98, 112, 100, 103, 99,
)
_JPEG_CHROMA_Q50 = (
    17, 18, 24, 47, 99, 99, 99, 99,
    18, 21, 26, 66, 99, 99, 99, 99,
    24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99,
)


@dataclass(frozen=True, slots=True)
class SteganalysisFinding:
    """A checked diagnostic pointing at a likely steganography family.

    ``score`` is a detector-local 0..1 strength, not a probability that a
    payload exists.  ``metrics`` preserves the values needed to reproduce the
    decision.  ``preview`` is a bounded monochrome textual heat/bit plane.
    """

    method: str
    channel: str
    score: float
    samples: int
    evidence: str
    metrics: tuple[tuple[str, float], ...]
    preview: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class _PlaneInput:
    """One already-admitted intensity plane used by the orchestrator."""

    plane: object
    label: str
    fmt: str


@dataclass(frozen=True, slots=True)
class _JpegContext:
    raw: bytes
    image: object
    pixels: object
    source_quality: int | None
    coefficients: object
    component_tags: tuple[int, ...]
    expected_blocks: int


def _finite(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, numbers.Real):
        return None
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def _exact_int(value: object, low: int, high: int) -> int | None:
    if type(value) is not int:
        return None
    return value if low <= value <= high else None


def _raw(source: object) -> bytes | None:
    if not isinstance(source, (bytes, bytearray, memoryview)):
        return None
    try:
        size = source.nbytes if isinstance(source, memoryview) else len(source)
        if size < 1 or size > MAX_SOURCE_BYTES:
            return None
        data = bytes(source)
    except (TypeError, ValueError, BufferError):
        return None
    return data if 0 < len(data) <= MAX_SOURCE_BYTES else None


def _load(source: object):
    """Return ``(uint8 HxWxC, format, intensity labels)``, or ``None``.

    Palette, bilevel, high-depth, floating, CMYK, and YCbCr inputs are not
    silently converted: representation changes manufacture sample LSBs.  LA and
    RGBA are admitted for their L/RGB planes only; alpha is deliberately never a
    steganalysis channel because ordinary masks routinely look structured.
    """
    if np is None:
        return None
    raw = _raw(source)
    fmt = "array"
    if isinstance(source, np.ndarray):
        try:
            # Masked arrays/memmaps and arbitrary ndarray subclasses may carry
            # hidden validity or external-I/O semantics.  Require a concrete
            # in-memory ndarray; ordinary strided views remain supported.
            if type(source) is not np.ndarray:
                return None
            arr = np.asarray(source)
            if arr.ndim == 2:
                arr = arr[:, :, None]
            if (arr.ndim != 3 or arr.shape[2] not in (1, 3, 4)
                    or arr.dtype != np.uint8):
                return None
            if (arr.shape[0] < 1 or arr.shape[1] < 1
                    or arr.shape[0] * arr.shape[1] > MAX_PIXELS):
                return None
            if not arr.flags.c_contiguous:
                arr = np.ascontiguousarray(arr)
            labels = ("L",) if arr.shape[2] == 1 else ("R", "G", "B")
        except (TypeError, ValueError, MemoryError):
            return None
    elif Image is not None and isinstance(source, Image.Image):
        try:
            if (source.width < 1 or source.height < 1
                    or source.width * source.height > MAX_PIXELS
                    or getattr(source, "n_frames", 1) != 1):
                return None
            image = source.copy()
            image.load()
            if image.mode not in ("L", "LA", "RGB", "RGBA"):
                return None
            arr = np.asarray(image, dtype=np.uint8)
            if arr.ndim == 2:
                arr = arr[:, :, None]
            arr = np.ascontiguousarray(arr)
            fmt = (source.format or "image").upper()
            labels = ("L",) if image.mode in ("L", "LA") else ("R", "G", "B")
        except Exception:
            return None
    elif raw is not None and Image is not None:
        try:
            with Image.open(io.BytesIO(raw)) as image:
                fmt = (image.format or "image").upper()
                width, height = image.size
                if (width < 1 or height < 1 or width * height > MAX_PIXELS
                        or getattr(image, "n_frames", 1) != 1):
                    return None
                image.load()
                if image.mode not in ("L", "LA", "RGB", "RGBA"):
                    return None
                arr = np.asarray(image, dtype=np.uint8)
                if arr.ndim == 2:
                    arr = arr[:, :, None]
                arr = np.ascontiguousarray(arr)
                labels = ("L",) if image.mode in ("L", "LA") else ("R", "G", "B")
        except Exception:
            return None
    else:
        return None
    try:
        height, width, channels = map(int, arr.shape)
    except (TypeError, ValueError, OverflowError):
        return None
    if (height < 1 or width < 1 or channels not in (1, 2, 3, 4)
            or height * width > MAX_PIXELS):
        return None
    return arr, fmt, labels


def _meaningful_intensity(plane) -> bool:
    """Reject masks/flat quantized art that is not a meaningful intensity plane."""
    if not isinstance(plane, np.ndarray) or plane.dtype != np.uint8 or plane.ndim != 2:
        return False
    try:
        values = np.unique(plane)
    except (TypeError, ValueError, MemoryError):
        return False
    return (values.size >= 16 and int(values[-1]) - int(values[0]) >= 15
            and np.unique(values >> 1).size >= 8)


def _plane(source: object, channel: object):
    if type(source) is _PlaneInput:
        if channel != 0 or not _meaningful_intensity(source.plane):
            return None
        return source.plane, source.label, source.fmt
    loaded = _load(source)
    if loaded is None:
        return None
    arr, fmt, labels = loaded
    index = _exact_int(channel, 0, len(labels) - 1)
    if index is None:
        return None
    plane = arr[:, :, index]
    if not _meaningful_intensity(plane):
        return None
    return plane, f"{labels[index]}[{index}]", fmt


# Regularized upper incomplete gamma Q(a, x), used for a real chi-square tail.
# The series/continued fraction is the standard stable split from Numerical
# Recipes; it avoids making SciPy a runtime dependency.
def _gammaincc(a: float, x: float) -> float | None:
    if not (a > 0.0 and x >= 0.0 and math.isfinite(a) and math.isfinite(x)):
        return None
    if x == 0.0:
        return 1.0
    gln = math.lgamma(a)
    eps = 3.0e-14
    tiny = 1.0e-300
    if x < a + 1.0:
        total = term = 1.0 / a
        ap = a
        for _ in range(10_000):
            ap += 1.0
            term *= x / ap
            total += term
            if abs(term) <= abs(total) * eps:
                p = total * math.exp(-x + a * math.log(x) - gln)
                return min(1.0, max(0.0, 1.0 - p))
        return None
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / max(b, tiny)
    h = d
    for i in range(1, 10_001):
        an = -float(i) * (float(i) - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) <= eps:
            q = math.exp(-x + a * math.log(x) - gln) * h
            return min(1.0, max(0.0, q))
    return None


def _chi2_sf(statistic: float, degrees: int) -> float | None:
    if degrees < 1 or statistic < 0.0 or not math.isfinite(statistic):
        return None
    return _gammaincc(degrees / 2.0, statistic / 2.0)


def _metrics(**values: float) -> tuple[tuple[str, float], ...]:
    return tuple((key, float(values[key])) for key in sorted(values))


def _cover_smoothness(plane) -> float:
    """Upper-bit neighbour smoothness, independent of the possible payload LSB."""
    high = (np.asarray(plane, dtype=np.uint8) >> 1).astype(np.int16)
    differences = []
    if high.shape[1] > 1:
        differences.append(float(np.mean(np.abs(high[:, 1:] - high[:, :-1]))))
    if high.shape[0] > 1:
        differences.append(float(np.mean(np.abs(high[1:, :] - high[:-1, :]))))
    if not differences:
        return 0.0
    # Independent 7-bit noise has mean neighbour distance about 42.7 and thus
    # scores around .33; ordinary spatial covers retain a materially higher score.
    return max(0.0, min(1.0, 1.0 - sum(differences) / (64.0 * len(differences))))


def _lsb_pattern_entropy(plane) -> float:
    """Normalized entropy of overlapping 2x2 LSB patterns (0..1)."""
    bits = np.asarray(plane, dtype=np.uint8) & 1
    if bits.shape[0] < 2 or bits.shape[1] < 2:
        return 0.0
    codes = ((bits[:-1, :-1] << 3) | (bits[:-1, 1:] << 2)
             | (bits[1:, :-1] << 1) | bits[1:, 1:])
    counts = np.bincount(codes.reshape(-1), minlength=16).astype(np.float64)
    probabilities = counts[counts > 0] / counts.sum()
    entropy = -float(np.sum(probabilities * np.log2(probabilities))) / 4.0
    return max(0.0, min(1.0, entropy))


def _spatial_applicable(fmt: str) -> bool:
    # Pixel LSB statistics are meaningful only when stored sample values survive
    # decoding exactly.  JPEG has dedicated diagnostics below; GIF/paletted and
    # WebP inputs are deliberately not guessed here because decoding can replace
    # the stored representation.
    return fmt in {"array", "IMAGE", "PNG", "BMP", "TIFF", "TIF", "PPM", "PGM", "TGA"}


def chi_square_lsb(source: object, *, channel: object = 0,
                   min_samples: object = MIN_STAT_SAMPLES,
                   p_threshold: object = 0.995) -> SteganalysisFinding | None:
    """Pairs-of-values chi-square detector for spatial LSB replacement.

    LSB replacement equalises counts of values ``2k`` and ``2k+1``.  A finding
    requires enough occupied value pairs, a high real chi-square survival
    probability, and a near-balanced aggregate LSB stream.
    """
    got = _plane(source, channel)
    minimum = _exact_int(min_samples, 256, MAX_PIXELS)
    threshold = _finite(p_threshold)
    if got is None or minimum is None or threshold is None or not 0.9 <= threshold < 1.0:
        return None
    plane, label, fmt = got
    if not _spatial_applicable(fmt):
        return None
    flat = plane.reshape(-1)
    if flat.size < minimum:
        return None
    counts = np.bincount(flat, minlength=256).astype(np.float64)
    statistic = 0.0
    degrees = 0
    samples = 0
    for value in range(0, 256, 2):
        pair = float(counts[value] + counts[value + 1])
        if pair < 20.0:
            continue
        expected = pair / 2.0
        statistic += ((counts[value] - expected) ** 2
                      + (counts[value + 1] - expected) ** 2) / expected
        degrees += 1
        samples += int(pair)
    if degrees < 16 or samples < minimum:
        return None
    survival = _chi2_sf(statistic, degrees)
    ones = int(np.count_nonzero(flat & 1))
    balance = 1.0 - abs(2.0 * ones / flat.size - 1.0)
    smoothness = _cover_smoothness(plane)
    pattern_entropy = _lsb_pattern_entropy(plane)
    if (survival is None or survival < threshold or balance < 0.97
            or smoothness < 0.50 or pattern_entropy < 0.85):
        return None
    score = min(1.0, 0.7 * survival + 0.3 * balance)
    return SteganalysisFinding(
        "spatial-lsb-replacement/chi-square", label, score, samples,
        "pairs-of-values are significantly equalised with a balanced LSB stream",
        _metrics(chi_square=statistic, degrees=degrees, p_equalised=survival,
                 lsb_balance=balance, cover_smoothness=smoothness,
                 lsb_pattern_entropy=pattern_entropy),
    )


def histogram_pair_analysis(source: object, *, channel: object = 0,
                            min_samples: object = MIN_STAT_SAMPLES,
                            ratio_threshold: object = 0.38) -> SteganalysisFinding | None:
    """Detect even/odd histogram pairing relative to neighbouring pair movement."""
    got = _plane(source, channel)
    minimum = _exact_int(min_samples, 256, MAX_PIXELS)
    threshold = _finite(ratio_threshold)
    if got is None or minimum is None or threshold is None or not 0.05 <= threshold <= 0.8:
        return None
    plane, label, fmt = got
    if not _spatial_applicable(fmt):
        return None
    flat = plane.reshape(-1)
    if flat.size < minimum:
        return None
    hist = np.bincount(flat, minlength=256).astype(np.float64)
    occupied = (hist[0::2] + hist[1::2]) >= 20.0
    if int(np.count_nonzero(occupied)) < 16:
        return None
    within = np.abs(hist[0::2] - hist[1::2])[occupied]
    # Compare against changes between adjacent PoV pairs.  A natural histogram
    # may be smooth, but replacement specifically makes the within-pair steps
    # much smaller than the two surrounding steps.
    cross_all = np.abs(hist[1:255:2] - hist[2:256:2])
    cross_mask = occupied[:-1] & occupied[1:]
    cross = cross_all[cross_mask]
    if cross.size < 12:
        return None
    within_norm = float(np.median(within / np.maximum(
        1.0, (hist[0::2] + hist[1::2])[occupied]
    )))
    cross_den = np.maximum(1.0, (hist[1:255:2] + hist[2:256:2])[cross_mask])
    cross_norm = float(np.median(cross / cross_den))
    if cross_norm <= 1e-9:
        return None
    ratio = within_norm / cross_norm
    smoothness = _cover_smoothness(plane)
    pattern_entropy = _lsb_pattern_entropy(plane)
    if ratio > threshold or smoothness < 0.50 or pattern_entropy < 0.85:
        return None
    score = min(1.0, max(0.0, 1.0 - ratio))
    return SteganalysisFinding(
        "spatial-lsb-replacement/histogram-pairs", label, score, int(flat.size),
        "even/odd PoV steps are abnormally flatter than between-pair histogram steps",
        _metrics(within_pair=within_norm, between_pairs=cross_norm, ratio=ratio,
                 cover_smoothness=smoothness,
                 lsb_pattern_entropy=pattern_entropy),
    )


def _discrimination(groups) -> object:
    return np.abs(np.diff(groups.astype(np.int16), axis=1)).sum(axis=1)


def _flip_positive(values, mask):
    out = values.astype(np.int16).copy()
    selected = mask[None, :]
    out = np.where(selected, np.where((out & 1) == 0, out + 1, out - 1), out)
    return np.clip(out, 0, 255)


def _flip_negative(values, mask):
    out = values.astype(np.int16).copy()
    selected = mask[None, :]
    # F-1 maps even -> previous odd and odd -> next even.  At endpoints the
    # inverse flip is undefined, so callers remove endpoint-containing groups.
    out = np.where(selected, np.where((out & 1) == 0, out - 1, out + 1), out)
    return out


def rs_analysis(source: object, *, channel: object = 0,
                min_groups: object = 1_024,
                symmetry_threshold: object = 0.90) -> SteganalysisFinding | None:
    """RS regular/singular flipping diagnostic for LSB replacement/matching."""
    got = _plane(source, channel)
    minimum = _exact_int(min_groups, 128, MAX_PIXELS // 4)
    threshold = _finite(symmetry_threshold)
    if got is None or minimum is None or threshold is None or not 0.5 <= threshold < 1.0:
        return None
    plane, label, fmt = got
    if not _spatial_applicable(fmt):
        return None
    flat = plane.reshape(-1)
    group_count = flat.size // 4
    if group_count < minimum:
        return None
    groups = flat[:group_count * 4].reshape(group_count, 4)
    valid = np.all((groups > 0) & (groups < 255), axis=1)
    groups = groups[valid]
    if groups.shape[0] < minimum:
        return None
    mask = np.array([True, False, True, False], dtype=bool)
    base = _discrimination(groups)
    positive = _discrimination(_flip_positive(groups, mask))
    negative = _discrimination(_flip_negative(groups, mask))

    def counts(changed):
        regular = int(np.count_nonzero(changed > base))
        singular = int(np.count_nonzero(changed < base))
        return regular, singular

    rp, sp = counts(positive)
    rn, sn = counts(negative)
    decided = rp + sp + rn + sn
    if decided < minimum:
        return None
    symmetry = 1.0 - (abs(rp - sp) + abs(rn - sn)) / decided
    direction_agreement = 1.0 - (abs(rp - rn) + abs(sp - sn)) / decided
    lsb_balance = 1.0 - abs(2.0 * int(np.count_nonzero(groups & 1)) / groups.size - 1.0)
    smoothness = _cover_smoothness(plane)
    pattern_entropy = _lsb_pattern_entropy(plane)
    pov_support = chi_square_lsb(
        _PlaneInput(plane, label, fmt),
        min_samples=max(MIN_STAT_SAMPLES, minimum * 2), p_threshold=0.995
    )
    # Randomised LSBs collapse regular/singular separation for both inverse
    # flips.  Requiring all three guards rejects low-texture/one-sided covers.
    if (symmetry < threshold or direction_agreement < 0.88
            or lsb_balance < 0.97 or smoothness < 0.50
            or pattern_entropy < 0.85 or pov_support is None):
        return None
    score = min(1.0, (symmetry + direction_agreement + lsb_balance) / 3.0)
    return SteganalysisFinding(
        "spatial-lsb/rs-analysis", label, score, int(groups.shape[0]),
        "regular/singular counts collapse under both inverse LSB flips and PoV support",
        _metrics(R_positive=rp, S_positive=sp, R_negative=rn, S_negative=sn,
                 symmetry=symmetry, inverse_agreement=direction_agreement,
                 lsb_balance=lsb_balance, cover_smoothness=smoothness,
                 lsb_pattern_entropy=pattern_entropy,
                 pov_support_score=pov_support.score),
    )


def sample_pair_analysis(source: object, *, channel: object = 0,
                         min_pairs: object = MIN_STAT_SAMPLES,
                         p_threshold: object = 0.995) -> SteganalysisFinding | None:
    """Conditional adjacent-sample-pair test for randomized LSBs.

    Pairs whose upper seven bits match form a controlled sample: under LSB
    replacement their four low-bit states (00, 01, 10, 11) become uniform.
    Horizontal and vertical pairs must independently pass the uniformity test.
    """
    got = _plane(source, channel)
    minimum = _exact_int(min_pairs, 256, MAX_PIXELS)
    threshold = _finite(p_threshold)
    if got is None or minimum is None or threshold is None or not 0.9 <= threshold < 1.0:
        return None
    plane, label, fmt = got
    if not _spatial_applicable(fmt):
        return None
    if plane.shape[0] < 2 or plane.shape[1] < 2:
        return None
    smoothness = _cover_smoothness(plane)
    pattern_entropy = _lsb_pattern_entropy(plane)
    if smoothness < 0.50 or pattern_entropy < 0.85:
        return None
    results: list[tuple[float, int, float]] = []
    for left, right in ((plane[:, :-1], plane[:, 1:]),
                        (plane[:-1, :], plane[1:, :])):
        selected = (left >> 1) == (right >> 1)
        count = int(np.count_nonzero(selected))
        if count < minimum:
            return None
        states = (((left[selected] & 1) << 1) | (right[selected] & 1)).astype(np.uint8)
        bins = np.bincount(states, minlength=4).astype(np.float64)
        expected = count / 4.0
        statistic = float(np.sum((bins - expected) ** 2 / expected))
        survival = _chi2_sf(statistic, 3)
        if survival is None or survival < threshold:
            return None
        balance = 1.0 - float(np.max(np.abs(bins / count - 0.25))) * 4.0
        results.append((survival, count, max(0.0, balance)))
    score = min(1.0, sum((p + b) / 2.0 for p, _n, b in results) / len(results))
    return SteganalysisFinding(
        "spatial-lsb-replacement/sample-pairs", label, score,
        min(result[1] for result in results),
        "conditional horizontal and vertical sample-pair LSB states are uniform",
        _metrics(horizontal_p=results[0][0], vertical_p=results[1][0],
                 horizontal_pairs=results[0][1], vertical_pairs=results[1][1],
                 cover_smoothness=smoothness,
                 lsb_pattern_entropy=pattern_entropy),
    )


def _preview(bits, height: int, width: int) -> tuple[str, ...]:
    if height < 1 or width < 1:
        return ()
    out_h = min(height, MAX_PREVIEW_SIDE)
    out_w = min(width, MAX_PREVIEW_SIDE)
    y_edges = np.linspace(0, height, out_h + 1, dtype=np.int64)
    x_edges = np.linspace(0, width, out_w + 1, dtype=np.int64)
    lines = []
    for yi in range(out_h):
        row = []
        for xi in range(out_w):
            cell = bits[y_edges[yi]:y_edges[yi + 1], x_edges[xi]:x_edges[xi + 1]]
            density = float(cell.mean()) if cell.size else 0.0
            row.append("#" if density >= 0.5 else ".")
        lines.append("".join(row))
    return tuple(lines)


def lsb_plane_score(source: object, *, channel: object = 0,
                    bit: object = 0,
                    structure_threshold: object = 0.68) -> SteganalysisFinding | None:
    """Return a bounded bit-plane preview only for a strong spatial structure."""
    got = _plane(source, channel)
    bit_index = _exact_int(bit, 0, 7)
    threshold = _finite(structure_threshold)
    if got is None or bit_index is None or threshold is None or not 0.5 <= threshold < 1.0:
        return None
    plane, label, fmt = got
    if not _spatial_applicable(fmt):
        return None
    if plane.size < 1_024 or min(plane.shape) < 8:
        return None
    bits = ((plane >> bit_index) & 1).astype(np.uint8)
    density = float(bits.mean())
    if density <= 0.01 or density >= 0.99:
        return None
    horizontal = float(np.mean(bits[:, 1:] == bits[:, :-1])) if bits.shape[1] > 1 else 0.5
    vertical = float(np.mean(bits[1:, :] == bits[:-1, :])) if bits.shape[0] > 1 else 0.5
    # Random bits have agreement 0.5.  Visible masks/text/QR-like structure have
    # persistent regions/edges and substantially higher neighbour agreement.
    agreement = (horizontal + vertical) / 2.0
    density_balance = 1.0 - abs(2.0 * density - 1.0)
    structure = max(0.0, min(1.0, 2.0 * (agreement - 0.5)))
    # Extremely biased planes can look structured merely because almost every
    # sample is the same.  Keep at least moderate support for each bit value.
    adjusted = structure * min(1.0, density_balance / 0.35)
    if adjusted < threshold:
        return None
    return SteganalysisFinding(
        "spatial-bitplane/visual-structure", f"{label}/bit-{bit_index}", adjusted,
        int(bits.size), "LSB plane has non-random two-dimensional structure",
        _metrics(density=density, horizontal_agreement=horizontal,
                 vertical_agreement=vertical, structure=adjusted),
        _preview(bits, bits.shape[0], bits.shape[1]),
    )


def _strict_sos_offset(raw: bytes) -> int | None:
    """Validate a contiguous single-scan sequential JPEG header.

    Entropy exhaustion is checked by :func:`_decode_complete_jpeg`; this pass
    ensures the marker header itself contains no arbitrary skipped bytes and
    that the supplied object ends exactly at EOI.
    """
    if len(raw) < 8 or raw[:2] != b"\xff\xd8" or raw[-2:] != b"\xff\xd9":
        return None
    position = 2
    frames = 0
    while position < len(raw) - 2:
        if raw[position] != 0xFF:
            return None
        while position < len(raw) and raw[position] == 0xFF:
            position += 1
        if position >= len(raw):
            return None
        marker = raw[position]
        position += 1
        if marker in (0x00, 0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            return None
        if marker == 0x01:  # TEM is the only lengthless marker legal here.
            continue
        if position + 2 > len(raw) - 2:
            return None
        length = int.from_bytes(raw[position:position + 2], "big")
        if length < 2 or position + length > len(raw) - 2:
            return None
        segment_end = position + length
        if marker in {0xC0, 0xC1}:
            frames += 1
            if frames != 1:
                return None
        elif marker in {0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                        0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}:
            return None
        if marker == 0xDA:
            return segment_end if frames == 1 else None
        position = segment_end
    return None


def _decode_complete_jpeg(raw: bytes):
    """Decode every expected block and require only pad-one bits before exact EOI."""
    strict_offset = _strict_sos_offset(raw)
    if strict_offset is None or _jpeg is None or np is None:
        return None
    try:
        frame, scan, data_offset = _jpeg._parse(raw)
        if data_offset != strict_offset:
            return None
        components = frame["comps"]
        if (not isinstance(components, list) or not 1 <= len(components) <= 4
                or frame["w"] < 1 or frame["h"] < 1
                or frame["w"] * frame["h"] > MAX_PIXELS):
            return None
        ids = [component["id"] for component in components]
        if len(set(ids)) != len(ids):
            return None
        by_id = {component["id"]: component for component in components}
        if {component["id"] for component in scan["comps"]} != set(ids):
            return None
        if any(component["h"] not in range(1, 5) or component["v"] not in range(1, 5)
               or component["tq"] not in range(4) for component in components):
            return None
        hmax = max(component["h"] for component in components)
        vmax = max(component["v"] for component in components)
        mcu_x = (frame["w"] + 8 * hmax - 1) // (8 * hmax)
        mcu_y = (frame["h"] + 8 * vmax - 1) // (8 * vmax)
        expected_blocks = mcu_x * mcu_y * sum(
            by_id[component["id"]]["h"] * by_id[component["id"]]["v"]
            for component in scan["comps"]
        )
        expected_coefficients = expected_blocks * 64
        if (expected_blocks < 1 or expected_blocks > _jpeg.MAX_BLOCKS
                or expected_coefficients > MAX_DCT_COEFFICIENTS):
            return None

        decoded_scan = []
        for component in scan["comps"]:
            frame_component = by_id.get(component["id"])
            dc = scan["dc"].get(component["td"])
            ac = scan["ac"].get(component["ta"])
            if frame_component is None or dc is None or ac is None:
                return None
            decoded_scan.append((frame_component, dc, ac))
        reader = _jpeg._BitReader(raw, data_offset)
        predictors = {component["id"]: 0 for component in components}
        coefficients: list[int] = []
        tags: list[int] = []
        restart_interval = scan["dri"]
        total_mcus = mcu_x * mcu_y
        for mcu in range(total_mcus):
            if restart_interval and mcu and mcu % restart_interval == 0:
                if not reader.sync_restart():
                    return None
                for key in predictors:
                    predictors[key] = 0
            for component, dc_table, ac_table in decoded_scan:
                component_index = components.index(component)
                for _vertical in range(component["v"]):
                    for _horizontal in range(component["h"]):
                        block, dc_value = _jpeg._decode_one(
                            reader, dc_table, ac_table, predictors[component["id"]]
                        )
                        if block is None or dc_value is None or len(block) != 64:
                            return None
                        predictors[component["id"]] = dc_value
                        coefficients.extend(block)
                        tags.append(component_index)
        if len(tags) != expected_blocks or len(coefficients) != expected_coefficients:
            return None
        if reader.nbits:
            mask = (1 << reader.nbits) - 1
            if reader.acc & mask != mask:
                return None
            reader.nbits = 0
        if reader.marker is None:
            # A whole extra entropy byte is not padding; only the next exact EOI
            # marker may remain after the final block's <=7 one pad bits.
            if reader._next_byte() is not None:
                return None
        if reader.marker != 0xD9 or reader.pos != len(raw):
            return None
        coefficient_array = np.asarray(coefficients, dtype=np.int32)
        if coefficient_array.size != expected_coefficients:
            return None
        return frame, coefficient_array.reshape(expected_blocks, 64), tuple(tags)
    except Exception:
        return None


def _standard_table(base: tuple[int, ...], quality: int) -> tuple[int, ...]:
    scale = 5000 // quality if quality < 50 else 200 - 2 * quality
    return tuple(max(1, min(255, (value * scale + 50) // 100)) for value in base)


def _standard_jpeg_quality(
    tables: object,
    references: object = None,
) -> int | None:
    """Coherent IJG/Pillow quality across every referenced quantization table."""
    if not isinstance(tables, dict) or not tables:
        return None
    if references is None:
        references = tuple(
            (table_id, "luma" if table_id == 0 else "chroma")
            for table_id in sorted(tables)
        )
    if not isinstance(references, tuple) or not references:
        return None
    checked: list[tuple[tuple[int, ...], str]] = []
    for reference in references:
        if (not isinstance(reference, tuple) or len(reference) != 2
                or type(reference[0]) is not int or reference[1] not in {"luma", "chroma"}):
            return None
        table = tables.get(reference[0])
        if not isinstance(table, (list, tuple)) or len(table) != 64:
            return None
        try:
            actual = tuple(int(value) for value in table)
        except (TypeError, ValueError, OverflowError):
            return None
        if any(value < 1 or value > 255 for value in actual):
            return None
        checked.append((actual, reference[1]))
    matches = []
    for quality in range(1, 101):
        if all(actual == _standard_table(
            _JPEG_LUMA_Q50 if role == "luma" else _JPEG_CHROMA_Q50, quality
        ) for actual, role in checked):
            matches.append(quality)
    return matches[0] if len(matches) == 1 else None


def _jpeg_context(source: object) -> _JpegContext | None:
    raw = _raw(source)
    if raw is None or Image is None or np is None:
        return None
    decoded = _decode_complete_jpeg(raw)
    if decoded is None:
        return None
    frame, coefficients, tags = decoded
    references = tuple(
        (component["tq"], "luma" if index == 0 else "chroma")
        for index, component in enumerate(frame["comps"])
    )
    try:
        with Image.open(io.BytesIO(raw)) as verifier:
            if (verifier.format != "JPEG" or verifier.width != frame["w"]
                    or verifier.height != frame["h"] or verifier.mode not in ("L", "RGB")
                    or getattr(verifier, "n_frames", 1) != 1):
                return None
            verifier.verify()
        with Image.open(io.BytesIO(raw)) as opened:
            if opened.mode not in ("L", "RGB"):
                return None
            opened.load()
            source_quality = _standard_jpeg_quality(
                getattr(opened, "quantization", None), references
            )
            image = opened.copy()
            pixels = np.asarray(opened.convert("RGB"), dtype=np.int16)
    except Exception:
        return None
    return _JpegContext(raw, image, pixels, source_quality, coefficients, tags,
                        int(coefficients.shape[0]))


def _largest_component(mask) -> int:
    """Largest four-connected true component in a bounded 2-D boolean mask."""
    height, width = mask.shape
    seen = np.zeros(mask.shape, dtype=bool)
    largest = 0
    for y, x in np.argwhere(mask):
        y, x = int(y), int(x)
        if seen[y, x]:
            continue
        seen[y, x] = True
        stack = [(y, x)]
        size = 0
        while stack:
            cy, cx = stack.pop()
            size += 1
            for ny, nx in ((cy - 1, cx), (cy + 1, cx),
                           (cy, cx - 1), (cy, cx + 1)):
                if (0 <= ny < height and 0 <= nx < width
                        and mask[ny, nx] and not seen[ny, nx]):
                    seen[ny, nx] = True
                    stack.append((ny, nx))
        largest = max(largest, size)
    return largest


def _jpeg_ela_context(
    context: _JpegContext,
    q: int,
    threshold: float,
) -> SteganalysisFinding | None:
    image, original, source_quality = context.image, context.pixels, context.source_quality
    if image.width < 32 or image.height < 32:
        return None
    if source_quality is None or abs(source_quality - q) > 8:
        return None
    luminance = np.mean(original, axis=2).astype(np.uint8)
    smoothness = _cover_smoothness(luminance)
    if smoothness < 0.50:
        return None
    try:
        buffer = io.BytesIO()
        image.save(buffer, "JPEG", quality=q, optimize=False, progressive=False)
        buffer.seek(0)
        with Image.open(buffer) as recompressed_image:
            recompressed_image.load()
            recompressed = np.asarray(recompressed_image.convert("RGB"), dtype=np.int16)
    except Exception:
        return None
    error = np.mean(np.abs(original - recompressed), axis=2)
    height = error.shape[0] // 8
    width = error.shape[1] // 8
    if height * width < 16:
        return None
    blocks = error[:height * 8, :width * 8].reshape(height, 8, width, 8).mean(axis=(1, 3))
    median = float(np.median(blocks))
    mad = float(np.median(np.abs(blocks - median)))
    if median <= 0.05 or mad <= 0.01:
        return None
    robust_peak = (float(np.max(blocks)) - median) / (1.4826 * mad)
    q95 = float(np.quantile(blocks, 0.95))
    q50 = median
    hot = blocks >= (median + threshold * 1.4826 * mad)
    localized_fraction = float(np.mean(hot))
    largest_hot_region = _largest_component(hot)
    if (robust_peak < threshold or localized_fraction > 0.12
            or largest_hot_region < 2):
        return None
    scaled = hot.astype(np.uint8)
    score = min(1.0, robust_peak / (threshold * 2.0))
    return SteganalysisFinding(
        "jpeg/ela-localized-recompression", "RGB", score, int(blocks.size),
        "recompression error contains a robust localized block outlier",
        _metrics(median_error=q50, q95_error=q95, robust_peak=robust_peak,
                 hot_fraction=localized_fraction, recompress_quality=q,
                 cover_smoothness=smoothness,
                 largest_hot_region=largest_hot_region,
                 source_quality=source_quality),
        _preview(scaled, height, width),
    )


def jpeg_ela(source: object, *, quality: object = 90,
             localization_threshold: object = 3.5) -> SteganalysisFinding | None:
    """JPEG error-level localisation over one exact, fully exhausted JPEG."""
    q = _exact_int(quality, 50, 98)
    threshold = _finite(localization_threshold)
    if q is None or threshold is None or not 2.0 <= threshold <= 20.0:
        return None
    context = _jpeg_context(source)
    return _jpeg_ela_context(context, q, threshold) if context is not None else None


def _jpeg_dct_context(
    context: _JpegContext,
    minimum: int,
    threshold: float,
) -> SteganalysisFinding | None:
    smoothness = _cover_smoothness(np.mean(context.pixels, axis=2).astype(np.uint8))
    if smoothness < 0.50:
        return None
    matrix = context.coefficients
    if (not isinstance(matrix, np.ndarray) or matrix.dtype != np.int32
            or matrix.shape != (context.expected_blocks, 64)):
        return None
    ac_all = matrix[:, 1:].reshape(-1)
    ac = ac_all[(ac_all != 0) & (np.abs(ac_all) > 1)]
    if ac.size < minimum:
        return None
    parity = np.abs(ac) & 1
    ones = int(np.count_nonzero(parity))
    balance = 1.0 - abs(2.0 * ones / ac.size - 1.0)
    positive = int(np.count_nonzero(ac > 0))
    sign_balance = 1.0 - abs(2.0 * positive / ac.size - 1.0)
    magnitudes = np.abs(ac)
    cap = min(255, int(magnitudes.max(initial=0)))
    hist = np.bincount(np.minimum(magnitudes, 255), minlength=256).astype(np.float64)
    statistic = 0.0
    degrees = 0
    paired = 0
    for even in range(2, cap, 2):
        total = hist[even] + hist[even + 1]
        if total < 12:
            continue
        expected = total / 2.0
        statistic += float(((hist[even] - expected) ** 2
                            + (hist[even + 1] - expected) ** 2) / expected)
        degrees += 1
        paired += int(total)
    pair_p = _chi2_sf(statistic, degrees) if degrees >= 3 else None
    pair_hit = pair_p is not None and pair_p >= 0.99 and paired >= minimum // 2
    parity_hit = balance >= threshold and sign_balance >= 0.80
    if not (pair_hit or parity_hit):
        return None
    score = min(1.0, max(balance, pair_p or 0.0) * (0.8 + 0.2 * sign_balance))
    family = "jsteg-pairing" if pair_hit else "f5-or-parity-channel"
    return SteganalysisFinding(
        f"jpeg/dct-{family}", "all-components/AC", score, int(ac.size),
        "non-zero AC coefficient parity/magnitude distribution is stego-like",
        _metrics(parity_balance=balance, sign_balance=sign_balance,
                 pair_chi_square=statistic, pair_degrees=degrees,
                 pair_p_equalised=pair_p or 0.0, paired_coefficients=paired,
                 cover_smoothness=smoothness),
    )


def jpeg_dct_anomaly(source: object, *, min_coefficients: object = MIN_DCT_SAMPLES,
                     parity_threshold: object = 0.985) -> SteganalysisFinding | None:
    """Detect suspicious parity/histogram structure in one exact baseline JPEG."""
    minimum = _exact_int(min_coefficients, 256, MAX_DCT_COEFFICIENTS)
    threshold = _finite(parity_threshold)
    if minimum is None or threshold is None or not 0.9 <= threshold < 1.0:
        return None
    context = _jpeg_context(source)
    return _jpeg_dct_context(context, minimum, threshold) if context is not None else None


def analyze_image(source: object) -> tuple[SteganalysisFinding, ...]:
    """Run every applicable detector and return only checked, deduplicated findings."""
    findings: list[SteganalysisFinding] = []
    spatial_functions: Iterable = (
        chi_square_lsb, rs_analysis, sample_pair_analysis,
        histogram_pair_analysis, lsb_plane_score,
    )
    raw = _raw(source)
    if raw is not None and raw.startswith(b"\xff\xd8"):
        context = _jpeg_context(raw)
        if context is not None:
            try:
                finding = _jpeg_ela_context(context, 90, 3.5)
            except Exception:
                finding = None
            if isinstance(finding, SteganalysisFinding):
                findings.append(finding)
            try:
                finding = _jpeg_dct_context(context, MIN_DCT_SAMPLES, 0.985)
            except Exception:
                finding = None
            if isinstance(finding, SteganalysisFinding):
                findings.append(finding)
    else:
        try:
            loaded = _load(source)
        except Exception:
            loaded = None
        if loaded is not None:
            array, fmt, labels = loaded
            if _spatial_applicable(fmt):
                for channel, label in enumerate(labels):
                    plane_source = _PlaneInput(
                        array[:, :, channel], f"{label}[{channel}]", fmt
                    )
                    for function in spatial_functions:
                        try:
                            finding = function(plane_source)
                        except Exception:
                            finding = None
                        if isinstance(finding, SteganalysisFinding):
                            findings.append(finding)
    best: dict[tuple[str, str], SteganalysisFinding] = {}
    for finding in findings:
        key = (finding.method, finding.channel)
        old = best.get(key)
        if old is None or finding.score > old.score:
            best[key] = finding
    return tuple(sorted(best.values(), key=lambda item: (-item.score, item.method, item.channel)))


__all__ = [
    "SteganalysisFinding", "chi_square_lsb", "rs_analysis",
    "sample_pair_analysis", "histogram_pair_analysis", "lsb_plane_score",
    "jpeg_ela", "jpeg_dct_anomaly", "analyze_image",
]
