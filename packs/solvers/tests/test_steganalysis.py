"""Deterministic fail-closed tests for phase-3 image steganalysis."""

from __future__ import annotations

import io
import math

import numpy as np
import pytest
from PIL import Image

import steganalysis as S
from test_day26_stego_f5 import jpeg_from_blocks


def _png(array: np.ndarray) -> bytes:
    buffer = io.BytesIO()
    Image.fromarray(np.asarray(array, dtype=np.uint8)).save(buffer, "PNG")
    return buffer.getvalue()


def _jpeg(array: np.ndarray, quality: int = 92) -> bytes:
    buffer = io.BytesIO()
    Image.fromarray(np.asarray(array, dtype=np.uint8)).save(
        buffer, "JPEG", quality=quality, optimize=False, progressive=False
    )
    return buffer.getvalue()


def _spatial_cover_and_randomized_lsb() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(42)
    y, x = np.indices((256, 256))
    high = np.clip(
        30 + x // 5 + y // 7 + rng.normal(0, 2, (256, 256)), 0, 127
    ).astype(np.uint8)
    cover = (high << 1) | ((x + y) % 11 == 0).astype(np.uint8)
    randomized = (high << 1) | _balanced_random_lsb(high, seed=0)
    return cover, randomized


def _balanced_random_lsb(high: np.ndarray, *, seed: int) -> np.ndarray:
    """Random-looking bits, exactly balanced inside every PoV value pair."""
    bits = np.zeros(high.shape, dtype=np.uint8)
    generator = np.random.default_rng(seed)
    for value in np.unique(high):
        positions = np.flatnonzero(high.reshape(-1) == value)
        positions = generator.permutation(positions)
        bits.reshape(-1)[positions[: len(positions) // 2]] = 1
    return bits


def _visual_carrier(mask: np.ndarray) -> np.ndarray:
    y, x = np.indices(mask.shape)
    high = (32 + ((x // 4) + (y // 4)) % 32).astype(np.uint8)
    return (high << 1) | mask


def test_chi_square_real_tail_reference_and_pov_detection():
    # For chi-square with two degrees of freedom the survival function is e^-x/2.
    assert S._chi2_sf(2.0, 2) == pytest.approx(math.exp(-1.0), rel=1e-12)
    assert S._chi2_sf(0.0, 8) == 1.0

    y, x = np.indices((256, 256))
    high = ((y // 16) % 16 + 30).astype(np.uint8)
    clean = high << 1
    replaced = clean | _balanced_random_lsb(high, seed=1)
    finding = S.chi_square_lsb(_png(replaced))
    assert finding is not None
    assert finding.method == "spatial-lsb-replacement/chi-square"
    assert dict(finding.metrics)["p_equalised"] == 1.0
    assert S.chi_square_lsb(_png(clean)) is None


def _histogram_fixture(*, equalized: bool) -> np.ndarray:
    values: list[int] = []
    for index in range(16):
        each = 392 + 16 * index
        if equalized:
            even_count, odd_count = each, each
        else:
            even_count, odd_count = each + each // 2, each - each // 2
        values.extend([40 + 2 * index] * even_count)
        values.extend([41 + 2 * index] * odd_count)
    array = np.asarray(values, dtype=np.uint8)
    np.random.default_rng(9).shuffle(array)
    return array.reshape(128, 128)


def test_histogram_pair_equalization_and_natural_imbalance_decline():
    finding = S.histogram_pair_analysis(_histogram_fixture(equalized=True))
    assert finding is not None
    assert finding.method.endswith("histogram-pairs")
    assert dict(finding.metrics)["ratio"] == 0.0
    assert S.histogram_pair_analysis(_histogram_fixture(equalized=False)) is None


def test_rs_regular_singular_randomized_lsb_and_cover_decline():
    cover, randomized = _spatial_cover_and_randomized_lsb()
    finding = S.rs_analysis(randomized)
    assert finding is not None
    metrics = dict(finding.metrics)
    assert metrics["symmetry"] >= 0.90
    assert metrics["inverse_agreement"] >= 0.88
    assert S.rs_analysis(cover) is None


def test_conditional_sample_pair_analysis_and_correlated_decline():
    # PCG64 seed 2312 is uniform in both directions inside each of the 32
    # smoothly tiled upper-seven-bit intensity classes.
    y, x = np.indices((128, 128))
    high = (32 + ((y // 8) * 4 + (x // 8)) % 32).astype(np.uint8)
    bits = np.random.default_rng(2312).integers(0, 2, high.shape, dtype=np.uint8)
    replaced = (high << 1) | bits
    finding = S.sample_pair_analysis(replaced)
    assert finding is not None
    metrics = dict(finding.metrics)
    assert metrics["horizontal_p"] >= 0.995
    assert metrics["vertical_p"] >= 0.995

    correlated = high << 1
    correlated[:, 64:] |= 1
    assert S.sample_pair_analysis(correlated) is None


def test_lsb_plane_visual_score_preview_and_noise_decline():
    mask = np.zeros((128, 128), dtype=np.uint8)
    mask[16:112, 16:112] = 1
    mask[32:96, 32:96] = 0
    mask[48:80, 48:80] = 1
    carrier = _visual_carrier(mask)
    finding = S.lsb_plane_score(Image.fromarray(carrier))
    assert finding is not None
    assert finding.channel == "L[0]/bit-0"
    assert 1 <= len(finding.preview) <= S.MAX_PREVIEW_SIDE
    assert all(1 <= len(line) <= S.MAX_PREVIEW_SIDE for line in finding.preview)
    assert any("#" in line and "." in line for line in finding.preview)

    noise = np.random.default_rng(4).integers(0, 256, carrier.shape, dtype=np.uint8)
    assert S.lsb_plane_score(noise) is None


def _dct_pair_carrier() -> bytes:
    blocks = []
    for _ in range(400):
        ac = [0] * 63
        ac[:6] = [2, 3, 4, 5, 6, 7]
        blocks.append(ac)
    return jpeg_from_blocks(blocks, 160, 160)


def test_jpeg_dct_histogram_anomaly_and_complete_structure_gate():
    carrier = _dct_pair_carrier()
    finding = S.jpeg_dct_anomaly(carrier)
    assert finding is not None
    assert finding.method == "jpeg/dct-jsteg-pairing"
    assert dict(finding.metrics)["pair_p_equalised"] == 1.0

    y, x = np.indices((160, 160))
    clean_pixels = np.clip(50 + x // 2 + y // 3, 0, 255).astype(np.uint8)
    assert S.jpeg_dct_anomaly(_jpeg(clean_pixels)) is None
    assert S.jpeg_dct_anomaly(carrier[:-8]) is None
    assert S.jpeg_dct_anomaly(carrier[: len(carrier) // 2] + b"\xff\xd9") is None


def _ela_pair() -> tuple[bytes, bytes]:
    y, x = np.indices((128, 128))
    base = np.empty((128, 128, 3), dtype=np.uint8)
    base[:, :, 0] = x
    base[:, :, 1] = y
    base[:, :, 2] = 90

    patch_buffer = io.BytesIO()
    Image.fromarray(base[40:88, 40:88]).save(patch_buffer, "JPEG", quality=25)
    patch_buffer.seek(0)
    with Image.open(patch_buffer) as patch_image:
        patch_image.load()
        patch = np.asarray(patch_image.convert("RGB"), dtype=np.uint8)
    spliced = base.copy()
    spliced[40:88, 40:88] = patch
    return _jpeg(base, 96), _jpeg(spliced, 96)


def test_jpeg_ela_localization_and_clean_or_corrupt_decline():
    clean, spliced = _ela_pair()
    finding = S.jpeg_ela(spliced)
    assert finding is not None
    assert finding.method == "jpeg/ela-localized-recompression"
    assert dict(finding.metrics)["robust_peak"] >= 3.5
    assert dict(finding.metrics)["source_quality"] == 96
    assert finding.preview
    assert S.jpeg_ela(clean) is None
    assert S.jpeg_ela(spliced, quality=60) is None
    assert S.jpeg_ela(spliced[: len(spliced) // 2]) is None
    assert S.jpeg_ela(b"\xff\xd8not-a-jpeg\xff\xd9") is None


def test_white_noise_is_not_mislabeled_as_stego_or_ela():
    for seed in range(12):
        noise = np.random.default_rng(seed).integers(
            0, 256, (128, 128), dtype=np.uint8
        )
        for function in (
            S.chi_square_lsb, S.histogram_pair_analysis, S.rs_analysis,
            S.sample_pair_analysis, S.lsb_plane_score,
        ):
            assert function(noise) is None
        noisy_jpeg = _jpeg(np.repeat(noise[:, :, None], 3, axis=2), 96)
        assert S.jpeg_ela(noisy_jpeg) is None
        assert S.jpeg_dct_anomaly(noisy_jpeg) is None


@pytest.mark.parametrize(
    "function",
    [
        S.chi_square_lsb, S.histogram_pair_analysis, S.rs_analysis,
        S.sample_pair_analysis, S.lsb_plane_score, S.jpeg_ela,
        S.jpeg_dct_anomaly,
    ],
)
def test_every_detector_declines_wrong_types_and_truncated_images(function):
    good = _png(np.zeros((64, 64), dtype=np.uint8))
    for bad in (None, True, 7, 3.5, "image.png", object(), b"", good[:31]):
        assert function(bad) is None


def test_parameter_and_resource_caps_fail_closed(monkeypatch):
    image = np.zeros((64, 64), dtype=np.uint8)
    for function in (
        S.chi_square_lsb, S.histogram_pair_analysis, S.rs_analysis,
        S.sample_pair_analysis, S.lsb_plane_score,
    ):
        assert function(image, channel=True) is None
        assert function(image, channel=5) is None
    assert S.chi_square_lsb(image, min_samples=True) is None
    assert S.chi_square_lsb(image, p_threshold=float("nan")) is None
    assert S.rs_analysis(image, min_groups=10**30) is None
    assert S.sample_pair_analysis(image, p_threshold=1.0) is None
    assert S.lsb_plane_score(image, bit=-1) is None
    assert S.jpeg_ela(_dct_pair_carrier(), quality=90.0) is None
    assert S.jpeg_dct_anomaly(_dct_pair_carrier(), min_coefficients=True) is None

    monkeypatch.setattr(S, "MAX_PIXELS", 100)
    oversized = np.zeros((11, 10), dtype=np.uint8)
    assert S.analyze_image(oversized) == ()


def test_orchestrator_returns_only_findings_and_is_deterministic():
    mask = np.zeros((64, 64), dtype=np.uint8)
    mask[8:56, 8:56] = 1
    mask[20:44, 20:44] = 0
    carrier = _visual_carrier(mask)
    first = S.analyze_image(carrier)
    second = S.analyze_image(carrier)
    assert first == second
    assert first
    assert all(isinstance(item, S.SteganalysisFinding) for item in first)
    assert any(item.method == "spatial-bitplane/visual-structure" for item in first)
    assert S.analyze_image(b"corrupt") == ()


@pytest.mark.parametrize(
    "bad", [True, "0.95", object(), float("nan"), float("inf"), -float("inf")]
)
def test_all_public_scalar_boundaries_reject_wrong_types_and_nonfinite(bad):
    image = np.zeros((64, 64), dtype=np.uint8)
    jpeg = _dct_pair_carrier()
    assert S.chi_square_lsb(image, min_samples=bad) is None
    assert S.chi_square_lsb(image, p_threshold=bad) is None
    assert S.histogram_pair_analysis(image, min_samples=bad) is None
    assert S.histogram_pair_analysis(image, ratio_threshold=bad) is None
    assert S.rs_analysis(image, min_groups=bad) is None
    assert S.rs_analysis(image, symmetry_threshold=bad) is None
    assert S.sample_pair_analysis(image, min_pairs=bad) is None
    assert S.sample_pair_analysis(image, p_threshold=bad) is None
    assert S.lsb_plane_score(image, bit=bad) is None
    assert S.lsb_plane_score(image, structure_threshold=bad) is None
    assert S.jpeg_ela(jpeg, quality=bad) is None
    assert S.jpeg_ela(jpeg, localization_threshold=bad) is None
    assert S.jpeg_dct_anomaly(jpeg, min_coefficients=bad) is None
    assert S.jpeg_dct_anomaly(jpeg, parity_threshold=bad) is None


def test_array_shape_dtype_subclass_and_noncontiguous_boundaries():
    _cover, carrier = _spatial_cover_and_randomized_lsb()
    contiguous = S.chi_square_lsb(carrier)
    assert contiguous is not None

    # Safe ordinary strided and read-only arrays are copied and analyzed.
    reversed_view = carrier[:, ::-1]
    assert not reversed_view.flags.c_contiguous
    assert S.chi_square_lsb(reversed_view) is not None
    readonly = carrier.copy()
    readonly.flags.writeable = False
    assert S.chi_square_lsb(readonly) is not None

    # Hidden masks, external/subclass semantics, malformed ranks/channels and
    # implicit numeric conversion all decline rather than being guessed.
    masked = np.ma.array(carrier, mask=np.zeros(carrier.shape, dtype=bool))
    class ArraySubclass(np.ndarray):
        pass
    subclass = carrier.view(ArraySubclass)
    bad_arrays = (
        masked, subclass, carrier.astype(np.uint16), carrier.astype(np.float32),
        carrier.reshape(-1), carrier[:, :, None, None],
        np.zeros((16, 16, 5), dtype=np.uint8),
        np.zeros((0, 16), dtype=np.uint8),
        np.array([[object()]], dtype=object),
    )
    for bad in bad_arrays:
        assert S.analyze_image(bad) == ()

    # A zero-stride view is bounded and deterministic; its flat plane declines.
    zero_stride = np.lib.stride_tricks.as_strided(
        np.array([128], dtype=np.uint8), shape=(64, 64), strides=(0, 0)
    )
    assert S.analyze_image(zero_stride) == ()


def test_source_byte_and_decoded_dimension_caps_precede_materialization(monkeypatch):
    image = np.zeros((11, 10), dtype=np.uint8)
    encoded = _png(image)
    monkeypatch.setattr(S, "MAX_PIXELS", 100)
    assert S.analyze_image(image) == ()
    assert S.analyze_image(encoded) == ()
    assert S.chi_square_lsb(encoded) is None

    monkeypatch.setattr(S, "MAX_SOURCE_BYTES", 16)
    view = memoryview(bytearray(1_024))
    assert S.analyze_image(view) == ()
    assert S.jpeg_ela(view) is None


def test_multiframe_and_representation_changing_images_decline_spatial_tests():
    first = Image.fromarray(np.zeros((64, 64), dtype=np.uint8))
    second = Image.fromarray(np.full((64, 64), 255, dtype=np.uint8))
    buffer = io.BytesIO()
    first.save(buffer, "GIF", save_all=True, append_images=[second], loop=0)
    animated = buffer.getvalue()
    assert S.analyze_image(animated) == ()
    with Image.open(io.BytesIO(animated)) as opened:
        assert getattr(opened, "n_frames", 1) == 2
        assert S.analyze_image(opened) == ()

    # Even a single-frame palette/lossy representation is not a pixel-LSB
    # carrier after conversion, so the spatial family remains inapplicable.
    single_gif = io.BytesIO()
    first.save(single_gif, "GIF")
    assert S.analyze_image(single_gif.getvalue()) == ()


def _replace_marker(data: bytes, old: bytes, new: bytes) -> bytes:
    position = data.find(old)
    assert position >= 0
    return data[:position] + new + data[position + len(old):]


def test_progressive_arithmetic_multiscan_and_fake_truncation_decline_dct():
    y, x = np.indices((160, 160))
    gradient = np.clip(30 + x // 2 + y // 3, 0, 255).astype(np.uint8)
    progressive_buffer = io.BytesIO()
    Image.fromarray(gradient).save(
        progressive_buffer, "JPEG", quality=90, progressive=True
    )
    progressive = progressive_buffer.getvalue()
    # Progressive JPEGs use multiple scans.  ELA remains applicable but the
    # clean carrier has no localized anomaly; quantized DCT parsing declines.
    assert progressive.count(b"\xff\xda") > 1
    assert S.jpeg_dct_anomaly(progressive) is None
    assert S.jpeg_ela(progressive) is None

    baseline = _jpeg(gradient, 90)
    arithmetic_claim = _replace_marker(baseline, b"\xff\xc0", b"\xff\xc9")
    assert S.jpeg_dct_anomaly(arithmetic_claim) is None
    assert S.jpeg_ela(arithmetic_claim) is None

    carrier = _dct_pair_carrier()
    for cut in (len(carrier) // 2, len(carrier) - 32, len(carrier) - 3):
        forged_eoi = carrier[:cut] + b"\xff\xd9"
        assert S.jpeg_dct_anomaly(forged_eoi) is None
        assert S.jpeg_ela(forged_eoi) is None


def test_ela_clean_quality_and_color_modes_are_not_findings():
    y, x = np.indices((128, 128))
    gradient = np.clip(20 + x + y // 2, 0, 255).astype(np.uint8)
    samples = {
        "L": gradient,
        "RGB": np.repeat(gradient[:, :, None], 3, axis=2),
        "CMYK": np.repeat(gradient[:, :, None], 4, axis=2),
    }
    for mode, array in samples.items():
        for quality in (60, 75, 90, 96):
            buffer = io.BytesIO()
            Image.fromarray(array, mode=mode).save(buffer, "JPEG", quality=quality)
            with Image.open(io.BytesIO(buffer.getvalue())) as parsed:
                assert S._standard_jpeg_quality(parsed.quantization) == quality
            assert S.jpeg_ela(buffer.getvalue()) is None

    custom = io.BytesIO()
    Image.fromarray(gradient).save(custom, "JPEG", qtables=[[2] * 64])
    with Image.open(io.BytesIO(custom.getvalue())) as parsed:
        assert S._standard_jpeg_quality(parsed.quantization) is None
    assert S.jpeg_ela(custom.getvalue()) is None


def test_flat_gradient_and_photo_like_clean_covers_decline_every_detector():
    y, x = np.indices((256, 256))
    flat = np.full((256, 256), 128, dtype=np.uint8)
    gradient = ((x + y) // 2).astype(np.uint8)
    base = 80 + 60 * np.sin(x / 40) + 40 * np.cos(y / 35)
    photo = np.clip(
        base + np.random.default_rng(123).normal(0, 8, base.shape), 0, 255
    ).astype(np.uint8)
    spatial = (
        S.chi_square_lsb, S.histogram_pair_analysis, S.rs_analysis,
        S.sample_pair_analysis, S.lsb_plane_score,
    )
    for cover in (flat, gradient, photo):
        assert all(function(cover) is None for function in spatial)
        assert S.analyze_image(cover) == ()

    photo_jpeg = _jpeg(np.repeat(photo[:, :, None], 3, axis=2), 92)
    assert all(function(photo_jpeg) is None for function in spatial)
    assert S.jpeg_ela(photo_jpeg) is None
    assert S.jpeg_dct_anomaly(photo_jpeg) is None
    assert S.analyze_image(photo_jpeg) == ()


def test_orchestrator_surveys_all_channels_with_stable_global_order():
    _cover, hidden = _spatial_cover_and_randomized_lsb()
    y, x = np.indices(hidden.shape)
    clean = ((x + y) // 2).astype(np.uint8)
    rgb = np.stack((clean, clean, hidden), axis=2)
    first = S.analyze_image(rgb)
    second = S.analyze_image(rgb.copy())
    assert first == second
    assert first
    assert {item.channel for item in first} == {"B[2]"}
    assert list(first) == sorted(
        first, key=lambda item: (-item.score, item.method, item.channel)
    )
    assert all(not hasattr(item, "payload") for item in first)
    assert all("payload" not in item.evidence.lower() for item in first)


def _encoded(image: Image.Image, fmt: str, **options) -> bytes:
    output = io.BytesIO()
    image.save(output, fmt, **options)
    return output.getvalue()


def test_representation_changing_modes_and_ordinary_alpha_masks_decline():
    y, x = np.indices((128, 128))
    binary = ((x // 16 + y // 16) & 1).astype(np.uint8) * 255

    bilevel = Image.fromarray(binary, "L").convert("1")
    palette = Image.fromarray(binary, "P")
    palette.putpalette([value for index in range(256) for value in (index, index, index)])
    high_depth = Image.fromarray((x * 257).astype(np.uint16), "I;16")
    integer_mode = Image.fromarray((x * 257).astype(np.int32), "I")
    cmyk = Image.fromarray(np.repeat(binary[:, :, None], 4, axis=2), "CMYK")
    encoded = (
        _encoded(bilevel, "PNG"), _encoded(palette, "PNG"),
        _encoded(high_depth, "PNG"), _encoded(integer_mode, "TIFF"),
        _encoded(cmyk, "TIFF"),
    )
    for artifact in encoded:
        assert S.analyze_image(artifact) == ()
        assert S.lsb_plane_score(artifact) is None

    # RGBA/LA may carry valid intensity samples, but alpha is never surveyed:
    # ordinary transparency masks are representation, not stego evidence.
    base = np.clip(70 + x // 2 + y // 3, 0, 255).astype(np.uint8)
    rgba = np.stack((base, np.roll(base, 7, axis=1), np.roll(base, 11, axis=0), binary), axis=2)
    rgba_png = _encoded(Image.fromarray(rgba, "RGBA"), "PNG")
    assert S.lsb_plane_score(rgba_png, channel=3) is None
    assert S.analyze_image(rgba_png) == ()
    la = np.stack((base, binary), axis=2)
    la_png = _encoded(Image.fromarray(la, "LA"), "PNG")
    assert S.lsb_plane_score(la_png, channel=1) is None
    assert S.analyze_image(la_png) == ()

    # A binary mask supplied directly is likewise not a meaningful intensity plane.
    assert S.lsb_plane_score(binary) is None
    assert S.analyze_image(binary) == ()


def test_exact_jpeg_boundary_header_and_entropy_exhaustion():
    carrier = _dct_pair_carrier()
    assert S._jpeg_context(carrier) is not None
    corruptions = (
        carrier + b"\x00",
        carrier + b"PK\x03\x04polyglot",
        carrier[:2] + b"arbitrary" + carrier[2:],
        carrier[:-2] + b"\x00" + carrier[-2:],
        carrier[:-2] + b"\xff\x00" + carrier[-2:],
    )
    for corrupt in corruptions:
        assert S._jpeg_context(corrupt) is None
        assert S.jpeg_dct_anomaly(corrupt) is None
        assert S.jpeg_ela(corrupt) is None
        assert S.analyze_image(corrupt) == ()


def test_jpeg_quality_requires_every_referenced_table_at_one_quality():
    y, x = np.indices((128, 128))
    rgb = np.stack((x, y, ((x + y) // 2)), axis=2).astype(np.uint8)
    coherent = _jpeg(rgb, 90)
    context = S._jpeg_context(coherent)
    assert context is not None and context.source_quality == 90

    luma90 = list(S._standard_table(S._JPEG_LUMA_Q50, 90))
    chroma75 = list(S._standard_table(S._JPEG_CHROMA_Q50, 75))
    inconsistent = io.BytesIO()
    Image.fromarray(rgb, "RGB").save(
        inconsistent, "JPEG", qtables=[luma90, chroma75], subsampling=0,
        optimize=False, progressive=False,
    )
    mixed = inconsistent.getvalue()
    mixed_context = S._jpeg_context(mixed)
    assert mixed_context is not None
    assert mixed_context.source_quality is None
    with Image.open(io.BytesIO(mixed)) as parsed:
        refs = ((0, "luma"), (1, "chroma"), (1, "chroma"))
        assert S._standard_jpeg_quality(parsed.quantization, refs) is None
    assert S.jpeg_ela(mixed) is None


def test_jpeg_cmyk_and_unreferenced_representation_decline():
    y, x = np.indices((64, 64))
    cmyk = np.stack((x * 3, y * 3, (x + y) * 2, np.full_like(x, 20)), axis=2).astype(np.uint8)
    artifact = _encoded(Image.fromarray(cmyk, "CMYK"), "JPEG", quality=90)
    assert S._jpeg_context(artifact) is None
    assert S.jpeg_ela(artifact) is None
    assert S.jpeg_dct_anomaly(artifact) is None
    assert S.analyze_image(artifact) == ()


def test_orchestrator_loads_each_artifact_once(monkeypatch):
    _cover, hidden = _spatial_cover_and_randomized_lsb()
    rgb = np.stack((hidden, np.roll(hidden, 3, axis=0), np.roll(hidden, 5, axis=1)), axis=2)
    png = _png(rgb)
    load_calls = 0
    original_load = S._load

    def counted_load(source):
        nonlocal load_calls
        load_calls += 1
        return original_load(source)

    monkeypatch.setattr(S, "_load", counted_load)
    assert S.analyze_image(png)
    assert load_calls == 1

    context_calls = 0
    original_context = S._jpeg_context

    def counted_context(source):
        nonlocal context_calls
        context_calls += 1
        return original_context(source)

    monkeypatch.setattr(S, "_jpeg_context", counted_context)
    S.analyze_image(_dct_pair_carrier())
    assert context_calls == 1
    assert load_calls == 1


def test_dct_dimension_preflight_precedes_huffman_expansion(monkeypatch):
    carrier = _dct_pair_carrier()
    calls = 0
    original = S._jpeg._decode_one

    def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(S._jpeg, "_decode_one", counted)
    monkeypatch.setattr(S, "MAX_DCT_COEFFICIENTS", 64)
    assert S._decode_complete_jpeg(carrier) is None
    assert calls == 0


def test_complete_context_uses_dense_bounded_coefficient_storage():
    context = S._jpeg_context(_dct_pair_carrier())
    assert context is not None
    assert isinstance(context.coefficients, np.ndarray)
    assert context.coefficients.dtype == np.int32
    assert context.coefficients.shape == (context.expected_blocks, 64)
    assert len(context.component_tags) == context.expected_blocks
