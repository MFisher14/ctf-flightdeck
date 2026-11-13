"""Independent vectors and fail-closed fuzz for the stegodepth DB/SW lane.

The positive artifacts are authored here from format specifications or by
independent libraries.  No expected value is derived from an engine under
test.  All random input uses fixed seeds.
"""

from __future__ import annotations

from io import BytesIO
import random
import struct
import wave

import numpy as np
from PIL import Image
import pytest

import stegodepth_echo as echo
import stegodepth_flac as flac
import stegodepth_jp2 as jp2
import stegodepth_jpegcover as jpegcover
import stegodepth_matroska as matroska
import stegodepth_spread as spread
import stegodepth_webp as webp


def _wav16(samples: np.ndarray, rate: int = 16_000) -> bytes:
    """Serialize mono PCM through stdlib ``wave``, an independent oracle."""

    values = np.clip(np.rint(samples * 32767.0), -32768, 32767).astype("<i2")
    output = BytesIO()
    with wave.open(output, "wb") as writer:
        writer.setnchannels(1)
        writer.setsampwidth(2)
        writer.setframerate(rate)
        writer.writeframes(values.tobytes())
    return output.getvalue()


def _echo_vector() -> tuple[bytes, tuple[int, ...]]:
    expected = tuple(int(bit) for bit in f"{ord('A'):08b}")
    rng = np.random.default_rng(0xEC40)
    windows: list[np.ndarray] = []
    for bit in expected:
        source = rng.normal(0.0, 0.12, 1024)
        delay = 19 if bit else 7
        encoded = source.copy()
        encoded[delay:] += 0.78 * source[:-delay]
        windows.append(encoded)
    return _wav16(np.concatenate(windows)), expected


def _spread_vector() -> tuple[bytes, tuple[int, ...], tuple[int, ...]]:
    chips = (1, -1, 1, 1, -1, 1, -1, -1)
    expected = tuple(int(bit) for bit in f"{ord('S'):08b}")
    samples: list[float] = []
    for bit in expected:
        sign = 1.0 if bit else -1.0
        for chip in chips:
            samples.extend([sign * chip * 0.55] * 8)
    return _wav16(np.asarray(samples)), chips, expected


def _riff_chunk(kind: bytes, body: bytes) -> bytes:
    assert len(kind) == 4
    return kind + struct.pack("<I", len(body)) + body + (b"\x00" if len(body) & 1 else b"")


def _webp_vector() -> bytes:
    # RIFF/WebP extended header: EXIF flag plus a structurally opaque VP8 body.
    vp8x = bytes([0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    chunks = _riff_chunk(b"VP8X", vp8x)
    chunks += _riff_chunk(b"EXIF", b"DBSW-EXIF")
    chunks += _riff_chunk(b"VP8 ", b"not-decoded")
    return b"RIFF" + struct.pack("<I", 4 + len(chunks)) + b"WEBP" + chunks


def _metadata_block(type_id: int, body: bytes, *, last: bool) -> bytes:
    assert 0 <= type_id < 127 and len(body) < (1 << 24)
    return bytes([(0x80 if last else 0) | type_id]) + len(body).to_bytes(3, "big") + body


def _flac_vector() -> bytes:
    # RFC FLAC STREAMINFO: 44.1 kHz, mono, 16 bit, zero declared samples.
    packed = (44_100 << 44) | (15 << 36)
    streaminfo = (
        struct.pack(">HH", 16, 4096)
        + b"\x00\x00\x00" * 2
        + packed.to_bytes(8, "big")
        + bytes(16)
    )
    vendor = b"independent-test"
    comment = b"TITLE=DBSW"
    vorbis = (
        len(vendor).to_bytes(4, "little") + vendor
        + (1).to_bytes(4, "little")
        + len(comment).to_bytes(4, "little") + comment
    )
    application = b"TEST" + b"known-carrier"
    return (
        b"fLaC"
        + _metadata_block(0, streaminfo, last=False)
        + _metadata_block(4, vorbis, last=False)
        + _metadata_block(2, application, last=True)
    )


def _pil_jpeg() -> bytes:
    yy, xx = np.mgrid[:16, :16]
    pixels = np.stack((xx * 13, yy * 11, (xx + yy) * 7), axis=-1).astype(np.uint8)
    image = Image.fromarray(pixels, "RGB")
    output = BytesIO()
    image.save(output, format="JPEG", quality=83, subsampling=0, progressive=False)
    raw = output.getvalue()
    # Pillow independently validates its own generated stream and dimensions.
    with Image.open(BytesIO(raw)) as decoded:
        assert decoded.format == "JPEG" and decoded.size == (16, 16)
    return raw


def _pil_jp2() -> bytes:
    pixels = np.arange(13 * 17, dtype=np.uint8).reshape(17, 13)
    image = Image.fromarray(pixels, "L")
    output = BytesIO()
    image.save(output, format="JPEG2000", irreversible=False)
    raw = output.getvalue()
    with Image.open(BytesIO(raw)) as decoded:
        assert decoded.format == "JPEG2000" and decoded.size == (13, 17)
    return raw


def _jp2_codestream(raw: bytes) -> bytes:
    """Find a top-level jp2c using documented LBox/TBox semantics."""

    at = 0
    while at + 8 <= len(raw):
        size = int.from_bytes(raw[at:at + 4], "big")
        kind = raw[at + 4:at + 8]
        header = 8
        if size == 1:
            size = int.from_bytes(raw[at + 8:at + 16], "big")
            header = 16
        elif size == 0:
            size = len(raw) - at
        assert size >= header and at + size <= len(raw)
        if kind == b"jp2c":
            return raw[at + header:at + size]
        at += size
    raise AssertionError("Pillow JP2 had no jp2c box")


def _ebml_size(length: int) -> bytes:
    assert 0 <= length < 127
    return bytes([0x80 | length])


def _ebml(element_id: bytes, body: bytes) -> bytes:
    return element_id + _ebml_size(len(body)) + body


def _matroska_vector() -> bytes:
    doc_type = _ebml(b"\x42\x82", b"webm")
    header = _ebml(b"\x1a\x45\xdf\xa3", doc_type)
    attached = _ebml(b"\x46\x6e", b"note.txt")
    attached += _ebml(b"\x46\x60", b"text/plain")
    attached += _ebml(b"\x46\x5c", b"DBSW-ATTACHMENT")
    attached_file = _ebml(b"\x61\xa7", attached)
    attachments = _ebml(b"\x19\x41\xa4\x69", attached_file)
    void = _ebml(b"\xec", b"DBSW-VOID")
    segment = _ebml(b"\x18\x53\x80\x67", attachments + void)
    return header + segment


def _mutations(valid: bytes) -> tuple[bytes, ...]:
    rng = random.Random(0xDB5A)
    random_rows = tuple(rng.randbytes(size) for size in (1, 7, 31, 127))
    cuts = tuple(valid[:cut] for cut in sorted({0, 1, len(valid) // 2, max(0, len(valid) - 1)}))
    flips: list[bytes] = []
    for position in sorted({0, len(valid) // 2, len(valid) - 1}):
        changed = bytearray(valid)
        changed[position] ^= 1 << (position % 8)
        flips.append(bytes(changed))
    return random_rows + cuts + tuple(flips)


def _only_declared(exception: type[Exception], function, /, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except exception:
        return None
    except Exception as exc:  # pragma: no cover - assertion failure path
        pytest.fail(f"leaked {type(exc).__name__}: {exc}")


def test_echo_synthesized_embed_vector_lock():
    raw, expected = _echo_vector()
    parsed = echo.parse_pcm_wav(raw)
    assert parsed is not None
    assert (parsed.rate, parsed.channels, parsed.bits_per_sample, parsed.frames) == (
        16_000, 1, 16, 8 * 1024,
    )
    result = echo.extract_echo(
        raw, delay_zero=7, delay_one=19, window_samples=1024,
        max_bits=8, min_margin=0.08,
    )
    assert result is not None
    assert result.bits == expected
    assert result.payload_msb == b"A"
    assert result.confident == 8
    assert echo.pack_bits(expected) == b"A"


def test_spread_synthesized_embed_vector_lock():
    raw, chips, expected = _spread_vector()
    assert spread.parse_chips("+ - + + - + - -") == chips
    result = spread.extract_dsss(
        raw, chips=chips, samples_per_chip=8, max_bits=8,
        min_correlation=0.95,
    )
    assert result is not None
    assert result.bits == expected
    assert result.payload_msb == b"S"
    assert result.confident == 8
    assert all(abs(value) > 0.999 for value in result.correlations)


def test_webp_documented_riff_metadata_vector_lock():
    raw = _webp_vector()
    report = webp.audit_webp(raw)
    assert report is not None
    assert report.declared_end == len(raw)
    assert report.vp8x_flags == 0x08
    assert [(item.kind, item.fourcc, item.data) for item in report.artifacts] == [
        ("metadata", "EXIF", b"DBSW-EXIF")
    ]
    assert not {item.code for item in report.findings}.intersection(
        {"vp8x-feature-mismatch", "image-data-missing"}
    )


def test_flac_documented_metadata_vector_lock(tmp_path):
    raw = _flac_vector()
    report = flac.audit_flac(raw)
    assert report is not None
    assert report.streaminfo.sample_rate == 44_100
    assert report.streaminfo.channels == 1
    assert report.streaminfo.bits_per_sample == 16
    assert [(item.key, item.value, item.vendor) for item in report.comments] == [
        ("TITLE", "DBSW", "independent-test")
    ]
    assert [(item.kind, item.application_id, item.data) for item in report.artifacts] == [
        ("application-data", b"TEST", b"known-carrier")
    ]
    metadata = flac.report_dict(report)
    assert metadata["streaminfo"]["sample_rate"] == 44_100
    written = flac.extract_artifacts(report, tmp_path / "out")
    assert len(written) == 1 and written[0].read_bytes() == b"known-carrier"
    source = tmp_path / "vector.flac"
    source.write_bytes(raw)
    assert flac.audit_path(source) == report


def test_jpegcover_pillow_identity_vector_lock():
    raw = _pil_jpeg()
    report = jpegcover.compare(raw, raw)
    assert report is not None
    assert (report.width, report.height) == (16, 16)
    assert report.coefficients == report.blocks * 64
    assert report.changed == 0
    assert report.changed_blocks == report.changed_dc == report.changed_ac == 0
    assert report.unit_changes == report.shrinkage == report.growth == 0
    assert report.delta_histogram == ()
    assert report.unit_change_fraction == 0.0


def test_jp2_pillow_container_and_codestream_vector_lock():
    original = _pil_jp2()
    free = (8 + len(b"DBSW-FREE")).to_bytes(4, "big") + b"free" + b"DBSW-FREE"
    report = jp2.inspect_jp2(original + free)
    assert report is not None
    assert report.container_format == "jp2"
    assert len(report.codestreams) == 1
    assert (report.codestreams[0].width, report.codestreams[0].height) == (13, 17)
    assert any(
        item.kind == "free_space" and item.data == b"DBSW-FREE"
        for item in report.artifacts
    )

    codestream = _jp2_codestream(original)
    raw_report = jp2.inspect_codestream(codestream)
    assert raw_report is not None
    assert (raw_report.width, raw_report.height) == (13, 17)
    assert raw_report.logical_end == len(codestream)


def test_matroska_documented_ebml_attachment_vector_lock():
    raw = _matroska_vector()
    report = matroska.inspect_matroska(raw)
    assert report is not None
    assert report.doc_type == "webm"
    assert len(report.attachments) == 1
    attachment = report.attachments[0]
    assert (attachment.filename, attachment.media_type, attachment.data) == (
        "note.txt", "text/plain", b"DBSW-ATTACHMENT",
    )
    assert any(
        item.kind == "void" and item.data == b"DBSW-VOID"
        for item in report.artifacts
    )
    assert report.tail_size == 0 and report.tail == b""


@pytest.mark.parametrize(
    ("module", "entrypoint", "valid", "kwargs"),
    (
        (echo, echo.parse_pcm_wav, _echo_vector()[0], {}),
        (
            echo, echo.extract_echo, _echo_vector()[0],
            {"delay_zero": 7, "delay_one": 19, "window_samples": 1024, "max_bits": 8},
        ),
        (
            spread, spread.extract_dsss, _spread_vector()[0],
            {"chips": _spread_vector()[1], "samples_per_chip": 8, "max_bits": 8},
        ),
        (webp, webp.audit_webp, _webp_vector(), {}),
        (flac, flac.audit_flac, _flac_vector(), {}),
        (jpegcover, jpegcover.compare, _pil_jpeg(), {}),
        (jp2, jp2.inspect_jp2, _pil_jp2(), {}),
        (jp2, jp2.inspect_codestream, _jp2_codestream(_pil_jp2()), {}),
        (matroska, matroska.inspect_matroska, _matroska_vector(), {}),
    ),
    ids=(
        "echo-parse", "echo-extract", "spread-extract", "webp", "flac",
        "jpeg-cover", "jp2-container", "jp2-codestream", "matroska",
    ),
)
def test_binary_entrypoints_fail_closed_on_deterministic_mutations(
    module, entrypoint, valid, kwargs,
):
    declared = next(
        value for name, value in vars(module).items()
        if name.startswith("Stegodepth") and name.endswith("Error")
    )
    for hostile in _mutations(valid):
        if entrypoint is jpegcover.compare:
            _only_declared(declared, entrypoint, hostile, hostile)
        else:
            _only_declared(declared, entrypoint, hostile, **kwargs)


def test_parameter_entrypoints_fail_closed():
    for hostile in ("", "x", "+,+,+,+", object(), [], [1, 1, 1, 1], [1, -1, 2, 0]):
        _only_declared(spread.StegodepthSpreadError, spread.parse_chips, hostile)
    for hostile in ([], [0] * 7, [0] * 8, [0, 1, 2] * 3, object()):
        _only_declared(echo.StegodepthEchoError, echo.pack_bits, hostile)
    _only_declared(flac.StegodepthFLACError, flac.report_dict, object())
    _only_declared(flac.StegodepthFLACError, flac.extract_artifacts, object(), ".")


def test_oversized_inputs_fail_closed(monkeypatch):
    monkeypatch.setattr(echo, "MAX_INPUT_BYTES", 32)
    assert echo.parse_pcm_wav(b"x" * 33) is None
    assert echo.extract_echo(
        b"x" * 33, delay_zero=1, delay_one=2, window_samples=8,
    ) is None
    assert spread.extract_dsss(
        b"x" * 33, chips=(1, -1, 1, -1), samples_per_chip=1,
    ) is None

    monkeypatch.setattr(webp, "MAX_INPUT_BYTES", 32)
    _only_declared(webp.StegodepthWebPError, webp.audit_webp, b"x" * 33)
    monkeypatch.setattr(flac, "MAX_INPUT", 32)
    _only_declared(flac.StegodepthFLACError, flac.audit_flac, b"x" * 33)
    monkeypatch.setattr(jpegcover, "MAX_INPUT_BYTES", 32)
    _only_declared(
        jpegcover.StegodepthJPEGCoverError, jpegcover.compare,
        b"x" * 33, b"x" * 33,
    )
    monkeypatch.setattr(jp2, "MAX_INPUT_BYTES", 32)
    assert jp2.inspect_jp2(b"x" * 33) is None
    assert jp2.inspect_codestream(b"x" * 33) is None
    monkeypatch.setattr(matroska, "MAX_INPUT_BYTES", 32)
    assert matroska.inspect_matroska(b"x" * 33) is None


def test_guarded_cli_entrypoints_return_clean_codes():
    for module in (echo, spread, webp, flac, jpegcover, jp2, matroska):
        assert module.main([]) == 2


@pytest.mark.parametrize("module", (echo, spread, webp, flac, jpegcover))
def test_guarded_cli_entrypoints_reject_hostile_path_values_cleanly(module):
    for argv in ([None], ["\ud800"], ["DBSW-" + "x" * 257]):
        result = module.main(argv)
        assert isinstance(result, int) and result in (0, 2)


@pytest.mark.parametrize(
    ("module", "argv"),
    (
        pytest.param(jp2, [None]),
        pytest.param(jp2, ["\ud800"]),
        pytest.param(matroska, [None]),
        pytest.param(matroska, ["\ud800"]),
    ),
)
def test_jp2_and_matroska_cli_path_fuzz_is_fail_closed(module, argv):
    result = module.main(argv)
    assert isinstance(result, int) and result == 2

