"""Independent hardening vectors for ``ff2_raw_vendor``.

ExifRead is the TIFF/MakerNote oracle and Pillow is the JPEG oracle.  The
fixtures below are assembled directly from the TIFF 6.0 IFD layout; no output
from the engine under test is used to construct or validate them.
"""

from __future__ import annotations

from io import BytesIO
import json
import random
import struct

import exifread
from PIL import Image
import pytest

import ff2_raw_vendor as raw


def _entry(tag: int, typ: int, count: int, value: int | bytes) -> bytes:
    field = struct.pack("<I", value) if isinstance(value, int) else value.ljust(4, b"\0")
    assert len(field) == 4
    return struct.pack("<HHI", tag, typ, count) + field


def _nikon_note() -> bytes:
    # Nikon type-3 MakerNote: ten-byte Nikon prefix followed by a self-relative
    # classic TIFF.  Tags 1 and 2 are MakerNoteVersion and ISOSetting.
    ifd = (
        struct.pack("<H", 2)
        + _entry(0x0001, 7, 4, b"0210")
        + _entry(0x0002, 3, 2, struct.pack("<HH", 100, 100))
        + struct.pack("<I", 0)
    )
    return b"Nikon\0\x02\x10\0\0" + b"II*\0" + struct.pack("<I", 8) + ifd


def _sony_note() -> bytes:
    # ExifTool/ExifRead's documented Sony layout places its IFD twelve bytes
    # after the SONY DSC signature.  Quality=0 denotes RAW in ExifRead.
    ifd = (
        struct.pack("<H", 2)
        + _entry(0x0102, 4, 1, 0)
        + _entry(0xB000, 1, 4, b"\x03\x01\0\0")
        + struct.pack("<I", 0)
    )
    return b"SONY DSC " + b"\0" * 3 + ifd


def _pillow_jpeg(size: tuple[int, int] = (3, 2)) -> bytes:
    stream = BytesIO()
    Image.new("RGB", size, (17, 34, 51)).save(
        stream, format="JPEG", quality=95, subsampling=0
    )
    return stream.getvalue()


def _tiff_raw(make: str, model: str, note: bytes, jpeg: bytes) -> tuple[bytes, int]:
    """Build classic little-endian TIFF with ExifIFD and IFD1 JPEG preview."""

    make_bytes = make.encode("ascii") + b"\0"
    model_bytes = model.encode("ascii") + b"\0"
    ifd0_at = 8
    ifd0_size = 2 + 3 * 12 + 4
    cursor = ifd0_at + ifd0_size
    make_at = cursor
    cursor += len(make_bytes)
    model_at = cursor
    cursor += len(model_bytes)
    cursor += cursor & 1
    exif_at = cursor
    cursor += 2 + 12 + 4
    note_at = cursor
    cursor += len(note)
    cursor += cursor & 1
    ifd1_at = cursor
    cursor += 2 + 5 * 12 + 4
    jpeg_at = cursor
    cursor += len(jpeg)

    output = bytearray(cursor)
    output[:8] = b"II*\0" + struct.pack("<I", ifd0_at)
    ifd0 = (
        struct.pack("<H", 3)
        + _entry(0x010F, 2, len(make_bytes), make_at)
        + _entry(0x0110, 2, len(model_bytes), model_at)
        + _entry(0x8769, 4, 1, exif_at)
        + struct.pack("<I", ifd1_at)
    )
    output[ifd0_at : ifd0_at + len(ifd0)] = ifd0
    output[make_at : make_at + len(make_bytes)] = make_bytes
    output[model_at : model_at + len(model_bytes)] = model_bytes
    exif_ifd = (
        struct.pack("<H", 1)
        + _entry(0x927C, 7, len(note), note_at)
        + struct.pack("<I", 0)
    )
    output[exif_at : exif_at + len(exif_ifd)] = exif_ifd
    output[note_at : note_at + len(note)] = note
    ifd1 = (
        struct.pack("<H", 5)
        + _entry(0x0100, 4, 1, 3)
        + _entry(0x0101, 4, 1, 2)
        + _entry(0x0103, 3, 1, struct.pack("<H", 6))
        + _entry(0x0201, 4, 1, jpeg_at)
        + _entry(0x0202, 4, 1, len(jpeg))
        + struct.pack("<I", 0)
    )
    output[ifd1_at : ifd1_at + len(ifd1)] = ifd1
    output[jpeg_at : jpeg_at + len(jpeg)] = jpeg
    return bytes(output), note_at


def _oracle_tags(data: bytes) -> dict:
    return exifread.process_file(BytesIO(data), details=True, strict=False)


def test_nikon_nef_matches_exifread_and_pillow_oracles() -> None:
    jpeg = _pillow_jpeg()
    note = _nikon_note()
    data, note_at = _tiff_raw("NIKON CORPORATION", "NIKON Z 6", note, jpeg)
    tags = _oracle_tags(data)

    assert str(tags["Image Make"]) == "NIKON CORPORATION"
    assert str(tags["Image Model"]) == "NIKON Z 6"
    assert str(tags["MakerNote MakernoteVersion"]) == "0210"
    assert str(tags["MakerNote ISOSetting"]) == "[100, 100]"
    assert bytes(tags["EXIF MakerNote"].values) == note

    report = raw.inventory(data)
    assert report["format"] == "nef"
    assert (report["make"], report["model"]) == (
        str(tags["Image Make"]),
        str(tags["Image Model"]),
    )
    assert report["maker_notes"][0]["offset"] == note_at
    assert report["maker_notes"][0]["ifds"][0]["tags"] == [1, 2]
    assert raw.extract_maker_note(data) == bytes(tags["EXIF MakerNote"].values)

    extracted = raw.extract_preview(data)
    assert extracted == tags["JPEGThumbnail"]
    with Image.open(BytesIO(extracted)) as image:
        assert image.format == "JPEG"
        assert image.size == (3, 2)
        image.load()


def test_sony_arw_matches_exifread_makernote_oracle() -> None:
    jpeg = _pillow_jpeg((4, 1))
    note = _sony_note()
    data, _note_at = _tiff_raw("SONY", "ILCE-7M4", note, jpeg)
    tags = _oracle_tags(data)

    assert str(tags["Image Make"]) == "SONY"
    assert str(tags["Image Model"]) == "ILCE-7M4"
    assert str(tags["MakerNote Quality"]) == "RAW"
    assert bytes(tags["EXIF MakerNote"].values) == note

    report = raw.inventory(data)
    assert report["format"] == "arw"
    assert report["maker_notes"][0]["format"] == "sony-prefixed"
    assert report["maker_notes"][0]["file_format_bytes"] == "03010000"
    assert raw.extract_maker_note(data) == note
    with Image.open(BytesIO(raw.extract_preview(data))) as image:
        assert image.size == (4, 1)


def test_cli_vector_uses_the_same_independent_tiff_fixture(tmp_path, capsys) -> None:
    data, _ = _tiff_raw("NIKON CORPORATION", "NIKON Z 6", _nikon_note(), _pillow_jpeg())
    source = tmp_path / "oracle.nef"
    source.write_bytes(data)
    assert raw.main([str(source)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["make"] == str(_oracle_tags(data)["Image Make"])
    assert raw.main(["--definitely-invalid"]) == 2


def _assert_closed(function, supplied: bytes) -> None:
    try:
        result = function(supplied)
    except Exception as exc:  # the exact type is the contract under test
        assert type(exc) is raw.FF2RawVendorError
    else:
        expected = dict if function is raw.inventory else bytes
        assert type(result) is expected


def test_all_public_binary_entrypoints_fail_closed_under_deterministic_fuzz(monkeypatch) -> None:
    valid, _ = _tiff_raw(
        "NIKON CORPORATION", "NIKON Z 6", _nikon_note(), _pillow_jpeg()
    )
    rng = random.Random(0xA3FF)
    flipped = bytearray(valid)
    flipped[4] ^= 0x80
    corpus = [
        b"",
        rng.randbytes(257),
        b"\xff" * 257,
        valid[:1],
        valid[:8],
        valid[: len(valid) // 2],
        valid[:-1],
        bytes(flipped),
    ]
    for supplied in corpus:
        for function in (raw.inventory, raw.extract_preview, raw.extract_maker_note):
            _assert_closed(function, supplied)

    # Exercise the real over-budget branch without allocating 128 MiB per call.
    monkeypatch.setattr(raw, "MAX_INPUT", 256)
    oversized = b"II" + b"\0" * 255
    for function in (raw.inventory, raw.extract_preview, raw.extract_maker_note):
        _assert_closed(function, oversized)


@pytest.mark.parametrize("bad_index", [None, True, 1.5, "0", object()])
def test_extract_entrypoints_translate_bad_index_types(bad_index: object) -> None:
    data, _ = _tiff_raw("SONY", "ILCE-7M4", _sony_note(), _pillow_jpeg())
    for function in (raw.extract_preview, raw.extract_maker_note):
        with pytest.raises(raw.FF2RawVendorError) as caught:
            function(data, bad_index)
        assert type(caught.value) is raw.FF2RawVendorError
