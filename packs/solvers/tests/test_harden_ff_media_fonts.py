"""Independent-oracle and fail-closed locks for PSD, RAW/TIFF, and WOFF.

The valid inputs are written and read by psd-tools, Pillow, and fontTools.  The
engines under test are never used to produce their own expected values.
"""

from dataclasses import replace
from io import BytesIO
import random

from PIL import Image
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import TTFont
from fontTools.ttLib.sfnt import calcChecksum
from psd_tools import PSDImage
from psd_tools.psd import PSD
import pytest

import ff_psd_inventory as psd_engine
import ff_raw_inventory as raw_engine
import ff_woff_inspect as woff_engine


@pytest.fixture(scope="module")
def psd_blob():
    stream = BytesIO()
    PSDImage.new("RGB", (4, 3), color=(10, 20, 30)).save(stream)
    return stream.getvalue()


@pytest.fixture(scope="module")
def tiff_blob():
    stream = BytesIO()
    Image.new("RGB", (5, 4), color=(17, 29, 43)).save(
        stream, format="TIFF", compression="raw"
    )
    return stream.getvalue()


@pytest.fixture(scope="module")
def woff_blob():
    builder = FontBuilder(1000, isTTF=True)
    builder.setupGlyphOrder([".notdef", "A"])
    empty = TTGlyphPen(None).glyph()
    pen = TTGlyphPen(None)
    pen.moveTo((100, 0))
    pen.lineTo((500, 700))
    pen.lineTo((900, 0))
    pen.closePath()
    builder.setupGlyf({".notdef": empty, "A": pen.glyph()})
    builder.setupHorizontalMetrics({".notdef": (1000, 0), "A": (1000, 100)})
    builder.setupHorizontalHeader(ascent=800, descent=-200)
    builder.setupCharacterMap({65: "A"})
    builder.setupNameTable(
        {
            "familyName": "Hardening",
            "styleName": "Regular",
            "uniqueFontIdentifier": "Hardening Regular",
            "fullName": "Hardening Regular",
            "psName": "Hardening-Regular",
            "version": "Version 1.0",
        }
    )
    builder.setupOS2(
        sTypoAscender=800,
        sTypoDescender=-200,
        usWinAscent=800,
        usWinDescent=200,
    )
    builder.setupPost()
    builder.setupMaxp()
    # Prevent the independent writer from inserting wall-clock-dependent data.
    builder.font["head"].created = builder.font["head"].modified = 3_800_000_000
    builder.font.flavor = "woff"
    stream = BytesIO()
    builder.font.save(stream)
    return stream.getvalue()


def test_psd_vector_lock_against_psd_tools(psd_blob):
    oracle = PSD.read(BytesIO(psd_blob))
    report = psd_engine.inventory(psd_blob)

    expected_header = {
        "version": oracle.header.version,
        "channels": oracle.header.channels,
        "height": oracle.header.height,
        "width": oracle.header.width,
        "depth": oracle.header.depth,
        "color_mode": int(oracle.header.color_mode),
    }
    assert report["format"] == "PSD"
    assert report["header"] == expected_header
    assert [item["id"] for item in report["resources"]] == [
        int(resource_id) for resource_id in oracle.image_resources
    ]
    assert report["composite"]["compression"] == int(oracle.image_data.compression)
    assert report["composite"]["extent_verified"] is True
    assert report["sections"][-1]["end"] == len(psd_blob)
    assert oracle.layer_and_mask_information.layer_info is None
    assert report["layer_count"] == 0


def _tuple(value):
    return value if isinstance(value, tuple) else (value,)


def test_raw_vector_lock_against_pillow_tiff(tiff_blob):
    with Image.open(BytesIO(tiff_blob)) as oracle:
        oracle.load()
        tags = dict(oracle.tag_v2)
        size = oracle.size
        bands = len(oracle.getbands())

    byte_order = "little" if tiff_blob[:2] == b"II" else "big"
    root = int.from_bytes(tiff_blob[4:8], byte_order)
    offsets, lengths = _tuple(tags[273]), _tuple(tags[279])
    expected_extents = [
        {"offset": offset, "length": length, "kind": "strip"}
        for offset, length in zip(offsets, lengths)
    ]
    assert sum(lengths) == size[0] * size[1] * bands

    report = raw_engine.inventory(tiff_blob)
    assert report["format"] == "tiff"
    assert report["endian"] == byte_order
    assert report["bigtiff"] is False
    assert report["ifds"][0]["offset"] == root
    assert report["ifds"][0]["tags"] == sorted(tags)
    assert report["ifds"][0]["extents"] == expected_extents
    assert report["previews"] == []


def _font_checksum(payload, tag):
    if tag == "head":
        payload = payload[:8] + b"\0" * 4 + payload[12:]
    return calcChecksum(payload)


def test_woff_vector_lock_against_fonttools(woff_blob):
    oracle = TTFont(BytesIO(woff_blob), recalcBBoxes=False, recalcTimestamp=False)
    try:
        report = woff_engine.inspect_font(woff_blob)
        actual = {item["tag"]: item for item in report["fonts"][0]["tables"]}
        assert report["format"] == "WOFF"
        assert report["total_sfnt_size"] == oracle.reader.totalSfntSize
        assert set(actual) == set(oracle.reader.keys())
        for tag in oracle.reader.keys():
            payload = oracle.reader[tag]
            directory = oracle.reader.tables[tag]
            assert actual[tag]["length"] == len(payload) == directory.origLength
            assert actual[tag]["stored_length"] == directory.length
            assert actual[tag]["checksum"]["actual"] == _font_checksum(payload, tag)
            assert actual[tag]["checksum"]["expected"] == directory.checkSum
            assert actual[tag]["checksum"]["valid"] is True
    finally:
        oracle.close()


def _corruptions(valid):
    """Empty/random/truncated-valid/bit-flipped deterministic cases."""
    cases = [b""]
    rng = random.Random(0xFF2026)
    for size in (1, 2, 3, 7, 16, 31, 64, 127):
        cases.append(bytes(rng.getrandbits(8) for _ in range(size)))
    cuts = {1, 2, 3, 4, 5, 8, 16, 25, 26, len(valid) // 2, len(valid) - 1}
    cases.extend(valid[:cut] for cut in sorted(cuts) if 0 < cut < len(valid))
    positions = {0, 1, 3, 4, 8, 12, 25, len(valid) // 2, len(valid) - 1}
    for position in sorted(positions):
        if 0 <= position < len(valid):
            changed = bytearray(valid)
            changed[position] ^= 0x80
            cases.append(bytes(changed))
    return cases


def _assert_closed(label, call, declared_error, result_type, cases):
    for index, blob in enumerate(cases):
        try:
            result = call(blob)
        except declared_error:
            continue
        except BaseException as exc:  # SystemExit and parser assertions are leaks too.
            pytest.fail(
                f"{label} case {index} leaked {type(exc).__name__}: {exc}",
                pytrace=False,
            )
        assert isinstance(result, result_type), (
            f"{label} case {index} returned {type(result).__name__}"
        )


def test_fail_closed_fuzz_for_all_public_byte_parsers(psd_blob, tiff_blob, woff_blob):
    psd_cases = _corruptions(psd_blob)
    raw_cases = _corruptions(tiff_blob)
    woff_cases = _corruptions(woff_blob)
    checks = (
        ("psd.inventory", psd_engine.inventory, psd_engine.PSDInventoryError, dict, psd_cases),
        (
            "psd.extract_payload",
            lambda blob: psd_engine.extract_payload(blob, "resource"),
            psd_engine.PSDInventoryError,
            bytes,
            psd_cases,
        ),
        ("raw.inventory", raw_engine.inventory, raw_engine.RawError, dict, raw_cases),
        (
            "raw.extract_preview",
            raw_engine.extract_preview,
            raw_engine.RawError,
            bytes,
            raw_cases,
        ),
        (
            "raw.extract_original",
            raw_engine.extract_original,
            raw_engine.RawError,
            bytes,
            raw_cases,
        ),
        (
            "raw.decode_original",
            raw_engine.decode_original,
            raw_engine.RawError,
            dict,
            raw_cases,
        ),
        (
            "woff.inspect_font",
            woff_engine.inspect_font,
            woff_engine.FFWOFFError,
            dict,
            woff_cases,
        ),
    )
    for check in checks:
        _assert_closed(*check)


def test_oversized_inputs_use_only_declared_errors(
    monkeypatch, psd_blob, tiff_blob, woff_blob
):
    monkeypatch.setattr(psd_engine, "MAX_BYTES", len(psd_blob) - 1)
    with pytest.raises(psd_engine.PSDInventoryError):
        psd_engine.inventory(psd_blob)

    monkeypatch.setattr(raw_engine, "MAX_INPUT", len(tiff_blob) - 1)
    with pytest.raises(raw_engine.RawError):
        raw_engine.inventory(tiff_blob)

    limits = replace(woff_engine.Limits(), max_input=len(woff_blob) - 1)
    with pytest.raises(woff_engine.FFWOFFError):
        woff_engine.inspect_font(woff_blob, limits=limits)
