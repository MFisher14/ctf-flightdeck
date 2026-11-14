from __future__ import annotations

import bz2
import gzip
import io
import lzma
import sqlite3
import struct
import wave
import zipfile
import zlib

from PIL import Image
import py7zr

import carving as C


def _image(fmt: str) -> bytes:
    stream = io.BytesIO()
    image = Image.new("RGB", (3, 2), (23, 99, 177))
    kwargs = {"quality": 90, "subsampling": 0} if fmt == "JPEG" else {}
    image.save(stream, format=fmt, **kwargs)
    return stream.getvalue()


def _zip() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("flag.txt", b"CSCTF{offline_carve}")
    return stream.getvalue()


def _pdf() -> bytes:
    return (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
            b"xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Root 1 0 R >>\n"
            b"startxref\n45\n%%EOF\n")


def _wav() -> bytes:
    stream = io.BytesIO()
    with wave.open(stream, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(1)
        output.setframerate(8000)
        output.writeframes(bytes(range(32)))
    return stream.getvalue()


def _avi() -> bytes:
    avih = b"avih" + struct.pack("<I", 40) + b"\x00" * 40
    payload = b"hdrl" + avih
    listing = b"LIST" + struct.pack("<I", len(payload)) + payload
    return b"RIFF" + struct.pack("<I", 4 + len(listing)) + b"AVI " + listing


def _zlib_with_header(payload: bytes, cinfo: int, flevel: int, dictionary: bytes | None = None) -> bytes:
    compressor = zlib.compressobj(level=6, wbits=-9, zdict=dictionary) if dictionary else zlib.compressobj(level=6, wbits=-9)
    deflate = compressor.compress(payload) + compressor.flush()
    cmf = (cinfo << 4) | 8
    flg_base = (flevel << 6) | (0x20 if dictionary else 0)
    flg = flg_base | (-((cmf << 8) | flg_base)) % 31
    dictionary_id = zlib.adler32(dictionary).to_bytes(4, "big") if dictionary else b""
    return bytes((cmf, flg)) + dictionary_id + deflate + zlib.adler32(payload).to_bytes(4, "big")


def _elf64() -> bytes:
    data = bytearray(124)
    data[:16] = b"\x7fELF" + bytes((2, 1, 1, 0)) + b"\x00" * 8
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 120, 0x400000, 0x400000, 4, 4, 0x1000)
    data[120:124] = b"ELF!"
    return bytes(data)


def _pe32() -> bytes:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    struct.pack_into("<I", data, 0x98 + 60, 0x200)
    section = 0x98 + 0xE0
    data[section:section + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", data, section + 8, 4, 0x1000, 0x200, 0x200)
    data[0x200:0x204] = b"PE!!"
    return bytes(data)


def _sevenzip() -> bytes:
    stream = io.BytesIO()
    with py7zr.SevenZipFile(stream, "w") as archive:
        archive.writestr(b"CSCTF{seven_zip}", "flag.txt")
    return stream.getvalue()


def _sqlite() -> bytes:
    database = sqlite3.connect(":memory:")
    try:
        database.execute("create table evidence(ts text, value text)")
        database.execute("insert into evidence values('2026-11-06T13:00:00Z', 'CSCTF{sqlite}')")
        database.commit()
        return database.serialize()
    finally:
        database.close()


def _fixtures():
    payload = b"forensic compression fixture" * 3
    return {
        "png": _image("PNG"),
        "jpeg": _image("JPEG"),
        "gif": _image("GIF"),
        "zip": _zip(),
        "pdf": _pdf(),
        "gzip": gzip.compress(payload, mtime=0),
        "bzip2": bz2.compress(payload),
        "xz": lzma.compress(payload, format=lzma.FORMAT_XZ),
        "zlib": zlib.compress(payload),
        "wav": _wav(),
        "avi": _avi(),
        "webp": _image("WEBP"),
        "bmp": _image("BMP"),
        "elf": _elf64(),
        "pe": _pe32(),
        "7z": _sevenzip(),
        "sqlite": _sqlite(),
    }


def test_all_foremost_formats_validate_and_corrupt_decline():
    for kind, blob in _fixtures().items():
        carved = C.carve_all(blob)
        assert any(item.kind == kind and item.offset == 0 and item.end == len(blob) for item in carved), kind
        corrupt = bytearray(blob)
        if kind in {"png", "gzip", "bzip2", "xz", "zlib", "zip", "7z"}:
            corrupt[-1] ^= 0x55
        else:
            corrupt[:] = corrupt[:max(4, len(corrupt) // 2)]
        assert not any(item.kind == kind and item.offset == 0 for item in C.carve_all(bytes(corrupt))), kind
    assert C.carve_all(b"SQLite format 3\x00" + b"\x00" * 84) == ()


def test_library_cross_checks_for_carved_images_zip_and_compression():
    fixtures = _fixtures()
    for kind in ("png", "jpeg", "gif", "bmp", "webp"):
        carved = next(item for item in C.carve_all(fixtures[kind]) if item.kind == kind)
        with Image.open(io.BytesIO(carved.data)) as image:
            image.verify()
    carved_zip = next(item for item in C.carve_all(fixtures["zip"]) if item.kind == "zip")
    with zipfile.ZipFile(io.BytesIO(carved_zip.data)) as archive:
        assert archive.read("flag.txt") == b"CSCTF{offline_carve}"
    assert gzip.decompress(next(item.data for item in C.carve_all(fixtures["gzip"]) if item.kind == "gzip")).startswith(b"forensic")
    assert bz2.decompress(next(item.data for item in C.carve_all(fixtures["bzip2"]) if item.kind == "bzip2")).startswith(b"forensic")
    assert lzma.decompress(next(item.data for item in C.carve_all(fixtures["xz"]) if item.kind == "xz")).startswith(b"forensic")
    seven = next(item.data for item in C.carve_all(fixtures["7z"]) if item.kind == "7z")
    with py7zr.SevenZipFile(io.BytesIO(seven), "r") as archive:
        assert archive.getnames() == ["flag.txt"]
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(next(item.data for item in C.carve_all(fixtures["sqlite"]) if item.kind == "sqlite"))
        assert connection.execute("select value from evidence").fetchone() == ("CSCTF{sqlite}",)
    finally:
        connection.close()


def test_every_valid_dictionary_free_zlib_header_and_corrupt_decline():
    payload = b"all RFC 1950 window and level headers" * 2
    assert len(C._ZLIB_MAGICS) == 64
    assert len({entry[1] for entry in C._ZLIB_MAGICS}) == 64
    for cinfo in range(8):
        for flevel in range(4):
            stream = _zlib_with_header(payload, cinfo, flevel)
            assert zlib.decompress(stream) == payload
            assert any(item.kind == "zlib" and item.offset == 0 and item.end == len(stream)
                       for item in C.carve_all(stream)), (cinfo, flevel, stream[:2].hex())
            corrupt = stream[:-1] + bytes((stream[-1] ^ 1,))
            assert not any(item.kind == "zlib" and item.offset == 0 for item in C.carve_all(corrupt))


def test_every_valid_dictionary_zlib_header_requires_and_checks_exact_dictionary():
    dictionary = b"CSCTF common preset dictionary prefix"
    wrong = b"CSCTF wrong preset dictionary prefix!"
    payload = dictionary[-16:] + b" payload payload payload"
    for cinfo in range(8):
        for flevel in range(4):
            stream = _zlib_with_header(payload, cinfo, flevel, dictionary)
            assert C.carve_all(stream) == ()
            assert C.carve_all(stream, zlib_dictionaries=(wrong,)) == ()
            carved = C.carve_all(stream, zlib_dictionaries=(dictionary,))
            assert any(item.kind == "zlib" and item.offset == 0 and item.end == len(stream) for item in carved)
    assert C.carve_all(_zlib_with_header(payload, 7, 2), zlib_dictionaries=(b"A" * 32769,)) == ()


def test_riff_avi_webp_positive_and_structural_corruption_decline():
    avi = _avi()
    assert next(item for item in C.carve_all(avi) if item.kind == "avi").data == avi
    assert not any(item.kind == "avi" for item in C.carve_all(avi.replace(b"hdrl", b"junk", 1)))
    webp = _image("WEBP")
    assert next(item for item in C.carve_all(webp) if item.kind == "webp").data == webp
    assert not any(item.kind == "webp" for item in C.carve_all(webp[:-3]))


def test_embedded_and_appended_polyglot_carving():
    png = _fixtures()["png"]
    embedded = b"random-prefix" + png + b"random-suffix"
    carved = C.carve_all(embedded)
    assert any(item.kind == "png" and item.offset == len(b"random-prefix") for item in carved)

    jpeg, archive = _fixtures()["jpeg"], _fixtures()["zip"]
    candidate = C.detect_polyglot(jpeg + archive)
    assert candidate is not None
    assert candidate.formats == ("jpeg", "zip")
    assert "appended" in candidate.relationship
    assert C.detect_polyglot(jpeg + archive[:-9]) is None
    assert C.detect_polyglot(b"not a file") is None


def test_nested_and_overlapping_objects_are_validated_without_container_false_polyglot():
    png = _fixtures()["png"]
    nested_stream = io.BytesIO()
    with zipfile.ZipFile(nested_stream, "w", compression=zipfile.ZIP_STORED) as outer:
        outer.writestr("nested.png", png)
    nested = nested_stream.getvalue()
    nested_objects = C.carve_all(nested)
    assert {item.kind for item in nested_objects} >= {"zip", "png"}
    assert C.detect_polyglot(nested) is None

    archive = _fixtures()["zip"]
    overlapping = (b"%PDF-1.4\n1 0 obj\n<< /Length 0 >>\nstream\n" + archive
                   + b"\nendstream\nendobj\nstartxref\n9\n%%EOF\n")
    objects = C.carve_all(overlapping)
    assert {item.kind for item in objects} >= {"pdf", "zip"}
    candidate = C.detect_polyglot(overlapping)
    assert candidate is not None and candidate.formats == ("pdf", "zip")
    assert "embedded" in candidate.relationship


def test_checked_file_slack_recovery_and_corrupt_decline():
    archive = _fixtures()["zip"]
    prefix = b"LIVE-DATA!"
    image = prefix + archive + b"\x00" * 16
    extent = C.FileExtent(0, len(prefix), len(image), "live.bin")
    recovered = C.carve_file_slack(image, [extent])
    assert len(recovered) == 1
    assert recovered[0].carvings[0].kind == "zip"
    assert recovered[0].carvings[0].offset == len(prefix)
    assert C.carve_file_slack(image, [C.FileExtent(0, len(prefix), len(prefix), "no-slack")]) == ()
    assert C.carve_file_slack(image, [C.FileExtent(-1, 0, len(image), "bad")]) == ()
    assert C.carve_file_slack(prefix + archive[:-5], [C.FileExtent(0, len(prefix), len(prefix + archive[:-5]))]) == ()


def test_checked_unallocated_recovery_and_bitmap_decline():
    block = 128
    archive = _fixtures()["zip"]
    allocated = b"A" * block
    unallocated = archive + b"\x00" * ((-len(archive)) % block)
    image = allocated + unallocated
    bitmap = [True] + [False] * (len(unallocated) // block)
    recovered = C.carve_unallocated(image, bitmap, block_size=block)
    assert len(recovered) == 1
    assert recovered[0].start == block
    assert recovered[0].carvings[0].offset == block
    assert recovered[0].carvings[0].kind == "zip"
    assert C.carve_unallocated(image, bitmap[:-1], block_size=block) == ()
    assert C.carve_unallocated(image, [True] * len(bitmap), block_size=block) == ()
    damaged = allocated + archive[:-8] + b"\x00" * (len(unallocated) - len(archive) + 8)
    assert C.carve_unallocated(damaged, bitmap, block_size=block) == ()


def test_carving_resource_and_expansion_bounds(monkeypatch):
    large_plain = b"A" * 512
    monkeypatch.setattr(C, "MAX_OUTPUT", 64)
    for compressed in (gzip.compress(large_plain, mtime=0), bz2.compress(large_plain),
                       lzma.compress(large_plain), zlib.compress(large_plain)):
        assert C.carve_all(compressed) == ()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large.bin", large_plain)
    assert C.carve_all(stream.getvalue()) == ()
    monkeypatch.setattr(C, "MAX_SCAN", 32)
    assert C.carve_all(b"X" * 33) == ()
    assert C.carve_all(_fixtures()["png"], max_carves=0) == ()
