"""Vendor RAW vectors cross-checked by ExifTool and literal container layouts."""
from __future__ import annotations

import json
import random
import shutil
import struct
import subprocess

import pytest

import ff2_raw_vendor as raw


EXIFTOOL = shutil.which("exiftool")
JPEG = b"\xff\xd8\xff\xd9"


def entry_le(tag, typ, count, value):
    if isinstance(value, int):
        field = struct.pack("<I", value)
    else:
        assert len(value) <= 4
        field = value.ljust(4, b"\0")
    return struct.pack("<HHI", tag, typ, count) + field


def nikon_note():
    # ExifTool Nikon.pm: Nikon\0\x02 prefix, then a standard TIFF at offset 0x0a.
    ifd = (struct.pack("<H", 2)
           + entry_le(0x0001, 7, 4, b"0210")
           + entry_le(0x0002, 3, 2, struct.pack("<HH", 100, 100))
           + struct.pack("<I", 0))
    return b"Nikon\0\x02\x10\0\0" + b"II*\0" + struct.pack("<I", 8) + ifd


def sony_note():
    # ExifTool Sony.pm: prefixed maker IFD starts 12 bytes after "SONY DSC ".
    ifd = (struct.pack("<H", 2)
           + entry_le(0x0102, 4, 1, 0)
           + entry_le(0xB000, 1, 4, b"\x03\x01\0\0")
           + struct.pack("<I", 0))
    return b"SONY DSC " + b"\0" * 3 + ifd


def tiff_raw(make: str, model: str, note: bytes):
    """Independent classic-TIFF builder with ExifIFD and IFD1 JPEG tags."""
    make_raw = make.encode("ascii") + b"\0"
    model_raw = model.encode("ascii") + b"\0"
    ifd0_at = 8
    ifd0_size = 2 + 3 * 12 + 4
    cursor = ifd0_at + ifd0_size
    make_at = cursor; cursor += len(make_raw)
    model_at = cursor; cursor += len(model_raw)
    cursor += cursor & 1
    exif_at = cursor; cursor += 2 + 12 + 4
    note_at = cursor; cursor += len(note)
    cursor += cursor & 1
    ifd1_at = cursor; cursor += 2 + 5 * 12 + 4
    jpeg_at = cursor; cursor += len(JPEG)
    output = bytearray(cursor)
    output[:8] = b"II*\0" + struct.pack("<I", ifd0_at)
    ifd0 = (struct.pack("<H", 3)
            + entry_le(0x010F, 2, len(make_raw), make_at)
            + entry_le(0x0110, 2, len(model_raw), model_at)
            + entry_le(0x8769, 4, 1, exif_at)
            + struct.pack("<I", ifd1_at))
    output[ifd0_at:ifd0_at + len(ifd0)] = ifd0
    output[make_at:make_at + len(make_raw)] = make_raw
    output[model_at:model_at + len(model_raw)] = model_raw
    exif = (struct.pack("<H", 1)
            + entry_le(0x927C, 7, len(note), note_at)
            + struct.pack("<I", 0))
    output[exif_at:exif_at + len(exif)] = exif
    output[note_at:note_at + len(note)] = note
    ifd1 = (struct.pack("<H", 5)
            + entry_le(0x0100, 4, 1, 1)
            + entry_le(0x0101, 4, 1, 1)
            + entry_le(0x0103, 3, 1, struct.pack("<H", 6))
            + entry_le(0x0201, 4, 1, jpeg_at)
            + entry_le(0x0202, 4, 1, len(JPEG))
            + struct.pack("<I", 0))
    output[ifd1_at:ifd1_at + len(ifd1)] = ifd1
    output[jpeg_at:jpeg_at + len(JPEG)] = JPEG
    return bytes(output), note_at


def fuji_note():
    ifd = (struct.pack("<H", 1)
           + entry_le(0x1000, 3, 1, struct.pack("<H", 2))
           + struct.pack("<I", 0))
    return b"FUJIFILM" + struct.pack("<I", 12) + ifd


def exif_tiff(note: bytes):
    make = b"FUJIFILM\0"
    model = b"X-T5\0"
    ifd_at = 8
    ifd_size = 2 + 3 * 12 + 4
    make_at = ifd_at + ifd_size
    model_at = make_at + len(make)
    exif_at = model_at + len(model) + ((model_at + len(model)) & 1)
    note_at = exif_at + 18
    output = bytearray(note_at + len(note))
    output[:8] = b"II*\0" + struct.pack("<I", ifd_at)
    ifd = (struct.pack("<H", 3)
           + entry_le(0x010F, 2, len(make), make_at)
           + entry_le(0x0110, 2, len(model), model_at)
           + entry_le(0x8769, 4, 1, exif_at)
           + struct.pack("<I", 0))
    output[ifd_at:ifd_at + len(ifd)] = ifd
    output[make_at:make_at + len(make)] = make
    output[model_at:model_at + len(model)] = model
    exif = (struct.pack("<H", 1)
            + entry_le(0x927C, 7, len(note), note_at)
            + struct.pack("<I", 0))
    output[exif_at:exif_at + len(exif)] = exif
    output[note_at:note_at + len(note)] = note
    return bytes(output)


def raf_fixture():
    tiff = exif_tiff(fuji_note())
    app1 = b"Exif\0\0" + tiff
    jpeg = b"\xff\xd8\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1 + b"\xff\xd9"
    metadata = (struct.pack(">I", 1) + struct.pack(">HHHH", 0x0100, 4, 480, 640))
    cfa = b"II*\0" + struct.pack("<IHI", 8, 0, 0)
    preview_at = 148
    metadata_at = preview_at + len(jpeg)
    cfa_at = metadata_at + len(metadata)
    header = bytearray(preview_at)
    header[:16] = b"FUJIFILMCCD-RAW "
    header[0x10:0x14] = b"0201"
    header[0x14:0x1C] = b"FF123456"
    header[0x1C:0x1C + 4] = b"X-T5"
    header[0x3C:0x40] = b"0100"
    struct.pack_into(">IIIIII", header, 0x54, preview_at, len(jpeg),
                     metadata_at, len(metadata), cfa_at, len(cfa))
    return bytes(header) + jpeg + metadata + cfa, jpeg


def exiftool_json(path, *tags):
    assert EXIFTOOL is not None, "ExifTool is the independent RAW oracle"
    command = [EXIFTOOL, "-j", "-n", *[f"-{tag}" for tag in tags], str(path)]
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)[0]


def test_nikon_nef_exiftool_vector(tmp_path):
    data, note_at = tiff_raw("NIKON CORPORATION", "NIKON Z 6", nikon_note())
    path = tmp_path / "vector.nef"
    path.write_bytes(data)
    oracle = exiftool_json(path, "Make", "Model", "MakerNoteVersion", "ISO")
    assert oracle["Make"] == "NIKON CORPORATION"
    assert oracle["Model"] == "NIKON Z 6"
    assert oracle["MakerNoteVersion"] == "0210"
    assert oracle["ISO"] == "100 100"
    report = raw.inventory(data)
    assert report["format"] == "nef" and report["vendor"] == "nikon"
    assert (report["make"], report["model"]) == (oracle["Make"], oracle["Model"])
    assert report["maker_notes"][0]["format"] == "nikon-type-3"
    assert report["maker_notes"][0]["offset"] == note_at
    assert report["maker_notes"][0]["ifds"][0]["tags"] == [1, 2]
    assert raw.extract_preview(data) == JPEG
    assert raw.extract_maker_note(data) == nikon_note()


def test_sony_arw_exiftool_vector(tmp_path):
    data, _note_at = tiff_raw("SONY", "ILCE-7M4", sony_note())
    path = tmp_path / "vector.arw"
    path.write_bytes(data)
    oracle = exiftool_json(path, "Make", "Model", "FileFormat", "Quality")
    assert oracle["Make"] == "SONY" and oracle["Model"] == "ILCE-7M4"
    assert oracle["FileFormat"] == "3 1 0 0"
    assert oracle["Quality"] == 0
    report = raw.inventory(data)
    assert report["format"] == "arw" and report["vendor"] == "sony"
    note = report["maker_notes"][0]
    assert note["format"] == "sony-prefixed"
    assert note["file_format_bytes"] == "03010000"
    assert note["ifds"][0]["tags"] == [0x0102, 0xB000]
    assert raw.extract_preview(data) == JPEG


def test_fuji_raf_exiftool_and_header_vector(tmp_path):
    data, jpeg = raf_fixture()
    path = tmp_path / "vector.raf"
    path.write_bytes(data)
    oracle = exiftool_json(path, "FileType", "RAFVersion", "RawImageFullSize",
                           "Make", "Model", "Quality")
    assert oracle["FileType"] == "RAF"
    assert oracle["RAFVersion"] == "0100"
    assert oracle["Make"] == "FUJIFILM" and oracle["Model"] == "X-T5"
    report = raw.inventory(data)
    assert report["format"] == "raf" and report["header"]["camera_model"] == "X-T5"
    assert report["header"]["directory_version"] == oracle["RAFVersion"]
    assert report["header"]["format_version"] == "0201"
    record = report["raf_metadata"]["records"][0]
    assert record["tag"] == 0x0100 and record["height"] == 480 and record["width"] == 640
    assert report["cfa"]["kind"] == "tiff"
    assert report["maker_notes"][0]["format"] == "fujifilm"
    assert report["maker_notes"][0]["ifds"][0]["tags"] == [0x1000]
    assert raw.extract_preview(data) == jpeg
    assert raw.extract_maker_note(data) == fuji_note()


def test_cli_guard_and_extract(tmp_path, capsys):
    data, _ = tiff_raw("SONY", "ILCE-7M4", sony_note())
    source = tmp_path / "source.arw"
    output = tmp_path / "preview.jpg"
    source.write_bytes(data)
    assert raw.main([str(source), "--extract-preview", "0", "--output", str(output)]) == 0
    assert output.read_bytes() == JPEG
    assert '"format": "arw"' in capsys.readouterr().out
    assert raw.main(["--not-an-option"]) == 2


def test_fail_closed_fuzz_truncation_bitflips_and_budget(monkeypatch):
    nef, _ = tiff_raw("NIKON CORPORATION", "NIKON Z 6", nikon_note())
    arw, _ = tiff_raw("SONY", "ILCE-7M4", sony_note())
    raf, _ = raf_fixture()
    rng = random.Random(0xFF2)
    corpus = [None, "写真.nef", bytearray(b"II"), b"", rng.randbytes(200)]
    for valid in (nef, arw, raf):
        corpus.extend(valid[:cut] for cut in range(0, len(valid), 23))
        for _ in range(24):
            changed = bytearray(valid)
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            corpus.append(bytes(changed))
    for supplied in corpus:
        for function in (raw.inventory, raw.extract_preview, raw.extract_maker_note):
            try:
                result = function(supplied)
                assert isinstance(result, (dict, bytes))
            except Exception as exc:
                assert type(exc) is raw.FF2RawVendorError
    monkeypatch.setattr(raw, "MAX_INPUT", 64)
    with pytest.raises(raw.FF2RawVendorError):
        raw.inventory(b"x" * 65)

