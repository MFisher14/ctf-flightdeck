from __future__ import annotations

import binascii
import bz2
import gzip
import io
import struct
import sys
import zipfile
import zlib
from pathlib import Path


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers/toolkits"
sys.path.insert(0, str(TOOLKITS))
import file_repair as F  # noqa: E402


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (struct.pack(">I", len(payload)) + kind + payload
            + struct.pack(">I", binascii.crc32(kind + payload) & 0xFFFFFFFF))


def _tiny_png() -> bytes:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = b"\x00\x12\x34\x56"  # filter byte + one RGB pixel
    return F.PNG_SIG + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", zlib.compress(raw)) + F.PNG_IEND


def test_png_repairs_signature_crc_and_missing_iend_only_after_decode():
    original = _tiny_png()
    broken = bytearray(original[:-12])  # remove IEND
    broken[:8] = b"BADPNG!!"
    # Damage only the stored IHDR CRC; the bounded IDAT pixels remain independently valid.
    ihdr_crc = 8 + 4 + 4 + 13
    broken[ihdr_crc:ihdr_crc + 4] = b"\x00\x00\x00\x00"
    result = F.repair(bytes(broken), "png")
    assert result.status == "repaired" and result.candidate is not None
    assert F.repair(result.candidate, "png").status == "valid"
    assert any("decode validated" in line for line in result.diagnostics)


def test_png_refuses_corrupt_pixel_stream():
    original = _tiny_png()
    idat_at = original.index(b"IDAT")
    corrupted = bytearray(original)
    corrupted[idat_at + 4:idat_at + 8] = b"nope"
    # Make the edited payload's chunk CRC self-consistent: zlib decode must still reject it.
    length = struct.unpack_from(">I", corrupted, idat_at - 4)[0]
    crc_at = idat_at + 4 + length
    struct.pack_into(">I", corrupted, crc_at,
                     binascii.crc32(corrupted[idat_at:idat_at + 4 + length]) & 0xFFFFFFFF)
    result = F.repair(bytes(corrupted), "png")
    assert result.status == "unrecoverable" and result.candidate is None


def _zip_fixture() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("one.txt", b"first verified member")
        archive.writestr("two.bin", b"\x00\x01\x02" * 20)
    return stream.getvalue()


def test_zip_rebuilds_missing_central_directory_and_round_trips():
    original = _zip_fixture()
    broken = original[:original.index(b"PK\x01\x02")]
    result = F.repair(broken, "zip")
    assert result.status == "repaired" and result.recovered_items == 2
    assert result.candidate is not None
    with zipfile.ZipFile(io.BytesIO(result.candidate)) as archive:
        assert archive.read("one.txt") == b"first verified member"
        assert archive.read("two.bin") == b"\x00\x01\x02" * 20


def test_zip_salvages_only_complete_crc_verified_prefix():
    original = _zip_fixture()
    first = original.find(b"PK\x03\x04")
    second = original.find(b"PK\x03\x04", first + 4)
    assert second > 0
    broken = original[:second + 20]  # second local header is incomplete
    result = F.repair(broken, "zip")
    assert result.status == "repaired" and result.recovered_items == 1
    with zipfile.ZipFile(io.BytesIO(result.candidate)) as archive:
        assert archive.namelist() == ["one.txt"]


def _pdf_without_xref() -> bytes:
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n"
    )


def test_pdf_rebuilds_and_revalidates_classic_xref():
    result = F.repair(_pdf_without_xref(), "pdf")
    assert result.status == "repaired" and result.recovered_items == 2
    assert result.candidate is not None and b"startxref" in result.candidate
    assert F.repair(result.candidate, "pdf").status == "valid"


def test_pdf_refuses_an_unresolved_pages_tree():
    bad = b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 99 0 R >> endobj\n"
    result = F.repair(bad, "pdf")
    assert result.status == "unrecoverable" and result.candidate is None


def test_gzip_reconstructs_only_a_complete_deflate_stream_trailer():
    payload = b"bounded gzip fixture" * 100
    original = gzip.compress(payload, mtime=0)
    result = F.repair(original[:-8], "gzip")
    assert result.status == "repaired" and result.candidate is not None
    assert gzip.decompress(result.candidate) == payload
    assert F.repair(original[:-20], "gzip").status == "unrecoverable"


def test_bzip2_strips_tail_and_salvages_complete_concatenated_prefix():
    one = bz2.compress(b"one" * 50)
    two = bz2.compress(b"two" * 50)
    result = F.repair(one + two + b"garbage", "bzip2")
    assert result.status == "repaired" and result.recovered_items == 2
    assert bz2.decompress(result.candidate) == b"one" * 50 + b"two" * 50
    truncated = F.repair(one + two[:-10], "bzip2")
    assert truncated.status == "repaired" and truncated.recovered_items == 1
    assert bz2.decompress(truncated.candidate) == b"one" * 50


def test_guarded_cli_never_traces_back(tmp_path, capsys):
    missing = tmp_path / "missing.bin"
    assert F.main([str(missing), "--json"]) == 2
    assert "file_repair:" in capsys.readouterr().err
    malformed = tmp_path / "broken.png"
    malformed.write_bytes(F.PNG_SIG + b"garbage")
    assert F.main([str(malformed), "--format", "png"]) == 2
    assert "file_repair:" in capsys.readouterr().err

