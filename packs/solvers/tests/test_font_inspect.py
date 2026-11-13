"""font_inspect: parse an SFNT/TTF name table and surface hidden flags/anomalies."""
from __future__ import annotations

import struct

import pytest

import font_inspect as fi


def _build_font(names, *, trailing=b"", sfnt=b"\x00\x01\x00\x00", base_offset=0):
    """Build a minimal valid SFNT with a single `name` table.

    names: list of (platformID, encodingID, languageID, nameID, text-bytes-already-encoded).
    base_offset: byte position where this SFNT will sit in the final file — SFNT table-directory
    offsets are absolute from the start of the FILE (matters when embedded in a TTC collection).
    """
    count = len(names)
    # name table: format(2) count(2) stringOffset(2) + count*record(12) + storage
    header = 6 + count * 12
    records = b""
    storage = b""
    for pid, eid, lid, nid, raw in names:
        off = len(storage)
        records += struct.pack(">HHHHHH", pid, eid, lid, nid, len(raw), off)
        storage += raw
    name_tbl = struct.pack(">HHH", 0, count, header) + records + storage
    # SFNT header: sfntVersion(4) numTables(2) searchRange(2) entrySelector(2) rangeShift(2)
    num_tables = 1
    sfnt_hdr = sfnt + struct.pack(">HHHH", num_tables, 0, 0, 0)
    dir_off = len(sfnt_hdr)
    tbl_off = dir_off + 16
    directory = struct.pack(">4sIII", b"name", 0, tbl_off + base_offset, len(name_tbl))
    return sfnt_hdr + directory + name_tbl + trailing


def _utf16(s):
    return s.encode("utf-16-be")


def test_extract_windows_name_flag():
    font = _build_font([
        (3, 1, 0x409, 1, _utf16("My Font Family")),
        (3, 1, 0x409, 0, _utf16("CSCTF{f0nt_n4me_t4ble}")),  # flag hidden in copyright
    ])
    r = fi.inspect(font)
    assert r["sfnt"] == "\x00\x01\x00\x00"
    assert len(r["tables"]) == 1 and r["tables"][0]["tag"] == "name"
    assert len(r["names"]) == 2
    texts = {n["name"]: n["text"] for n in r["names"]}
    assert texts["family"] == "My Font Family"
    assert texts["copyright"] == "CSCTF{f0nt_n4me_t4ble}"
    assert "CSCTF{f0nt_n4me_t4ble}" in r["flags"]


def test_mac_platform_name_decoded():
    font = _build_font([(1, 0, 0, 4, b"PlainMacName")])  # Mac platform, Mac-Roman
    r = fi.inspect(font)
    assert r["names"][0]["text"] == "PlainMacName"
    assert r["names"][0]["name"] == "full_name"


def test_trailing_data_anomaly_and_flag():
    # real appended payloads sit after the table data; a NUL separates it from the name storage
    font = _build_font([(3, 1, 0x409, 1, _utf16("Fam"))], trailing=b"\x00CSCTF{appended_after_tables}")
    r = fi.inspect(font)
    assert any("trailing data" in a for a in r["anomalies"])
    assert "CSCTF{appended_after_tables}" in r["flags"]


def test_unknown_name_id_reported_by_number():
    font = _build_font([(3, 1, 0x409, 256, _utf16("custom256"))])
    r = fi.inspect(font)
    assert r["names"][0]["name"] == "id_256"
    assert r["names"][0]["text"] == "custom256"


def test_otf_magic_accepted():
    font = _build_font([(3, 1, 0x409, 1, _utf16("OTF"))], sfnt=b"OTTO")
    r = fi.inspect(font)
    assert r["sfnt"] == "OTTO"
    assert r["names"][0]["text"] == "OTF"


def test_ttc_collection_first_font():
    # ttcf header is 16 bytes, so the inner SFNT sits at offset 16 and its (file-absolute) table
    # offsets must account for that
    inner = _build_font([(3, 1, 0x409, 0, _utf16("CSCTF{ttc}"))], base_offset=16)
    # ttcf header: tag(4) version(4) numFonts(4) offset[0](4) -> points at the inner SFNT
    ttc = b"ttcf" + struct.pack(">II", 0x00010000, 1) + struct.pack(">I", 16) + inner
    r = fi.inspect(ttc)
    assert "CSCTF{ttc}" in r["flags"]


def test_fail_closed():
    with pytest.raises(fi.FontError):
        fi.inspect("not bytes")
    with pytest.raises(fi.FontError):
        fi.inspect(b"too short")
    with pytest.raises(fi.FontError):
        fi.inspect(b"RIFF" + b"\x00" * 20)          # bad magic
    with pytest.raises(fi.FontError):
        fi.inspect(b"wOFF" + b"\x00" * 20)          # WOFF declines explicitly
    with pytest.raises(fi.FontError):
        fi.inspect(b"\x00\x01\x00\x00" + struct.pack(">HHHH", 9999, 0, 0, 0))  # implausible count


def test_truncated_name_table_does_not_crash():
    font = _build_font([(3, 1, 0x409, 1, _utf16("Fam"))])
    # chop off the storage so a record points past EOF -> must skip, not raise
    r = fi.inspect(font[:-2])
    assert isinstance(r["names"], list)  # fail-soft, no exception


def test_cli(capsys, tmp_path):
    font = _build_font([(3, 1, 0x409, 0, _utf16("CSCTF{cli_font}"))])
    p = tmp_path / "hidden.ttf"
    p.write_bytes(font)
    assert fi.main([str(p)]) == 0
    out = capsys.readouterr().out
    assert "CSCTF{cli_font}" in out
    assert fi.main([str(tmp_path / "missing.ttf")]) == 1
    assert fi.main(["--help"]) == 0
