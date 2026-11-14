"""Inert fixtures written from Symantec and published MC7 field layouts.

No malware, engine-produced fixture or PLC access. The bytearray assignments
below are an independent transcription of TS7CompactBlockInfo / MC7Converter;
ZIP creation uses Python's separate standard-library writer.
"""
import io
import argparse
import json
import random
import stat
import struct
import zipfile

import pytest

import ot_stuxnet_artifacts as engine


def mc7_fixture(number=888, kind=0x0A, body=b"inert!", variable=b"\0" * 12):
    # Header36 + data + variable interface/segment area + footer36.
    raw = bytearray(36 + len(body) + len(variable) + 36)
    raw[:6] = bytes([0x70, 0x70, 1, 1, 5, kind])
    struct.pack_into(">HII", raw, 6, number, len(raw), 0x12345678)
    struct.pack_into(">IHIH", raw, 16, 1234, 1, 0, 0)
    struct.pack_into(">HHHH", raw, 28, 6, 2, 32, len(body))
    raw[36:36 + len(body)] = body
    raw[36 + len(body):-36] = variable
    raw[-36:-28] = b"AUTHOR  "
    raw[-28:-20] = b"FAMILY\0\0"
    raw[-20:-12] = b"BLOCK   "
    raw[-12] = 0x12
    raw[-10:-8] = b"\xbe\xef"
    return bytes(raw)


def zipped(entries, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = compression
            archive.writestr(info, data)
    return stream.getvalue()


def codes(report):
    return [finding["code"] for row in report["entries"] for finding in row["findings"]]


def test_mc7_independent_layout_all_metadata():
    data = mc7_fixture()
    assert engine.parse_mc7(data) == {
        "format": "classic-mc7", "block_type": "DB", "block_number": 888,
        "language_code": 5, "language": "DB", "flags": 1, "header_unknown": 1,
        "security": 0x12345678, "load_size": 90, "mc7_offset": 36, "mc7_size": 6,
        "sbb_size": 6, "segment_size": 2, "local_data_size": 32,
        "variable_size": 12, "footer_offset": 54,
        "timestamps": {"code": {"days_since_1984_01_01": 1, "milliseconds": 1234},
                       "interface": {"days_since_1984_01_01": 0, "milliseconds": 0}},
        "author": "AUTHOR", "family": "FAMILY", "name": "BLOCK", "version": "1.2",
        "checksum_stored": 0xBEEF, "checksum_verified": False,
    }


@pytest.mark.parametrize("subtype,expected", [(8, "OB"), (10, "DB"), (11, "SDB"), (12, "FC"),
                                             (13, "SFC"), (14, "FB"), (15, "SFB")])
def test_mc7_type_codes(subtype, expected):
    assert engine.parse_mc7(mc7_fixture(35, subtype))["block_type"] == expected


def test_mc7_empty_body_minimum_footer():
    # A56-byte Snap7 footer VIEW includes preceding interface material;
    # this independently constructed minimum has the actual36-byte footer.
    data = bytearray(72)
    data[:6] = b"pp\1\0\5\x0a"
    struct.pack_into(">HI", data, 6, 1, 72)
    assert engine.parse_mc7(data)["mc7_size"] == 0


def test_mc7_truncations_and_trailing_data_fail_closed():
    data = mc7_fixture()
    for cut in range(len(data)):
        with pytest.raises(engine.StuxnetError):
            engine.parse_mc7(data[:cut])
    with pytest.raises(engine.StuxnetError):
        engine.parse_mc7(data + b"\0")


@pytest.mark.parametrize("offset,replacement", [(0, b"PP"), (5, b"\xff"), (8, b"\xff" * 4),
                                              (34, b"\xff\xff"), (28, b"\xff\xff"),
                                              (30, b"\xff\xff")])
def test_mc7_invalid_fields(offset, replacement):
    data = bytearray(mc7_fixture())
    data[offset:offset + len(replacement)] = replacement
    with pytest.raises(engine.StuxnetError):
        engine.parse_mc7(data)


def test_mc7_metadata_preserves_ambiguous_sbb_and_raw_timestamp():
    data = bytearray(mc7_fixture())
    # Documented readers do not normalize these metadata values. SBB can
    # describe actual-value bytes, so cannot be bounded by auxiliary bytes alone.
    struct.pack_into(">H", data, 28, 18)
    struct.pack_into(">I", data, 16, 86400000)
    result = engine.parse_mc7(data)
    assert result["sbb_size"] == 18
    assert result["timestamps"]["code"]["milliseconds"] == 86400000


def test_normal_dll_and_standard_ob_are_only_context():
    report = engine.scan_manifest([{"path": "S7BIN/s7otbxdx.dll"}, {"path": "OB1.awl"}])
    assert report["indicator_count"] == 0
    assert report["assessment"] == "no-indicators-observed"
    assert set(codes(report)) == {"step7-original-dll-name", "hook-target-ob"}


def test_documented_project_files_and_dll_pair_manifest_only():
    paths = ["P/XUTILS/listen/XR000000.MDX", "P/XUTILS/links/S7P00001.DBF",
             "P/XUTILS/listen/S7000001.MDX", "P/GracS/cc_alg.sav", "P/GracS/db_log.sav",
             "P/GracS/cc_tlg7.sav", "P/GracS/cc_tag.sav",
             "C:\\Step7\\S7BIN\\s7otbxdx.dll", "c:\\step7\\s7bin\\s7otbxsx.dll"]
    report = engine.scan_manifest([{"path": path, "size": 90} for path in paths])
    assert codes(report).count("documented-project-path") == 7
    assert report["correlations"][0]["code"] == "paired-step7-dll-names"
    assert all(not row["content_scanned"] for row in report["entries"])
    assert report["infection_confirmed"] is False
    assert report["assessment"] == "review-recommended"


@pytest.mark.parametrize("name,data,strong,name_only", [
    ("~WR12346.tmp", b"LRW~LRW~inert", True, True),  # 1+2+3+4+6=16
    ("~wr00000.TMP", b"LRW~LRW~", True, True),
    ("~WR12345.tmp", b"LRW~LRW~inert", False, False),
    ("~WR12346.tmp", b"xLRW~LRW~", False, True),
    ("~WR12346.tmp", b"LRW~LRW", False, True),
    ("~WTR4141.tmp", b"LRW~LRW~", False, False),
    ("~WR123460.tmp", b"LRW~LRW~", False, False),
    ("~WR12346.tmp.bak", b"LRW~LRW~", False, False),
])
def test_documented_wr_name_checksum_and_offset_zero_header(name, data, strong, name_only):
    result = codes(engine.scan_manifest([{"path": name, "data": data}]))
    assert ("wr-name-and-header" in result) is strong
    assert ("wr-checksummed-name" in result) is name_only


@pytest.mark.parametrize("number", [888, 889, 890, 891])
def test_db_number_from_real_metadata_not_only_filename(number):
    report = engine.scan_manifest([{"path": "opaque.bin", "data": mc7_fixture(number)}])
    row = report["entries"][0]
    assert row["mc7"]["block_number"] == number
    assert row["findings"] == [{"code": "documented-db-number", "strength": "context",
                               "detail": "Data-block number used by Stuxnet, also available to legitimate programs",
                               "block": f"DB{number}"}]
    assert report["indicator_count"] == 0


def test_raw_marker_offsets_with_explicit_encoding_and_bounded_results():
    report = engine.scan_manifest([{"path": "DB890.bin", "data": b"xx\xde\xad\xf0\x07..\x07\xf0\xad\xde deadf007"}])
    hits = [f for f in report["entries"][0]["findings"] if f["code"] == "deadf007-marker"]
    assert [(f["encoding"], f["offsets"]) for f in hits] == [
        ("binary-big-endian", [2]), ("binary-little-endian", [8]), ("ascii", [13])]
    many = engine.scan_manifest([{"path": "x", "data": b"DEADF007" * 100}])
    assert len(many["entries"][0]["findings"][0]["offsets"]) == 64
    assert many["entries"][0]["findings"][0]["offsets_truncated"] is True


@pytest.mark.parametrize("number,target", [(1, 1865), (35, 1874)])
def test_documented_stl_hook_sequence(number, target):
    # Literal instruction sequence transcribed from Symantec dossier pp36-37.
    text = (f"ORGANIZATION_BLOCK OB {number}\nBEGIN\nUC FC{target}\nPOP\n"
            "L DW#16#DEADF007\n==D\nBEC\nL DW#16#0\nL DW#16#0\nEND_ORGANIZATION_BLOCK\n").encode()
    report = engine.scan_manifest([{"path": "export.awl", "data": text}])
    hooks = [f for f in report["entries"][0]["findings"] if f["code"] == "documented-ob-hook"]
    assert len(hooks) == 1
    assert (hooks[0]["block"], hooks[0]["called_fc"]) == (f"OB{number}", target)
    assert "documented-ob-hook" not in codes(engine.scan_manifest([{"path": "export.awl", "data": text.replace(b"BEC", b"NOP 0")}]))
    assert "documented-ob-hook" not in codes(engine.scan_manifest([{"path": "export.awl", "data": text.replace(b"BEGIN", b"BEGIN\nNOP 0")}]))
    for start, end in ((b"(*", b"*)"), (b"/*", b"*/"), (b"(*", b"")):
        commented = start + text + end
        assert "documented-ob-hook" not in codes(engine.scan_manifest([{"path": "export.awl", "data": commented}]))


def test_similar_names_and_plain_comments_are_negative():
    entries = [{"path": p} for p in ("other/cc_alg.sav", "xutils/links/s7p00001.dbf.bak", "DB8888.bin", "s7otbxsx.dll.bak")]
    entries.append({"path": "OB1.awl", "data": b"// UC FC1865\n// POP\n// L DW#16#DEADF007\n"})
    report = engine.scan_manifest(entries)
    assert "documented-project-path" not in codes(report)
    assert "documented-ob-hook" not in codes(report)
    assert "documented-db-number" not in codes(report)


def test_zip_and_directory_inventory_match(tmp_path):
    files = [("project/~WR12346.tmp", b"LRW~LRW~synthetic"), ("project/opaque.bin", mc7_fixture())]
    for name, data in files:
        destination = tmp_path / name
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(data)
    archive = zipped(files)
    zipped_result = engine.scan_zip(archive)
    assert engine.scan_path(tmp_path) == zipped_result
    assert "wr-name-and-header" in codes(zipped_result)
    blocks = [row["mc7"] for row in zipped_result["entries"] if "mc7" in row]
    assert len(blocks) == 1 and blocks[0]["block_number"] == 888
    output = tmp_path / "inert.zip"
    output.write_bytes(archive)
    assert engine.scan_path(output) == zipped_result


@pytest.mark.parametrize("name", ["../outside", "/absolute", "C:\\outside", "a/../b", "a//b", "./b"])
def test_zip_rejects_unsafe_member_names(name):
    with pytest.raises(engine.StuxnetError):
        engine.scan_zip(zipped([(name, b"x")]))


def test_zip_rejects_links_and_duplicate_case():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "outside")
    with pytest.raises(engine.StuxnetError):
        engine.scan_zip(stream.getvalue())
    with pytest.raises(engine.StuxnetError):
        engine.scan_zip(zipped([("A", b""), ("a", b"")]))


def test_zip_ratio_and_entry_caps(monkeypatch):
    with pytest.raises(engine.StuxnetError):
        engine.scan_zip(zipped([("zeros", bytes(100000))], zipfile.ZIP_DEFLATED))
    monkeypatch.setattr(engine, "MAX_ENTRIES", 1)
    with pytest.raises(engine.StuxnetError):
        engine.scan_zip(zipped([("one", b""), ("two", b"")]))


def test_directory_rejects_symlinks_and_oversize(tmp_path, monkeypatch):
    (tmp_path / "link").symlink_to(tmp_path / "missing")
    with pytest.raises(engine.StuxnetError):
        engine.scan_path(tmp_path)
    (tmp_path / "link").unlink()
    (tmp_path / "file").write_bytes(b"1234")
    monkeypatch.setattr(engine, "MAX_FILE", 3)
    with pytest.raises(engine.StuxnetError):
        engine.scan_path(tmp_path)


@pytest.mark.parametrize("entries", [None, {}, [None], [{}], [{"path": None}], [{"path": "\ud800"}],
                                     [{"path": "x", "data": None}], [{"path": "x", "size": -1}],
                                     [{"path": "x", "size": True}], [{"path": "x", "size": 2, "data": b"a"}],
                                     [{"path": "X"}, {"path": "x"}]])
def test_malformed_manifests_fail_closed(entries):
    with pytest.raises(engine.StuxnetError):
        engine.scan_manifest(entries)


@pytest.mark.parametrize("value", [None, 1, "text", {}, [], memoryview(b"x")])
def test_binary_api_type_contract(value):
    for function in (engine.parse_mc7, engine.scan_zip):
        with pytest.raises(engine.StuxnetError):
            function(value)


def test_deterministic_binary_fuzz_and_malformed_mc7_inventory():
    rng = random.Random(0xF007)
    for size in range(180):
        data = rng.randbytes(size)
        for function in (engine.parse_mc7, engine.scan_zip):
            try:
                function(data)
            except engine.StuxnetError:
                pass
        report = engine.scan_manifest([{"path": "fuzz.bin", "data": b"pp" + data}])
        assert "mc7_error" in report["entries"][0]


def test_cli_all_modes_and_guard(tmp_path, capsys):
    artifact = tmp_path / "DB888.mc7"
    artifact.write_bytes(mc7_fixture())
    assert engine.main([str(artifact), "--mc7"]) == 0
    assert json.loads(capsys.readouterr().out)["block_number"] == 888
    assert engine.main([str(artifact)]) == 0
    assert "documented-db-number" in capsys.readouterr().out
    manifest = tmp_path / "manifest.json"
    manifest.write_text('[{"path":"s7otbxsx.dll"}]')
    assert engine.main([str(manifest), "--manifest"]) == 0
    assert json.loads(capsys.readouterr().out)["indicator_count"] == 1
    for argv in ([], ["--unknown"], [str(artifact), "--manifest", "--mc7"], [str(tmp_path / "missing")], [None], "wrong"):
        assert engine.main(argv) == 2
    assert engine.main(["--help"]) == 0


def test_scan_path_contract(tmp_path):
    for value in (None, 1, [], str(tmp_path / "missing"), "\0", "\ud800"):
        with pytest.raises(engine.StuxnetError):
            engine.scan_path(value)


def test_cli_noninteger_systemexit_and_released_buffer(monkeypatch):
    def invalid_exit(self, argv):
        raise SystemExit("invalid")
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", invalid_exit)
    assert engine.main([]) == 2
    view = memoryview(b"x")
    view.release()
    for function in (engine.parse_mc7, engine.scan_zip):
        with pytest.raises(engine.StuxnetError):
            function(view)
