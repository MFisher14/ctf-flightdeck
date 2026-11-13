"""Independent APPNOTE layouts, stdlib ZIP oracle, and deterministic mutations."""
import argparse
import io
import random
import struct
import zipfile
import zlib

import pytest

import ff_zipdiff_diagnostics as engine


def _local(name=b"note.txt", payload=b"CSCTF{fixture}", *, flags=0, method=0,
           crc=None, csize=None, usize=None, extra=b"", need=20, time=0, date=0):
    # Literal APPNOTE 4.3.7 field layout; never uses the engine's helpers.
    return (b"PK\x03\x04" + struct.pack("<HHHHHIIIHH", need, flags, method, time,
            date, zlib.crc32(payload) if crc is None else crc,
            len(payload) if csize is None else csize,
            len(payload) if usize is None else usize, len(name), len(extra))
            + name + extra + payload)


def _central(name=b"note.txt", payload=b"CSCTF{fixture}", *, offset=0, flags=0,
             method=0, crc=None, csize=None, usize=None, extra=b"", need=20,
             time=0, date=0, disk=0, made=20, attributes=0):
    return (b"PK\x01\x02" + struct.pack("<HHHHHHIIIHHHHHII", made, need, flags,
            method, time, date, zlib.crc32(payload) if crc is None else crc,
            len(payload) if csize is None else csize,
            len(payload) if usize is None else usize, len(name), len(extra),
            0, disk, 0, attributes, offset) + name + extra)


def _end(offset, size, count=1, *, comment=b"", disk=0, cd_disk=0, on_disk=None):
    return (b"PK\x05\x06" + struct.pack("<HHHHIIH", disk, cd_disk,
            count if on_disk is None else on_disk, count, size, offset, len(comment))
            + comment)


def _zip(local=None, central=None, count=1, **end_kw):
    local = _local() if local is None else local
    central = _central() if central is None else central
    return local + central + _end(len(local), len(central), count, **end_kw)


def _unicode(raw, name, *, crc=None, version=1):
    payload = bytes([version]) + struct.pack("<I", zlib.crc32(raw) if crc is None else crc) + name
    return struct.pack("<HH", 0x7075, len(payload)) + payload


def _view(blob, **kw):
    result = engine.analyze_zip(blob, **kw)
    assert len(result["views"]) == 1
    return result["views"][0]


def _codes(view):
    return {finding["code"] for finding in view["findings"]}


def test_stored_vector_offsets_and_zipfile_oracle():
    archive = _zip()
    view = _view(archive)
    entry = view["entries"][0]
    with zipfile.ZipFile(io.BytesIO(archive)) as oracle:
        info = oracle.infolist()[0]
        assert entry["name"]["name"] == info.filename == "note.txt"
        assert entry["crc32"] == info.CRC == zlib.crc32(b"CSCTF{fixture}")
        assert entry["compressed_size"] == info.compress_size == 14
        assert entry["uncompressed_size"] == info.file_size == 14
        assert oracle.read(info) == b"CSCTF{fixture}"
    assert entry["local"]["data_offset"] == 38
    assert entry["local"]["central_data_span"] == [38, 52]
    assert view["central_span"] == [52, 106]
    assert view["eocd_offset"] == 106
    assert not view["findings"]


@pytest.mark.parametrize("field,kw", [
    ("name_bytes", {"name": b"evil.txt"}), ("flags", {"flags": 1}),
    ("method", {"method": 8}), ("crc32", {"crc": 0x12345678}),
    ("compressed_size", {"csize": 1}), ("uncompressed_size", {"usize": 2}),
    ("version_needed", {"need": 45}), ("time", {"time": 123}),
    ("date", {"date": 456}),
])
def test_each_central_local_divergence(field, kw):
    findings = _view(_zip(local=_local(**kw)))["findings"]
    assert any(row["code"] == "header_mismatch" and row["field"] == field
               and row["offset"] == 0 for row in findings)


@pytest.mark.parametrize("signed", [False, True])
def test_descriptor_with_zero_local_fields(signed):
    payload = b"abc"
    dd = (b"PK\x07\x08" if signed else b"") + struct.pack("<III", zlib.crc32(payload), 3, 3)
    local = _local(payload=payload, flags=8, crc=0, csize=0, usize=0) + dd
    view = _view(_zip(local, _central(payload=payload, flags=8)))
    descriptor = view["entries"][0]["local"]["descriptor"]
    assert descriptor["status"] == "valid"
    assert descriptor["matches"][0]["signed"] is signed
    assert descriptor["matches"][0]["offset"] == 41
    assert not view["findings"]


def test_unsigned_descriptor_crc_is_signature():
    # CRC field equals the optional signature. Payload CRC intentionally isn't
    # claimed verified: this tests the descriptor/central metadata comparison.
    crc = 0x08074B50
    local = _local(payload=b"abc", flags=8, crc=0, csize=0, usize=0)
    local += struct.pack("<III", crc, 3, 3)
    view = _view(_zip(local, _central(payload=b"abc", flags=8, crc=crc)))
    descriptor = view["entries"][0]["local"]["descriptor"]
    assert descriptor["status"] == "valid"
    assert descriptor["matches"][0]["signed"] is False


@pytest.mark.parametrize("descriptor", [b"", b"PK\x07\x08", struct.pack("<III", 7, 8, 9)])
def test_missing_truncated_or_incorrect_descriptor(descriptor):
    local = _local(flags=8, crc=0, csize=0, usize=0) + descriptor
    assert "descriptor_invalid" in _codes(_view(_zip(local, _central(flags=8))))


def test_shared_local_alias_and_overlap():
    view = _view(_zip(central=_central() + _central(name=b"alias.txt"), count=2))
    assert {"local_header_alias", "record_overlap", "header_mismatch"} <= _codes(view)
    overlap = next(row for row in view["findings"] if row["code"] == "record_overlap")
    assert overlap["entries"] == [0, 1]
    assert overlap["overlap"] == [0, 52]


def test_distinct_nested_local_record_overlap():
    inside = _local(name=b"inside", payload=b"x")
    outer = _local(name=b"outer", payload=inside)
    # Outer data starts at 30 + len('outer') = 35. Inner record ends at 72.
    directory = _central(name=b"outer", payload=inside) + _central(name=b"inside", payload=b"x", offset=35)
    view = _view(_zip(outer, directory, count=2))
    assert "record_overlap" in _codes(view)
    assert "local_header_alias" not in _codes(view)
    assert next(row["overlap"] for row in view["findings"] if row["code"] == "record_overlap") == [35, 72]


def test_no_overlap_for_adjacent_records():
    first = _local(name=b"a", payload=b"1")
    second = _local(name=b"b", payload=b"2")
    directory = _central(name=b"a", payload=b"1") + _central(name=b"b", payload=b"2", offset=32)
    assert not _view(_zip(first + second, directory, count=2))["findings"]


def test_longer_local_size_crosses_next_header():
    first = _local(name=b"a", payload=b"1", csize=3)
    second = _local(name=b"b", payload=b"2")
    directory = _central(name=b"a", payload=b"1") + _central(name=b"b", payload=b"2", offset=32)
    view = _view(_zip(first + second, directory, count=2))
    assert "record_overlap" not in _codes(view)
    witness = next(row for row in view["findings"] if row["code"] == "local_size_overlap")
    assert witness["overlap"] == [32, 34]


def test_cp437_and_unicode_extra_conflict():
    raw = b"caf\x82.txt"
    extra = _unicode(raw, b"../outside.txt")
    view = _view(_zip(_local(name=raw, extra=extra), _central(name=raw, extra=extra)))
    name = view["entries"][0]["name"]
    assert name["name"] == "café.txt"
    assert name["unicode_paths"][0]["valid"] is True
    assert {"unicode_name_conflict", "unsafe_path"} <= _codes(view)
    assert any(row.get("interpretation") == "unicode_extra" for row in view["findings"])


@pytest.mark.parametrize("extra", [
    _unicode(b"note.txt", b"../outside", crc=0),
    _unicode(b"note.txt", b"../outside", version=2),
    _unicode(b"note.txt", b"\xff"), struct.pack("<HH", 0x7075, 1) + b"\x01",
])
def test_invalid_unicode_extra_never_becomes_active_name(extra):
    view = _view(_zip(_local(extra=extra), _central(extra=extra)))
    assert "invalid_unicode_extra" in _codes(view)
    assert "unsafe_path" not in _codes(view)
    assert "unicode_name_conflict" not in _codes(view)


def test_utf8_flag_and_invalid_utf8():
    raw = "café".encode()
    assert not _view(_zip(_local(name=raw, flags=0x800), _central(name=raw, flags=0x800)))["findings"]
    view = _view(_zip(_local(name=b"\xff", flags=0x800), _central(name=b"\xff", flags=0x800)))
    assert "invalid_utf8_name" in _codes(view)


@pytest.mark.parametrize("name", [b"../x", b"a/../../x", b"..\\x", b"/etc/x", b"C:\\x", b"\\\\srv\\x", b"safe\0../x", b""])
def test_all_name_views_flag_unsafe_paths(name):
    view = _view(_zip(_local(name=name), _central(name=name)))
    paths = [row for row in view["findings"] if row["code"] == "unsafe_path"]
    assert {row["source"] for row in paths} == {"local", "central"}


def test_in_root_parent_normalization_does_not_escape():
    assert "unsafe_path" not in _codes(_view(_zip(_local(name=b"a/../b"), _central(name=b"a/../b"))))


def test_duplicate_names_are_evidence_separate_from_alias():
    view = _view(_zip(central=_central() + _central(), count=2))
    assert {"duplicate_central_name", "local_header_alias"} <= _codes(view)


def test_two_valid_eocd_records_and_terminal_ambiguity():
    prefix = _local() + _central()
    second = _end(52, 54)
    # First EOCD's comment is itself a complete EOCD; both views end at EOF.
    archive = prefix + _end(52, 54, comment=second)
    result = engine.analyze_zip(archive)
    assert [row["eocd_offset"] for row in result["views"]] == [106, 128]
    assert {"multiple_eocd", "ambiguous_terminal_views"} <= _codes(result)


def test_fake_eocd_signature_in_data_is_not_a_second_view():
    payload = b"PK\x05\x06" + b"\xff" * 25
    result = engine.analyze_zip(_zip(_local(payload=payload), _central(payload=payload)))
    assert len(result["views"]) == 1
    assert len(result["rejected_eocd"]) == 1
    assert not result["findings"]


def test_complete_empty_eocd_in_payload_is_qualified():
    payload = _end(0, 0, 0)
    result = engine.analyze_zip(_zip(_local(payload=payload), _central(payload=payload)))
    assert len(result["views"]) == 2
    assert "payload_contained_eocd" in _codes(result["views"][0])
    assert "multiple_eocd" not in _codes(result)
    assert result["views"][0]["contained_in_payload"] == [{"eocd_offset": 114, "entry": 0}]


def test_trailer_and_prefixed_archive_offsets():
    view = _view(b"PREFIX" + _zip() + b"TRAILER")
    assert view["archive_base"] == 6
    assert view["entries"][0]["local"]["data_offset"] == 44
    assert view["trailing_bytes"] == 7
    assert {"rebased_offsets", "trailing_bytes"} <= _codes(view)


def _zip64(*, prefix=b"", descriptor=False):
    payload = b"xyz"
    xlocal = struct.pack("<HHQQ", 1, 16, 3, 3)
    local = _local(payload=payload, extra=xlocal, csize=0xFFFFFFFF,
                   usize=0xFFFFFFFF, need=45, flags=8 if descriptor else 0,
                   crc=0 if descriptor else None)
    if descriptor:
        local += b"PK\x07\x08" + struct.pack("<IQQ", zlib.crc32(payload), 3, 3)
    xcentral = struct.pack("<HHQQQ", 1, 24, 3, 3, 0)
    central = _central(payload=payload, extra=xcentral, offset=0xFFFFFFFF,
                       csize=0xFFFFFFFF, usize=0xFFFFFFFF, need=45,
                       flags=8 if descriptor else 0)
    at = len(local) + len(central)
    z64 = b"PK\x06\x06" + struct.pack("<QHHIIQQQQ", 44, 45, 45, 0, 0, 1, 1, len(central), len(local))
    locator = b"PK\x06\x07" + struct.pack("<IQI", 0, at, 1)
    return prefix + local + central + z64 + locator + _end(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF)


@pytest.mark.parametrize("prefix", [b"", b"SFX PREFIX"])
@pytest.mark.parametrize("descriptor", [False, True])
def test_zip64_metadata_offsets_and_descriptor(prefix, descriptor):
    archive = _zip64(prefix=prefix, descriptor=descriptor)
    view = _view(archive)
    entry = view["entries"][0]
    assert view["zip64"] is True
    assert view["archive_base"] == len(prefix)
    assert entry["compressed_size"] == entry["uncompressed_size"] == 3
    assert entry["local_offset"] == 0
    assert entry["local"]["data_offset"] == len(prefix) + 58
    assert _codes(view) <= {"rebased_offsets"}
    if descriptor:
        match = entry["local"]["descriptor"]["matches"][0]
        assert match["zip64"] is True
        assert match["end"] - match["offset"] == 24
    else:
        with zipfile.ZipFile(io.BytesIO(archive)) as oracle:
            assert oracle.read("note.txt") == b"xyz"


def test_zip64_extra_only_consumes_sentinel_fields():
    extra = struct.pack("<HHQ", 1, 8, 14)
    view = _view(_zip(central=_central(usize=0xFFFFFFFF, extra=extra)))
    assert view["entries"][0]["uncompressed_size"] == 14
    assert not view["findings"]


@pytest.mark.parametrize("extension", [b"", b"extension contains PK\x06\x06 and padding"])
def test_empty_zip64_with_prefix_and_extension_magic(extension):
    record = b"PK\x06\x06" + struct.pack("<QHHIIQQQQ", 44 + len(extension), 45, 45, 0, 0, 0, 0, 0, 0) + extension
    locator = b"PK\x06\x07" + struct.pack("<IQI", 0, 0, 1)
    archive = b"PREFIX" + record + locator + _end(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF)
    view = _view(archive)
    assert view["archive_base"] == 6
    assert view["zip64_offset"] == 6
    assert view["entries"] == []


def test_zip64_sentinel_without_locator_rejects():
    with pytest.raises(engine.ZipDiffError):
        engine.analyze_zip(_end(0xFFFFFFFF, 0xFFFFFFFF, 0xFFFF))


def test_multidisk_reports_metadata_without_inventing_entries():
    result = engine.analyze_zip(_zip(disk=1, cd_disk=0))
    assert result["views"] == []
    assert "multidisk_unsupported" in _codes(result)
    assert result["rejected_eocd"][0]["metadata"]["disk"] == 1


def test_directory_digital_signature():
    central = _central() + b"PK\x05\x05\x03\x00sig"
    assert not _view(_zip(central=central))["findings"]


def test_declared_expansion_and_symlink_evidence_no_payload_inflation(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("metadata analyzer attempted decompression")
    monkeypatch.setattr(zlib, "decompress", forbidden)
    monkeypatch.setattr(zlib, "decompressobj", forbidden)
    view = _view(_zip(_local(payload=b"x", method=8, usize=1 << 30),
        _central(payload=b"x", method=8, usize=1 << 30, made=3 << 8, attributes=0o120777 << 16)))
    assert {"declared_ratio_limit", "declared_output_limit", "symlink_member"} <= _codes(view)
    assert view["declared_uncompressed_total"] == 1 << 30


def test_out_of_bounds_spans_reported_not_read():
    view = _view(_zip(central=_central(csize=0xFFFFFFFE)))
    assert "data_out_of_bounds" in _codes(view)


@pytest.mark.parametrize("kw", [{"max_input_bytes": 1}, {"max_entries": 1},
    {"max_candidates": 1}, {"max_findings": 1}, {"max_metadata_bytes": 1}])
def test_resource_caps(kw):
    archive = _zip(central=_central() + _central(), count=2) + _end(52, 108, 2)
    with pytest.raises(engine.ZipDiffError):
        engine.analyze_zip(archive, **kw)


@pytest.mark.parametrize("kw", [{"max_ratio": 0}, {"max_entries": -1},
    {"max_declared_output": float("inf")}, {"max_input_bytes": True}])
def test_invalid_limits_fail_closed(kw):
    with pytest.raises(engine.ZipDiffError):
        engine.analyze_zip(_zip(), **kw)


@pytest.mark.parametrize("data", [None, "PK", 123, [], {}, memoryview(b"PK")[::2]])
def test_invalid_input_contract(data):
    with pytest.raises(engine.ZipDiffError):
        engine.analyze_zip(data)


def _fuzz_cases():
    rng = random.Random(0x5A17)
    yield b""
    for length in [1, 3, 4, 8, 16, 22, 30, 46, 64, 128, 256, 1024]:
        yield b"\xff" * length
        yield rng.randbytes(length)
    for fixture in [_zip(), _zip64(), _zip(disk=1)]:
        for length in range(len(fixture)):
            yield fixture[:length]
        for _ in range(64):
            changed = bytearray(fixture)
            changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
            yield bytes(changed)


@pytest.mark.parametrize("blob", list(_fuzz_cases()), ids=lambda blob: f"bytes-{len(blob)}")
def test_fail_closed_deterministic_fuzz(blob):
    try:
        result = engine.analyze_zip(blob)
    except engine.ZipDiffError:
        return
    assert result["format"] == "zip"
    assert result["payloads_verified"] is False


def test_cli(tmp_path, capsys):
    path = tmp_path / "sample.zip"
    path.write_bytes(_zip())
    assert engine.main([str(path)]) == 0
    assert '"payloads_verified": false' in capsys.readouterr().out
    assert engine.main([str(path), "--max-input", "1"]) == 2
    assert engine.main([str(path), "--max-input", str(engine.MAX_INPUT + 1)]) == 2
    assert engine.main([str(path.parent / "missing")]) == 2
    assert engine.main(["\x00"]) == 2
    assert engine.main([]) == 2
    assert engine.main(["--help"]) == 0


def test_cli_noninteger_systemexit_guard(monkeypatch):
    def fail(*args, **kwargs):
        raise SystemExit("parse failure")
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args", fail)
    assert engine.main([]) == 2
