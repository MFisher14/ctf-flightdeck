"""ESE headers/types locked to dissect.esedb and Microsoft format definitions.

References: microsoft/Extensible-Storage-Engine dev/ese/src/inc/daedef.hxx;
https://learn.microsoft.com/en-us/dotnet/api/system.datetime.fromoadate
"""
import hashlib
import io
import random
import struct
import uuid

import pytest
from dissect.esedb.c_esedb import c_esedb, COLUMN_TYPE_MAP
from dissect.esedb import EseDB

import ese_reader as engine


def header():
    raw = bytearray(4096 * 8)
    struct.pack_into("<III", raw, 4, 0x89ABCDEF, 0x620, 0)
    struct.pack_into("<IIII", raw, 228, 3, 17, 4096, 9)
    return raw


def leaf(records, object_id):
    raw = bytearray(4096)
    struct.pack_into("<I", raw, 24, object_id)
    struct.pack_into("<H", raw, 34, len(records) + 1)
    struct.pack_into("<I", raw, 36, 3)  # root + leaf
    offset = 0
    for index, record in enumerate(records, 1):
        cell = b"\x00\x00" + record  # zero-length local key
        raw[40 + offset:40 + offset + len(cell)] = cell
        struct.pack_into("<HH", raw, 4096 - 4 * (index + 1), len(cell), offset)
        offset += len(cell)
    struct.pack_into("<H", raw, 32, offset)
    return raw


def catalog_record(kind, ident, typ, name, width=0):
    # MSysObjects fixed fids1..9, then 2 null-bitmap bytes, then variable fid128.
    codepage = 1200 if kind == 2 and typ == 10 else 0
    fixed = struct.pack("<I H I I I I I B H", 10, kind, ident, typ, width, 0, codepage, 0, 0)
    name = name.encode("ascii")
    return struct.pack("<BBH", 9, 128, 4 + len(fixed) + 2) + fixed + b"\0\0" + struct.pack("<H", len(name)) + name


def database():
    raw = header()
    raw[5 * 4096:6 * 4096] = leaf([
        catalog_record(1, 10, 5, "Datum"),
        catalog_record(2, 1, 4, "Count", 4),
        catalog_record(2, 128, 10, "Label")], 2)
    rows = []
    for count, label in [(42, "Alpha"), (-7, "Beta")]:
        text = label.encode("utf-16-le")
        rows.append(struct.pack("<BBHiBH", 1, 128, 9, count, 0, len(text)) + text)
    raw[6 * 4096:7 * 4096] = leaf(rows, 10)
    return bytes(raw)


def test_header_layout_against_dissect_schema():
    raw = bytes(header())
    ref = c_esedb.DBFILEHDR(raw)
    actual = engine.read_header(raw)
    assert actual["page_size"] == ref.cbPageSize == 4096
    assert actual["format_version"] == ref.ulVersion == 0x620
    assert actual["file_type"] == ref.attrib == 0
    assert ref.ulDaeUpdateMajor == 17 and ref.lSPNumber == 3 and ref.ulRepairCount == 9


def test_header_revision_against_dissect_schema():
    raw = bytes(header())
    assert engine.read_header(raw)["format_revision"] == c_esedb.DBFILEHDR(raw).ulDaeUpdateMajor


def test_logical_page_count_excludes_both_headers():
    raw = database()
    assert engine.Database(raw).total_pages == len(raw) // 4096 - 2


def test_catalog_rows_counts_and_reports_from_independent_layout():
    raw = database()
    db = engine.Database(raw)
    assert db.tables() == {10: {"name": "Datum", "fdp": 5}}
    assert [col["name"] for col in db.columns(10)] == ["Count", "Label"]
    assert db.table_by_name("Datum") == (10, {"name": "Datum", "fdp": 5})
    oracle = EseDB(io.BytesIO(raw))
    oracle_rows = [record.as_dict() for record in oracle.table("Datum").records()]
    assert list(db.rows(10)) == oracle_rows == [{"Count": 42, "Label": "Alpha"}, {"Count": -7, "Label": "Beta"}]
    assert db.count_rows(10) == (2, True)
    assert db.count_rows(999) == (None, False)
    result = engine.classify(raw)
    assert result["catalog_complete"] is True
    assert result["tables"][0]["name"] == "Datum"
    reports = engine.reports({"fixture.edb": raw})
    assert len(reports) == 1 and reports[0][1]["digest"] == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize("typ,fmt,value", [(2,"B",255),(3,"h",-123),(4,"i",-123456),(5,"q",-10000),(6,"f",1.25),(7,"d",-3.125),(14,"I",4000000000),(15,"q",-2**60),(17,"H",60000)])
def test_numeric_columns_against_dissect(typ, fmt, value):
    raw = struct.pack("<" + fmt, value)
    assert engine._decode_value(typ, raw) == COLUMN_TYPE_MAP[typ].parse(raw) == value


def test_guid_and_ole_published_vectors():
    value = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff")
    assert engine._decode_value(16, value.bytes_le) == COLUMN_TYPE_MAP[16].parse(value.bytes_le) == str(value)
    for days, expected in [(0,"1899-12-30T00:00:00Z"),(2,"1900-01-01T00:00:00Z"),(2.5,"1900-01-01T12:00:00Z"),(3.25,"1900-01-02T06:00:00Z")]:
        assert engine._decode_value(8, struct.pack("<d", days)) == expected
    for days in [float("nan"), float("inf"), 1e300]:
        assert engine._decode_value(8, struct.pack("<d", days)) is None


@pytest.mark.parametrize("days,expected", [(-0.5,"1899-12-30T12:00:00Z"),(-1.25,"1899-12-29T06:00:00Z")])
def test_negative_ole_date_published_semantics(days, expected):
    assert engine._decode_value(8, struct.pack("<d", days)) == expected


def test_caps_mark_counts_incomplete(monkeypatch):
    raw = database()
    monkeypatch.setattr(engine, "MAX_ROWS", 1)
    db = engine.Database(raw)
    # Build complete catalog before limiting data rows separately.
    monkeypatch.setattr(engine, "MAX_ROWS", 4096)
    assert db.tables()
    monkeypatch.setattr(engine, "MAX_ROWS", 1)
    assert list(db.rows(10)) == [{"Count": 42, "Label": "Alpha"}]
    assert db.count_rows(10) == (1, False)
    monkeypatch.setattr(engine, "MAX_FILE", 32)
    assert engine.reports({"fixture.edb": raw}) == []


def test_public_parser_fuzz_declared_errors_only():
    rng = random.Random(701)
    valid = database()
    samples = [None, [], "not-bytes", b"", b"\xff" * 2048, rng.randbytes(4096)]
    samples += [valid[:n] for n in [1,7,100,667,4095,20000]]
    for offset in [4,8,12,228,232,236,5*4096+34,6*4096+4090]:
        changed = bytearray(valid); changed[offset] ^= 0x80; samples.append(bytes(changed))
    for raw in samples:
        for function in [engine.read_header, engine.classify, engine.Database]:
            try:
                result = function(raw)
                if isinstance(result, engine.Database):
                    result.tables(); result.columns(10); list(result.rows(10)); result.count_rows(10)
            except engine.EseError:
                pass


def test_zero_row_limit():
    assert list(engine.Database(database()).rows(10, limit=0)) == []


def test_direct_classify_input_cap(monkeypatch):
    monkeypatch.setattr(engine, "MAX_FILE", 32)
    assert engine.classify(database()) is None


def test_reports_malformed_container_fail_closed():
    try:
        engine.reports([b"bad"])
    except engine.EseError:
        pass
