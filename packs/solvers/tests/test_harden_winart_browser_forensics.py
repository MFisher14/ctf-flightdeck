"""Real SQLite/plist writers; independent LevelDB records and HTTP wire bytes.

Sources: sqlite.org/fileformat2.html; google/leveldb doc/log_format.md;
Chromium base/time/time.h Windows epoch; RFC9112 HTTP/1.1 framing.
"""
import datetime
import hashlib
import json
import plistlib
import random
import sqlite3
import struct

import pytest

import browser_forensics as engine


def sql_db(script, inserts):
    with sqlite3.connect(":memory:") as db:
        db.executescript(script)
        for statement, values in inserts:
            db.execute(statement, values)
        db.commit()
        return db.serialize()


def chromium():
    return sql_db("CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,last_visit_time INTEGER); CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER);", [
        ("INSERT INTO urls VALUES(1,?,?,?,?)", ("https://example.invalid/", "Known title", 3, 13344473600123456)),
        ("INSERT INTO visits VALUES(1,1,?)", (13344473600123456,))])


def test_sqlite_chromium_real_writer_and_exact_webkit_time():
    raw = chromium()
    assert engine.validate_sqlite_bundle(raw) == (raw, None, 0)
    result = engine.decode_browser_database(raw)
    assert (result.browser, result.artifact, result.schema) == ("chromium", "history", "chromium_history")
    assert result.sha256 == hashlib.sha256(raw).hexdigest()
    assert len(result.records) == 2
    for row in result.records:
        assert row.url == "https://example.invalid/"
        assert row.timestamp == "2023-11-14T22:13:20.123456+00:00"
    assert next(row for row in result.records if row.kind == "url").title == "Known title"


def test_firefox_prtime_and_safari_mac_epoch():
    raw = sql_db("CREATE TABLE moz_places(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INTEGER,last_visit_date INTEGER);", [
        ("INSERT INTO moz_places VALUES(1,?,?,?,?)", ("https://example.invalid/", "Fox", 2, 1700000000123456))])
    result = engine.decode_browser_database(raw)
    assert result.browser == "firefox"
    assert result.records[0].timestamp == "2023-11-14T22:13:20.123456+00:00"
    raw = sql_db("CREATE TABLE history_items(id INTEGER PRIMARY KEY,url TEXT); CREATE TABLE history_visits(id INTEGER PRIMARY KEY,history_item INTEGER,visit_time REAL,title TEXT);", [
        ("INSERT INTO history_items VALUES(1,?)", ("https://example.invalid/",)),
        ("INSERT INTO history_visits VALUES(1,1,?,?)", (721692800.25, "Safari"))])
    result = engine.decode_browser_database(raw)
    assert result.browser == "safari"
    assert {row.timestamp for row in result.records} == {"2023-11-14T22:13:20.250000+00:00"}


def test_real_sqlite_wal_bundle(tmp_path):
    path = tmp_path / "fixture.sqlite"
    db = sqlite3.connect(path)
    try:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("CREATE TABLE ItemTable(key TEXT,value TEXT)")
        db.commit(); db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        raw = path.read_bytes()
        db.execute("INSERT INTO ItemTable VALUES('flag','CSCTF{wal_fixture}')"); db.commit()
        wal = path.with_name(path.name + "-wal").read_bytes()
        frames = (len(wal) - 32) // (24 + int.from_bytes(raw[16:18], "big"))
        assert engine.validate_sqlite_bundle(raw, wal=wal) == (raw, wal, frames)
        result = engine.decode_browser_database(raw, wal=wal)
        assert result.wal_frames == frames and result.records[0].value == "CSCTF{wal_fixture}"
        corrupted = bytearray(wal); corrupted[-1] ^= 1
        assert engine.validate_sqlite_bundle(raw, wal=corrupted) is None
    finally:
        db.close()


def crc32c(raw):
    value = 0xFFFFFFFF
    for byte in raw:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


def varint(value):
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128); value >>= 7
    out.append(value)
    return bytes(out)


def batch(rows, sequence=50):
    out = struct.pack("<QI", sequence, len(rows))
    for key, value in rows:
        out += bytes([value is not None]) + varint(len(key)) + key
        if value is not None:
            out += varint(len(value)) + value
    return out


def frame(payload, kind=1):
    crc = crc32c(bytes([kind]) + payload)
    masked = (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF
    return struct.pack("<IHB", masked, len(payload), kind) + payload


def test_leveldb_crc_and_localstorage_reference_records():
    assert crc32c(b"123456789") == 0xE3069283
    assert engine._crc32c(b"123456789") == 0xE3069283
    key = b"_https://example.invalid\0\x01flag"
    raw = frame(batch([(key, b"\x01CSCTF{leveldb_fixture}"), (key, None)]))
    result = engine.decode_leveldb_storage(raw, store="localstorage")
    assert [(r.sequence,r.state,r.origin,r.key,r.value) for r in result] == [
        (50,"live","https://example.invalid","flag","CSCTF{leveldb_fixture}"),
        (51,"deleted","https://example.invalid","flag",None)]
    changed = bytearray(raw); changed[-1] ^= 1
    assert engine.decode_leveldb_storage(changed, store="localstorage") is None


def test_leveldb_fragmented_indexeddb_and_caps(monkeypatch):
    payload = batch([(b"opaque-key", b"x" * 35000)])
    raw = frame(payload[:32761], 2) + frame(payload[32761:], 4)
    result = engine.decode_leveldb_storage(raw, store="indexeddb", origin="https://example.invalid")
    assert result[0].key == b"opaque-key" and result[0].value == b"x" * 35000
    monkeypatch.setattr(engine, "MAX_VALUE", 32)
    assert engine.decode_leveldb_storage(raw, store="indexeddb") is None


def test_http_contentlength_chunked_and_caps(monkeypatch):
    payload = b"CSCTF{http_fixture}"
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(payload)).encode() + b"\r\n\r\n" + payload
    result = engine.decode_http_cache_object(raw, browser="chromium", url="https://example.invalid")
    assert result.status == 200 and result.body == payload
    assert result.sha256 == hashlib.sha256(payload).hexdigest()
    chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;name=value\r\nde\r\n0\r\n\r\n"
    assert engine.decode_http_cache_object(chunked, browser="firefox", url="https://example.invalid").body == b"abcde"
    monkeypatch.setattr(engine, "MAX_VALUE", 4)
    assert engine.decode_http_cache_object(raw, browser="chromium", url="https://example.invalid") is None


@pytest.mark.parametrize("fmt", [plistlib.FMT_BINARY, plistlib.FMT_XML])
def test_safari_session_real_plist_writer(fmt, monkeypatch):
    doc = {"SessionWindows": [{"SelectedTabIndex": 1, "TabStates": [
        {"TabURL": "https://example.invalid/one", "TabTitle": "One"},
        {"TabURL": "https://example.invalid/two", "TabTitle": "Two"}]}]}
    raw = plistlib.dumps(doc, fmt=fmt)
    result = engine.decode_session_restore(raw)
    assert result.format == "plist" and result.browser == "safari"
    assert [(r.title,r.selected,r.semantic_verified) for r in result.entries] == [("One",False,True),("Two",True,True)]
    monkeypatch.setattr(engine, "MAX_SESSION_ENTRIES", 1)
    assert engine.decode_session_restore(raw) is None


def test_all_public_parsers_malformed_corpus():
    rng = random.Random(702)
    valid = chromium()
    cases = [None, [], {}, "text", b"", b"\xff"*2048, rng.randbytes(2048), b"SQLite format 3\0", b"bplist00", b"SNSS\x01\0\0\0", b"mozLz40\0", b"x"*65536]
    cases += [valid[:n] for n in [1,99,511,len(valid)-1]]
    for offset in [0,16,18,100,512]:
        changed = bytearray(valid); changed[offset] ^= 128; cases.append(bytes(changed))
    functions = [engine.validate_sqlite_bundle, engine.decode_browser_database,
        lambda raw: engine.decode_leveldb_storage(raw, store="indexeddb"),
        lambda raw: engine.decode_http_cache_object(raw, browser="chromium", url="https://example.invalid"),
        engine.decode_session_restore]
    for raw in cases:
        for function in functions:
            function(raw)  # contract is None, with no declared exception


@pytest.mark.parametrize("value", [b"\xb2", b"9"*5000])
def test_http_malformed_numeric_length_fail_closed(value):
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: " + value + b"\r\n\r\n"
    assert engine.decode_http_cache_object(raw, browser="chromium", url="https://example.invalid") is None


def test_http_malformed_url_fail_closed():
    assert engine.decode_http_cache_object(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", browser="chromium", url="http://[bad") is None
