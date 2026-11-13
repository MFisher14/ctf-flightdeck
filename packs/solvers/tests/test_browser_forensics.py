from __future__ import annotations

import json
import plistlib
import sqlite3
import struct
from pathlib import Path

import pytest

import browser_forensics as browser

from browser_forensics import (
    decode_browser_database,
    decode_http_cache_object,
    decode_leveldb_storage,
    decode_session_restore,
    validate_sqlite_bundle,
)


def _sqlite(tmp_path: Path, schema: str, rows: str, *, wal: bool = False):
    path = tmp_path / ("wal.db" if wal else "plain.db")
    connection = sqlite3.connect(path)
    if wal:
        assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
    connection.executescript(schema)
    connection.commit()
    if wal:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    connection.executescript(rows)
    connection.commit()
    raw = path.read_bytes()
    side_wal = Path(str(path) + "-wal").read_bytes() if wal else None
    side_shm = Path(str(path) + "-shm").read_bytes() if wal else None
    connection.close()
    return raw, side_wal, side_shm


def test_chromium_history_with_checksum_valid_wal_and_corrupt_declines(tmp_path):
    schema = """
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                          visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER,
                            visit_time INTEGER, transition INTEGER);
    """
    rows = """
        INSERT INTO urls VALUES(1, 'https://example.invalid/a', 'A', 1, 1, 13300000000000000);
        INSERT INTO visits VALUES(1, 1, 13300000000000000, 1);
    """
    raw, wal, shm = _sqlite(tmp_path, schema, rows, wal=True)
    assert wal is not None and shm is not None
    checked = validate_sqlite_bundle(raw, wal=wal)
    assert checked is not None and checked[2] >= 1
    report = decode_browser_database(raw, wal=wal)
    assert report is not None
    assert report.schema == "chromium_history"
    assert report.wal_frames >= 1
    assert report.supplied_shm is False
    assert {(row.kind, row.url) for row in report.records} == {
        ("url", "https://example.invalid/a"),
        ("visit", "https://example.invalid/a"),
    }

    damaged = bytearray(wal)
    damaged[-1] ^= 1
    assert validate_sqlite_bundle(raw, wal=damaged) is None
    assert decode_browser_database(raw, wal=damaged) is None
    assert decode_browser_database(raw, wal=wal[:-1]) is None
    # A transient/native-endian WAL-index cannot be bound from header twins alone.
    assert validate_sqlite_bundle(raw, wal=wal, shm=shm) is None
    forged_shm = bytearray(shm)
    forged_shm[48] ^= 1
    assert decode_browser_database(raw, wal=wal, shm=forged_shm) is None


@pytest.mark.parametrize(
    ("schema", "rows", "expected_schema", "expected_value"),
    [
        (
            "CREATE TABLE moz_cookies(id INTEGER, host TEXT, name TEXT, value TEXT, path TEXT, "
            "expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER);",
            "INSERT INTO moz_cookies VALUES(1,'.example.invalid','sid','abc','/',2000000000,1700000000000000,1690000000000000,1,1);",
            "firefox_cookies",
            "abc",
        ),
        (
            "CREATE TABLE ItemTable(key TEXT, value TEXT);",
            "INSERT INTO ItemTable VALUES('token','local-value');",
            "safari_localstorage",
            "local-value",
        ),
        (
            "CREATE TABLE object_data(object_store_id INTEGER, key BLOB, data BLOB);",
            "INSERT INTO object_data VALUES(3,x'0102',x'7061796c6f6164');",
            "firefox_indexeddb",
            b"payload",
        ),
        (
            "CREATE TABLE cfurl_cache_response(entry_ID INTEGER, request_key TEXT, time_stamp REAL);"
            "CREATE TABLE cfurl_cache_receiver_data(entry_ID INTEGER, receiver_data BLOB);",
            "INSERT INTO cfurl_cache_response VALUES(4,'https://cache.invalid/o',12.0);"
            "INSERT INTO cfurl_cache_receiver_data VALUES(4,x'626f6479');",
            "safari_cache",
            b"body",
        ),
    ],
)
def test_firefox_and_safari_schema_gated_artifacts(tmp_path, schema, rows, expected_schema, expected_value):
    raw, _, _ = _sqlite(tmp_path, schema, rows)
    report = decode_browser_database(raw)
    assert report is not None and report.schema == expected_schema
    assert any(row.value == expected_value for row in report.records)
    corrupt = bytearray(raw)
    corrupt[0] ^= 0xFF
    assert decode_browser_database(corrupt) is None


def test_chromium_cookies_and_safari_history_are_schema_checked(tmp_path):
    cookie_schema = """
        CREATE TABLE cookies(host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB,
                             path TEXT, creation_utc INTEGER, expires_utc INTEGER,
                             last_access_utc INTEGER, is_secure INTEGER, is_httponly INTEGER);
    """
    cookie_rows = """
        INSERT INTO cookies VALUES('.example.invalid','sid','cookie-value',x'','/',
                                   13300000000000000,13400000000000000,
                                   13300000000000000,1,1);
    """
    raw, _, _ = _sqlite(tmp_path, cookie_schema, cookie_rows)
    report = decode_browser_database(raw)
    assert report is not None and report.schema == "chromium_cookies"
    assert report.records[0].host == ".example.invalid"
    assert report.records[0].value == "cookie-value"

    history_schema = """
        CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER);
        CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER,
                                    visit_time REAL, title TEXT);
    """
    history_rows = """
        INSERT INTO history_items VALUES(1,'https://safari.invalid/history',1);
        INSERT INTO history_visits VALUES(1,1,700000000.0,'Safari visit');
    """
    # The helper uses a fixed name inside tmp_path; remove the previous closed database.
    (tmp_path / "plain.db").unlink()
    raw, _, _ = _sqlite(tmp_path, history_schema, history_rows)
    report = decode_browser_database(raw)
    assert report is not None and report.schema == "safari_history"
    assert {row.url for row in report.records} == {"https://safari.invalid/history"}


def _varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _masked(value: int) -> int:
    rotated = ((value >> 15) | (value << 17)) & 0xFFFFFFFF
    return (rotated + 0xA282EAD8) & 0xFFFFFFFF


def _leveldb_batch(entries, sequence=51):
    batch = bytearray(struct.pack("<QI", sequence, len(entries)))
    for key, value in entries:
        batch.append(0 if value is None else 1)
        batch += _varint(len(key)) + key
        if value is not None:
            batch += _varint(len(value)) + value
    return bytes(batch)


def _leveldb_record(kind, payload):
    checksum = _masked(_crc32c(bytes([kind]) + payload))
    return struct.pack("<IHB", checksum, len(payload), kind) + payload


def _leveldb_log(entries, sequence=51):
    batch = _leveldb_batch(entries, sequence)
    kind = 1
    checksum = _masked(_crc32c(bytes([kind]) + batch))
    return struct.pack("<IHB", checksum, len(batch), kind) + batch


def test_crc_checked_leveldb_localstorage_and_indexeddb_declines():
    assert _crc32c(b"123456789") == 0xE3069283
    log = _leveldb_log([
        (b"_https://example.invalid\x00\x01role", b"\x01admin"),
        (b"_https://example.invalid\x00\x01old", None),
    ])
    rows = decode_leveldb_storage(log, store="localstorage")
    assert rows is not None
    assert [(row.origin, row.key, row.value, row.state) for row in rows] == [
        ("https://example.invalid", "role", "admin", "live"),
        ("https://example.invalid", "old", None, "deleted"),
    ]
    opaque = _leveldb_log([(b"\x00\x01binary-key", b"\xff\x00value")])
    indexed = decode_leveldb_storage(opaque, store="indexeddb", origin="https://example.invalid")
    assert indexed is not None and indexed[0].value == b"\xff\x00value"

    damaged = bytearray(log)
    damaged[-1] ^= 1
    assert decode_leveldb_storage(damaged, store="localstorage") is None
    assert decode_leveldb_storage(log[:-1], store="localstorage") is None
    assert decode_leveldb_storage(_leveldb_log([(b"not-a-localstorage-key", b"v")]),
                                  store="localstorage") is None
    assert decode_leveldb_storage(log + b"\x00" * 5, store="localstorage") is None
    block_tail = _leveldb_log([(b"k", b"x" * 32738)]) + b"\x00" * 5
    assert len(block_tail) == 32768
    assert decode_leveldb_storage(block_tail, store="indexeddb") is not None


def test_complete_http_cache_objects_and_corrupt_declines():
    body = b"cached-body"
    raw = (b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nContent-Type: text/plain\r\n\r\n" + body)
    result = decode_http_cache_object(raw, browser="chromium", url="https://cache.invalid/a")
    assert result is not None and result.body == body
    assert result.sha256

    chunked = (b"HTTP/1.1 206 Partial Content\r\nTransfer-Encoding: chunked\r\n"
               b"Content-Location: https://cache.invalid/b\r\n\r\n"
               b"5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n")
    result = decode_http_cache_object(chunked, browser="firefox")
    assert result is not None and result.body == b"hello!"
    assert decode_http_cache_object(raw[:-1], browser="chromium", url="https://cache.invalid/a") is None
    assert decode_http_cache_object(raw.replace(b"11", b"10", 1), browser="chromium",
                                    url="https://cache.invalid/a") is None
    assert decode_http_cache_object(chunked[:-1], browser="firefox") is None
    assert decode_http_cache_object(raw, browser="unknown", url="https://cache.invalid/a") is None


def _lz4_literals(data: bytes) -> bytes:
    if len(data) < 15:
        return bytes([len(data) << 4]) + data
    left = len(data) - 15
    extension = bytearray()
    while left >= 255:
        extension.append(255)
        left -= 255
    extension.append(left)
    return b"\xf0" + bytes(extension) + data


def test_firefox_chromium_and_safari_session_restore_checks():
    firefox_json = json.dumps({
        "selectedWindow": 1,
        "windows": [{"selected": 1, "tabs": [{"index": 1, "entries": [
            {"url": "https://firefox.invalid/", "title": "Firefox"}
        ]}]}],
    }, separators=(",", ":")).encode()
    firefox = b"mozLz40\x00" + struct.pack("<I", len(firefox_json)) + _lz4_literals(firefox_json)
    report = decode_session_restore(firefox)
    assert report is not None and report.browser == "firefox"
    assert report.entries[0].selected and report.entries[0].semantic_verified
    bad = bytearray(firefox)
    struct.pack_into("<I", bad, 8, len(firefox_json) + 1)
    assert decode_session_restore(bad) is None
    malformed_json = json.dumps({"windows": [{"tabs": [{"index": 1}]}]}).encode()
    malformed = (b"mozLz40\x00" + struct.pack("<I", len(malformed_json))
                 + _lz4_literals(malformed_json))
    assert decode_session_restore(malformed) is None

    url = b"https://chromium.invalid/tab"
    pickle = struct.pack("<I", len(url)) + url
    pickle += b"\x00" * (-len(pickle) % 4)
    command = bytes([6]) + pickle
    snss = b"SNSS" + struct.pack("<i", 3) + struct.pack("<H", len(command)) + command
    report = decode_session_restore(snss)
    assert report is not None and report.browser == "chromium"
    assert report.entries[0].url == url.decode() and not report.entries[0].semantic_verified
    assert decode_session_restore(snss[:-1]) is None
    bad_version = bytearray(snss)
    struct.pack_into("<i", bad_version, 4, -1)
    assert decode_session_restore(bad_version) is None

    safari = plistlib.dumps({
        "SessionWindows": [{"SelectedTabIndex": 1, "TabStates": [
            {"TabURL": "https://safari.invalid/first", "TabTitle": "First"},
            {"TabURL": "https://safari.invalid/selected", "TabTitle": "Safari"}
        ]}]
    }, fmt=plistlib.FMT_BINARY)
    report = decode_session_restore(safari, browser="safari")
    assert report is not None and [entry.selected for entry in report.entries] == [False, True]
    assert decode_session_restore(safari[:-4], browser="safari") is None


@pytest.mark.parametrize("bad", [None, True, 1, "bytes", object(), [], {}])
def test_public_browser_decoders_decline_wrong_types(bad):
    assert validate_sqlite_bundle(bad) is None
    assert decode_browser_database(bad) is None
    assert decode_leveldb_storage(bad, store="localstorage") is None
    assert decode_http_cache_object(bad, browser="firefox", url="https://x.invalid") is None
    assert decode_session_restore(bad) is None


def test_public_browser_keyword_types_decline_without_exceptions():
    raw = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx"
    assert decode_http_cache_object(raw, browser=[]) is None
    assert decode_leveldb_storage(b"x", store=[]) is None
    assert decode_session_restore(b"SNSS" + b"\x00" * 8, browser=[]) is None


def test_browser_resource_caps_decline_without_partial_results(tmp_path, monkeypatch):
    schema = """
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                          visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER,
                            visit_time INTEGER, transition INTEGER);
    """
    rows = """
        INSERT INTO urls VALUES(1,'https://one.invalid','one',1,0,13300000000000000);
        INSERT INTO urls VALUES(2,'https://two.invalid','two',1,0,13300000000000001);
    """
    raw, _, _ = _sqlite(tmp_path, schema, rows)
    monkeypatch.setattr(browser, "MAX_RECORDS", 1)
    assert decode_browser_database(raw) is None
    log = _leveldb_log([(b"k1", b"v1"), (b"k2", b"v2")])
    assert decode_leveldb_storage(log, store="indexeddb") is None

    monkeypatch.setattr(browser, "MAX_SESSION_ENTRIES", 1)
    safari = plistlib.dumps({"SessionWindows": [{"TabStates": [
        {"TabURL": "https://one.invalid"}, {"TabURL": "https://two.invalid"}
    ]}]})
    assert decode_session_restore(safari, browser="safari") is None
