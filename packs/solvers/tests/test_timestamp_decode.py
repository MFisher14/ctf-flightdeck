"""timestamp_decode: decode a mystery number as every common timestamp format."""
from __future__ import annotations

import datetime as dt

import pytest

import timestamp_decode as ts


REF = dt.datetime(2023, 6, 1, 12, 0, 0, tzinfo=dt.timezone.utc)


def _find(results, fmt_prefix):
    return next((r for r in results if r["format"].startswith(fmt_prefix)), None)


def test_unix_seconds():
    val = int((REF - ts.EPOCH_1970).total_seconds())
    r = _find(ts.decode(val), "unix_seconds")
    assert r and r["plausible"] and r["year"] == 2023


def test_unix_millis():
    val = int((REF - ts.EPOCH_1970).total_seconds() * 1000)
    r = _find(ts.decode(val), "unix_millis")
    assert r and r["plausible"] and r["year"] == 2023


def test_windows_filetime():
    val = int((REF - ts.EPOCH_1601).total_seconds() * 1e7)
    r = _find(ts.decode(val), "windows_filetime")
    assert r and r["plausible"] and r["year"] == 2023


def test_chrome_webkit():
    val = int((REF - ts.EPOCH_1601).total_seconds() * 1e6)
    r = _find(ts.decode(val), "chrome/webkit")
    assert r and r["plausible"] and r["year"] == 2023


def test_apple_cocoa():
    val = int((REF - ts.EPOCH_2001).total_seconds())
    r = _find(ts.decode(val), "apple_cocoa")
    assert r and r["plausible"] and r["year"] == 2023


def test_dos_datetime_roundtrip():
    # pack 2023-06-01 12:00:00 into the DOS 32-bit format and decode it back
    date = ((2023 - 1980) << 9) | (6 << 5) | 1
    time = (12 << 11) | (0 << 5) | (0 // 2)
    val = (date << 16) | time
    r = _find(ts.decode(val), "dos_datetime")
    assert r and r["utc"].startswith("2023-06-01T12:00:00")


def test_hex_input_and_plausible_ranking():
    val = int((REF - ts.EPOCH_1970).total_seconds())
    r = ts.decode(hex(val))  # "0x..."
    assert r and r[0]["plausible"]  # a plausible interpretation ranks first


def test_fail_closed():
    assert ts.decode("not a number") == []
    assert ts.decode("") == []
    assert ts.decode(None) == []


def test_cli(capsys):
    val = int((REF - ts.EPOCH_1970).total_seconds())
    rc = ts.main([str(val), "--json"])
    assert rc == 0
    import json
    out = json.loads(capsys.readouterr().out)
    assert any(o["format"].startswith("unix_seconds") and o["year"] == 2023 for o in out)
    assert ts.main(["not-a-number"]) == 1  # nothing decodes -> nonzero
    assert ts.main(["--help"]) == 0
