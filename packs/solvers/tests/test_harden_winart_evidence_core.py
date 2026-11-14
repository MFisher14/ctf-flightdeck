"""Evidence time, row, and routing tests using independent documented semantics.

https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-dosdatetimetofiletime
https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
All routing tests use inert registry doubles; no live toolkit is invoked.
"""
import datetime as dt
import importlib.util
import json
import random
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Other family tests can import the common reader by this flat basename first.
# Load the wrapper explicitly because route() exists only in the toolkit face.
_SPEC = importlib.util.spec_from_file_location(
    "harden_winart_evidence_core_toolkit",
    Path(__file__).resolve().parents[1] / "solvers/toolkits/evidence_core.py",
)
engine = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = engine
_SPEC.loader.exec_module(engine)

UTC = dt.timezone.utc
STAMP = dt.datetime(2024, 1, 2, 3, 4, 5, 123456, UTC)


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("evidence test attempted a live registry, execution, or network")
    for name in ("Popen", "run", "call", "check_output"):
        monkeypatch.setattr(subprocess, name, blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(engine, "_registry", blocked)
    monkeypatch.setenv("CTF_BUNDLE_ROUTER", "off")
    # These are text-only IOC tests; archive expansion is tested in compression lanes.
    monkeypatch.setattr(engine.triage, "expand_more", lambda files: {})


@pytest.mark.parametrize("unit,value,expected", [("s", 1704164645, STAMP.replace(microsecond=0)),
    ("ms", 1704164645123, STAMP.replace(microsecond=123000)), ("us", 1704164645123456, STAMP),
    ("ns", 1704164645123456789, STAMP), ("s", 0, dt.datetime(1970, 1, 1, tzinfo=UTC)),
    ("us", -1, dt.datetime(1969, 12, 31, 23, 59, 59, 999999, UTC))])
def test_unix_units_exact_arithmetic(unit, value, expected):
    assert engine.from_unix(value, unit) == expected


@pytest.mark.parametrize("function,value", [(engine.from_filetime, 133486382451234567),
    (engine.from_webkit, 13348638245123456), (engine.from_prtime, 1704164645123456)])
def test_epoch_converters_exact_microseconds(function, value):
    assert function(value) == STAMP


def test_cocoa_and_dos_exact_values():
    assert engine.from_mac_absolute(725857445.125) == STAMP.replace(microsecond=125000)
    date_word = ((2024 - 1980) << 9) | (1 << 5) | 2
    time_word = (3 << 11) | (4 << 5) | (6 // 2)
    expected = dt.datetime(2024, 1, 2, 3, 4, 6)
    assert engine.from_dos(date_word, time_word) == expected
    assert engine.from_dos32((date_word << 16) | time_word) == expected
    assert engine.from_dos(0, 0) is None


@pytest.mark.parametrize("seconds_code", [30, 31])
def test_dos_invalid_seconds(seconds_code):
    assert engine.from_dos(((2024 - 1980) << 9) | (1 << 5) | 2, seconds_code) is None


def test_iso_log_times_timezone_and_rendering():
    expected = STAMP.replace(microsecond=0)
    parsed = engine.parse_iso("2024-01-02T05:04:05+02:00")
    assert parsed.astimezone(UTC) == expected
    assert engine.parse_time("02/Jan/2024:05:04:05 +0200").astimezone(UTC) == expected
    assert engine.parse_time("2024:01:02 03:04:05") == expected.replace(tzinfo=None)
    assert engine.parse_time("Jan  2 03:04:05", year=2024) == expected.replace(tzinfo=None)
    assert engine.parse_time("03/04/2024") is None
    opts = dict(engine.time_options(parsed))
    assert opts["iso_z"] == "2024-01-02T03:04:05Z" and opts["epoch"] == "1704164645"
    assert opts["epoch_ms"] == "1704164645000"
    assert engine.guess_epoch(1704164645) == [("unix_s", expected)]


@pytest.mark.parametrize("name,raw", [("rows.csv", b"time,user,status\n2024-01-02T01:00:00Z,bob,404\n2024-01-02T03:00:00+01:00,alice,200\n"),
    ("rows.json", json.dumps([{"time": "2024-01-02T01:00:00Z", "user": "bob", "status": 404},
        {"time": "2024-01-02T03:00:00+01:00", "user": "alice", "status": 200}]).encode()),
    ("rows.jsonl", b'{"time":"2024-01-02T01:00:00Z","user":"bob","status":404}\n{"time":"2024-01-02T03:00:00+01:00","user":"alice","status":200}\n')])
def test_table_rows_queries_and_timezone_order(name, raw):
    table = engine.tables(name, raw)[0]
    assert engine.q(table, "count") == 2
    assert engine.q(table, "count", where={"status": "404"}) == 1
    assert engine.q(table, "first", "user", time="time") == (["bob"], None)
    assert engine.q(table, "last", "user", time="time") == (["alice"], None)
    assert engine.q(table, "top", "user") == ([("bob", 1)], True)


def test_xml_flatten_and_table_row_cap():
    raw = b'<Events><Event id="1"><Data Name="User">bob</Data></Event><Event id="2"><Data Name="User">alice</Data></Event></Events>'
    table = engine.tables("fixture.xml", raw)[0]
    assert list(table) == [{"@id": "1", "User": "bob"}, {"@id": "2", "User": "alice"}]
    assert table.rows(cap=1) is None and table.too_long is True
    assert engine.flatten({"a": [True, None, 7], "b": {"x": "value"}}) == {
        "a.0": "true", "a.1": "", "a.2": "7", "b.x": "value"}


def test_ioc_cross_references_and_scan_cap(monkeypatch):
    files = {"a.log": b"source 198.51.100.10 endpoint https://example.test/path",
             "b.log": b"same source 198.51.100.10"}
    index = engine.ioc(files)
    assert list(index.values("ipv4")) == ["198.51.100.10"]
    assert ("ipv4", "198.51.100.10", ["a.log", "b.log"]) in index.cross()
    assert list(index.values("url")) == ["https://example.test/path"]
    monkeypatch.setitem(engine.ioc.__globals__, "INDEX_SCAN", 8)
    assert engine.ioc(files).complete is False


@pytest.mark.parametrize("values,expected", [(["same", "same"], {"q": "same"}), (["left", "right"], {})])
def test_router_consensus_only_uses_inert_registry(monkeypatch, values, expected):
    names = ["offline_a", "offline_b"]
    registry = SimpleNamespace(entries=lambda **kwargs: [{"key": "web"}, *({"key": key} for key in names)],
        signal=lambda *args: 1.0,
        load=lambda key: SimpleNamespace(solve_set=lambda *args: {"q": values[names.index(key)]}))
    monkeypatch.setattr(engine, "_registry", lambda: registry)
    result, who, notes = engine.route([{"id": "q"}], {"fixture.txt": b"inert"})
    assert result == expected and who == {"q": names}
    assert bool(notes) is (len(set(values)) > 1)


def test_seeded_table_and_time_fuzz():
    rng = random.Random(0xE71D)
    corpus = [b"", b"\xff" * 512, bytes(rng.randrange(256) for _ in range(256))]
    seed = b'[{"time":"2024-01-02T03:04:05Z","value":1}]'
    corpus += [seed[:n] for n in (1, 5, len(seed) // 2, len(seed) - 1)]
    corpus.append(seed[:10] + bytes([seed[10] ^ 4]) + seed[11:])
    for raw in corpus:
        for table in engine.tables("fixture.json", raw):
            assert isinstance(list(table), list)
        assert engine.parse_iso(raw.decode("latin1")) is None
        assert engine.parse_time(raw.decode("latin1")) is None
    assert engine.parse_time(float("nan")) is None
    assert engine.guess_epoch(float("inf")) == []


@pytest.mark.parametrize("call", [lambda: engine.from_unix(float("nan")),
    lambda: engine.from_unix(1, "invalid"), lambda: engine.from_unix(None),
    lambda: engine.from_prtime(None), lambda: engine.from_filetime(float("inf")),
    lambda: engine.from_webkit(None), lambda: engine.from_mac_absolute(float("nan")),
    lambda: engine.from_dos(None, 0), lambda: engine.from_dos32(None)])
def test_converter_malformed_contract(call):
    try:
        call()
    except engine.OverBudget:
        pass


def test_flatten_recursion_fail_closed():
    value = None
    for _ in range(1500):
        value = {"x": value}
    leaked = None
    try:
        engine.flatten(value)
    except engine.OverBudget:
        pass
    except Exception as exc:
        leaked = type(exc).__name__
    assert leaked is None, leaked
