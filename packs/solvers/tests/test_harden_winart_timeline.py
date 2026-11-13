"""Timeline vectors use exact epoch arithmetic, never the engine as encoder.

FILETIME: https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-filetime
Unix integers are seconds/milliseconds/microseconds/nanoseconds since 1970 UTC.
"""
import csv
import datetime as dt
import io
import json
import random
import socket
import subprocess

import pytest
import timeline as engine

UTC = dt.timezone.utc
STAMP = dt.datetime(2024, 1, 2, 3, 4, 5, 123456, UTC)


@pytest.fixture(autouse=True)
def offline_only(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("timeline attempted execution or network")
    for name in ("Popen", "run", "check_output", "call"):
        monkeypatch.setattr(subprocess, name, blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)


@pytest.mark.parametrize("value,field,expected", [
    (1704164645, "unix_s", STAMP.replace(microsecond=0)),
    (1704164645123, "unix_ms", STAMP.replace(microsecond=123000)),
    (1704164645123456000, "unix_ns", STAMP),
    (725857445.125, "cocoa", STAMP.replace(microsecond=125000)),
    ("2024-01-02T05:04:05.123456+02:00", "timestamp", STAMP),
    ((2024, 1, 2, 3, 4, 5, 123456), "timestamp", STAMP),
    (dt.date(2024, 1, 2), "timestamp", dt.datetime(2024, 1, 2, tzinfo=UTC)),
])
def test_timestamp_exact_arithmetic(value, field, expected):
    assert engine.parse_timestamp(value, field) == expected


@pytest.mark.parametrize("field", ["unix_us", "prtime", "unix_microseconds"])
def test_named_unix_microseconds_override_heuristic(field):
    assert engine.parse_timestamp(1704164645123456, field) == STAMP


@pytest.mark.parametrize("value,field", [(133486382451234560, "filetime"), (13348638245123456, "webkit"),
                                        (13348638245123456, "chrome")])
def test_windows_epoch_preserves_microseconds(value, field):
    assert engine.parse_timestamp(value, field) == STAMP


@pytest.mark.parametrize("value", [0, -1])
def test_unix_epoch_and_negative_seconds(value):
    assert engine.parse_timestamp(value, "unix_s") == dt.datetime(1970, 1, 1, tzinfo=UTC) + dt.timedelta(seconds=value)


def _rows():
    return [{"timestamp": "2024-01-02T04:00:00+01:00", "path": "late", "action": "write", "source": "fs"},
            {"timestamp": "2024-01-02T02:00:00Z", "path": "early", "action": "read", "source": "fs"}]


def test_ingest_json_csv_jsonl_and_path_ordering(tmp_path):
    rows = _rows()
    csv_out = io.StringIO()
    writer = csv.DictWriter(csv_out, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    variants = [engine.ingest_records(rows), engine.parse_json_text(json.dumps({"events": rows})),
                engine.parse_json_text("\n".join(map(json.dumps, rows))), engine.parse_csv_text(csv_out.getvalue())]
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(rows))
    variants.append(engine.ingest_path(path))
    for events in variants:
        assert [e.path for e in events] == ["early", "late"]
        assert [e.timestamp.hour for e in events] == [2, 3]
        assert all(e.timestamp.tzinfo == UTC for e in events)


def test_bodyfile_unix_epoch_strings():
    raw = "0|/known|4|r/rrwx|1000|1001|99|1704164641|1704164642|1704164643|1704164644\n"
    events = engine.parse_bodyfile(raw)
    epoch = dt.datetime(1970, 1, 1, tzinfo=UTC)
    assert [e.timestamp for e in events] == [epoch + dt.timedelta(seconds=n) for n in range(1704164641, 1704164645)]


def test_event_serializers_against_known_timestamps():
    events = [engine.TimelineEvent(STAMP.replace(second=n, microsecond=0), "fixture", "filesystem", "/known",
        time_type=kind, metadata={"size": 99}) for n, kind in zip(range(1, 5), ("a", "m", "c", "b"))]
    assert [e.time_type for e in events] == ["a", "m", "c", "b"]
    assert [e.timestamp.second for e in events] == [1, 2, 3, 4]
    for event, expected_slot in zip(events, (7, 8, 9, 10)):
        fields = engine.to_bodyfile([event]).strip().split("|")
        assert fields[1] == "/known"
        assert fields[expected_slot] == str(1704164641 + expected_slot - 7)
        assert sum(int(v) != 0 for v in fields[7:]) == 1
    rendered = json.loads(engine.render_json(events))
    assert rendered[0]["timestamp"] == "2024-01-02T03:04:01Z"
    rows = list(csv.DictReader(io.StringIO(engine.to_mactime_csv(events))))
    assert rows[0]["Type"] == "a" and rows[0]["Size"] == "99" and rows[0]["File Name"] == "/known"


def test_filter_window_and_metadata_limits(monkeypatch):
    events = engine.ingest_records(_rows())
    selected = engine.filter_events(events, start="2024-01-02T03:00:00Z", end="2024-01-02T03:00:00Z",
                                    keywords=["WRITE"], iocs=["LATE"])
    assert [e.path for e in selected] == ["late"]
    assert len(engine.ingest_records(_rows(), max_records=1)) == 1
    monkeypatch.setattr(engine, "MAX_METADATA_BYTES", 8)
    output = engine.events_from_record({"timestamp": "2024-01-01T00:00:00Z", "oversize": "A" * 100})
    assert "oversize" not in output[0].metadata


@pytest.mark.parametrize("parser", [engine.parse_bodyfile, engine.parse_csv_text, engine.parse_json_text])
def test_seeded_text_parser_fuzz(parser):
    rng = random.Random(0x71AE)
    seed = json.dumps(_rows())
    corpus = ["", "\xff" * 256, "".join(chr(rng.randrange(32, 127)) for _ in range(256))]
    corpus.extend(seed[:n] for n in (1, 5, len(seed) // 2, len(seed) - 1))
    corpus.append(seed[:20] + chr(ord(seed[20]) ^ 4) + seed[21:])
    for raw in corpus:
        assert isinstance(parser(raw), list)


@pytest.mark.parametrize("value", [None, True, {}, [], "nonsense", "2024-99-99", float("nan"), float("inf"), -float("inf")])
def test_timestamp_invalid_clean(value):
    assert engine.parse_timestamp(value) is None


@pytest.mark.parametrize("value", [10**1000, [float("nan"), 1, 1], [float("inf"), 1, 1],
                                   [2024, 1, 1, float("nan")], [2024, 1, 1, 0, 0, 0, float("inf")]])
def test_timestamp_numeric_coercion_fail_closed(value):
    assert engine.parse_timestamp(value) is None


def test_json_unicode_fail_closed():
    leaked = None
    try:
        engine.parse_json_text("\ud800")
    except Exception as exc:
        leaked = type(exc).__name__
    assert leaked is None, leaked


def test_json_depth_and_irrelevant_records_are_clean():
    assert engine.parse_json_text("[" * 4000 + "0" + "]" * 4000) == []


@pytest.mark.parametrize("parser", [engine.parse_bodyfile, engine.parse_csv_text, engine.parse_json_text])
def test_input_cap_fail_closed(parser, monkeypatch):
    monkeypatch.setattr(engine, "MAX_INPUT_BYTES", 16)
    assert parser("x" * 17) in (None, [])


def test_cli_help_guard(capsys):
    assert engine.main(["--help"]) == 0
