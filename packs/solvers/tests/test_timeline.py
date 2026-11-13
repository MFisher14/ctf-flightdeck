from __future__ import annotations

import csv
import datetime as dt
import io
import json
import sys
from pathlib import Path


TOOLKITS = Path(__file__).resolve().parents[1] / "solvers/toolkits"
sys.path.insert(0, str(TOOLKITS))
import timeline as T  # noqa: E402


def test_reader_records_cover_major_dfir_families_and_sort():
    records = [
        {"source": "USN", "timestamp": "2026-11-04T12:00:03Z", "filename": "drop.bin", "reason": "CREATE"},
        {"source": "EVTX", "time_created": "2026-11-04T12:00:01.1234567Z", "event_id": 4688,
         "message": "process start", "command_line": "cmd.exe /c whoami"},
        {"source": "Prefetch", "last_run_time": "2026-11-04T12:00:02+00:00", "path": "CMD.EXE"},
        {"source": "browser", "visit_time": "2026-11-04T12:00:04Z", "url": "https://example.invalid/"},
        {"source": "registry", "last_written": "2026-11-04T12:00:00Z", "key_path": "HKCU\\Software\\Fixture"},
    ]
    events = T.ingest_records(records)
    assert len(events) == 5
    assert [event.source for event in events] == ["registry", "EVTX", "Prefetch", "USN", "browser"]
    assert events[1].timestamp.microsecond == 123456
    assert events[-1].path == "https://example.invalid/"


def test_mft_bodyfile_round_trip_and_mactime_csv():
    body = "0|/tmp/evidence.txt|42|r/rr|1000|1000|12|1793793601|1793793602|1793793603|1793793600\n"
    events = T.parse_bodyfile(body, source="$MFT")
    assert len(events) == 4
    assert {event.time_type for event in events} == {"a", "m", "c", "b"}
    assert all(event.path == "/tmp/evidence.txt" for event in events)
    emitted = T.to_bodyfile(events)
    assert emitted.count("/tmp/evidence.txt") == 4
    rows = list(csv.DictReader(io.StringIO(T.to_mactime_csv(events))))
    assert len(rows) == 4 and rows[0]["File Name"] == "/tmp/evidence.txt"


def test_windows_and_webkit_epoch_normalization():
    wanted = dt.datetime(2026, 11, 4, 12, 0, tzinfo=dt.timezone.utc)
    unix = int(wanted.timestamp())
    filetime = (unix + 11_644_473_600) * 10_000_000
    webkit = (unix + 11_644_473_600) * 1_000_000
    assert T.parse_timestamp(filetime, "filetime") == wanted
    assert T.parse_timestamp(webkit, "webkit_visit_time") == wanted
    assert T.parse_timestamp(unix * 1000, "unix_ms") == wanted
    assert T.parse_timestamp(unix * 1_000_000_000, "unix_ns") == wanted


def test_json_csv_ingest_filter_and_ioc(tmp_path):
    records = [
        {"timestamp": "2026-11-04T10:00:00Z", "path": "benign.txt", "event": "open"},
        {"timestamp": "2026-11-04T10:01:00Z", "path": "evil.exe", "event": "execute",
         "description": "IOC 203.0.113.8"},
    ]
    path = tmp_path / "events.json"
    path.write_text(json.dumps({"events": records}), encoding="utf-8")
    events = T.ingest_path(path)
    selected = T.filter_events(events, start="2026-11-04T10:00:30Z",
                               keywords=["execute"], iocs=["203.0.113.8"])
    assert len(selected) == 1 and selected[0].path == "evil.exe"
    assert json.loads(T.render_json(selected))[0]["time_type"] == "event"


def test_binary_and_malformed_cli_are_guarded(tmp_path, capsys):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"\x00\x01\x02")
    assert T.main([str(bad)]) == 2
    assert "timeline:" in capsys.readouterr().err

