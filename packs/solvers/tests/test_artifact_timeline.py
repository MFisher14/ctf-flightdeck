from __future__ import annotations

import datetime as dt
import json
import sqlite3
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solvers" / "toolkits"))

import artifact_timeline as A  # noqa: E402
import timeline  # noqa: E402


UTC = dt.timezone.utc
FILETIME_EPOCH = 116_444_736_000_000_000


def _filetime(when: dt.datetime) -> int:
    return int(when.timestamp() * 10_000_000) + FILETIME_EPOCH


def _event_xml(path: str = r"C:\Temp\evil.exe") -> bytes:
    return f"""<?xml version="1.0"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon"/>
    <EventID>1</EventID><EventRecordID>7</EventRecordID>
    <TimeCreated SystemTime="2026-11-06T13:00:03.0000000Z"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>host.example</Computer>
  </System>
  <EventData><Data Name="Image">{path}</Data><Data Name="ProcessId">4242</Data></EventData>
</Event>""".encode()


def _add_cell(body: bytearray, content: bytes) -> int:
    offset = len(body)
    size = (4 + len(content) + 7) & ~7
    body.extend(struct.pack("<i", -size))
    body.extend(content)
    body.extend(b"\x00" * (size - 4 - len(content)))
    return offset


def _key_cell(name: str, stamp: int, *, child: int | None = None,
              value_list: int | None = None, value_count: int = 0) -> bytes:
    encoded = name.encode("latin-1")
    cell = bytearray(0x4C + len(encoded))
    cell[:2] = b"nk"
    struct.pack_into("<H", cell, 2, 0x20)  # compressed/Latin-1 key name
    struct.pack_into("<Q", cell, 4, stamp)
    struct.pack_into("<I", cell, 0x14, 1 if child is not None else 0)
    struct.pack_into("<I", cell, 0x1C, child if child is not None else 0xFFFFFFFF)
    struct.pack_into("<I", cell, 0x24, value_count)
    struct.pack_into("<I", cell, 0x28, value_list if value_list is not None else 0xFFFFFFFF)
    struct.pack_into("<H", cell, 0x48, len(encoded))
    cell[0x4C:] = encoded
    return bytes(cell)


def _hive_with_path(path: list[str], *, shellbag: bool = False) -> bytes:
    """Small structurally valid hive containing one chain and optional BagMRU value."""

    stamp = _filetime(dt.datetime(2026, 11, 6, 13, 0, 1, tzinfo=UTC))
    cells = bytearray()
    value_list = None
    value_count = 0
    if shellbag:
        item = b"\x0b\x00\x20SecretFolder\x00"
        data_offset = _add_cell(cells, item)
        name = b"0"
        value = bytearray(0x14 + len(name))
        value[:2] = b"vk"
        struct.pack_into("<H", value, 2, len(name))
        struct.pack_into("<I", value, 4, len(item))
        struct.pack_into("<I", value, 8, data_offset)
        struct.pack_into("<I", value, 0x0C, 3)
        struct.pack_into("<H", value, 0x10, 1)
        value[0x14:] = name
        value_offset = _add_cell(cells, value)
        value_list = _add_cell(cells, struct.pack("<I", value_offset))
        value_count = 1

    child_key = _add_cell(
        cells,
        _key_cell(path[-1], stamp, value_list=value_list, value_count=value_count),
    )
    for name in reversed(path[:-1]):
        listing = _add_cell(cells, b"li" + struct.pack("<H", 1) + struct.pack("<I", child_key))
        child_key = _add_cell(cells, _key_cell(name, stamp, child=listing))

    image = bytearray(0x1000)
    image[:4] = b"regf"
    struct.pack_into("<Q", image, 0x0C, stamp)
    struct.pack_into("<I", image, 0x24, child_key)
    image.extend(cells)
    return bytes(image)


def _browser_db() -> bytes:
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE urls (
          id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
          typed_count INTEGER, last_visit_time INTEGER
        );
        CREATE TABLE visits (
          id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, transition INTEGER
        );
        """
    )
    unix_us = int(dt.datetime(2026, 11, 6, 13, 0, tzinfo=UTC).timestamp() * 1_000_000)
    webkit = unix_us + 11_644_473_600_000_000
    connection.execute(
        "INSERT INTO urls VALUES (1, ?, ?, 1, 0, ?)",
        ("https://example.invalid/payload", "payload", webkit),
    )
    connection.execute("INSERT INTO visits VALUES (1, 1, ?, 0)", (webkit,))
    connection.commit()
    data = connection.serialize()
    connection.close()
    return data


def test_event_log_decoder_checks_complete_structure_and_declines_corruption():
    events = A.event_log_timeline(_event_xml(), source="sysmon.xml")
    assert len(events) == 1
    assert events[0].action == "sysmon_process_creation"
    assert events[0].path == r"C:\Temp\evil.exe"
    assert events[0].metadata["id"] == "1"

    assert A.event_log_timeline(_event_xml() + b"<broken") == ()
    assert A.event_log_timeline(b"ElfFile\x00" + b"\x00" * 64) == ()
    assert A.event_log_timeline(b"not an event log") == ()
    assert A.event_log_timeline(_event_xml("C:\\" + "a" * 8192)) == ()
    assert A.event_log_timeline(_event_xml(), include_slack=1) == ()


def test_registry_decoder_uses_hive_key_timestamps_and_declines_text_or_corrupt():
    hive = _hive_with_path(["Run"])
    events = A.registry_timeline(hive, source="NTUSER.DAT")
    assert len(events) == 1
    assert events[0].path == "Run"
    assert events[0].timestamp == dt.datetime(2026, 11, 6, 13, 0, 1, tzinfo=UTC)

    assert A.registry_timeline(b"Windows Registry Editor Version 5.00\n\n[HKCU\\Run]\n") == ()
    assert A.registry_timeline(hive[:0x1020]) == ()
    assert A.registry_timeline(b"regf" + b"\x00" * 0x1100) == ()
    assert A.registry_timeline(hive, include_all="yes") == ()


def test_shellbag_decoder_reconstructs_checked_bagmru_and_declines_corrupt():
    hive = _hive_with_path(
        ["USRCLASS", "Local Settings", "Software", "Microsoft", "Windows", "Shell", "BagMRU"],
        shellbag=True,
    )
    events = A.shellbag_timeline(hive, source="UsrClass.dat")
    assert len(events) == 1
    assert events[0].path == "SecretFolder"
    assert events[0].action == "shellbag_folder_observed"

    assert A.shellbag_timeline(hive[:-12]) == ()
    assert A.shellbag_timeline(b"not a hive") == ()


def test_browser_decoder_requires_known_schema_and_timestamped_records():
    events = A.browser_timeline(_browser_db(), source="History")
    assert {event.action for event in events} >= {"browser_url", "browser_visit"}
    assert all(event.path == "https://example.invalid/payload" for event in events)
    assert all(event.timestamp.year == 2026 for event in events)

    empty = sqlite3.connect(":memory:")
    unrelated = empty.serialize()
    empty.close()
    assert A.browser_timeline(unrelated) == ()
    assert A.browser_timeline(b"SQLite format 3\x00" + b"\x00" * 100) == ()
    assert A.browser_timeline(_browser_db(), wal=b"broken") == ()


def test_journal_decoder_is_strict_json_and_requires_realtime_timestamp():
    record = {
        "__REALTIME_TIMESTAMP": "1793970000000000",
        "MESSAGE": "service started",
        "SYSLOG_IDENTIFIER": "systemd",
        "_PID": "42",
        "_EXE": "/usr/lib/systemd/systemd",
    }
    events = A.journal_timeline(json.dumps(record).encode(), source="journal.json")
    assert len(events) == 1
    assert events[0].path == "/usr/lib/systemd/systemd"
    assert events[0].action == "journal_systemd"

    assert A.journal_timeline(json.dumps(record).encode() + b"\n{broken") == ()
    assert A.journal_timeline(b'{"MESSAGE":"no timestamp"}') == ()
    assert A.journal_timeline(b"\xff\xfe") == ()
    duplicate = (b'{"__REALTIME_TIMESTAMP":"1793970000000000",'
                 b'"MESSAGE":"one","MESSAGE":"two"}')
    assert A.journal_timeline(duplicate) == ()
    assert A.journal_timeline(
        b'{"__REALTIME_TIMESTAMP":"1793970000000000","MESSAGE":"x","bad":NaN}'
    ) == ()
    mixed = json.dumps([record, {"MESSAGE": "missing timestamp"}]).encode()
    assert A.journal_timeline(mixed) == ()
    assert A.journal_timeline(b'[{"__REALTIME_TIMESTAMP":"1793970000000000","MESSAGE":"x"},]') == ()


def test_shell_history_decoder_accepts_only_explicit_complete_timestamps():
    data = b"#1793970000\n/usr/bin/curl https://example.invalid/x\n: 1793970005:0;/tmp/evil\n"
    events = A.shell_history_timeline(data, source=".history")
    assert len(events) == 2
    assert all(event.action == "shell_command" for event in events)
    assert events[0].description.startswith("/usr/bin/curl")

    assert A.shell_history_timeline(b"echo no-time") == ()
    assert A.shell_history_timeline(b"#1793970000\n") == ()
    assert A.shell_history_timeline(b"#1793970000\ncmd\x00hidden") == ()
    assert A.shell_history_timeline(b"#99999999999\ncmd") == ()


def test_auto_timeline_routes_by_content_and_ignores_unrecognized_corrupt_entries():
    timeline_events = A.build_artifact_timeline({
        "sysmon.bin": _event_xml(),
        "browser.bin": _browser_db(),
        "journal.bin": json.dumps({
            "__REALTIME_TIMESTAMP": "1793970000000000", "MESSAGE": "ok", "_COMM": "agent"
        }).encode(),
        "history.bin": b"#1793970000\n/tmp/evil\n",
        "junk.bin": b"corrupt and unrecognized",
    })
    assert {event.source for event in timeline_events} == {
        "sysmon.bin", "browser.bin", "journal.bin", "history.bin"
    }
    assert list(timeline_events) == sorted(timeline_events, key=A._event_sort)
    assert A.build_artifact_timeline({"bad": object()}) == ()


def _event(seconds: int, source: str, action: str, path: str = "", description: str = ""):
    return timeline.TimelineEvent(
        dt.datetime(2026, 11, 6, 13, 0, seconds, tzinfo=UTC), source, action, path, description
    )


def test_exact_cross_artifact_correlations_and_false_positive_guards():
    path = r"C:\Temp\evil.exe"
    events = [
        _event(0, "browser", "browser_download", path),
        _event(1, "registry", "registry_persistence", r"HKCU\Software\Run", path),
        _event(2, "history", "shell_command", description=path),
        _event(3, "sysmon", "sysmon_process_creation", path),
        _event(4, "sysmon-network", "sysmon_network_connection", path),
    ]
    links = A.correlate_artifacts(events, window_seconds=10)
    assert {link.kind for link in links} == {
        "download-execute", "persistence-execute", "command-execute", "execute-network"
    }
    assert all(link.entity == "path:" + path.lower() for link in links)
    assert all(link.sources[0] != link.sources[1] and link.start <= link.end for link in links)

    no_shared_entity = [
        _event(0, "browser", "browser_download", r"C:\one\same.exe"),
        _event(1, "sysmon", "sysmon_process_creation", r"C:\two\same.exe"),
    ]
    assert A.correlate_artifacts(no_shared_entity) == ()
    same_source = [
        _event(0, "one", "browser_download", path),
        _event(1, "one", "sysmon_process_creation", path),
    ]
    assert A.correlate_artifacts(same_source) == ()
    assert A.correlate_artifacts(events, window_seconds=0) == ()
    quoted = _event(2, "history", "shell_command", description='"C:\\Program Files\\evil.exe" -q')
    quoted_exec = _event(3, "sysmon", "sysmon_process_creation", r"C:\Program Files\evil.exe")
    assert {link.kind for link in A.correlate_artifacts([quoted, quoted_exec])} == {"command-execute"}

    url_upper = _event(0, "browser", "browser_download", "https://x.invalid/A")
    url_lower = _event(1, "process", "process_execute", "https://x.invalid/a")
    assert A.correlate_artifacts([url_upper, url_lower]) == ()
    failed = _event(0, "browser", "browser_download_failed", path)
    denied = _event(1, "process", "execute_denied", path)
    assert A.correlate_artifacts([failed, denied]) == ()
    simultaneous = [
        _event(0, "browser", "browser_download", path),
        _event(0, "process", "process_execute", path),
    ]
    assert A.correlate_artifacts(simultaneous) == ()


def test_correlation_declines_raising_iterables_forged_events_and_oversized_entities():
    good = _event(0, "browser", "browser_download", "/tmp/a")

    def broken():
        yield good
        raise RuntimeError("cut evidence stream")

    assert A.correlate_artifacts(broken()) == ()
    forged = timeline.TimelineEvent(good.timestamp, "source", "process_execute", "/tmp/a",
                                    metadata=None)
    assert A.correlate_artifacts([good, forged]) == ()
    forged_action = timeline.TimelineEvent(good.timestamp, "source", 7, "/tmp/a")
    assert A.correlate_artifacts([good, forged_action]) == ()
    oversized = _event(1, "process", "process_execute", "/" + "a" * 8192)
    assert A.correlate_artifacts([good, oversized]) == ()
    assert A.correlate_artifacts([good], window_seconds=True) == ()


def test_registry_and_shellbag_resource_caps_decline_instead_of_returning_prefix(monkeypatch):
    stamp = dt.datetime(2026, 11, 6, 13, 0, tzinfo=UTC)

    class Key:
        def __init__(self, path="Run", values=None):
            self.path = self.name = path
            self.ts = stamp
            self._values = values or {}

        def values(self):
            return self._values

        def subkeys(self):
            return []

    class RegistryView:
        kind = "NTUSER"
        root = Key("ROOT")

        def walk(self, limit=0):
            return iter((Key("Run"), Key("RunOnce")))

    monkeypatch.setattr(A, "MAX_REGISTRY_KEYS", 1)
    monkeypatch.setattr(A._windows, "Hive", lambda _raw: RegistryView())
    assert A.registry_timeline(b"supplied") == ()

    class Value:
        raw = b"\x0b\x00\x20Folder\x00"

    bag = Key("BagMRU", {str(index): Value() for index in range(3)})

    class BagView:
        def find(self, relative):
            return [bag] if relative.startswith("Microsoft") else []

    monkeypatch.setattr(A, "MAX_SHELLBAG_EVENTS", 2)
    monkeypatch.setattr(A._windows, "Hive", lambda _raw: BagView())
    assert A.shellbag_timeline(b"supplied") == ()


def test_resource_limits_decline_instead_of_returning_partial_results(monkeypatch):
    monkeypatch.setattr(A, "MAX_ARTIFACT", 8)
    assert A.event_log_timeline(_event_xml()) == ()
    monkeypatch.setattr(A, "MAX_ARTIFACT", 64 * 1024 * 1024)
    monkeypatch.setattr(A, "MAX_TOTAL_BYTES", 5)
    assert A.build_artifact_timeline({"a": b"123", "b": b"456"}) == ()
    monkeypatch.setattr(A, "MAX_CORRELATION_EVENTS", 1)
    assert A.correlate_artifacts([
        _event(0, "a", "browser_download", "/tmp/a"),
        _event(1, "b", "process_execute", "/tmp/a"),
    ]) == ()
    monkeypatch.setattr(A, "MAX_EVENTS", 1)
    journal_rows = [
        {"__REALTIME_TIMESTAMP": "1793970000000000", "MESSAGE": "one"},
        {"__REALTIME_TIMESTAMP": "1793970001000000", "MESSAGE": "two"},
    ]
    assert A.journal_timeline(json.dumps(journal_rows).encode()) == ()
