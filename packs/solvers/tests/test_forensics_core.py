from __future__ import annotations

import json

import forensics_core as F


def test_volatility_plans_are_installed_cross_checked_and_non_executable():
    inventory = F.installed_volatility_plugins()
    assert {"windows.pslist", "linux.pslist", "mac.pslist", "yarascan"} <= inventory
    for os_family in ("windows", "linux", "mac"):
        plan = F.build_volatility_plan(os_family, ("network", "malware", "files", "credentials", "shell", "persistence"))
        assert plan is not None
        assert plan.steps and all(step.available == (step.plugin in inventory) for step in plan.steps)
        assert len({step.plugin for step in plan.steps}) == len(plan.steps)
        positions = {step.plugin: index for index, step in enumerate(plan.steps)}
        for step in plan.steps:
            for dependency in step.depends_on:
                assert dependency in positions and positions[dependency] < positions[step.plugin]
        assert "no plugin invocation" in plan.notes[0]
    assert F.build_volatility_plan("plan9") is None
    assert F.build_volatility_plan("windows", ("unknown-goal",)) is None
    assert F.build_volatility_plan("windows", "network") is None
    assert F.build_volatility_plan("windows", ["network"] * 33) is None


def test_volatility_inventory_absence_is_reported_not_executed(monkeypatch):
    monkeypatch.setattr(F, "installed_volatility_plugins", lambda: frozenset())
    plan = F.build_volatility_plan("windows", ("malware",))
    assert plan is not None and plan.steps
    assert plan.unavailable == tuple(step.plugin for step in plan.steps)
    assert not any(step.available for step in plan.steps)


def _records():
    return [
        {"timestamp": "2026-11-06T13:00:00Z", "source": "browser", "action": "download",
         "path": "/tmp/evil.exe", "url": "https://example.invalid/evil.exe"},
        {"timestamp": "2026-11-06T13:00:05Z", "source": "usn", "action": "file create",
         "path": "/tmp/evil.exe"},
        {"timestamp": "2026-11-06T13:00:08Z", "source": "prefetch", "action": "process execute",
         "path": "/tmp/evil.exe", "pid": 4242},
        {"timestamp": "2026-11-06T13:00:12Z", "source": "netscan", "action": "network connect",
         "path": "/tmp/evil.exe", "remote": "192.0.2.8"},
    ]


def test_strict_json_jsonl_csv_and_bodyfile_timeline_decoding():
    records = _records()
    as_json = json.dumps(records).encode()
    events = F.decode_timeline_artifact(as_json, source="bundle.json")
    assert len(events) == 4
    assert events[0].timestamp.isoformat() == "2026-11-06T13:00:00+00:00"
    scalar_data_field = json.dumps({"timestamp": "2026-11-06T13:00:00Z", "data": "detail"}).encode()
    assert len(F.decode_timeline_artifact(scalar_data_field)) == 1

    jsonl = b"\n".join(json.dumps(record).encode() for record in records)
    assert len(F.decode_timeline_artifact(jsonl, source="bundle.jsonl", format_hint="jsonl")) == 4

    csv_data = ("timestamp,source,action,path\n"
                "2026-11-06T13:00:00Z,browser,download,/tmp/evil.exe\n"
                "2026-11-06T13:00:08Z,prefetch,process execute,/tmp/evil.exe\n").encode()
    assert len(F.decode_timeline_artifact(csv_data, source="bundle.csv")) == 2

    body = b"0|/tmp/evil.exe|42|r/rrwxrwxrwx|0|0|10|1793970000|1793970001|1793970002|1793970003\n"
    body_events = F.decode_timeline_artifact(body, source="disk.body")
    assert len(body_events) == 4
    assert {event.time_type for event in body_events} == {"a", "m", "c", "b"}


def test_timeline_decoders_decline_partial_corrupt_and_binary_inputs():
    valid = json.dumps(_records()[0]).encode()
    assert F.decode_timeline_artifact(valid + b"\n{broken", format_hint="jsonl") == ()
    assert F.decode_timeline_artifact(b"timestamp,source\n2026-01-01T00:00:00Z\n") == ()
    assert F.decode_timeline_artifact(b"0|x|1|m|0|0|1|bad|2|3|4\n") == ()
    assert F.decode_timeline_artifact(b"time\x00stamp") == ()
    assert F.decode_timeline_artifact(b"not a format") == ()
    assert F.decode_timeline_artifact(valid, format_hint="plaso-binary") == ()
    assert F.decode_timeline_artifact(b'{"timestamp":"not-a-time","action":"execute"}') == ()


def test_timeline_resource_gates(monkeypatch):
    valid = json.dumps(_records()[0]).encode()
    monkeypatch.setattr(F, "MAX_ARTIFACT", len(valid) - 1)
    assert F.decode_timeline_artifact(valid) == ()
    monkeypatch.setattr(F, "MAX_ARTIFACT", 1 << 20)
    monkeypatch.setattr(F, "MAX_RECORDS", 1)
    csv_data = ("timestamp,source\n2026-01-01T00:00:00Z,a\n2026-01-01T00:00:01Z,b\n").encode()
    assert F.decode_timeline_artifact(csv_data) == ()
    monkeypatch.setattr(F, "MAX_TOTAL_TIMELINE", len(valid) + 1)
    assert F.build_super_timeline({"one": valid, "two": valid}) == ()


def test_super_timeline_and_evidence_correlations():
    records = _records()
    timeline = F.build_super_timeline({
        "part-a.json": json.dumps(records[:2]).encode(),
        "part-b.json": json.dumps(records[2:]).encode(),
        "corrupt.jsonl": b'{"timestamp":"2026-01-01T00:00:00Z"}\n{bad',
    })
    assert len(timeline) == 4
    correlations = F.correlate_events(timeline, window_seconds=30)
    by_kind = {item.kind: item for item in correlations}
    assert {"download-execute", "file-execute-network"} <= set(by_kind)
    assert by_kind["download-execute"].entity == "file:evil.exe"
    assert len(by_kind["file-execute-network"].sources) == 3
    assert all(item.start <= item.end and item.confidence >= 0.8 for item in correlations)


def test_correlation_declines_proximity_without_shared_entity_or_sources():
    unrelated = F.decode_timeline_artifact(json.dumps([
        {"timestamp": "2026-11-06T13:00:00Z", "source": "one", "action": "download", "path": "/tmp/a.exe"},
        {"timestamp": "2026-11-06T13:00:01Z", "source": "two", "action": "execute", "path": "/tmp/b.exe"},
    ]).encode())
    assert F.correlate_events(unrelated) == ()
    same_source = F.decode_timeline_artifact(json.dumps([
        {"timestamp": "2026-11-06T13:00:00Z", "source": "one", "action": "download", "path": "/tmp/a.exe"},
        {"timestamp": "2026-11-06T13:00:01Z", "source": "one", "action": "execute", "path": "/tmp/a.exe"},
    ]).encode())
    assert F.correlate_events(same_source) == ()
    assert F.correlate_events(same_source, window_seconds=0) == ()


def test_correlation_resource_gates(monkeypatch):
    events = F.decode_timeline_artifact(json.dumps(_records()).encode())
    monkeypatch.setattr(F, "MAX_CORRELATION_EVENTS", 2)
    assert F.correlate_events(events) == ()
    monkeypatch.setattr(F, "MAX_CORRELATION_EVENTS", 100)
    monkeypatch.setattr(F, "MAX_ENTITY_LINKS", 1)
    assert F.correlate_events(events) == ()
