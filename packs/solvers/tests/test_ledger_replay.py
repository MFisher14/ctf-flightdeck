"""B-101: stage events (ctf/stages.py), the wave replay and live summary (ctf/replay.py), the
`ctf ledger` command, and the stage hooks in `ctf wait`, `ctf pull` and the agent launchers.

Every ledger is synthetic. Records with chosen timestamps are written as JSON lines, so the replay
numbers are exact. The launcher test runs a stub `claude` executable written by the test: no real
agent session starts and nothing leaves the machine.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ctf import budget, event, flagfmt, ledger, paths, replay, stages
from ctf import cli as ctf_cli
from ctf.event import Budget

REPO = paths.repo_root()
PY = sys.executable
T = 1_800_000_000.0          # a fixed epoch for synthetic records


def write(wd: Path, recs: list[dict]) -> None:
    wd.mkdir(parents=True, exist_ok=True)
    with open(ledger.path(wd), "a", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")


def rec(dt: float, event_type: str, **fields) -> dict:
    return {"ts": T + dt, "event": event_type, **fields}


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def csctf():
    return event.load("csctf")


# ------------------------------------------------------------------ stages.mark / try_mark

def test_mark_validates_stage_challenge_and_wave(tmp_path):
    with pytest.raises(stages.StageError, match="unknown stage"):
        stages.mark("firsttool", "7", workdir=tmp_path)
    with pytest.raises(stages.StageError, match="challenge id"):
        stages.mark("claim", None, workdir=tmp_path)
    with pytest.raises(stages.StageError, match="challenge id"):
        stages.mark("claim", "  ", workdir=tmp_path)
    with pytest.raises(stages.StageError, match="wave label"):
        stages.mark("wave_open", workdir=tmp_path)
    with pytest.raises(stages.StageError, match="whole board"):
        stages.mark("wave_open", "7", workdir=tmp_path, wave="W1")
    assert not ledger.path(tmp_path).exists()
    r = stages.mark("claim", 7, workdir=tmp_path, by="dispatcher")
    assert (r["event"], r["challenge_id"], r["by"]) == ("claim", "7", "dispatcher")
    assert [x["event"] for x in ledger.read(tmp_path)] == ["claim"]


def test_try_mark_reports_an_unresolvable_workdir_and_still_raises_on_a_bad_stage(monkeypatch, capsys):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b101")
    stages._notified.clear()
    assert stages.try_mark("intake_start", "7") is None
    assert stages.try_mark("intake_start", "8") is None
    err = capsys.readouterr().err
    assert "stage 'intake_start' not recorded in the ledger" in err and "CTF_WORKDIR" in err
    assert err.count("not recorded") == 1                     # once per reason per process
    with pytest.raises(stages.StageError):
        stages.try_mark("nope", "7")


def test_try_mark_writes_when_the_workdir_resolves(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    r = stages.try_mark("intake_done", "9", ok=True)
    assert r is not None and [(x["event"], x["challenge_id"], x["ok"]) for x in ledger.read(tmp_path)] == \
        [("intake_done", "9", True)]


# ------------------------------------------------------------------ record_wave / record_spend

def test_record_wave_labels_waves_and_detects_only_new_challenges(tmp_path):
    o1, d1 = stages.record_wave([3, "1", "1", 2], workdir=tmp_path, announced=T)
    assert (o1["wave"], o1["count"], o1["announced"]) == ("W1", 3, T)
    assert [d["challenge_id"] for d in d1] == ["3", "1", "2"] and {d["wave"] for d in d1} == {"W1"}
    o2, d2 = stages.record_wave(["1", "2", "3", "4", "5"], workdir=tmp_path)
    assert o2["wave"] == "W2" and o2["count"] == 5 and "announced" not in o2
    assert [d["challenge_id"] for d in d2] == ["4", "5"]
    with pytest.raises(stages.StageError, match="already in the ledger"):
        stages.record_wave(["6"], label="W2", workdir=tmp_path)
    o3, d3 = stages.record_wave(["6"], label="late", workdir=tmp_path)
    assert o3["wave"] == "late" and [d["challenge_id"] for d in d3] == ["6"]
    assert stages.wave_labels(tmp_path) == ["W1", "W2", "late"]
    with pytest.raises(stages.StageError, match="epoch"):
        stages.record_wave(["7"], announced="tomorrow", workdir=tmp_path)


def test_record_spend_is_categorised_and_never_charged_to_a_challenge(tmp_path):
    for bad in ("Build", "misc", ""):
        with pytest.raises(stages.StageError, match="category"):
            stages.record_spend(1.0, 10, bad, workdir=tmp_path)
    for usd, tok in ((-1.0, 1), (float("nan"), 1), (1.0, -1), (1.0, 1.5), (True, 1)):
        with pytest.raises(stages.StageError):
            stages.record_spend(usd, tok, "build", workdir=tmp_path)
    r = stages.record_spend(12.5, 1000, "build", source="tools.ledger price", workdir=tmp_path)
    assert r["category"] == "build" and "challenge_id" not in r and r["tok"] == 1000
    m = budget.LedgerMeter(Budget(), workdir=tmp_path)
    assert m.challenges() == []                                 # the meter ignores team-level spend


def test_placeholders_are_not_candidates():
    for p in ("CSCTF{...}", "flag{xxx}", "CTF{<flag>}", "CTF{example}", "CSCTF{FLAG}", "CTF{___}",
              "flag{your_flag}", "CTF{ }"):
        assert stages.is_placeholder(p), p
    for real in ("CSCTF{x0r_1s_fun}", "flag{a}", "CTF{example_2}", "CTF{...a}"):
        assert not stages.is_placeholder(real), real


# ------------------------------------------------------------------ the agent stream tap

class Inner:
    harness = "claude"
    usd = 1.5

    def __init__(self):
        self.lines = []

    def feed(self, line):
        self.lines.append(line)
        return [len(self.lines)]


def tap(flags=None, record=None):
    got = []
    inner = Inner()
    t = stages.AgentStreamTap(inner, record or (lambda ev, **f: got.append((ev, f))), harness="claude",
                              flags=flags)
    return t, inner, got


def claude_line(kind, *blocks):
    return json.dumps({"type": kind, "message": {"role": "x", "content": list(blocks)}})


def test_tap_records_the_first_claude_tool_call_once_and_passes_lines_through():
    t, inner, got = tap()
    lines = [claude_line("assistant", {"type": "text", "text": "thinking"}),
             "not json", "[1, 2]",
             claude_line("assistant", {"type": "text", "text": "x"}, {"type": "tool_use", "name": "Bash"}),
             claude_line("assistant", {"type": "tool_use", "name": "Read"})]
    out = [t.feed(x) for x in lines]
    assert out == [[1], [2], [3], [4], [5]] and inner.lines == lines      # the usage feed is unchanged
    assert got == [("first_tool", {"by": "agent:claude", "tool": "Bash"})]
    assert t.usd == 1.5                                                    # reader attributes pass through


def test_tap_reads_codex_tool_items_only():
    assert stages.AgentStreamTap.tool_in({"type": "item.started", "item": {"type": "agent_message"}}) is None
    assert stages.AgentStreamTap.tool_in({"type": "item.started", "item": {"type": "reasoning"}}) is None
    assert stages.AgentStreamTap.tool_in({"type": "turn.completed", "usage": {}}) is None
    assert stages.AgentStreamTap.tool_in({"type": "user", "message": {"content": [{"type": "tool_use"}]}}) is None
    for it in ("command_execution", "file_change", "mcp_tool_call", "web_search"):
        assert stages.AgentStreamTap.tool_in({"type": "item.started", "item": {"type": it}}) == it
        assert stages.AgentStreamTap.tool_in({"type": "item.completed", "item": {"type": it}}) == it
    assert stages.AgentStreamTap.tool_in({"type": "item.updated", "item": {"type": "command_execution"}}) is None


def test_tap_records_each_distinct_flag_once_as_a_hash_and_skips_placeholders():
    ff = flagfmt.for_profile(csctf())
    t, _, got = tap(flags=ff)
    real = "CSCTF{st4ge_l3dger}"
    t.feed(json.dumps({"type": "system", "subtype": "init", "note": "CSCTF{in_the_init_line}"}))
    t.feed(claude_line("assistant", {"type": "text", "text": "the format is CSCTF{...}"}))
    t.feed(claude_line("user", {"type": "tool_result", "content": f"out: {real} done"}))
    t.feed(claude_line("assistant", {"type": "text", "text": f"found {real}"}))
    t.feed(json.dumps({"type": "item.completed",
                       "item": {"type": "command_execution", "aggregated_output": "chronos{second_one}"}}))
    cands = [f for ev, f in got if ev == "candidate"]
    assert cands == [{"by": "agent:claude", "flag_sha256": sha(real)},
                     {"by": "agent:claude", "flag_sha256": sha("chronos{second_one}")}]
    assert all(real not in json.dumps(f) for _, f in got)                # never the value


def test_tap_dedupes_spellings_that_normalize_to_one_flag_and_hashes_the_normalized_form():
    ff = flagfmt.for_profile(csctf())                    # case = prefix-insensitive
    assert ff.normalize("csctf{dup_V4riant}") == "CSCTF{dup_V4riant}"
    t, _, got = tap(flags=ff)
    t.feed(claude_line("user", {"type": "tool_result", "content": "seen csctf{dup_V4riant} here"}))
    t.feed(claude_line("assistant", {"type": "text", "text": "so the flag is CSCTF{dup_V4riant}"}))
    t.feed(claude_line("user", {"type": "tool_result", "content": "Csctf{dup_V4riant}"}))
    t.feed(claude_line("user", {"type": "tool_result", "content": "CSCTF{dup_v4riant}"}))  # body differs
    assert [f for ev, f in got if ev == "candidate"] == [
        {"by": "agent:claude", "flag_sha256": sha("CSCTF{dup_V4riant}")},
        {"by": "agent:claude", "flag_sha256": sha("CSCTF{dup_v4riant}")}]


def test_tap_looks_for_no_candidates_when_the_format_is_unknown():
    unknown = flagfmt.FlagFormat(event.FlagSpec(prefixes=()))
    assert not unknown.known and unknown.find_flags("anything{goes_here}")   # it would match anything
    t, _, got = tap(flags=unknown)
    t.feed(claude_line("user", {"type": "tool_result", "content": "anything{goes_here}"}))
    assert got == []


def test_tap_reports_a_failing_ledger_write_and_keeps_feeding(capsys):
    def boom(ev, **f):
        raise OSError("disk full")
    stages._notified.clear()
    t, inner, _ = tap(record=boom)
    assert t.feed(claude_line("assistant", {"type": "tool_use", "name": "Bash"})) == [1]
    assert inner.lines and "stage events not recorded: OSError: disk full" in capsys.readouterr().err


# ------------------------------------------------------------------ stage_events

def test_engine_runs_and_platform_submits_become_stages():
    recs = [rec(10, "engine.run", engine="warmups.crib", challenge_id="5", seconds=4.0, status="candidate",
                exit_code=0, via="ctf-run"),
            rec(11, "engine.run", engine="warmups.other", challenge_id="5", seconds=1.0, status="none",
                exit_code=0, via="ctf-run"),
            rec(12, "engine.run", engine="no.challenge", seconds=1.0, exit_code=0, via="ctf-run"),
            rec(20, "platform.submit", challenge_id="5#a", status="incorrect", provenance="xor"),
            rec(21, "platform.submit", challenge_id="5", status="rate_limited"),
            rec(22, "platform.submit", challenge_id="5", status="correct", provenance="xor"),
            rec(23, "platform.submit", challenge_id="6", status="already_solved"),
            rec(24, "agent_launch", challenge_id="6", harness="codex", mode="headless"),
            rec(25, "spend", challenge_id="6", usd=1.0, tok=3)]
    got = [(s.ts - T, s.stage, s.challenge_id, s.by) for s in replay.stage_events(recs)]
    assert got == [(6.0, "first_tool", "5", "engine:warmups.crib"),
                   (10.0, "candidate", "5", "engine:warmups.crib"),
                   (10.0, "first_tool", "5", "engine:warmups.other"),
                   (20.0, "submit", "5", "submit:xor"), (20.0, "rejected", "5", "submit:xor"),
                   (21.0, "submit", "5", None),
                   (22.0, "submit", "5", "submit:xor"), (22.0, "accepted", "5", "submit:xor"),
                   (23.0, "submit", "6", None), (23.0, "accepted", "6", None),
                   (24.0, "agent_launch", "6", "agent:codex")]


# ------------------------------------------------------------------ the wave replay

def wave_ledger(wd: Path) -> None:
    """W1 announced at T, seen open at T+7.7; three challenges; then W2 at T+1000 with one more."""
    write(wd, [
        rec(-50, "claim", challenge_id="99"),                         # before any wave: in none
        rec(7.7, "wave_open", wave="W1", count=3, announced=T),
        rec(7.7, "detect", challenge_id="1", wave="W1"),
        rec(7.7, "detect", challenge_id="2", wave="W1"),
        rec(7.7, "detect", challenge_id="3", wave="W1"),
        rec(9.0, "claim", challenge_id="1", by="dispatcher"),
        rec(12.3, "intake_start", challenge_id="1"),
        rec(13.0, "intake_start", challenge_id="2"),
        rec(30.0, "intake_done", challenge_id="1", ok=True),
        rec(84.9, "intake_done", challenge_id="2", ok=True),
        rec(100.0, "agent_launch", challenge_id="1", harness="claude", mode="headless"),
        rec(101.0, "first_tool", challenge_id="1", by="agent:claude", tool="Bash"),
        rec(150.0, "spend", challenge_id="1", usd=2.0, tok=100, source="launcher:claude"),
        rec(160.0, "candidate", challenge_id="1", by="agent:claude", flag_sha256="ab"),
        rec(170.0, "platform.submit", challenge_id="1", status="correct", provenance="agent"),
        rec(200.0, "engine.run", engine="warmups.crib", challenge_id="2", seconds=5.0, status="solved",
            exit_code=0, via="ctf-run"),
        rec(205.0, "platform.submit", challenge_id="2", status="correct", provenance="engine"),
        rec(250.0, "accepted", challenge_id="3", layer="human"),
        rec(1000.0, "wave_open", wave="W2", count=4),
        rec(1001.0, "detect", challenge_id="4", wave="W2"),
        rec(1002.0, "claim", challenge_id="3"),                          # W1's challenge, worked later
        rec(1003.0, "claim", challenge_id="5"),                          # never detected: by time -> W2
    ])


def test_replay_prints_the_wave_pipeline_second_by_second(tmp_path):
    wave_ledger(tmp_path)
    r = replay.wave_replay(list(ledger.read(tmp_path)), "W1")
    assert r.wave.t0 == T and r.wave.opened_ts == T + 7.7
    assert r.pipeline == [
        (0.0, "T0", None),
        (7.7, "wave W1 detected (3 challenges listed)", 7.7),
        (9.0, "first claim (1)", 1.3),
        (12.3, "first intake started (1)", 3.3),
        (84.9, "last intake done (2 of 3)", 72.6),
        (100.0, "first agent launched (1)", 15.1),
        (101.0, "first tool call (1, agent:claude)", 1.0),
        (160.0, "first candidate flag (1, agent:claude)", 59.0),
        (170.0, "first submit (1)", 10.0),
        (170.0, "first accepted (1)", 0.0),
        (250.0, "last first-accept (3 of 3 solved)", 80.0),
    ]
    rows = {x.challenge_id: x for x in r.rows}
    assert list(rows) == ["1", "2", "3"]                         # 4/5 are W2's, 99 is in no wave
    assert rows["1"].cells == {"detect": 7.7, "claim": 9.0, "intake": 30.0, "agent": 100.0, "tool": 101.0,
                               "cand": 160.0, "submit": 170.0, "accepted": 170.0}
    assert rows["1"].hold == 10.0 and rows["1"].closed_by == "agent"
    assert rows["2"].cells["tool"] == 195.0 and rows["2"].cells["cand"] == 200.0
    assert rows["2"].hold == 5.0 and rows["2"].closed_by == "layer1"
    assert rows["3"].closed_by == "human" and rows["3"].cells["claim"] == 1002.0
    assert r.medians["hold"] == (7.5, 2) and r.medians["accepted"] == (205.0, 3)
    assert r.medians["agent"] == (100.0, 1)
    assert any("announced" in n for n in r.notes)


def test_replay_assigns_late_and_undetected_challenges_to_the_right_wave(tmp_path):
    wave_ledger(tmp_path)
    recs = list(ledger.read(tmp_path))
    r2 = replay.wave_replay(recs, "W2")
    assert [x.challenge_id for x in r2.rows] == ["4", "5"]
    assert r2.wave.t0 == T + 1000 and r2.pipeline[0] == (0.0, "wave W2 detected (4 challenges listed)", None)
    latest = replay.wave_replay(recs)
    assert latest.wave.label == "W2" and any("showing the latest" in n for n in latest.notes)
    with pytest.raises(KeyError, match="W3"):
        replay.wave_replay(recs, "W3")


def test_an_explicit_detect_wins_over_time_order():
    st = replay.stage_events([rec(0, "wave_open", wave="W1"), rec(100, "wave_open", wave="W2"),
                              rec(150, "detect", challenge_id="6", wave="W1"),     # marked late, for W1
                              rec(160, "claim", challenge_id="7"),
                              rec(170, "detect", challenge_id="8", wave="nope"),   # unknown label: by time
                              rec(-5, "claim", challenge_id="9")])
    wl = replay.waves([], stages=st)
    assert replay.assign(st, wl) == {"6": "W1", "7": "W2", "8": "W2"}


def test_replay_t0_override_and_a_ledger_without_waves(tmp_path):
    write(tmp_path, [rec(5, "claim", challenge_id="1"), rec(9, "first_tool", challenge_id="1", by="agent:codex")])
    recs = list(ledger.read(tmp_path))
    r = replay.wave_replay(recs)
    assert r.wave.label == "all" and r.wave.t0 == T + 5 and any("no wave_open" in n for n in r.notes)
    assert r.pipeline == [(0.0, "first claim (1)", None), (4.0, "first tool call (1, agent:codex)", 4.0)]
    r = replay.wave_replay(recs, t0=T)
    assert [p[:2] for p in r.pipeline] == [(0.0, "T0"), (5.0, "first claim (1)"), (9.0, "first tool call (1, agent:codex)")]
    with pytest.raises(KeyError):
        replay.wave_replay(recs, "W1")
    with pytest.raises(KeyError, match="no stage records"):
        replay.wave_replay([])


def test_hold_is_left_out_when_the_candidate_comes_after_the_accept():
    recs = [rec(0, "wave_open", wave="W1", count=2),
            rec(0, "detect", challenge_id="1", wave="W1"), rec(0, "detect", challenge_id="2", wave="W1"),
            rec(10, "candidate", challenge_id="1", by="agent:claude"),
            rec(20, "accepted", challenge_id="1"),
            rec(30, "accepted", challenge_id="2"),
            rec(40, "candidate", challenge_id="2", by="agent:claude")]     # seen only after the accept
    r = replay.wave_replay(recs, "W1")
    rows = {x.challenge_id: x for x in r.rows}
    assert rows["1"].hold == 10.0 and rows["2"].hold is None
    assert r.medians["hold"] == (10.0, 1)


def test_a_wave_with_one_intake_and_one_solve_has_the_exact_pipeline():
    recs = [rec(0, "wave_open", wave="W1", count=1), rec(0, "detect", challenge_id="1", wave="W1"),
            rec(2, "intake_start", challenge_id="1"), rec(5, "intake_done", challenge_id="1", ok=True),
            rec(9, "platform.submit", challenge_id="1", status="correct")]
    assert replay.wave_replay(recs, "W1").pipeline == [
        (0.0, "wave W1 detected (1 challenges listed)", None),
        (2.0, "first intake started (1)", 2.0),
        (5.0, "last intake done (1 of 1)", 3.0),
        (9.0, "first submit (1)", 4.0),
        (9.0, "first accepted (1)", 0.0)]                 # no 'last first-accept' with one solve


def test_a_failed_intake_is_not_counted_as_done():
    recs = [rec(0, "wave_open", wave="W1", count=3)]
    recs += [rec(0, "detect", challenge_id=c, wave="W1") for c in ("1", "2", "3")]
    recs += [rec(5, "intake_done", challenge_id="1"),                 # no ok field (a mark): done
             rec(6, "intake_done", challenge_id="2", ok=False),       # failed, never retried
             rec(7, "intake_done", challenge_id="3", ok=False),       # failed, then pulled
             rec(20, "intake_done", challenge_id="3", ok=True),
             rec(30, "intake_done", challenge_id="2", ok=False)]      # failed again, last of all
    r = replay.wave_replay(recs, "W1")
    assert [p[:2] for p in r.pipeline if "intake" in p[1]] == [(20.0, "last intake done (2 of 3)")]
    assert {x.challenge_id: x.cells["intake"] for x in r.rows} == {"1": 5.0, "2": None, "3": 20.0}
    assert r.medians["intake"] == (12.5, 2)
    assert any("intake failed and never succeeded for 1 challenge(s): 2" in n for n in r.notes)
    recs[-1] = rec(30, "intake_done", challenge_id="2", ok=True)
    r = replay.wave_replay(recs, "W1")
    assert not any("intake failed" in n for n in r.notes)
    assert [p[:2] for p in r.pipeline if "intake" in p[1]] == [(30.0, "last intake done (3 of 3)")]


def test_closed_by_needs_activity_before_the_accept():
    def st(dt, stage, by=None, **d):
        return replay.Stage(T + dt, stage, "1", by, d)
    acc = st(10, "accepted")
    assert replay.closed_by([st(1, "first_tool", "engine:x"), acc], []) == "layer1"
    assert replay.closed_by([st(1, "first_tool", "engine:x"), acc], [T + 5]) == "agent"     # spend first
    assert replay.closed_by([st(1, "first_tool", "engine:x"), acc], [T + 11]) == "layer1"   # spend after
    assert replay.closed_by([st(1, "first_tool", "engine:x"), acc], [T + 10]) == "agent"    # same instant
    assert replay.closed_by([acc], [T + 10]) == "agent"                                       # spend only
    assert replay.closed_by([st(1, "first_tool", "engine:x"), acc, st(11, "agent_launch")], []) == "layer1"
    assert replay.closed_by([st(1, "candidate", "agent:codex"), acc], []) == "agent"
    assert replay.closed_by([acc], []) == "other"
    assert replay.closed_by([st(1, "first_tool", "agent:codex")], []) is None
    assert replay.closed_by([replay.Stage(T + 10, "accepted", "1", None, {"layer": "layer1"}),
                             st(1, "agent_launch")], []) == "layer1"


def test_render_shows_the_pipeline_and_the_rows(tmp_path):
    wave_ledger(tmp_path)
    text = replay.render(replay.wave_replay(list(ledger.read(tmp_path)), "W1"))
    assert "Wave W1, T0 = 2027-01-15 08:00:00.000Z (announced)" in text
    assert "     84.9 |     72.6 | last intake done (2 of 3)" in text
    row1 = next(x for x in text.splitlines() if x.startswith("1 "))
    assert [c.strip() for c in row1.split("|")] == ["1", "7.7", "9.0", "30.0", "100.0", "101.0", "160.0",
                                                    "170.0", "170.0", "10.0", "agent"]
    med = next(x for x in text.splitlines() if x.startswith("median"))
    assert [c.strip() for c in med.split("|")][-2] == "7.5"


# ------------------------------------------------------------------ the summary

def summary_ledger(wd: Path) -> None:
    wave_ledger(wd)
    write(wd, [
        rec(1, "spend", usd=40.0, tok=10, category="build"),             # before W2: counts for W1
        rec(2, "spend", usd=10.0, tok=5),                                 # no category, no challenge
        rec(150.5, "spend", challenge_id="1", usd=3.0, tok=7, category="verify"),
        rec(300, "spend", challenge_id="3", usd=30.0, tok=1),
        rec(310, "stop", challenge_id="3", reason="team_solve"),
        rec(320, "spend", challenge_id="3", usd=5.0, tok=1),             # after the team solve
        rec(1100, "spend", challenge_id="4", usd=100.0, tok=1),
        rec(1101, "spend", usd=7.0, tok=1, category="doc"),
    ])


def test_summary_spend_by_category_dollars_per_solve_tail_and_layer1(tmp_path):
    summary_ledger(tmp_path)
    s = replay.summarize(list(ledger.read(tmp_path)), tail_of=lambda c: c == "4")
    assert s.by_category == {"build": {"usd": 40.0, "tok": 10}, "doc": {"usd": 7.0, "tok": 1},
                             "solve": {"usd": 137.0, "tok": 103}, "uncategorized": {"usd": 10.0, "tok": 5},
                             "verify": {"usd": 3.0, "tok": 7}}
    assert s.total_usd == 197.0 and s.challenge_usd == 140.0
    assert s.solved == ["1", "2", "3"]
    assert s.usd_per_solve == pytest.approx(197.0 / 3) and s.solve_usd_per_solve == pytest.approx(137.0 / 3)
    assert s.tail == ["4"] and s.tail_usd == 100.0 and s.tail_share == pytest.approx(100 / 140)
    assert s.top5_share == pytest.approx(1.0)
    assert s.after_team_solve_usd == 5.0
    assert s.closed_by == {"agent": 1, "human": 1, "layer1": 1}
    assert s.layer1_rate == pytest.approx(1 / 3) and s.engine_challenges == 1 and s.layer1_armed_rate == 1.0
    text = replay.render_summary(s)
    assert "Layer-1 close rate: 33.3% of solves (1 of 3)" in text
    assert "Hard-tail share: 71.4% of challenge spend ($100.00 on 1 tail challenge(s): 4)" in text
    assert "Spent after a team solve: $5.00" in text


def test_spend_at_the_team_solve_instant_is_not_after_it():
    recs = [rec(0, "wave_open", wave="W1"), rec(1, "claim", challenge_id="1"),
            rec(50, "spend", challenge_id="1", usd=2.0, tok=1),
            rec(50, "stop", challenge_id="1", reason="team_solve"),
            rec(60, "spend", challenge_id="1", usd=4.0, tok=1)]
    assert replay.summarize(recs, tail_of=lambda c: False).after_team_solve_usd == 4.0


def test_summary_of_one_wave(tmp_path):
    summary_ledger(tmp_path)
    recs = list(ledger.read(tmp_path))
    s1 = replay.summarize(recs, tail_of=lambda c: False, wave="W1")
    assert s1.solved == ["1", "2", "3"] and s1.challenge_usd == 40.0          # 2 + 3 + 30 + 5
    assert s1.by_category["build"]["usd"] == 40.0 and "doc" not in s1.by_category
    assert s1.tail_share == 0.0
    s2 = replay.summarize(recs, tail_of=lambda c: True, wave="W2")
    assert s2.solved == [] and s2.usd_per_solve is None and s2.layer1_rate is None
    assert s2.by_category == {"doc": {"usd": 7.0, "tok": 1}, "solve": {"usd": 100.0, "tok": 1}}
    assert s2.tail_share == 1.0
    with pytest.raises(KeyError, match="no wave 'W9'"):
        replay.summarize(recs, tail_of=lambda c: False, wave="W9")


# ------------------------------------------------------------------ the CLI

def cli(*argv) -> int:
    return ctf_cli.main(list(argv))


def test_cli_replay_waves_and_json(tmp_path, capsys):
    wave_ledger(tmp_path)
    assert cli("ledger", "--workdir", str(tmp_path), "replay", "--wave", "W1") == 0
    out = capsys.readouterr().out
    assert "wave W1 detected (3 challenges listed)" in out and "last intake done (2 of 3)" in out
    assert cli("ledger", "--workdir", str(tmp_path), "replay", "--wave", "W1", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["pipeline"][4] == [84.9, "last intake done (2 of 3)", 72.6]
    assert cli("ledger", "--workdir", str(tmp_path), "replay", "--t0", "2027-01-15T08:00:10+00:00",
               "--wave", "W1", "--json") == 0
    assert json.loads(capsys.readouterr().out)["wave"]["t0"] == T + 10      # ISO with offset parsed
    assert cli("ledger", "--workdir", str(tmp_path), "waves") == 0
    out = capsys.readouterr().out
    assert "W1" in out and "(announced)" in out and "challenges 3" in out and "challenges 2" in out
    assert cli("ledger", "--workdir", str(tmp_path), "replay", "--wave", "W7") == 2
    assert "no wave 'W7'" in capsys.readouterr().err
    assert cli("ledger", "--workdir", str(tmp_path), "replay", "--t0", "2027-01-15T08:00") == 2
    assert "no UTC offset" in capsys.readouterr().err
    assert cli("ledger", "--workdir", str(tmp_path / "empty"), "replay") == 2
    assert "no ledger at" in capsys.readouterr().err


def test_cli_replay_t0_override_moves_every_offset(tmp_path, capsys):
    wave_ledger(tmp_path)
    assert cli("ledger", "--workdir", str(tmp_path), "replay", "--wave", "W1", "--t0", str(T + 10), "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["wave"]["t0"] == T + 10
    assert d["pipeline"][0] == [-2.3, "wave W1 detected (3 challenges listed)", None]
    assert d["rows"][0]["cells"]["claim"] == -1.0


def test_cli_summary_uses_the_event_budget_for_the_hard_tail(tmp_path, capsys):
    summary_ledger(tmp_path)
    # csctf: per_point 0.5, ceiling 250 -> a challenge worth 500+ points is a high-value tail
    write(tmp_path, [rec(1, "budget_challenge", challenge_id="4", points=500),
                     rec(1, "budget_challenge", challenge_id="3", points=100)])
    assert cli("ledger", "--event", "csctf", "--workdir", str(tmp_path), "summary", "--json") == 0
    d = json.loads(capsys.readouterr().out)
    assert d["tail"] == ["4"] and d["tail_usd"] == 100.0
    assert cli("ledger", "--event", "csctf", "--workdir", str(tmp_path), "summary") == 0
    assert "Spend by category:" in capsys.readouterr().out
    assert cli("ledger", "--event", "no-such-event-b101", "--workdir", str(tmp_path), "summary") == 2
    assert "ctf ledger summary:" in capsys.readouterr().err


def test_cli_mark_and_spend(tmp_path, capsys):
    wd = str(tmp_path)
    assert cli("ledger", "--workdir", wd, "mark", "wave_open", "--announced", "2027-01-15T08:00:00Z") == 0
    assert cli("ledger", "--workdir", wd, "mark", "claim", "--challenge", "12", "--by", "orchestrator") == 0
    assert cli("ledger", "--workdir", wd, "mark", "accepted", "--challenge", "12", "--layer", "layer1") == 0
    capsys.readouterr()
    assert cli("ledger", "--workdir", wd, "mark", "claim") == 2
    assert "challenge id" in capsys.readouterr().err
    assert cli("ledger", "--workdir", wd, "mark", "claim", "--challenge", "1", "--layer", "agent") == 2
    assert cli("ledger", "--workdir", wd, "mark", "wave_open", "--wave", "W1") == 2
    assert "already in the ledger" in capsys.readouterr().err
    assert cli("ledger", "--workdir", wd, "spend", "--usd", "3.5", "--tok", "70", "--category", "verify") == 0
    recs = list(ledger.read(tmp_path))
    assert [(r["event"], r.get("challenge_id"), r.get("wave"), r.get("by"), r.get("layer")) for r in recs] == [
        ("wave_open", None, "W1", None, None), ("claim", "12", None, "orchestrator", None),
        ("accepted", "12", None, None, "layer1"), ("spend", None, None, None, None)]
    assert recs[0]["announced"] == T                       # 2027-01-15T08:00:00Z
    assert recs[3]["category"] == "verify" and recs[3]["usd"] == 3.5
    r = replay.wave_replay(recs)
    assert r.rows[0].closed_by == "layer1"


# ------------------------------------------------------------------ hooks: ctf wait, ctf pull

class FakeCfg:
    def require_auth(self):
        pass


class FakeBoard:
    cfg = FakeCfg()

    def __init__(self, ids):
        self.ids = ids

    def challenges(self):
        return [{"id": i, "name": f"c{i}"} for i in self.ids]


def test_ctf_wait_records_the_wave_and_new_detects(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    board = FakeBoard([11, 12])
    monkeypatch.setattr(ctf_cli, "_ctfd", lambda: board)
    assert cli("wait", "--interval", "1", "--timeout", "1") == 0
    board.ids = [11, 12, 13]
    past = 1_700_000_000.0                                   # an announced start already gone by
    assert cli("wait", "--grow-from", "2", "--interval", "1", "--timeout", "1", "--wave", "late",
               "--not-before", str(past)) == 0
    recs = list(ledger.read(tmp_path))
    assert [(r["event"], r.get("wave"), r.get("challenge_id")) for r in recs] == [
        ("wave_open", "W1", None), ("detect", "W1", "11"), ("detect", "W1", "12"),
        ("wave_open", "late", None), ("detect", "late", "13")]
    assert "announced" not in recs[0] and recs[0]["count"] == 2
    assert recs[3]["announced"] == past and recs[3]["count"] == 3
    capsys.readouterr()

    def no_poll():
        raise AssertionError("a clashing --wave label must fail before the board is polled")
    monkeypatch.setattr(ctf_cli, "_ctfd", no_poll)
    assert cli("wait", "--grow-from", "2", "--interval", "1", "--timeout", "1", "--wave", "late") == 2
    err = capsys.readouterr().err
    assert "wave 'late' is already in the ledger" in err and "CTF_WORKDIR" not in err
    assert len(list(ledger.read(tmp_path))) == len(recs)                 # nothing written


def test_record_wave_reports_a_label_clash_without_the_workdir_hint(monkeypatch, tmp_path, capsys):
    # the clash can still arise at record time (another writer took the label during the poll)
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    stages.record_wave(["1"], label="W1", workdir=tmp_path)
    ctf_cli._record_wave(["2"], label="W1", announced=None)
    err = capsys.readouterr().err
    assert "wave not recorded in the ledger: wave 'W1' is already in the ledger" in err
    assert "CTF_WORKDIR" not in err
    assert [r["event"] for r in ledger.read(tmp_path)] == ["wave_open", "detect"]


def test_ctf_wait_with_a_label_and_no_ledger_still_waits_and_says_why_nothing_was_recorded(
        monkeypatch, capsys):
    monkeypatch.delenv("CTF_WORKDIR", raising=False)
    monkeypatch.setenv("CTF_EVENT", "no-such-event-b101")
    monkeypatch.setattr(ctf_cli, "_ctfd", lambda: FakeBoard([1]))
    assert cli("wait", "--interval", "1", "--timeout", "1", "--wave", "W1") == 0
    err = capsys.readouterr().err
    assert "wave not recorded in the ledger" in err and "CTF_WORKDIR" in err
    # the label pre-check warns before the wait starts, not only after the board opens
    warn = err.find("cannot read the ledger to check wave label 'W1'")
    assert 0 <= warn < err.find("waiting for the wave to open")


def test_ctf_wait_warns_at_pre_check_on_a_corrupt_ledger(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    lp = ledger.path(tmp_path)
    lp.parent.mkdir(parents=True, exist_ok=True)
    lp.write_text("{not json\n")
    polled = []

    class Board(FakeBoard):
        def challenges(self):
            polled.append(capsys.readouterr().err)       # stderr written before the first poll
            return super().challenges()
    monkeypatch.setattr(ctf_cli, "_ctfd", lambda: Board([1]))
    assert cli("wait", "--interval", "1", "--timeout", "1", "--wave", "W1") == 0
    assert polled and "cannot read the ledger to check wave label 'W1'" in polled[0]
    assert "wave not recorded in the ledger" in capsys.readouterr().err


def test_ctf_wait_records_nothing_on_a_timeout(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(ctf_cli, "_ctfd", lambda: FakeBoard([1]))
    monkeypatch.setattr(ctf_cli, "wait_for_open", lambda fn, **kw: (1, "timed out"))
    assert cli("wait", "--interval", "1", "--timeout", "1") == 1
    assert not ledger.path(tmp_path).exists()


def test_ctf_pull_records_intake_start_and_done(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    calls = []

    def inner(c, cid):
        calls.append(cid)
        if cid == 2:
            raise RuntimeError("download failed")
        return "ch"
    monkeypatch.setattr(ctf_cli, "_pull_one_inner", inner)
    assert ctf_cli._pull_one(object(), 1) == "ch"
    with pytest.raises(RuntimeError):
        ctf_cli._pull_one(object(), 2)
    got = [(r["event"], r["challenge_id"], r.get("ok")) for r in ledger.read(tmp_path)]
    assert calls == [1, 2]
    assert got == [("intake_start", "1", None), ("intake_done", "1", True),
                   ("intake_start", "2", None), ("intake_done", "2", False)]


# ------------------------------------------------------------------ hook: the agent launcher

STUB = '''#!{py}
import json, os, sys
if sys.argv[1:] == ["--help"]:      # B-095: claude_launch reads the CLI's help for --effort; no session
    print("Options:\\n  --effort <level>  Effort level for the current session")
    sys.exit(0)
for line in json.load(open(os.environ["STUB_LINES"])):
    print(line, flush=True)
'''


def test_claude_launcher_records_first_tool_and_candidates(tmp_path):
    work, ws, bindir = tmp_path / "work", tmp_path / "ws", tmp_path / "bin"
    work.mkdir(), bindir.mkdir()
    stub = bindir / "claude"
    stub.write_text(STUB.format(py=PY))
    stub.chmod(0o755)
    real = "CSCTF{l4unch3r_s4w_1t}"
    m = "claude-sonnet-4-6"

    def msg(mid, *blocks, kind="assistant"):
        return json.dumps({"type": kind, "message": {"id": mid, "model": m, "role": kind,
                                                     "content": list(blocks),
                                                     "usage": {"input_tokens": 10, "output_tokens": 5}}})
    lines = [json.dumps({"type": "system", "subtype": "init"}),
             msg("m1", {"type": "text", "text": "flag format CSCTF{...}"}),
             msg("m2", {"type": "tool_use", "name": "Bash", "input": {"command": "strings x"}}),
             json.dumps({"type": "user", "message": {"role": "user", "content": [
                 {"type": "tool_result", "content": f"junk {real} junk"}]}}),
             msg("m3", {"type": "tool_use", "name": "Read", "input": {}}),
             json.dumps({"type": "result", "subtype": "success", "total_cost_usd": 0.0})]
    (tmp_path / "lines.json").write_text(json.dumps(lines))
    env = dict(os.environ, CTF_WORKDIR=str(work), CTF_EVENT="csctf", STUB_LINES=str(tmp_path / "lines.json"))
    env.pop("CTF_CHALLENGE", None)
    r = subprocess.run([PY, str(REPO / "tools" / "claude_launch"), "--workspace", str(ws), "--claude-bin",
                        str(stub), "--challenge", "21", "--", "-p", "go"], capture_output=True, text=True,
                       env=env, stdin=subprocess.DEVNULL, timeout=60)
    assert r.returncode == 0, r.stderr
    recs = list(ledger.read(work))
    ft = [x for x in recs if x["event"] == "first_tool"]
    cand = [x for x in recs if x["event"] == "candidate"]
    assert [(x["challenge_id"], x["by"], x["tool"], x["harness"]) for x in ft] == [("21", "agent:claude", "Bash", "claude")]
    assert [(x["challenge_id"], x["flag_sha256"]) for x in cand] == [("21", sha(real))]
    assert real not in ledger.path(work).read_text()
    launch = next(x for x in recs if x["event"] == "agent_launch")
    assert launch["ts"] <= ft[0]["ts"] <= cand[0]["ts"]
    rows = replay.wave_replay(recs).rows
    assert rows[0].cells["tool"] is not None and rows[0].cells["cand"] >= rows[0].cells["tool"]
