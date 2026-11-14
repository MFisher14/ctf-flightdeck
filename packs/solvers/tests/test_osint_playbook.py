"""B-115: the time-boxed live-OSINT playbook -- the token cap + time box on the meter, the written human
handoff (queries tried, candidates, models tried, stop record), and the threat-intel guess-budget guard.

No network, no browser, no model: synthetic ledgers and an injected clock throughout.
"""
from __future__ import annotations

import json
import time
import types

import pytest

from ctf import budget, escalation, hypothesis, ledger, osint_playbook as pb
from ctf.event import Budget


class Clock:
    """Real time plus a movable offset; the ledger's record timestamps use the same source, so the time
    box (box_elapsed = now - first ledger ts) is driven entirely by `advance`, never by wall time."""

    def __init__(self):
        self.offset = 0.0

    def __call__(self):
        return time.time() + self.offset

    def advance(self, seconds):
        self.offset += seconds


class FixedClock:
    """A clock with no real-time component, so `box_elapsed = now - first_ts` lands on an exact second.
    The real-time `clock` fixture drifts by the wall time elapsed between opening the box and checking
    it, so it cannot test the boundary second (`elapsed == time_box_seconds`) exactly; this can."""

    def __init__(self, base=1_000_000.0):
        self.now = float(base)

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def fixed_clock(monkeypatch):
    c = FixedClock()
    monkeypatch.setattr(ledger, "time", types.SimpleNamespace(time=c))
    monkeypatch.setattr(hypothesis, "time", types.SimpleNamespace(time=c))
    return c


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(ledger, "time", types.SimpleNamespace(time=c))
    monkeypatch.setattr(hypothesis, "time", types.SimpleNamespace(time=c))
    return c


def _meter(tmp_path, clock, **osint):
    prof = pb.OsintProfile(**{"time_box_seconds": 600, "token_cap": 1000, **osint})
    return pb.meter(Budget(), workdir=tmp_path, osint=prof, clock=clock)


def events(tmp_path, kind):
    return [r for r in ledger.read(tmp_path) if r["event"] == kind]


# ------------------------------------------------------------------ the meter: token cap + time box

def test_token_cap_trips_check_and_shows_in_status(tmp_path, clock):
    m = _meter(tmp_path, clock, token_cap=1000)
    pb.open_box(m, "viz")
    st = m.status("viz")
    assert st.box_state == "ok" and st.tokens_left == 1000 and st.token_cap == 1000
    m.add_spend("viz", 1.0, 400)
    assert m.status("viz").tokens_left == 600
    assert m.check("viz").box_state == "ok"          # still under the cap
    m.add_spend("viz", 1.0, 700)                       # 1100 > 1000
    st = m.status("viz")
    assert st.box_state == "over_tokens" and st.tokens_left == 0
    with pytest.raises(budget.OsintBoxExceeded) as ei:
        m.check("viz")
    assert ei.value.reason == budget.OSINT_TOKEN_CAP and ei.value.tokens == 1100


def test_time_box_trips_check_on_the_injected_clock(tmp_path, clock):
    m = _meter(tmp_path, clock, time_box_seconds=600)
    pb.open_box(m, "viz")
    clock.advance(599)
    assert m.check("viz").box_state == "ok"
    assert 0 < m.status("viz").box_seconds_left <= 1.0
    clock.advance(2)                                   # 601s elapsed, past the 600s box
    st = m.status("viz")
    assert st.box_state == "over_time" and st.box_seconds_left == 0.0
    with pytest.raises(budget.OsintBoxExceeded) as ei:
        m.check("viz")
    assert ei.value.reason == budget.OSINT_TIME_BOX


def test_token_cap_trips_at_exactly_the_cap(tmp_path, clock):
    # The boundary: spending exactly the cap must trip (osint_reason uses `tokens >= token_cap`).
    # A run that lands on the cap stops here, not one token later.
    m = _meter(tmp_path, clock, token_cap=1000)
    pb.open_box(m, "viz")
    m.add_spend("viz", 1.0, 999)
    assert m.check("viz").box_state == "ok"            # one short of the cap: still allowed
    m.add_spend("viz", 1.0, 1)                          # now exactly 1000 == token_cap
    st = m.status("viz")
    assert st.box_state == "over_tokens" and st.tokens_left == 0
    with pytest.raises(budget.OsintBoxExceeded) as ei:
        m.check("viz")
    assert ei.value.reason == budget.OSINT_TOKEN_CAP and ei.value.tokens == 1000


def test_time_box_trips_at_exactly_the_box(tmp_path, fixed_clock):
    # The boundary: elapsed exactly == time_box_seconds must trip (box_elapsed uses `>= time_box_seconds`).
    # Driven by a FixedClock so elapsed is exactly 600.0, not 600 + the wall drift of the real-time clock.
    m = _meter(tmp_path, fixed_clock, time_box_seconds=600)
    pb.open_box(m, "viz")
    fixed_clock.advance(599)
    assert m.check("viz").box_state == "ok"            # one second short of the box
    fixed_clock.advance(1)                              # elapsed is now exactly 600.0
    assert m.box_elapsed("viz") == 600.0
    st = m.status("viz")
    assert st.box_state == "over_time" and st.box_seconds_left == 0.0
    with pytest.raises(budget.OsintBoxExceeded) as ei:
        m.check("viz")
    assert ei.value.reason == budget.OSINT_TIME_BOX


def test_meter_without_osint_profile_never_raises_the_box(tmp_path, clock):
    m = budget.LedgerMeter(Budget(), workdir=tmp_path, clock=clock)   # neither cap nor box
    m.register("x")                                     # low-value, no no-progress timer
    m.add_spend("x", 1.0, 10**9)                       # a billion tokens
    clock.advance(10 * 3600)
    st = m.check("x")                                   # no OsintBoxExceeded
    assert st.box_state == "ok" and st.token_cap is None and st.tokens_left is None
    assert st.box_seconds_left is None


def test_bad_osint_profile_values_are_loud():
    with pytest.raises(pb.PlaybookError):
        pb.OsintProfile(token_cap=0)
    with pytest.raises(pb.PlaybookError):
        pb.OsintProfile(time_box_seconds=0)
    with pytest.raises(ValueError):
        budget.LedgerMeter(Budget(), token_cap=True)   # a bool is not a token count


# ------------------------------------------------------------------ what has already been done

def test_tried_queries_and_candidates_come_from_the_hypothesis_ledger(tmp_path, clock):
    cid = "viz"
    hypothesis.record(cid, hypothesis="exif has coords", method="exiftool -gps", result=hypothesis.NEGATIVE,
                       agent="codex-1", workdir=tmp_path)
    hypothesis.record(cid, hypothesis="reverse image", method="reverse image search", result=hypothesis.NEGATIVE,
                       agent="claude-2", workdir=tmp_path)
    hypothesis.record(cid, hypothesis="venue guess", method="name the venue", result=hypothesis.POSITIVE,
                       payload="spooky{a_real_looking_flag}", agent="claude-2", workdir=tmp_path)
    tried = pb.tried_queries(cid, tmp_path)
    assert {t.method for t in tried} == {"exiftool -gps", "reverse image search", "name the venue"}
    cands = pb.candidates(cid, workdir=tmp_path)
    assert [c.value for c in cands] == ["spooky{a_real_looking_flag}"]
    assert cands[0].source == "hypothesis"


def test_candidates_mark_a_known_wrong_answer_do_not_resubmit(tmp_path, clock):
    cid = "viz"

    class FakeWorkspace:
        def load_tried(self):
            return {"attempts": [{"flag": "spooky{wrong}", "status": "incorrect"},
                                 {"flag": "spooky{also_wrong}", "status": "incorrect"}]}

    hypothesis.record(cid, hypothesis="guess", method="m", result=hypothesis.POSITIVE,
                      payload="spooky{wrong}", agent="a", workdir=tmp_path)
    cands = pb.candidates(cid, workdir=tmp_path, workspace=FakeWorkspace())
    wrong = next(c for c in cands if c.value == "spooky{wrong}" and c.source == "hypothesis")
    assert wrong.resubmit is False                      # already judged incorrect in the workspace
    ws_rows = [c for c in cands if c.source == "workspace"]
    assert all(c.resubmit is False for c in ws_rows)


def test_models_tried_reads_escalation_records(tmp_path, clock):
    cid = "viz"
    ledger.append("agent_launch", workdir=tmp_path, challenge_id=cid, model="claude-opus-5-5")
    escalation.record_agent_stop("refusal", cid, harness="claude", workdir=tmp_path, model="claude-opus-5-5")
    assert pb.models_tried(cid, tmp_path) == ["claude-opus-5-5"]


# ------------------------------------------------------------------ the handoff

def test_build_handoff_writes_file_records_stop_and_ledger_event(tmp_path, clock):
    cid = "viz"
    m = _meter(tmp_path, clock)
    pb.open_box(m, cid)
    m.add_spend(cid, 12.0, 500)
    hypothesis.record(cid, hypothesis="h", method="reverse image search", result=hypothesis.NEGATIVE,
                      agent="codex", workdir=tmp_path)
    h = pb.build_handoff(m, cid, reason=budget.OSINT_TIME_BOX,
                         sources=["instagram venue tag", "news article on the launch"], notes="stuck")
    assert h.path.exists()
    doc = json.loads(h.path.read_text(encoding="utf-8"))
    assert doc["reason"] == budget.OSINT_TIME_BOX
    assert doc["tokens"] == 500 and doc["spent_usd"] == 12.0
    assert [q["method"] for q in doc["queries_tried"]] == ["reverse image search"]
    assert doc["sources"] == ["instagram venue tag", "news article on the launch"]
    assert "human takes over" in doc["next_steps"].lower()
    # the stop makes is_stopped report it, so the dispatcher/escalator leave it alone
    assert budget.is_stopped(cid, workdir=tmp_path) == "manual"
    hs = events(tmp_path, pb.HANDOFF_EVENT)
    assert len(hs) == 1 and hs[0]["tok"] == 500 and hs[0]["queries"] == 1


def test_handoff_ledger_record_never_uses_a_token_keyed_field(tmp_path, clock):
    # ctf.ledger refuses any field whose key contains "token" as a possible secret; the handoff must
    # record the count under "tok", so this must not raise.
    m = _meter(tmp_path, clock)
    pb.open_box(m, "viz")
    m.add_spend("viz", 1.0, 42)
    pb.build_handoff(m, "viz", reason=budget.OSINT_TOKEN_CAP)   # would raise if it wrote a "token" key


def test_guard_hands_off_once_then_returns_the_same_handoff(tmp_path, clock):
    cid = "viz"
    m = _meter(tmp_path, clock, token_cap=100)
    pb.open_box(m, cid)
    assert pb.guard(m, cid) is None                     # under the cap: continue
    m.add_spend(cid, 1.0, 150)                           # over the token cap
    h1 = pb.guard(m, cid)
    assert h1 is not None and h1.reason == budget.OSINT_TOKEN_CAP
    h2 = pb.guard(m, cid)                                # called again by the loop
    assert h2 is not None and h2.path == h1.path
    assert len(events(tmp_path, pb.HANDOFF_EVENT)) == 1  # written exactly once
    assert len(events(tmp_path, "stop")) == 1


def test_guard_hands_off_on_the_time_box(tmp_path, clock):
    cid = "viz"
    m = _meter(tmp_path, clock, time_box_seconds=600)
    pb.open_box(m, cid)
    clock.advance(601)
    h = pb.guard(m, cid, sources=["a source"])
    assert h is not None and h.reason == budget.OSINT_TIME_BOX
    assert budget.is_stopped(cid, workdir=tmp_path) == "manual"


def test_guard_hands_off_on_an_existing_stop_without_double_stopping(tmp_path, clock):
    cid = "viz"
    m = _meter(tmp_path, clock)
    pb.open_box(m, cid)
    m.stop(cid, "team_solve", by="teammate")            # someone solved it
    h = pb.guard(m, cid)
    assert h is not None and h.reason == "team_solve"
    stops = events(tmp_path, "stop")
    assert len(stops) == 1 and stops[0]["reason"] == "team_solve"   # no extra manual stop


# ------------------------------------------------------------------ the guess-budget guard

def test_guess_budget_allows_until_the_wrong_count_reaches_it():
    assert pb.check_guess_budget(0, guess_budget=3).allowed
    assert pb.check_guess_budget(2, guess_budget=3).allowed
    g = pb.check_guess_budget(3, guess_budget=3)
    assert not g.allowed and "stop and ask the player" in g.reason


def test_guess_budget_reopens_with_a_player_approval():
    g = pb.check_guess_budget(5, guess_budget=3, approvals_left=1)
    assert g.allowed and "approval permits" in g.reason
    assert not pb.check_guess_budget(5, guess_budget=3, approvals_left=0).allowed


def test_guard_osint_lookup_reads_the_workspace_wrong_count_and_approvals():
    class FakeWorkspace:
        def __init__(self, wrong, approvals):
            self._wrong, self._approvals = wrong, approvals

        def wrong_count(self):
            return self._wrong

        def post_guard_approvals_left(self):
            return self._approvals

    assert pb.guard_osint_lookup(FakeWorkspace(1, 0), guess_budget=3).allowed
    assert not pb.guard_osint_lookup(FakeWorkspace(3, 0), guess_budget=3).allowed
    assert pb.guard_osint_lookup(FakeWorkspace(3, 2), guess_budget=3).allowed


def test_guess_budget_rejects_a_negative_count():
    with pytest.raises(pb.PlaybookError):
        pb.check_guess_budget(-1, guess_budget=3)


# ------------------------------------------------------------------ the CLI

def _cli(monkeypatch, tmp_path, *argv):
    import argparse
    from ctf.cli import osint as cli_osint
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setenv("CTF_EVENT", "csctf")
    p = argparse.ArgumentParser()
    cli_osint.add_arguments(p)
    return cli_osint.run(p.parse_args(list(argv)))


def test_cli_status_and_handoff(monkeypatch, tmp_path, capsys):
    rc = _cli(monkeypatch, tmp_path, "status", "viz", "--token-cap", "1000", "--time-box", "600")
    assert rc == 0 and "box=ok" in capsys.readouterr().out
    rc = _cli(monkeypatch, tmp_path, "handoff", "viz", "--reason", "time_box",
              "--source", "venue tag", "--note", "stuck")
    out = capsys.readouterr().out
    assert rc == 0 and "handoff written" in out
    assert budget.is_stopped("viz", workdir=tmp_path) == "manual"
    files = list((tmp_path / "osint-handoff").glob("viz-*.json"))
    assert len(files) == 1


def test_cli_guess_budget_exits_three_when_spent(monkeypatch, tmp_path, capsys):
    rc = _cli(monkeypatch, tmp_path, "guess-budget", "--wrong-count", "3", "--guess-budget", "3")
    assert rc == 3 and "BLOCKED" in capsys.readouterr().out
    rc = _cli(monkeypatch, tmp_path, "guess-budget", "--wrong-count", "1", "--guess-budget", "3")
    assert rc == 0 and "ALLOWED" in capsys.readouterr().out
