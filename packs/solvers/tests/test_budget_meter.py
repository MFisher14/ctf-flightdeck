"""B-033: LedgerMeter (per-challenge budget gates), the team-solve hook and the no-progress timer."""
from __future__ import annotations

import json
import multiprocessing as mp
import time
import types

import pytest

from ctf import budget, ledger
from ctf.event import Budget


class Clock:
    """Real time plus a movable offset (ledger records carry real timestamps)."""

    def __init__(self):
        self.offset = 0.0

    def __call__(self):
        return time.time() + self.offset

    def advance(self, seconds):
        self.offset += seconds


@pytest.fixture
def clock(monkeypatch):
    """One fake time source for the meter and for the ledger's record timestamps."""
    c = Clock()
    monkeypatch.setattr(ledger, "time", types.SimpleNamespace(time=c))
    return c


def meter(tmp_path, b=None, **kw):
    calls = []
    m = budget.LedgerMeter(b or Budget(), workdir=tmp_path, on_cap=lambda st, p: calls.append((st, p)), **kw)
    return m, calls


def events(tmp_path, kind):
    return [r for r in ledger.read(tmp_path) if r["event"] == kind]


# ------------------------------------------------------------------ spend and caps

def test_is_a_meter_and_accumulates_spend(tmp_path):
    m, _ = meter(tmp_path)
    assert isinstance(m, budget.Meter)
    m.add_spend("7", 1.25, 1000)
    m.add_spend("7", 0.75, 500)
    m.add_spend("8", 2.0, 10)
    assert m.spent("7") == budget.Spend(2.0, 1500)
    assert m.spent("8") == budget.Spend(2.0, 10)
    assert m.spent("nope") == budget.Spend()
    recs = events(tmp_path, "spend")
    assert [r["tok"] for r in recs] == [1000, 500, 10]


def test_spend_is_shared_through_the_ledger(tmp_path):
    a, _ = meter(tmp_path)
    b, _ = meter(tmp_path)
    a.add_spend("7", 3.0, 30)
    assert b.spent("7").usd == 3.0          # another process/instance sees it
    b.add_spend("7", 1.0, 10)
    assert a.spent("7") == budget.Spend(4.0, 40)   # a's incremental reader picks up b's line


def test_partial_trailing_line_waits_for_its_newline(tmp_path):
    m, _ = meter(tmp_path)
    m.add_spend("7", 1.0, 1)
    p = ledger.path(tmp_path)
    line = json.dumps({"ts": time.time(), "event": "spend", "challenge_id": "7", "usd": 5.0, "tok": 5})
    with open(p, "a") as fh:
        fh.write(line[:20])
    assert m.spent("7").usd == 1.0
    with open(p, "a") as fh:
        fh.write(line[20:] + "\n")
    assert m.spent("7").usd == 6.0


@pytest.mark.parametrize("usd, tokens", [(-1, 0), (float("nan"), 0), (True, 0), (1.0, -1), (1.0, 2.5), (1.0, True)])
def test_add_spend_rejects_bad_values(tmp_path, usd, tokens):
    m, _ = meter(tmp_path)
    with pytest.raises(ValueError):
        m.add_spend("7", usd, tokens)
    assert not ledger.path(tmp_path).exists()


def test_empty_challenge_id_is_refused(tmp_path):
    m, _ = meter(tmp_path)
    with pytest.raises(ValueError, match="challenge_id"):
        m.add_spend("", 1.0, 1)


@pytest.mark.parametrize("points, cap", [(None, 25.0), (10, 25.0), (200, 100.0), (560, 250.0)])
def test_cap_follows_points(tmp_path, points, cap):
    m, _ = meter(tmp_path)
    if points is not None:
        m.register("7", points=points)
    assert m.cap("7") == cap


def test_points_from_mapping_or_callable_and_register_wins(tmp_path):
    m, _ = meter(tmp_path, points={"7": 120})
    assert m.cap("7") == 60.0
    m.register("7", points=300)
    assert m.cap("7") == 150.0
    m2, _ = meter(tmp_path / "other", points=lambda cid: 80 if cid == "9" else None)
    assert m2.cap("9") == 40.0 and m2.cap("10") == 25.0


def test_profile_budget_values_are_used(tmp_path):
    m, _ = meter(tmp_path, Budget(per_point=1.0, floor=10.0, ceiling=40.0))
    m.register("a", points=5)
    m.register("b", points=30)
    m.register("c", points=500)
    assert (m.cap("a"), m.cap("b"), m.cap("c")) == (10.0, 30.0, 40.0)


def test_per_challenge_day_cap_grows_with_days_open(tmp_path, clock):
    m, _ = meter(tmp_path, Budget(per_challenge_day=50.0), clock=clock)
    m.register("d1", opened_at=time.time() - 2.5 * 86400)
    assert m.cap("d1") == 150.0                       # 3 challenge-days
    m.register("d2", opened_at=time.time() - 60)
    assert m.cap("d2") == 50.0
    clock.advance(9 * 86400)
    assert m.cap("d2") == 250.0                       # ceiling
    m.add_spend("d3", 1.0, 1)                         # never registered: open since first seen
    assert m.cap("d3") == 50.0
    clock.advance(1.5 * 86400)
    assert m.cap("d3") == 100.0
    m3, _ = meter(tmp_path / "x", Budget(per_challenge_day=50.0))
    m3.add_spend("n", 1.0, 1)
    assert m3.cap("n") == 50.0


def test_register_validates(tmp_path):
    m, _ = meter(tmp_path)
    with pytest.raises(ValueError):
        m.register("7", points=-3)
    with pytest.raises(ValueError, match="not a time"):
        m.register("7", opened_at="yesterday")
    rec = m.register("7", opened_at="2026-11-06T13:00:00Z")
    assert rec["opened_at"] == 1793970000.0


# ------------------------------------------------------------------ the cap gate

def test_reaching_the_cap_checkpoints_once_and_raises(tmp_path):
    m, calls = meter(tmp_path)                        # floor cap $25
    m.add_spend("7", 20.0, 100)
    assert m.check("7").state == "ok"
    with pytest.raises(budget.BudgetExceeded) as ei:
        m.add_spend("7", 6.0, 10)
    assert (ei.value.spent_usd, ei.value.cap_usd) == (26.0, 25.0)
    assert m.spent("7").usd == 26.0                   # the spend that crossed is still recorded
    cps = events(tmp_path, "budget_checkpoint")
    assert len(cps) == 1 and cps[0]["cap_usd"] == 25.0
    doc = json.loads(open(cps[0]["path"]).read())
    assert doc["status"]["state"] == "at_cap" and doc["status"]["spent_usd"] == 26.0
    assert "ctf budget extend 7" in doc["ask"]
    assert [r["event"] for r in doc["recent_events"]] == ["spend", "spend"]
    assert len(calls) == 1 and calls[0][0].challenge_id == "7"
    # more spend or a check: still refused, no second checkpoint, no second ask
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("7", 1.0, 1)
    with pytest.raises(budget.BudgetExceeded):
        m.check("7")
    assert len(events(tmp_path, "budget_checkpoint")) == 1 and len(calls) == 1


def test_exactly_at_cap_is_at_cap(tmp_path):
    m, _ = meter(tmp_path)
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("7", 25.0, 1)


def test_cap_is_never_extended_without_extend(tmp_path):
    m, _ = meter(tmp_path)
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("7", 30.0, 1)
    for _ in range(3):
        with pytest.raises(budget.BudgetExceeded):
            m.check("7")
    assert m.cap("7") == 25.0
    assert events(tmp_path, "budget_extend") == []


def test_extend_raises_the_cap_and_a_new_cap_checkpoints_again(tmp_path):
    m, calls = meter(tmp_path)
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("7", 30.0, 1)
    new = m.extend("7", 20.0, by="max", reason="close on the second stage")
    assert new == 45.0 and m.cap("7") == 45.0
    assert m.check("7").state == "ok"
    ext = events(tmp_path, "budget_extend")
    assert ext[0]["by"] == "max" and ext[0]["usd"] == 20.0 and ext[0]["cap_usd"] == 45.0
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("7", 15.0, 1)
    assert [c["cap_usd"] for c in events(tmp_path, "budget_checkpoint")] == [25.0, 45.0]
    assert len(calls) == 2
    st = m.status("7")
    assert (st.base_cap_usd, st.extended_usd, st.cap_usd) == (25.0, 20.0, 45.0)


@pytest.mark.parametrize("usd, by, reason", [(0, "max", "r"), (-5, "max", "r"), (5, "", "r"), (5, "max", " ")])
def test_extend_needs_amount_person_and_reason(tmp_path, usd, by, reason):
    m, _ = meter(tmp_path)
    with pytest.raises(ValueError):
        m.extend("7", usd, by=by, reason=reason)
    assert events(tmp_path, "budget_extend") == []


def test_default_on_cap_tells_the_player_how_to_extend(tmp_path, capsys):
    m = budget.LedgerMeter(Budget(), workdir=tmp_path)
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("7", 25.0, 1)
    err = capsys.readouterr().err
    assert "BUDGET:" in err and "python -m ctf budget extend 7 --usd" in err


def test_meter_from_profile_uses_profile_budget_and_workdir(tmp_path, monkeypatch):
    from ctf import event
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    m = budget.LedgerMeter(event.load("huntress"))
    assert m.budget.per_challenge_day == 50.0 and m.workdir == tmp_path.resolve()
    with pytest.raises(TypeError):
        budget.LedgerMeter({"per_point": 1}, workdir=tmp_path)


def _spender(wd, n):
    m = budget.LedgerMeter(Budget(floor=1000.0, ceiling=1000.0), workdir=wd)
    for _ in range(n):
        m.add_spend("7", 0.25, 3)


def test_concurrent_spenders_total_exactly(tmp_path):
    ctx = mp.get_context("spawn")
    procs = [ctx.Process(target=_spender, args=(tmp_path, 25)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(60)
        assert p.exitcode == 0
    m, _ = meter(tmp_path)
    assert m.spent("7") == budget.Spend(25.0, 300)


# ------------------------------------------------------------------ stop signals

def test_team_solve_hook_stops_once_and_is_final(tmp_path):
    m, _ = meter(tmp_path)
    m.add_spend("7", 1.0, 1)
    assert budget.on_team_solve("7", solver="teammate", workdir=tmp_path) is True
    assert budget.on_team_solve("7", solver="teammate", workdir=tmp_path) is False
    assert len(events(tmp_path, "stop")) == 1
    with pytest.raises(budget.ChallengeStopped) as ei:
        m.check("7")
    assert ei.value.reason == "team_solve"
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"
    assert budget.is_stopped("8", workdir=tmp_path) is None
    assert m.stop("7", "manual") is False            # a solve is not downgraded
    with pytest.raises(ValueError, match="final"):
        m.resume("7", by="max")
    assert m.status("7").stop_reason == "team_solve" and m.status("7").stop_by == "teammate"


def test_team_solve_overrides_an_earlier_manual_stop(tmp_path):
    m, _ = meter(tmp_path)
    m.stop("7", "manual", by="max")
    assert budget.on_team_solve("7", workdir=tmp_path) is True
    assert m.status("7").stop_reason == "team_solve"
    assert budget.is_stopped("7", workdir=tmp_path) == "team_solve"


# The reader-side half of team-solve finality (LedgerMeter._apply's "stop" branch: a later stop record that
# reached the ledger behind stop()'s back never replaces a team solve) is tested in
# tests/test_phase0_mutation_survivors.py (R-07), not here. stop() refuses to write that record, so the
# tests above never reach the guard with a team solve already recorded; a mutation run scoped to this file
# alone will report it as a survivor.


def test_team_solve_hook_defaults_to_the_workdir(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    assert budget.on_team_solve("42") is True
    assert events(tmp_path, "stop")[0]["challenge_id"] == "42"


def test_manual_stop_and_resume(tmp_path):
    m, _ = meter(tmp_path)
    assert m.stop("7", "manual", by="max", note="pivot") is True
    assert m.stop("7", "manual") is False
    with pytest.raises(budget.ChallengeStopped):
        m.check("7")
    with pytest.raises(ValueError):
        m.resume("7", by="")
    m.resume("7", by="max")
    assert m.check("7").state == "ok"
    assert budget.is_stopped("7", workdir=tmp_path) is None
    with pytest.raises(ValueError, match="not stopped"):
        m.resume("7", by="max")
    with pytest.raises(ValueError, match="stop reason"):
        m.stop("7", "bored")


def test_no_progress_timer_on_a_high_value_tail(tmp_path, clock):
    m, _ = meter(tmp_path, clock=clock)
    m.register("hv", points=600)                      # 600 * 0.5 >= ceiling: the value cap does not bite
    assert m.status("hv").timer_applies
    clock.advance(15 * 60)
    m.mark_progress("hv", "found the second layer")   # resets the clock (real ts ~ now)
    clock.advance(19 * 60)
    assert m.check("hv").state == "ok"
    m.add_spend("hv", 1.0, 1)                         # spend alone is not progress
    clock.advance(2 * 60)
    with pytest.raises(budget.ChallengeStopped) as ei:
        m.check("hv")
    assert ei.value.reason == "no_progress"
    stops = events(tmp_path, "stop")
    assert len(stops) == 1 and stops[0]["reason"] == "no_progress"
    with pytest.raises(budget.ChallengeStopped):
        m.check("hv")
    assert len(events(tmp_path, "stop")) == 1          # recorded once
    m.resume("hv", by="max")                          # a resume restarts the clock
    assert m.check("hv").state == "ok"


def test_no_progress_timer_skips_low_value_and_obeys_tail_flag(tmp_path, clock):
    m, _ = meter(tmp_path, clock=clock)
    m.register("low", points=100)
    m.register("forced", points=100, tail=True)
    m.register("unknown")
    clock.advance(3600)
    assert m.check("low").state == "ok"
    assert m.check("unknown").state == "ok"
    with pytest.raises(budget.ChallengeStopped):
        m.check("forced")


def test_no_progress_timer_under_per_day_budget_needs_the_tail_flag(tmp_path, clock):
    m, _ = meter(tmp_path, Budget(per_challenge_day=50.0), clock=clock)
    m.register("a", points=5000)
    m.register("b", tail=True)
    clock.advance(25 * 60)
    assert m.check("a").state == "ok"
    with pytest.raises(budget.ChallengeStopped):
        m.check("b")


def test_no_progress_minutes_are_configurable(tmp_path, clock):
    m, _ = meter(tmp_path, clock=clock, no_progress_seconds=60, high_value_points=50)
    m.register("x", points=50)
    clock.advance(61)
    with pytest.raises(budget.ChallengeStopped):
        m.check("x")


def test_stop_is_checked_before_the_cap(tmp_path):
    m, _ = meter(tmp_path)
    with pytest.raises(budget.BudgetExceeded):
        m.add_spend("7", 30.0, 1)
    budget.on_team_solve("7", workdir=tmp_path)
    with pytest.raises(budget.ChallengeStopped):
        m.check("7")


def test_challenges_lists_every_challenge_seen(tmp_path):
    m, _ = meter(tmp_path)
    m.add_spend("b", 1.0, 1)
    m.register("a", points=1)
    ledger.append("detect", workdir=tmp_path, note="no challenge")
    assert m.challenges() == ["a", "b"]


def test_truncated_ledger_is_reread(tmp_path):
    m, _ = meter(tmp_path)
    m.add_spend("7", 5.0, 5)
    assert m.spent("7").usd == 5.0
    ledger.path(tmp_path).unlink()
    ledger.append("spend", workdir=tmp_path, challenge_id="7", usd=1.0, tok=1)
    assert m.spent("7") == budget.Spend(1.0, 1)
