"""B-016: escalation timers and reroutes in the dispatcher (ctf/escalation.py, ctf/cli/escalate.py).

Offline. Ledger records and dispatch claims are written to a temp workdir with chosen timestamps; the
escalator reads them and writes `escalation` records with no model and no platform call. Nothing is
launched. A controlled clock makes every timer and the 30 s reroute budget exact.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

from ctf import cli, escalation, event, ledger, paths, stages
from ctf.cli import escalate as cli_escalate

ROSTER = ["glm-5.3", "gpt-6-sol"]          # extend the csctf default [opus-5-5, opus-4-8]


@pytest.fixture
def prof():
    return event.load("csctf")


def write_ledger(workdir, event_type, *, ts, **fields):
    """Append one raw ledger line with a chosen ts (ledger.append forbids setting ts)."""
    rec = {"ts": float(ts), "event": event_type, **fields}
    p = ledger.path(workdir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")
    return rec


def claims(dispatched_at, *cids):
    rec = {cid: {"challenge_id": cid, "dispatched_at": dispatched_at} for cid in cids}
    return lambda _wd: (rec, [])


def esc(prof, workdir, *, now, roster=ROSTER, read_claims=None, **kw):
    return escalation.Escalator(prof, workdir=workdir, roster=roster, clock=lambda: now,
                                read_claims=read_claims, **kw)


# ----------------------------------------------------------------------------------- detect_stop

def test_detect_stop_reads_a_claude_refusal():
    line = json.dumps({"type": "assistant", "message": {"stop_reason": "refusal", "role": "assistant"}})
    assert escalation.detect_stop(line) == ("refusal", "stop_reason: refusal")


def test_detect_stop_reads_a_codex_turn_failure_as_a_provider_error():
    line = json.dumps({"type": "turn.failed", "error": {"message": "the model is unavailable"}})
    reason, detail = escalation.detect_stop(line)
    assert reason == "provider_error" and "unavailable" in detail


def test_detect_stop_reads_a_claude_result_error():
    line = json.dumps({"type": "result", "is_error": True, "subtype": "error_during_execution"})
    assert escalation.detect_stop(line)[0] == "provider_error"


def test_detect_stop_ignores_a_normal_stop_and_non_json():
    assert escalation.detect_stop(json.dumps({"type": "assistant",
                                              "message": {"stop_reason": "end_turn"}})) is None
    assert escalation.detect_stop("the agent printed stop_reason: refusal as prose") is None
    assert escalation.detect_stop(json.dumps({"type": "result", "is_error": False})) is None


# ----------------------------------------------------------------------------------- record_agent_stop

def test_record_agent_stop_writes_an_agent_stop_record(tmp_path):
    escalation.record_agent_stop("provider_error", "9", harness="codex", workdir=tmp_path,
                                 detail="Daybreak is unavailable for model gpt-6-astra")
    recs = [r for r in ledger.read(tmp_path) if r["event"] == "agent_stop"]
    assert len(recs) == 1
    assert recs[0]["challenge_id"] == "9" and recs[0]["reason"] == "provider_error"
    assert recs[0]["harness"] == "codex" and "Daybreak" in recs[0]["detail"]


def test_record_agent_stop_refuses_an_unknown_reason(tmp_path):
    with pytest.raises(escalation.EscalationError):
        escalation.record_agent_stop("bored", "9", harness="codex", workdir=tmp_path)


def test_record_agent_stop_refuses_an_empty_challenge(tmp_path):
    with pytest.raises(escalation.EscalationError):
        escalation.record_agent_stop("refusal", "  ", harness="claude", workdir=tmp_path)


# ----------------------------------------------------------------------------------- the second timer

def test_second_agent_fires_on_the_timer_onto_a_different_model(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    e = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S)
    made = e.once()
    assert len(made) == 1
    d = made[0]
    assert d.action == "second" and d.trigger == "timer" and d.status == "dispatched"
    assert d.from_model == prof.models.primary and d.to_model != prof.models.primary
    assert d.to_model == prof.models.fallback[0]     # next in roster after the owner


def test_second_agent_does_not_fire_before_the_timer(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    assert esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S - 1).once() == []


def test_second_agent_fires_at_once_on_a_rejected_flag(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1030.0, challenge_id="9", status="incorrect")
    made = esc(prof, tmp_path, now=1035.0).once()       # only 35 s in, well before SECOND_S
    assert len(made) == 1 and made[0].action == "second" and made[0].trigger == "rejected_flag"


def test_a_rejected_stage_event_also_triggers_the_second(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "rejected", ts=1020.0, challenge_id="9", status="incorrect")
    made = esc(prof, tmp_path, now=1025.0).once()
    assert made and made[0].trigger == "rejected_flag"


# ----------------------------------------------------------------------------------- the third timer

def test_third_agent_fires_at_the_third_timer_onto_a_third_model(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    made = esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S).once()
    by_action = {d.action: d for d in made}
    assert set(by_action) == {"second", "third"}
    models = {by_action["second"].to_model, by_action["third"].to_model, prof.models.primary}
    assert len(models) == 3           # owner, second, third are three distinct models


# ----------------------------------------------------------------------------------- reroutes

def test_a_refusal_is_rerouted_within_the_budget(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "agent_stop", ts=1010.0, challenge_id="9", harness="claude", reason="refusal")
    made = esc(prof, tmp_path, now=1013.0).once()
    reroutes = [d for d in made if d.action == "reroute"]
    assert len(reroutes) == 1
    r = reroutes[0]
    assert r.trigger == "refusal" and r.to_model != prof.models.primary
    assert r.elapsed_s <= escalation.REROUTE_BUDGET_S and r.for_stop_ts == 1010.0


def test_a_provider_error_is_rerouted(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="codex")
    write_ledger(tmp_path, "agent_stop", ts=1005.0, challenge_id="9", harness="codex",
                 reason="provider_error", detail="Daybreak is unavailable")
    made = esc(prof, tmp_path, now=1006.0).once()
    reroutes = [d for d in made if d.action == "reroute"]
    assert len(reroutes) == 1 and reroutes[0].trigger == "provider_error"


def test_a_reroute_is_written_once_per_stop(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "agent_stop", ts=1010.0, challenge_id="9", harness="claude", reason="refusal")
    assert len([d for d in esc(prof, tmp_path, now=1013.0).once() if d.action == "reroute"]) == 1
    # a second escalator over the same ledger (which now holds the escalation record) does not repeat it
    assert [d for d in esc(prof, tmp_path, now=1020.0).once() if d.action == "reroute"] == []


# ----------------------------------------------------------------------------------- resolution

def test_a_solved_challenge_does_not_escalate(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9", status="correct")
    assert esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S).once() == []


def test_a_stopped_challenge_does_not_escalate(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "stop", ts=1050.0, challenge_id="9", reason="team_solve")
    assert esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S).once() == []


# ----------------------------------------------------------------------------------- idempotence

def test_two_passes_do_not_double_emit_the_second(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    e1 = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S)
    assert len(e1.once()) == 1
    e2 = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S + 60)
    assert [d for d in e2.once() if d.action == "second"] == []


# ----------------------------------------------------------------------------------- claims as t0

def test_the_claim_dispatch_time_is_the_timer_origin_without_an_agent_launch(tmp_path, prof):
    e = esc(prof, tmp_path, now=2000.0 + escalation.SECOND_S, read_claims=claims(2000.0, "9"))
    made = e.once()
    assert len(made) == 1 and made[0].action == "second"
    assert made[0].elapsed_s == pytest.approx(escalation.SECOND_S)


def test_a_claim_ledger_event_alone_makes_the_challenge_owned(tmp_path, prof):
    write_ledger(tmp_path, "claim", ts=1500.0, challenge_id="9", lane="web", seq=1, source="dispatch")
    made = esc(prof, tmp_path, now=1500.0 + escalation.SECOND_S, read_claims=lambda _wd: ({}, [])).once()
    assert len(made) == 1 and made[0].action == "second"


def test_a_challenge_with_no_claim_and_no_agent_is_not_escalated(tmp_path, prof):
    write_ledger(tmp_path, "detect", ts=1000.0, challenge_id="9", wave="W1")
    # a detect alone (no claim, no agent_launch) is not an owned challenge
    assert esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S, read_claims=lambda _wd: ({}, [])).once() == []


# ----------------------------------------------------------------------------------- no silent fallback

def test_no_unused_model_is_a_loud_no_model_decision_not_a_reuse(tmp_path, prof):
    # The default roster is [primary, fallback] (two models). The owner is primary; a prior second
    # already took the fallback. By the third timer there is no unused model, so the third must be a
    # loud no_model decision, never a reuse of primary or fallback.
    problems = []
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "escalation", ts=1001.0, challenge_id="9", action="second", trigger="timer",
                 to_model=prof.models.fallback[0], from_model=prof.models.primary, elapsed_s=180.0,
                 status="dispatched")
    e = escalation.Escalator(prof, workdir=tmp_path, roster=None,
                             clock=lambda: 1000.0 + escalation.THIRD_S, on_problem=problems.append)
    thirds = [d for d in e.once() if d.action == "third"]
    assert len(thirds) == 1 and thirds[0].status == "no_model" and thirds[0].to_model == ""
    assert any("no model" in p.lower() for p in problems)


# ----------------------------------------------------------------------------------- stream tap wiring

def test_the_stream_tap_records_an_agent_stop_from_a_refusal():
    calls = []

    class _Inner:
        def feed(self, line):
            return []

    tap = stages.AgentStreamTap(_Inner(), lambda ev, **f: calls.append((ev, f)),
                                harness="claude", flags=None)
    tap.feed(json.dumps({"type": "assistant", "message": {"stop_reason": "refusal"}}))
    tap.feed(json.dumps({"type": "assistant", "message": {"stop_reason": "end_turn"}}))
    stops = [c for c in calls if c[0] == "agent_stop"]
    assert len(stops) == 1 and stops[0][1]["reason"] == "refusal"
    assert tap.stops_seen == 1


# ----------------------------------------------------------------------------------- CLI

def _run_cli(argv, monkeypatch, tmp_path):
    monkeypatch.setenv("CTF_EVENT", "csctf")
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    return cli.main(argv)


def test_cli_once_writes_escalations_and_show_prints_them(tmp_path, prof, monkeypatch, capsys):
    write_ledger(tmp_path, "agent_launch", ts=time.time() - escalation.SECOND_S - 5,
                 challenge_id="9", harness="claude")
    rc = _run_cli(["escalate", "once", "--model", "glm-5.3"], monkeypatch, tmp_path)
    out = capsys.readouterr().out
    assert rc == 0 and "escalate 9: second" in out
    recs = [r for r in ledger.read(tmp_path) if r["event"] == "escalation"]
    assert recs and recs[0]["action"] == "second"
    rc = _run_cli(["escalate", "show", "9"], monkeypatch, tmp_path)
    shown = json.loads(capsys.readouterr().out)
    assert rc == 0 and shown["challenge_id"] == "9" and shown["escalations"]


def test_cli_stop_records_an_agent_stop(tmp_path, prof, monkeypatch, capsys):
    rc = _run_cli(["escalate", "stop", "--challenge", "9", "--reason", "provider_error",
                   "--harness", "codex", "--detail", "Daybreak is unavailable"], monkeypatch, tmp_path)
    assert rc == 0
    recs = [r for r in ledger.read(tmp_path) if r["event"] == "agent_stop"]
    assert len(recs) == 1 and recs[0]["reason"] == "provider_error"


def test_cli_exits_1_when_a_decision_had_no_model(tmp_path, prof, monkeypatch, capsys):
    t0 = time.time() - escalation.THIRD_S - 5
    write_ledger(tmp_path, "agent_launch", ts=t0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "escalation", ts=t0 + 1, challenge_id="9", action="second", trigger="timer",
                 to_model=prof.models.fallback[0], from_model=prof.models.primary, elapsed_s=180.0,
                 status="dispatched")
    rc = _run_cli(["escalate", "once"], monkeypatch, tmp_path)   # default roster [primary, fallback] exhausted
    err = capsys.readouterr().err
    assert rc == 1 and "no model" in err.lower()


# =================================================================================== round 1 fixes

# ----------------------------------------------------------------------------------- terminal signals only

def test_detect_stop_ignores_a_bare_codex_error_notice():
    # A Codex `error` event is a notice (e.g. a reconnect) the run may recover from: not a stop.
    assert escalation.detect_stop(json.dumps({"type": "error", "message": "Reconnecting... 1/5"})) is None


def test_detect_stop_reads_is_error_alone_with_a_non_error_subtype():
    # Claude reports an API failure as subtype "success" with is_error true: only is_error says so.
    line = json.dumps({"type": "result", "subtype": "success", "is_error": True})
    assert escalation.detect_stop(line) == ("provider_error", "result is_error")


@pytest.mark.parametrize("subtype", ["error_max_turns", "error_max_budget_usd"])
def test_detect_stop_does_not_count_a_self_imposed_limit_as_a_provider_error(subtype):
    line = json.dumps({"type": "result", "subtype": subtype, "is_error": True})
    assert escalation.detect_stop(line) is None


def test_detect_stop_reads_a_claude_error_subtype_without_is_error():
    line = json.dumps({"type": "result", "subtype": "error_during_execution"})
    assert escalation.detect_stop(line) == ("provider_error", "error_during_execution")


class _NoUsage:
    def __init__(self, model=None):
        if model is not None:
            self.model = model

    def feed(self, line):
        return []


def _tap(calls, *, harness="codex", inner=None, model=None):
    return stages.AgentStreamTap(inner or _NoUsage(), lambda ev, **f: calls.append((ev, f)),
                                 harness=harness, flags=None, model=model)


def test_the_stream_tap_records_one_agent_stop_per_dying_run():
    calls = []
    tap = _tap(calls, inner=_NoUsage("gpt-6.1-terra"))
    tap.feed(json.dumps({"type": "error", "message": "stream disconnected"}))
    tap.feed(json.dumps({"type": "error", "message": "Daybreak is unavailable for model gpt-6.1-terra"}))
    tap.feed(json.dumps({"type": "turn.failed", "error": {"message": "Daybreak is unavailable"}}))
    tap.feed(json.dumps({"type": "turn.failed", "error": {"message": "again"}}))
    stops = [f for ev, f in calls if ev == "agent_stop"]
    assert len(stops) == 1 and tap.stops_seen == 1
    assert stops[0]["reason"] == "provider_error" and "Daybreak" in stops[0]["detail"]
    assert stops[0]["model"] == "gpt-6.1-terra"          # the codex usage reader's model


def test_the_stream_tap_records_no_stop_for_a_recovered_error_notice():
    calls = []
    tap = _tap(calls)
    tap.feed(json.dumps({"type": "error", "message": "Reconnecting... 1/5"}))
    tap.feed(json.dumps({"type": "turn.completed", "usage": {}}))
    assert [c for c in calls if c[0] == "agent_stop"] == [] and tap.stops_seen == 0


def test_the_stream_tap_learns_the_claude_model_from_the_stream():
    calls = []
    tap = _tap(calls, harness="claude")
    tap.feed(json.dumps({"type": "system", "subtype": "init", "model": "claude-opus-4-8"}))
    tap.feed(json.dumps({"type": "assistant", "message": {"stop_reason": "refusal", "model": "other"}}))
    stops = [f for ev, f in calls if ev == "agent_stop"]
    assert len(stops) == 1 and stops[0]["model"] == "claude-opus-4-8"


def test_one_dying_run_with_several_stop_records_gets_one_reroute(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="codex", model="gpt-x")
    for ts in (1005.0, 1005.5, 1006.0):           # e.g. legacy per-line records of one Codex death
        write_ledger(tmp_path, "agent_stop", ts=ts, challenge_id="9", harness="codex",
                     reason="provider_error", model="gpt-x")
    made = esc(prof, tmp_path, now=1007.0).once()
    reroutes = [d for d in made if d.action == "reroute"]
    assert len(reroutes) == 1 and reroutes[0].for_stop_ts == 1005.0
    assert reroutes[0].from_model == "gpt-x"
    # and the next pass does not reroute the same run again off a later record of it
    assert [d for d in esc(prof, tmp_path, now=1010.0).once() if d.action == "reroute"] == []


def test_two_runs_that_die_get_a_reroute_each(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="codex", model="gpt-x")
    write_ledger(tmp_path, "agent_stop", ts=1005.0, challenge_id="9", harness="codex",
                 reason="provider_error", model="gpt-x")
    write_ledger(tmp_path, "agent_launch", ts=1010.0, challenge_id="9", harness="codex", model="gpt-y")
    write_ledger(tmp_path, "agent_stop", ts=1012.0, challenge_id="9", harness="codex",
                 reason="provider_error", model="gpt-y")
    reroutes = [d for d in esc(prof, tmp_path, now=1013.0).once() if d.action == "reroute"]
    assert sorted(d.from_model for d in reroutes) == ["gpt-x", "gpt-y"]
    assert len({d.to_model for d in reroutes}) == 2      # never the same model twice


def test_metered_launch_records_the_model_and_one_stop_and_gets_one_reroute(tmp_path, prof, monkeypatch):
    """End to end through tools/launch_gate.supervise: a stub agent (python -c, not a challenge binary)
    prints two Codex `error` notices and a `turn.failed`, as one dying Codex run does."""
    import io
    import sys

    from ctf import budget
    from ctf.event import Budget
    from tools import launch_gate

    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    lines = [{"type": "error", "message": "Reconnecting... 1/5"},
             {"type": "error", "message": "Daybreak is unavailable for model gpt-6.1-terra"},
             {"type": "turn.failed", "error": {"message": "Daybreak is unavailable for model gpt-6.1-terra"}}]
    script = "import json\n" + "".join(f"print(json.dumps({ln!r}), flush=True)\n" for ln in lines)
    meter = budget.LedgerMeter(Budget(per_point=0.5, floor=25.0, ceiling=250.0), workdir=tmp_path)
    gate = launch_gate.Gate(meter, "9", harness="codex")
    usage = launch_gate.CodexJsonUsage("gpt-6.1-terra")
    rc = launch_gate.supervise([sys.executable, "-I", "-c", script], gate, cwd=tmp_path, usage=usage,
                               poll_seconds=0.2, stdout=io.StringIO(), stderr=io.StringIO())
    assert rc == 0
    launches = [r for r in ledger.read(tmp_path) if r["event"] == "agent_launch"]
    assert [r.get("model") for r in launches] == ["gpt-6.1-terra"]
    stops = [r for r in ledger.read(tmp_path) if r["event"] == "agent_stop"]
    assert len(stops) == 1 and stops[0]["model"] == "gpt-6.1-terra" and stops[0]["challenge_id"] == "9"
    made = esc(prof, tmp_path, now=stops[0]["ts"] + 1).once()
    reroutes = [d for d in made if d.action == "reroute"]
    assert len(reroutes) == 1 and reroutes[0].from_model == "gpt-6.1-terra"
    assert reroutes[0].to_model == prof.models.primary   # the owner ran codex, so the primary is free


# ----------------------------------------------------------------------------------- multi-answer ids

def test_a_rejected_part_triggers_the_parents_second(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1030.0, challenge_id="9#a", status="incorrect")
    made = esc(prof, tmp_path, now=1035.0).once()
    assert [(d.challenge_id, d.action, d.trigger) for d in made] == [("9", "second", "rejected_flag")]


def test_a_correct_part_does_not_resolve_the_parent_but_the_bare_id_does(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9#a", status="correct")
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S, record=False).once()
    assert [d.action for d in made] == ["second"]          # part b may still be open
    assert escalation.read_states(tmp_path)["9"].solved_parts == {"9#a"}
    write_ledger(tmp_path, "platform.submit", ts=1060.0, challenge_id="9", status="correct")
    assert esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once() == []


def test_a_launch_on_a_part_owns_the_parent(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9#b", harness="claude")
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S, read_claims=lambda _wd: ({}, [])).once()
    assert [(d.challenge_id, d.action) for d in made] == [("9", "second")]


# ----------------------------------------------------------------------------------- resolution / idempotence

def test_an_accepted_stage_resolves_the_challenge(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "accepted", ts=1050.0, challenge_id="9", status="correct")
    assert esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S).once() == []


def test_the_third_is_written_only_once(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    first = esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S).once()
    assert sorted(d.action for d in first) == ["second", "third"]
    assert esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S + 60).once() == []
    assert len([r for r in ledger.read(tmp_path) if r["event"] == "escalation"
                and r["action"] == "third"]) == 1


# ----------------------------------------------------------------------------------- the timer origin

def test_t0_is_the_earliest_launch_even_when_a_later_launch_is_read_first(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1100.0, challenge_id="9", harness="codex")
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    assert escalation.read_states(tmp_path)["9"].t0 == 1000.0
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once()
    assert [d.action for d in made] == ["second"]


def test_t0_is_the_claim_dispatch_time_when_the_agent_launches_later(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1100.0, challenge_id="9", harness="claude")
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S, read_claims=claims(1000.0, "9")).once()
    assert [d.action for d in made] == ["second"]
    assert made[0].elapsed_s == pytest.approx(escalation.SECOND_S)


def test_t0_takes_the_earliest_of_two_claims_on_one_challenge(tmp_path, prof):
    two = {"9#a": {"challenge_id": "9#a", "dispatched_at": 1100.0},
           "9#b": {"challenge_id": "9#b", "dispatched_at": 1000.0}}
    states = escalation.read_states(tmp_path, claims=two)
    assert states["9"].t0 == 1000.0


def test_t0_takes_a_claim_event_earlier_than_a_launch_read_before_it(tmp_path, prof):
    write_ledger(tmp_path, "detect", ts=900.0, challenge_id="9", wave="W1")
    write_ledger(tmp_path, "agent_launch", ts=1100.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "claim", ts=1000.0, challenge_id="9", lane="web", seq=1, source="dispatch")
    assert escalation.read_states(tmp_path)["9"].t0 == 1000.0   # a detect is only a fallback


def test_a_reroute_is_timed_from_the_stop_not_from_t0(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "agent_stop", ts=1100.0, challenge_id="9", harness="claude", reason="refusal")
    made = esc(prof, tmp_path, now=1110.0).once()
    r = [d for d in made if d.action == "reroute"][0]
    assert r.elapsed_s == pytest.approx(10.0) and r.elapsed_s <= escalation.REROUTE_BUDGET_S


# ----------------------------------------------------------------------------------- the owner model

def test_the_owner_is_the_launched_model_not_roster_0(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="codex", model="glm-5.3")
    d = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once()[0]
    assert d.action == "second" and d.from_model == "glm-5.3"
    assert d.to_model == prof.models.primary               # roster[0] is free: the owner ran glm


def test_a_reroute_moves_off_the_stopped_agents_model(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude",
                 model=prof.models.primary)
    write_ledger(tmp_path, "escalation", ts=1180.0, challenge_id="9", action="second", trigger="timer",
                 to_model="glm-5.3", from_model=prof.models.primary, elapsed_s=180.0, status="dispatched")
    write_ledger(tmp_path, "agent_launch", ts=1185.0, challenge_id="9", harness="codex", model="glm-5.3")
    write_ledger(tmp_path, "agent_stop", ts=1190.0, challenge_id="9", harness="codex",
                 reason="provider_error", model="glm-5.3")
    r = [d for d in esc(prof, tmp_path, now=1192.0).once() if d.action == "reroute"][0]
    assert r.from_model == "glm-5.3"
    assert r.to_model not in (prof.models.primary, "glm-5.3")


# ----------------------------------------------------------------------------------- no_model is retried

def _exhausted(tmp_path, prof, t0):
    write_ledger(tmp_path, "agent_launch", ts=t0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "escalation", ts=t0 + 1, challenge_id="9", action="second", trigger="timer",
                 to_model=prof.models.fallback[0], from_model=prof.models.primary, elapsed_s=180.0,
                 status="dispatched")


def test_a_no_model_third_is_not_rewritten_but_is_routed_once_the_roster_grows(tmp_path, prof):
    _exhausted(tmp_path, prof, 1000.0)
    now = 1000.0 + escalation.THIRD_S
    first = escalation.Escalator(prof, workdir=tmp_path, roster=None, clock=lambda: now).once()
    assert [(d.action, d.status) for d in first] == [("third", "no_model")]
    # the same roster again: nothing new written, but still reported loudly as unrouted
    problems = []
    again = escalation.Escalator(prof, workdir=tmp_path, roster=None, clock=lambda: now + 5,
                                 on_problem=problems.append)
    assert again.once() == []
    assert [d.action for d in again.unrouted] == ["third"]
    assert any("still has no model" in p for p in problems)
    thirds = [r for r in ledger.read(tmp_path) if r["event"] == "escalation" and r["action"] == "third"]
    assert len(thirds) == 1
    # a grown roster routes it
    grown = escalation.Escalator(prof, workdir=tmp_path, roster=["glm-5.3"], clock=lambda: now + 10).once()
    assert [(d.action, d.status, d.to_model) for d in grown] == [("third", "dispatched", "glm-5.3")]
    # and once dispatched it is done
    assert escalation.Escalator(prof, workdir=tmp_path, roster=["glm-5.3", "gpt-6-sol"],
                                clock=lambda: now + 20).once() == []


def test_a_no_model_second_is_retried_with_a_free_model(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "escalation", ts=1180.0, challenge_id="9", action="second", trigger="timer",
                 to_model="", from_model=prof.models.primary, elapsed_s=180.0, status="no_model",
                 detail="no unused model in roster")
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S + 30).once()
    seconds = [d for d in made if d.action == "second"]
    assert [(d.status, d.to_model) for d in seconds] == [("dispatched", prof.models.fallback[0])]


def test_a_manual_stop_naming_a_model_reroutes_off_that_model(tmp_path, prof):
    # the codex-handoff path: no agent_launch for the codex run, only `ctf escalate stop --model`
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude",
                 model=prof.models.primary)
    write_ledger(tmp_path, "agent_stop", ts=1100.0, challenge_id="9", harness="codex",
                 reason="provider_error", model="gpt-other")
    r = [d for d in esc(prof, tmp_path, now=1101.0).once() if d.action == "reroute"][0]
    assert r.from_model == "gpt-other" and r.to_model not in ("gpt-other", prof.models.primary)


def test_a_no_model_reroute_is_retried_with_a_free_model(tmp_path, prof):
    _exhausted(tmp_path, prof, 1000.0)
    write_ledger(tmp_path, "agent_stop", ts=1200.0, challenge_id="9", harness="claude", reason="refusal")
    first = escalation.Escalator(prof, workdir=tmp_path, roster=None, clock=lambda: 1201.0).once()
    assert [(d.action, d.status) for d in first] == [("reroute", "no_model")]
    grown = escalation.Escalator(prof, workdir=tmp_path, roster=["glm-5.3"], clock=lambda: 1202.0).once()
    assert [(d.action, d.status, d.for_stop_ts) for d in grown] == [("reroute", "dispatched", 1200.0)]


def test_cli_still_exits_1_while_an_earlier_no_model_is_unrouted(tmp_path, prof, monkeypatch, capsys):
    _exhausted(tmp_path, prof, time.time() - escalation.THIRD_S - 5)
    assert _run_cli(["escalate", "once"], monkeypatch, tmp_path) == 1
    capsys.readouterr()
    assert _run_cli(["escalate", "once"], monkeypatch, tmp_path) == 1
    assert "still has no model" in capsys.readouterr().err
    assert len([r for r in ledger.read(tmp_path) if r["event"] == "escalation"
                and r["action"] == "third"]) == 1


# ----------------------------------------------------------------------------------- CLI show / stop model

def test_cli_show_uses_the_model_roster(tmp_path, prof, monkeypatch, capsys):
    _exhausted(tmp_path, prof, time.time() - escalation.THIRD_S - 5)
    assert _run_cli(["escalate", "show", "9"], monkeypatch, tmp_path) == 0
    plain = json.loads(capsys.readouterr().out)
    assert [(d["action"], d["status"]) for d in plain["due_now"]] == [("third", "no_model")]
    assert _run_cli(["escalate", "show", "9", "--model", "glm-5.3"], monkeypatch, tmp_path) == 0
    grown = json.loads(capsys.readouterr().out)
    assert [(d["action"], d["status"], d["to_model"]) for d in grown["due_now"]] == \
        [("third", "dispatched", "glm-5.3")]
    # show writes nothing
    assert len([r for r in ledger.read(tmp_path) if r["event"] == "escalation"]) == 1


def test_cli_stop_records_the_model(tmp_path, prof, monkeypatch, capsys):
    assert _run_cli(["escalate", "stop", "--challenge", "9", "--reason", "refusal", "--harness", "claude",
                     "--model", "claude-opus-4-8"], monkeypatch, tmp_path) == 0
    recs = [r for r in ledger.read(tmp_path) if r["event"] == "agent_stop"]
    assert [r.get("model") for r in recs] == ["claude-opus-4-8"]


# ----------------------------------------------------------------------------------- codex_handoff.sh wiring

HANDOFF = paths.repo_root() / "tools" / "codex_handoff.sh"


def _handoff_env(tmp_path, **extra):
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("CODEX_", "CTF_EVENT", "CTF_FLAG_HINT", "CTF_CHALLENGE", "CTF_WORKDIR"))}
    env.update(CODEX_BIN=str(tmp_path / "codex"), CODEX_PREFLIGHT_DIR=str(tmp_path / "pf"),
               TMPDIR=str(tmp_path), CTF_EVENT="csctf", CTF_WORKDIR=str(tmp_path / "work"),
               CODEX_MODEL="gpt-other")
    env.update(extra)
    return env


def _fake_codex(tmp_path, *, fail_preflight="", fail_launch=""):
    # A stub CLI written by the test (not a challenge binary). The launch call carries --json; the
    # preflight does not.
    body = f'''#!/bin/bash
launch=0; for a in "$@"; do [ "$a" = --json ] && launch=1; done
if [ $launch = 1 ] && [ -n "{fail_launch}" ]; then echo "{fail_launch}" >&2; exit 1; fi
if [ $launch = 0 ] && [ -n "{fail_preflight}" ]; then echo "{fail_preflight}" >&2; exit 1; fi
while [ $# -gt 0 ]; do
  if [ "$1" = -o ]; then echo "PREFLIGHT_OK done" > "$2"; shift 2; else shift; fi
done
'''
    p = tmp_path / "codex"
    p.write_text(body)
    p.chmod(0o755)


def _handoff(tmp_path, args, **extra):
    (tmp_path / "work" / "42-babyrev").mkdir(parents=True, exist_ok=True)
    return subprocess.run(["bash", str(HANDOFF), "--event", "X", *args], input="try xor", text=True,
                          capture_output=True, env=_handoff_env(tmp_path, **extra), timeout=60)


def _wait_stops(workdir, timeout=30.0):
    end = time.time() + timeout
    while time.time() < end:
        recs = [r for r in ledger.read(workdir) if r["event"] == "agent_stop"]
        if recs:
            return recs
        time.sleep(0.1)
    return []


def test_handoff_records_an_agent_stop_when_the_codex_run_dies(tmp_path):
    _fake_codex(tmp_path, fail_launch="Daybreak is unavailable for model gpt-other")
    r = _handoff(tmp_path, ["--challenge", "42", "--no-preflight"])
    assert r.returncode == 0, r.stderr                  # the launch itself is in the background
    stops = _wait_stops(tmp_path / "work")
    assert len(stops) == 1, r.stderr
    s = stops[0]
    assert (s["challenge_id"], s["reason"], s["harness"], s["model"]) == \
        ("42", "provider_error", "codex", "gpt-other")
    assert "Daybreak is unavailable" in s["detail"]


def test_handoff_records_an_agent_stop_when_the_preflight_fails(tmp_path):
    _fake_codex(tmp_path, fail_preflight="Daybreak is unavailable for model gpt-other")
    r = _handoff(tmp_path, ["--challenge", "42"])
    assert r.returncode != 0 and "preflight failed" in r.stderr
    stops = [x for x in ledger.read(tmp_path / "work") if x["event"] == "agent_stop"]
    assert len(stops) == 1 and stops[0]["challenge_id"] == "42" and "preflight" in stops[0]["detail"]


def test_handoff_records_no_stop_for_a_run_that_succeeds(tmp_path):
    _fake_codex(tmp_path)
    r = _handoff(tmp_path, ["--challenge", "42", "--no-preflight"])
    assert r.returncode == 0, r.stderr
    result = tmp_path / "work" / "42-babyrev" / "codex_result.md"
    end = time.time() + 30
    while time.time() < end and "PREFLIGHT_OK" not in (result.read_text() if result.exists() else ""):
        time.sleep(0.1)
    time.sleep(1.0)                                      # past the point a stop would be written
    assert "PREFLIGHT_OK" in result.read_text()
    assert [x for x in ledger.read(tmp_path / "work") if x["event"] == "agent_stop"] == []


def test_handoff_says_so_when_a_folder_challenge_has_no_id(tmp_path):
    _fake_codex(tmp_path, fail_preflight="boom")
    folder = str(tmp_path / "work" / "42-babyrev")
    r = _handoff(tmp_path, ["--challenge", folder])
    assert r.returncode != 0 and "agent_stop NOT recorded" in r.stderr and "CTF_CHALLENGE" in r.stderr
    assert [x for x in ledger.read(tmp_path / "work") if x["event"] == "agent_stop"] == []
    _handoff(tmp_path, ["--challenge", folder], CTF_CHALLENGE="42")
    stops = [x for x in ledger.read(tmp_path / "work") if x["event"] == "agent_stop"]
    assert [x["challenge_id"] for x in stops] == ["42"]


# ----------------------------------------------------------------------------------- round 2: unowned stops

def test_a_handoff_stop_with_no_claim_and_no_launch_gets_a_reroute(tmp_path, prof):
    # tools/codex_handoff.sh writes no agent_launch and no claim: only the agent_stop
    write_ledger(tmp_path, "agent_stop", ts=1000.0, challenge_id="42", harness="codex",
                 reason="provider_error", model="gpt-other")
    made = esc(prof, tmp_path, now=1001.0, read_claims=lambda _wd: ({}, [])).once()
    assert [(d.challenge_id, d.action, d.trigger, d.from_model, d.status) for d in made] == \
        [("42", "reroute", "provider_error", "gpt-other", "dispatched")]
    assert made[0].to_model not in ("gpt-other", "")


def test_an_unowned_stop_times_the_ladder_from_the_stop_not_the_detect(tmp_path, prof):
    write_ledger(tmp_path, "detect", ts=500.0, challenge_id="42", wave="W1")
    write_ledger(tmp_path, "agent_stop", ts=1000.0, challenge_id="42", harness="codex",
                 reason="provider_error", model="gpt-other")
    assert escalation.read_states(tmp_path)["42"].t0 == 1000.0
    # 500 + SECOND_S has passed, 1000 + SECOND_S has not: only the reroute is due
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S - 1, record=False,
               read_claims=lambda _wd: ({}, [])).once()
    assert [d.action for d in made] == ["reroute"]
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S, record=False,
               read_claims=lambda _wd: ({}, [])).once()
    assert sorted(d.action for d in made) == ["reroute", "second"]


def test_handoff_death_end_to_end_is_rerouted(tmp_path, prof):
    _fake_codex(tmp_path, fail_launch="Daybreak is unavailable for model gpt-other")
    r = _handoff(tmp_path, ["--challenge", "42", "--no-preflight"])
    assert r.returncode == 0, r.stderr
    stops = _wait_stops(tmp_path / "work")
    assert len(stops) == 1, r.stderr
    assert [x for x in ledger.read(tmp_path / "work")
            if x["event"] in ("agent_launch", "claim")] == []        # the path the finding names
    made = esc(prof, tmp_path / "work", now=stops[0]["ts"] + 1, read_claims=lambda _wd: ({}, [])).once()
    reroutes = [d for d in made if d.action == "reroute"]
    assert len(reroutes) == 1 and reroutes[0].challenge_id == "42"
    assert reroutes[0].from_model == "gpt-other" and reroutes[0].status == "dispatched"


# ----------------------------------------------------------------------------------- round 2: parts

def test_an_accepted_stage_on_a_part_does_not_resolve_the_parent(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "accepted", ts=1050.0, challenge_id="9#a", status="correct")
    st = escalation.read_states(tmp_path)["9"]
    assert st.resolved is False and st.solved_parts == {"9#a"}
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once()
    assert [(d.challenge_id, d.action) for d in made] == [("9", "second")]


def test_a_part_with_answers_remaining_does_not_resolve_the_parent(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9#a", status="correct", remaining=1)
    assert escalation.read_states(tmp_path)["9"].resolved is False
    assert [d.action for d in esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once()] == ["second"]


def test_the_last_part_resolves_the_parent_when_the_platform_says_none_remain(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9#a", status="correct", remaining=1)
    write_ledger(tmp_path, "platform.submit", ts=1060.0, challenge_id="9#b", status="correct", remaining=0)
    st = escalation.read_states(tmp_path)["9"]
    assert st.resolved is True and st.solved_parts == {"9#a", "9#b"}
    assert esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S).once() == []


def test_a_bool_remaining_is_not_read_as_zero(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9#a", status="correct", remaining=False)
    assert escalation.read_states(tmp_path)["9"].resolved is False


def test_a_partial_batch_on_the_bare_id_does_not_resolve_it(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9", status="correct", answers=2,
                 partial=True)
    assert escalation.read_states(tmp_path)["9"].resolved is False
    assert [d.action for d in esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S).once()] == ["second"]


def test_a_bare_id_with_answers_remaining_but_no_partial_flag_does_not_resolve_it(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9", status="correct", remaining=2)
    assert escalation.read_states(tmp_path)["9"].resolved is False


def test_a_complete_batch_on_the_bare_id_resolves_it(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "platform.submit", ts=1050.0, challenge_id="9", status="correct", answers=2,
                 remaining=0)
    assert escalation.read_states(tmp_path)["9"].resolved is True


# ----------------------------------------------------------------------------------- round 2: remaining recorded

def _record_submit(tmp_path, prof, cid, result):
    from ctf.platform import rules
    from ctf.platform.policy import SubmitRequest
    rules.EventRules(prof, workdir=tmp_path).record(prof, SubmitRequest(cid, "CSCTF{x}", "test"), result)
    return [r for r in ledger.read(tmp_path) if r["event"] == "platform.submit"][-1]


def test_the_submit_record_carries_the_game_masters_remaining_count(tmp_path, prof):
    from ctf.platform.base import SubmitResult, SubmitStatus
    banked = _record_submit(tmp_path, prof, "9#a", SubmitResult(
        SubmitStatus.CORRECT, "accepted", reply={"result": "accepted", "remaining": 1}))
    assert banked["remaining"] == 1
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    assert escalation.read_states(tmp_path)["9"].resolved is False
    done = _record_submit(tmp_path, prof, "9#b", SubmitResult(
        SubmitStatus.CORRECT, "CORRECT", reply={"result": "CORRECT", "name": "Many Phones"}))
    assert done["remaining"] == 0
    assert escalation.read_states(tmp_path)["9"].resolved is True


def test_the_submit_record_has_no_remaining_without_a_game_master_reply(tmp_path, prof):
    from ctf.platform.base import SubmitResult, SubmitStatus
    plain = _record_submit(tmp_path, prof, "9#a", SubmitResult(SubmitStatus.CORRECT, "correct"))
    assert "remaining" not in plain
    wrong = _record_submit(tmp_path, prof, "9#b", SubmitResult(
        SubmitStatus.INCORRECT, "incorrect", reply={"result": "CORRECT"}))
    assert "remaining" not in wrong
    odd = _record_submit(tmp_path, prof, "9#c", SubmitResult(
        SubmitStatus.CORRECT, "accepted", reply={"result": "accepted", "remaining": True}))
    assert "remaining" not in odd
    neg = _record_submit(tmp_path, prof, "9#d", SubmitResult(
        SubmitStatus.CORRECT, "accepted", reply={"result": "accepted", "remaining": -1}))
    assert "remaining" not in neg
    other = _record_submit(tmp_path, prof, "9#e", SubmitResult(
        SubmitStatus.CORRECT, "x", reply={"remaining": 0}))           # no Game Master result word
    assert "remaining" not in other


# ----------------------------------------------------------------------------------- round 2: runs by harness

def test_a_stop_is_matched_to_its_own_harness_launch_for_the_model(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude",
                 model="claude-opus-4-8")
    write_ledger(tmp_path, "agent_launch", ts=1005.0, challenge_id="9", harness="codex", model="gpt-x")
    write_ledger(tmp_path, "agent_stop", ts=1010.0, challenge_id="9", harness="claude", reason="refusal")
    r = [d for d in esc(prof, tmp_path, now=1011.0).once() if d.action == "reroute"]
    assert len(r) == 1 and r[0].from_model == "claude-opus-4-8"


def test_two_stops_of_one_claude_run_share_a_reroute_across_a_codex_launch(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "agent_stop", ts=1003.0, challenge_id="9", harness="claude", reason="refusal")
    write_ledger(tmp_path, "agent_launch", ts=1005.0, challenge_id="9", harness="codex")
    write_ledger(tmp_path, "agent_stop", ts=1010.0, challenge_id="9", harness="claude", reason="refusal")
    r = [d for d in esc(prof, tmp_path, now=1011.0).once() if d.action == "reroute"]
    assert [d.for_stop_ts for d in r] == [1003.0]


def test_a_claude_and_a_codex_run_that_both_stop_get_a_reroute_each(tmp_path, prof):
    write_ledger(tmp_path, "agent_launch", ts=1000.0, challenge_id="9", harness="claude")
    write_ledger(tmp_path, "agent_launch", ts=1002.0, challenge_id="9", harness="codex")
    write_ledger(tmp_path, "agent_stop", ts=1010.0, challenge_id="9", harness="claude", reason="refusal")
    write_ledger(tmp_path, "agent_stop", ts=1012.0, challenge_id="9", harness="codex",
                 reason="provider_error")
    r = [d for d in esc(prof, tmp_path, now=1013.0).once() if d.action == "reroute"]
    assert sorted((d.trigger, d.for_stop_ts) for d in r) == [("provider_error", 1012.0), ("refusal", 1010.0)]
    assert len({d.to_model for d in r}) == 2


# ----------------------------------------------------------------------------------- B-015 claim status

def _claim_with(status):
    rec = {"9": {"challenge_id": "9", "dispatched_at": 1000.0, "status": status}}
    return lambda _wd: (rec, [])


@pytest.mark.parametrize("status", ["solved", "gone"])
def test_a_claim_marked_solved_or_gone_does_not_escalate(tmp_path, prof, status):
    write_ledger(tmp_path, "agent_stop", ts=1010.0, challenge_id="9", harness="claude", reason="refusal")
    assert esc(prof, tmp_path, now=1000.0 + escalation.THIRD_S, read_claims=_claim_with(status)).once() == []


def test_a_returned_claim_escalates_again(tmp_path, prof):
    made = esc(prof, tmp_path, now=1000.0 + escalation.SECOND_S, read_claims=_claim_with("dispatched")).once()
    assert [(d.challenge_id, d.action) for d in made] == [("9", "second")]
