"""B-036: timed-mode chaining (ctf/adapt/chain.py).

The chain reads the event's own records (ledger and watch stream) and runs the real lane gate on a
synthetic checkout (tests/adapt_repo.py); nothing about the decision is mocked."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys

import pytest

from ctf import ledger
from ctf.adapt import AdaptError
from ctf.adapt import chain as C


import adapt_repo as AR

pytestmark = pytest.mark.needs_tool("git")

GATE = dict(load=0.0, cpus=1, guard="hook")
BASE = "binary-reverse-engineering-day-04-go-runtime-fingerprints"
TT, MA = f"{BASE}/time_trial", f"{BASE}/mastery"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_GATE_STATE", str(tmp_path / "gate-state"))
    for k in AR.PROBE_VARS:
        monkeypatch.delenv(k, raising=False)
    root = AR.make_repo(tmp_path)
    wd = tmp_path / "work"
    wd.mkdir()
    return root, wd


def plan(root, wd, **kw):
    return C.plan(BASE, "probe", workdir=wd, root=root, gate_kw=GATE, **kw)


def submit(wd, cid, status="correct", **extra):
    ledger.append("platform.submit", workdir=wd, event_slug="huntress", challenge_id=cid, status=status, judged=True,
                  guess=False, confirmed=False, provenance="test", post_stop=False, **extra)


def team_solved(wd, cid, seq=1):
    p = wd / "watch" / "events.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a") as fh:
        fh.write(json.dumps({"seq": seq, "ts": 1.0, "event": "team_solved", "challenge_id": cid}) + "\n")


def gates(wd):
    return [r for r in ledger.read(wd) if r["event"] == "adapt.gate"]


def test_split_and_mode_id():
    assert C.split(f"{BASE}/time_trial#a1") == (BASE, "time_trial")
    assert C.split(MA) == (BASE, "mastery") and C.split(BASE) == (BASE, "base")
    assert C.mode_id(BASE, "mastery") == MA and C.mode_id(BASE, "base") == BASE
    with pytest.raises(AdaptError):
        C.mode_id(BASE, "practice")


def test_closures_read_every_source_and_only_real_closes(env):
    root, wd = env
    submit(wd, "a", "incorrect")
    submit(wd, "b#q1", "correct", partial=True)                    # banked, answers still open: not closed
    submit(wd, "c#q2", "correct")                                    # the last answer: closed
    submit(wd, "d", "already_solved")
    C.mark_closed("e", by="hand", note="banked by hand", workdir=wd)
    team_solved(wd, "f")
    C.record_attempt("g", "correct", workdir=wd)
    C.record_attempt("h", "incorrect", workdir=wd)
    got = C.closures(wd)
    assert set(got) == {"c", "d", "e", "f", "g"}
    assert (got["c"].by, got["c"].source) == ("us", "submit")
    assert (got["e"].by, got["e"].note) == ("hand", "banked by hand")
    assert (got["f"].by, got["f"].source) == ("teammate", "watch")
    with pytest.raises(AdaptError, match="one of teammate, hand"):
        C.mark_closed("x", by="us", workdir=wd)


def test_the_shared_solved_view_is_a_close(env):
    root, wd = env
    from ctf import solved
    assert solved.record_solve(BASE, solver="teammate-x", workdir=wd)   # B-015: a team-solve stop
    c = C.closures(wd)[BASE]
    assert (c.by, c.source, c.note) == ("teammate", "solved", "teammate-x")
    assert plan(root, wd).action == "start"
    submit(wd, "ours")
    solved.record_solve("ours", workdir=wd)
    assert C.closures(wd)["ours"].by == "us", "our own send came first"


@pytest.mark.parametrize("bad", ["yesterday", [1], {"t": 1}, True])
def test_a_malformed_ledger_ts_is_a_named_error(env, bad):
    root, wd = env
    submit(wd, "a")
    with open(ledger.path(wd), "a") as fh:
        fh.write(json.dumps({"ts": bad, "event": "adapt.closed", "challenge_id": "b", "by": "hand",
                             "note": "b036-row-text-not-to-echo"}) + "\n")
    with pytest.raises(AdaptError, match=r"the ledger: the 'adapt.closed' record for 'b' has a malformed ts") as e:
        C.closures(wd)
    assert "b036-row-text-not-to-echo" not in str(e.value), "the error quoted the raw row"


@pytest.mark.parametrize("row", [
    {"event": "platform.submit", "status": "rejected", "challenge_id": "r"},
    {"event": "adapt.gate", "challenge_id": "g", "verdict": "yes"},
    {"event": "adapt.attempt", "challenge_id": "w", "outcome": "incorrect"},
])
def test_a_malformed_ts_on_a_row_that_is_not_a_close_is_not_read(env, row):
    root, wd = env
    submit(wd, "a")
    with open(ledger.path(wd), "a") as fh:
        fh.write(json.dumps({"ts": "yesterday", **row}) + "\n")
    got = C.closures(wd)
    assert "a" in got and row["challenge_id"] not in got


def test_a_malformed_watch_ts_is_a_named_error(env):
    root, wd = env
    p = wd / "watch" / "events.jsonl"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"seq": 1, "ts": "noon", "event": "team_solved", "challenge_id": "f"}) + "\n")
    with pytest.raises(AdaptError, match="the board watch stream: the 'team_solved' record for 'f' has a malformed ts 'noon'"):
        C.closures(wd)


def test_a_missing_ts_still_reads_as_the_epoch(env):
    root, wd = env
    with open(ledger.path(wd), "a") as fh:
        fh.write(json.dumps({"event": "adapt.closed", "challenge_id": "b", "by": "hand"}) + "\n")
    assert C.closures(wd)["b"].ts == 0.0


def test_the_earliest_close_wins(env):
    root, wd = env
    team_solved(wd, "z")                                             # ts 1.0
    submit(wd, "z")                                                  # now
    assert C.closures(wd)["z"].by == "teammate"


def test_base_not_closed_waits_and_runs_no_gate(env):
    root, wd = env
    step = plan(root, wd)
    assert step.action == "wait" and step.challenge_id == BASE and step.gate is None
    assert gates(wd) == []
    assert [r["action"] for r in ledger.read(wd) if r["event"] == "adapt.chain"] == ["wait"]


@pytest.mark.parametrize("close", ["ours", "teammate", "hand"])
def test_any_close_of_the_base_opens_the_time_trial_behind_the_gate(env, close):
    root, wd = env
    if close == "ours":
        submit(wd, BASE)
    elif close == "teammate":
        team_solved(wd, BASE)
    else:
        C.mark_closed(BASE, by="hand", workdir=wd)
    step = plan(root, wd)
    assert step.action == "start" and step.challenge_id == TT and step.mode == "time_trial"
    assert step.gate is not None and step.gate.ok and step.lane_key == step.gate.lane_key
    assert step.closed == {"base": {"ours": "us"}.get(close, close)}
    assert len(gates(wd)) == 1


def test_a_hand_banked_time_trial_opens_the_mastery(env):
    root, wd = env
    submit(wd, BASE)
    C.mark_closed(TT, by="hand", workdir=wd)
    step = plan(root, wd)
    assert step.action == "start" and step.challenge_id == MA


def test_everything_closed_is_done(env):
    root, wd = env
    for cid in (BASE, TT, MA):
        submit(wd, cid)
    step = plan(root, wd)
    assert step.action == "done" and step.challenge_id is None and gates(wd) == []


def test_gate_no_stops_and_not_run_holds(env, monkeypatch):
    root, wd = env
    submit(wd, BASE)
    monkeypatch.setenv("ADAPT_PROBE_EXIT", "4")
    step = plan(root, wd)
    assert step.action == "stop" and "lane gate NO" in step.reason and "engine exited 4" in step.reason
    monkeypatch.delenv("ADAPT_PROBE_EXIT")
    assert plan(root, wd).action == "start", "a red gate is never cached: once fixed, the step is start"
    ans = AR.fixture_answer(AR.BASE_FIXTURE, wd)
    needy = AR.make_repo(wd / "needy", opener=(
        f'[[opener]]\nlane = "probe"\ncategory = "Probe"\nengine = "{AR.ENGINE}"\nlabel = "p"\n'
        f'fixture = "{AR.BASE_FIXTURE}"\nexpect = ["{ans}"]\ncontrols = ["{AR.CONTROL_FIXTURE}"]\n'
        'needs_tools = ["py:no_such_module_b036"]\n'))
    step = C.plan(BASE, "probe", workdir=wd, root=needy, gate_kw=GATE)
    assert step.action == "hold" and "no_such_module_b036" in step.reason


def test_a_not_submitted_attempt_is_retried_once_behind_the_gate(env):
    root, wd = env
    submit(wd, BASE)
    C.record_attempt(TT, "not_submitted", note="killed", workdir=wd)
    step = plan(root, wd)
    assert step.action == "retry" and step.challenge_id == TT and step.gate.ok
    C.record_attempt(TT, "expired", workdir=wd)
    step = plan(root, wd)
    assert step.action == "stop" and "2 failed attempt(s)" in step.reason
    assert plan(root, wd, max_retries=2).action == "retry"
    assert plan(root, wd, max_retries=0).action == "stop"


def test_a_wrong_answer_is_retried_only_after_the_lane_changed(env):
    root, wd = env
    submit(wd, BASE)
    C.mark_closed(TT, by="teammate", workdir=wd)
    first = plan(root, wd)
    assert first.action == "start" and first.challenge_id == MA
    C.record_attempt(MA, "incorrect", lane_key=first.lane_key, workdir=wd)
    n_gates = len(gates(wd))
    same = plan(root, wd)
    assert same.action == "stop" and "lane is unchanged" in same.reason
    assert len(gates(wd)) == n_gates, "a determined retry runs no gate"
    AR.write(root, "solvers/toolkits/adapt_probe_fallback.py", "READER = 'fallback'\n")   # the fold
    folded = plan(root, wd)
    assert folded.action == "retry" and folded.challenge_id == MA and folded.gate.ok
    assert folded.lane_key != first.lane_key


def test_a_wrong_answer_without_a_lane_key_is_not_retried(env):
    root, wd = env
    submit(wd, BASE)
    C.record_attempt(TT, "incorrect", workdir=wd)
    step = plan(root, wd)
    assert step.action == "stop" and "no lane key" in step.reason


def test_plan_takes_the_base_id(env):
    root, wd = env
    with pytest.raises(AdaptError, match="base id"):
        C.plan(TT, "probe", workdir=wd, root=root)
    with pytest.raises(AdaptError, match="max_retries"):
        C.plan(BASE, "probe", workdir=wd, root=root, max_retries=-1)


def test_record_attempt_checks_the_outcome(env):
    root, wd = env
    with pytest.raises(AdaptError, match="outcome"):
        C.record_attempt(TT, "partial", workdir=wd)
    rec = C.record_attempt(TT, "incorrect", lane_key="k1", note="n", workdir=wd)
    assert {k: rec[k] for k in ("challenge_id", "outcome", "lane_key", "note")} == \
        {"challenge_id": TT, "outcome": "incorrect", "lane_key": "k1", "note": "n"}


# --------------------------------------------------------------------------- the attempt guard

def test_attempt_guard_records_done_once(tmp_path):
    with C.AttemptGuard(TT, lane_key="k", workdir=tmp_path) as att:
        att.done("correct")
        with pytest.raises(AdaptError, match="already recorded"):
            att.done("incorrect")
    assert [(a["outcome"], a["lane_key"]) for a in C.attempts(TT, tmp_path)] == [("correct", "k")]


def test_attempt_guard_marks_an_exception_not_submitted(tmp_path):
    with pytest.raises(RuntimeError):
        with C.AttemptGuard(TT, workdir=tmp_path):
            raise RuntimeError("solver blew up")
    [a] = C.attempts(TT, tmp_path)
    assert a["outcome"] == "not_submitted" and "RuntimeError" in a["note"]
    with C.AttemptGuard(MA, workdir=tmp_path):
        pass
    assert C.attempts(MA, tmp_path)[0]["note"] == "the attempt ended without an outcome"


def test_attempt_guard_restores_the_previous_sigterm_handler(tmp_path):
    before = signal.getsignal(signal.SIGTERM)
    with C.AttemptGuard(TT, workdir=tmp_path) as att:
        assert signal.getsignal(signal.SIGTERM) != before
        att.done("correct")
    assert signal.getsignal(signal.SIGTERM) == before


def test_a_killed_runner_leaves_a_not_submitted_marker(tmp_path):
    code = ("import os, signal, time\n"
            "from ctf.adapt import chain\n"
            f"with chain.AttemptGuard({MA!r}, lane_key='k9'):\n"
            "    os.kill(os.getpid(), signal.SIGTERM)\n"
            "    time.sleep(10)\n")
    env = dict(os.environ, CTF_WORKDIR=str(tmp_path))
    r = subprocess.run([sys.executable, "-c", code], cwd=str(AR.REPO), env=env, capture_output=True, text=True,
                       timeout=60)
    assert r.returncode == 128 + signal.SIGTERM, r.stderr
    [a] = C.attempts(MA, tmp_path)
    assert a["outcome"] == "not_submitted" and a["lane_key"] == "k9" and "SIGTERM" in a["note"]
