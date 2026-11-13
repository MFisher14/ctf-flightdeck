"""Offline coverage for ctf.dynamic: the rotating-flag window logic, now through the submit gate (B-006).

Rotating flags die on global :00/:05/:10 boundaries, so the danger is submitting a flag that expires
mid-flight. These tests pin, without any network or real sleeping: the window math, the server-clock
offset (from the adapter, never a silent zero), the boundary refusal (wait out the boundary, re-fetch
in the fresh window), the retry-across-windows behaviour on a stale rotation, the immediate stop on an
accepted answer or a refusal, and -- critically -- that a rejected rotating flag never counts toward
the wrong-answer stop (it is a timing miss the organizer sanctions re-retrying, bounded instead by the
attempts cap) -- up to submit.rotating_miss_budget misses per challenge; past that each miss counts,
so a long sweep cannot walk past the stop. The gate, the event rules, the queue and the ledger are real; the platform is a double.
"""
from __future__ import annotations

import pytest

from ctf import dynamic as D
from ctf import event
from ctf.platform import NotAllowed, NotSupported, PlatformError, SubmitGate, SubmitStatus, queue, rules

from test_submit_queue import Clock, ScriptedAdapter, flag, make_profile, records


# ----- pure window math -------------------------------------------------------

def test_seconds_left_in_window_basic():
    # 12 s into a 300 s window => 288 s left.
    assert D.seconds_left_in_window(now=12.0, window_s=300, offset=0.0) == pytest.approx(288.0)
    # exactly on a boundary => a full window remains.
    assert D.seconds_left_in_window(now=300.0, window_s=300, offset=0.0) == pytest.approx(300.0)
    # 1 s before the boundary => 1 s left (the danger zone).
    assert D.seconds_left_in_window(now=299.0, window_s=300, offset=0.0) == pytest.approx(1.0)


def test_offset_shifts_onto_server_clock():
    # local clock 3 s behind the server: offset=+3 should advance the window position by 3 s.
    base = D.seconds_left_in_window(now=100.0, offset=0.0)
    shifted = D.seconds_left_in_window(now=100.0, offset=3.0)
    assert shifted == pytest.approx(base - 3.0)


# ----- the server clock -------------------------------------------------------

class ClockedAdapter(ScriptedAdapter):
    def __init__(self, *answers, server_t: float, clock: Clock):
        super().__init__(*answers, clock=clock)
        self.server_t = server_t
        self.probes = 0

    def server_time(self):
        self.probes += 1
        return self.server_t


def test_server_offset_comes_from_the_adapter_clock():
    clock = Clock(1000.0)
    a = ClockedAdapter(server_t=1003.5, clock=clock)
    assert D.server_offset(a, clock) == pytest.approx(3.5)


def test_server_offset_without_a_server_clock_fails_loudly():
    with pytest.raises(NotSupported, match="no server_time"):
        D.server_offset(ScriptedAdapter(), Clock())


def test_a_failed_clock_probe_is_raised_not_zeroed():
    class Broken(ScriptedAdapter):
        def server_time(self):
            raise PlatformError("server_time: HEAD / failed (ConnectionError)")
    with pytest.raises(PlatformError, match="HEAD / failed"):
        D.server_offset(Broken(), Clock())


# ----- solve_dynamic (the gate, rules, queue and ledger are real) -------------

@pytest.fixture
def setup(tmp_path, monkeypatch):
    work = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(work))

    def _make(*answers, t=10.0, stop=3, server_t=None, rotating_budget=None):
        clock = Clock(t)
        prof = make_profile(tmp_path, stop=stop, rotating_budget=rotating_budget)
        a = ClockedAdapter(*answers, server_t=t if server_t is None else server_t, clock=clock)
        g = SubmitGate(a, prof)
        rules.install(g, work)
        queue.install(g, work, clock=clock, sleep=clock.sleep)
        return g, a, clock, work
    return _make


def test_correct_on_first_fetch_returns_immediately(setup):
    g, a, clock, work = setup(SubmitStatus.CORRECT, t=10.0)       # mid-window, safe
    calls = []
    res = D.solve_dynamic(g, "42", lambda: calls.append(1) or flag("fresh_rotating"), attempts=6,
                          clock=clock, sleep=clock.sleep)
    assert res.accepted and len(calls) == 1 and a.probes == 1
    assert clock.slept == [], "mid-window fetch should not wait out a boundary"
    [rec] = records(work)
    assert rec["rotating"] is True and rec["provenance"] == "dynamic-flag (fresh fetch)"


def test_boundary_refusal_waits_then_refetches(setup):
    g, a, clock, _ = setup(SubmitStatus.CORRECT, t=298.0)         # 2 s left in a 300 s window
    res = D.solve_dynamic(g, "42", lambda: flag("after_boundary"), attempts=3, clock=clock,
                          sleep=clock.sleep)
    assert res.accepted
    assert clock.slept[0] == pytest.approx(2.0 + 0.3), "must wait out the remaining window + margin"
    assert a.sent_at[0] >= 300.0


def test_window_uses_the_server_clock(setup):
    # Local clock says 10 s into the window, the server says 297 s: the server's boundary wins.
    g, a, clock, _ = setup(SubmitStatus.CORRECT, t=10.0, server_t=297.0)
    D.solve_dynamic(g, "42", lambda: flag("x"), attempts=2, clock=clock, sleep=clock.sleep)
    assert clock.slept and clock.slept[0] == pytest.approx(3.0 + 0.3)


def test_explicit_offset_skips_the_probe(setup):
    g, a, clock, _ = setup(SubmitStatus.CORRECT)
    assert D.solve_dynamic(g, "42", lambda: flag("x"), offset=0.0, clock=clock, sleep=clock.sleep).accepted
    assert a.probes == 0


def test_stale_rotation_retries_and_never_trips_the_wrong_answer_stop(setup):
    attempts = 4
    g, a, clock, work = setup(*[SubmitStatus.INCORRECT] * attempts, t=50.0, stop=1)
    n = {"i": 0}

    def retrieve():
        n["i"] += 1
        return flag(f"window_{n['i']}")                          # a freshly fetched flag each window

    res = D.solve_dynamic(g, "42", retrieve, attempts=attempts, clock=clock, sleep=clock.sleep)
    assert res.status is SubmitStatus.INCORRECT
    assert n["i"] == attempts and len(a.sent) == attempts
    assert rules.EventRules(g.profile, work).wrong_count("42") == 0, \
        "stale rotations must NOT count toward the wrong-answer stop"
    assert all(r["rotating"] and r["status"] == "incorrect" for r in records(work))
    # with a stop of 1, a static wrong answer would have stopped a second send; the static path still works
    assert g.submit("42", flag("static"), provenance="p").status is SubmitStatus.INCORRECT
    assert "wrong_answer_stop" in g.submit("42", flag("static2"), provenance="p").message


def test_an_unrotated_value_is_not_resent_but_waits_for_the_next_window(setup):
    g, a, clock, _ = setup(SubmitStatus.INCORRECT, SubmitStatus.CORRECT, t=50.0)
    values = iter([flag("w1"), flag("w1"), flag("w2")])
    res = D.solve_dynamic(g, "42", lambda: next(values), attempts=3, clock=clock, sleep=clock.sleep)
    assert res.accepted
    assert [f for _, f in a.sent] == [flag("w1"), flag("w2")]
    assert clock.slept == [pytest.approx(250.3)], "slept to the next rotation instead of re-sending"


def test_garbage_from_the_target_is_not_sent(setup):
    g, a, clock, _ = setup(SubmitStatus.CORRECT, t=50.0)
    values = iter(["Connection reset", flag("good")])
    assert D.solve_dynamic(g, "42", lambda: next(values), attempts=2, clock=clock, sleep=clock.sleep).accepted
    assert [f for _, f in a.sent] == [flag("good")]


def test_stops_on_correct_within_attempts(setup):
    g, a, clock, _ = setup(SubmitStatus.INCORRECT, SubmitStatus.INCORRECT, SubmitStatus.CORRECT, t=50.0)
    n = {"i": 0}

    def retrieve():
        n["i"] += 1
        return flag(f"w_{n['i']}")

    res = D.solve_dynamic(g, "42", retrieve, attempts=6, clock=clock, sleep=clock.sleep)
    assert res.accepted and n["i"] == 3, "stops as soon as a window yields the correct flag"


def test_a_refusal_returns_immediately(setup):
    # The team already has it (an accepted record in the ledger): the gate refuses and the loop stops.
    g, a, clock, work = setup(SubmitStatus.CORRECT, t=50.0)
    g.submit("77", flag("earlier"), provenance="teammate's static solve")
    calls = []
    res = D.solve_dynamic(g, "77", lambda: calls.append(1) or flag("x"), attempts=6, clock=clock,
                          sleep=clock.sleep)
    assert res.status is SubmitStatus.NOT_ALLOWED and res.message.startswith(queue.SOLVED)
    assert len(calls) == 1 and len(a.sent) == 1


def test_manual_events_are_refused_before_the_probe_and_the_fetch(tmp_path, monkeypatch):
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path / "work"))
    clock = Clock(10.0)
    for prof in (event.load("spooky"),):
        a = ClockedAdapter(server_t=10.0, clock=clock)
        g = SubmitGate(a, prof)
        fetched = []
        with pytest.raises(NotAllowed, match="manual"):
            D.solve_dynamic(g, "1", lambda: fetched.append(1) or "spooky{x}", clock=clock, sleep=clock.sleep)
        assert a.probes == 0 and fetched == [] and a.sent == []


def _sweeper(tag="guess"):
    n = {"i": 0}

    def retrieve():
        n["i"] += 1
        return flag(f"{tag}_{n['i']}")                            # a new value every window
    return retrieve


def test_a_long_sweep_is_stopped_past_the_rotating_miss_budget(setup):
    # The verifier's probe: stop=3, 40 attempts of distinct values. The first 6 misses (the default
    # budget) are timing misses; the next 3 count as wrong answers; then the stop refuses.
    g, a, clock, work = setup(t=50.0, stop=3)
    assert g.profile.submit.rotating_miss_budget == 6
    res = D.solve_dynamic(g, "42", _sweeper(), attempts=40, clock=clock, sleep=clock.sleep)
    assert len(a.sent) == 6 + 3, "budget + stop wrong values at most"
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent
    assert "wrong_answer_stop" in res.message and "rotating_miss_budget" in res.message
    er = rules.EventRules(g.profile, work)
    assert er.rotating_misses("42") == 9 and er.wrong_count("42") == 3
    later = g.submit("42", flag("static"), provenance="p")
    assert not later.sent and "wrong_answer_stop" in later.message, "a normal submit is stopped too"
    assert len(a.sent) == 9


def test_the_rotating_budget_spans_calls(setup):
    g, a, clock, work = setup(t=50.0, stop=2, rotating_budget=2)
    D.solve_dynamic(g, "42", _sweeper(), attempts=3, clock=clock, sleep=clock.sleep)
    assert len(a.sent) == 3 and rules.EventRules(g.profile, work).wrong_count("42") == 1
    # misses 1-2 were free, miss 3 counted: one more counted miss reaches the stop of 2
    res = D.solve_dynamic(g, "42", _sweeper("second"), attempts=5, clock=clock, sleep=clock.sleep)
    assert len(a.sent) == 4 and "wrong_answer_stop" in res.message


def test_a_zero_budget_makes_every_rotating_miss_count(setup):
    g, a, clock, work = setup(t=50.0, stop=1, rotating_budget=0)
    res = D.solve_dynamic(g, "42", _sweeper(), attempts=10, clock=clock, sleep=clock.sleep)
    assert len(a.sent) == 1 and "wrong_answer_stop" in res.message


def test_an_approval_alone_does_not_reopen_an_unconfirmed_sweep(setup):
    # solve_dynamic never sends confirmed=True, so a recorded approval does not restart a sweep
    g, a, clock, work = setup(t=50.0, stop=1, rotating_budget=1)
    D.solve_dynamic(g, "42", _sweeper(), attempts=10, clock=clock, sleep=clock.sleep)
    assert len(a.sent) == 2
    rules.EventRules(g.profile, work).grant("42", "player: one more", 1)
    res = D.solve_dynamic(g, "42", _sweeper("again"), attempts=3, clock=clock, sleep=clock.sleep)
    assert not res.sent and "wrong_answer_stop" in res.message and len(a.sent) == 2
