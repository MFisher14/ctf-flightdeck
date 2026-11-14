"""B-173: per-event policy config (penalty, throttle, who submits, wrong quota and approved extras,
guess provenance, player-authorized one-run sweeps with a pacer, hints, player-pointed services).

The platform is a scripted double; the profile parser, the submit gate, the event rules, the submit
queue, the scope guard, the ledger, the template renderer and the CLI are real. No network.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import sys
import types
from pathlib import Path

import pytest

import ctf.cli as cli
from ctf import event, eventpolicy, eventrules, eventscaffold, ledger, scope
from ctf.platform import SubmitGate, SubmitStatus, queue, rules
from ctf.platform.base import PlatformError, SubmitResult
from ctf.platform.policy import SubmitRequest

PREFIX = "POL"


def flag(body: str) -> str:
    return f"{PREFIX}{{{body}}}"


def make(slug="pol-test", *, rules_extra=None, sweep=None, submit=None, kind="ctfd", **rules_kw) -> event.EventProfile:
    r = {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed",
         "wrong_answer_stop": 3, "live_service_scope": ["*.svc.test"]}
    r.update(rules_kw)
    r.update(rules_extra or {})
    data = {"slug": slug, "name": "policy test", "dates": {"start": dt.date(2026, 1, 1), "end": dt.date(2026, 12, 31)},
            "platform": {"kind": kind, "base_url": "https://board.pol.test"} if kind != "manual" else {"kind": "manual"},
            "flag": {"prefixes": [PREFIX]}, "rules": r,
            "submit": submit or {"per_minute": 100, "interval_s": 0.0, "per_challenge_interval_s": 0.0}}
    if sweep is not None:
        data["sweep"] = sweep
    return event.parse(data, src="test")


AUTH = {"mode": "player-authorized", "max_count": 10, "interval_s": 5.0, "ttl_s": 600.0}


class Clock:
    def __init__(self, t=1_000_000.0):
        self.t, self.slept = t, []

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.slept.append(round(s, 6))
        self.t += s


class Scripted:
    kind = "ctfd"

    def __init__(self, *answers, clock=None):
        self.answers, self.sent, self.sent_at, self.clock = list(answers), [], [], clock

    def submit(self, cid, value):
        self.sent.append((cid, value))
        if self.clock is not None:
            self.sent_at.append(self.clock.t)
        a = self.answers.pop(0) if self.answers else SubmitStatus.INCORRECT
        if isinstance(a, Exception):
            raise a
        return a if isinstance(a, SubmitResult) else SubmitResult(a)

    def list_challenges(self): return []
    def get_challenge(self, cid): raise NotImplementedError
    def download_files(self, cid, dest): return []
    def team_solves(self): return []
    def scoreboard(self): return []


@pytest.fixture
def work(tmp_path, monkeypatch):
    w = tmp_path / "work"
    monkeypatch.setenv("CTF_WORKDIR", str(w))
    return w


def gate_for(prof, adapter, work, clock=None, with_queue=True):
    clock = clock or Clock()
    g = SubmitGate(adapter, prof)
    g.add_check(rules.EventRules(prof, work, clock=clock).check)
    g.add_observer(rules.EventRules(prof, work, clock=clock).record)
    if with_queue:
        queue.install(g, work, clock=clock, sleep=clock.sleep)
    return g


def subs(work):
    return [r for r in ledger.read(work) if r["event"] == "platform.submit"]


# ------------------------------------------------------------------------------- profile schema
def test_new_fields_default_to_the_cautious_values():
    p = make()
    assert p.rules.wrong_penalty is None
    assert p.rules.approved_extras is True
    assert p.rules.hint_suggestions is False
    assert p.rules.pointed_services == "forbidden"
    assert p.sweep == event.SweepPolicy(mode="forbidden", max_count=50, interval_s=5.0, ttl_s=3600.0)
    assert not p.sweep.authorized


def test_new_fields_are_read():
    p = make(sweep=AUTH, wrong_penalty=25, approved_extras=False, hint_suggestions=True,
             pointed_services="allowed")
    assert (p.rules.wrong_penalty, p.rules.approved_extras, p.rules.hint_suggestions,
            p.rules.pointed_services) == (25, False, True, "allowed")
    assert p.sweep.authorized and p.sweep.max_count == 10 and p.sweep.ttl_s == 600.0


@pytest.mark.parametrize("change, msg", [
    (dict(wrong_penalty=-1), "rules.wrong_penalty must be >= 0"),
    (dict(wrong_penalty=True), "rules.wrong_penalty must be int"),
    (dict(approved_extras="yes"), "rules.approved_extras must be bool"),
    (dict(pointed_services="sometimes"), "rules.pointed_services must be one of allowed, forbidden"),
    (dict(sweep={"mode": "always"}), "sweep.mode must be one of forbidden, player-authorized"),
    (dict(sweep={"max_count": 0}), "sweep.max_count must be >= 1"),
    (dict(sweep={"interval_s": -1}), "sweep.interval_s must be >= 0"),
    (dict(sweep={"ttl_s": 0}), "sweep.ttl_s must be > 0"),
    (dict(sweep={"mode": "forbidden", "every": 1}), "unknown key(s): sweep.every"),
])
def test_bad_policy_values_fail_loudly(change, msg):
    sweep = change.pop("sweep", None)
    with pytest.raises(event.EventError, match=msg.replace("(", r"\(").replace(")", r"\)")):
        make(sweep=sweep, **change)


def test_sweeps_cannot_be_authorized_on_a_manual_event():
    with pytest.raises(event.EventError, match="player-authorized' needs rules.submit_mode"):
        make(kind="manual", submit_mode="manual", sweep={"mode": "player-authorized"})


def test_shipped_profiles_carry_the_rulings():
    assert event.load("spooky").rules.pointed_services == "allowed"
    assert event.load("csctf").sweep.authorized
    for slug in ("huntress", "pink"):
        p = event.load(slug)
        assert p.rules.pointed_services == "forbidden" and not p.sweep.authorized


# ------------------------------------------------------------------------------- approved extras
def test_approved_extras_false_makes_the_stop_final(work):
    prof = make(approved_extras=False, wrong_answer_stop=1)
    a = Scripted()
    g = gate_for(prof, a, work)
    assert g.submit("5", flag("w1"), provenance="p").status is SubmitStatus.INCORRECT
    with pytest.raises(ValueError, match="approved_extras = false"):
        rules.EventRules(prof, work).grant("5", "player: one more", 1)
    # even an approval recorded by hand (e.g. before the profile changed) does not reopen it
    ledger.append(rules.APPROVAL, workdir=work, event_slug=prof.slug, challenge_id="5", count=5, reason="x")
    res = g.submit("5", flag("w2"), provenance="p", confirmed=True)
    assert not res.sent and "stop is final" in res.message
    assert len(a.sent) == 1


def test_approved_extras_true_keeps_the_b006_approval_path(work):
    prof = make(wrong_answer_stop=1)
    a = Scripted()
    g = gate_for(prof, a, work)
    g.submit("5", flag("w1"), provenance="p")
    rules.EventRules(prof, work).grant("5", "player: one more", 1)
    assert g.submit("5", flag("w2"), provenance="p", confirmed=True).sent


# ------------------------------------------------------------------------------- guesses
def test_guess_budget_counts_logged_guesses_with_their_provenance(work):
    prof = make(guess_budget=1)
    a = Scripted()
    g = gate_for(prof, a, work)
    assert g.submit("5", flag("g1"), provenance="swapped l/1 in the decoded word", guess=True).sent
    res = g.submit("5", flag("g2"), provenance="another variant", guess=True)
    assert not res.sent and res.message.startswith("guess_budget")
    log = eventpolicy.guess_log(prof, "5", workdir=work)
    assert [(r["provenance"], r["status"]) for r in log] == [("swapped l/1 in the decoded word", "incorrect")]
    assert eventpolicy.guess_log(prof, "6", workdir=work) == []


def test_ctf_submit_guess_flag_marks_the_send_as_a_guess(work, monkeypatch, capsys):
    prof = make(guess_budget=0)
    adapter = Scripted()
    monkeypatch.setattr(event, "current", lambda root=None: prof)
    mod = types.ModuleType("ctf.platform.ctfd")
    mod.make_adapter = lambda profile: adapter
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    assert cli.main(["submit", "5", flag("a"), "--note", "derived"]) == 1     # a normal send goes out
    code = cli.main(["submit", "5", flag("b"), "--note", "a variant", "--guess"])
    assert code == 4 and "guess_budget" in capsys.readouterr().err
    assert adapter.sent == [("5", flag("a"))]
    assert [r["guess"] for r in subs(work)] == [False]


# ------------------------------------------------------------------------------- sweeps: authorization
def test_authorize_sweep_is_refused_when_the_event_forbids_sweeps(work):
    with pytest.raises(ValueError, match="sweep.mode = 'forbidden'"):
        rules.EventRules(make(), work).authorize_sweep("5", 3, "player: go")
    assert not ledger.path(work).exists()


@pytest.mark.parametrize("count, ttl, msg", [
    (0, None, "from 1 to sweep.max_count"), (11, None, "from 1 to sweep.max_count"),
    (True, None, "from 1 to sweep.max_count"), (3, 601.0, "at most sweep.ttl_s"), (3, 0, "> 0"),
])
def test_authorize_sweep_bounds(work, count, ttl, msg):
    with pytest.raises(ValueError, match=msg):
        rules.EventRules(make(sweep=AUTH), work).authorize_sweep("5", count, "player: go", ttl_s=ttl)


@pytest.mark.parametrize("count, ttl", [(1, None), (10, None), (3, 600.0), (10, 600.0)])
def test_authorize_sweep_accepts_the_bounds_themselves(work, count, ttl):
    clock = Clock(7000.0)
    rec = rules.EventRules(make(sweep=AUTH), work, clock=clock).authorize_sweep("5", count, "player: go", ttl_s=ttl)
    assert rec["count"] == count and rec["expires_at"] == 7600.0, "max_count and ttl_s are inclusive"


def test_authorize_sweep_needs_a_reason(work):
    with pytest.raises(ValueError, match="needs a reason"):
        rules.EventRules(make(sweep=AUTH), work).authorize_sweep("5", 3, "  ")


def test_authorization_record_has_id_count_and_expiry(work):
    clock = Clock(5000.0)
    rec = rules.EventRules(make(sweep=AUTH), work, clock=clock).authorize_sweep("5#2", 4, " player: go ", ttl_s=60)
    assert rec["challenge_id"] == "5" and rec["count"] == 4 and rec["reason"] == "player: go"
    assert rec["expires_at"] == 5060.0 and rec["auth_id"].isalnum() and len(rec["auth_id"]) == 16
    rec2 = rules.EventRules(make(sweep=AUTH), work, clock=clock).authorize_sweep("5", 4, "again")
    assert rec2["auth_id"] != rec["auth_id"] and rec2["expires_at"] == 5600.0


# ------------------------------------------------------------------------------- sweeps: the run
def _auth(prof, work, clock, cid="5", count=5, ttl=None):
    return rules.EventRules(prof, work, clock=clock).authorize_sweep(cid, count, "player: sweep it", ttl_s=ttl)["auth_id"]


def test_an_authorized_run_passes_the_stop_and_the_guess_budget_without_reauthorizing(work):
    clock = Clock()
    prof = make(sweep=AUTH, wrong_answer_stop=1, guess_budget=0)
    a = Scripted(SubmitStatus.INCORRECT, SubmitStatus.INCORRECT, SubmitStatus.INCORRECT, SubmitStatus.CORRECT,
                 clock=clock)
    g = gate_for(prof, a, work, clock)
    assert g.submit("5", flag("first"), provenance="derived").status is SubmitStatus.INCORRECT   # stop reached
    auth = _auth(prof, work, clock)
    rep = eventpolicy.run_sweep(g, "5", [flag(f"c{i}") for i in range(5)], auth_id=auth,
                                note="rotations of the key", workdir=work, clock=clock, sleep=clock.sleep)
    assert rep.outcome == "accepted" and rep.accepted == flag("c2") and rep.sent == 3
    assert [v for _, v in a.sent] == [flag("first"), flag("c0"), flag("c1"), flag("c2")]
    sweeps = [r for r in subs(work) if r.get("sweep") == auth]
    assert len(sweeps) == 3 and all(r["guess"] and not r["post_stop"] for r in sweeps)
    assert sweeps[0]["provenance"] == f"rotations of the key [sweep {auth} #1]"


def test_the_pacer_spaces_sweep_sends(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(clock=clock)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock, count=3)
    eventpolicy.run_sweep(g, "5", [flag("a"), flag("b"), flag("c")], auth_id=auth, note="n",
                          workdir=work, clock=clock, sleep=clock.sleep)
    gaps = [round(b - x, 6) for x, b in zip(a.sent_at, a.sent_at[1:])]
    assert gaps == [5.0, 5.0], "sweep sends go sweep.interval_s apart"


def test_the_pacer_counts_only_real_sends_not_skipped_duplicates(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(clock=clock)
    g = gate_for(prof, a, work, clock)
    g.submit("5", flag("old"), provenance="derived")       # judged before the run: a duplicate in it
    clock.t += 100.0
    auth = _auth(prof, work, clock, count=3)
    rep = eventpolicy.run_sweep(g, "5", [flag("a"), flag("old"), flag("b")], auth_id=auth, note="n",
                                workdir=work, clock=clock, sleep=clock.sleep)
    assert rep.skipped == [flag("old")] and rep.sent == 2
    assert [v for _, v in a.sent] == [flag("old"), flag("a"), flag("b")]
    first, second = a.sent_at[1], a.sent_at[2]
    assert round(second - first, 6) == 5.0, "the next real send waits interval_s after the last REAL send"


def test_sweep_misses_leave_the_guard_unchanged_after_the_run(work):
    clock = Clock()
    prof = make(sweep=AUTH, wrong_answer_stop=2, guess_budget=1)
    a = Scripted()
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock, count=4)
    rep = eventpolicy.run_sweep(g, "5", [flag(f"s{i}") for i in range(4)], auth_id=auth, note="n",
                                workdir=work, clock=clock, sleep=clock.sleep)
    assert rep.outcome == "exhausted" and rep.sent == 4
    r = rules.EventRules(prof, work, clock=clock)
    assert r.wrong_count("5") == 0 and r.guesses_used("5") == 0
    # the normal guard is back: two static misses reach the stop, one guess spends the budget
    assert g.submit("5", flag("x1"), provenance="p", guess=True).sent
    assert not g.submit("5", flag("x2"), provenance="p", guess=True).sent
    assert g.submit("5", flag("x3"), provenance="p").sent
    res = g.submit("5", flag("x4"), provenance="p")
    assert not res.sent and "wrong_answer_stop" in res.message


def test_a_run_stops_when_the_authorization_is_used_up(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted()
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock, count=2)
    rep = eventpolicy.run_sweep(g, "5", [flag(f"u{i}") for i in range(5)], auth_id=auth, note="n",
                                workdir=work, clock=clock, sleep=clock.sleep)
    assert rep.outcome == "stopped" and rep.sent == 2 and "used up (2 of 2" in rep.reason
    assert len(a.sent) == 2


def test_unjudged_sends_do_not_spend_the_authorization(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(SubmitStatus.RATE_LIMITED, SubmitStatus.INCORRECT, SubmitStatus.INCORRECT)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock, count=2)
    rep = eventpolicy.run_sweep(g, "5", [flag("a"), flag("b"), flag("c")], auth_id=auth, note="n",
                                workdir=work, clock=clock, sleep=clock.sleep)
    assert len(a.sent) == 3 and rep.sent == 2          # the queue re-sent the rate-limited one
    assert rules.EventRules(prof, work, clock=clock).sweep_used(auth) == 2


def test_an_authorization_covers_one_run_only(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    g = gate_for(prof, Scripted(), work, clock)
    auth = _auth(prof, work, clock, count=5)
    eventpolicy.run_sweep(g, "5", [flag("a")], auth_id=auth, note="n", workdir=work, clock=clock, sleep=clock.sleep)
    with pytest.raises(eventpolicy.SweepError, match="already used by a run"):
        eventpolicy.run_sweep(g, "5", [flag("b")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)


@pytest.mark.parametrize("case, msg", [
    ("unknown", "no authorization"), ("other", "is for challenge 9, not 5"), ("expired", "expired"),
])
def test_a_run_refuses_before_any_send(work, case, msg):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted()
    g = gate_for(prof, a, work, clock)
    auth = {"unknown": lambda: "deadbeef00000000", "other": lambda: _auth(prof, work, clock, cid="9"),
            "expired": lambda: _auth(prof, work, clock, ttl=10)}[case]()
    clock.t += 10
    with pytest.raises(eventpolicy.SweepError, match=msg):
        eventpolicy.run_sweep(g, "5", [flag("a")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)
    assert a.sent == []
    assert not (work / "sweeps" / f"{auth}.run").exists(), "a refused run does not burn the authorization"


def test_a_run_needs_a_note(work):
    prof = make(sweep=AUTH)
    with pytest.raises(eventpolicy.SweepError, match="needs a note"):
        eventpolicy.run_sweep(gate_for(prof, Scripted(), work), "5", [flag("a")], auth_id="x", note=" ",
                              workdir=work)


def test_an_authorization_expiring_mid_run_stops_it(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(clock=clock)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock, count=5, ttl=7)
    rep = eventpolicy.run_sweep(g, "5", [flag("a"), flag("b"), flag("c")], auth_id=auth, note="n",
                                workdir=work, clock=clock, sleep=clock.sleep)
    assert rep.outcome == "stopped" and "expired" in rep.reason and len(a.sent) == 2


def test_a_forbidden_profile_refuses_sweep_sends_even_with_a_recorded_authorization(work):
    clock = Clock()
    allowed = make(sweep=AUTH)
    auth = _auth(allowed, work, clock)
    a = Scripted()
    g = gate_for(make(), a, work, clock)                   # the same event, sweeps now forbidden
    with pytest.raises(eventpolicy.SweepError, match="sweep.mode = 'forbidden'"):
        eventpolicy.run_sweep(g, "5", [flag("a")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)
    assert a.sent == []


def test_a_sweep_past_a_final_stop_is_refused(work):
    clock = Clock()
    prof = make(sweep=AUTH, approved_extras=False, wrong_answer_stop=1)
    a = Scripted()
    g = gate_for(prof, a, work, clock)
    g.submit("5", flag("w"), provenance="p")
    auth = _auth(prof, work, clock)
    rep = eventpolicy.run_sweep(g, "5", [flag("a")], auth_id=auth, note="n", workdir=work, clock=clock,
                                sleep=clock.sleep)
    assert rep.outcome == "stopped" and "stop is final" in rep.reason and len(a.sent) == 1


def test_duplicates_are_skipped_not_sent_and_a_solved_challenge_stops_the_run(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(SubmitStatus.INCORRECT)
    g = gate_for(prof, a, work, clock)
    g.submit("5", flag("old"), provenance="derived")
    auth = _auth(prof, work, clock)
    rep = eventpolicy.run_sweep(g, "5", [flag("old"), flag("new"), flag("new")], auth_id=auth, note="n",
                                workdir=work, clock=clock, sleep=clock.sleep)
    assert rep.skipped == [flag("old")] and rep.sent == 1
    assert [v for _, v in a.sent] == [flag("old"), flag("new")]
    ledger.append("platform.submit", workdir=work, event_slug=prof.slug, challenge_id="7", status="correct",
                  judged=True, guess=False, confirmed=False, provenance="teammate", post_stop=False, flag=flag("t"))
    auth7 = _auth(prof, work, clock, cid="7")
    rep = eventpolicy.run_sweep(g, "7", [flag("z")], auth_id=auth7, note="n", workdir=work, clock=clock,
                                sleep=clock.sleep)
    assert rep.outcome == "stopped" and rep.reason.startswith("solved")


def test_only_the_sweep_runner_may_pass_sweep(work):
    g = gate_for(make(sweep=AUTH), Scripted(), work)
    with pytest.raises(ValueError, match="reserved for the paced sweep runner"):
        g.submit("5", flag("a"), provenance="p", sweep="abc")


def test_a_spooled_sweep_send_keeps_its_authorization_for_drain(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(PlatformError("submit: POST failed (Timeout)"), SubmitStatus.INCORRECT)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock)
    with pytest.raises(PlatformError):
        eventpolicy.run_sweep(g, "5", [flag("a")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)
    [err] = subs(work)
    assert err["status"] == "error" and err["sweep"] == auth
    [(rec, res)] = g.queue.drain(g)
    assert rec["sweep"] == auth and res.status is SubmitStatus.INCORRECT
    assert subs(work)[-1]["sweep"] == auth


def test_drain_paces_a_spooled_sweep_send_after_the_last_send(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(SubmitStatus.INCORRECT, PlatformError("submit: POST failed (Timeout)"), SubmitStatus.INCORRECT,
                 clock=clock)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock)
    with pytest.raises(PlatformError):
        eventpolicy.run_sweep(g, "5", [flag("a"), flag("b")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)
    errored_at = a.sent_at[1]
    clock.t += 1.0                                          # drain starts 1 s after the failed send
    [(rec, res)] = g.queue.drain(g)
    assert rec["sweep"] == auth and res.status is SubmitStatus.INCORRECT
    assert round(a.sent_at[2] - errored_at, 6) == 5.0, "drain keeps the sweep pacer (sweep.interval_s)"


def test_drain_waits_out_a_pacer_gap_under_one_second(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(SubmitStatus.INCORRECT, PlatformError("submit: POST failed (Timeout)"), SubmitStatus.INCORRECT,
                 clock=clock)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock)
    with pytest.raises(PlatformError):
        eventpolicy.run_sweep(g, "5", [flag("a"), flag("b")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)
    errored_at = a.sent_at[1]
    clock.t += 4.5                                          # drain starts 0.5 s before the pacer allows
    g.queue.drain(g)
    assert round(a.sent_at[2] - errored_at, 6) == 5.0, "even a 0.5 s pacer gap is waited out"


def test_drain_paces_a_sweep_longer_than_the_queues_window(work):
    clock = Clock()
    prof = make(sweep=dict(AUTH, interval_s=120.0))         # longer than the queue's 60 s window
    a = Scripted(SubmitStatus.INCORRECT, PlatformError("submit: POST failed (Timeout)"), SubmitStatus.INCORRECT,
                 SubmitStatus.INCORRECT, clock=clock)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock)
    with pytest.raises(PlatformError):
        eventpolicy.run_sweep(g, "5", [flag("a"), flag("b")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)
    errored_at = a.sent_at[1]
    clock.t += 70.0
    g.submit("6", flag("other"), provenance="derived")    # another challenge's send prunes old stamps
    g.queue.drain(g)
    assert [v for _, v in a.sent][-1] == flag("b")
    assert round(a.sent_at[-1] - errored_at, 6) == 120.0, "the challenge's last send is kept as long as the pacer"


def _spool_by_hand(g, prof, auth, value):
    q = g.queue
    q._mkdirs()
    req = SubmitRequest("5", value, f"hand [sweep {auth} #1]", True, False, True, sweep=auth)
    path, fd = q._open_spool(q._spool_record(req))
    q._close_spool(path, fd, remove=False)                  # unlocked: drain sees an orphan
    return path


def test_drain_refuses_a_sweep_record_no_run_claimed(work):
    clock = Clock()
    prof = make(sweep=AUTH, wrong_answer_stop=1)
    a = Scripted(clock=clock)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock)                         # authorized, but never run
    path = _spool_by_hand(g, prof, auth, flag("forged"))
    [(rec, res)] = g.queue.drain(g)
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent
    assert "was not claimed by a run" in res.message
    assert a.sent == [] and not path.exists()
    # once a run has claimed the authorization, a record of a value the run never offered is still
    # refused: the claim binds the run's own values, not just the authorization id
    eventpolicy.run_sweep(g, "5", [flag("r1")], auth_id=auth, note="n", workdir=work, clock=clock, sleep=clock.sleep)
    path = _spool_by_hand(g, prof, auth, flag("forged"))
    [(rec, res)] = g.queue.drain(g)
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent
    assert "never offered by the run" in res.message
    assert [v for _, v in a.sent] == [flag("r1")] and not path.exists()


def test_drain_resends_only_the_runs_own_spooled_value(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    a = Scripted(PlatformError("submit: POST failed (Timeout)"), SubmitStatus.INCORRECT, SubmitStatus.INCORRECT,
                 clock=clock)
    g = gate_for(prof, a, work, clock)
    auth = _auth(prof, work, clock)
    with pytest.raises(PlatformError):
        eventpolicy.run_sweep(g, "5", [flag("a"), flag("b")], auth_id=auth, note="n", workdir=work, clock=clock,
                              sleep=clock.sleep)
    _spool_by_hand(g, prof, auth, flag("b"))               # the run's next value, which it never offered
    results = g.queue.drain(g)
    by_value = {rec["flag"]: res for rec, res in results}
    assert by_value[flag("a")].status is SubmitStatus.INCORRECT, "the run's own spooled send is resent"
    assert by_value[flag("b")].status is SubmitStatus.NOT_ALLOWED and not by_value[flag("b")].sent
    assert [v for _, v in a.sent] == [flag("a"), flag("a")]


def test_the_claim_file_lists_each_offered_value_by_hash_only(work):
    clock = Clock()
    prof = make(sweep=AUTH)
    g = gate_for(prof, Scripted(SubmitStatus.INCORRECT, SubmitStatus.INCORRECT, clock=clock), work, clock)
    auth = _auth(prof, work, clock)
    eventpolicy.run_sweep(g, "5", [flag("a"), flag("b")], auth_id=auth, note="n", workdir=work, clock=clock,
                          sleep=clock.sleep)
    text = rules.sweep_claim_path(work, auth).read_text()
    claim = json.loads(text)
    assert claim["offered"] == [hashlib.sha256(flag(v).encode()).hexdigest() for v in ("a", "b")]
    assert flag("a") not in text and flag("b") not in text


def test_a_non_id_sweep_auth_is_never_claimed(work):
    prof = make(sweep=AUTH)
    (work / "sweeps").mkdir(parents=True)
    offered = json.dumps({"offered": [hashlib.sha256(flag("v").encode()).hexdigest()]})
    (work / "x.run").write_text(offered)                   # what "../x" would reach outside sweeps/
    assert "not claimed" in rules.EventRules(prof, work).sweep_unclaimed("../x", flag("v"))
    (work / "sweeps" / "abc.run").write_text(offered)
    assert rules.EventRules(prof, work).sweep_unclaimed("abc", flag("v")) is None
    assert "never offered" in rules.EventRules(prof, work).sweep_unclaimed("abc", flag("w"))


@pytest.mark.parametrize("body", ["not json", "{}", '{"offered": "abc"}'])
def test_an_unreadable_claim_file_refuses_by_name(work, body):
    prof = make(sweep=AUTH)
    (work / "sweeps").mkdir(parents=True)
    (work / "sweeps" / "abc.run").write_text(body)
    assert "claim file of authorization abc" in rules.EventRules(prof, work).sweep_unclaimed("abc", flag("v"))


# ------------------------------------------------------------------------------- pointed services
def test_parse_address():
    assert eventpolicy.parse_address("Svc.Example.:31337") == ("svc.example", 31337)
    assert eventpolicy.parse_address("10.1.2.3") == ("10.1.2.3", None)
    assert eventpolicy.parse_address("[::1]:8080") == ("::1", 8080)
    assert eventpolicy.parse_address("fd00::5") == ("fd00::5", None)
    for bad in ("http://x.test/", "*.x.test", "x.test:0", "x.test:99999", "x.test:ab", "10.0.0.0/8", "[::1"):
        with pytest.raises(eventpolicy.PolicyError):
            eventpolicy.parse_address(bad)


def test_point_is_refused_when_the_event_forbids_it(work):
    with pytest.raises(eventpolicy.PolicyError, match="pointed_services = 'forbidden'"):
        eventpolicy.point(make(), "5", "chal.other.example:1337", "player: use this", workdir=work)
    assert not ledger.path(work).exists()


def test_pointed_records_are_ignored_when_the_event_forbids_them(work):
    prof = make(pointed_services="allowed")
    eventpolicy.point(prof, "5", "chal.other.example:1337", "player: use this", workdir=work)
    scope.check_host("chal.other.example", 1337, profile=prof)
    with pytest.raises(scope.OutOfScope, match="outside event"):
        scope.check_host("chal.other.example", 1337, profile=make())


def test_a_pointed_service_is_admitted_exactly(work):
    prof = make(pointed_services="allowed")
    with pytest.raises(scope.OutOfScope):
        scope.check_host("chal.other.example", 1337, profile=prof)
    rec = eventpolicy.point(prof, "5", "chal.other.example:1337", "player: nc chal.other.example 1337", workdir=work)
    assert rec["host"] == "chal.other.example" and rec["port"] == 1337 and rec["challenge_id"] == "5"
    assert scope.check_host("CHAL.other.example", 1337, profile=prof) == "chal.other.example"
    with pytest.raises(scope.OutOfScope, match="no player-pointed service matches"):
        scope.check_host("chal.other.example", 1338, profile=prof)
    with pytest.raises(scope.OutOfScope):
        scope.check_host("chal.other.example", None, profile=prof)
    with pytest.raises(scope.OutOfScope):
        scope.check_host("evil.other.example", 1337, profile=prof)
    assert scope.check_host("a.svc.test", 80, profile=prof) == "a.svc.test"   # the glob scope still works
    eventpolicy.unpoint(prof, "chal.other.example:1337", "player: done", workdir=work)
    with pytest.raises(scope.OutOfScope):
        scope.check_host("chal.other.example", 1337, profile=prof)


def test_a_point_without_a_port_admits_any_port_of_that_host(work):
    prof = make(pointed_services="allowed", live_service_scope=[])
    with pytest.raises(scope.OutOfScope, match="empty rules.live_service_scope"):
        scope.check_host("10.9.8.7", 22, profile=prof)
    eventpolicy.point(prof, "5", "10.9.8.7", "player: the box is 10.9.8.7", workdir=work)
    assert scope.check_host("10.9.8.7", 22, profile=prof) == "10.9.8.7"
    assert scope.check_url("http://10.9.8.7:8080/x", profile=prof) == "10.9.8.7"
    assert scope.policy(prof).pointed == (("10.9.8.7", None),)


def test_the_platform_is_never_pointable(work):
    prof = make(pointed_services="allowed")
    with pytest.raises(eventpolicy.PolicyError, match="is the event platform"):
        eventpolicy.point(prof, "5", "board.pol.test:443", "player", workdir=work)
    with pytest.raises(eventpolicy.PolicyError, match="is the event platform"):
        eventpolicy.point(prof, "5", "board.pol.test", "player", workdir=work)
    # a hand-written record for the platform does not open it either
    ledger.append(scope.POINTED, workdir=work, event_slug=prof.slug, challenge_id="5", host="board.pol.test",
                  port=443, reason="x")
    with pytest.raises(scope.OutOfScope, match="event platform"):
        scope.check_host("board.pol.test", 443, profile=prof)


def test_another_events_points_do_not_count(work):
    prof = make(pointed_services="allowed")
    other = make(slug="other-ev", pointed_services="allowed")
    eventpolicy.point(other, "5", "chal.other.example:1", "player", workdir=work)
    with pytest.raises(scope.OutOfScope):
        scope.check_host("chal.other.example", 1, profile=prof)


def test_an_unreadable_ledger_refuses(work):
    prof = make(pointed_services="allowed")
    work.mkdir(parents=True)
    ledger.path(work).write_text("{not json\n")
    with pytest.raises(scope.OutOfScope, match="could not be read"):
        scope.check_host("a.svc.test", 80, profile=prof)


def test_point_needs_a_reason_and_a_challenge(work):
    prof = make(pointed_services="allowed")
    with pytest.raises(eventpolicy.PolicyError, match="needs a reason"):
        eventpolicy.point(prof, "5", "x.example:1", "", workdir=work)
    with pytest.raises(eventpolicy.PolicyError, match="names the challenge"):
        eventpolicy.point(prof, " ", "x.example:1", "r", workdir=work)


# ------------------------------------------------------------------------------- summary
def test_summary_answers_every_policy_question(work):
    prof = make(sweep=AUTH, wrong_penalty=10, approved_extras=False, hint_suggestions=True,
                pointed_services="allowed", guess_budget=2)
    eventpolicy.point(prof, "5", "chal.other.example:1337", "player", workdir=work)
    pol = eventpolicy.summary(prof)
    d = pol.to_dict()
    assert d["who_submits"].startswith("each solver submits") and d["submit_mode"] == "auto"
    assert (d["wrong_penalty"], d["per_minute"], d["wrong_answer_stop"], d["approved_extras"],
            d["guess_budget"], d["sweep_mode"], d["sweep_max_count"], d["hint_suggestions"]) == (
        10, 100, 3, False, 2, "player-authorized", 10, True)
    assert d["pointed"] == ["chal.other.example:1337"] and d["live_service_scope"] == ["*.svc.test"]
    text = "\n".join(eventpolicy.lines(pol))
    for want in ("10 point(s) lost per wrong answer", "final: no approval", "budget 2",
                 "player-authorized, once per run: at most 10 sends, 5s apart", "agents may suggest one",
                 "now: chal.other.example:1337"):
        assert want in text, want
    plain = "\n".join(eventpolicy.lines(eventpolicy.summary(make(wrong_penalty=0))))
    assert "none (0 points)" in plain and "sweeps         forbidden" in plain and "agents do not suggest" in plain
    assert "not recorded" in "\n".join(eventpolicy.lines(eventpolicy.summary(make())))
    manual = eventpolicy.summary(make(kind="manual", submit_mode="manual", ai_on_platform="forbidden"))
    assert manual.who_submits.startswith("the player submits by hand")


# ------------------------------------------------------------------------------- agent rules
def _render(prof):
    out = eventrules.render(prof)
    assert eventrules.split_header(out["CLAUDE.md"])[1] == eventrules.split_header(out["AGENTS.md"])[1]
    return out["AGENTS.md"]


def _variant(base, sweep=None, **rules_kw):
    p = dataclasses.replace(base, rules=dataclasses.replace(base.rules, **rules_kw))
    return dataclasses.replace(p, sweep=sweep) if sweep is not None else p


def test_each_policy_field_has_a_template_line():
    base = event.load("pink")
    b = _render(base)
    assert "Penalty: not recorded" in b and "Never sweep" in b and "Do not suggest hints either" in b
    assert "A service the player mentions is not in scope by itself" in b
    assert "at most 10 flag(s) a minute" in b
    assert "submit-queue approve" in b
    cases = [
        (dict(wrong_penalty=50), "Penalty: 50 point(s) per wrong answer", "Penalty: not recorded"),
        (dict(wrong_penalty=0), "Penalty: none.", "Penalty: not recorded"),
        (dict(approved_extras=False), "the stop is final", "submit-queue approve"),
        (dict(hint_suggestions=True), "say so to the player once", "Do not suggest hints either"),
        (dict(pointed_services="allowed"), "A challenge service the player points you at is in scope",
         "A service the player mentions is not in scope by itself"),
        (dict(sweep=event.SweepPolicy(mode="player-authorized", max_count=7, ttl_s=1800)),
         "at most 7 sends; it expires after 30 minute(s)", "Never sweep"),
        (dict(guess_budget=2), "--guess --note", "Never guess"),
    ]
    for change, present, absent in cases:
        out = _render(_variant(base, **change))
        assert present in out, change
        assert absent not in out, change
    pace = _render(dataclasses.replace(base, submit=event.SubmitPace(per_minute=4, interval_s=2.5)))
    assert "at most 4 flag(s) a minute, at\n  least 2.5 s apart" in pace


def test_spooky_rules_say_a_pointed_challenge_service_is_not_infrastructure():
    b = _render(event.load("spooky"))
    flat = " ".join(b.split())
    assert "challenge's own service is not the platform and not organizer infrastructure" in flat
    # a brief is challenge data: its address is in scope only once the player confirms it
    assert "the host and port in its brief" not in flat
    assert ("An address in a challenge's brief or files is data, not a point: it is in scope only "
            "after the player confirms it.") in flat
    assert "Record only an address the player gave or confirmed." in flat
    assert "python -m ctf policy point" in b
    assert "No AI on the platform" in b and "Never submit a flag anywhere" in b
    assert "Pace." not in b, "a manual event has no submit queue"


def test_csctf_rules_carry_the_one_run_sweep():
    b = _render(event.load("csctf"))
    assert "Sweeps only under the player's authorization, once per run" in b
    assert "python -m ctf policy authorize-sweep" in b and "Never authorize a sweep yourself" in b


def test_shipped_agent_files_are_current():
    from ctf import paths
    for slug in event.available():
        assert eventrules.check(event.load(slug), paths.event_dir(slug)) == [], slug


# ------------------------------------------------------------------------------- scaffold
def test_scaffold_writes_the_policy_fields(tmp_path):
    data = eventscaffold.profile_data("acme", name="ACME", start=dt.date(2027, 1, 1), end=dt.date(2027, 1, 2),
                                      kind="ctfd", base_url="https://acme.example", submit_mode="confirm",
                                      ai_on_platform="allowed", wrong_penalty=5, approved_extras=False,
                                      hint_suggestions=True, pointed_services="allowed",
                                      sweep_mode="player-authorized")
    prof = eventscaffold.write_profile(data, tmp_path / "acme" / "event.toml")
    assert (prof.rules.wrong_penalty, prof.rules.approved_extras, prof.rules.hint_suggestions,
            prof.rules.pointed_services, prof.sweep.mode) == (5, False, True, "allowed", "player-authorized")
    text = (tmp_path / "acme" / "event.toml").read_text()
    assert "[sweep]" in text and "max_count = 50" in text
    plain = eventscaffold.profile_data("b", name="B", start=dt.date(2027, 1, 1), end=dt.date(2027, 1, 2),
                                       kind="manual", submit_mode="manual", ai_on_platform="forbidden")
    assert "wrong_penalty" not in plain["rules"], "an unknown penalty is left out, not written as 0"
    assert eventscaffold.validate(plain, "b").rules.pointed_services == "forbidden"


def test_new_event_options_reach_the_profile(tmp_path, capsys):
    code = cli.main(["new-event", "acme", "--events-root", str(tmp_path), "--start", "2027-01-01",
                     "--end", "2027-01-02", "--base-url", "https://acme.example", "--no-fetch",
                     "--wrong-penalty", "0", "--no-approved-extras", "--hint-suggestions",
                     "--pointed-services", "allowed", "--sweep", "player-authorized"])
    assert code == 0, capsys.readouterr()
    prof = event.load("acme", tmp_path)
    assert (prof.rules.wrong_penalty, prof.rules.approved_extras, prof.rules.hint_suggestions,
            prof.rules.pointed_services, prof.sweep.mode) == (0, False, True, "allowed", "player-authorized")
    assert "Penalty: none." in (tmp_path / "acme" / "AGENTS.md").read_text()


def test_regen_refuses_an_explicit_zero_option(tmp_path, capsys):
    cli.main(["new-event", "acme", "--events-root", str(tmp_path), "--start", "2027-01-01",
              "--end", "2027-01-02", "--base-url", "https://acme.example", "--no-fetch"])
    capsys.readouterr()
    code = cli.main(["new-event", "acme", "--events-root", str(tmp_path), "--regen", "--wrong-penalty", "0"])
    assert code == 1 and "--wrong-penalty" in capsys.readouterr().err


# ------------------------------------------------------------------------------- CLI
def run(capsys, *argv):
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def test_policy_show_json_reads_the_named_event(capsys):
    code, out, _ = run(capsys, "policy", "show", "--json", "--event", "csctf")
    d = json.loads(out)
    assert code == 0 and d["event"] == "csctf" and d["sweep_mode"] == "player-authorized"
    assert d["who_submits"].startswith("each solver") and d["pointed_services"] == "forbidden"
    code, out, _ = run(capsys, "policy", "show", "--event", "pink")
    assert code == 0 and "sweeps         forbidden" in out and "who submits    auto" in out


def test_policy_cli_authorize_point_guesses(work, monkeypatch, capsys):
    prof = make(sweep=AUTH, pointed_services="allowed", wrong_penalty=3)
    monkeypatch.setattr(event, "current", lambda root=None: prof)
    code, out, _ = run(capsys, "policy", "authorize-sweep", "5", "--count", "4", "--reason", "player: go")
    assert code == 0 and "worst case: 12 point(s)" in out
    [auth] = [r for r in ledger.read(work) if r["event"] == rules.SWEEP_AUTH]
    assert auth["auth_id"] in out and auth["count"] == 4
    code, _, err = run(capsys, "policy", "authorize-sweep", "5", "--count", "40", "--reason", "x")
    assert code == 4 and "sweep.max_count" in err
    code, out, _ = run(capsys, "policy", "point", "5", "chal.other.example:1337", "--reason", "player gave it")
    assert code == 0 and "chal.other.example:1337" in out
    assert scope.check_host("chal.other.example", 1337, profile=prof)
    code, _, err = run(capsys, "policy", "point", "5", "board.pol.test", "--reason", "x")
    assert code == 4 and "event platform" in err
    code, out, _ = run(capsys, "policy", "unpoint", "chal.other.example:1337", "--reason", "done")
    assert code == 0
    with pytest.raises(scope.OutOfScope):
        scope.check_host("chal.other.example", 1337, profile=prof)
    ledger.append("platform.submit", workdir=work, event_slug=prof.slug, challenge_id="5", status="incorrect",
                  judged=True, guess=True, confirmed=False, provenance="l/1 swap", post_stop=False, flag=flag("g"))
    code, out, _ = run(capsys, "policy", "guesses", "5")
    assert code == 0 and "l/1 swap" in out and flag("g") in out
    code, out, _ = run(capsys, "policy", "guesses", "6")
    assert "no logged guesses" in out


def test_policy_cli_sweep_refusals(work, monkeypatch, capsys, tmp_path):
    cands = tmp_path / "c.txt"
    cands.write_text(flag("a") + "\n\n" + flag("b") + "\n")
    manual = make(kind="manual", submit_mode="manual", ai_on_platform="forbidden")
    monkeypatch.setattr(event, "current", lambda root=None: manual)
    code, _, err = run(capsys, "policy", "sweep", "5", "--auth", "x", "--candidates", str(cands), "--note", "n")
    assert code == 4 and "manual" in err
    prof = make(sweep={**AUTH, "interval_s": 0.0})     # the CLI runs on the real clock: no pacer wait
    adapter = Scripted(SubmitStatus.INCORRECT, SubmitStatus.CORRECT)
    monkeypatch.setattr(event, "current", lambda root=None: prof)
    mod = types.ModuleType("ctf.platform.ctfd")
    mod.make_adapter = lambda profile: adapter
    monkeypatch.setitem(sys.modules, "ctf.platform.ctfd", mod)
    code, _, err = run(capsys, "policy", "sweep", "5", "--auth", "deadbeef", "--candidates", str(cands), "--note", "n")
    assert code == 4 and "no authorization" in err and adapter.sent == []
    empty = tmp_path / "e.txt"
    empty.write_text("\n")
    code, _, err = run(capsys, "policy", "sweep", "5", "--auth", "x", "--candidates", str(empty), "--note", "n")
    assert code == 2 and "no candidate" in err
    rec = rules.EventRules(prof).authorize_sweep("5", 3, "player: go")
    code, out, _ = run(capsys, "policy", "sweep", "5", "--auth", rec["auth_id"], "--candidates", str(cands),
                       "--note", "two rotations")
    assert code == 0 and "accepted" in out and adapter.sent == [("5", flag("a")), ("5", flag("b"))]
