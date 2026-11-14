"""B-006: the cross-process submit queue (ctf/platform/queue.py) behind the submit gate.

The adapter is a test double for the platform; the gate, the event rules, the queue, the ledger and
the lock files are real. Time is a fake clock unless a test runs real processes, where the point is
that separate processes share one queue.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from ctf import event, ledger
from ctf.platform import SubmitGate, SubmitStatus, queue, rules
from ctf.platform.base import SubmitResult
from ctf.platform.policy import SubmitRequest
from ctf.platform.queue import QueueError, SubmitQueue

REPO = Path(__file__).resolve().parent.parent
PREFIX = "SQTEST"


def flag(body: str) -> str:
    return f"{PREFIX}{{{body}}}"


PROFILE_TOML = """
slug = "{slug}"
name = "submit queue test"
dates = {{ start = 2026-01-01, end = 2026-12-31 }}

[platform]
kind = "ctfd"
base_url = "https://board.submit-queue.test"

[flag]
prefixes = ["{prefix}"]

[rules]
submit_mode = "auto"
flag_sharing = "{sharing}"
ai_on_platform = "allowed"
wrong_answer_stop = {stop}

[submit]
per_minute = {per_minute}
interval_s = {interval}
per_challenge_interval_s = {per_ch}
max_hold_s = {hold}
"""


def write_profile(root: Path, *, slug="sq-test", sharing="allowed", stop=3, per_minute=100,
                  interval=0.0, per_ch=0.0, hold=600.0, rotating_budget=None) -> Path:
    d = root / "profiles" / slug
    d.mkdir(parents=True, exist_ok=True)
    text = PROFILE_TOML.format(
        slug=slug, prefix=PREFIX, sharing=sharing, stop=stop, per_minute=per_minute,
        interval=float(interval), per_ch=float(per_ch), hold=float(hold))
    if rotating_budget is not None:
        text += f"rotating_miss_budget = {rotating_budget}\n"
    (d / "event.toml").write_text(text, encoding="utf-8")
    return d / "event.toml"


def make_profile(tmp_path: Path, **kw) -> event.EventProfile:
    return event.load_path(write_profile(tmp_path, **kw), expect_slug=kw.get("slug", "sq-test"))


class Clock:
    def __init__(self, t: float = 1_000_000.0):
        self.t = t
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(round(s, 6))
        self.t += s


class ScriptedAdapter:
    """Answers each submit with the next scripted status or SubmitResult (default: incorrect)."""
    kind = "ctfd"

    def __init__(self, *answers, clock: Clock | None = None):
        self.answers = list(answers)
        self.sent: list[tuple[str, str]] = []
        self.sent_at: list[float] = []
        self.clock = clock

    def submit(self, challenge_id, flag):
        self.sent.append((challenge_id, flag))
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


def gate_for(prof, adapter, work, clock):
    g = SubmitGate(adapter, prof)
    rules.install(g, work)
    queue.install(g, work, clock=clock, sleep=clock.sleep)
    return g


def records(work, kind="platform.submit"):
    return [r for r in ledger.read(work) if r["event"] == kind]


# ------------------------------------------------------------------------------- submit on sight
def test_idle_queue_sends_at_once_and_records(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path, interval=1, per_ch=3), a, work, clock)
    res = g.submit("5", flag("first"), provenance="xor of body")
    assert res.accepted and res.sent
    assert clock.slept == [], "an idle queue must not hold a flag"
    assert a.sent == [("5", flag("first"))]
    [done] = records(work, queue.DONE_EVENT)
    assert done["attempts"] == 1 and done["held_s"] == 0 and done["status"] == "correct"
    assert not list((work / "submitq" / "pending").iterdir()), "a judged send leaves no spool"


def test_interval_spaces_any_two_sends(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.CORRECT, SubmitStatus.CORRECT, clock=clock)
    g = gate_for(make_profile(tmp_path, interval=1.5), a, work, clock)
    g.submit("1", flag("a"), provenance="p")
    g.submit("2", flag("b"), provenance="p")
    assert clock.slept == [1.5]
    assert a.sent_at[1] - a.sent_at[0] == pytest.approx(1.5)


def test_per_challenge_spacing_only_holds_that_challenge(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(clock=clock)
    g = gate_for(make_profile(tmp_path, per_ch=3), a, work, clock)
    g.submit("1", flag("a"), provenance="p")
    g.submit("2", flag("b"), provenance="p")          # another challenge: no wait
    assert clock.slept == []
    g.submit("1", flag("c"), provenance="p")          # same challenge: 3 s after the first
    assert clock.slept == [3.0]
    assert a.sent_at == [clock.t - 3.0, clock.t - 3.0, clock.t]


def test_team_budget_per_minute(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(*[SubmitStatus.CORRECT] * 4, clock=clock)
    g = gate_for(make_profile(tmp_path, per_minute=3), a, work, clock)
    for i in range(3):
        g.submit(str(i), flag(f"v{i}"), provenance="p")
        clock.t += 5
    assert clock.slept == []
    g.submit("9", flag("v9"), provenance="p")
    # the first of the three went 15 s ago: the fourth waits until it leaves the 60 s window
    assert clock.slept == [45.0]
    assert a.sent_at[3] - a.sent_at[0] == pytest.approx(60.0)


def test_budget_is_shared_between_queue_instances(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path, per_minute=2)
    a1, a2 = ScriptedAdapter(*[SubmitStatus.CORRECT] * 2), ScriptedAdapter(SubmitStatus.CORRECT)
    g1, g2 = gate_for(prof, a1, work, clock), gate_for(prof, a2, work, clock)
    g1.submit("1", flag("a"), provenance="p")
    g1.submit("2", flag("b"), provenance="p")
    g2.submit("3", flag("c"), provenance="p")         # another process's queue object, same state
    assert clock.slept == [60.0]


# ------------------------------------------------------------------------------- automatic retry
def test_rate_limited_answer_is_retried_automatically(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.RATE_LIMITED, SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path), a, work, clock)
    res = g.submit("5", flag("x"), provenance="p")
    assert res.status is SubmitStatus.CORRECT
    assert a.sent == [("5", flag("x"))] * 2
    assert clock.slept == [queue.RATELIMIT_PAUSE_S]
    assert [r["status"] for r in records(work)] == ["rate_limited", "correct"]
    assert records(work, queue.DONE_EVENT)[0]["attempts"] == 2


def test_retry_after_from_the_platform_is_honoured(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitResult(SubmitStatus.RATE_LIMITED, retry_after=7.0), SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path), a, work, clock)
    assert g.submit("5", flag("x"), provenance="p").accepted
    assert clock.slept == [7.0]


def test_backoff_doubles_up_to_the_cap(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(*[SubmitStatus.RATE_LIMITED] * 5, SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path, hold=10_000), a, work, clock)
    assert g.submit("5", flag("x"), provenance="p").accepted
    assert clock.slept == [20.0, 40.0, 80.0, 120.0, 120.0]
    clock.t += 500
    g.submit("6", flag("y"), provenance="p")          # a judged answer reset the backoff
    a.answers = [SubmitStatus.RATE_LIMITED, SubmitStatus.CORRECT]
    clock.slept.clear()
    g.submit("7", flag("z"), provenance="p")
    assert clock.slept == [20.0]


def test_paused_answer_is_retried(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.PAUSED, SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path), a, work, clock)
    assert g.submit("5", flag("x"), provenance="p").accepted
    assert clock.slept == [queue.PAUSED_WAIT_S]


def test_a_rate_limit_pauses_every_process(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path, hold=0)
    a1 = ScriptedAdapter(SubmitStatus.RATE_LIMITED)
    a2 = ScriptedAdapter(SubmitStatus.CORRECT, clock=clock)
    g1 = gate_for(prof, a1, work, clock)
    res = g1.submit("1", flag("a"), provenance="p")
    assert res.status is SubmitStatus.RATE_LIMITED and res.sent and "left queued" in res.message
    g2 = gate_for(make_profile(tmp_path / "b"), a2, work, clock)   # same event, own hold budget
    t0 = clock.t
    assert g2.submit("2", flag("b"), provenance="p").accepted
    assert a2.sent_at == [t0 + queue.RATELIMIT_PAUSE_S], "the other process waited out the pause"


def test_unjudged_past_max_hold_stays_queued_and_drain_sends_it(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path, hold=70)
    a = ScriptedAdapter(*[SubmitStatus.RATE_LIMITED] * 3)
    g = gate_for(prof, a, work, clock)
    res = g.submit("5", flag("held"), provenance="strings")
    assert res.status is SubmitStatus.RATE_LIMITED and res.sent
    # sends at +0, +20, +60; the third pause (80 s) would end past the 70 s hold
    assert len(a.sent) == 3 and clock.slept == [20.0, 40.0]
    assert "rate_limited 3 time(s)" in res.message and res.retry_after == pytest.approx(80.0)
    [p] = g.queue.pending()
    assert p["state"] == "orphaned" and p["flag"] == flag("held") and p["provenance"] == "strings"
    assert records(work, queue.DONE_EVENT)[-1]["queued"] is True
    clock.t += 200
    a2 = ScriptedAdapter(SubmitStatus.CORRECT)
    g2 = gate_for(prof, a2, work, clock)
    [(rec, out)] = g2.queue.drain(g2)
    assert rec["challenge_id"] == "5" and out.accepted
    assert a2.sent == [("5", flag("held"))]
    assert g2.queue.pending() == [] and g2.queue.drain(g2) == []


def test_turn_past_the_hold_is_queued_without_a_send(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path, per_minute=1, hold=10)
    a = ScriptedAdapter(SubmitStatus.CORRECT)
    g = gate_for(prof, a, work, clock)
    g.submit("1", flag("a"), provenance="p")
    res = g.submit("2", flag("b"), provenance="p")
    assert res.status is SubmitStatus.RATE_LIMITED and not res.sent
    assert res.retry_after == pytest.approx(60.0) and "queued" in res.message
    assert len(a.sent) == 1 and clock.slept == []
    assert [p["challenge_id"] for p in g.queue.pending()] == ["2"]


def test_an_in_flight_spool_is_not_drained(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path)
    seen = {}

    class Peek(ScriptedAdapter):
        def submit(self, cid, f):
            # while this call is in flight, another process looks at the queue
            other = SubmitQueue(prof, workdir=work, clock=clock, sleep=clock.sleep)
            seen["pending"] = [p["state"] for p in other.pending()]
            seen["drained"] = other.drain(g)
            return super().submit(cid, f)
    a = Peek(SubmitStatus.CORRECT)
    g = gate_for(prof, a, work, clock)
    assert g.submit("5", flag("x"), provenance="p").accepted
    assert seen == {"pending": ["in_flight"], "drained": []}
    assert len(a.sent) == 1


def test_a_send_that_raises_stays_queued_with_an_error_record_and_drain_resends_it(tmp_path, work):
    from ctf.platform import PlatformError
    clock = Clock()
    prof = make_profile(tmp_path, sharing="forbidden")
    g = gate_for(prof, ScriptedAdapter(PlatformError("submit: POST /challenges/attempt failed (Timeout)")),
                 work, clock)
    with pytest.raises(PlatformError, match="POST /challenges/attempt failed") as info:
        g.submit("5", flag("lost"), provenance="strings")
    assert any("submit-queue drain" in n for n in info.value.__notes__)
    [p] = g.queue.pending()
    assert p["state"] == "orphaned" and p["challenge_id"] == "5" and p["flag"] == flag("lost")
    [rec] = records(work)
    assert rec["status"] == queue.ERROR_STATUS and rec["judged"] is False
    assert "Timeout" in rec["error"] and "lost" not in json.dumps(rec), "flag_sharing still applies"
    [done] = records(work, queue.DONE_EVENT)
    assert done["status"] == queue.ERROR_STATUS and done["queued"] is True and done["attempts"] == 1
    # an unjudged error counts toward nothing: not a duplicate, not a wrong answer
    assert rules.EventRules(prof, work).wrong_count("5") == 0
    a2 = ScriptedAdapter(SubmitStatus.CORRECT)
    g2 = gate_for(prof, a2, work, clock)
    [(_, out)] = g2.queue.drain(g2)
    assert out.accepted and a2.sent == [("5", flag("lost"))]
    assert g2.queue.pending() == []


def test_a_record_error_does_not_keep_the_spool(tmp_path, work):
    # The platform answered (the value was judged); only the ledger write failed: no resend.
    from ctf.platform.policy import RecordError
    clock = Clock()
    g = gate_for(make_profile(tmp_path), ScriptedAdapter(SubmitStatus.CORRECT), work, clock)

    def broken(profile, req, result):
        raise OSError("disk full")
    g.add_observer(broken)
    with pytest.raises(RecordError, match="disk full"):
        g.submit("5", flag("x"), provenance="p")
    assert g.queue.pending() == []


def test_corrupt_spool_fails_loudly(tmp_path, work):
    clock = Clock()
    g = gate_for(make_profile(tmp_path), ScriptedAdapter(), work, clock)
    pend = work / "submitq" / "pending"
    pend.mkdir(parents=True)
    (pend / "bad.json").write_text("{not json")
    with pytest.raises(QueueError, match="bad.json"):
        g.queue.drain(g)


# ------------------------------------------------------------------------------- dedupe
def test_a_judged_value_is_never_resent(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.INCORRECT)
    g = gate_for(make_profile(tmp_path), a, work, clock)
    assert g.submit("5", flag("x"), provenance="p").status is SubmitStatus.INCORRECT
    res = g.submit("5", f"  {flag('x')} ", provenance="again")
    assert res.status is SubmitStatus.NOT_ALLOWED and not res.sent
    assert res.message.startswith(queue.DUPLICATE) and "incorrect" in res.message
    assert len(a.sent) == 1
    assert g.submit("6", flag("x"), provenance="p").sent, "the same value on another challenge is new"


def test_an_unjudged_value_may_be_sent_again(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.RATE_LIMITED, SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path, hold=0), a, work, clock)
    assert g.submit("5", flag("x"), provenance="p").status is SubmitStatus.RATE_LIMITED
    clock.t += 100
    assert g.submit("5", flag("x"), provenance="p").accepted
    assert len(a.sent) == 2


def test_an_already_solved_answer_blocks_later_sends(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.ALREADY_SOLVED)
    g = gate_for(make_profile(tmp_path), a, work, clock)
    assert g.submit("5", flag("teammates"), provenance="p").status is SubmitStatus.ALREADY_SOLVED
    res = g.submit("5", flag("another"), provenance="p")
    assert res.message.startswith(queue.SOLVED) and "already_solved" in res.message
    assert not res.sent and len(a.sent) == 1


def test_nothing_is_sent_on_an_accepted_challenge(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path), a, work, clock)
    g.submit("5", flag("right"), provenance="p")
    res = g.submit("5", flag("other"), provenance="p")
    assert res.message.startswith(queue.SOLVED) and not res.sent and len(a.sent) == 1


def test_an_accepted_answer_does_not_block_the_next_answer_id(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.CORRECT, SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path), a, work, clock)
    g.submit("chal-1#a", flag("one"), provenance="p")
    assert g.submit("chal-1#b", flag("two"), provenance="p").accepted
    assert g.submit("chal-1#a", flag("three"), provenance="p").message.startswith(queue.SOLVED)


def test_dedupe_works_from_the_hash_when_flags_stay_in_the_team(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.INCORRECT)
    g = gate_for(make_profile(tmp_path, sharing="forbidden"), a, work, clock)
    g.submit("5", flag("secret"), provenance="p")
    assert "secret" not in (work / "ledger.jsonl").read_text()
    assert g.submit("5", flag("secret"), provenance="p").message.startswith(queue.DUPLICATE)
    assert len(a.sent) == 1


# ------------------------------------------------------------------------------- the wrong-answer stop
def _trip(g, n=3):
    for i in range(n):
        assert g.submit("5", flag(f"w{i}"), provenance="p").status is SubmitStatus.INCORRECT


def test_confirmed_alone_does_not_pass_the_stop(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter()
    g = gate_for(make_profile(tmp_path), a, work, clock)
    _trip(g)
    plain = g.submit("5", flag("w3"), provenance="p")
    assert "wrong_answer_stop" in plain.message and "submit-queue approve 5" in plain.message
    res = g.submit("5", flag("w3"), provenance="p", confirmed=True)
    assert not res.sent and "no unused player approval" in res.message
    assert len(a.sent) == 3


def test_a_counted_approval_lets_exactly_that_many_confirmed_sends_through(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path)
    a = ScriptedAdapter()
    g = gate_for(prof, a, work, clock)
    _trip(g)
    er = rules.EventRules(prof, work)
    er.grant("5", "player: one more, from the second key", count=2)
    assert er.approvals_left("5") == 2
    assert not g.submit("5", flag("w3"), provenance="p").sent, "the approval still needs confirmed=True"
    assert g.submit("5", flag("w3"), provenance="p", confirmed=True).status is SubmitStatus.INCORRECT
    assert g.submit("5", flag("w4"), provenance="p", confirmed=True).status is SubmitStatus.INCORRECT
    assert er.approvals_left("5") == 0
    assert "no unused player approval" in g.submit("5", flag("w5"), provenance="p", confirmed=True).message
    assert len(a.sent) == 5
    assert [r["post_stop"] for r in records(work)] == [False, False, False, True, True]


def test_an_unjudged_send_does_not_spend_an_approval(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path, hold=0)
    a = ScriptedAdapter(*[SubmitStatus.INCORRECT] * 3, SubmitStatus.RATE_LIMITED, SubmitStatus.CORRECT)
    g = gate_for(prof, a, work, clock)
    _trip(g)
    rules.EventRules(prof, work).grant("5", "player ok", 1)
    assert g.submit("5", flag("w3"), provenance="p", confirmed=True).status is SubmitStatus.RATE_LIMITED
    assert rules.EventRules(prof, work).approvals_left("5") == 1
    clock.t += 100
    assert g.submit("5", flag("w3"), provenance="p", confirmed=True).accepted


def test_an_approval_is_per_challenge_and_per_event(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path)
    g = gate_for(prof, ScriptedAdapter(), work, clock)
    _trip(g)
    rules.EventRules(prof, work).grant("6", "for another challenge", 1)
    ledger.append(rules.APPROVAL, workdir=work, event_slug="other-event", challenge_id="5", count=3,
                  reason="x")
    assert not g.submit("5", flag("w3"), provenance="p", confirmed=True).sent


@pytest.mark.parametrize("reason, count", [("", 1), ("   ", 1), ("ok", 0), ("ok", -2), ("ok", True)])
def test_an_approval_needs_a_reason_and_a_positive_count(tmp_path, work, reason, count):
    er = rules.EventRules(make_profile(tmp_path), work)
    with pytest.raises(ValueError):
        er.grant("5", reason, count)
    assert er.approvals_granted("5") == 0


# ------------------------------------------------------------------------------- rotating flags
def test_rotating_is_reserved_for_ctf_dynamic(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter()
    g = gate_for(make_profile(tmp_path), a, work, clock)
    with pytest.raises(ValueError, match="reserved for the rotating-flag path"):
        g.submit("5", flag("x"), provenance="p", rotating=True)
    assert a.sent == []


def _rotating(cid, value):
    return SubmitRequest(cid, value, "dynamic fetch", rotating=True)


def test_a_rotating_flag_is_never_spooled(tmp_path, work):
    clock = Clock()
    prof = make_profile(tmp_path, hold=0)
    seen = []

    class Peek(ScriptedAdapter):
        def submit(self, cid, f):
            seen.append(list((work / "submitq" / "pending").iterdir()))
            return super().submit(cid, f)
    a = Peek(SubmitStatus.RATE_LIMITED, SubmitStatus.RATE_LIMITED)
    g = gate_for(prof, a, work, clock)
    res = g.queue.submit(g, _rotating("5", flag("rot")))
    assert res.status is SubmitStatus.RATE_LIMITED and res.sent
    assert seen == [[]], "no spool file while the rotating send is in flight"
    assert g.queue.pending() == [] and "drain" not in res.message, "a dead rotating flag is never drained"
    # the same request, static: spooled while in flight and left queued for drain
    clock.t += 200                                     # past the shared pause the first answer set
    res = g.queue.submit(g, SubmitRequest("6", flag("static"), "p"))
    assert len(seen[1]) == 1 and "drain" in res.message and len(g.queue.pending()) == 1


def test_a_rotating_flag_whose_send_raises_is_not_spooled(tmp_path, work):
    from ctf.platform import PlatformError
    clock = Clock()
    g = gate_for(make_profile(tmp_path), ScriptedAdapter(PlatformError("submit: POST failed")), work, clock)
    with pytest.raises(PlatformError):
        g.queue.submit(g, _rotating("5", flag("rot")))
    assert g.queue.pending() == []
    assert records(work)[0]["rotating"] is True and records(work)[0]["status"] == queue.ERROR_STATUS


# ------------------------------------------------------------------------------- the challenge lock
def _hold_lock(q, cid):
    import fcntl
    q._mkdirs()
    fd = os.open(q._lock_path(cid), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def test_the_challenge_lock_is_free_while_a_call_waits_for_its_turn(tmp_path, work):
    import fcntl
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.INCORRECT, SubmitStatus.CORRECT, clock=clock)
    g = gate_for(make_profile(tmp_path, per_ch=3), a, work, clock)
    g.submit("5", flag("a"), provenance="p")
    probes = []

    def sleep(s):
        fd = os.open(g.queue._lock_path("5"), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            probes.append("free")
        except BlockingIOError:
            probes.append("held")
        finally:
            os.close(fd)
        clock.sleep(s)
    g.queue._sleep = sleep
    assert g.submit("5", flag("b"), provenance="p").accepted
    assert probes == ["free"], "a waiting call must not hold its challenge's lock"


def test_the_checks_run_again_after_a_wait(tmp_path, work):
    # While this call waits out the per-challenge spacing, a teammate's process gets the flag
    # accepted: the woken call is refused, not sent.
    clock = Clock()
    prof = make_profile(tmp_path, per_ch=3)
    a = ScriptedAdapter(SubmitStatus.INCORRECT, clock=clock)
    g = gate_for(prof, a, work, clock)
    g.submit("5", flag("a"), provenance="p")

    def sleep(s):
        rules.EventRules(prof, work).record(prof, SubmitRequest("5", flag("mate"), "teammate"),
                                            SubmitResult(SubmitStatus.CORRECT))
        clock.sleep(s)
    g.queue._sleep = sleep
    res = g.submit("5", flag("b"), provenance="p")
    assert res.message.startswith(queue.SOLVED) and not res.sent
    assert len(a.sent) == 1
    assert g.queue.pending() == []


def test_a_busy_challenge_lock_is_waited_for_only_until_the_deadline(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter(SubmitStatus.CORRECT)
    g = gate_for(make_profile(tmp_path, hold=1), a, work, clock)
    fd = _hold_lock(g.queue, "5")
    try:
        t0 = clock.t
        res = g.submit("5", flag("x"), provenance="p")
        waited = clock.t - t0
        rot = g.queue.submit(g, _rotating("5", flag("rot")))
    finally:
        os.close(fd)
    assert res.status is SubmitStatus.RATE_LIMITED and not res.sent and a.sent == []
    assert "challenge lock" in res.message and "drain" in res.message
    assert 1.0 <= waited < 1.1, "gave up at its own max_hold_s"
    assert rot.status is SubmitStatus.RATE_LIMITED and "drain" not in rot.message
    [p] = g.queue.pending()
    assert p["flag"] == flag("x") and p["state"] == "orphaned", "only the static request was spooled"
    [(_, out)] = g.queue.drain(g)
    assert out.accepted and a.sent == [("5", flag("x"))]


# ------------------------------------------------------------------------------- no state for a refusal
def test_a_refused_request_leaves_no_queue_state(tmp_path, work):
    clock = Clock()
    a = ScriptedAdapter()
    g = gate_for(make_profile(tmp_path), a, work, clock)
    assert not g.submit("5", "not a flag", provenance="p").sent
    assert not g.submit("5", flag("x"), provenance="").sent
    spooky = event.load("spooky")
    gs = SubmitGate(ScriptedAdapter(), spooky)
    rules.install(gs, work)
    queue.install(gs, work, clock=clock, sleep=clock.sleep)
    assert "manual" in gs.submit("1", "spooky{x}", provenance="p", confirmed=True).message
    assert not work.exists(), "a stateless refusal must not create the workdir, locks or a spool"
    assert a.sent == []


# ------------------------------------------------------------------------------- real processes
CHILD = textwrap.dedent("""
    import fcntl, json, sys, time
    sys.path.insert(0, sys.argv[1])
    from pathlib import Path
    from ctf import event
    from ctf.platform import SubmitGate, SubmitStatus, queue, rules
    from ctf.platform.base import SubmitResult
    profile_path, work, log, cid, value, start, slow, answer = sys.argv[2:10]
    prof = event.load_path(profile_path)

    class Adapter:
        kind = "ctfd"
        def submit(self, challenge_id, flag):
            with open(log, "a") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX)
                fh.write(json.dumps({"t": time.time(), "cid": challenge_id, "flag": flag}) + "\\n")
            time.sleep(float(slow))
            return SubmitResult(SubmitStatus(answer))
        def list_challenges(self): return []
        def get_challenge(self, cid): raise NotImplementedError
        def download_files(self, cid, dest): return []
        def team_solves(self): return []
        def scoreboard(self): return []

    gate = SubmitGate(Adapter(), prof)
    rules.install(gate, Path(work))
    queue.install(gate, Path(work))
    while time.time() < float(start):
        time.sleep(0.002)
    res = gate.submit(cid, value, provenance="child " + value)
    print(res.status.value, res.sent)
""")


def run_children(tmp_path, profile_path, work, jobs, *, slow=0.0, answer="incorrect"):
    script = tmp_path / "child_submit.py"
    script.write_text(CHILD, encoding="utf-8")
    log = tmp_path / "sends.log"
    start = time.time() + 4.0
    env = {k: v for k, v in os.environ.items() if k not in ("CTF_EVENT", "PYTHONPATH")}
    procs = [subprocess.Popen([sys.executable, "-I", str(script), str(REPO), str(profile_path), str(work),
                               str(log), cid, value, str(start), str(slow), answer],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
             for cid, value in jobs]
    outs = [p.communicate(timeout=120) for p in procs]
    for p, (out, err) in zip(procs, outs):
        assert p.returncode == 0, err[-2000:]
    sends = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
    return [o for o, _ in outs], sends


def test_wrong_answer_stop_is_atomic_across_processes(tmp_path):
    work = tmp_path / "work"
    prof = write_profile(tmp_path, stop=3)
    jobs = [("5", flag(f"proc{i}")) for i in range(6)]
    outs, sends = run_children(tmp_path, prof, work, jobs, slow=0.3)
    assert len(sends) == 3, f"exactly the 3 allowed wrong answers may be sent, got {len(sends)}"
    assert sum(o.startswith("incorrect") for o in outs) == 3
    assert sum(o.startswith("not_allowed") for o in outs) == 3


def test_pacing_holds_across_processes(tmp_path):
    work = tmp_path / "work"
    prof = write_profile(tmp_path, interval=0.4)
    jobs = [(str(i), flag(f"p{i}")) for i in range(4)]
    outs, sends = run_children(tmp_path, prof, work, jobs, answer="correct")
    assert len(sends) == 4 and all(o.startswith("correct") for o in outs)
    times = sorted(s["t"] for s in sends)
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert min(gaps) >= 0.35, f"sends from separate processes were not spaced: {gaps}"
