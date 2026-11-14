"""Offline coverage for ctf.submit.guarded_submit — the race-critical, rule-critical submit path.

These tests never touch the network. A fake CTFd records every submit() call so we can assert the
guards that keep us inside the event rules (no brute-forcing, no flooding) actually prevent a send:
bad-format, skip-solved, duplicate dedupe, the 3-wrong-then-ask stop, and dry-run. They also lock the
dynamic-flag carve-out (count_wrong=False records a rotating miss as `stale`, and only ctf.dynamic may
pass it), the OSINT carve-out (allow_nonstandard), the counted per-challenge player approval past the
wrong guard, the unjudged-verdict dedupe fix, and the machine-wide submit pacing in ctf.client.

The challenge is the REAL ctf.workspace.Challenge in a temp folder. The config is the REAL loaded Config
(so submit_wrong_limit is the value we run with) with the flag format INJECTED: the fixture flags are
built from $CTF_TEST_FLAG_PREFIX (default TESTCTF), never from one event's literal.
"""
from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from ctf import client as C
from ctf import submit as S
from ctf import workspace as W
from ctf.client import Submission
from ctf import flagfmt
from ctf.config import Config, load as load_cfg
from ctf import event as E
from ctf.event import FlagSpec

REPO = Path(__file__).resolve().parent.parent
FLAG_PREFIX = os.environ.get("CTF_TEST_FLAG_PREFIX", "TESTCTF")


def flag(body: str) -> str:
    return f"{FLAG_PREFIX}{{{body}}}"


def make_cfg() -> Config:
    cfg = load_cfg()
    cfg.flags = flagfmt.FlagFormat(FlagSpec(prefixes=(FLAG_PREFIX,), body=r"[^}\n]{1,256}"))
    return cfg


GOOD = flag("t3st_Fl4g")

# The event the fake client acts for. R-02: guarded_submit and solve_dynamic read the client's
# `profile` and refuse a manual event, so the fake carries a CTFd event that allows auto-submit.
AUTO_PROFILE = E.parse({
    "slug": "submit-guard-auto", "name": "submit guard test event",
    "dates": {"start": datetime.date(2026, 1, 1), "end": datetime.date(2026, 12, 31)},
    "platform": {"kind": "ctfd", "base_url": "https://board.submit-guard.test"},
    "flag": {"prefixes": [FLAG_PREFIX]},
    "rules": {"submit_mode": "auto", "flag_sharing": "allowed", "ai_on_platform": "allowed"},
}, src="tests/test_submit_guard.py")


class FakeCTFd:
    """Scripted CTFd: pops a queued Submission per submit() and records the (cid, flag) sent.
    `cfg` defaults to the plain loaded Config (tests/test_dynamic_rotation.py imports this class);
    the tests here pass the injected-format config through `fake()`. `profile` is the event the
    client acts for (default AUTO_PROFILE)."""

    def __init__(self, responses: list[Submission] | None = None, cfg: Config | None = None,
                 profile: E.EventProfile = AUTO_PROFILE) -> None:
        self.cfg = cfg or load_cfg()
        self.profile = profile
        self._responses = list(responses or [])
        self.sent: list[tuple[int, str]] = []

    def submit(self, cid: int, flag: str) -> Submission:
        self.sent.append((cid, flag))
        if self._responses:
            return self._responses.pop(0)
        return Submission(status="incorrect", message="nope")


def fake(responses: list[Submission] | None = None) -> FakeCTFd:
    return FakeCTFd(responses, cfg=make_cfg())


class FakeChallenge:
    """In-memory stand-in for ctf.workspace.Challenge with the methods guarded_submit uses.
    Kept for tests/test_dynamic_rotation.py; the tests in this file use the real Challenge."""

    def __init__(self, cid: int = 101) -> None:
        self.cid = cid
        self.attempts: list[tuple[str, str]] = []   # (flag, recorded-status)
        self.notes: list[str] = []
        self.solved_with: str | None = None
        self.approvals_left = 0

    def record_attempt(self, flag: str, status: str) -> None:
        self.attempts.append((flag, status))

    def already_tried(self, flag: str) -> bool:
        return any(f == flag and st not in W.UNJUDGED_STATUSES for f, st in self.attempts)

    def wrong_count(self) -> int:
        return sum(1 for _, st in self.attempts if st == "incorrect")

    def post_guard_approvals_left(self) -> int:
        return self.approvals_left

    def consume_post_guard_approval(self, flag: str, provenance: str = "") -> None:
        self.approvals_left -= 1

    def mark_solved(self, flag: str) -> None:
        self.solved_with = flag

    def note(self, line: str) -> None:
        self.notes.append(line)


@pytest.fixture
def ch(tmp_path) -> W.Challenge:
    d = tmp_path / "101-test"
    d.mkdir()
    return W.Challenge(cid=101, name="test", category="misc", dir=d)


def attempts(ch: W.Challenge) -> list[tuple[str, str]]:
    return [(a["flag"], a["status"]) for a in ch.load_tried()["attempts"]]


def notes(ch: W.Challenge) -> str:
    return ch.notes_path.read_text(encoding="utf-8") if ch.notes_path.exists() else ""


def trip_guard(ch: W.Challenge) -> int:
    maxw = make_cfg().submit_wrong_limit
    for i in range(maxw):
        ch.record_attempt(flag(f"wrong_{i}"), "incorrect")
    assert ch.wrong_count() == maxw
    return maxw


def test_injected_flag_format_is_what_the_guard_checks():
    cfg = make_cfg()
    assert cfg.looks_like_flag(GOOD)
    assert not cfg.looks_like_flag(GOOD.replace("{", "[").replace("}", "]"))
    assert not cfg.looks_like_flag(FLAG_PREFIX + "{}")


def test_bad_format_is_never_sent(ch):
    ctfd = fake()
    res = S.guarded_submit(ctfd, ch, "totally not a flag", provenance="unit")
    assert res.status == "bad-format" and res.submitted is False
    assert ctfd.sent == [], "a format-mismatch candidate must never reach the API"
    assert not ch.solved()


def test_allow_nonstandard_lets_reasoned_osint_value_through(ch):
    ctfd = fake([Submission("correct", "nice")])
    res = S.guarded_submit(ctfd, ch, "47.1585, 27.6014", provenance="osint-pin",
                           allow_nonstandard=True)
    assert res.correct and res.submitted is True
    assert ctfd.sent == [(101, "47.1585, 27.6014")]


def test_skip_already_solved_by_team_does_not_submit(ch):
    ctfd = fake([Submission("correct", "x")])
    res = S.guarded_submit(ctfd, ch, GOOD, team_solved={101})
    assert res.status == "skipped-solved" and res.submitted is False
    assert ctfd.sent == [], "never race a teammate's solved challenge"
    assert ch.flag_path.read_text().strip() == GOOD


def test_duplicate_flag_is_not_resent(ch):
    ctfd = fake([Submission("incorrect", "no")])
    ch.record_attempt(GOOD, "incorrect")           # already tried once
    res = S.guarded_submit(ctfd, ch, GOOD)
    assert res.status == "duplicate" and res.submitted is False
    assert ctfd.sent == [], "one try per distinct value — no re-send"


@pytest.mark.parametrize("status", ["ratelimited", "paused", "authentication_required"])
def test_unjudged_attempt_does_not_block_a_resend(ch, status):
    # Wave 1: a rate-limited flag was locked out as a "duplicate" though CTFd never judged it.
    ch.record_attempt(GOOD, status)
    ctfd = fake([Submission("correct", "ok")])
    res = S.guarded_submit(ctfd, ch, GOOD)
    assert res.correct and ctfd.sent == [(101, GOOD)]


def test_three_wrong_then_ask_blocks_further_sends(ch):
    trip_guard(ch)
    ctfd = fake([Submission("correct", "would-be")])
    res = S.guarded_submit(ctfd, ch, GOOD)
    assert res.status == "blocked-maxwrong" and res.submitted is False
    assert ctfd.sent == [], "the 3-wrong guard is the line against brute-forcing — it must stop the send"


def test_dry_run_allow_false_checks_but_never_sends(ch):
    ctfd = fake([Submission("correct", "x")])
    res = S.guarded_submit(ctfd, ch, GOOD, allow=False)
    assert res.status == "not-submitted" and res.submitted is False
    assert ctfd.sent == []


def test_correct_flag_marks_solved_and_records(ch):
    ctfd = fake([Submission("correct", "great")])
    res = S.guarded_submit(ctfd, ch, GOOD, provenance="xor-decode")
    assert res.correct and res.submitted is True
    assert ctfd.sent == [(101, GOOD)]
    assert ch.flag_path.read_text().strip() == GOOD
    assert attempts(ch) == [(GOOD, "correct")]


def test_incorrect_counts_toward_guard_by_default(ch):
    ctfd = fake([Submission("incorrect", "no")])
    res = S.guarded_submit(ctfd, ch, GOOD)
    assert res.status == "incorrect" and res.submitted is True
    assert ch.wrong_count() == 1, "a real wrong answer must count toward the 3-wrong guard"


# ---------------------------------------------------------------- dynamic-flag carve-out
def test_count_wrong_false_outside_dynamic_path_is_refused(ch):
    # Solver scripts passed count_wrong=False on static challenges to walk past the guard.
    trip_guard(ch)
    ctfd = fake([Submission("correct", "x")])
    with pytest.raises(ValueError, match="dynamic-flag path"):
        S.guarded_submit(ctfd, ch, GOOD, count_wrong=False)
    assert ctfd.sent == []


# B-006: ctf.dynamic now submits through the gate (rotating=True), not guarded_submit; the rotating
# carve-out is tested in tests/test_dynamic_rotation.py and tests/test_submit_queue.py.


def test_guard_holds_across_a_sequence_no_brute_force(ch):
    maxw = make_cfg().submit_wrong_limit
    ctfd = fake([Submission("incorrect", "no") for _ in range(maxw)])
    for i in range(maxw):
        r = S.guarded_submit(ctfd, ch, flag(f"try_{i}"))
        assert r.submitted is True
    assert len(ctfd.sent) == maxw and ch.wrong_count() == maxw
    blocked = S.guarded_submit(ctfd, ch, flag("one_more"))
    assert blocked.status == "blocked-maxwrong"
    assert len(ctfd.sent) == maxw, "no further API calls after the guard trips"


# ---------------------------------------------------------------- player approval past the guard
def test_authorization_flag_without_a_recorded_approval_stays_blocked(ch):
    trip_guard(ch)
    ctfd = fake([Submission("correct", "x")])
    res = S.guarded_submit(ctfd, ch, GOOD, human_authorized_after_maxwrong=True)
    assert res.status == "blocked-maxwrong" and res.submitted is False
    assert ctfd.sent == []


def test_explicit_human_authorization_allows_one_post_guard_send(ch):
    trip_guard(ch)
    ch.grant_post_guard_approval("player approved one more reasoned candidate", count=1)
    ctfd = fake([Submission("incorrect", "no"), Submission("correct", "x")])

    res = S.guarded_submit(
        ctfd, ch, GOOD,
        provenance="player explicitly approved this one post-guard candidate",
        human_authorized_after_maxwrong=True,
    )
    assert res.submitted is True and ctfd.sent == [(101, GOOD)]
    assert "PLAYER-AUTHORIZED" in notes(ch)
    assert ch.post_guard_approvals_left() == 0
    used = [r for r in ch.load_tried()["approvals"] if r["kind"] == "use"]
    assert [r["flag"] for r in used] == [GOOD], "the spend is logged with the flag it unlocked"

    # The approval was for ONE send: the next candidate is blocked again.
    again = S.guarded_submit(ctfd, ch, flag("second"), human_authorized_after_maxwrong=True)
    assert again.status == "blocked-maxwrong" and len(ctfd.sent) == 1


def test_approval_count_and_unjudged_verdict_do_not_spend_it(ch):
    trip_guard(ch)
    ch.grant_post_guard_approval("player: two more", count=2)
    ctfd = fake([Submission("ratelimited", "slow down"),
                     Submission("incorrect", "no"),
                     Submission("incorrect", "no")])
    r1 = S.guarded_submit(ctfd, ch, flag("a"), human_authorized_after_maxwrong=True)
    assert r1.status == "ratelimited" and ch.post_guard_approvals_left() == 2
    S.guarded_submit(ctfd, ch, flag("a"), human_authorized_after_maxwrong=True)   # re-send allowed
    S.guarded_submit(ctfd, ch, flag("b"), human_authorized_after_maxwrong=True)
    assert ch.post_guard_approvals_left() == 0 and len(ctfd.sent) == 3
    r4 = S.guarded_submit(ctfd, ch, flag("c"), human_authorized_after_maxwrong=True)
    assert r4.status == "blocked-maxwrong" and len(ctfd.sent) == 3


def test_dry_run_does_not_spend_an_approval(ch):
    trip_guard(ch)
    ch.grant_post_guard_approval("player ok", count=1)
    ctfd = fake()
    res = S.guarded_submit(ctfd, ch, GOOD, allow=False, human_authorized_after_maxwrong=True)
    assert res.status == "not-submitted" and ch.post_guard_approvals_left() == 1


def test_approval_requires_a_reason(ch):
    with pytest.raises(ValueError):
        ch.grant_post_guard_approval("   ")
    with pytest.raises(ValueError):
        ch.grant_post_guard_approval("ok", count=0)


def test_cli_approve_records_a_gate_approval_in_the_ledger(tmp_path, monkeypatch, capsys):
    # B-006: `python -m ctf.submit approve` writes the submit gate's approval (a ledger record the
    # wrong-answer stop reads), not tried.json, which only the legacy guarded_submit reads.
    from ctf.platform.rules import EventRules
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(E, "current", lambda root=None: AUTO_PROFILE)
    assert S.main(["approve", "202", "--reason", "player said one more", "--count", "2"]) == 0
    assert EventRules(AUTO_PROFILE, tmp_path).approvals_left("202") == 2
    assert "unused now: 2" in capsys.readouterr().out
    assert not (tmp_path / "202-some-chal").exists()


def test_cli_approve_without_a_reason_fails_loudly(tmp_path, monkeypatch, capsys):
    from ctf.platform.rules import EventRules
    monkeypatch.setenv("CTF_WORKDIR", str(tmp_path))
    monkeypatch.setattr(E, "current", lambda root=None: AUTO_PROFILE)
    assert S.main(["approve", "999", "--reason", "  "]) == 2
    assert "needs a reason" in capsys.readouterr().err
    assert EventRules(AUTO_PROFILE, tmp_path).approvals_granted("999") == 0


# ---------------------------------------------------------------- machine-wide submit pacing
class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t
        self.slept: list[float] = []

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.slept.append(s)
        self.t += s


def test_pacer_state_is_shared_between_instances(tmp_path):
    clk = FakeClock()
    a = C.SubmitPacer("https://ctf.example", 3.0, state_dir=tmp_path, sleep=clk.sleep, clock=clk)
    b = C.SubmitPacer("https://ctf.example/", 3.0, state_dir=tmp_path, sleep=clk.sleep, clock=clk)
    with a.slot() as s:
        s.record("incorrect")
    with b.slot() as s:              # a second "process": must wait out a's interval
        s.record("correct")
    assert clk.slept and abs(sum(clk.slept) - 3.0) < 1e-9


def test_pacer_ratelimit_pauses_every_instance(tmp_path):
    clk = FakeClock()
    a = C.SubmitPacer("https://ctf.example", 1.0, state_dir=tmp_path, sleep=clk.sleep, clock=clk)
    b = C.SubmitPacer("https://ctf.example", 1.0, state_dir=tmp_path, sleep=clk.sleep, clock=clk)
    with a.slot() as s:
        s.record("ratelimited")
    with b.slot():
        pass
    assert sum(clk.slept) >= C.RATELIMIT_PAUSE_S


def test_pacer_unusable_state_dir_fails_loudly(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    with pytest.raises(C.CTFdError, match="unpaced"):
        C.SubmitPacer("https://ctf.example", 1.0, state_dir=blocker / "sub")


def test_client_submit_goes_through_the_shared_pacer(tmp_path, monkeypatch):
    monkeypatch.setenv(C.SUBMIT_STATE_ENV, str(tmp_path / "pace"))
    cfg = Config(base_url="https://ctf.example", token=None, team_id=None, workdir=tmp_path, cookie=None)
    c = C.CTFd(cfg, profile=AUTO_PROFILE)
    monkeypatch.setattr(c, "_post", lambda path, json: {"data": {"status": "ratelimited",
                                                                   "message": "too fast"}})
    sub = c.submit(1, "x")
    assert sub.status == "ratelimited"
    state = json.loads(c.pacer.state_path.read_text())
    assert state["blocked_until"] > state["last_submit"], "a rate limit must pause the other processes"


_WORKER = textwrap.dedent("""
    import json, sys, time
    from pathlib import Path
    from ctf.client import SubmitPacer
    p = SubmitPacer("https://ctf.example", float(sys.argv[2]), state_dir=Path(sys.argv[1]))
    out = []
    for _ in range(int(sys.argv[3])):
        with p.slot() as s:
            out.append(time.time())
            s.record("incorrect")
    print(json.dumps(out))
""")


def test_pacer_spaces_submits_across_real_processes(tmp_path):
    interval, per_proc = 0.25, 3
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    procs = [subprocess.Popen([sys.executable, "-c", _WORKER, str(tmp_path), str(interval), str(per_proc)],
                              stdout=subprocess.PIPE, text=True, env=env, cwd=str(tmp_path))
             for _ in range(3)]
    stamps = []
    for p in procs:
        out, _ = p.communicate(timeout=60)
        assert p.returncode == 0
        stamps += json.loads(out)
    stamps.sort()
    assert len(stamps) == 3 * per_proc
    gaps = [b - a for a, b in zip(stamps, stamps[1:])]
    assert min(gaps) >= interval - 0.02, f"processes did not pace each other: {gaps}"
