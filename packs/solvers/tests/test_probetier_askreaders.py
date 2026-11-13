"""B-221: the probe tier's caller, `ctf ask-readers probe` (B-139), and askreaders.probe's `stop`.

The CLI builds its job from the ask report (probetier.job_from_report), sends under the lane lock at the
job's tier (probetier.turn) and passes probetier.stop_for as askreaders.probe's stop. The Game Master is
the fake one test_askreaders starts on 127.0.0.1; the delivered file is test_askreaders_lanes's synthetic
PE. No test here has a wall-clock bound.
"""
from __future__ import annotations

import io
import json
import sys
import threading
from types import SimpleNamespace

import pytest

from ctf import askreaders as ar
from ctf import cli, lanelock, paths
from ctf import probetier as P

from test_askreaders import FakeGM, huntress_at
from test_probetier import HANG_GUARD_S
from test_askreaders_lanes import case, work  # noqa: F401  (fixtures)

LANE = "metadata"
_EVENTS_ROOT = paths.events_root


def _cli_probe(tmp, monkeypatch, gm_key, *, answers=True, extra=(), gm=None):
    for name in ("CTF_TOKEN", "CTF_PLATFORM_URL"):
        monkeypatch.delenv(name, raising=False)
    gm = gm or FakeGM()
    try:
        monkeypatch.setattr(paths, "events_root", _EVENTS_ROOT)     # a second run here: the real profile again
        n = 0
        while (tmp / f"gm{n}").exists():
            n += 1
        profile = huntress_at(tmp / f"gm{n}", gm.url)
        monkeypatch.setattr(paths, "events_root", lambda: profile.path.parent.parent)
        gm.key["metadata-day-09"] = gm_key
        argv = ["ask-readers", "probe", "--lane", LANE, "--challenge", "metadata-day-09", "--event", "huntress",
                "--questions", str(tmp / "questions.json"), "--files", str(tmp / "files"), "--json"]
        if answers:
            argv += ["--answers", str(tmp / "answers.json")]
        code = cli.main(argv + list(extra))
        posts = list(gm.posts)
    finally:
        gm.close()
    return code, posts


def _report(qs, tmp, answers):
    return ar.ask_missing(qs, answers, {"sample.exe": (tmp / "files" / "sample.exe").read_bytes()}, LANE)


# ------------------------------------------------------------------ job_from_report

def test_job_from_report_settles_the_offers_and_opens_every_missing_id(case):
    tmp, qs = case
    closing = _report(qs, tmp, {qs[0]["qid"]: None, qs[1]["qid"]: "banked"})
    job = P.job_from_report(closing, "metadata-day-09")
    (offer,) = closing.offers()
    assert job.answer_ids == (qs[0]["qid"],) and job.open_ids == (qs[0]["qid"],)
    assert job.options[qs[0]["qid"]] == list(ar.labels_module().parse(offer.offer).options)
    assert P.classify(job)[0] == P.FIXUP
    open_left = _report(qs, tmp, {})                       # pe.bogus_thing stops: it stays open after the job
    job = P.job_from_report(open_left, "metadata-day-09")
    assert job.answer_ids == (qs[0]["qid"],) and job.open_ids == (qs[0]["qid"], qs[1]["qid"])
    assert P.classify(job) == (P.NORMAL, f"other ids stay open after it: {qs[1]['qid']}")
    nothing = _report([qs[1]], tmp, {})
    with pytest.raises(P.ProbeTierError, match="at least one answer id"):
        P.job_from_report(nothing, "metadata-day-09")


# ------------------------------------------------------------------ askreaders.probe's stop

def test_probe_stops_sending_once_stop_is_true(case):
    tmp, qs = case
    rep = _report([qs[0]], tmp, {})
    (offer,) = rep.offers()
    n_options = len(ar.labels_module().parse(offer.offer).options)
    assert n_options >= 3
    sent = []

    def submit(answer_id, value):
        sent.append(value)
        return SimpleNamespace(accepted=False, status=SimpleNamespace(judged=True, value="incorrect"), message="no")

    reads = []

    def stop():
        reads.append(len(sent))
        return len(sent) >= 2

    probes = ar.probe(rep, submit, stop=stop)
    assert len(sent) == 2 and reads == [0, 1, 2]           # read before each send, never again once yielded
    assert [p.status for p in probes] == ["rejected", "rejected"] + ["not_probed"] * (n_options - 2)
    assert {p.message for p in probes[2:]} == {"yielded the lane"}
    sent.clear(), reads.clear()
    early = ar.probe(rep, submit, stop=lambda: stop() or len(sent) >= 1)       # yields after one send
    assert len(sent) == 1 and reads == [0, 1] and early[0].status == "rejected"
    assert {p.message for p in early[1:]} == {"yielded the lane"}
    sent.clear(), reads.clear()

    def unjudged(answer_id, value):                        # a held answer holds the rest: stop is not read
        sent.append(value)
        return SimpleNamespace(accepted=False, status=SimpleNamespace(judged=False, value="rate_limited"), message="wait")

    held = ar.probe(rep, unjudged, stop=stop)
    assert len(sent) == 1 and reads == [0] and {p.message for p in held[1:]} == {"held"}
    sent.clear()                                           # an option over max_per_id was never to be sent:
    capped = ar.probe(rep, submit, max_per_id=1, stop=lambda: len(sent) >= 1)   # it is not a yield
    assert len(sent) == 1 and {p.message for p in capped[1:]} == {"over max_per_id 1"}
    sent.clear()
    assert len(ar.probe(rep, submit, stop=lambda: False)) == n_options and len(sent) == n_options
    sent.clear()
    assert len(ar.probe(rep, submit)) == n_options and len(sent) == n_options       # no stop: never yields


# ------------------------------------------------------------------ the CLI under the lane lock

def test_cli_fixup_probe_sends_under_the_lane_lock_without_a_stop(case, work, monkeypatch, capsys):
    tmp, qs = case
    real, seen = ar.probe, []

    def watching(rep, submit, **kw):
        try:
            with lanelock.lane_lock(work, LANE, blocking=False):
                held = False
        except BlockingIOError:
            held = True
        seen.append((held, kw.get("stop"), lanelock.promote_wanted(work, LANE)))
        return real(rep, submit, **kw)

    monkeypatch.setattr(ar, "probe", watching)
    code, posts = _cli_probe(tmp, monkeypatch, {qs[0]["qid"]: "34404"})
    rep = json.loads(capsys.readouterr().out)
    assert code == 0 and rep["probe_tier"][0] == P.FIXUP
    assert seen == [(True, None, False)]                   # lock held, a fixup never yields, its flag cleared
    assert [p["value"] for p in rep["probes"] if p["status"] == "accepted"] == ["34404"]
    with lanelock.lane_lock(work, LANE, blocking=False):   # released afterwards
        pass


def test_cli_normal_probe_yields_the_lane_to_a_waiting_fixup(case, work, monkeypatch, capsys):
    """No --answers: pe.bogus_thing is MISSING with no offer, so the job is normal. A fixup is waiting (the
    flag is up): the probe takes the free lock and stops before its first send."""
    tmp, qs = case
    lanelock.set_promote_wanted(work, LANE, "fixup-probe:other")
    code, posts = _cli_probe(tmp, monkeypatch, {qs[0]["qid"]: "34404"}, answers=False)
    rep = json.loads(capsys.readouterr().out)
    assert rep["probe_tier"][0] == P.NORMAL and "other ids stay open" in rep["probe_tier"][1]
    assert posts == [] and rep["probes"]
    assert {(p["status"], p["message"]) for p in rep["probes"]} == {("not_probed", "yielded the lane")}
    assert code == 1


def test_cli_normal_probe_sends_when_no_fixup_waits(case, work, monkeypatch, capsys):
    tmp, qs = case
    code, posts = _cli_probe(tmp, monkeypatch, {qs[0]["qid"]: "34404"}, answers=False)
    rep = json.loads(capsys.readouterr().out)
    assert rep["probe_tier"][0] == P.NORMAL
    assert posts and [p["value"] for p in rep["probes"] if p["status"] == "accepted"] == ["34404"]
    assert code == 1                                        # pe.bogus_thing is still open


# ------------------------------------------------------------------ the CLI on a lane another job holds

class _Tap(io.StringIO):
    """sys.stderr for the CLI: sets `seen` once the waiting line is written, so the holder below releases
    the lane only after the CLI has said it waits (no sleep, no wall-clock bound in the assertion)."""

    def __init__(self):
        super().__init__()
        self.seen = threading.Event()

    def write(self, text):
        n = super().write(text)
        if "is held; waiting for it" in self.getvalue():
            self.seen.set()
        return n


def _held_lane_probe(tmp, work, monkeypatch, gm_key, *, answers, extra=()):
    """Run `ask-readers probe` while a thread holds the lane lock. The holder releases once the CLI's
    waiting line is on stderr, or once the CLI has returned, or after HANG_GUARD_S (so a broken CLI fails
    instead of hanging the suite), and
    records what it saw while it still held the lane: the flag, and the posts the Game Master had."""
    gm, tap = FakeGM(), _Tap()
    monkeypatch.setattr(sys, "stderr", tap)
    holding, finished, at_release = threading.Event(), threading.Event(), {}

    def holder():
        with lanelock.lane_lock(work, LANE):
            holding.set()
            for _ in range(int(HANG_GUARD_S / 0.01)):   # a hang guard only: a CLI that waits silently
                if tap.seen.is_set() or finished.is_set():  # fails here (said_waiting False), never deadlocks
                    break
                tap.seen.wait(0.01)
            at_release.update(flag=lanelock.promote_wanted(work, LANE), posts=list(gm.posts),
                              said_waiting=tap.seen.is_set())

    t = threading.Thread(target=holder, daemon=True)
    t.start()
    assert holding.wait(HANG_GUARD_S)
    try:
        code, posts = _cli_probe(tmp, monkeypatch, gm_key, answers=answers, gm=gm, extra=extra)
    finally:
        finished.set()
        t.join(HANG_GUARD_S)
    assert not t.is_alive()
    return code, posts, at_release, tap.getvalue()


def test_cli_fixup_probe_waits_for_a_held_lane_with_the_flag_up_then_sends(case, work, monkeypatch, capsys):
    """Day 28: the fixup probe finds the lane held. It says so on stderr, keeps the promote-wanted flag up
    while it waits (what makes a held split hand the lane over), sends nothing until the holder releases,
    then sends and is accepted; the flag is down afterwards."""
    tmp, qs = case
    code, posts, at_release, err = _held_lane_probe(tmp, work, monkeypatch, {qs[0]["qid"]: "34404"}, answers=True)
    rep = json.loads(capsys.readouterr().out)
    assert at_release == {"flag": True, "posts": [], "said_waiting": True}
    assert f"lane {LANE} is held; waiting for it at the fixup tier with the promote-wanted flag up" in err
    assert code == 0 and rep["probe_tier"][0] == P.FIXUP
    assert posts and [p["value"] for p in rep["probes"] if p["status"] == "accepted"] == ["34404"]
    assert not lanelock.promote_wanted(work, LANE)


def test_cli_normal_probe_waits_for_a_held_lane_without_the_flag(case, work, monkeypatch, capsys):
    tmp, qs = case
    code, posts, at_release, err = _held_lane_probe(tmp, work, monkeypatch, {qs[0]["qid"]: "34404"}, answers=False)
    rep = json.loads(capsys.readouterr().out)
    assert at_release == {"flag": False, "posts": [], "said_waiting": True}
    assert f"lane {LANE} is held; waiting for it at the normal tier\n" in err and "promote-wanted" not in err
    assert rep["probe_tier"][0] == P.NORMAL
    assert posts and [p["value"] for p in rep["probes"] if p["status"] == "accepted"] == ["34404"]
    assert code == 1                                        # pe.bogus_thing is still open


def test_cli_probe_on_a_free_lane_says_nothing_about_waiting(case, work, monkeypatch, capsys):
    tmp, qs = case
    code, posts = _cli_probe(tmp, monkeypatch, {qs[0]["qid"]: "34404"})
    captured = capsys.readouterr()
    assert code == 0 and posts and "waiting" not in captured.err


def test_cli_no_wait_on_a_held_lane_exits_2_and_sends_nothing(case, work, monkeypatch, capsys):
    """The lane is held by another thread (released only once the CLI says it waits, or has returned), so a
    --no-wait that waited anyway would send and exit 0 here instead of hanging the test."""
    tmp, qs = case
    for answers in (True, False):                           # the fixup job, then the normal one
        code, posts, at_release, err = _held_lane_probe(tmp, work, monkeypatch, {qs[0]["qid"]: "34404"},
                                                        answers=answers, extra=["--no-wait"])
        assert code == 2 and posts == [] and capsys.readouterr().out == ""
        assert at_release == {"flag": False, "posts": [], "said_waiting": False}
        assert f"lane {LANE} is held by another job and --no-wait was given; nothing was sent" in err
        assert "waiting for it" not in err
        assert not lanelock.promote_wanted(work, LANE)
    code, posts = _cli_probe(tmp, monkeypatch, {qs[0]["qid"]: "34404"}, extra=["--no-wait"])
    assert code == 0 and posts                              # a free lane: --no-wait changes nothing
