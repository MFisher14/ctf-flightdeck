"""B-221: the probe tier (ctf/probetier.py) and the wire class every probe goes out at.

The Day 28 shape: the Metadata base lacks one id, the proposer holds the correct candidate, and the release
minute is tight. No test here has a wall-clock upper bound (rule 16): the lane-lock tests wait on events
and on the flag file, with generous lower-bound-free timeouts only as a hang guard.
"""
import threading

import pytest

from ctf import lanelock, probetier as P
from ctf.event import WirePace
from ctf.platform import wire

DAY28 = dict(challenge_id="metadata-day-28", answer_ids=("d28-disk-001",), open_ids=("d28-disk-001",),
             options={"d28-disk-001": [("json_numbers_table_order", "[34]")]})
HANG_GUARD_S = 120.0     # only so a broken lock fails instead of hanging the suite; never a speed claim


def job(**kw):
    return P.ProbeJob(**{**DAY28, **kw})


# ------------------------------------------------------------------ classification

def test_day28_ready_clean_closing_probe_is_fixup():
    tier, why = P.classify(job())
    assert tier == P.FIXUP and "closes the base" in why


@pytest.mark.parametrize("kw, tier, why", [
    (dict(split=True), P.LOW, "split"),
    (dict(bad=True), P.LOW, "rejected or held"),
    (dict(split=True, bad=True), P.LOW, "split"),
    (dict(deadline=1_700_000_000.0), P.NORMAL, "deadline"),
    (dict(options={}), P.NORMAL, "no candidate built yet for d28-disk-001"),
    (dict(options={"d28-disk-001": []}), P.NORMAL, "no candidate"),
    (dict(open_ids=("d28-disk-001", "d28-hash-002")), P.NORMAL, "other ids stay open after it: d28-hash-002"),
    (dict(open_ids=()), P.NORMAL, "open ids are not given"),
])
def test_anything_short_of_ready_clean_closing_and_untimed_is_not_fixup(kw, tier, why):
    got, reason = P.classify(job(**kw))
    assert got == tier and why in reason


def test_a_job_of_several_ids_is_ready_only_when_every_id_has_a_candidate():
    two = dict(answer_ids=("a", "b"), open_ids=("a", "b"))
    assert P.classify(job(**two, options={"a": [("x", "1")], "b": [("y", "2")]}))[0] == P.FIXUP
    tier, why = P.classify(job(**two, options={"a": [("x", "1")]}))
    assert tier == P.NORMAL and why.endswith("for b")
    # a job may settle more than the base lacks (an id already unsure-answered): it still closes the base
    assert P.classify(job(answer_ids=("a", "b"), open_ids=("a",), options={"a": [("x", "1")], "b": [("y", "2")]}))[0] == P.FIXUP


def test_bad_jobs_are_refused_by_name():
    with pytest.raises(P.ProbeTierError, match="at least one answer id"):
        P.ProbeJob("cid", answer_ids=())
    with pytest.raises(P.ProbeTierError, match="names its challenge"):
        P.ProbeJob("", answer_ids=("a",))
    with pytest.raises(P.ProbeTierError, match=r"ids the job does not settle: \['z'\]"):
        P.ProbeJob("cid", answer_ids=("a",), options={"a": [("x", "1")], "z": [("y", "2")]})


def test_order_puts_fixup_first_and_keeps_order_within_a_tier():
    low1, normal1, fix1 = job(split=True, source="low1"), job(deadline=5.0, source="normal1"), job(source="fix1")
    normal2, fix2, low2 = job(options={}, source="normal2"), job(source="fix2"), job(bad=True, source="low2")
    got = [j.source for j in P.order([low1, normal1, fix1, normal2, fix2, low2])]
    assert got == ["fix1", "fix2", "normal1", "normal2", "low1", "low2"]
    assert P.order([]) == []


# ------------------------------------------------------------------ the wire class of a probe

def test_a_probe_submit_is_never_held_at_a_reads_place_in_a_tight_release_minute():
    """Day 28: the probe was the 47th request of the release minute and was held at a reads' tier. At the
    master's wire a submit is the priority class: it may use the reserve the reads leave."""
    pace = WirePace(per_minute=0, release_budget=50, reserve=4)
    anchor, now = 1000.0, 1012.0
    rows = [[anchor + i * 0.25, "metadata", wire.READ] for i in range(46)]   # 46 requests already in the window
    assert wire.op_class("submit") == wire.PRIORITY
    held, reason = wire.decide(pace, rows, now, lane="metadata", cls=wire.READ, anchors=[anchor])
    assert reason == "release" and held > 0                                  # a read is held here
    assert wire.decide(pace, rows, now, lane="metadata", cls=wire.op_class("submit"), anchors=[anchor]) == (0.0, None)


# ------------------------------------------------------------------ the lane turn

def _wait_for(pred, what):
    ev = threading.Event()
    for _ in range(int(HANG_GUARD_S / 0.01)):
        if pred():
            return
        ev.wait(0.01)
    pytest.fail(f"never saw: {what}")


def test_a_fixup_probe_makes_a_held_split_yield_the_lane(tmp_path):
    split = job(split=True, source="split")
    fixup = job(source="fixup")
    order, holding, released = [], threading.Event(), threading.Event()
    stop = P.stop_for(split, workdir=tmp_path, lane="metadata")
    assert stop is not None and stop() is False

    def held_split():
        with P.turn(split, workdir=tmp_path, lane="metadata") as tier:
            order.append(("split-start", tier))
            holding.set()
            for _ in range(int(HANG_GUARD_S / 0.005)):   # the split's sub-batch loop: stop is read between sends
                if stop():
                    order.append(("split-yields", tier))
                    break
                threading.Event().wait(0.005)
            else:
                order.append(("split-ran-out", tier))    # the flag never came: the fixup never asked for the lane
        released.set()

    def fixup_probe():
        holding.wait(HANG_GUARD_S)
        with P.turn(fixup, workdir=tmp_path, lane="metadata") as tier:
            order.append(("fixup-runs", tier, lanelock.promote_wanted(tmp_path, "metadata")))

    a = threading.Thread(target=held_split, daemon=True)
    b = threading.Thread(target=fixup_probe, daemon=True)
    a.start(), b.start()
    a.join(HANG_GUARD_S * 2), b.join(HANG_GUARD_S * 2)
    assert not a.is_alive() and not b.is_alive()
    assert order == [("split-start", P.LOW), ("split-yields", P.LOW), ("fixup-runs", P.FIXUP, False)]
    assert not lanelock.promote_wanted(tmp_path, "metadata")


def test_a_normal_probe_waits_without_raising_the_flag(tmp_path):
    normal = job(open_ids=("d28-disk-001", "other"))
    assert P.classify(normal)[0] == P.NORMAL
    started, done = threading.Event(), threading.Event()
    with lanelock.lane_lock(tmp_path, "metadata"):
        def waiter():
            started.set()
            with P.turn(normal, workdir=tmp_path, lane="metadata"):
                done.set()
        t = threading.Thread(target=waiter)
        t.start()
        started.wait(HANG_GUARD_S)
        # A fixup turn raises the flag before it blocks (the next test); a normal one must not, ever.
        for _ in range(50):
            assert not lanelock.promote_wanted(tmp_path, "metadata")
            assert not done.is_set()
            threading.Event().wait(0.01)
    t.join(HANG_GUARD_S)
    assert done.is_set()


def test_a_fixup_probe_raises_the_flag_while_it_waits_and_clears_it(tmp_path):
    fixup = job()
    done = threading.Event()
    def waiter():
        with P.turn(fixup, workdir=tmp_path, lane="metadata"):
            done.set()

    with lanelock.lane_lock(tmp_path, "metadata"):
        t = threading.Thread(target=waiter, daemon=True)
        t.start()
        _wait_for(lambda: lanelock.promote_wanted(tmp_path, "metadata"), "the promote-wanted flag")
        assert not done.is_set()
    t.join(HANG_GUARD_S)
    assert done.is_set() and not lanelock.promote_wanted(tmp_path, "metadata")


def _in_thread(fn):
    """Run fn in a thread while this one holds the lane: a turn that waits when it should raise fails the
    test after HANG_GUARD_S instead of deadlocking the suite. Re-raises what fn raised."""
    out = []

    def run():
        try:
            fn()
        except BaseException as e:      # noqa: BLE001  (handed back to the test thread)
            out.append(e)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(HANG_GUARD_S)
    if t.is_alive():
        pytest.fail("the turn waited on the held lane instead of raising")
    if out:
        raise out[0]


def test_a_non_blocking_turn_on_a_held_lane_raises_and_leaves_no_flag(tmp_path):
    def nb(j):
        with P.turn(j, workdir=tmp_path, lane="metadata", blocking=False):
            pass

    with lanelock.lane_lock(tmp_path, "metadata"):
        for j in (job(), job(bad=True)):
            with pytest.raises(BlockingIOError):
                _in_thread(lambda: nb(j))
            assert not lanelock.promote_wanted(tmp_path, "metadata")


def test_on_wait_is_called_once_only_when_the_turn_waits_on_a_held_lane(tmp_path):
    for j in (job(), job(bad=True)):                    # a fixup turn, then a low one
        calls = []
        with P.turn(j, workdir=tmp_path, lane="metadata", on_wait=lambda: calls.append("free")):
            pass
        assert calls == []                              # a free lane: no wait, no notice
        def nb():
            with P.turn(j, workdir=tmp_path, lane="metadata", blocking=False, on_wait=lambda: calls.append("nb")):
                pass
        with lanelock.lane_lock(tmp_path, "metadata"):
            with pytest.raises(BlockingIOError):
                _in_thread(nb)
        assert calls == []                              # not blocking: it raises, it never waits
        entered, notified = threading.Event(), threading.Event()

        def on_wait():
            calls.append(("waits", lanelock.promote_wanted(tmp_path, "metadata")))
            notified.set()

        def waiter():
            with P.turn(j, workdir=tmp_path, lane="metadata", on_wait=on_wait):
                entered.set()

        with lanelock.lane_lock(tmp_path, "metadata"):
            t = threading.Thread(target=waiter, daemon=True)
            t.start()
            assert notified.wait(HANG_GUARD_S)
            assert not entered.is_set()                 # the notice comes before the turn, while it waits
        t.join(HANG_GUARD_S)
        assert entered.is_set()
        # the fixup's flag is already up when it says it waits; a low turn never raises it
        assert calls == [("waits", P.classify(j)[0] == P.FIXUP)]
        assert not lanelock.promote_wanted(tmp_path, "metadata")


def test_stop_for_by_tier(tmp_path):
    assert P.stop_for(job(), workdir=tmp_path, lane="metadata") is None              # fixup never yields
    assert P.stop_for(job(deadline=9.0), workdir=tmp_path, lane="metadata") is None  # a timed job never reads the flag
    held_normal = P.stop_for(job(options={}), workdir=tmp_path, lane="metadata")
    held_low = P.stop_for(job(bad=True), workdir=tmp_path, lane="metadata")
    assert held_normal() is False and held_low() is False
    lanelock.set_promote_wanted(tmp_path, "metadata", "fixup-probe")
    assert held_normal() is True and held_low() is True
    other = P.stop_for(job(bad=True), workdir=tmp_path, lane="binary")
    assert other() is False                                                         # the flag is per lane
