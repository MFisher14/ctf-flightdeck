"""B-141: the live per-lane lock and the promote-wanted flag."""
from __future__ import annotations

import threading

import pytest

from ctf import lanelock


# --------------------------------------------------------------------------- the flag

def test_flag_lifecycle(tmp_path):
    assert lanelock.promote_wanted(tmp_path, "metadata") is False
    path = lanelock.set_promote_wanted(tmp_path, "metadata", "fix")
    assert path.exists()
    assert lanelock.promote_wanted(tmp_path, "metadata") is True
    lanelock.clear_promote_wanted(tmp_path, "metadata")
    assert lanelock.promote_wanted(tmp_path, "metadata") is False


def test_clear_is_idempotent(tmp_path):
    # Clearing a flag that was never raised is not an error.
    lanelock.clear_promote_wanted(tmp_path, "metadata")
    assert lanelock.promote_wanted(tmp_path, "metadata") is False


def test_flag_is_per_lane(tmp_path):
    lanelock.set_promote_wanted(tmp_path, "metadata", "fix")
    assert lanelock.promote_wanted(tmp_path, "metadata") is True
    assert lanelock.promote_wanted(tmp_path, "binary") is False


def test_bad_lane_name_is_loud(tmp_path):
    with pytest.raises(lanelock.LaneLockError):
        lanelock.lock_path(tmp_path, "../escape")
    with pytest.raises(lanelock.LaneLockError):
        lanelock.set_promote_wanted(tmp_path, "a/b", "x")


# --------------------------------------------------------------------------- the lock

def test_lock_is_reentrant_after_release(tmp_path):
    with lanelock.lane_lock(tmp_path, "metadata"):
        pass
    # A second acquisition after release must succeed (the fd was closed, the lock dropped).
    with lanelock.lane_lock(tmp_path, "metadata", blocking=False):
        pass


def test_lock_is_exclusive_across_threads(tmp_path):
    # If the lock really serialises, no two threads are ever inside the critical section at once.
    # This fails loudly (overlap recorded) if lane_lock does not actually lock -- no wall-clock bound.
    state = {"inside": 0, "max": 0}
    overlaps: list[int] = []
    plain = []   # a list mutated under the lock without its own lock: corrupts if the lock is a no-op

    def worker(tag):
        for _ in range(40):
            with lanelock.lane_lock(tmp_path, "metadata"):
                state["inside"] += 1
                state["max"] = max(state["max"], state["inside"])
                if state["inside"] != 1:
                    overlaps.append(state["inside"])
                # a read-modify-write that a no-op lock would let race
                n = len(plain)
                plain.append(n)
                state["inside"] -= 1

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert overlaps == []
    assert state["max"] == 1
    assert plain == list(range(len(plain)))   # no lost updates


def test_nonblocking_lock_raises_when_held(tmp_path):
    held = threading.Event()
    release = threading.Event()
    result = {}

    def holder():
        with lanelock.lane_lock(tmp_path, "metadata"):
            held.set()
            release.wait(5)

    t = threading.Thread(target=holder)
    t.start()
    assert held.wait(5)
    try:
        with lanelock.lane_lock(tmp_path, "metadata", blocking=False):
            result["got"] = True
    except BlockingIOError:
        result["got"] = False
    finally:
        release.set()
        t.join()
    assert result["got"] is False


# --------------------------------------------------------------------------- promote_waiting

def test_promote_waiting_clears_flag_after_acquiring(tmp_path):
    # Inside the block the lock is held and the flag is down again; after the block the flag stays down.
    with lanelock.promote_waiting(tmp_path, "metadata", agent="fix"):
        assert lanelock.promote_wanted(tmp_path, "metadata") is False
        # the lane lock is held, so a non-blocking acquisition fails
        with pytest.raises(BlockingIOError):
            with lanelock.lane_lock(tmp_path, "metadata", blocking=False):
                pass
    assert lanelock.promote_wanted(tmp_path, "metadata") is False


def test_promote_waiting_raises_the_flag_while_blocked(tmp_path):
    # While a promoter waits for a held lane, the flag is up -- this is the signal a held no-deadline
    # bisect reads to yield. Hold the lane in another thread, start the promoter, and observe the flag.
    held = threading.Event()
    release = threading.Event()
    promoted = threading.Event()

    def promoter():
        with lanelock.promote_waiting(tmp_path, "metadata", agent="fix"):
            promoted.set()

    def holder():
        with lanelock.lane_lock(tmp_path, "metadata"):
            held.set()
            # wait until the flag the promoter raises becomes visible, then release
            for _ in range(500):
                if lanelock.promote_wanted(tmp_path, "metadata"):
                    break
                release.wait(0.01)
            flag_seen.append(lanelock.promote_wanted(tmp_path, "metadata"))

    flag_seen: list[bool] = []
    h = threading.Thread(target=holder)
    h.start()
    assert held.wait(5)
    p = threading.Thread(target=promoter)
    p.start()
    h.join(10)
    assert promoted.wait(10)
    p.join(10)
    assert flag_seen == [True]                       # the promoter's flag was up while it waited
    assert lanelock.promote_wanted(tmp_path, "metadata") is False   # cleared when it got the lock


# --------------------------------------------------------------------------- yield_stop

def test_yield_stop_deadline_is_none(tmp_path):
    # A deadline attempt never reads the flag: yield_stop returns None.
    lanelock.set_promote_wanted(tmp_path, "metadata", "fix")
    assert lanelock.yield_stop(tmp_path, "metadata", deadline=True) is None


def test_yield_stop_no_deadline_tracks_flag(tmp_path):
    stop = lanelock.yield_stop(tmp_path, "metadata", deadline=False)
    assert stop() is False
    lanelock.set_promote_wanted(tmp_path, "metadata", "fix")
    assert stop() is True
    lanelock.clear_promote_wanted(tmp_path, "metadata")
    assert stop() is False
