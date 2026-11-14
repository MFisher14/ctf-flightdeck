"""Huntress backlog row 485 (Day 23 Script Mastery): the set pool serves a Mastery with MORE sets than
workers, with no deadlock and no lost set.

The pool was carried into ctf/adapt/setpool.py by B-036 (the Huntress timed_ladder.py that first held it
needs the archived Game Master client and cannot be imported in the master; these tests used to be
reported not run for that reason, and this file used to call sys.exit at import). No network and no
token. Before the fix, `k % len(workers)` queued two sets down one worker's pipe, so a fast set sat out
a slow one; the queue hands a worker its next set only once it has answered the last. A set that is
genuinely too slow still falls to the serial path, so no set is lost.
"""
from __future__ import annotations

import multiprocessing
import os
import threading
import time

import pytest

from ctf.adapt import setpool as P


class Timed:
    """Answers with the wall time the set finished; set `slow` takes `slow_s`, the others `fast_s`."""

    def __init__(self, slow=None, slow_s=1.0, fast_s=0.05):
        self.slow, self.slow_s, self.fast_s = slow, slow_s, fast_s

    def solve_set(self, qs, files, ctx):
        time.sleep(self.slow_s if ctx["set"] == self.slow else self.fast_s)
        return {q["qid"]: f"{ctx['set']}@{time.time():.6f}" for q in qs}


class Gated:
    """Answers with completion ORDER (a shared counter), not wall time, so the finish order this test
    asserts is deterministic and load-independent — no wall-clock race that inverts under xdist load.

    The slow set returns only once every fast set has recorded done, so it is always last. The mechanism
    under test still decides the outcome: a fast set queued behind the slow set on the same worker (the
    old `k % workers` bug) would never run while the slow set holds that worker, the fast counter would
    never complete, and the slow set would return on its safety ceiling with that fast set still missing
    or finishing after it — the order assertion then fails loudly rather than flaking.

    Built on fork-shared multiprocessing values: the workers are forked and inherit this solver, so the
    counter and the order sequence are shared between the parent and every worker without pickling.
    """

    def __init__(self, slow, nfast, mp_ctx, ceiling):
        self.slow, self.nfast, self.ceiling = slow, nfast, ceiling
        self.done = mp_ctx.Value("i", 0)   # fast sets that have finished
        self.seq = mp_ctx.Value("i", 0)    # a monotonically increasing completion-order counter

    def solve_set(self, qs, files, ctx):
        n = ctx["set"]
        if n == self.slow:
            # Wall-clock safety ceiling for the FAILURE case only (rule 16): on success the gate opens
            # the instant the fast counter reaches nfast (a few pipe round trips). It never bounds the
            # measured order; it only stops a genuinely queued-behind bug from hanging the suite. The
            # test sets it, below the pool wait it also sets.
            end = time.monotonic() + self.ceiling
            while self.done.value < self.nfast and time.monotonic() < end:
                time.sleep(0.01)
        with self.seq.get_lock():
            self.seq.value += 1
            order = self.seq.value
        if n != self.slow:
            with self.done.get_lock():
                self.done.value += 1
        return {q["qid"]: f"{n}@{order}" for q in qs}


def sets(n):
    return [(s, [{"qid": "q", "answer_id": f"set{s}.q"}], {}, {"set": s}) for s in range(1, n + 1)]


def run(solver, n, budget, workers=6, deadline=True):
    pool = P.SetPool(solver, workers=workers)
    errors, notes = [], []
    t0 = time.perf_counter()
    try:
        out = pool.solve_sets(sets(n), budget, errors, notes, deadline=deadline)
    finally:
        pool.close()
    return out, time.perf_counter() - t0, errors, notes


@pytest.mark.parametrize("nsets", [7, 13])
def test_more_sets_than_workers_no_deadline(nsets):
    out, dt, errors, notes = run(Timed(), nsets, None, deadline=False)
    assert sorted(int(k[3:-2]) for k in out.raw) == list(range(1, nsets + 1)), "every set solved (no lost set)"
    assert out.pooled == list(range(1, nsets + 1)) and out.serial == [], f"all by the workers: {notes}"
    assert dt < 30.0, f"finished (no deadlock) in {dt:.1f}s"
    assert notes[-1].startswith(f"set pool: {nsets} of {nsets} sets solved by workers")


def test_a_fast_set_never_waits_behind_a_slow_one(monkeypatch):
    # 2 workers, set 1 slow. Dealt k % workers, sets 3 and 5 would queue behind set 1 on worker 0 and
    # finish after it; fed one at a time, every fast set is answered by the other worker before the slow
    # one returns. Finish ORDER is a shared completion counter, not wall time, so the assertion holds at
    # any load (see Gated) rather than racing real sleeps that invert under xdist.
    # The only wall-clock limits left are two ceilings for the failure case (rule 16): the slow set gives
    # up on the fast ones after 60 s, inside a pool wait raised from its 20 s default to 120 s. Four fast
    # round trips take ~0.02 s at load 55-120, so neither is near at any load this machine reaches; a
    # real queued-behind bug takes 60 s to report.
    monkeypatch.setattr(P, "POOL_UNTIMED_WAIT_MAX", 120.0)
    mp_ctx = multiprocessing.get_context("fork")
    solver = Gated(slow=1, nfast=4, mp_ctx=mp_ctx, ceiling=60.0)
    out, dt, errors, notes = run(solver, 5, None, workers=2, deadline=False)
    done = {int(k[3:-2]): float(v.split("@")[1]) for k, v in out.raw.items()}
    assert sorted(done) == [1, 2, 3, 4, 5] and out.serial == []
    assert all(done[s] < done[1] for s in (2, 3, 4, 5)), f"finish order {done}"


def test_deadline_budget_loses_no_set():
    out, dt, errors, notes = run(Timed(), 7, 3.0)
    assert sorted(int(k[3:-2]) for k in out.raw) == list(range(1, 8))


class DiesOn:
    """Kills its own worker process on set `bad` (only in a forked worker, never in the parent)."""

    def __init__(self, bad, parent):
        self.bad, self.parent = bad, parent

    def solve_set(self, qs, files, ctx):
        if ctx["set"] == self.bad and os.getpid() != self.parent:
            os._exit(7)
        return {q["qid"]: f"v{ctx['set']}" for q in qs}


def test_a_dead_worker_s_set_is_solved_serially():
    out, dt, errors, notes = run(DiesOn(3, os.getpid()), 6, 4.0, workers=3)
    assert sorted(out.raw) == [f"set{s}.q" for s in range(1, 7)] and out.raw["set3.q"] == "v3"
    assert 3 in out.serial and 3 not in out.pooled
    assert "set 3 solved here instead" in notes[-1]


class HangsOn:
    def __init__(self, bad):
        self.bad = bad

    def solve_set(self, qs, files, ctx):
        if ctx["set"] == self.bad:
            ctx["partial"][qs[0]["qid"]] = "early"
            while True:
                time.sleep(0.01)
        return {q["qid"]: f"v{ctx['set']}" for q in qs}


def test_a_hung_set_falls_to_the_serial_path_and_keeps_its_partial():
    out, dt, errors, notes = run(HangsOn(2), 4, 2.0, workers=4)
    assert out.pooled == [1, 3, 4] and out.serial == [2]
    assert out.raw["set2.q"] == "early" and out.timed_out
    assert dt < 2.0 + 1.5, f"the hung set cost only the budget ({dt:.2f}s)"


def test_maybe_refuses_to_fork_beside_another_thread():
    notes = []
    stop = threading.Event()
    t = threading.Thread(target=stop.wait, daemon=True)
    t.start()
    try:
        assert P.SetPool.maybe(Timed(), 5, notes) is None
    finally:
        stop.set()
        t.join()
    assert "another thread is running" in notes[0]
    assert P.SetPool.maybe(Timed(), 1, []) is None, "one set needs no pool"


def test_maybe_also_sees_a_thread_threading_does_not_list():
    import _thread
    go, started = threading.Event(), threading.Event()

    def raw():
        started.set()
        go.wait()
    _thread.start_new_thread(raw, ())
    started.wait(5)
    notes = []
    try:
        assert threading.active_count() == 1, "the raw thread is invisible to threading"
        assert P.SetPool.maybe(Timed(), 5, notes) is None
    finally:
        go.set()
    assert "another thread is running" in notes[0]


def test_worker_count_and_budget_scale_with_the_sets():
    assert P.workers_for(3) == P.POOL_WORKERS
    assert P.workers_for(9) == 11 and P.workers_for(40) == P.POOL_WORKERS_MAX
    assert P.solve_budget(7) == pytest.approx(7 * P.LADDER_CAP), "no deadline: a share for every set"
    assert P.solve_budget(2, deliveries=9) == pytest.approx(9 * P.LADDER_CAP)
    assert P.solve_budget(0) == pytest.approx(P.LADDER_CAP)
    assert P.pool_wait(None, True) == P.POOL_WAIT_MAX and P.pool_wait(None, False) == P.POOL_UNTIMED_WAIT_MAX
    assert P.pool_wait(3.0) == pytest.approx(1.5) and P.pool_wait(100.0) == P.POOL_WAIT_MAX
    assert P.pool_wait(0.1) == pytest.approx(0.2)
