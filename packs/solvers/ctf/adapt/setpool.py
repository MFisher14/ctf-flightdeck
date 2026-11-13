"""The set pool of a multi-set timed attempt (B-036), free of any platform module.

Carried from the Huntress timed runner (solvers/script-analysis/timed_ladder.py: `solve`, `SetPool`,
`_pool_wait`, `solve_cap`), which needs the archived Game Master client and cannot be imported in the
master. The behaviour is the one its fixes earned:

  * **No deadlock when sets outnumber workers** (Huntress backlog row 485, Day 23 Script Mastery). Sets
    were dealt `k % workers`, so two went down one worker's pipe and the second sat out the first. The
    pool now hands a worker its next set only when it has answered the last (at most one in flight per
    worker), so every worker stays busy and nothing queues behind a slow set.
  * **The serial fallback always fires.** A set whose worker died, raised, timed out, was not back
    within the wait, or never got a worker is solved in the parent with what is left of the budget. No
    set is lost.
  * **Each set gets a share of the budget** (backlog row 163). One set that cannot be read in time loses
    only its own unanswered ids: its watchdog keeps back half a fair share for every set still to come,
    and the answers it had put into `ctx["partial"]` are taken.
  * **A no-deadline attempt gets a budget scaled to its set count** (Day 23 Binary Mastery):
    `solve_budget(sets, deliveries)` is `LADDER_CAP` per set or delivery, whichever is more.

    raw, timed_out, said = solve(solver, sets, budget, errors)          # the serial path
    pool = SetPool.maybe(solver, len(sets), notes)                       # None: solve serially
    run = pool.solve_sets(sets, budget, errors, notes); pool.close()     # PoolRun(raw, timed_out, said, pooled, serial)

`sets` is a list of `(n, questions, files, ctx)`: each question a dict with `qid` (what the solver
answers) and `answer_id` (what is sent); `ctx` the set's context (`set`, `delivery`, ...). The solver is
any object with `solve_set(questions, files, ctx) -> {qid: value}` that may fill `ctx["partial"]`.
Workers are forked (the solver is inherited, never pickled); `maybe` refuses to fork while another
thread runs, as fork with threads is unsafe, and says so in `notes`.
"""
from __future__ import annotations

import _thread
import contextlib
import io
import multiprocessing
import os
import signal
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field

from .. import deliveries

LADDER_CAP = 2.0          # the longest a solver runs per delivery or set, whichever is more (Huntress lanes.py)
LADDER_FLOOR = 0.05       # a solver is always given this long
POOL_WORKERS = 6          # the floor of forked workers
POOL_WORKERS_MAX = 12     # the most workers forked
POOL_WORKER_HEADROOM = 2  # workers above the set count
POOL_SHARE = 0.5          # of the solve budget the workers may use before the serial path takes over
POOL_WAIT_MAX = 4.0       # seconds the parent waits for its workers on an attempt with a deadline
POOL_UNTIMED_WAIT_MAX = 20.0   # ... and without one
POOL_MARGIN = 0.1         # a worker stops its solver this long before the parent stops waiting


class SolverTimeout(BaseException):
    """A set's time share ran out. A BaseException, so a solver's own `except Exception` cannot swallow it."""


class Watchdog:
    """Raise SolverTimeout in the main thread once `seconds` have passed (no-op when seconds is None or
    off the main thread). Repeats every 0.25 s, so a solver that swallows the first with a bare `except:`
    is interrupted again."""

    def __init__(self, seconds: float | None):
        self.seconds, self.armed, self.installed, self.previous = seconds, False, False, None

    def _fire(self, signum, frame):
        if self.armed:
            raise SolverTimeout()

    def __enter__(self):
        if (self.seconds is not None and hasattr(signal, "setitimer")
                and threading.current_thread() is threading.main_thread()):
            self.previous = signal.signal(signal.SIGALRM, self._fire)
            self.armed = self.installed = True
            signal.setitimer(signal.ITIMER_REAL, max(self.seconds, 0.01), 0.25)
        return self

    def __exit__(self, *exc):
        self.armed = False
        if self.installed:
            signal.setitimer(signal.ITIMER_REAL, 0)
            # not back to the default action: a stray late alarm would then kill the process
            signal.signal(signal.SIGALRM, self.previous if callable(self.previous) else signal.SIG_IGN)
            self.installed = False
        return False


def is_blank(value) -> bool:
    """A string that is empty once stripped is no answer: sent, it could only cost its batch."""
    return isinstance(value, str) and not value.strip()


def solve_budget(sets: int, deliveries: int = 1, per: float = LADDER_CAP) -> float:
    """The solve budget of an attempt with no deadline: `per` seconds for each set or each delivery,
    whichever is more, so a Mastery that grows a set a day is not cut at a one-set budget."""
    return float(per) * max(1, int(deliveries or 1), int(sets or 1))


def workers_for(sets: int) -> int:
    """Workers to fork for `sets` sets: the set count plus headroom, within [POOL_WORKERS, POOL_WORKERS_MAX]."""
    return max(POOL_WORKERS, min(POOL_WORKERS_MAX, int(sets) + POOL_WORKER_HEADROOM))


def pool_wait(budget: float | None, deadline: bool = True) -> float:
    """Seconds the parent waits for its workers: the budget's share, capped at POOL_WAIT_MAX with a
    deadline and POOL_UNTIMED_WAIT_MAX without one."""
    cap = POOL_WAIT_MAX if deadline else POOL_UNTIMED_WAIT_MAX
    return cap if budget is None else max(0.2, min(budget * POOL_SHARE, cap))


def solve(solver, sets, budget: float | None, errors: list) -> tuple[dict, bool, str]:
    """Run the solver over every set under one budget: ({answer id: value}, timed out, its stderr).

    Each set runs under a watchdog of its own that keeps back half a fair share (budget / sets / 2) for
    every set still to come. A set that runs out of its share, raises or calls sys.exit gives the answers
    it put into ctx['partial']; a blank answer is no answer. budget None: no watchdog."""
    raw: dict = {}
    timed_out = False
    said = io.StringIO()
    end = None if budget is None else time.perf_counter() + budget
    keep = 0.0 if budget is None else budget / max(1, len(sets)) / 2

    def take(qs, got):
        for q in qs:
            value = (got or {}).get(q["qid"])
            if value is not None and not is_blank(value):
                raw[q["answer_id"]] = value

    with contextlib.redirect_stderr(said):
        for i, (n, qs, files, ctx) in enumerate(sets):
            if "delivery" in ctx and not ctx["delivery"]:
                errors.append(deliveries.unsolved_line(n, ctx))     # B-042: names the runner's split reason
                continue
            limit = None
            if end is not None:
                left = end - time.perf_counter()
                if left <= 0.01:
                    timed_out = True
                    errors.append(f"set {n}: the time budget was spent before it, so it was not solved")
                    continue
                later = len(sets) - i - 1
                limit = max(min(left, keep), left - keep * later)
            ctx["partial"] = {}
            dog = Watchdog(limit)
            try:
                with dog:
                    got = solver.solve_set(qs, files, ctx) or {}
            except SolverTimeout:
                timed_out = True
                got = dict(ctx.get("partial") or {})
                errors.append(f"set {n}: solver stopped after its {limit:.2f}s share with {len(got)} answer(s) ready")
            except SystemExit as e:
                errors.append(f"set {n}: solver called sys.exit({e.code!r}); its partial answers are used")
                got = dict(ctx.get("partial") or {})
            except Exception:  # noqa: BLE001 - one set's failure must not cost the others
                errors.append(f"set {n}: solver raised; its partial answers are used\n{traceback.format_exc()}")
                got = dict(ctx.get("partial") or {})
            finally:
                dog.armed = False
                with contextlib.suppress(Exception):
                    signal.setitimer(signal.ITIMER_REAL, 0)
            take(qs, got)
    if timed_out:
        errors.append(f"solver stopped after its {budget:.2f}s time budget with {len(raw)} answer(s) ready")
    return raw, timed_out, said.getvalue()


def _worker(conn, solver, parent: int) -> None:
    """A worker's life: wait for ("set", n, qs, files, ctx, budget), answer, wait again. It ends on None,
    a closed pipe, or when the process that forked it is gone."""
    with contextlib.suppress(Exception):
        sys.stdout = io.StringIO()
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 1)
        os.dup2(null, 2)
        os.close(null)
    try:
        while True:
            if not conn.poll(1.0):
                if os.getppid() != parent:
                    return
                continue
            task = conn.recv()
            if task is None:
                return
            _, n, qs, files, ctx, budget = task
            try:
                errors: list = []
                raw, timed_out, said = solve(solver, [(n, qs, files, ctx)], budget, errors)
                conn.send({"set": n, "raw": raw, "errors": errors, "timed_out": timed_out, "said": said})
            except Exception as e:  # noqa: BLE001 - the parent solves the set serially
                conn.send({"set": n, "failed": f"{type(e).__name__}: {e}"})
    except (EOFError, OSError, KeyboardInterrupt):
        return
    finally:
        os._exit(0)                     # no atexit handler or buffer of the parent's runs here


@dataclass
class PoolRun:
    raw: dict
    timed_out: bool
    said: str
    pooled: list = field(default_factory=list)     # sets a worker answered cleanly
    serial: list = field(default_factory=list)     # sets the parent solved itself


class SetPool:
    """Forked workers for the sets of one attempt. Use `maybe` (None when forking is unsafe here)."""

    def __init__(self, solver, workers: int = POOL_WORKERS):
        if workers < 1:
            raise ValueError("a set pool needs at least one worker")
        self.solver = solver
        ctx = multiprocessing.get_context("fork")
        for stream in (sys.stdout, sys.stderr):
            with contextlib.suppress(Exception):
                stream.flush()          # nothing buffered is inherited, so nothing is printed twice
        self.workers = []
        parent = os.getpid()
        for _ in range(workers):
            ours, theirs = ctx.Pipe()
            proc = ctx.Process(target=_worker, args=(theirs, solver, parent), daemon=True)
            proc.start()
            theirs.close()
            self.workers.append((proc, ours))

    @classmethod
    def maybe(cls, solver, sets: int, notes: list, workers: int | None = None) -> "SetPool | None":
        if sets < 2:
            return None
        if threading.active_count() > 1 or _thread._count() > 0:     # _count also sees threads not made by threading
            notes.append("set pool: another thread is running, so no worker was forked; the sets are solved one by one")
            return None
        try:
            return cls(solver, workers=workers or workers_for(sets))
        except Exception as e:  # noqa: BLE001
            notes.append(f"set pool: the workers could not be forked ({type(e).__name__}: {e}); "
                         "the sets are solved one by one")
            return None

    def _dispatch(self, items, build_task, wait: float) -> dict:
        """Feed `items` to the workers, at most one in flight per worker, the next only once a worker
        has answered. {item: msg} for what came back within `wait`; anything else is absent."""
        from multiprocessing import connection
        t0 = time.perf_counter()
        results: dict = {}
        pending = list(items)
        idle = [w for w in self.workers if w[0].is_alive()]
        inflight: dict = {}                      # id(conn) -> (item, (proc, conn))

        def feed():
            while pending and idle:
                proc, conn = idle.pop()
                item = pending.pop(0)
                try:
                    conn.send(build_task(item))
                    inflight[id(conn)] = (item, (proc, conn))
                except Exception:  # noqa: BLE001 - that item falls to the serial path
                    pass

        feed()
        while inflight:
            left = t0 + wait - time.perf_counter()
            if left <= 0:
                break
            for conn in connection.wait([w[1] for _, w in inflight.values()], timeout=min(left, 0.05)):
                item, w = inflight.pop(id(conn))
                try:
                    msg = conn.recv()
                except (EOFError, OSError):
                    continue                     # the worker is gone: its item falls to the serial path
                if isinstance(msg, dict) and msg.get("set") == item:
                    results[item] = msg
                if w[0].is_alive():
                    idle.append(w)
            feed()
        return results

    def solve_sets(self, sets, budget: float | None, errors: list, notes: list, deadline: bool = True) -> PoolRun:
        """Every set to a worker; a set not answered cleanly in time is solved here, serially, with what
        is left of the budget (the workers are stopped first, so none goes on beside the serial path)."""
        t0 = time.perf_counter()
        by_n = {s[0]: s for s in sets}
        order = [s[0] for s in sets]
        wait = pool_wait(budget, deadline)
        task_budget = max(LADDER_FLOOR, wait - POOL_MARGIN)
        results = self._dispatch(order, lambda n: ("set", n, by_n[n][1], by_n[n][2], by_n[n][3], task_budget), wait)
        raw, said, done = {}, "", []
        for n in order:
            msg = results.get(n)
            if msg is None:
                continue
            if "failed" in msg or not isinstance(msg.get("raw"), dict):
                notes.append(f"set pool: the worker of set {n} failed ({msg.get('failed', 'no answers')})")
                continue
            if msg.get("errors") or msg.get("timed_out"):
                why = str((msg.get("errors") or ["its time share ran out"])[0]).splitlines()[0][:120]
                notes.append(f"set pool: the worker of set {n} did not finish cleanly ({why})")
                continue
            raw.update(msg["raw"])
            said += msg.get("said") or ""
            done.append(n)
        rest = [n for n in order if n not in done]
        timed_out = False
        if rest:
            self.close()
            left = None if budget is None else max(LADDER_FLOOR, budget - (time.perf_counter() - t0))
            more, timed_out, said2 = solve(self.solver, [by_n[n] for n in rest], left, errors)
            raw.update(more)
            said += said2
        notes.append(f"set pool: {len(done)} of {len(order)} sets solved by workers in {time.perf_counter() - t0:.2f}s"
                     + (f"; set {', '.join(str(n) for n in rest)} solved here instead" if rest else ""))
        return PoolRun(raw, timed_out, said, done, rest)

    def close(self) -> None:
        for proc, conn in self.workers:
            with contextlib.suppress(Exception):
                conn.send(None)
            with contextlib.suppress(Exception):
                conn.close()
        for proc, _ in self.workers:
            proc.join(timeout=0.2)
            if proc.is_alive():
                with contextlib.suppress(Exception):
                    proc.kill()
                proc.join(timeout=1.0)
        self.workers = []
