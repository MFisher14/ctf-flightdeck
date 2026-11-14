"""SH-10: clocks for tests whose checks must not depend on how loaded the machine is (not a test module).

The suite runs at a load average of 50 to 170 on 14 cores, so a process waits for a core for much of its
wall time. These helpers measure work instead (docs/build-log/SH-08.md, SH-10.md):

  cpu_clock()        for the block, time.monotonic and time.perf_counter read time.process_time, so an
                     engine's own budget or deadline (read from either clock) counts seconds of work.
                     The same budgets, in the same numbers; work over a budget still runs it out.
                     Code that bound a clock at import (threading, subprocess, socket timeouts) keeps
                     the real one, so no real wait is stretched or shortened by it.
                     It patches the whole process, every thread included: never wrap code that forks or
                     starts workers (a child inherits the patch while its process_time restarts near
                     zero), and never one that receives a deadline computed outside the block.
  cpu_seconds(fn)    (fn(), the CPU seconds of this process it took).
  thread_seconds(fn) (fn(), the CPU seconds of this thread it took): for a single-threaded call in a
                     process that may hold other busy threads (a fake server another test left running).
  pool_seconds(fn, workers)
                     (fn(), its CPU time as wall time on `workers` free cores): this process's CPU plus
                     the CPU of the children it reaped in the call (a process pool's workers), divided
                     among the workers. For a call that fans work out to a pool.

Usable from a pytest module (tests/ is on sys.path) and from a tests/real script (it adds tests/ itself).
"""
from __future__ import annotations

import contextlib
import resource
import time


@contextlib.contextmanager
def cpu_clock():
    saved = time.monotonic, time.perf_counter
    time.monotonic = time.perf_counter = time.process_time
    try:
        yield
    finally:
        time.monotonic, time.perf_counter = saved


def cpu_seconds(fn, *args, **kw):
    t0 = time.process_time()
    out = fn(*args, **kw)
    return out, time.process_time() - t0


def thread_seconds(fn, *args, **kw):
    t0 = time.thread_time()
    out = fn(*args, **kw)
    return out, time.thread_time() - t0


def _children_cpu() -> float:
    r = resource.getrusage(resource.RUSAGE_CHILDREN)
    return r.ru_utime + r.ru_stime


def pool_seconds(fn, workers: int, *args, **kw):
    """(fn(), parent CPU + reaped children's CPU / workers). A pool's workers are reaped when the pool is
    closed and joined, so their CPU is in RUSAGE_CHILDREN by the time fn returns. The children's share is
    what the call costs on `workers` free cores when its jobs are spread evenly over them; uneven jobs
    make the real wall time longer than this, never shorter, so it is a lower bound on the unloaded
    wall time and a bound on it still fails a call that does several times the work."""
    if workers < 1:
        raise ValueError(f"pool_seconds needs workers >= 1, got {workers}")
    p0, c0 = time.process_time(), _children_cpu()
    out = fn(*args, **kw)
    return out, (time.process_time() - p0) + (_children_cpu() - c0) / workers
