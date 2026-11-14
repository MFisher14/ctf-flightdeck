#!/usr/bin/env python3
"""Parallel-search helper for the brute-ish solvers (key spaces, PRNG seeds, cipher-ID sweeps).

Two small reusable pieces built on the standard-library ``multiprocessing`` only:

  parallel_map(fn, items, ...)        fn over items, results in input order (or as they finish),
                                      across `workers` processes. Falls back to a plain serial map
                                      when multiprocessing cannot start, when workers <= 1, or when
                                      there is almost nothing to do.
  parallel_search(candidates, score)  the best (or first matching) candidate by a score/match
                                      function, evaluated across processes. `score` returns a
                                      comparable value (higher is better, by default) or, with
                                      first_match=True, a truthy value that stops the search.

Everything here is offline and does nothing but call the function it is handed. The function and
its items must be picklable under the "spawn" start method (module-level functions, or
functools.partial over them); on POSIX this module prefers the cheaper "fork" context, which
inherits the parent's memory and sidesteps pickling the work function at all.

  .venv/bin/python solvers/common/psearch.py        # self-check / tiny demo

Why it exists: a crib-first Enigma break fans ~60 rotor orders across cores (see
solvers/common/classical.py, enigma_crib_break); key-space and seed sweeps elsewhere reuse the
same two calls instead of each hand-rolling a Pool.
"""
import functools
import multiprocessing
import os
import sys

__all__ = ["cpu_count", "parallel_map", "parallel_search"]


def cpu_count() -> int:
    """A sensible default worker count: the usable CPUs, at least 1."""
    try:
        n = len(os.sched_getaffinity(0))      # respects cgroup/taskset limits where present
    except (AttributeError, OSError):
        n = os.cpu_count() or 1
    return max(1, n)


def _get_context():
    """A multiprocessing context, preferring 'fork' (no pickling of the work function, warm
    inheritance of anything the parent already built), or None when none can be made."""
    for method in ("fork", "forkserver", "spawn"):
        try:
            return multiprocessing.get_context(method)
        except ValueError:
            continue
    return None


def _normalise_workers(workers, n_items):
    if workers is None:
        workers = cpu_count()
    workers = max(1, int(workers))
    if n_items is not None:
        workers = min(workers, max(1, n_items))
    return workers


def parallel_map(fn, items, workers=None, chunksize=None, ordered=True, serial=False):
    """Apply `fn` to each of `items` across `workers` processes and return a list of results.

    ordered     keep results in the order of `items` (the default); False yields them as they
                finish, which is faster when runtimes vary a lot.
    chunksize   items handed to a worker at once; a sensible value is chosen when omitted.
    serial      force the plain in-process map (also used automatically as the fallback).

    `fn` and every item must be picklable (a module-level function, or functools.partial over
    one). Falls back to a serial map on any failure to start the pool, and never leaves a pool
    running."""
    items = list(items)
    workers = _normalise_workers(workers, len(items))
    if serial or workers == 1 or len(items) <= 1:
        return [fn(x) for x in items]
    ctx = _get_context()
    if ctx is None:
        return [fn(x) for x in items]
    if chunksize is None:
        chunksize = max(1, len(items) // (workers * 4) or 1)
    pool = None
    try:
        pool = ctx.Pool(processes=workers)
        if ordered:
            return list(pool.map(fn, items, chunksize=chunksize))
        return list(pool.imap_unordered(fn, items, chunksize=chunksize))
    except Exception:
        # A child that cannot be forked/spawned, an unpicklable closure, etc.: do it in-process.
        if pool is not None:
            pool.terminate()
            pool = None
        return [fn(x) for x in items]
    finally:
        if pool is not None:
            pool.close()
            pool.join()


def _scored(pair):
    """Worker shim for parallel_search: evaluate the score function on one candidate.

    `pair` is (score_fn, candidate); returns (score, candidate). Module-level so it pickles under
    spawn; the score function is carried in the payload (picklable: a module-level function or a
    functools.partial over one)."""
    score_fn, cand = pair
    return score_fn(cand), cand


def parallel_search(candidates, score, workers=None, chunksize=256, maximize=True,
                    first_match=False, serial=False):
    """The best candidate under `score`, searched across processes.

    Returns (best_candidate, best_score), or (None, None) when `candidates` is empty (or, with
    first_match, when nothing matched).

    score        score(candidate) -> comparable value; the highest wins (lowest when
                 maximize=False). With first_match=True it is read as a predicate: the first
                 candidate for which it is truthy is returned at once (its truthy value as the
                 score), and the rest are not scored.
    workers      process count (default: all CPUs).
    chunksize    candidates per task handed to a worker.
    serial       force the in-process search (also the automatic fallback).

    `score` must be picklable (module-level, or functools.partial over a module-level function).
    """
    candidates = list(candidates)
    if not candidates:
        return (None, None)
    workers = _normalise_workers(workers, len(candidates))

    def better(a, b):     # is score a strictly better than score b?
        return a > b if maximize else a < b

    use_serial = serial or workers == 1 or len(candidates) <= 1
    ctx = None if use_serial else _get_context()
    if ctx is None:
        use_serial = True

    if use_serial:
        best_c, best_s = None, None
        for c in candidates:
            s = score(c)
            if first_match:
                if s:
                    return (c, s)
                continue
            if best_s is None or better(s, best_s):
                best_c, best_s = c, s
        return (best_c, best_s) if not first_match else (None, None)

    payload = [(score, c) for c in candidates]
    pool = None
    best_c, best_s = None, None
    try:
        pool = ctx.Pool(processes=workers)
        for s, c in pool.imap_unordered(_scored, payload, chunksize=max(1, chunksize)):
            if first_match:
                if s:
                    return (c, s)
                continue
            if best_s is None or better(s, best_s):
                best_c, best_s = c, s
    except Exception:
        if pool is not None:
            pool.terminate()
            pool = None
        return parallel_search(candidates, score, workers=1, maximize=maximize,
                               first_match=first_match, serial=True)
    finally:
        if pool is not None:
            pool.close()
            pool.join()
    return (best_c, best_s) if not first_match else (None, None)


# ---------------------------------------------------------------------------- self-check

def _sq(x):
    return x * x


def _is_target(x):
    return x if x == 42 else 0


def main(argv) -> int:
    squares = parallel_map(_sq, range(10), workers=4)
    assert squares == [i * i for i in range(10)], squares
    cand, sc = parallel_search(range(100), _sq, workers=4)
    assert (cand, sc) == (99, 99 * 99), (cand, sc)
    hit, _ = parallel_search(range(100), _is_target, workers=4, first_match=True)
    assert hit == 42, hit
    print("psearch ok: map=%d cpus=%d" % (len(squares), cpu_count()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
