"""Binary speed path for the cumulative days (11-31): the SHIPPED solver, split by day prefix over warm,
pre-forked worker processes (2026-10-31 night).

Why: solvers/binary/evidence.py answers every saved variant exactly but runs its ~31 day prefixes one after
another (about 2.3 s a set on Day 31, plus ~0.2 s of zip expansion), and from Day 23 on no member of a fresh
variant repeats a saved one, so a fact table cannot answer it. Each prefix is independent: it reads only its own
members (members.day_members: the basename starts with the prefix), so the work is cut into (set, prefix) tasks,
heavy ones first, and run in parallel.

Exactness: a worker builds the set's `files` the way tools/run.split_sets does (run.expand on each member under
"<delivery> -> <member>", then run._collision_keys), but only for the members of its prefixes, and runs the body
of evidence.solve_set for its groups. The judged-forms plan (which counts the WHOLE set's questions) and the
static-reader decision are made in the parent from the whole set, exactly as solve_set makes them.

Deliveries reach workers through POSIX shared memory (one copy each), the workers were forked in prepare() after
the shipped solver was loaded and warmed, so nothing is imported or compiled inside a clock.

Master hand-merge (B-001, from Huntress only; csctf never had speedrun/): kept as the reusable
pre-forked warm pool around a shipped solver. Changes from Huntress: the worker count is
$CTF_SPEED_BINARY_WORKERS (was CTF_SPEED_BINARY_WORKERS); the shipped solver is
solvers/binary/evidence.py read directly (Huntress resolved it through tools/lanes.py, which the master
does not carry) and a missing one raises ShippedSolverMissing naming the path; judged_forms is imported
without a fallback, so a missing guard fails loudly instead of skipping the demotion it does.
"""
from __future__ import annotations

import contextlib
import io
import os
import re
import sys
import threading
import time
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import env as ctf_env
from ctf import deliveries as _deliveries   # noqa: E402  B-042: which delivery is a set's own

ROOT = Path(__file__).resolve().parent.parent.parent

_EV = None          # the shipped solver module (solvers/binary/evidence.py, loaded as tools/run.py loads it)
_RUN = None         # tools/run.py
_EXEC = None        # ProcessPoolExecutor (fork)
_WORKERS = int(ctf_env.get("CTF_SPEED_BINARY_WORKERS", "0") or 0) or max(2, min(12, (os.cpu_count() or 4) - 2))
_COST: dict = {}    # prefix -> seconds, measured in prepare (a default by member size otherwise)
_LOCK = threading.Lock()
_SOLVE_NO = [0]

SOLVER_REL = Path("solvers") / "binary" / "evidence.py"
SET_RE = re.compile(r"set(\d+)\.(.+)$")


class ShippedSolverMissing(FileNotFoundError):
    """The shipped binary solver this pool wraps is not in the checkout."""


def solver_path(root: Path | None = None) -> Path:
    """solvers/binary/evidence.py under `root` (default: this checkout). Raises ShippedSolverMissing."""
    p = Path(root or ROOT) / SOLVER_REL
    if not p.is_file():
        raise ShippedSolverMissing(f"binary_par: the shipped binary solver {p} is missing")
    return p


class _Null(io.TextIOBase):
    def write(self, s):
        return len(s)


def _quiet():
    n = _Null()
    return contextlib.ExitStack() if False else _Both(n)


class _Both:
    def __init__(self, n):
        self.n = n

    def __enter__(self):
        self.o, self.e = sys.stdout, sys.stderr
        sys.stdout = sys.stderr = self.n

    def __exit__(self, *a):
        sys.stdout, sys.stderr = self.o, self.e
        return False


def load_shipped():
    global _EV, _RUN
    if _EV is not None:
        return _EV
    path = solver_path()
    for p in (ROOT / "tools", ROOT):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    import run as runmod  # tools/run.py
    with _quiet():
        ev = runmod.load_solver(str(path))
        # import every day module now, so no worker imports one inside a clock
        for p in sorted(Path(ev.MODULES).glob("d[0-9][0-9].py")):
            try:
                ev.load(p.stem)
            except Exception:  # noqa: BLE001
                pass
        for name in ("judged_forms", "hcfg_storage", "structural_enums", "static_re"):
            try:
                __import__(name)
            except Exception:  # noqa: BLE001
                pass
        try:
            ev._generic()
        except Exception:  # noqa: BLE001
            pass
    _RUN, _EV = runmod, ev
    return ev


# ---- the worker side ------------------------------------------------------------------------------------

_W_CACHE: dict = {}     # solve no -> {shm name: (data, ZipView)}
_MINE: dict = {}


def _child_init():
    from speedrun import common
    common._POOL = None          # the parent's thread pool does not exist in a forked child
    try:
        os.nice(0)
    except OSError:
        pass


def _mine(prefix: str):
    r = _MINE.get(prefix)
    if r is None:
        r = _MINE[prefix] = re.compile(rf"{re.escape(prefix)}(?![0-9A-Za-z])", re.I)
    return r


def _delivery(solve_no, shm_name, size):
    from speedrun.common import open_zip
    c = _W_CACHE.get(solve_no)
    if c is None:
        _W_CACHE.clear()
        c = _W_CACHE[solve_no] = {}
    got = c.get(shm_name)
    if got is None:
        if shm_name.startswith("file:"):
            data = Path(shm_name[5:]).read_bytes()
        else:
            from multiprocessing import shared_memory
            shm = shared_memory.SharedMemory(name=shm_name)
            try:
                data = bytes(shm.buf[:size])
            finally:
                shm.close()
            try:
                from multiprocessing import resource_tracker
                resource_tracker.unregister(shm._name, "shared_memory")  # noqa: SLF001 - the parent owns it
            except Exception:  # noqa: BLE001
                pass
        try:
            z = open_zip(data)
        except Exception:  # noqa: BLE001
            z = None
        got = c[shm_name] = (data, z)
    return got


def _files_for(dname, data, z, prefixes, everything=False):
    """The set's files as run.split_sets builds them, restricted to the members of `prefixes`."""
    run = _RUN
    keys = run.Keys(None)
    files = {}
    rows = []
    files.setdefault(dname, data)
    rows.append(((dname,), dname, data))
    if z is None:
        # not a zip we read: the whole expansion, as split_sets does it
        files = {}
        run.expand(dname, data, files, keys=keys)
        return files
    pats = [_mine(p) for p in prefixes]
    for m in z.names():
        base = m.rsplit("/", 1)[-1]
        if not everything and not any(p.match(base) for p in pats):
            continue
        body = z.read(m)
        files[f"{dname} -> {m}"] = body
        rows.append(((dname, m), f"{dname} -> {m}", body))
        run.expand(m, body, files, 1, keys, _rows=rows, _chain=(dname, m))
    try:
        run._collision_keys(files, rows)  # noqa: SLF001
    except Exception:  # noqa: BLE001
        pass
    return files


def _solve_groups(groups, files, ctx, held, static_none=True):
    """The body of evidence.solve_set's loop, for the given groups [(name, qs)]."""
    ev = _EV
    override = ev.day_patch()
    guard = None
    if held:
        import judged_forms as guard
    out = {}
    for name, qs in groups:
        got = ev.sendable(ev.static_filled(None, qs, ev.solve_prefix(name, qs, files, ctx), files, ctx))
        if held:
            got = guard.demote(qs, got, held)
        got = ev.folded_storage(qs, got, files, ctx)
        got = ev.structural_enums(qs, got, files, ctx, guard, held)
        got = ev.hook_override(name, qs, got, files, ctx)
        if override is not None:
            got = ev.overridden(override, qs, got, files, ctx)
        out.update(got)
    return out


def _task(t):
    """One (set, prefixes) task in a worker: {qid: answer} and the seconds it took."""
    t0 = time.perf_counter()
    solve_no, shm_name, size, dname, set_no, attempt, held, groups, everything = t
    with _quiet():
        data, z = _delivery(solve_no, shm_name, size)
        files = _files_for(dname, data, z, [g for g, _ in groups], everything)
        ctx = {"set": set_no, "delivery_name": dname, "delivery": data, "attempt": attempt, "partial": {}}
        try:
            got = _solve_groups(groups, files, ctx, held)
        except Exception as e:  # noqa: BLE001
            got = {"__error__": f"{type(e).__name__}: {e}"}
    out = {}
    for k, v in got.items():
        if v is None:
            continue
        if not isinstance(v, str):
            try:
                import json
                v = json.dumps(v, separators=(",", ":"), ensure_ascii=False)
            except Exception:  # noqa: BLE001
                continue
        out[k] = v
    return out, {g: time.perf_counter() - t0 for g, _ in groups}, os.getpid()


def _ping(_x):
    return os.getpid()


# ---- the parent side ------------------------------------------------------------------------------------

def start_pool():
    global _EXEC
    if _EXEC is not None:
        return _EXEC
    import multiprocessing as mp
    from concurrent.futures import ProcessPoolExecutor
    ctx = mp.get_context("fork")
    ex = ProcessPoolExecutor(max_workers=_WORKERS, mp_context=ctx, initializer=_child_init)
    # start every worker now (ProcessPoolExecutor forks on demand)
    futs = [ex.submit(time.sleep, 0.05) for _ in range(_WORKERS * 2)]
    for f in futs:
        f.result()
    _EXEC = ex
    return ex


def _shape(attempt):
    """[(set no, [question as the shipped solver sees it])] in set order, as run.split_sets groups them."""
    run = _RUN
    groups = {}
    for q, aid in zip(attempt.get("questions") or [], run.answer_ids_for(attempt)):
        n, question = run.shaped(q, aid)
        groups.setdefault(n, []).append(question)
    return [(n, groups[n]) for n in sorted(groups)]


def _slim(attempt):
    return {k: v for k, v in attempt.items() if k not in ("questions", "answer_ids")}


def _est(prefix, size):
    c = _COST.get(prefix)
    if c is not None:
        return c
    return 0.004 + size / 25e6


def pairing(sets, count):
    """[(set no, delivery index, qs)] for `sets` ([(set no, qs)] as _shape gives them) over `count`
    deliveries, by the runner's own rule (ctf.deliveries.choose, which tools/run.split_sets follows), or
    None when this path cannot take the attempt and the caller runs the shipped solver whole: a set with
    no proven delivery (B-042: it is never handed a neighbour's), one set over several deliveries (it
    reads them all), or one bundle for several sets (its members need the runner's expander)."""
    order = [n for n, _ in sets]
    if count < 1 or (count == 1 and len(order) > 1):
        return None
    out = []
    for n, qs in sets:
        choice = _deliveries.choose(n, qs, order, count)
        if choice.index is not None and choice.member is None:
            out.append((n, choice.index, qs))
        elif choice.rule == _deliveries.ALL and count == 1:
            out.append((n, 0, qs))
        else:
            return None
    return out


def plan_tasks(attempt, deliveries):
    """[(cost, task)] or None when this attempt is not a shape the split handles (the caller then runs the
    shipped solver whole)."""
    from speedrun.common import open_zip
    ev = _EV
    run = _RUN
    att = run.normalize(dict(attempt))
    names = [a.get("filename") or f"delivery-{i}" for i, a in enumerate(att.get("artifacts") or [])]
    blobs = [d.data for d in deliveries]
    if len(names) < len(blobs):
        names += [d.filename for d in deliveries[len(names):]]
    for i, d in enumerate(deliveries):
        if i < len(names) and not names[i]:
            names[i] = d.filename
    plan = pairing(_shape(att), len(blobs))      # (set no, delivery index, qs)
    if plan is None:
        return None
    slim = _slim(att)
    import judged_forms as guard  # solvers/binary/judged_forms.py (on sys.path once load_shipped ran)
    tasks = []
    zips = {}
    for n, i, qs in plan:
        z = zips.get(i)
        if z is None:
            try:
                z = zips[i] = open_zip(blobs[i])
            except Exception:  # noqa: BLE001
                return None
        ctx = {"set": n, "delivery_name": names[i], "delivery": blobs[i], "attempt": att}
        with _quiet():
            if ev.static_reader(qs, None, ctx) is not None:
                return None
            held = guard.plan(qs, ctx)
        groups = {}
        for q in qs:
            groups.setdefault(ev.module_for(q), []).append(q)
        sizes = {}
        for m in z.names():
            base = m.rsplit("/", 1)[-1]
            mm = re.match(r"([a-z]+\d+)", base, re.I)
            if mm:
                sizes[mm.group(1).lower()] = sizes.get(mm.group(1).lower(), 0) + z.entry(m).size
        small = []
        for g, gq in groups.items():
            ok = re.fullmatch(r"d\d\d", g) is not None and g in sizes
            cost = _est(g, sizes.get(g, 0))
            if not ok:
                tasks.append((cost + 1.0, (n, i, names[i], slim, held, [(g, gq)], True)))
            elif cost < 0.02:
                small.append((cost, g, gq))
            else:
                tasks.append((cost, (n, i, names[i], slim, held, [(g, gq)], False)))
        # light prefixes in batches of about 20 ms
        batch, bc = [], 0.0
        for cost, g, gq in sorted(small, key=lambda x: x[0], reverse=True):
            batch.append((g, gq))
            bc += cost
            if bc >= 0.03:
                tasks.append((bc, (n, i, names[i], slim, held, batch, False)))
                batch, bc = [], 0.0
        if batch:
            tasks.append((bc, (n, i, names[i], slim, held, batch, False)))
    tasks.sort(key=lambda x: x[0], reverse=True)
    return tasks, blobs, plan


def solve(attempt, deliveries, timing=None):
    """{qid-with-set-prefix-as-in-attempt -> answer} keyed by answer id. None when the split does not apply."""
    from multiprocessing import shared_memory
    load_shipped()
    got = plan_tasks(attempt, deliveries)
    if got is None:
        return None
    tasks, blobs, plan = got
    ex = start_pool()
    with _LOCK:
        _SOLVE_NO[0] += 1
        solve_no = _SOLVE_NO[0]
    shms = {}
    try:
        need = sorted({t[1][1] for t in tasks})
        for i in need:
            b = blobs[i]
            shm = shared_memory.SharedMemory(create=True, size=max(1, len(b)))
            shm.buf[:len(b)] = b
            shms[i] = shm
        futs = []
        for cost, (n, i, dname, slim, held, groups, everything) in tasks:
            futs.append(ex.submit(_task, (solve_no, shms[i].name, len(blobs[i]), dname, n, slim, held, groups,
                                          everything)))
        per_set = {}
        for f, (cost, t) in zip(futs, tasks):
            ans, secs, pid = f.result()
            per_set.setdefault(t[0], {}).update(ans)
            if timing is not None:
                for g, s in secs.items():
                    timing.setdefault(g, []).append(s)
    finally:
        for shm in shms.values():
            try:
                shm.close()
                shm.unlink()
            except Exception:  # noqa: BLE001
                pass
    out = {}
    for n, i, qs in plan:
        ans = per_set.get(n, {})
        for q in qs:
            v = ans.get(q["qid"])
            if v is None or v.startswith("??"):
                continue
            out[q["answer_id"]] = v
    return out


def warm(cases, rounds=1):
    """Run whole saved attempts through the pool (each worker meets every prefix module) and learn the cost of
    every prefix from it."""
    timing = {}
    for _ in range(rounds):
        for att, dels in cases:
            try:
                solve(att, dels, timing)
            except Exception:  # noqa: BLE001
                pass
    for g, xs in timing.items():
        xs = sorted(xs)
        _COST[g] = xs[len(xs) // 2]
    return timing
