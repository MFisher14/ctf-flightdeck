"""Worker pool of the Script speed solver for Days 11 to 31 (2026-10-31 night).

The cumulative zip of a late day holds ~190 specimens a set (2865 in Day 31's 15-set Mastery), each its own
AES member: key derivation, inflate and the reading are pure CPU, so the specimens are spread over worker
processes (script_worker.py, started once by start() before the clock, warm). A try then costs the parent only the
questions' grouping, one temp file of the delivery and one pickled job per worker.

solve(attempt, deliveries, ctx) -> {answer_id: value}, or None when the shape is not one this pool serves (the caller
then solves in line). With no worker alive the same reading runs in this process (exact, slower). Workers: CTF_SPEED_SCRIPT_WORKERS (default 10). A worker that dies has its share
read in this process by the same code (script_worker.run_job).

Master hand-merge (B-001, from Huntress only; csctf never had speedrun/): kept as the reusable warm worker
pool for many-member archives. Changes from Huntress: the result is a plain dict (Huntress returned
speedrun.common.Answers, the guess-marking dict the master dropped: nothing here guesses); the worker count
is $CTF_SPEED_SCRIPT_WORKERS (was HUNTRESS_SPEED_SCRIPT_WORKERS); see script_worker.py for its changes.
"""
from __future__ import annotations

import atexit
import gc
import os
import shutil
import pickle
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from speedrun.common import is_zip, open_zip

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
WORKERS = int(os.environ.get("CTF_SPEED_SCRIPT_WORKERS", "10"))
_DELIV_RE = re.compile(r"^\s*delivery\s+(\d+)\s*:\s*", re.I)
# Estimated cost of one specimen (ms) by extension, key derivation included.
COST = {"py": 0.46, "js": 0.36, "jse": 0.36, "vbs": 0.36, "vbe": 0.36, "cmd": 0.33, "bat": 0.33, "gs": 0.3,
        "mjs": 0.28, "sh": 0.23, "ps1": 0.19}
DEFAULT_COST = 0.22     # a LYR-tagged polyglot: key derivation 0.16 ms, reading 0.06 ms (Day 31, measured)

_procs: list = []
_ready = threading.Event()
_lock = threading.Lock()
_solve_lock = threading.Lock()
_tmpdir = None
LAST: list = []     # (seconds, specimens) of each worker in the last solve, for diagnosis


class _W:
    def __init__(self, p):
        self.p = p
        self.ok = False

    def send(self, obj):
        b = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
        self.p.stdin.write(struct.pack("<I", len(b)) + b)
        self.p.stdin.flush()

    def _exact(self, n):
        buf = bytearray()
        rd = self.p.stdout.read
        while len(buf) < n:
            c = rd(n - len(buf))
            if not c:
                raise EOFError("worker closed")
            buf += c
        return buf

    def recv(self):
        n = struct.unpack("<I", self._exact(4))[0]
        return pickle.loads(self._exact(n))


def start(n: int | None = None):
    """Start the workers (no wait). Idempotent."""
    global _tmpdir
    with _lock:
        if _procs:
            return
        _tmpdir = tempfile.mkdtemp(prefix="speed-script-")
        env = dict(os.environ)
        for _ in range(n or WORKERS):
            p = subprocess.Popen([sys.executable, "-I", str(HERE / "script_worker.py")], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, cwd=str(ROOT),
                                 bufsize=0)
            _procs.append(_W(p))


def wait_ready(timeout: float = 120.0):
    """Wait until every worker said ready (its imports and warm-up done)."""
    t = time.monotonic() + timeout
    for w in _procs:
        if w.ok:
            continue
        try:
            if w.recv() == "ready":
                w.ok = True
        except Exception:  # noqa: BLE001 - a worker that failed to boot is left out
            w.ok = False
        if time.monotonic() > t:
            break
    _ready.set()


def alive():
    return [w for w in _procs if w.ok and w.p.poll() is None]


def stop():
    for w in _procs:
        try:
            w.p.kill()
        except Exception:  # noqa: BLE001
            pass
    _procs.clear()


# The question text and the accepted values reach a worker only for the fields that read them (Huntress script_fast:
# style, indicator; script.field_for: the joined carrier / obfuscation, the enum expansion): the rest is the id.
TEXT_SUFFIXES = ("-style", "-indicator", "-carrier", "-obfuscation")
VALUES_SUFFIXES = ("-expansion",)


def _group(attempt, outer_names):
    """[(container or None, member, [lean item], [(answer_id, raw question)])] in question order, or None.
    A lean item is (answer_id, question id or None when it is the answer id, text or None, accepted values or
    None): what the speed reader needs. The raw questions go to a worker only for a specimen it hands to the
    shipped solver."""
    qs = attempt.get("questions") or []
    ids = attempt.get("answer_ids") or []
    if len(ids) != len(qs):
        ids = [q.get("id") for q in qs]
    tasks: dict = {}
    for q, aid in zip(qs, ids):
        art = q.get("artifact") or ""
        key = tasks.get(art)
        if key is None:
            if art[:1] in "dD" and _DELIV_RE.match(art):
                return None
            cont, sep, member = art.partition(" -> ")
            if not sep or " -> " in member:
                return None
            key = tasks[art] = (cont.strip(), member.strip(), [], [])
        qid = q.get("id")
        text = av = None
        if isinstance(aid, str) and aid.endswith(TEXT_SUFFIXES):
            text = q.get("question") or ""
        elif isinstance(aid, str) and aid.endswith(VALUES_SUFFIXES):
            fmt = q.get("answer_format")
            av = fmt.get("accepted_values") if isinstance(fmt, dict) else None
            text = q.get("question") or ""
        key[2].append((aid, None if qid == aid else qid, text, av))
        key[3].append((aid, q))
    out = []
    for cont, member, lean, raw in tasks.values():
        if cont in outer_names:
            out.append((cont, member, lean, raw))
        elif member in outer_names:
            out.append((None, member, lean, raw))
        else:
            return None
    return out


STAGGER = 0.01    # a later worker gets its job later (the parent pickles the jobs one by one): a bit less work


def _split(tasks, n):
    """n contiguous shares of about equal estimated finish (contiguous: a worker opens few containers)."""
    cost = [COST.get(t[1].rsplit(".", 1)[-1].lower(), DEFAULT_COST) for t in tasks]
    total = sum(cost) or 1.0
    w = [(1.0 - STAGGER) ** i for i in range(n)]
    sw = sum(w)
    cuts, acc = [], 0.0
    for x in w[:-1]:
        acc += x / sw
        cuts.append(total * acc)
    shares, cur, run, k = [], [], 0.0, 0
    for t, c in zip(tasks, cost):
        cur.append(t)
        run += c
        if k < len(cuts) and run >= cuts[k]:
            shares.append(cur)
            cur = []
            k += 1
    shares.append(cur)
    return [s for s in shares if s]


def _solve_try(attempt, deliveries, ctx):
    if len(deliveries) != 1 or not is_zip(deliveries[0].data):
        return None
    data = deliveries[0].data
    outer = open_zip(data)
    tasks = _group(attempt, set(outer.names()))
    if tasks is None:
        return None
    with _solve_lock:      # one try at a time on the pipes
        return _solve(data, tasks)


def solve(attempt, deliveries, ctx):
    # No cyclic GC inside a try: the grouping alone allocates ~60k small objects (gen-0 passes cost it 2x).
    was = gc.isenabled()
    gc.disable()
    try:
        return _solve_try(attempt, deliveries, ctx)
    finally:
        if was:
            gc.enable()


def _lean(share):
    return [(c, m, lean) for c, m, lean, _raw in share]


def _full(share, idx):
    return [(share[i][0], share[i][1], share[i][3]) for i in idx]


def _solve(data, tasks):
    workers = alive() if _ready.is_set() else []
    out: dict = {}
    LAST.clear()
    if not workers:
        from speedrun.solvers import script_worker
        out.update(script_worker.run_full(data, [(c, m, raw) for c, m, _l, raw in tasks]))
        return out
    path = os.path.join(_tmpdir, f"d-{os.getpid()}-{time.perf_counter_ns()}.zip")
    with open(path, "wb") as fh:
        fh.write(data)
    try:
        shares = _split(tasks, len(workers))
        sent = []
        for w, share in zip(workers, shares):
            try:
                w.send(("lean", path, _lean(share)))
                sent.append((w, share))
            except Exception:  # noqa: BLE001 - its share is read here
                w.ok = False
                sent.append((None, share))
        later = []
        for w, share in sent:
            res = None
            if w is not None:
                try:
                    res = w.recv()
                except Exception:  # noqa: BLE001
                    w.ok = False
                    res = None
            if isinstance(res, dict):
                LAST.append(res.pop("__t__", None))
            if not isinstance(res, dict) or "__error__" in res:
                from speedrun.solvers import script_worker
                out.update(script_worker.run_full(data, [(c, m, raw) for c, m, _l, raw in share]))
                continue
            need = res.pop("__need__", None)
            out.update(res)
            if need:
                # The specimens the speed reader did not answer whole: the shipped solver, with the raw questions.
                try:
                    w.send(("full", path, _full(share, need)))
                    later.append((w, share, need))
                except Exception:  # noqa: BLE001
                    w.ok = False
                    later.append((None, share, need))
        for w, share, need in later:
            res = None
            if w is not None:
                try:
                    res = w.recv()
                except Exception:  # noqa: BLE001
                    w.ok = False
            if not isinstance(res, dict) or "__error__" in res:
                from speedrun.solvers import script_worker
                res = script_worker.run_full(data, _full(share, need))
            res.pop("__t__", None)
            res.pop("__need__", None)
            out.update(res)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    return out


def _cleanup():
    stop()
    if _tmpdir:
        shutil.rmtree(_tmpdir, ignore_errors=True)


atexit.register(_cleanup)
