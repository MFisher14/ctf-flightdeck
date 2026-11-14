"""Pooled stability and variant replays of saved attempts, behind a per-prefix replay cache (B-253).

At Huntress 2026 gate time was the cheapest large mechanical target (Binary 306.97 s and Script 116.90 s
in gates over Days 20-30). Two of its causes are this module's:

  * **Serial replays** (improvements row 582). The Day 30 Script Mastery resume gate took 58.67 s: its
    one 14-set Mastery folder was replayed set after set, twice (the stability check), while the timed
    runner's set pool solved the same 14 sets in 3.92 s. Here every replay goes through the set pool
    (`ctf.adapt.setpool`: forked workers, one set in flight each, a set not back cleanly is solved
    serially), and the two stability replays run at the same time in two separate interpreters (so they
    are distinct processes with their own hash seeds, as the Huntress check required).
  * **A cache voided by any new day module** (row 590). The Day 30 Binary TT gate replayed cold for
    147.26 s because `d30.py` changed the lane hash. Here each saved row's green result is cached under
    a key of its own: the solver's static closure, the solver folder minus the day modules of days the
    row does not touch (`regress.Keyer.folder_files`, with its import audit), and the row's bytes. A new
    `fields_d99.py` leaves every other row warm; a change to `generic.py` voids them all. The cache is a
    `ctf.gate.inventory.Inventory` (content-keyed, atomic, rebuilt loudly when unreadable); a red row is
    discarded from it, so it always runs again.

    run = replay(solver, make_sets, budget=None, pooled=True)          # ReplayRun: one replay in-process
    st = stability(attempt_dir, solver_file, workdir=wd)               # Stability: two concurrent child replays
    g = gate_rows(rows_in(folder), solver_file, workdir=wd, lane="binary")   # RowsGate: cached per row
    prof = profile_attempt(attempt_dir, solver_file)                   # Profile: where a solve spends its time

**A saved attempt** is a folder holding `attempt.json` (the start response: `questions`, `answer_ids`,
`artifacts`) and `artifact/` (one file per delivery, or `artifact/delivery-NN/<file>`), the layout the
Huntress runner saved; its sets are split exactly as the live runner splits them (`tools/run.py`
`split_sets`). A delivery whose sha256 differs from attempt.json, or that is missing, is an AdaptError.
A row may hold `expect.json` (`{answer id: value}`): its replay is green only when stable and every
expected answer is given exactly.

**The quiet check.** The two stability children run at the replay policy of `ctf.adapt.clocks`: nice 0
with the set pool's own worker count when no clock with a deadline runs; nice 10 with at most 3 workers
each while one does. A clock with no deadline does not throttle them.

Challenge data is only read here. The solver is this checkout's lane code; the children run with
`python -I` from the checkout root, never from inside an attempt folder. Nothing here talks to a
platform or starts a clock.
"""
from __future__ import annotations

import contextlib
import cProfile
import hashlib
import importlib.util
import io
import json
import os
import pstats
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

from .. import paths as _paths
from ..gate.inventory import Inventory
from . import AdaptError
from . import clocks as _clocks
from . import regress as _regress
from . import setpool as _setpool

KEY_VERSION = "adapt-replay-1"
CACHE_VERSION = "adapt-replay-cache-1"
ATTEMPT_FILE = "attempt.json"
EXPECT_FILE = "expect.json"
STABLE, UNSTABLE, CUT, FAILED = "stable", "unstable", "cut", "failed"
GREEN, WARM, RED = "green", "warm", "red"
CHILD_TIMEOUT = 1800.0          # seconds a stability child may run before it is killed (a hung solver)
_RUN_MODULE = "adapt_replay_tools_run"
RUN_FILES = ("tools/run.py", "tools/archive_expand.py", "ctf/adapt/setpool.py", "ctf/adapt/replay.py")  # in every row key


# --------------------------------------------------------------------------- one replay

@dataclass
class ReplayRun:
    answers: dict                       # {answer id: value}
    pooled: list = field(default_factory=list)      # sets a worker solved
    serial: list = field(default_factory=list)      # sets solved in the replaying process
    timed_out: bool = False
    seconds: float = 0.0                # wall
    cpu: float = 0.0                    # this process plus its reaped workers (user + system)
    errors: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    workers: int = 0                    # workers the set pool forked (0: solved serially)

    def to_json(self) -> dict:
        return {"answers": self.answers, "pooled": self.pooled, "serial": self.serial, "timed_out": self.timed_out,
                "seconds": round(self.seconds, 4), "cpu": round(self.cpu, 4),
                "errors": [str(e).splitlines()[0][:200] for e in self.errors if str(e).strip()],
                "notes": list(self.notes), "workers": self.workers}


def _cpu() -> float:
    t = os.times()
    return t.user + t.system + t.children_user + t.children_system


def replay(solver, make_sets, budget: float | None = None, *, pooled: bool = True,
           workers: int | None = None) -> ReplayRun:
    """One replay of an attempt's sets: through the set pool (`pooled`, when it can fork), else serially.
    `make_sets()` returns fresh `(n, questions, files, ctx)` sets: a replay never reuses another's ctx."""
    sets = list(make_sets())
    notes: list = []
    errors: list = []
    t0, c0 = time.perf_counter(), _cpu()
    pool = _setpool.SetPool.maybe(solver, len(sets), notes, workers=workers) if pooled else None
    forked = 0
    if pool is None:
        raw, timed_out, _said = _setpool.solve(solver, sets, budget, errors)
        done, rest = [], [s[0] for s in sets]
    else:
        forked = len(pool.workers)
        try:
            run = pool.solve_sets(sets, budget, errors, notes, deadline=False)
        finally:
            pool.close()
        raw, timed_out, done, rest = run.raw, run.timed_out, run.pooled, run.serial
    return ReplayRun(dict(raw), list(done), list(rest), bool(timed_out), time.perf_counter() - t0, _cpu() - c0,
                     errors, notes, forked)


def _canon(answers: dict) -> dict:
    """Answers as JSON gives them back (str keys, JSON values), so two replays compare alike."""
    return json.loads(json.dumps(answers, sort_keys=True, default=str))


def diff_answers(a: dict, b: dict) -> dict:
    """{answer id: (a's value, b's value)} for every id the two disagree on (an absent id is None)."""
    a, b = _canon(a), _canon(b)
    return {k: (a.get(k), b.get(k)) for k in sorted(set(a) | set(b)) if a.get(k) != b.get(k)}


# --------------------------------------------------------------------------- saved attempts

def load_solver(path: Path):
    """The lane solver module at `path` (it must define solve_set(questions, files, ctx)). Its folder goes
    on sys.path, as the runner puts it, so its sibling imports resolve."""
    p = Path(path).resolve()
    if not p.is_file():
        raise AdaptError(f"solver {p} is not a file")
    name = "adapt_replay_solver_" + hashlib.sha256(str(p).encode()).hexdigest()[:12]
    if name in sys.modules:
        mod = sys.modules[name]
    else:
        if str(p.parent) not in sys.path:
            sys.path.insert(0, str(p.parent))
        spec = importlib.util.spec_from_file_location(name, p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        try:
            spec.loader.exec_module(mod)
        except BaseException as e:
            sys.modules.pop(name, None)
            raise AdaptError(f"solver {p} could not be loaded: {type(e).__name__}: {e}") from None
    if not callable(getattr(mod, "solve_set", None)):
        raise AdaptError(f"solver {p} defines no solve_set(questions, files, ctx)")
    return mod


def _split_sets():
    """tools/run.py's split_sets: the one splitter every live run and replay goes through."""
    tools = Path(__file__).resolve().parents[2] / "tools"
    path = tools / "run.py"
    if not path.is_file():
        raise AdaptError(f"tools/run.py is missing under {tools.parent}: saved attempts cannot be split")
    mod = sys.modules.get(_RUN_MODULE)
    if mod is None:
        known = sys.modules.get("run")          # the runner imported as `run` (timed_ladder.py does) is reused
        if known is not None and Path(getattr(known, "__file__", "") or "").resolve() == path:
            mod = known
    if mod is None:
        if str(tools) not in sys.path:
            sys.path.insert(0, str(tools))      # its own `import archive_expand`
        spec = importlib.util.spec_from_file_location(_RUN_MODULE, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[_RUN_MODULE] = mod
        try:
            spec.loader.exec_module(mod)
        except Exception as e:  # noqa: BLE001
            sys.modules.pop(_RUN_MODULE, None)
            raise AdaptError(f"tools/run.py could not be imported ({type(e).__name__}: {e})") from None
    fn = getattr(mod, "split_sets", None)
    if not callable(fn):
        raise AdaptError("tools/run.py has no split_sets(attempt, blobs)")
    return fn


@dataclass
class SavedAttempt:
    folder: Path
    attempt: dict
    paths: list                         # one delivery file per artifact
    shas: list

    @classmethod
    def load(cls, folder: Path) -> "SavedAttempt":
        d = Path(folder)
        f = d / ATTEMPT_FILE
        try:
            attempt = json.loads(f.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise AdaptError(f"{d} is not a saved attempt: no {ATTEMPT_FILE}") from None
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            raise AdaptError(f"{f} is unreadable ({type(e).__name__}: {e})") from None
        if not isinstance(attempt, dict) or not isinstance(attempt.get("questions"), list) \
                or not attempt["questions"]:
            raise AdaptError(f"{f} has no questions")
        arts = attempt.get("artifacts") or []
        if not isinstance(arts, list):
            raise AdaptError(f"{f}: artifacts must be a list")
        paths, shas = [], []
        for i, a in enumerate(arts):
            a = a if isinstance(a, dict) else {}
            p = _delivery(d, a, i, len(arts))
            sha = _regress._sha_file(p)
            want = a.get("sha256")
            if want and sha != want:
                raise AdaptError(f"{p} does not match the sha256 attempt.json gives for delivery {i + 1}")
            paths.append(p)
            shas.append(sha)
        return cls(d, attempt, paths, shas)

    def blobs(self) -> list:
        return [p.read_bytes() for p in self.paths]

    def make_sets(self):
        """A fresh split of the attempt into sets on every call (a replay never shares ctx)."""
        split = _split_sets()
        attempt = json.loads(json.dumps(self.attempt))
        return lambda: split(json.loads(json.dumps(attempt)), self.blobs())

    def days(self) -> set[str]:
        qids = [str(q.get("id", "")) for q in self.attempt.get("questions") or [] if isinstance(q, dict)]
        qids += [str(x) for x in self.attempt.get("answer_ids") or []]
        names = [str(a.get("filename", "")) for a in self.attempt.get("artifacts") or [] if isinstance(a, dict)]
        out = _regress.days_in_text(*qids, *names)
        for p in self.paths:
            out |= _regress.days_in_file(p)
        return out

    def content_sha(self) -> str:
        h = hashlib.sha256()
        h.update(_regress._sha_file(self.folder / ATTEMPT_FILE).encode())
        for s in self.shas:
            h.update(s.encode())
        ex = self.folder / EXPECT_FILE
        h.update(_regress._sha_file(ex).encode() if ex.is_file() else b"-")
        return h.hexdigest()

    def expect(self) -> dict | None:
        ex = self.folder / EXPECT_FILE
        if not ex.is_file():
            return None
        try:
            got = json.loads(ex.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            raise AdaptError(f"{ex} is unreadable ({type(e).__name__}: {e})") from None
        if not isinstance(got, dict) or not got:
            raise AdaptError(f"{ex} must be a non-empty object {{answer id: value}}")
        return _canon(got)


def _delivery(d: Path, art: dict, i: int, total: int) -> Path:
    name = art.get("filename")
    tries = []
    if name:
        if "/" in str(name) or str(name) in ("", ".", ".."):
            raise AdaptError(f"delivery {i + 1}'s filename {str(name)[:80]!r} is not a plain file name")
        tries += [d / "artifact" / name, d / "artifact" / f"delivery-{i + 1:02d}" / name]
    for t in tries:
        if t.is_file() and not t.is_symlink():
            return t
    folder = d / "artifact" if total == 1 else d / "artifact" / f"delivery-{i + 1:02d}"
    found = [x for x in sorted(folder.glob("*")) if x.is_file() and not x.is_symlink()] if folder.is_dir() else []
    if len(found) == 1:
        return found[0]
    raise AdaptError(f"delivery {i + 1} of {total} is not saved under {d / 'artifact'}"
                     + (f" (looked for {name})" if name else ""))


def replay_attempt(folder: Path, solver_file: Path, budget: float | None = None, *, pooled: bool = True,
                   workers: int | None = None) -> ReplayRun:
    att = SavedAttempt.load(folder)
    return replay(load_solver(solver_file), att.make_sets(), budget, pooled=pooled, workers=workers)


# --------------------------------------------------------------------------- stability: two children at once

@dataclass
class Stability:
    status: str                         # stable | unstable | cut | failed
    reason: str
    runs: tuple = ()                    # the two children's ReplayRun
    diffs: dict = field(default_factory=dict)
    seconds: float = 0.0
    policy: _clocks.ReplayPolicy | None = None

    @property
    def stable(self) -> bool:
        return self.status == STABLE

    @property
    def answers(self) -> dict:
        return _canon(self.runs[0].answers) if self.runs else {}


def _child_cmd(folder: Path, solver_file: Path, out: Path, *, budget, pooled: bool, workers, nice: int) -> list:
    root = _paths.repo_root()
    code = ("import sys; sys.path.insert(0, sys.argv[1]); from ctf.adapt.replay import child_main; "
            "sys.exit(child_main(sys.argv[2:]))")
    cmd = [sys.executable, "-I", "-c", code, str(root), "--attempt", str(Path(folder).resolve()),
           "--solver", str(Path(solver_file).resolve()), "--out", str(out)]
    if budget is not None:
        cmd += ["--budget", repr(float(budget))]
    if not pooled:
        cmd.append("--serial")
    if workers:
        cmd += ["--workers", str(int(workers))]
    if nice:
        nice_bin = shutil.which("nice")
        if nice_bin is None:
            raise AdaptError(f"nice is not on PATH: the replay was asked to run at nice {nice}")
        cmd = [nice_bin, "-n", str(int(nice)), *cmd]
    return cmd


def stability(folder: Path, solver_file: Path, *, workdir: Path, budget: float | None = None,
              pooled: bool = True, policy: _clocks.ReplayPolicy | None = None,
              timeout: float = CHILD_TIMEOUT) -> Stability:
    """Replay a saved attempt twice at once, in two fresh interpreters, each through its set pool, and
    compare. A child that fails or is cut is not a verdict on stability (`failed`, `cut`)."""
    SavedAttempt.load(folder)                       # refuse a bad attempt before starting anything
    policy = policy or _clocks.replay_policy(workdir)
    workers = min(_setpool.POOL_WORKERS_MAX, policy.jobs) if policy.busy else None
    Path(workdir).mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    with tempfile.TemporaryDirectory(dir=workdir, prefix="adapt-replay-") as tmp:
        outs = [Path(tmp) / f"run-{i}.json" for i in (1, 2)]
        procs = []
        for o in outs:
            cmd = _child_cmd(folder, solver_file, o, budget=budget, pooled=pooled, workers=workers, nice=policy.nice)
            procs.append(subprocess.Popen(cmd, cwd=str(_paths.repo_root()), stdin=subprocess.DEVNULL,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                          errors="replace", start_new_session=True))
        runs, problems = [], []
        for i, (p, o) in enumerate(zip(procs, outs), 1):
            try:
                _out, err = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(OSError):
                    os.killpg(p.pid, signal.SIGKILL)
                _out, err = p.communicate()
                problems.append(f"replay {i} ran past {timeout:g}s and was killed")
                continue
            if p.returncode != 0 or not o.is_file():
                tail = (err or "").strip().splitlines()[-1:] or ["no output"]
                problems.append(f"replay {i} exited {p.returncode}: {tail[0][:200]}")
                continue
            d = json.loads(o.read_text(encoding="utf-8"))
            runs.append(ReplayRun(d["answers"], d["pooled"], d["serial"], d["timed_out"], d["seconds"], d["cpu"],
                                  d["errors"], d["notes"], d["workers"]))
    seconds = time.perf_counter() - t0
    if problems:
        return Stability(FAILED, "; ".join(problems), tuple(runs), {}, seconds, policy)
    if any(r.timed_out for r in runs):
        return Stability(CUT, f"a replay ran out of its {budget}s budget: not a verdict on stability",
                         tuple(runs), {}, seconds, policy)
    diffs = diff_answers(runs[0].answers, runs[1].answers)
    if diffs:
        shown = ", ".join(f"{k}: {a!r} vs {b!r}" for k, (a, b) in list(diffs.items())[:5])
        return Stability(UNSTABLE, f"{len(diffs)} answer(s) differ between two replays ({shown})",
                         tuple(runs), diffs, seconds, policy)
    return Stability(STABLE, "", tuple(runs), {}, seconds, policy)


def child_main(argv: list) -> int:
    """One stability child: replay the attempt, write the ReplayRun as JSON to --out."""
    import argparse
    ap = argparse.ArgumentParser(prog="ctf.adapt.replay child")
    ap.add_argument("--attempt", required=True, type=Path)
    ap.add_argument("--solver", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--budget", type=float)
    ap.add_argument("--workers", type=int)
    ap.add_argument("--serial", action="store_true")
    a = ap.parse_args(argv)
    with contextlib.redirect_stdout(sys.stderr):    # a solver's prints never reach the result
        run = replay_attempt(a.attempt, a.solver, a.budget, pooled=not a.serial, workers=a.workers)
    tmp = a.out.with_name(a.out.name + ".tmp")
    tmp.write_text(json.dumps(run.to_json(), sort_keys=True, default=str), encoding="utf-8")
    os.replace(tmp, a.out)
    return 0


# --------------------------------------------------------------------------- the per-prefix replay cache

def rows_in(folder: Path) -> dict[str, Path]:
    """{row name: saved attempt folder} for every folder holding attempt.json, one or two levels below
    `folder` (`<folder>/<id>/` or `<folder>/day-NN/<id>/`); the name is its path under `folder`."""
    base = Path(folder)
    if not base.is_dir():
        raise AdaptError(f"rows folder {base} does not exist")
    out = {}
    for f in sorted(list(base.glob(f"*/{ATTEMPT_FILE}")) + list(base.glob(f"*/*/{ATTEMPT_FILE}"))):
        out[f.parent.relative_to(base).as_posix()] = f.parent
    if not out:
        raise AdaptError(f"no saved attempt (a folder with {ATTEMPT_FILE}) under {base}")
    return out


def row_key(keyer: _regress.Keyer, solver_file: Path, att: SavedAttempt) -> tuple[str, frozenset]:
    """(key, days) of one saved row: sha256 over the key version, the interpreter, the solver's static
    closure, its folder minus other days' modules (with the import audit), and the row's bytes."""
    rel = keyer._rel(Path(solver_file))
    if rel is None:
        raise AdaptError(f"solver {solver_file} is not inside the checkout {keyer.root}")
    days = frozenset(att.days()) if keyer.day_scoped else frozenset()
    folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
    files = set(keyer.graph.closure(rel)) | set(keyer.folder_files(folder, days))
    h = hashlib.sha256()

    def put(*parts) -> None:
        for x in parts:
            b = str(x).encode("utf-8", "surrogateescape")
            h.update(len(b).to_bytes(8, "big"))
            h.update(b)

    put(KEY_VERSION, sys.version, sys.executable, rel, "days", len(days), *sorted(days))
    for f in sorted(files):
        put("file", f, keyer.graph.sha(f) or "<missing>")
    for f in RUN_FILES:
        put("run", f, keyer._ext_sha(f))
    put("row", att.content_sha())
    return h.hexdigest(), days


def cache_path(lane: str, workdir: Path) -> Path:
    return Path(workdir) / "adapt" / "replay" / f"{_regress._check_name(lane, 'lane')}.json"


@dataclass(frozen=True)
class RowOutcome:
    row: str
    status: str                         # green | warm | red
    reason: str
    key: str
    days: tuple = ()
    seconds: float = 0.0
    stability: str = ""


@dataclass(frozen=True)
class RowsGate:
    lane: str
    verdict: str                        # regress.YES | regress.NO
    reason: str
    rows: tuple
    seconds: float
    notes: tuple = ()

    @property
    def ok(self) -> bool:
        return self.verdict == _regress.YES

    def count(self, status: str) -> int:
        return sum(1 for r in self.rows if r.status == status)


def _judge_row(att: SavedAttempt, st: Stability) -> tuple[bool, str]:
    if not st.stable:
        return False, f"{st.status}: {st.reason}"
    want = att.expect()
    if want is None:
        return True, ""
    got = st.answers
    wrong = {k: (v, got.get(k)) for k, v in want.items() if got.get(k) != v}
    if wrong:
        shown = ", ".join(f"{k}: want {a!r}, got {b!r}" for k, (a, b) in list(wrong.items())[:5])
        return False, f"{len(wrong)} of {len(want)} expected answer(s) not given ({shown})"
    return True, ""


def gate_rows(rows: dict, solver_file: Path, *, workdir: Path, lane: str, keyer: _regress.Keyer | None = None,
              budget: float | None = None, warm: bool = True, policy: _clocks.ReplayPolicy | None = None) -> RowsGate:
    """Replay every saved row of a lane whose key changed (stable twice, expected answers given), reuse
    the cached green of every other. `rows` is the lane's whole row set ({name: folder}): a cached row
    not listed is dropped. A red row is never cached. Lane verdict: NO when any row is red."""
    keyer = keyer or _regress.Keyer()
    t0 = time.perf_counter()
    loaded = {name: SavedAttempt.load(f) for name, f in sorted(rows.items())}
    keyed = {name: row_key(keyer, solver_file, att) for name, att in loaded.items()}
    inv = Inventory(cache_path(lane, workdir), CACHE_VERSION)
    notes = [inv.stats.rebuilt] if inv.stats.rebuilt else []
    if not warm:
        for name in keyed:
            inv.discard(name)
    policy = policy or _clocks.replay_policy(workdir)
    computed: dict[str, dict] = {}

    def compute(name: str) -> dict:
        st = stability(loaded[name].folder, solver_file, workdir=workdir, budget=budget, policy=policy)
        ok, why = _judge_row(loaded[name], st)
        computed[name] = {"green": ok, "reason": why, "seconds": round(st.seconds, 3), "stability": st.status}
        return computed[name]

    inv.refresh({name: k for name, (k, _d) in keyed.items()}, compute)
    out = []
    for name, (k, days) in keyed.items():
        v = inv.get(name)
        if name in computed:
            status = GREEN if v["green"] else RED
            if not v["green"]:
                inv.discard(name)
        else:
            status = WARM
        out.append(RowOutcome(name, status, v.get("reason", ""), k, tuple(sorted(days)), float(v.get("seconds", 0.0)),
                              v.get("stability", "")))
    inv.save()
    red = [r for r in out if r.status == RED]
    verdict = _regress.NO if red else _regress.YES
    reason = "; ".join(f"{r.row}: {r.reason}" for r in red)
    notes.append(f"replays at nice {policy.nice}" + (f", at most {policy.jobs} workers each" if policy.busy else "")
                 + f": {policy.reason}")
    return RowsGate(lane, verdict, reason, tuple(out), time.perf_counter() - t0, tuple(notes))


# --------------------------------------------------------------------------- profiling one solve

@dataclass
class Profile:
    sets: int
    deliveries: int
    workers: int                        # what the set pool would fork for this many sets
    serial_seconds: float
    serial_cpu: float
    per_set: dict                       # set number -> seconds (serial)
    pooled: ReplayRun | None
    top: list                           # the heaviest functions by cumulative time (pstats lines)
    equal: bool                         # pooled answers == serial answers

    @property
    def heaviest(self) -> tuple:
        return max(self.per_set.items(), key=lambda kv: kv[1]) if self.per_set else (None, 0.0)


class _Timed:
    """A solver proxy that times each set it is asked."""

    def __init__(self, solver):
        self.solver, self.per_set = solver, {}

    def solve_set(self, questions, files, ctx):
        t = time.perf_counter()
        try:
            return self.solver.solve_set(questions, files, ctx)
        finally:
            n = ctx.get("set") if isinstance(ctx, dict) else None
            self.per_set[n] = self.per_set.get(n, 0.0) + time.perf_counter() - t


def profile_attempt(folder: Path, solver_file: Path, budget: float | None = None, *, top: int = 25,
                    pooled: bool = True) -> Profile:
    """Where one saved attempt's solve spends its time: a serial solve under cProfile (each set timed),
    then a pooled replay; the two answers must agree. Day-24-shape Binary Mastery is what it is for."""
    att = SavedAttempt.load(folder)
    solver = load_solver(solver_file)
    make = att.make_sets()
    timed = _Timed(solver)
    sets = make()
    prof = cProfile.Profile()
    errors: list = []
    t0, c0 = time.perf_counter(), time.process_time()
    with contextlib.redirect_stdout(io.StringIO()):
        prof.enable()
        try:
            raw, _to, _said = _setpool.solve(timed, sets, budget, errors)
        finally:
            prof.disable()
    serial_s, serial_c = time.perf_counter() - t0, time.process_time() - c0
    buf = io.StringIO()
    pstats.Stats(prof, stream=buf).sort_stats("cumulative").print_stats(top)
    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    run = None
    if pooled:
        with contextlib.redirect_stdout(io.StringIO()):
            run = replay(solver, make, budget, pooled=True)
    equal = run is None or not diff_answers(raw, run.answers)
    return Profile(len(sets), len(att.paths), _setpool.workers_for(len(sets)), serial_s, serial_c,
                   dict(timed.per_set), run, lines, equal)
