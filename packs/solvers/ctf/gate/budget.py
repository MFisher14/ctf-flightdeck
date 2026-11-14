"""Per-lane time budgets for the gate (B-153): a lane gate fits in five minutes or fails loudly.

The Huntress acceptance gate took 3,713 s and still finished red; a build agent waiting on it learned
nothing for an hour. A lane gate (`ctf gate run --lane L`) is the quick check a builder runs, so it has
a budget -- `[budget] lane_seconds` in tests/gate.toml, 300 s by default and never more than 300 s
(config.MAX_LANE_SECONDS, checked when the config loads): anything longer is the pre-arm full gate's job (`ctf gate prearm`).

Time on this host is not wall time: a dozen agents share 14 cores and load sits between 50 and 170, so
a wall-clock budget would fail at random. A file's **cost** is its idle-host estimate. With C its
pytest child's CPU seconds (its waited-for children included), W its wall seconds and
r = max(1, load1 / cpus) at its start:

    cost = max(C, W - C * (r - 1))

The model: under load r a CPU-bound stretch of C seconds takes about C * r of wall time (the file gets
1/r of a core), while time spent waiting (a sleep, a socket, a child tool's I/O) does not stretch. So
W = C * r + wait, and the idle-host cost is C + wait = W - C * (r - 1). CPU time is the main measure and
never inflates with contention; the wait part is counted whole, never divided by the load (dividing the
whole wall by r made a file that mostly waits up to r times too cheap). The residual error: a file
that got more than its 1/r share of a core (stretch s < r) has its wait part under-counted by C * (r - s),
never below C; one that got less (s > r) is over-estimated, which fails loudly rather than letting a
slow lane through. A pure-CPU or pure-wait file is exact either way. A junit-seeded record has no CPU or load (C = 0,
r = 1): its cost is its wall time, an over-estimate under load until a gate run measures the file.
A lane's cost is the makespan of its files' costs packed onto `--jobs` workers
(longest first, each onto the least-loaded worker), so more jobs buy a smaller cost.

Costs come from `<state>/timings.json` (shared by every worktree through the gate state): every file a
gate run really runs records its seconds, cpu and load there, and `ctf gate budget --import-junit X`
seeds it from a full-suite junit (the per-test times summed per file; marked source "junit"). The
budget is checked twice:

  * before a lane run, from the recorded costs: when the files that have a record already exceed the
    budget the run is refused (exit 3) naming the costliest files and the --jobs that would fit;
  * after a lane run, from the measured costs: over budget is reported on the GATE line
    (`budget=over:...`) and the run exits 3 even when every test passed.

`--budget SECONDS` on the command line is the one explicit override, printed in every line it affects.
"""
from __future__ import annotations

import contextlib
import fcntl
import json
import os
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

from . import GateError

TIMINGS = "timings.json"
TIMINGS_VERSION = 1
EXIT_OVER_BUDGET = 3


def file_cost(seconds: float, cpu: float, load: float, cpus: int) -> float:
    """A file's idle-host cost in seconds (see the module docstring): its CPU seconds plus the part of its
    wall time that was waiting, which load does not stretch."""
    ratio = max(1.0, float(load) / max(1, int(cpus))) if load else 1.0
    cpu = max(0.0, float(cpu or 0.0))
    seconds = max(0.0, float(seconds or 0.0))
    return max(cpu, seconds - cpu * (ratio - 1.0))


def makespan(costs, jobs: int) -> float:
    """Longest-first packing of `costs` onto `jobs` workers: the busiest worker's total."""
    jobs = max(1, int(jobs))
    workers = [0.0] * jobs
    for c in sorted((float(c) for c in costs), reverse=True):
        i = workers.index(min(workers))
        workers[i] += c
    return max(workers) if workers else 0.0


def jobs_to_fit(costs, budget: float, max_jobs: int = 64) -> int | None:
    """The fewest workers whose makespan fits `budget`, or None when no count up to `max_jobs` does
    (one file alone costs more than the budget)."""
    costs = [float(c) for c in costs]
    if not costs:
        return 1
    if max(costs) > budget:
        return None
    for j in range(1, max_jobs + 1):
        if makespan(costs, j) <= budget:
            return j
    return None


# ------------------------------------------------------------------------------------- timings store

def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=0, sort_keys=True)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


class Timings:
    """`<state>/timings.json`: {test file: {seconds, cpu, load, cpus, ts, source}} for the last real run
    of each file. Updates take a lock beside the file, so gates in several worktrees can record at once."""

    def __init__(self, state: Path):
        self.path = Path(state) / TIMINGS
        self.lock_path = Path(state) / (TIMINGS + ".lock")

    def load(self) -> dict:
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as e:
            raise GateError(f"timings file {self.path} is unreadable ({e}); delete it to start a fresh one") from e
        if not isinstance(d, dict) or d.get("version") != TIMINGS_VERSION or not isinstance(d.get("files"), dict):
            raise GateError(f"timings file {self.path} is not version {TIMINGS_VERSION}; delete it to start a "
                            f"fresh one")
        return d["files"]

    @contextlib.contextmanager
    def _locked(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def update(self, entries: dict) -> None:
        """Merge {test: record} into the store (a record replaces the file's previous one)."""
        if not entries:
            return
        with self._locked():
            files = self.load()
            files.update(entries)
            _atomic_write(self.path, {"version": TIMINGS_VERSION, "files": files})

    def cost(self, test: str, files: dict | None = None) -> float | None:
        rec = (self.load() if files is None else files).get(test)
        if not isinstance(rec, dict):
            return None
        return file_cost(rec.get("seconds", 0.0), rec.get("cpu", 0.0), rec.get("load", 0.0), rec.get("cpus", 1))


def record_rows(state: Path, rows, *, cpus: int) -> int:
    """Record every row that really ran (not warm, not EMPTY) into the timings store. Returns the count."""
    now = time.time()
    entries = {}
    for r in rows:
        if r.warm or r.status == "EMPTY":
            continue
        entries[r.test] = {"seconds": round(float(r.seconds), 3), "cpu": round(float(getattr(r, "cpu", 0.0)), 3),
                           "load": round(float(getattr(r, "load", 0.0)), 2), "cpus": int(cpus), "ts": now,
                           "source": "gate", "status": r.status}
    Timings(state).update(entries)
    return len(entries)


def junit_file_seconds(junit: Path) -> dict[str, float]:
    """{test file: summed testcase seconds} from a full-suite pytest junit. A classname `tests.test_x`
    or `tests.test_x.TestC` maps to `tests/test_x.py` (the longest dotted prefix that names a file is
    not knowable from the junit alone, so a class segment is recognised by its capital letter)."""
    try:
        root = ET.parse(junit).getroot()
    except (OSError, ET.ParseError) as e:
        raise GateError(f"cannot read junit {junit}: {e}") from e
    out: dict[str, float] = {}
    for tc in root.iter("testcase"):
        cls = tc.get("classname") or ""
        if not cls:
            continue
        parts = cls.split(".")
        while len(parts) > 1 and parts[-1][:1].isupper():
            parts.pop()
        f = "/".join(parts) + ".py"
        try:
            t = float(tc.get("time") or 0.0)
        except ValueError:
            t = 0.0
        out[f] = out.get(f, 0.0) + t
    return out


def import_junit(state: Path, junit: Path, known_tests) -> tuple[int, list[str]]:
    """Seed the timings store from a junit for the files in `known_tests` that have no gate record yet
    (a gate-measured record is better evidence and is never overwritten). Returns (imported, unknown
    files in the junit that are not test files of this checkout)."""
    secs = junit_file_seconds(junit)
    known = set(known_tests)
    t = Timings(state)
    have = t.load()
    now = time.time()
    entries = {f: {"seconds": round(s, 3), "cpu": 0.0, "load": 0.0, "cpus": 1, "ts": now, "source": "junit"}
               for f, s in secs.items() if f in known and (f not in have or have[f].get("source") == "junit")}
    t.update(entries)
    return len(entries), sorted(f for f in secs if f not in known)


# ------------------------------------------------------------------------------------------ estimates

@dataclass
class Estimate:
    lane: str
    budget: float
    jobs: int
    cost: float                     # makespan of the files with a record
    known: int
    unknown: list = field(default_factory=list)
    top: list = field(default_factory=list)        # [(test, cost)] costliest first, at most 5
    fit_jobs: int | None = 1

    @property
    def over(self) -> bool:
        return self.cost > self.budget

    def line(self) -> str:
        verdict = "over" if self.over else "ok"
        s = (f"BUDGET lane={self.lane} limit={self.budget:.0f}s estimate={self.cost:.0f}s jobs={self.jobs} "
             f"known={self.known} unknown={len(self.unknown)} verdict={verdict}")
        if self.over:
            s += f" fits_at_jobs={self.fit_jobs if self.fit_jobs else 'none (one file alone is over)'}"
        return s

    def explain(self) -> str:
        top = ", ".join(f"{t} {c:.0f}s" for t, c in self.top)
        floor = " (a floor: files with no timing record are not counted)" if self.unknown else ""
        fix = (f"run with --jobs {self.fit_jobs}" if self.fit_jobs
               else "split the costliest file or move it out of the lane")
        return (f"lane {self.lane} costs {self.cost:.0f}s at --jobs {self.jobs}, over its {self.budget:.0f}s "
                f"budget{floor}; costliest: {top}; {fix}, split the lane, or pass --budget SECONDS")


def estimate(lane: str, tests, timings: dict, *, budget: float, jobs: int) -> Estimate:
    """The lane's cost from recorded timings (`timings` = Timings.load())."""
    costs, unknown = {}, []
    for t in tests:
        rec = timings.get(t)
        if isinstance(rec, dict):
            costs[t] = file_cost(rec.get("seconds", 0.0), rec.get("cpu", 0.0), rec.get("load", 0.0),
                                 rec.get("cpus", 1))
        else:
            unknown.append(t)
    top = sorted(costs.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return Estimate(lane=lane, budget=float(budget), jobs=max(1, int(jobs)), cost=makespan(costs.values(), jobs),
                    known=len(costs), unknown=sorted(unknown), top=top,
                    fit_jobs=jobs_to_fit(costs.values(), budget))


def measured(lane: str, rows, *, budget: float, jobs: int, cpus: int) -> Estimate:
    """The lane's cost from a finished run's rows (warm rows cost nothing: they did not run)."""
    costs = {r.test: file_cost(r.seconds, getattr(r, "cpu", 0.0), getattr(r, "load", 0.0), cpus)
             for r in rows if not r.warm}
    top = sorted(costs.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
    return Estimate(lane=lane, budget=float(budget), jobs=max(1, int(jobs)), cost=makespan(costs.values(), jobs),
                    known=len(costs), top=top, fit_jobs=jobs_to_fit(costs.values(), budget))


def lane_budget(cfg, lane: str, override: float | None = None) -> float:
    """The budget of `lane`: --budget when given, else [budget.lanes] L, else [budget] lane_seconds."""
    if override is not None:
        if override <= 0:
            raise GateError("--budget must be a positive number of seconds")
        return float(override)
    return float(cfg.lane_budgets.get(lane, cfg.lane_budget))
