"""Progress files for long runs: what is running right now, how far it is, and when it will finish (B-198).

    from ctf import progress
    p = progress.Progress(folder, "gate", total=120, jobs=2, label="impact", head="a46b293...")
    p.step(seconds=3.2)                      # one item done (a test file, a challenge, ...)
    p.step(warm=True)                        # done without running (a reused result)
    p.step(seconds=8.9, bad="tests/test_x.py")
    p.finish("fail")                         # also appends the run to <folder>/history.jsonl
    for rec in progress.read(folder): rec["state"], rec["eta"]

Why. Status and ETA questions were answered by model turns, and once by an agent
that said it was building with nothing launched. A progress file is written by the process doing the
work, so `ctf live` can answer from it with no model: a record whose owner pid is gone and that never
finished is reported as `died`, never as running.

One JSON file per run, `<folder>/<kind>-<run id>.json`, replaced atomically on every step:

    kind, label, run_id, pid, child_pid?, started, updated, total (int or null: a job with no item
    count), done, ran, warm, ran_seconds (sum of the seconds of the items that ran), bad, bad_items
    (first 20), jobs (items at a time), head (git commit the run started from, or null), finished
    (epoch or null), result (null while running)

Where: the regression gate writes `<gate state>/progress/` (ctf.paths.gate_state(), `ctf gate run`);
`ctf live job` writes `<status state>/progress/` (ctf.paths.status_state()). The record holds no path,
no command line and no challenge text, so it is safe to put on a status page.

State, computed when read: `running` (not finished, owner pid alive), `finished`, `died` (not finished,
owner pid gone), `unreadable` (a corrupt file: reported with its error, never skipped).

ETA, computed when read: remaining items x seconds per item / jobs. Seconds per item is the mean of
this run's items that ran (`observed`), else the median per-item time of the last 10 finished runs of
the same kind and label in history.jsonl (`usual`), else unknown (`basis` says so). A run with no total
has no ETA. Finished runs beyond the newest 20 per folder are pruned when a run finishes, and
history.jsonl is trimmed to its newest 500 lines.
"""
from __future__ import annotations

import json
import os
import statistics
import subprocess
import time
from pathlib import Path
from typing import Callable

PROGRESS_DIR = "progress"
HISTORY = "history.jsonl"
KEEP_FINISHED = 20
MAX_BAD_ITEMS = 20
HISTORY_RUNS = 10
HISTORY_MAX = 500           # history.jsonl keeps its newest lines only (the ETA reads the last 10 runs)

RUNNING, FINISHED, DIED, UNREADABLE = "running", "finished", "died", "unreadable"


def pid_alive(pid) -> bool:
    """True when a process with this pid exists (one of another user counts)."""
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def head_of(root: Path) -> str | None:
    """The git commit checked out at `root`, or None when it is not a git checkout (the record then
    says it does not know what code the run started from)."""
    try:
        cp = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True,
                            timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    out = cp.stdout.strip()
    return out if cp.returncode == 0 and len(out) in (40, 64) else None


def _write_atomic(p: Path, rec: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(rec, sort_keys=True), encoding="utf-8")
    os.replace(tmp, p)


class Progress:
    """The progress file of one run. Every method rewrites the file; `finish` also records history."""

    def __init__(self, folder: Path, kind: str, *, total: int | None, jobs: int = 1, label: str = "",
                 head: str | None = None, child_pid: int | None = None, run_id: str | None = None,
                 clock: Callable[[], float] = time.time):
        if not kind or not kind.replace("-", "").replace("_", "").isalnum():
            raise ValueError(f"bad progress kind {kind!r}")
        if total is not None and (not isinstance(total, int) or total < 0):
            raise ValueError(f"bad progress total {total!r}")
        self.folder, self.clock = Path(folder), clock
        now = clock()
        # two runs started by one process in the same second get their own files
        run_id = run_id or f"{time.strftime('%Y%m%d-%H%M%S', time.localtime(now))}-{os.getpid()}-{os.urandom(3).hex()}"
        self.path = self.folder / f"{kind}-{run_id}.json"
        self.rec = {"kind": kind, "label": label, "run_id": run_id, "pid": os.getpid(), "child_pid": child_pid,
                    "started": now, "updated": now, "total": total, "done": 0, "ran": 0, "warm": 0,
                    "ran_seconds": 0.0, "bad": 0, "bad_items": [], "jobs": max(1, int(jobs)), "head": head,
                    "finished": None, "result": None}
        _write_atomic(self.path, self.rec)

    def set(self, **fields) -> None:
        """Update fields that are not counters (child_pid, total once known)."""
        allowed = {"child_pid", "total", "head", "jobs"}
        bad = set(fields) - allowed
        if bad:
            raise ValueError(f"Progress.set: not settable: {', '.join(sorted(bad))}")
        self.rec.update(fields)
        self.rec["updated"] = self.clock()
        _write_atomic(self.path, self.rec)

    def step(self, *, seconds: float | None = None, warm: bool = False, bad: str | bool | None = None) -> None:
        r = self.rec
        r["done"] += 1
        if warm:
            r["warm"] += 1
        else:
            r["ran"] += 1
            r["ran_seconds"] = round(r["ran_seconds"] + max(0.0, float(seconds or 0.0)), 3)
        if bad:
            r["bad"] += 1
            if isinstance(bad, str) and len(r["bad_items"]) < MAX_BAD_ITEMS:
                r["bad_items"].append(bad)
        r["updated"] = self.clock()
        _write_atomic(self.path, r)

    def finish(self, result: str) -> None:
        r = self.rec
        if r["finished"] is not None:
            return
        now = self.clock()
        r["finished"] = r["updated"] = now
        r["result"] = str(result)
        _write_atomic(self.path, r)
        line = {"kind": r["kind"], "label": r["label"], "total": r["total"], "done": r["done"], "ran": r["ran"],
                "ran_seconds": r["ran_seconds"], "seconds": round(now - r["started"], 3), "jobs": r["jobs"],
                "result": r["result"], "ts": now}
        with open(self.folder / HISTORY, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
        prune(self.folder)
        trim_history(self.folder)


def trim_history(folder: Path, keep: int | None = None) -> int:
    """Keep the newest `keep` (default HISTORY_MAX) lines of history.jsonl, rewritten atomically; returns
    the number of lines dropped."""
    keep = HISTORY_MAX if keep is None else keep
    p = Path(folder) / HISTORY
    if not p.exists():
        return 0
    lines = p.read_text(encoding="utf-8").splitlines(keepends=True)
    if len(lines) <= keep:
        return 0
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text("".join(lines[-keep:]), encoding="utf-8")
    os.replace(tmp, p)
    return len(lines) - keep


def prune(folder: Path, keep: int = KEEP_FINISHED) -> list[Path]:
    """Remove finished run files beyond the newest `keep`; running, died and unreadable ones stay."""
    done = []
    for p in Path(folder).glob("*.json"):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(rec, dict) and rec.get("finished") is not None:
            done.append((float(rec["finished"]), p))
    done.sort(reverse=True)
    gone = [p for _, p in done[keep:]]
    for p in gone:
        p.unlink(missing_ok=True)
    return gone


def history(folder: Path) -> list[dict]:
    """The finished runs of this folder, oldest first. A corrupt line is ignored: history only feeds the
    `usual` ETA, which then says it has fewer runs to go on, never a wrong state."""
    p = Path(folder) / HISTORY
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict):
            out.append(rec)
    return out


def usual_item_seconds(hist: list[dict], kind: str, label: str) -> float | None:
    """Median seconds per item that ran, over the last HISTORY_RUNS finished runs of this kind and label."""
    rates = [h["ran_seconds"] / h["ran"] for h in hist
             if h.get("kind") == kind and h.get("label") == label and isinstance(h.get("ran"), int)
             and h["ran"] > 0 and isinstance(h.get("ran_seconds"), (int, float))]
    rates = rates[-HISTORY_RUNS:]
    return statistics.median(rates) if rates else None


def estimate(rec: dict, usual: float | None) -> dict:
    """{"eta_s": seconds or None, "basis": observed | usual | why unknown}."""
    if rec.get("finished") is not None:
        return {"eta_s": 0.0, "basis": "finished"}
    total = rec.get("total")
    if total is None:
        return {"eta_s": None, "basis": "no item count"}
    remaining = max(0, int(total) - int(rec.get("done") or 0))
    jobs = max(1, int(rec.get("jobs") or 1))
    if rec.get("ran"):
        per, basis = float(rec["ran_seconds"]) / int(rec["ran"]), "observed"
    elif usual is not None:
        per, basis = usual, "usual"
    else:
        return {"eta_s": None, "basis": "unknown until the first item finishes"}
    return {"eta_s": round(remaining * per / jobs, 1), "basis": basis}


def read(folder: Path, *, alive: Callable[[object], bool] = pid_alive) -> list[dict]:
    """Every run file in `folder`, newest first, each with `state`, `eta` and `file` (its name)."""
    folder = Path(folder)
    if not folder.is_dir():
        return []
    hist = history(folder)
    out = []
    for p in sorted(folder.glob("*.json")):
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
            if not isinstance(rec, dict) or "kind" not in rec or "started" not in rec:
                raise ValueError("not a progress record")
        except (OSError, ValueError) as e:
            out.append({"file": p.name, "state": UNREADABLE, "error": f"{type(e).__name__}: {e}", "started": 0.0})
            continue
        rec["file"] = p.name
        if rec.get("finished") is not None:
            rec["state"] = FINISHED
        elif alive(rec.get("pid")) or alive(rec.get("child_pid")):
            rec["state"] = RUNNING
        else:
            rec["state"] = DIED
        rec["eta"] = estimate(rec, usual_item_seconds(hist, rec["kind"], rec.get("label", "")))
        if rec["state"] == DIED:
            rec["eta"] = {"eta_s": None, "basis": "died"}
        out.append(rec)
    out.sort(key=lambda r: float(r.get("started") or 0.0), reverse=True)
    return out
