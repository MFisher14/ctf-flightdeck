"""A stable record of the gate's last run, so a failure is never lost to a pipe (B-137).

On Oct 9 one of the acceptance gate's reds "was never identified because output was piped to tail":
the line that named the failing item scrolled off before the operator saw it. Per-run output lives
under ``<state>/runs/<stamp>/`` with a fresh name each time, so an operator who piped the run and lost
the tail has nowhere fixed to look.

This writes two files at a FIXED path under the gate state folder, overwritten every run, so there is
always one place that names what failed:

    <state>/last-run.json   the machine form: result, mode, head, when, the run's output dir, and one
                            record per file that was not green ({test, status, detail, log}).
    <state>/last-fail.log   the human form: a header line naming the result and the failing items, then
                            one line per red or ENV file -- its status, the file, the detail, and the
                            absolute path to that file's own log. A green run writes a one-line "all N
                            files green" so a stale red log is never mistaken for the current state.

Both are written atomically (temp file + rename) so a reader never sees half a file, and FAIL/ERROR/
TIMEOUT are separated from ENV (an environment problem, not a code defect; see ``envfail.py``): an arm
run records what the code left red apart from what the environment left unproven.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

LAST_RUN = "last-run.json"
LAST_FAIL = "last-fail.log"

# The statuses that are not a clean green pass, in the order the fail log lists them.
_RED = ("FAIL", "ERROR", "TIMEOUT")
_REPORTED = _RED + ("ENV",)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _row_log(row, run_dir: Path) -> str:
    """The absolute path to a row's own pytest log, as the runner names it (warm.py layout)."""
    if getattr(row, "log", ""):
        return str(Path(row.log).resolve())
    safe = row.test.replace("/", "__")
    return str((run_dir / (safe + ".log")).resolve())


def record(state: Path, root: Path, rep, *, run_dir: Path, head: str = "",
           when: float | None = None) -> Path:
    """Write <state>/last-run.json and <state>/last-fail.log for a finished run. Returns the fail-log
    path. Called whatever the result, so the stable files always describe the latest run."""
    state = Path(state)
    when = time.time() if when is None else when
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(when))
    reported = [r for r in rep.rows if r.status in _REPORTED]
    red = [r for r in reported if r.status in _RED]
    env = [r for r in reported if r.status == "ENV"]

    doc = {
        "when": stamp,
        "result": "pass" if rep.ok else "fail",
        "mode": rep.mode,
        "head": head,
        "repo": str(Path(root).resolve()),
        "run_dir": str(Path(run_dir).resolve()),
        "files": len(rep.rows),
        "red": len(red),
        "env": len(env),
        "items": [{"test": r.test, "status": r.status, "detail": r.detail,
                   "log": _row_log(r, run_dir), "red_new": getattr(r, "red_new", 0),
                   "red_baseline": getattr(r, "red_baseline", 0)} for r in reported],
    }
    _atomic_write(state / LAST_RUN, json.dumps(doc, indent=1, sort_keys=True) + "\n")

    lines = [f"# ctf gate last run: {stamp} result={doc['result']} mode={rep.mode}"
             + (f" head={head}" if head else ""),
             f"# repo={doc['repo']} run={doc['run_dir']} files={len(rep.rows)} "
             f"fail={sum(1 for r in red if r.status == 'FAIL')} "
             f"error={sum(1 for r in red if r.status == 'ERROR')} "
             f"timeout={sum(1 for r in red if r.status == 'TIMEOUT')} env={len(env)}"]
    if not red and not env:
        lines.append(f"all {len(rep.rows)} file(s) green")
    for r in red:
        lines.append(f"{r.status:<7} {r.test}  {r.detail}  (log: {_row_log(r, run_dir)})")
    for r in env:
        lines.append(f"ENV     {r.test}  {r.detail}  (log: {_row_log(r, run_dir)})")
    _atomic_write(state / LAST_FAIL, "\n".join(lines) + "\n")
    return state / LAST_FAIL
