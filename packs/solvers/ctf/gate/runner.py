"""Run the selected test files: one pytest child per file, `jobs` at a time, each under a wall scaled by
host load, a warm result reused where its exact key is stored. One line per file, one GATE line at the end:

    PASS     3.2s  tests/test_x.py  passed=12 failed=0 errors=0 skipped=0 xfailed=1
    PASS     0.0s  tests/test_y.py  passed=40 ... warm 3f9a1c2b7d10 (saved 61.4s)
    FAIL     8.9s  tests/test_z.py  passed=3 failed=1 ...  | <last line the file printed>
    TIMEOUT 600.0s tests/test_w.py  ... | wall 600s (load 9.1 on 14 cpus, x1.00)
    EMPTY    0.6s  tests/test_v.py  no test collected (a script-style file)
    ENV      1.1s  tests/test_d.py  the Docker daemon did not answer [docker-daemon]
    NOTRUN   2.0s  tests/test_n.py  passed=4 ... skipped=1  | 1 not run, not allowed in a strict gate: ...
    GATE result=fail mode=impact files=6 ran=5 warm=1 pass=2 fail=1 error=0 timeout=1 empty=1 env=1 ...

The wall: base_seconds * clamp(load1 / cpus, 1, max_scale), measured when the file starts, so a file
started on a contended host gets more time instead of a false red (the Huntress day-26 gate cut at 75 s
under release load). A TIMEOUT is still a failure: the gate never turns a wall into a pass.

ENV is a sixth status (B-137): a red whose every failing message blames the environment (Docker down, a
sandbox-denied bind, a declared-missing tool) is classified ENV (ctf/gate/envfail.py) from the junit and
log alone -- never by probing Docker. ENV is not in BAD: it does not turn the gate red and is not stored
warm, because the file did not test what it set out to. The CLI writes a stable record of every run to
<state>/last-fail.log (ctf/gate/faillog.py) so a red is never lost to a pipe.

NOTRUN is a seventh status (B-196, ctf/gate/notrun.py): every test that ran passed, but a test (or a
recorded part of one) did not run, of a kind the run does not allow. It is in BAD. run_file and run_gate
take `allow_not_run`: None (the API default) keeps such a file PASS; the CLI is strict by default and
passes tests/gate.toml `not_run_ok` plus any --allow-not-run kinds.

B-153: each child is reaped with os.wait4, so a row carries its CPU seconds and the load it started at;
every file that really ran is recorded in <state>/timings.json for the lane budgets (budget.py). With a
baseline ledger (baseline.py) each red file's failing tests are split into new and baseline reds.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, ContextManager

from . import envfail, notrun
from .config import matches
from .warm import WarmResult, WarmStore, file_key

# A red result: it makes the gate fail. ENV (an environment problem, not a code defect) is deliberately
# not here -- it is reported apart and never turns the gate red (envfail.py). NOTRUN (B-196): every test
# that ran passed but some test (or part of one) did not run, of a kind the run does not allow (notrun.py).
BAD = ("FAIL", "ERROR", "TIMEOUT", "NOTRUN")
XFAIL_KINDS = ("xfail", "known-fail")     # the not-run kinds a stored warm PASS may carry (as its xfail count)


@dataclass
class Row:
    test: str
    status: str                     # PASS FAIL ERROR TIMEOUT EMPTY ENV NOTRUN
    seconds: float = 0.0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    xfailed: int = 0
    warm: str = ""                  # the warm key prefix when reused
    detail: str = ""
    log: str = ""
    not_run: list = field(default_factory=list)   # notrun.NotRun items the file reported (any kind)
    cpu: float = 0.0                # the pytest child's user+system CPU seconds (B-153 budget cost)
    load: float = 0.0               # load1 when the file started (B-153 budget cost)
    red_new: int = 0                # failing tests not in the baseline ledger (B-153)
    red_baseline: int = 0           # failing tests the baseline ledger lists (B-153)


@dataclass
class Report:
    mode: str
    rows: list = field(default_factory=list)
    seconds: float = 0.0
    jobs: int = 1
    load: float = 0.0
    cpus: int = 1
    scale: float = 1.0
    wall: float = 0.0
    attributed: bool = False        # a baseline ledger split the reds (B-153): red_new / red_baseline
    budget: str = ""                # the lane budget verdict the CLI sets, e.g. "ok:120/300s" (B-153)

    @property
    def ok(self) -> bool:
        return not any(r.status in BAD for r in self.rows)

    def count(self, status: str) -> int:
        return sum(1 for r in self.rows if r.status == status)


def scaled_wall(base: float, max_scale: float, load: float, cpus: int) -> tuple[float, float]:
    """(wall seconds, scale) for a file started at this load."""
    cpus = max(1, int(cpus))
    scale = min(float(max_scale), max(1.0, float(load) / cpus))
    return base * scale, scale


def host_load() -> float:
    return os.getloadavg()[0]


def parse_junit(path: Path) -> dict:
    """Counts from a pytest junit XML: passed, failed, errors, skipped (plain skips), xfailed."""
    root = ET.parse(path).getroot()
    c = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "xfailed": 0}
    for tc in root.iter("testcase"):
        kids = {k.tag: k for k in tc}
        if "failure" in kids:
            c["failed"] += 1
        elif "error" in kids:
            c["errors"] += 1
        elif "skipped" in kids:
            if kids["skipped"].get("type") == "pytest.xfail":
                c["xfailed"] += 1
            else:
                c["skipped"] += 1
        else:
            c["passed"] += 1
    # errors outside any testcase (a collection error) still count
    for suite in root.iter("testsuite"):
        extra = int(suite.get("errors", 0) or 0) - sum(1 for tc in suite.iter("testcase") if tc.find("error") is not None)
        if extra > 0:
            c["errors"] += extra
    return c


def _log_lines(log: Path) -> list[str]:
    try:
        return [ln.strip() for ln in log.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]
    except OSError:
        return []


def _last_line(log: Path) -> str:
    lines = _log_lines(log)
    return lines[-1][:200] if lines else ""


def _env_messages(junit: Path, log: Path) -> list[str]:
    """The messages a file's ENV classification reads: the failing/erroring junit messages when the
    report has them, else the tail of the child's log (a collection error, a timeout, or a crash that
    wrote no per-case junit still prints its reason to the log)."""
    msgs = envfail.junit_bad_messages(junit) if junit.exists() else []
    if msgs:
        return msgs
    tail = _log_lines(log)[-40:]
    return ["\n".join(tail)] if tail else []


def _safe_name(test: str) -> str:
    return test.replace("/", "__")


class _Procs:
    def __init__(self):
        self.lock = threading.Lock()
        self.live: set = set()

    def kill_all(self) -> None:
        with self.lock:
            procs = list(self.live)
        for p in procs:
            _kill_group(p)


def _wait_cpu(proc: subprocess.Popen, timeout: float) -> tuple[int, float]:
    """Wait for `proc` like proc.wait(timeout) but reap it with os.wait4, so its CPU time (user + system,
    its waited-for children included) comes back with the exit code. Raises subprocess.TimeoutExpired
    after `timeout` seconds with the child still running, as Popen.wait does."""
    deadline = time.monotonic() + timeout
    delay = 0.005
    while True:
        try:
            pid, status, ru = os.wait4(proc.pid, os.WNOHANG)
        except ChildProcessError:                  # reaped elsewhere: no rusage, keep Popen's answer
            return proc.wait(), 0.0
        if pid == proc.pid:
            proc.returncode = os.waitstatus_to_exitcode(status)
            return proc.returncode, ru.ru_utime + ru.ru_stime
        left = deadline - time.monotonic()
        if left <= 0:
            raise subprocess.TimeoutExpired(proc.args, timeout)
        time.sleep(min(delay, left))
        delay = min(delay * 2, 0.2)


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.wait()


def run_file(root: Path, test: str, *, out_dir: Path, wall: float, pytest_args=(), python: str | None = None,
             procs: _Procs | None = None, allow_not_run=None) -> Row:
    """Run one test file in its own pytest child (its own process group) under `wall` seconds.
    `allow_not_run` (B-196): None keeps a green file PASS whatever did not run; a tuple of not-run kinds
    (notrun.KINDS, or "any") makes a green file NOTRUN when any not-run item is of another kind."""
    out_dir.mkdir(parents=True, exist_ok=True)
    log = out_dir / (_safe_name(test) + ".log")
    junit = out_dir / (_safe_name(test) + ".xml")
    if junit.exists():
        junit.unlink()
    cmd = [python or sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={junit}",
           test, *pytest_args]
    t0 = time.monotonic()
    with open(log, "wb") as fh:
        proc = subprocess.Popen(cmd, cwd=str(root), stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                start_new_session=True)
        if procs:
            with procs.lock:
                procs.live.add(proc)
        cpu = 0.0
        try:
            rc, cpu = _wait_cpu(proc, wall)
            timed_out = False
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            rc, timed_out = None, True
        finally:
            if procs:
                with procs.lock:
                    procs.live.discard(proc)
    secs = time.monotonic() - t0
    row = Row(test=test, status="ERROR", seconds=secs, log=str(log), cpu=cpu)
    counts = None
    if junit.exists():
        try:
            counts = parse_junit(junit)
        except ET.ParseError as e:
            row.detail = f"unreadable junit report: {e}"
    if counts:
        for k, v in counts.items():
            setattr(row, k, v)
        try:
            row.not_run = notrun.from_junit(junit)
        except ET.ParseError:
            row.not_run = []
    if timed_out:
        row.status = "TIMEOUT"
        row.detail = f"stopped at the {wall:.0f}s wall; last line: {_last_line(log)}"
    elif rc == 5:
        row.status, row.detail = "EMPTY", "no test collected (a script-style or ignored file)"
    elif rc == 0 and counts is not None:
        row.status = "PASS"
        blocking = notrun.blocking(row.not_run, allow_not_run) if allow_not_run is not None else []
        if blocking:
            first = blocking[0]
            row.status = "NOTRUN"
            row.detail = (f"{len(blocking)} not run, not allowed in a strict gate: {first.reason} ({first.test})"
                          f"; allow a kind with --allow-not-run or tests/gate.toml not_run_ok")
    elif rc == 0:
        row.detail = row.detail or "pytest exited 0 but wrote no junit report"
    elif rc == 1:
        row.status, row.detail = "FAIL", _last_line(log)
    else:
        row.detail = f"pytest exit {rc}: {_last_line(log)}"
    # A red outcome whose every failing message blames the environment (Docker down, a sandbox-denied
    # bind, a declared-missing tool) is ENV, not a code failure: reported apart, never turns the gate
    # red. Judged from the test outcomes only -- the gate never probes Docker or the network itself.
    if row.status in ("FAIL", "ERROR", "TIMEOUT"):     # a NOTRUN row is never reclassified as ENV
        verdict = envfail.classify(_env_messages(junit, log))
        if verdict:
            row.status = "ENV"
            row.detail = f"{verdict.reason} [{verdict.signature}]"
    return row


def format_row(r: Row) -> str:
    s = (f"{r.status:<7} {r.seconds:7.1f}s  {r.test}  passed={r.passed} failed={r.failed} errors={r.errors} "
         f"skipped={r.skipped} xfailed={r.xfailed}")
    if r.warm:
        s += f"  warm {r.warm}"
    if r.detail:
        s += f"  | {r.detail}"
    return s


def format_summary(rep: Report) -> str:
    rows = rep.rows
    tot = lambda k: sum(getattr(r, k) for r in rows)  # noqa: E731
    return (f"GATE result={'pass' if rep.ok else 'fail'} mode={rep.mode} files={len(rows)} "
            f"ran={sum(1 for r in rows if not r.warm)} warm={sum(1 for r in rows if r.warm)} "
            f"pass={rep.count('PASS')} fail={rep.count('FAIL')} error={rep.count('ERROR')} "
            f"timeout={rep.count('TIMEOUT')} empty={rep.count('EMPTY')} env={rep.count('ENV')} "
            f"tests_passed={tot('passed')} "
            f"tests_failed={tot('failed') + tot('errors')} skipped={tot('skipped')} xfailed={tot('xfailed')} "
            f"seconds={rep.seconds:.1f} jobs={rep.jobs} load={rep.load:.2f} cpus={rep.cpus} "
            f"wall={rep.wall:.0f}s scale={rep.scale:.2f} notrun={rep.count('NOTRUN')}"
            + (f" red_new={tot('red_new')} red_baseline={tot('red_baseline')}" if rep.attributed else "")
            + (f" budget={rep.budget}" if rep.budget else ""))


def run_gate(graph, selection, *, state: Path, out_dir: Path, jobs: int = 1, warm: bool = True, pytest_args=(),
             emit: Callable[[str], None] = print, load_fn: Callable[[], float] = host_load,
             cpus: int | None = None, python: str | None = None, no_reuse=(),
             on_row: Callable[[Row], None] | None = None, allow_not_run=None, baseline=None,
             record_timings: bool = True,
             idle: Callable[[], ContextManager] | None = None) -> Report:
    """Run `selection.tests` of `graph` and return the Report. `warm` allows reusing stored green results;
    green complete results are stored either way (a full run warms the next impact run). A file in
    `no_reuse` (a batch's red files) always runs, whatever is stored. A red run deletes the green result
    stored under its key. `on_row(row)` is called once per finished file, under the row lock (the CLI
    writes the gate's progress file with it, B-198). `allow_not_run` (B-196) is passed to run_file: with
    it set, a stored result that had xfails is reused only when both xfail kinds are allowed.

    `python` is the children's interpreter (default:
    the running one). `baseline` (a ctf.gate.baseline.Ledger) splits each red file's failing tests into
    new and baseline reds (B-153). Every file that really ran is recorded in <state>/timings.json for
    the lane budgets unless `record_timings` is False (ctf.gate.budget). `idle` (B-213) makes the
    idle-machine lock (ctf.workreg.IdleLock) a factory: it is entered before the first file runs and held
    until the last ends, and not taken at all when every file is reused warm (each file's wall is measured
    as it starts, so under the lock)."""
    from . import baseline as _baseline
    cfg = graph.cfg
    cpus = cpus or os.cpu_count() or 1
    load0 = load_fn()
    wall0, scale0 = scaled_wall(cfg.wall_base, cfg.wall_max_scale, load0, cpus)
    rep = Report(mode=selection.mode, jobs=max(1, jobs), load=load0, cpus=cpus, scale=scale0, wall=wall0,
                 attributed=baseline is not None)
    store = WarmStore(state)
    keys = {}
    for t in selection.tests:
        keys[t] = file_key(graph, t, pytest_args, python)
    graph.hashes.save()
    t0 = time.monotonic()
    lock = threading.Lock()
    rows: dict[str, Row] = {}

    def done(row: Row) -> None:
        with lock:
            rows[row.test] = row
            emit(format_row(row))
            if on_row is not None:
                on_row(row)

    no_reuse = set(no_reuse)
    todo = []
    for t in selection.tests:
        hit = store.get(keys[t], t) if warm and t not in no_reuse and not matches(t, cfg.no_warm) else None
        if hit and hit.xfailed and allow_not_run is not None and \
                notrun.blocking([notrun.NotRun(t, k, k) for k in XFAIL_KINDS], allow_not_run):
            hit = None                    # a strict run must see the xfails again, not a stored PASS
        if hit:
            done(Row(test=t, status="PASS", passed=hit.passed, xfailed=hit.xfailed, warm=keys[t][:12],
                     detail=f"reused exact-hash result (saved {hit.seconds:.1f}s)"))
        else:
            todo.append(t)
    procs = _Procs()

    def work(t: str) -> None:
        load = load_fn()
        wall, _scale = scaled_wall(cfg.wall_base, cfg.wall_max_scale, load, cpus)
        row = run_file(graph.root, t, out_dir=out_dir, wall=wall, pytest_args=pytest_args, python=python,
                       procs=procs, allow_not_run=allow_not_run)
        row.load = load
        if baseline is not None and row.status in BAD:
            junit = out_dir / (_safe_name(t) + ".xml")
            att = _baseline.attribute(_baseline.failing_keys(junit), baseline)
            row.red_new, row.red_baseline = len(att.new), len(att.baseline)
            if not att.new and not att.baseline:
                row.red_new = 1                  # red with no failing case to name (a timeout, a crash): new
            note = att.detail()
            if note:
                row.detail = f"{row.detail} | {note}" if row.detail else note
        # A stored PASS carries only an xfail count, so store only a file whose every not-run item is an
        # xfail (re-judged at reuse above). A file that reported a not-run part through the ctf_not_run
        # property has skipped == 0, and storing it would let a later strict run reuse a PASS it must not see.
        recorded = [n for n in row.not_run if n.kind not in XFAIL_KINDS]
        if row.status == "PASS" and row.skipped == 0 and row.errors == 0 and row.failed == 0 and not recorded:
            store.put(WarmResult(test=t, key=keys[t], seconds=round(row.seconds, 3), passed=row.passed,
                                 xfailed=row.xfailed, ts=time.time()))
        elif row.status in BAD:
            store.drop(keys[t])
        done(row)

    with (idle() if idle is not None and todo else nullcontext()):
        ex = ThreadPoolExecutor(max_workers=rep.jobs)
        try:
            for fut in [ex.submit(work, t) for t in todo]:
                fut.result()
        except BaseException:
            ex.shutdown(wait=False, cancel_futures=True)
            procs.kill_all()
            raise
        ex.shutdown(wait=True)
    rep.rows = [rows[t] for t in selection.tests]
    rep.seconds = time.monotonic() - t0
    if record_timings:
        from .budget import record_rows
        record_rows(state, rep.rows, cpus=cpus)
    return rep
