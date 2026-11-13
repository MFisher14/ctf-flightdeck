"""Running clocks and the deadline-aware quiet check (B-253).

Offline replay work (the lane gate's replays, a prewarm, an agent's `tools/yield_clocks.py` child) shares
the CPU with every running timed attempt. At Huntress 2026 the quiet check asked "does any clock run?"
(`judge.clock_busy()`), with no deadline test: on Day 30 Metadata's regular Time Trial, a clock with no
deadline, made every other lane busy, so Binary's prewarm was skipped and its TT gate replayed throttled
(3 processes at nice 10) for 147.26 s (improvements row 591). A clock with no deadline cannot be lost to
CPU contention, so it must not throttle anything. This module is that check, platform-free:

    with hold("binary-day-30/time_trial", deadline=time.time() + 27, workdir=wd):   # AttemptGuard does this
        ...
    running(wd)                  # [Clock(challenge_id, pid, deadline, started, path)], live ones only
    deadline_busy(wd)            # True only while a clock WITH a deadline runs (in another process)
    busy_source(wd)              # that test as a zero-argument callable: tools/yield_clocks.run_held(busy=...)
    replay_policy(wd)            # ReplayPolicy(jobs, nice, busy, reason): idle 10 jobs at nice 0, busy 3 at 10

**The registry.** One JSON file per running clock under `<workdir>/adapt/clocks/` (`challenge_id`,
`pid`, `deadline` as epoch seconds or null, `started`), written atomically (temp file + rename) when a
clock starts and removed when it ends. `chain.AttemptGuard` holds one for the life of every timed attempt.

**Live.** A clock is running while its process is alive and, when it has a deadline, until
`deadline + GRACE` (a runner killed without cleanup, or one still sending past its window, holds the CPU
no longer than that). A file whose process is gone is stale: it is removed when read, never counted. A
file that is not a clock record (unreadable, wrong fields) is an AdaptError naming it, never skipped.

**Busy.** Only a clock with a deadline makes the machine busy, and never the asking process's own clock
(a runner's own gate must not throttle itself). A deadline-null clock counts as idle.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from . import AdaptError

GRACE = 5.0                 # seconds a clock still counts after its deadline
REPLAY_PROCS_IDLE = 10      # replay processes when no deadline clock runs (Huntress REPLAY_PROCS_IDLE)
REPLAY_PROCS_BUSY = 3       # ... and while one does (REPLAY_PROCS_BUSY)
NICE_BUSY = 10              # replay niceness while a deadline clock runs; nice 0 when idle
SUFFIX = ".clock.json"
_FIELDS = {"challenge_id", "pid", "deadline", "started"}


def clock_dir(workdir: Path) -> Path:
    return Path(workdir) / "adapt" / "clocks"


@dataclass(frozen=True)
class Clock:
    challenge_id: str
    pid: int
    deadline: float | None      # epoch seconds; None: a regular attempt with no deadline
    started: float
    path: Path

    def live(self, now: float) -> bool:
        return _alive(self.pid) and (self.deadline is None or now <= self.deadline + GRACE)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True                 # another user's process with that pid: it exists
    return True


def _file_for(challenge_id: str, pid: int) -> str:
    tag = hashlib.sha256(challenge_id.encode("utf-8", "surrogateescape")).hexdigest()[:16]
    return f"{pid}-{tag}{SUFFIX}"


def check_deadline(deadline) -> float | None:
    if deadline is None:
        return None
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or deadline != deadline:
        raise AdaptError(f"clock deadline {deadline!r}: epoch seconds, or None for a clock without one")
    return float(deadline)


def start(challenge_id: str, *, deadline: float | None, workdir: Path, pid: int | None = None,
          now: float | None = None) -> Path:
    """Register a running clock; returns its file (remove it with `stop`)."""
    if not isinstance(challenge_id, str) or not challenge_id:
        raise AdaptError("a clock needs a challenge id")
    deadline = check_deadline(deadline)
    pid = os.getpid() if pid is None else int(pid)
    d = clock_dir(workdir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / _file_for(challenge_id, pid)
    rec = {"challenge_id": challenge_id, "pid": pid, "deadline": deadline,
           "started": time.time() if now is None else float(now)}
    fd, tmp = tempfile.mkstemp(prefix=".clock-", suffix=".tmp", dir=str(d))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(rec, fh)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    return path


def stop(path: Path) -> None:
    with contextlib.suppress(FileNotFoundError):
        Path(path).unlink()


@contextlib.contextmanager
def hold(challenge_id: str, *, deadline: float | None, workdir: Path):
    """A running clock for the life of the block."""
    path = start(challenge_id, deadline=deadline, workdir=workdir)
    try:
        yield path
    finally:
        stop(path)


def _load(path: Path) -> Clock:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise AdaptError(f"clock file {path} is unreadable ({type(e).__name__}); remove it if no clock runs") from None
    if not isinstance(raw, dict) or set(raw) != _FIELDS:
        raise AdaptError(f"clock file {path} is not a clock record (fields {sorted(_FIELDS)})")
    pid, cid, started = raw["pid"], raw["challenge_id"], raw["started"]
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0 or not isinstance(cid, str) \
            or isinstance(started, bool) or not isinstance(started, (int, float)):
        raise AdaptError(f"clock file {path} has a malformed pid, challenge id or start")
    try:
        deadline = check_deadline(raw["deadline"])
    except AdaptError:
        raise AdaptError(f"clock file {path} has a malformed deadline") from None
    return Clock(cid, pid, deadline, float(started), path)


def running(workdir: Path, *, now: float | None = None) -> list[Clock]:
    """The clocks running now, oldest first. A stale file (its process is gone) is removed."""
    d = clock_dir(workdir)
    if not d.is_dir():
        return []
    now = time.time() if now is None else float(now)
    out = []
    for p in sorted(d.glob("*" + SUFFIX)):
        try:
            c = _load(p)
        except AdaptError:
            if not p.exists():          # removed by its owner while we read it: it has ended
                continue
            raise
        if not _alive(c.pid):
            stop(p)
            continue
        if c.live(now):
            out.append(c)
    return sorted(out, key=lambda c: c.started)


def deadline_clocks(workdir: Path, *, now: float | None = None, exclude_pid: int | None = None) -> list[Clock]:
    """The running clocks that have a deadline, the process `exclude_pid` (default: this one) left out."""
    me = os.getpid() if exclude_pid is None else exclude_pid
    return [c for c in running(workdir, now=now) if c.deadline is not None and c.pid != me]


def deadline_busy(workdir: Path, *, now: float | None = None, exclude_pid: int | None = None) -> bool:
    """True only while a clock with a deadline runs in another process. A deadline-null clock is idle."""
    return bool(deadline_clocks(workdir, now=now, exclude_pid=exclude_pid))


def busy_source(workdir: Path):
    """deadline_busy(workdir) as a zero-argument callable (tools/yield_clocks.run_held's `busy`)."""
    wd = Path(workdir)
    return lambda: deadline_busy(wd)


@dataclass(frozen=True)
class ReplayPolicy:
    jobs: int                   # replay processes at once
    nice: int                   # their niceness
    busy: bool
    reason: str


def replay_policy(workdir: Path, *, cpus: int | None = None, now: float | None = None,
                  exclude_pid: int | None = None) -> ReplayPolicy:
    """How offline replays share the machine now: REPLAY_PROCS_BUSY at nice NICE_BUSY while a deadline
    clock runs, else REPLAY_PROCS_IDLE (at most the CPU count) at nice 0."""
    cpus = (os.cpu_count() or 1) if cpus is None else max(1, int(cpus))
    held = deadline_clocks(workdir, now=now, exclude_pid=exclude_pid)
    if held:
        names = ", ".join(c.challenge_id for c in held[:3]) + (f" (+{len(held) - 3})" if len(held) > 3 else "")
        return ReplayPolicy(min(REPLAY_PROCS_BUSY, cpus), NICE_BUSY, True, f"a deadline clock runs: {names}")
    others = [c for c in running(workdir, now=now) if c.deadline is None]
    why = "no clock runs" if not others else f"only clocks without a deadline run ({len(others)}): idle"
    return ReplayPolicy(min(REPLAY_PROCS_IDLE, cpus), 0, False, why)
