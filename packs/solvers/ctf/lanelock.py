"""B-141: the live per-lane lock and the promote-wanted flag.

This is the *live* lane lock, not ctf.promote (which is post-event promotion of what an event
changed). During play a lane runs one submission at a time under an exclusive lock; a standby's
finished fix that wants the lane takes that lock to promote itself. The problem it solves: on
Huntress Day 30 a standby's finished fix waited 124 s for the lane lock while a no-deadline bisect
ran the lane's rejected batch down to its one wrong id.

The fix is a flag. While a promoter waits for the lane lock it raises a *promote-wanted* flag beside
the lock. A *held, no-deadline* bisect polls the flag between sub-batches (ctf.bisect's ``stop``) and
ends the moment it sees the flag, handing the lane back so the fix goes in without waiting out the
whole split. A *deadline* attempt never reads the flag: its clock decides when it stops, and yielding
a timed attempt to a fix could lose the attempt. ``yield_stop(..., deadline=True)`` returns None for
exactly that reason, so the timed caller cannot accidentally wire the flag in.

Layout, under the workdir (ctf.paths.workdir), never committed::

    <workdir>/lanes/<lane>.lock            the flock file (held while a lane runs its submission)
    <workdir>/lanes/<lane>.promote-wanted  a promoter is waiting for the lock (JSON: who, when, pid)

The lock is an exclusive ``flock``; the kernel drops it when its holder dies, so a crashed holder
never wedges a lane (standby.py's pattern). The flag is an ordinary file whose presence is the
signal; its contents are advisory only.

    from ctf import lanelock, bisect
    # held, no-deadline bisect: yields to a waiting promote
    stop = lanelock.yield_stop(workdir, lane, deadline=False)
    res = bisect.bisect(gate, cid, answers, provenance=..., suspects=..., stop=stop)
    # a promoter waiting for the lane:
    with lanelock.promote_waiting(workdir, lane, agent="metadata-fix"):
        ...   # the flag is up until the lock is held, then cleared; promote runs under the lock
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from . import paths as _paths

LANES = "lanes"
WANTED_SUFFIX = ".promote-wanted"

# A lane name must name a file under lanes/; keep it a plain token (the lane ids are short slugs:
# metadata, binary, web, script-analysis, warmups, mobile-android).
_SAFE_LANE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class LaneLockError(RuntimeError):
    """A lane name cannot safely name a file, or the lanes dir cannot be used."""


def safe_lane(lane: str) -> str:
    name = str(lane)
    if not _SAFE_LANE.fullmatch(name):
        raise LaneLockError(
            f"bad lane name {lane!r}: use [A-Za-z0-9][A-Za-z0-9_.-]{{0,63}} (it names a lock file)")
    return name


def _resolve_workdir(workdir: Path | None) -> Path:
    return Path(workdir) if workdir is not None else _paths.workdir()


def lanes_dir(workdir: Path | None = None) -> Path:
    return _resolve_workdir(workdir) / LANES


def lock_path(workdir: Path | None, lane: str) -> Path:
    return lanes_dir(workdir) / f"{safe_lane(lane)}.lock"


def wanted_path(workdir: Path | None, lane: str) -> Path:
    return lanes_dir(workdir) / f"{safe_lane(lane)}{WANTED_SUFFIX}"


# --------------------------------------------------------------------------- the lock

@contextmanager
def lane_lock(workdir: Path | None, lane: str, *, blocking: bool = True):
    """Hold the lane's exclusive ``flock`` for the duration of the ``with`` block. ``blocking`` False
    makes it raise BlockingIOError instead of waiting when another holder has the lane. The kernel
    releases the lock when the fd is closed (here) or the process dies."""
    path = lock_path(workdir, lane)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
    flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
    try:
        fcntl.flock(fd, flags)
        yield
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- the flag

def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp{os.getpid()}-{threading.get_ident()}")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def set_promote_wanted(workdir: Path | None, lane: str, agent: str = "promote",
                       *, clock=time.time) -> Path:
    """Raise the promote-wanted flag for ``lane``: a promoter is waiting for the lane lock. Returns
    the flag path. Idempotent (a second waiter just rewrites it)."""
    path = wanted_path(workdir, lane)
    _write_atomic(path, json.dumps({"agent": str(agent), "pid": os.getpid(),
                                    "at": round(clock(), 3)}) + "\n")
    return path


def clear_promote_wanted(workdir: Path | None, lane: str) -> None:
    """Lower the flag. Idempotent: no error if it was never raised or already cleared."""
    try:
        wanted_path(workdir, lane).unlink()
    except FileNotFoundError:
        pass


def promote_wanted(workdir: Path | None, lane: str) -> bool:
    """True when a promoter has raised the flag for ``lane`` (the held-bisect yield signal)."""
    return wanted_path(workdir, lane).exists()


def yield_stop(workdir: Path | None, lane: str, *, deadline: bool):
    """The ``stop`` predicate for ctf.bisect. On a **no-deadline** attempt it returns a callable that
    is true once the promote-wanted flag is up, so a held split yields the lane to the waiting fix. On
    a **deadline** attempt it returns None: a timed attempt never reads the flag (yielding it to a fix
    could lose the attempt), and a None stop means ctf.bisect never checks it."""
    if deadline:
        return None
    return lambda: promote_wanted(workdir, lane)


# --------------------------------------------------------------------------- the promoter's wait

@contextmanager
def promote_waiting(workdir: Path | None, lane: str, *, agent: str = "promote",
                    blocking: bool = True):
    """A promoter's wait for the lane: raise the promote-wanted flag, block on the lane lock, and once
    the lock is held clear the flag and run the ``with`` block under the lock. The flag is cleared on
    the way out whether or not the lock was ever acquired."""
    set_promote_wanted(workdir, lane, agent)
    try:
        with lane_lock(workdir, lane, blocking=blocking):
            clear_promote_wanted(workdir, lane)
            yield
    finally:
        clear_promote_wanted(workdir, lane)
