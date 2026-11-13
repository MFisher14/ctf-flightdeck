"""Exact process identity: a pid together with its start time (B-175).

A pid alone is not an identity. Pids are reused, so a record that says "pid 4242" can point at an
unrelated process a day later, and signalling it would hit that process. Everything that stops a
process from a record (the named-job manager, the session claim, the end-of-event reaper) checks
the pair (pid, start time) instead:

    start_time(pid)        -> float | None   the kernel's start time of pid, None when no live process
    identity(pid)          -> {"pid", "start"}   raises ProcIdError when pid is not a live process
    matches(pid, start)    -> bool           True only when pid is live AND started at `start`
    status(pid, start)     -> "alive" | "gone" | "reused" | "zombie"
    pgid_of(pid)           -> int | None
    terminate(pid, start, pgid=None)   TERM then KILL, only while (pid, start) is still that process
    terminate_report(...)  -> (outcome, signal)   the same, and which signal ended it (SIGTERM|SIGKILL)

A zombie (exited, not yet reaped by its parent) counts as not alive: it can be neither stopped nor
reused until it is reaped, and its process group is no longer provable through it. Start times
come from psutil (pinned in requirements.in); a missing psutil is a named failure, never a guess.
"""
from __future__ import annotations

import os
import signal
import time

# psutil reports create_time as a float of seconds; the same process always gives the same value,
# but it passes through a float conversion, so two reads are compared with a small tolerance. Pids
# are not reused within 10 ms, so this cannot confuse two processes.
START_TOLERANCE = 0.01


class ProcIdError(RuntimeError):
    """A process identity cannot be established (no such process, or psutil is missing)."""


def _psutil():
    try:
        import psutil
    except ImportError as e:  # pinned in requirements.in; its absence is an install fault
        raise ProcIdError(f"psutil is not installed ({e}); install requirements.txt into the venv") from None
    return psutil


def _check_pid(pid) -> int:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ProcIdError(f"bad pid {pid!r}")
    return pid


def _probe(pid: int) -> tuple[str, float | None]:
    """('alive', start) | ('zombie', start-or-None) | ('gone', None)."""
    ps = _psutil()
    try:
        p = ps.Process(pid)
        try:
            if p.status() == ps.STATUS_ZOMBIE:
                try:
                    return "zombie", p.create_time()
                except ps.Error:
                    return "zombie", None
        except ps.ZombieProcess:
            return "zombie", None
        return "alive", p.create_time()
    except ps.ZombieProcess:
        return "zombie", None
    except ps.NoSuchProcess:
        return "gone", None
    except ps.AccessDenied:
        # A process we may not inspect (another user's) cannot be ours: its identity cannot be
        # proved, so it is reported as not ours ("gone") and is never signalled.
        return "gone", None


def start_time(pid: int) -> float | None:
    """The start time of live (non-zombie) process `pid`, or None."""
    state, start = _probe(_check_pid(pid))
    return start if state == "alive" else None


def identity(pid: int) -> dict:
    """{"pid", "start"} of a live process; ProcIdError naming the pid when it is not live."""
    st = start_time(pid)
    if st is None:
        raise ProcIdError(f"pid {pid} is not a live process")
    return {"pid": pid, "start": st}


def same_start(a, b) -> bool:
    return (isinstance(a, (int, float)) and isinstance(b, (int, float))
            and abs(float(a) - float(b)) <= START_TOLERANCE)


def status(pid, start) -> str:
    """'alive' (pid live and started at `start`), 'reused' (pid live, other start), 'zombie', 'gone'.

    A record without a start time can never be 'alive': a bare pid proves nothing."""
    try:
        pid = _check_pid(pid)
    except ProcIdError:
        return "gone"
    state, now = _probe(pid)
    if state != "alive":
        return state
    if not isinstance(start, (int, float)) or isinstance(start, bool):
        return "reused"
    return "alive" if same_start(now, start) else "reused"


def matches(pid, start) -> bool:
    return status(pid, start) == "alive"


def pgid_of(pid: int) -> int | None:
    try:
        return os.getpgid(_check_pid(pid))
    except (OSError, ProcIdError):
        return None


def terminate(pid: int, start: float, *, pgid: int | None = None, grace: float = 1.0,
              timeout: float = 8.0) -> str:
    """Stop the process (pid, start) -- with `pgid`, its whole process group -- by TERM, then KILL
    after `grace` seconds; wait up to `timeout` more for it to go. Returns 'stopped', or
    'not_running' when (pid, start) is not a live process (nothing is sent).

    Every signal is preceded by the identity check, so a pid that ends and is reused mid-way is
    never hit. With `pgid`, the process must still lead that group (pid == pgid == getpgid(pid)),
    else ProcIdError and nothing is sent. ProcIdError too when it outlives the KILL by `timeout`."""
    return terminate_report(pid, start, pgid=pgid, grace=grace, timeout=timeout)[0]


def terminate_report(pid: int, start: float, *, pgid: int | None = None, grace: float = 1.0,
                     timeout: float = 8.0) -> tuple[str, str | None]:
    """terminate(), also saying which signal ended the process: ('stopped', 'SIGTERM') when it went
    within `grace` of the TERM, ('stopped', 'SIGKILL') when the KILL was needed, ('stopped', None)
    when it was gone before the TERM could be delivered, ('not_running', None) when nothing was sent."""
    _check_pid(pid)
    if pgid is not None and pgid != pid:
        raise ProcIdError(f"pid {pid} is not the leader of group {pgid}; refused to signal the group")

    def ours() -> bool:
        return matches(pid, start) and (pgid is None or pgid_of(pid) == pgid)

    if not matches(pid, start):
        return "not_running", None
    if not ours():
        raise ProcIdError(f"pid {pid} no longer leads process group {pgid}; refused to signal it")

    def send(sig) -> bool:
        try:
            if pgid is not None:
                os.killpg(pgid, sig)
            else:
                os.kill(pid, sig)
            return True
        except ProcessLookupError:
            return False

    if not send(signal.SIGTERM):
        return "stopped", None
    end = time.monotonic() + max(0.0, grace)
    while time.monotonic() < end and ours():
        time.sleep(0.05)
    last = "SIGTERM"
    if ours():
        if not send(signal.SIGKILL):
            return "stopped", "SIGTERM"      # it went between the check and the KILL
        last = "SIGKILL"
    end = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < end:
        if status(pid, start) != "alive":
            return "stopped", last
        time.sleep(0.05)
    raise ProcIdError(f"pid {pid} still running {timeout:g}s after {last}")
