#!/usr/bin/env python3
"""Offline work that gives the CPU to every running clock (the adaptability build; the parallel racers).

On a release morning the owner and two helper agents race on every lane that stops (tools/helpers_due.py), each
replaying candidate fixes offline (`tools/preflight.py --replay ... --yield-clocks`), while Layer 1 and the
agents' resumes run clocks on the same 14 cores. Nothing an agent replays may slow a clock. This module is the
one way such work runs:

  run_held(argv, max_hold=MAX_HOLD) -> exit code

starts `argv` as a child at nice NICE (10), in a process group of its own, and holds that whole group STOPPED
(SIGSTOP to the group: a replay solves in a grandchild) for as long as a clock runs anywhere
on this machine (the caller's `busy()`, looked at every POLL s; in Huntress `judge.clock_busy()`, which master
does not carry, so a run without busy= says so and is never held), SIGCONT when the clock is over: the work never
computes beside a clock, even mid-replay. It is the rule of tools/forecast_timed.py's --yield-clocks (row 385),
for an agent's command, with one difference: an agent wants its answer, so past `max_hold` s held in all the
child is let go (it runs on at nice 10 and is never held again) instead of ended. One NOTE line goes to stderr,
never stdout (a replay's JSON stays whole): `NOTE held <s> s in <n> stop(s) while a clock ran (--yield-clocks,
adaptability build)`.

Only for work that never takes a clock, a ticket or a lock a clock or a gate waits for: a replay, an unpack, a
scratch reader. A tool that starts a clock would be held by its own clock. The child's stdin, stdout and stderr
are the caller's. A parent ended by SIGTERM, SIGHUP or ^C ends its child too, never leaving it STOPPED.
`CTF_YIELD=off` runs the child at nice NICE with no hold.
"""
import contextlib
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import env as ctf_env
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[1]))
    from ctf import env as ctf_env

NICE = 10            # the child's niceness: a clock's runner (nice 0) always comes first
POLL = 0.05          # seconds between looks at the clock locks
MAX_HOLD = 120.0     # seconds held in all, after which the child runs on (niced) and is never held again

HERE = Path(__file__).resolve().parent


# The default busy source was judge.clock_busy (tools/judge.py, the Huntress clock locks). The merge plan
# archived judge.py and kept this module for its nice-10 child (infra-tools-ctf-claude.merge.json, verifier note),
# so B-001b removed the import that could never load: a caller that wants the hold passes busy=, and a run
# without one says so on stderr instead of quietly never holding. B-253 added the master's source,
# clock_busy(workdir): the running clocks of ctf.adapt.clocks (held by chain.AttemptGuard), counting only clocks
# WITH a deadline (Huntress row 591: judge.clock_busy() had no deadline test, so a regular Time Trial with no
# deadline held every other lane's replays).
NO_BUSY_SOURCE = ("NOTE no clock source (tools/judge.py, the Huntress clock locks, is not in master; pass "
                  "busy=clock_busy(workdir)): "
                  f"the work runs at nice {NICE} and is never held")


def clock_busy(workdir):
    """The deadline-aware busy source for run_held: true only while a clock with a deadline runs in another
    process (ctf.adapt.clocks.deadline_busy over `workdir`'s running clocks). A deadline-null clock is idle."""
    from ctf.adapt import clocks as _clocks
    return _clocks.busy_source(Path(workdir))


def _nice_child():
    with contextlib.suppress(OSError):
        os.nice(NICE)


def _signal(child, sig):
    """sig to the child's whole process group (the child and everything it started); the child alone when the
    group is gone."""
    try:
        os.killpg(child.pid, sig)
    except OSError:
        with contextlib.suppress(OSError):
            os.kill(child.pid, sig)


def run_held(argv: list, max_hold: float = MAX_HOLD, busy=None, poll: float = POLL, note=None) -> int:
    """Run argv held while a clock runs; the child's exit code (1 when it could not be started)."""
    holding = str(ctf_env.get("CTF_YIELD", "")).strip().lower() not in ("off", "0", "no")
    note = note or (lambda text: print(text, file=sys.stderr, flush=True))
    if busy is None:
        if holding:
            note(NO_BUSY_SOURCE)
        holding = False
        busy = lambda: False   # noqa: E731 - never consulted: holding is off
    try:
        # A process group of its own: a replay solves in a grandchild (preflight.py --child), and SIGSTOP must
        # reach every process of the work, not only the one started here.
        child = subprocess.Popen(list(argv), preexec_fn=_nice_child, process_group=0)
    except OSError as e:
        note(f"NOTE the held run could not start: {e}")
        return 1

    def _ended(signum, frame):
        raise SystemExit(128 + signum)
    for sig in (signal.SIGTERM, signal.SIGHUP):
        with contextlib.suppress(ValueError, OSError):
            signal.signal(sig, _ended)
    stopped, held, stops, since, free = False, 0.0, 0, 0.0, not holding
    try:
        while child.poll() is None:
            if not free:
                try:
                    now_busy = bool(busy())
                except Exception:
                    now_busy = False
                if now_busy and not stopped:
                    _signal(child, signal.SIGSTOP)
                    stopped, stops, since = True, stops + 1, time.monotonic()
                elif not now_busy and stopped:
                    _signal(child, signal.SIGCONT)
                    held += time.monotonic() - since
                    stopped = False
                if stopped and held + time.monotonic() - since > max_hold:
                    _signal(child, signal.SIGCONT)
                    held += time.monotonic() - since
                    stopped, free = False, True
                    note(f"NOTE held {max_hold:g} s in all for clocks: the work runs on at nice {NICE} "
                         f"(--yield-clocks, adaptability build)")
            time.sleep(poll)
    except BaseException:
        _signal(child, signal.SIGKILL)
        _signal(child, signal.SIGCONT)
        raise
    finally:
        if stopped:
            held += time.monotonic() - since
            _signal(child, signal.SIGCONT)
        if child.poll() is None:
            with contextlib.suppress(Exception):
                child.wait(5)
    if stops:
        note(f"NOTE held {held:.1f} s in {stops} stop(s) while a clock ran (--yield-clocks, adaptability build)")
    code = child.returncode
    return 1 if code is None else (128 - code if code < 0 else code)
