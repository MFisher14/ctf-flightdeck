"""The idle-machine lock flags (B-213, ctf.workreg) shared by `ctf gate run` and `ctf adapt gate|prewarm|chain`.

    --idle-lock | --no-idle-lock   hold the lock exclusive while tests or cases run; neither given:
                                   $CTF_IDLE_LOCK (a boolean), else off
    --idle-timeout S               give up after S s waiting (an error naming the holder); default: wait
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Callable

from .. import env as _env
from .. import workreg as _workreg

ENV_IDLE_LOCK = "CTF_IDLE_LOCK"


def add_idle_lock_args(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--idle-lock", dest="idle_lock", action="store_true", default=None,
                   help=f"hold the idle-machine lock exclusive while tests run (ctf.workreg; default: "
                        f"${ENV_IDLE_LOCK}, else off)")
    g.add_argument("--no-idle-lock", dest="idle_lock", action="store_false",
                   help=f"do not take the idle-machine lock, whatever ${ENV_IDLE_LOCK} says")
    p.add_argument("--idle-timeout", type=float, metavar="S",
                   help="give up (an error naming the holder) after S s waiting for the lock (default: wait)")


def idle_lock_factory(args: argparse.Namespace, root: Path | None, label: str,
                      *, stream=None) -> Callable[[], _workreg.IdleLock] | None:
    """The idle-lock factory the flags ask for, or None when the lock is off. The flags win over
    $CTF_IDLE_LOCK; a non-boolean $CTF_IDLE_LOCK is a WorkRegError naming it (never read as off). Each
    wait reason is printed to `stream` (stderr) once, when it changes."""
    on = args.idle_lock
    if on is None:
        try:
            on = _env.get_bool(ENV_IDLE_LOCK, False)
        except _env.EnvError as e:
            raise _workreg.WorkRegError(str(e)) from None
    if not on:
        return None
    out = stream if stream is not None else sys.stderr
    last = {"why": None}

    def waiting(why: str) -> None:
        if why != last["why"]:
            last["why"] = why
            print(f"{label}: waiting for the idle-machine lock: {why}", file=out)
            out.flush()
    return _workreg.idle_lock_for(root, label, timeout=args.idle_timeout, on_wait=waiting)
