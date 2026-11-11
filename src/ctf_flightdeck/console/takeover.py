"""Take over: hand the terminal to a lane's shell, then take it back (M1).

The console's event loop keeps running while the player is in the shell, so the other
lanes keep working; nothing is drawn meanwhile (the console is suspended and its output
held). The shell gets its own process group and becomes the terminal's foreground group,
the way a shell runs a job: ctrl+c in the shell reaches the shell's programs, not the
console.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

from textual.app import App


async def run_in_terminal(app: App, argv: Sequence[str], cwd: Path | None, env: Mapping[str, str] | None) -> int:
    """Run `argv` with the terminal until it exits; return its exit status.

    Raises textual.app.SuspendNotSupported where the console cannot let go of the
    terminal (a headless or web console), and OSError when there is no terminal."""
    with app.batch_update():  # nothing is drawn while the player has the terminal
        with app.suspend():
            return await _foreground(argv, cwd, env)


async def _foreground(argv: Sequence[str], cwd: Path | None, env: Mapping[str, str] | None) -> int:
    stdin = sys.__stdin__
    if stdin is None or not stdin.isatty():
        raise OSError("there is no terminal to hand over")
    tty = stdin.fileno()
    ours = os.getpgrp()
    # Giving the terminal back to our own (then background) group would stop us with
    # SIGTTOU; shells ignore it for the same reason.
    previous = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=str(cwd) if cwd else None, env=dict(env) if env is not None else None, process_group=0
        )
        try:
            os.tcsetpgrp(tty, proc.pid)
        except OSError:
            pass  # it exited already
        return await proc.wait()
    finally:
        try:
            os.tcsetpgrp(tty, ours)
        finally:
            signal.signal(signal.SIGTTOU, previous)
