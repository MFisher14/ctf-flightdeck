"""Take over: hand the terminal to a lane's shell, then take it back (M1).

The console's event loop keeps running while the player is in the shell, so the other
lanes keep working; nothing is drawn meanwhile (the console is suspended and its output
held). The shell gets its own process group and becomes the terminal's foreground group,
the way a shell runs a job: ctrl+c in the shell reaches the shell's programs, not the
console.

The console always comes back (P69). Textual's App.suspend() resumes the console only when
the code inside it returns: an exception there (no `docker` to run, a program that cannot be
executed, a cancel) would leave the console suspended, reading no key and drawing nothing.
So nothing is raised inside it: what went wrong is kept and raised once the console is back.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from textual.app import App

QUICK_EXIT = 2.0  # seconds: a shell that ends with an error status sooner never opened for the player


@dataclass(frozen=True)
class ShellExit:
    """How the take-over shell ended: its exit status (a negative one is the signal that
    ended it, as asyncio has it) and how long it ran."""

    status: int
    seconds: float

    def problem(self) -> str:
        """Why the shell did not open for the player, or "" when it did. A shell the player
        used may end with an error status (bash exits with its last command's), so only one
        that ended at once, or that a signal ended, is a problem."""
        if self.status < 0:
            try:
                name = signal.Signals(-self.status).name
            except ValueError:
                name = f"signal {-self.status}"
            return f"the shell was ended by {name}"
        if self.status == 0 or self.seconds >= QUICK_EXIT:
            return ""
        meaning = {126: ": its program could not be run", 127: ": its program was not found"}.get(self.status, "")
        return f"the shell exited at once with status {self.status}{meaning}"


def takeover_banner(lane_id: str, cwd: Path | None) -> str:
    """The line the take-over's shell opens under: whose shell, where (the lane's container
    when there is no folder on this machine), and how to hand it back."""
    where = f"in {cwd}" if cwd is not None else "in its container"
    return f"flightdeck: {lane_id}'s shell, {where}. The lane is paused; exit (or ctrl+d) hands it back."


def not_started(exc: OSError, argv: Sequence[str]) -> str:
    """Why the shell's program did not start, in words: the program or folder it names, never
    its environment."""
    name = exc.filename if exc.filename is not None else (argv[0] if argv else "")
    if isinstance(exc, FileNotFoundError):
        if argv and name == argv[0]:
            return f"{name} was not found (is it installed and on your PATH?)"
        return f"{name} does not exist"
    if isinstance(exc, PermissionError):
        return f"{name} cannot be run: permission denied"
    return f"{name}: {exc.strerror}" if exc.strerror and name else str(exc)


def terminal() -> int:
    """The terminal's descriptor; OSError when there is none to hand over."""
    stdin = sys.__stdin__
    if stdin is None or not stdin.isatty():
        raise OSError("there is no terminal to hand over")
    return stdin.fileno()


def hand_terminal(tty: int, group: int) -> None:
    """Make `group` the terminal's foreground process group."""
    os.tcsetpgrp(tty, group)


async def run_in_terminal(
    app: App, argv: Sequence[str], cwd: Path | None, env: Mapping[str, str] | None, *, banner: str = ""
) -> ShellExit:
    """Run `argv` with the terminal until it exits; say how it ended. `banner`, when given, is
    written to the terminal first, on a line of its own: where the player is and how to get
    back (a take-over's shell starts at a bare prompt).

    Raises textual.app.SuspendNotSupported where the console cannot let go of the terminal
    (a headless or web console), OSError when there is no terminal or the program cannot be
    started; whatever is raised, the console has the terminal back first."""
    failure: BaseException | None = None
    ended: ShellExit | None = None
    with app.batch_update():  # nothing is drawn while the player has the terminal
        with app.suspend():
            try:
                tty = terminal()
                if banner:
                    os.write(tty, f"\r\n{banner}\r\n".encode("utf-8", "replace"))
                ended = await _foreground(tty, argv, cwd, env)
            except BaseException as exc:  # raised once the console is back (see the module's doc)
                failure = exc
    if failure is not None:
        raise failure
    assert ended is not None
    return ended


async def _foreground(tty: int, argv: Sequence[str], cwd: Path | None, env: Mapping[str, str] | None) -> ShellExit:
    ours = os.getpgrp()
    # Giving the terminal back to our own (then background) group would stop us with
    # SIGTTOU; shells ignore it for the same reason.
    previous = signal.signal(signal.SIGTTOU, signal.SIG_IGN)
    try:
        started = time.monotonic()
        proc = await asyncio.create_subprocess_exec(
            *argv, cwd=str(cwd) if cwd else None, env=dict(env) if env is not None else None, process_group=0
        )
        try:
            hand_terminal(tty, proc.pid)
        except OSError:
            pass  # it exited already
        status = await proc.wait()
        return ShellExit(status, time.monotonic() - started)
    finally:
        try:
            hand_terminal(tty, ours)
        finally:
            signal.signal(signal.SIGTTOU, previous)
