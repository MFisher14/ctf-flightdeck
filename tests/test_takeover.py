"""The take-over's hand of the terminal (console/takeover.py, P69): whatever the shell does,
the console gets the terminal back.

The console here is a stand-in whose suspend() is Textual's own App.suspend, so what is
tested is what Textual does when the code inside it raises; the shell programs run are `sh`
and a name that does not exist, never a challenge's."""

from __future__ import annotations

import asyncio
import contextlib
import signal

import pytest
from textual.app import App

from ctf_flightdeck.console import takeover
from ctf_flightdeck.console.takeover import QUICK_EXIT, ShellExit, not_started, run_in_terminal


class Driver:
    can_suspend = True

    def __init__(self) -> None:
        self.suspended = 0
        self.resumed = 0

    def suspend_application_mode(self) -> None:
        self.suspended += 1

    def resume_application_mode(self) -> None:
        self.resumed += 1

    @contextlib.contextmanager
    def no_automatic_restart(self):
        yield


class Console:
    """Enough of an App for App.suspend (Textual's code, not a copy of it)."""

    suspend = App.suspend

    def __init__(self) -> None:
        self._driver = Driver()
        self.signals: list[str] = []

    @contextlib.contextmanager
    def batch_update(self):
        yield

    def _suspend_signal(self) -> None:
        self.signals.append("suspend")

    def _resume_signal(self) -> None:
        self.signals.append("resume")

    def refresh(self, **_) -> None:
        self.signals.append("drawn")

    @property
    def back(self) -> bool:
        """Suspended as often as resumed, and drawn again after the last resume."""
        return self._driver.suspended == self._driver.resumed >= 1 and self.signals[-2:] == ["resume", "drawn"]


@pytest.fixture
def a_terminal(monkeypatch):
    """A terminal as far as run_in_terminal can tell (pytest's stdin is none): the foreground
    group it is handed is recorded, not set."""
    handed: list[int] = []
    monkeypatch.setattr(takeover, "terminal", lambda: 99)
    monkeypatch.setattr(takeover, "hand_terminal", lambda tty, group: handed.append(group))
    return handed


def test_a_shell_program_that_is_not_there_raises_after_the_console_is_back(a_terminal):
    """The bug: Textual resumes only when the code inside suspend() returns, so a missing
    `docker` left the console suspended, reading no key and drawing nothing."""
    console = Console()
    with pytest.raises(FileNotFoundError) as caught:
        asyncio.run(run_in_terminal(console, ["flightdeck-no-such-program-p69"], None, None))
    assert console.back
    assert caught.value.filename == "flightdeck-no-such-program-p69"


def test_no_terminal_to_hand_over_still_gives_the_console_back(monkeypatch):
    console = Console()
    monkeypatch.setattr(takeover.sys, "__stdin__", None)
    with pytest.raises(OSError, match="there is no terminal to hand over"):
        asyncio.run(run_in_terminal(console, ["sh", "-c", "exit 0"], None, None))
    assert console.back


def test_a_take_over_cancelled_in_the_shell_gives_the_console_back(monkeypatch, a_terminal):
    console = Console()
    inside = asyncio.Event()

    async def a_long_shell(tty, argv, cwd, env):
        inside.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(takeover, "_foreground", a_long_shell)

    async def main():
        task = asyncio.create_task(run_in_terminal(console, ["sh"], None, None))
        await inside.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(main())
    assert console.back


def test_a_shell_that_exits_with_an_error_says_its_status_and_the_terminal_comes_back_to_the_console(a_terminal):
    console = Console()
    ended = asyncio.run(run_in_terminal(console, ["sh", "-c", "exit 3"], None, None))
    assert ended.status == 3 and ended.seconds < QUICK_EXIT
    assert console.back
    assert len(a_terminal) == 2 and a_terminal[0] != a_terminal[1]  # the shell's group, then the console's again
    assert ended.problem() == "the shell exited at once with status 3"


@pytest.mark.parametrize("ended, problem", [
    (ShellExit(0, 0.1), ""),
    (ShellExit(0, 600.0), ""),
    (ShellExit(1, 600.0), ""),  # bash exits with the player's last command's status
    (ShellExit(1, 0.2), "the shell exited at once with status 1"),
    (ShellExit(127, 0.1), "the shell exited at once with status 127: its program was not found"),
    (ShellExit(126, 0.1), "the shell exited at once with status 126: its program could not be run"),
    (ShellExit(-signal.SIGKILL, 600.0), "the shell was ended by SIGKILL"),
], ids=["ok", "ok later", "error later", "error at once", "not found", "cannot run", "killed"])
def test_only_a_shell_that_never_opened_for_the_player_is_a_problem(ended, problem):
    assert ended.problem() == problem


def test_why_a_shell_did_not_start_names_the_program_or_folder_and_nothing_else():
    argv = ["docker", "exec", "-it", "-e", "HISTFILE=/work/.flightdeck/takeover_history", "fd-L01", "bash"]
    assert not_started(FileNotFoundError(2, "No such file or directory", "docker"), argv) == (
        "docker was not found (is it installed and on your PATH?)")
    assert not_started(FileNotFoundError(2, "No such file or directory", "/work/L01"), argv) == "/work/L01 does not exist"
    assert not_started(PermissionError(13, "Permission denied", "docker"), argv) == "docker cannot be run: permission denied"
    assert not_started(OSError(8, "Exec format error"), argv) == "docker: Exec format error"
    assert not_started(OSError("there is no terminal to hand over"), argv) == "there is no terminal to hand over"
