"""The console's terminal when it goes away: a hang-up (the window closed, an SSH connection
dropped) or a SIGTERM must stop the run's lanes the way quitting does (app.py catches the
signals), and nothing about the terminal may stop that from happening.

Once the terminal has hung up, every write to it fails (EIO) and every read returns end of
file at once. Textual writes from one output thread fed by a queue of 30 writes; the first
failed write kills that thread, and the 31st write after it would block the event loop for
good, with the lanes still running and nothing left to stop them. TerminalDriver drops writes
instead once its output thread is gone. On a hang-up, let_go() also stops Textual's input
thread (it would spin on the end of file) and points stdout and stderr at /dev/null, so what
flightdeck prints on its way out cannot fail either.

The driver is also where the console's `mouse` setting acts ([console] mouse in the config):
with it off, the terminal is never asked to report the mouse, so clicks, drags and the wheel
stay the terminal's own (its text selection, for one).

Beacon is what the console says outside its own window, for a player who is looking at
another one ([console] title and bell in the config): how many lanes need the player, in the
terminal's title, and the terminal's bell once each time that count goes up. The title is
made of a count and fixed words (title_text), so no text of a challenge or a lane can be in
it. The console saves the title it found on the terminal's own title stack before it writes
one, and puts it back when it leaves (xterm's window operations 22 and 23:
https://invisible-island.net/xterm/ctlseqs/ctlseqs.html). Textual's App.bell() writes nothing
on a headless driver, so the bell and the title are written here, through whatever write the
console hands over: a test reads what was written.
"""

from __future__ import annotations

import os
import queue
import signal
from collections.abc import Callable

from textual.drivers.linux_driver import LinuxDriver

STOP_SIGNALS = (signal.SIGHUP, signal.SIGTERM)  # SIGINT already ends the run through asyncio
PUT_WAIT = 0.25  # seconds a write waits for room in the output queue before it checks the thread again

NAME = "flightdeck"  # the title when nothing needs the player, and the end of every other one
HELD = "queue held"  # the header's words for it (views.HELD)
BELL = "\a"
TITLE_SAVE = "\x1b[22;0t"  # the terminal puts its icon and window title on its stack
TITLE_BACK = "\x1b[23;0t"  # and takes them back from it


def title_text(need: int, held: bool) -> str:
    """The terminal's title: how many lanes need the player (the header's "▲ N need you"),
    that the queue is held, and the name. A count and fixed words, nothing else."""
    parts = [f"▲ {int(need)} need you"] if need > 0 else []
    if held:
        parts.append(HELD)
    return " · ".join([*parts, NAME])


def set_title(text: str) -> str:
    """The write that sets the terminal's icon and window title (OSC 0), which is the tab's
    title where the terminal has tabs."""
    return f"\x1b]0;{text}{BELL}"


class Beacon:
    """The terminal's title and bell, written only while the console has the terminal
    (between open() and close()), and only when there is something new to say."""

    def __init__(self, write: Callable[[str], None], *, title: bool = True, bell: bool = True) -> None:
        self._write = write
        self.title = title  # false: the title is never read, written or put back
        self.bell = bell  # false: the bell never rings
        self._open = False
        self._shown: str | None = None  # the title the terminal has from here (None: none yet)
        self._need: int | None = None  # the count last seen (None: none yet, so the next one rings no bell)

    def open(self) -> None:
        """The console has the terminal (it started, or came back from a shell): the title
        that is there is saved, and the next show() writes the console's own."""
        if self._open:
            return
        self._open = True
        self._shown = self._need = None
        if self.title:
            self._write(TITLE_SAVE)

    def show(self, need: int, held: bool) -> None:
        """`need` lanes need the player, and the queue is held or not. The title is written
        when its text is not the one already there; the bell rings once when `need` is more
        than it was at the last call, never for the first count after open() (the player is
        at the console then), a count that stays, or one that falls."""
        if not self._open:
            return
        if self.title:
            text = title_text(need, held)
            if text != self._shown:
                self._write(set_title(text))
                self._shown = text
        rose = self._need is not None and need > self._need
        self._need = need
        if rose and self.bell:
            self._write(BELL)

    def close(self) -> None:
        """The console lets the terminal go (it ends, or hands the terminal to a shell): the
        title goes back to what open() saved. A terminal with no title stack ignores that,
        so the title is emptied first, which is the terminal's own default title: a count of
        lanes never stays behind."""
        if not self._open:
            return
        self._open = False
        if self.title:
            self._write(set_title("") + TITLE_BACK)


class TerminalDriver(LinuxDriver):
    """Textual's terminal driver, except that a write never waits on an output thread that
    has died: what it would have drawn is dropped (there is no terminal to draw it on)."""

    gone = False  # let_go() has run: the terminal hung up

    def __init__(self, app, *, debug: bool = False, mouse: bool = True, size: tuple[int, int] | None = None) -> None:
        super().__init__(app, debug=debug, mouse=mouse and getattr(app, "mouse", True), size=size)

    def write(self, data: str) -> None:
        self._put(data)

    def close(self) -> None:
        writer = self._writer_thread
        if writer is None:
            return
        self._put(None)  # the thread's signal to stop
        writer.join()  # at once when it has died

    def let_go(self) -> None:
        """The terminal hung up: stop reading it, and send what is printed from now on to
        /dev/null. The input thread is stopped first, while its reads still return end of
        file at once."""
        if self.gone:
            return
        self.gone = True
        self.disable_input()
        null = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(null, 1)
            os.dup2(null, 2)
        finally:
            os.close(null)

    def _put(self, data: str | None) -> None:
        writer = self._writer_thread
        assert writer is not None, "Driver must be in application mode"
        while writer.is_alive():
            try:
                writer._queue.put(data, timeout=PUT_WAIT)
                return
            except queue.Full:
                continue  # the terminal is slow; or the thread died with its queue full
