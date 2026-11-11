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
"""

from __future__ import annotations

import os
import queue
import signal

from textual.drivers.linux_driver import LinuxDriver

STOP_SIGNALS = (signal.SIGHUP, signal.SIGTERM)  # SIGINT already ends the run through asyncio
PUT_WAIT = 0.25  # seconds a write waits for room in the output queue before it checks the thread again


class TerminalDriver(LinuxDriver):
    """Textual's terminal driver, except that a write never waits on an output thread that
    has died: what it would have drawn is dropped (there is no terminal to draw it on)."""

    gone = False  # let_go() has run: the terminal hung up

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
