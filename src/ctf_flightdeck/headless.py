"""A run without the console: `play --headless` and `practice --headless`.

Headless.fly is what cli._fly awaits in the console's place: it releases the board, then
waits until the run is told to stop or has nothing left to do, and returns, so _fly shuts
the run down and prints the exit lines as after the console.

The deck's rules are the same. Nobody is watching, so nothing is approved or declined: a
flag under submit "confirm", a budget, a live box wait as they would at the console, the
status file (status.py) and the notification webhook (notify.py) say so, and the exit lines
name each flag left waiting. Nothing here answers the deck.

It stops on SIGTERM, SIGHUP or SIGINT (Ctrl-C), as quitting the console does: every lane
stops, every workspace closes, the run log gets its run-end line, and flightdeck exits with
128 + the signal's number (cli.play). A signal ignored when flightdeck started stays ignored
(nohup's SIGHUP). The handlers stay until the run's loop closes, so a second signal while the
lanes are stopping does not cut the shutdown short.

It also ends on its own, with exit status 0, once nothing is left to do (nothing_left): no
lane is open (a lane that waits for an approval is open, so a waiting flag keeps the run up
until it is stopped), the queue is empty and not held, no flag is on its way to the
platform, and nothing can bring more work: no CTFd waves (the pull policy "auto" pulls the
board again), no team folder (a teammate's released claim queues a challenge again), and
nothing the caller names (`more_to_come`: an autopilot that may queue a challenge again).
That must hold at two polls in a row. Where more can come, the run goes on until a signal.
"""

from __future__ import annotations

import asyncio
import os
import signal
from collections.abc import Callable
from typing import TYPE_CHECKING

from .status import NAME as STATUS_NAME
from .text import untrusted

if TYPE_CHECKING:
    from .run import Run

STOP_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
POLL_SECONDS = 1.0  # how often the run is asked whether anything is left to do


class Headless:
    """One headless flight of `run`. `say` prints a line for whoever started it. After
    fly(): `stopped_by` is the signal that stopped the run, or None when it ended on its
    own; `return_code` is 0 (the console's has Textual's), so cli.play reads both alike."""

    return_code = 0

    def __init__(
        self, run: Run, *, say: Callable[[str], None], poll_seconds: float = POLL_SECONDS,
        more_to_come: Callable[[], bool] | None = None,
    ) -> None:
        self.run = run
        self.say = say
        self.poll_seconds = poll_seconds
        self.more_to_come = more_to_come
        self.stopped_by: signal.Signals | None = None
        self._stop: asyncio.Event | None = None

    async def fly(self) -> None:
        """Release the board and wait for a signal, or for nothing to be left to do."""
        loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        for sig in STOP_SIGNALS:
            if signal.getsignal(sig) is signal.SIG_IGN:
                continue
            loop.add_signal_handler(sig, self._on_signal, sig)  # removed when the loop closes
        self.run.release()
        self.say(self.start_line())
        quiet = 0  # polls in a row at which nothing was left to do
        while not self._stop.is_set():
            try:
                async with asyncio.timeout(self.poll_seconds):
                    await self._stop.wait()
            except TimeoutError:
                pass
            if self._stop.is_set():
                break
            quiet = quiet + 1 if self.nothing_left() else 0
            if quiet >= 2:
                self.say("nothing is left to do (no lane is open, nothing is queued): closing the run")
                return
        assert self.stopped_by is not None
        self.say(f"{self.stopped_by.name}: stopping the lanes and closing their workspaces...")

    def stop(self, sig: int = signal.SIGTERM) -> None:
        """Stop the run as that signal would (on the run's loop)."""
        self._on_signal(sig)

    def _on_signal(self, sig: int) -> None:
        if self.stopped_by is None:
            self.stopped_by = signal.Signals(sig)
        if self._stop is not None:
            self._stop.set()

    def more_can_come(self) -> str:
        """What can still bring the run work once its lanes have ended; "" when nothing can."""
        run = self.run
        if run.ctfd is not None and run.ctfd.waves:
            return "the board is pulled again for new challenges"
        if run.team is not None:
            return "a teammate's released claim can queue a challenge again"
        if self.more_to_come is not None and self.more_to_come():
            return "autopilot may queue a challenge again"
        return ""

    def nothing_left(self) -> bool:
        """Nothing is running, queued, waiting for the player or on its way to the platform,
        and nothing can bring more (see the module docstring)."""
        deck = self.run.deck
        if deck.active_lanes() or deck.queue or deck.held:
            return False
        if any(deck.submitting(cid) for cid in deck.challenges):
            return False
        return not self.more_can_come()

    def start_line(self) -> str:
        status = untrusted(str(self.run.dir / STATUS_NAME), one_line=True)
        more = self.more_can_come()
        ends = (
            f"It runs until you stop it ({more})" if more
            else "It ends on its own once no lane is open and nothing is queued, or when you stop it"
        )
        return (
            f"headless: no console. The run's status is in {status}, rewritten as the run goes. Approvals wait: "
            "nothing is approved or declined in a headless run, and a flag left waiting is named when the run ends. "
            f"{ends}: SIGTERM (kill {os.getpid()}), SIGHUP or Ctrl-C stops every lane as quitting the console does."
        )
