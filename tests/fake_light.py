"""A light engine for the flagcheck tests that calls no server: it never answers a flag check,
and a check cancelled under it winds down slowly. That is the window in which the run's end
used to let a lane start a check that outlived it (agent/flaggate.py, FlagGate.aclose).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from ctf_flightdeck import light as L


class Lingers:
    """Never answers a flag check. When a check is cancelled, it calls `on_cancel` (to let the
    lane's next turn come in, say), then waits until another check is asked or `done()` (the
    lane's task has ended), at most WAIT seconds, before it lets the cancellation through."""

    WAIT = 10.0
    engine, model, label = "openai", "slow/m", "openai slow/m"

    def __init__(self, on_cancel: Callable[[], object] = lambda: None, done: Callable[[], bool] = lambda: True) -> None:
        self.on_cancel = on_cancel
        self.done = done
        self.asked: list[str] = []  # the candidates it was asked about, in order

    def does(self, job: str) -> bool:
        return job == L.FLAGCHECK

    async def ask_choice(self, job, data, question, choices):
        self.asked.append(data["candidate"])
        try:
            await asyncio.sleep(3600)
        except asyncio.CancelledError:
            asked = len(self.asked)
            self.on_cancel()
            end = time.monotonic() + self.WAIT
            while len(self.asked) == asked and not self.done() and time.monotonic() < end:
                await asyncio.sleep(0.01)
            raise
        raise AssertionError("Lingers never answers a flag check")

    async def aclose(self) -> None:
        return None
