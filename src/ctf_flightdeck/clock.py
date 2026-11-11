"""The run's clock: seconds since the run started, for the deck in a real run (the mock
has its own manual clock)."""

from __future__ import annotations

import time
from collections.abc import Callable


class RunClock:
    def __init__(self, source: Callable[[], float] = time.monotonic) -> None:
        self._source = source
        self._start = source()

    def now(self) -> float:
        return self._source() - self._start
