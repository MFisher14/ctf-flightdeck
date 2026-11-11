"""A deadline for one block of a test.

`within(seconds, what)` fails the test once the block has run for `seconds`. A timer signal
(SIGALRM) interrupts the block wherever it is, a regular expression stuck backtracking
included (CPython's re checks for signals while it matches), so code that turned quadratic
fails here in seconds instead of holding the suite for minutes or hours. Tests run in the
main thread, where Python handles signals; CI runs on Linux and macOS, which have SIGALRM.
"""

from __future__ import annotations

import contextlib
import signal
from collections.abc import Iterator

import pytest


@contextlib.contextmanager
def within(seconds: float, what: str) -> Iterator[None]:
    def late(signum, frame):
        pytest.fail(f"{what} took more than {seconds:g} s", pytrace=False)

    previous = signal.signal(signal.SIGALRM, late)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
