"""The run clock counts seconds since the run started."""

from __future__ import annotations

from ctf_flightdeck.clock import RunClock


def test_the_run_clock_counts_from_its_start():
    t = [100.0]
    clock = RunClock(source=lambda: t[0])
    assert clock.now() == 0.0
    t[0] = 112.5
    assert clock.now() == 12.5
