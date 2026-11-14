"""Game Master release-pipeline timing (B-252), kept out of the shared code path.

The wire budget (ctf/platform/wire.py) and the generic latency path (ctf/platform/latency.py) hold no
event numbers. The Huntress-specific figures from the first-blood benchmark live here, so the shared
path stays event-blind and a different event overrides one table instead of editing the hot path.

What the Huntress first-blood benchmark (docs/research/firstblood-benchmark.md in the event tree)
measured:

  * Bases closed 1.5-9 s behind first blood on every Huntress day, against 1-4 s firsts; 15 of 17
    first-blood FAILs were the pipeline floor, not the solver.
  * The timed modes (Time Trial, Mastery) gate behind a *cumulative base bank*: 1300-1516 answer ids
    had to be banked before the timed ladder opened. At the measured per-submit round trip that bank
    is a flat-seconds floor no solver speed can cut; shrinking the per-submit critical path is the
    only lever (B-044's batch submit is one; this table sizes the bank the floor is computed against).

`BankProfile` is one event's bank sizes. `HUNTRESS` is the benchmark's. `bank_count(...)` picks the
count to size a mode's bank floor against (the low end of the observed range by default: the floor is
a lower bound, so the smallest credible bank gives the smallest credible floor). Nothing here contacts
the platform or reads a clock; it is a table and the arithmetic over it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

# The cumulative base-bank range the benchmark saw before the timed ladder opened (answer ids).
HUNTRESS_BANK_LOW = 1300
HUNTRESS_BANK_HIGH = 1516

TIMED_SUFFIXES = ("time_trial", "mastery")


@dataclass(frozen=True)
class BankProfile:
    """One event's cumulative base-bank sizes. `default` is used for a mode with no per-lane entry;
    `by_lane` overrides it for a lane (the lane of a `<lane>/<mode>` key, e.g. "web" from
    "web/time_trial"). `high` records the top of the observed range for reporting."""
    default_low: int
    high: int
    by_lane: Mapping[str, int] = field(default_factory=dict)

    def low_for(self, lane: str | None) -> int:
        if lane and lane in self.by_lane:
            return int(self.by_lane[lane])
        return int(self.default_low)


HUNTRESS = BankProfile(default_low=HUNTRESS_BANK_LOW, high=HUNTRESS_BANK_HIGH)

# One entry per event slug that has a measured bank floor. A slug with no entry has no bank floor,
# and the caller is told so rather than given a guessed number (no silent fallback).
PROFILES: dict[str, BankProfile] = {"huntress": HUNTRESS}


def profile_for(slug: str | None) -> BankProfile | None:
    """The bank profile for an event slug, or None (the caller must not invent one)."""
    return PROFILES.get((slug or "").lower()) or None


def is_timed_mode(mode: str) -> bool:
    """Whether a floor-table mode key ("<lane>/<suffix>") is a timed mode."""
    return str(mode).rpartition("/")[2] in TIMED_SUFFIXES


def lane_of(mode: str) -> str | None:
    """The lane of a "<lane>/<mode>" key, or None."""
    lane = str(mode).partition("/")[0]
    return lane or None


def bank_counts(slug: str | None, modes: object) -> dict[str, int]:
    """{timed mode: cumulative bank size} for the timed modes among `modes`, from the event's bank
    profile. Empty when the event has no profile (so floor_table adds no bank floor and says why)."""
    prof = profile_for(slug)
    if prof is None:
        return {}
    out: dict[str, int] = {}
    for mode in modes or ():
        m = str(mode)
        if is_timed_mode(m):
            out[m] = prof.low_for(lane_of(m))
    return out
