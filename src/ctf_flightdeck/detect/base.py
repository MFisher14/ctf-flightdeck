"""What every detector shares: the Signal it returns, the Detector protocol, the thresholds.

A detector looks at one lane (its log of actions, files, plan, counters) and its challenge,
and says whether its alert holds right now. It never changes the lane or the deck: the
Watch (watch.py) turns signals into alerts through Deck.report().

Everything a detector reads from a lane or a challenge is untrusted text. It is only ever
matched against flightdeck's own rules and word lists, never followed, and any piece of it
quoted in a reason or a suggestion is folded to one short line (`quote`), so it cannot
forge a line in the console or the log.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, fields
from typing import Protocol, runtime_checkable

from ..core.model import Action, ActionKind, Actor, Alert, AlertKind, Challenge, Lane, Suggestion
from ..text import untrusted


@dataclass(frozen=True)
class Signal:
    """A detector's finding: its alert holds, for this reason, with these answers."""

    kind: AlertKind  # EFFORT, HINT, DIRECTION, LOOP or STALL
    reason: str  # words the player can check, citing the numbers and commands it used
    suggestions: tuple[Suggestion, ...] = ()  # keys h r f k e, as in the CONSOLE-SPEC table

    def alert(self) -> Alert:
        return Alert(self.kind, self.reason, self.suggestions)


@runtime_checkable
class Detector(Protocol):
    kind: AlertKind

    def check(self, lane: Lane, challenge: Challenge, now: float) -> Signal | None:
        """The signal if the alert holds for `lane` now, else None."""
        ...


@dataclass(frozen=True)
class DetectConfig:
    """Every threshold the detectors and the Watch use. Counts are turns or steps."""

    # Effort vs value: budget = base * points/100, halved at 50+ solves, quartered at 200+.
    effort_base_tokens: int = 60_000
    effort_base_turns: int = 15
    effort_min_turns: int = 8  # the turns budget never falls below this (the tokens budget has no floor)
    effort_points_unit: int = 100
    effort_half_solves: int = 50
    effort_quarter_solves: int = 200
    # Ignores the hint.
    hint_grace_turns: int = 4
    hint_window: int = 8  # steps
    # Wrong direction (web).
    direction_window: int = 6  # steps
    direction_min_fuzz: int = 3  # fuzzing commands in the window
    # Loop.
    loop_window: int = 6  # steps
    loop_same_command: int = 3
    loop_same_output: int = 4
    loop_output_chars: int = 200
    loop_digit_run: int = 4  # runs of this many digits or more are masked when comparing commands
    # Stall.
    stall_turns: int = 10
    # The Watch.
    quiet_turns: int = 3  # an answered alert is not raised again for this many turns
    judge_every_turns: int = 5  # the optional hint judge is asked at most once per lane per this many turns

    def __post_init__(self) -> None:
        for f in fields(self):
            value = getattr(self, f.name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"DetectConfig.{f.name} must be a whole number, got {value!r}")
            least = 0 if f.name in ("hint_grace_turns", "quiet_turns") else 1
            if value < least:
                raise ValueError(f"DetectConfig.{f.name} must be at least {least}, got {value}")
        if self.effort_quarter_solves < self.effort_half_solves:
            raise ValueError(
                f"DetectConfig.effort_quarter_solves ({self.effort_quarter_solves}) must not be below "
                f"effort_half_solves ({self.effort_half_solves})"
            )

    def effort_factor(self, points: int, solves: int) -> float:
        """How much effort the challenge is worth, relative to a 100-point one with few solves."""
        divisor = 4 if solves >= self.effort_quarter_solves else 2 if solves >= self.effort_half_solves else 1
        return max(0, points) / self.effort_points_unit / divisor

    def effort_tokens(self, points: int, solves: int) -> int:
        return math.ceil(self.effort_base_tokens * self.effort_factor(points, solves))

    def effort_turns(self, points: int, solves: int) -> int:
        return max(self.effort_min_turns, math.ceil(self.effort_base_turns * self.effort_factor(points, solves)))


QUOTE_CHARS = 120


def quote(text: str, limit: int = QUOTE_CHARS) -> str:
    """Untrusted text as one short line, safe to put inside a reason or a suggestion."""
    line = " ".join(untrusted(text, one_line=True).split())
    return line if len(line) <= limit else line[: limit - 1] + "…"


def steps(lane: Lane, last: int | None = None) -> list[Action]:
    """The lane's own steps (STEP actions), oldest first; only the last `last` if given."""
    found = [a for a in lane.actions if a.kind is ActionKind.STEP and a.by is Actor.LANE]
    return found[-last:] if last is not None else found


def suggestions(*items: tuple[str, str] | tuple[str, str, str]) -> tuple[Suggestion, ...]:
    return tuple(Suggestion(*item) for item in items)


def kinds(detectors: Sequence[Detector]) -> list[AlertKind]:
    """The alert kinds a set of detectors covers, in their order, each once."""
    out: list[AlertKind] = []
    for detector in detectors:
        if detector.kind not in out:
            out.append(detector.kind)
    return out
