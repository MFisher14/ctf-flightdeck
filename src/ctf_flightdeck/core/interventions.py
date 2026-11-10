"""Interventions: what the player can do to a lane or a challenge.

The console turns a key press into one of these and passes it to Deck.apply(), which
returns an Outcome. Every intervention is recorded in the deck's event log.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Pause:
    lane: str


@dataclass(frozen=True)
class Resume:
    lane: str


@dataclass(frozen=True)
class Hint:
    """Inject free text into the lane's next turn."""

    lane: str
    text: str


@dataclass(frozen=True)
class Redirect:
    """Replace the lane's plan with a new direction."""

    lane: str
    text: str


@dataclass(frozen=True)
class Fork:
    """Start a sibling lane on the same challenge with another approach or model."""

    lane: str
    approach: str = ""
    model: str | None = None  # None: the next model that differs from the parent's


@dataclass(frozen=True)
class Kill:
    """End the lane. The challenge goes back to the front of the queue, or is parked."""

    lane: str
    requeue: bool = True


@dataclass(frozen=True)
class Escalate:
    """Hand a compact summary of the lane to the next stronger model."""

    lane: str


@dataclass(frozen=True)
class TakeOver:
    """The player takes the lane's shell; the lane waits."""

    lane: str


@dataclass(frozen=True)
class HandBack:
    lane: str
    note: str = ""


@dataclass(frozen=True)
class Approve:
    """Approve what the lane is waiting for: a submit, more budget, live-box access."""

    lane: str


@dataclass(frozen=True)
class Claim:
    """Team mode: tell teammates we are on this challenge."""

    challenge: str


@dataclass(frozen=True)
class Release:
    challenge: str


Intervention = (
    Pause
    | Resume
    | Hint
    | Redirect
    | Fork
    | Kill
    | Escalate
    | TakeOver
    | HandBack
    | Approve
    | Claim
    | Release
)


@dataclass(frozen=True)
class Outcome:
    ok: bool
    message: str
