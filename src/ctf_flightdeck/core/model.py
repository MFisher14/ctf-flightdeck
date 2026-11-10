"""Shared data: challenges, lanes, alerts, approvals and events.

The deck owns these objects and is the only thing that changes them. Drivers report
what a lane did; the console only reads. Nothing here knows whether a lane is
scripted (the M0 mock) or a real agent (M1).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum

ME = "me"
"""Owner name for the player themself (claims, manual solves)."""


class ChallengeStatus(StrEnum):
    NEW = "new"
    QUEUED = "queued"
    RUNNING = "running"
    SOLVED = "solved"  # solved by us
    TEAMMATE = "teammate"  # solved by a teammate (team mode)
    BLOCKED = "blocked"  # cannot be worked as things stand
    PARKED = "parked"  # set aside after a kill or a lane giving up


CLOSED = frozenset({ChallengeStatus.SOLVED, ChallengeStatus.TEAMMATE})


@dataclass
class Challenge:
    id: str
    name: str
    category: str
    points: int
    solves: int = 0
    description: str = ""
    files: tuple[str, ...] = ()
    live: bool = False  # has a live instance
    status: ChallengeStatus = ChallengeStatus.NEW
    claimed_by: str | None = None  # team mode: ME or a teammate handle
    solved_by: str | None = None  # a lane id, ME or a teammate handle
    note: str = ""  # why it is blocked or parked

    @property
    def closed(self) -> bool:
        return self.status in CLOSED


class LaneState(StrEnum):
    RUNNING = "run"
    WAITING = "wait"  # waiting for the player to approve something
    PAUSED = "paused"
    TAKEOVER = "takeover"  # the player has the lane's shell
    SOLVED = "solved"
    KILLED = "killed"
    STOPPED = "stopped"  # stopped by a rule, e.g. a teammate solved the challenge
    GAVE_UP = "gave up"  # ended without a flag

    @property
    def finished(self) -> bool:
        return self in FINISHED


FINISHED = frozenset({LaneState.SOLVED, LaneState.KILLED, LaneState.STOPPED, LaneState.GAVE_UP})


class AlertKind(StrEnum):
    """The alerts from CONSOLE-SPEC.md, built from the author's real intervention cues."""

    EFFORT = "effort"
    HINT = "hint"
    DIRECTION = "direction"
    LOOP = "loop"
    STALL = "stall"
    TEAMMATE = "teammate"
    BUDGET = "budget"
    FLAG = "flag"

    @property
    def label(self) -> str:
        return _ALERT_LABELS[self]

    @property
    def tag(self) -> str:
        """Short name for the lane row."""
        return _ALERT_TAGS[self]


_ALERT_LABELS = {
    AlertKind.EFFORT: "Effort vs value",
    AlertKind.HINT: "Ignores the hint",
    AlertKind.DIRECTION: "Wrong direction",
    AlertKind.LOOP: "Loop",
    AlertKind.STALL: "Stall",
    AlertKind.TEAMMATE: "Teammate solved / box in use",
    AlertKind.BUDGET: "Budget",
    AlertKind.FLAG: "Flag found",
}
_ALERT_TAGS = {
    AlertKind.EFFORT: "effort",
    AlertKind.HINT: "hint",
    AlertKind.DIRECTION: "wrongway",
    AlertKind.LOOP: "loop",
    AlertKind.STALL: "stall",
    AlertKind.TEAMMATE: "team",
    AlertKind.BUDGET: "budget",
    AlertKind.FLAG: "flag",
}

COURSE_ALERTS = frozenset(
    {AlertKind.EFFORT, AlertKind.HINT, AlertKind.DIRECTION, AlertKind.LOOP, AlertKind.STALL}
)
"""Alerts about the lane's course. A hint, redirect or escalation answers them."""


@dataclass(frozen=True)
class Suggestion:
    key: str  # the console key for the intervention, e.g. "r"
    label: str  # what pressing it does
    text: str = ""  # prefill for the hint, redirect or fork prompt


@dataclass
class Alert:
    kind: AlertKind
    reason: str  # why it fired, in words the player can check
    suggestions: tuple[Suggestion, ...] = ()
    at: float = 0.0  # set by the deck when raised


class PendingKind(StrEnum):
    SUBMIT = "submit"
    BUDGET = "budget"
    LIVE_BOX = "live box"


@dataclass
class Pending:
    """Something the lane needs the player to approve (key `a`)."""

    kind: PendingKind
    detail: str
    flag: str | None = None
    at: float = 0.0  # set by the deck


class Actor(StrEnum):
    LANE = "lane"
    PLAYER = "player"
    DECK = "flightdeck"


@dataclass(frozen=True)
class Action:
    at: float
    turn: int
    text: str
    output: str = ""
    by: Actor = Actor.LANE


@dataclass
class Lane:
    number: int
    challenge_id: str
    model: str
    state: LaneState = LaneState.RUNNING
    plan: str = ""
    approach: str = ""
    parent: str | None = None  # lane id this one was forked from
    attempt: int = 1  # 2+ after a kill and re-queue
    turns: int = 0
    tokens: int = 0
    dollars: float | None = 0.0  # None once any turn had no known price
    token_cap: int | None = None
    dollar_cap: float | None = None
    started_at: float = 0.0
    last_active_at: float = 0.0
    ended_at: float | None = None
    result: str = ""  # one line, once finished
    actions: list[Action] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    pending: Pending | None = None
    hints: list[str] = field(default_factory=list)  # queued for the next turn

    @property
    def id(self) -> str:
        return f"L{self.number:02d}"

    @property
    def finished(self) -> bool:
        return self.state.finished

    @property
    def last_action(self) -> str:
        return self.actions[-1].text if self.actions else ""

    def idle(self, now: float) -> float:
        """Seconds since the lane last did something itself."""
        return max(0.0, now - self.last_active_at)

    def alert(self, kind: AlertKind) -> Alert | None:
        return next((a for a in self.alerts if a.kind is kind), None)

    def budget_used(self) -> float | None:
        """Largest fraction of a cap used so far, or None if the lane has no caps."""
        used = []
        if self.token_cap:
            used.append(self.tokens / self.token_cap)
        if self.dollar_cap and self.dollars is not None:
            used.append(self.dollars / self.dollar_cap)
        return max(used) if used else None


class EventKind(StrEnum):
    RELEASE = "release"
    LANE_START = "lane.start"
    LANE_END = "lane.end"
    ALERT = "alert"
    PENDING = "pending"
    INTERVENTION = "intervention"
    SUBMIT = "submit"
    TEAMMATE = "teammate"
    BOARD = "board"


@dataclass(frozen=True)
class Event:
    at: float
    kind: EventKind
    text: str
    lane: str | None = None
    challenge: str | None = None
    alert: AlertKind | None = None  # for alert events


SUBMIT_POLICIES = ("auto", "confirm")


@dataclass(frozen=True)
class DeckConfig:
    event: str
    team: bool = False
    containerized: bool = True  # D9: True runs lanes in Docker, False on the host
    max_lanes: int = 16
    flag_format: str = r"\w+\{[^{}\s]+\}"
    submit: str = "confirm"  # stage policy for submitting flags
    models: tuple[str, ...] = ()  # weakest to strongest; escalation moves right

    def __post_init__(self) -> None:
        if self.max_lanes < 1:
            raise ValueError(f"max_lanes must be at least 1, got {self.max_lanes}")
        if self.submit not in SUBMIT_POLICIES:
            raise ValueError(
                f"submit policy {self.submit!r} is not supported yet; known: {', '.join(SUBMIT_POLICIES)}"
            )
        re.compile(self.flag_format)
