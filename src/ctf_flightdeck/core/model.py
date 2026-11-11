"""Shared data: challenges, lanes, alerts, approvals, files and events.

The deck owns these objects and is the only thing that changes them. Drivers report
what a lane did; the console only reads. Nothing here knows whether a lane is
scripted (the M0 mock) or a real agent (M1).

Text that comes from a challenge, a lane, a tool or a model is untrusted. It is kept
as is here; whoever shows it or hands it to a model must treat it as data (see
ctf_flightdeck.text and EscalationSummary).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
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
    AlertKind.HINT: "offhint",
    AlertKind.DIRECTION: "wrongway",
    AlertKind.LOOP: "loop",
    AlertKind.STALL: "stall",
    AlertKind.TEAMMATE: "teammate",
    AlertKind.BUDGET: "budget",
    AlertKind.FLAG: "flag",
}

COURSE_ALERTS = frozenset(
    {AlertKind.EFFORT, AlertKind.HINT, AlertKind.DIRECTION, AlertKind.LOOP, AlertKind.STALL}
)
"""Alerts about the lane's course. A hint, redirect or escalation answers them."""

INFORMATIONAL_ALERTS = frozenset({AlertKind.TEAMMATE})
"""Alerts that need no answer: flightdeck already acted (stopped the lane, kept it off a box)."""


@dataclass(frozen=True)
class Suggestion:
    key: str  # the console key for the intervention, e.g. "r" ("" when nothing to press)
    label: str  # what pressing it does
    text: str = ""  # prefill for the hint, redirect or fork


@dataclass
class Alert:
    kind: AlertKind
    reason: str  # why it fired, in words the player can check
    suggestions: tuple[Suggestion, ...] = ()
    at: float = 0.0  # set by the deck when raised


class PendingKind(StrEnum):
    SUBMIT = "submit"
    CONFIRM = "confirm"  # the board cannot check flags: the player submits by hand and says how it went
    BUDGET = "budget"
    LIVE_BOX = "live box"


FLAG_PENDING = (PendingKind.SUBMIT, PendingKind.CONFIRM)


@dataclass
class Pending:
    """Something the lane needs the player to approve (key `a`) or decline (key `d`)."""

    kind: PendingKind
    detail: str
    flag: str | None = None
    at: float = 0.0  # set by the deck


class Actor(StrEnum):
    LANE = "lane"
    PLAYER = "player"
    DECK = "flightdeck"


class ActionKind(StrEnum):
    STEP = "step"  # the lane did something
    MESSAGE = "message"  # the player's message to the lane (a hint)
    PLAYER = "player"  # another intervention by the player
    NOTE = "note"  # a note from flightdeck (a submit result, a format check)
    ALERT = "alert"  # an alert fired: text is its label, output its reason
    APPROVAL = "approval"  # the lane asked for approval: text is what


@dataclass(frozen=True)
class Action:
    """One entry in a lane's log. The log is the lane's transcript, in order."""

    at: float
    turn: int
    text: str
    output: str = ""
    by: Actor = Actor.LANE
    kind: ActionKind = ActionKind.STEP
    alert: AlertKind | None = None


@dataclass(frozen=True)
class FileChange:
    """A file the lane changed in its workspace, with a unified diff."""

    path: str
    diff: str = ""
    status: str = "modified"  # added | modified | deleted
    turn: int = 0  # set by the deck
    at: float = 0.0  # set by the deck

    @property
    def added(self) -> int:
        return sum(1 for ln in self.diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))

    @property
    def removed(self) -> int:
        return sum(1 for ln in self.diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))


@dataclass(frozen=True)
class EscalationSummary:
    """What a stronger model is told about a lane.

    Everything except the counts is untrusted text from the challenge or the lane. A
    driver must hand it to a model as data (for example as JSON fields after its own
    instructions), never pasted into the instructions themselves.
    """

    lane: str
    challenge: str
    category: str
    points: int
    solves: int
    files: tuple[str, ...]
    plan: str
    model: str
    turns: int
    tokens: int
    tried: tuple[str, ...]
    found: tuple[str, ...]
    alerts: tuple[str, ...]


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
    cached_tokens: int = 0  # prompt tokens the API served from its cache
    dollars: float | None = 0.0  # None once any turn had no known price
    token_cap: int | None = None
    dollar_cap: float | None = None
    started_at: float = 0.0
    last_active_at: float = 0.0
    ended_at: float | None = None
    result: str = ""  # one line, once finished
    actions: list[Action] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    files: dict[str, FileChange] = field(default_factory=dict)  # newest change per path, newest last
    alerts: list[Alert] = field(default_factory=list)
    pending: Pending | None = None  # the approval the lane waits for now
    waiting: list[Pending] = field(default_factory=list)  # further approvals, oldest first
    hints: list[str] = field(default_factory=list)  # sent, not yet taken in by a turn

    @property
    def id(self) -> str:
        return f"L{self.number:02d}"

    @property
    def finished(self) -> bool:
        return self.state.finished

    @property
    def last_action(self) -> str:
        for action in reversed(self.actions):
            if action.kind not in (ActionKind.ALERT, ActionKind.APPROVAL):
                return action.text
        return ""

    @property
    def needs_you(self) -> bool:
        """Something only the player can answer: an approval or a non-informational alert."""
        if self.finished:
            return False
        return self.pending is not None or any(a.kind not in INFORMATIONAL_ALERTS for a in self.alerts)

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
    TURN = "turn"
    ALERT = "alert"
    PENDING = "pending"
    INTERVENTION = "intervention"  # the player asked for something (before its effects)
    OUTCOME = "outcome"  # what came of it
    SUBMIT = "submit"
    TEAMMATE = "teammate"
    BOARD = "board"
    WARNING = "warning"  # something did not happen as asked, with the reason


@dataclass(frozen=True)
class Event:
    at: float
    kind: EventKind
    text: str
    lane: str | None = None
    challenge: str | None = None
    alert: AlertKind | None = None
    data: Mapping[str, object] = field(default_factory=dict)  # structured payload for the log


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
