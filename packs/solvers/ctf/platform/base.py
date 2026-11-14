"""Platform adapter interface (B-005 implements CTFd, Game Master and manual adapters).

An adapter is a module ctf/platform/<kind>.py (kind = the profile's platform.kind) exposing

    def make_adapter(profile: EventProfile) -> PlatformAdapter

Nothing outside ctf/platform/ calls make_adapter or a raw adapter's submit(): callers use
ctf.platform.get_adapter(profile), which returns the adapter wrapped in the submit policy gate
(ctf/platform/policy.py). That wrapper is the one road to a platform submission.

Challenge ids are strings at this layer (CTFd ints are str()-ed by the adapter). A platform whose
challenges take several answers (Game Master) addresses one answer as "<challenge id>#<answer id>".
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


class PlatformError(RuntimeError):
    """A platform call failed (network, auth, unexpected response). The message names the call."""


class NotSupported(PlatformError):
    """The adapter (or the event's rules) does not offer this operation, e.g. any call in manual mode."""


class NotAllowed(NotSupported):
    """The event's rules forbid this operation (manual mode: submit, instances, scoreboard)."""


INSTANCE_METHODS = ("start_instance", "stop_instance", "instance_status")


class InstancesUnavailable(NotSupported, AttributeError):
    """Raised for an InstanceCapability method on an adapter that does not offer it. It is an
    AttributeError too, so hasattr()/supports_instances() stay False, while a direct call names why."""


class InstancesNotAllowed(NotAllowed, AttributeError):
    """As InstancesUnavailable, for an event whose rules forbid instance calls (manual mode)."""


class SubmitStatus(str, enum.Enum):
    CORRECT = "correct"
    INCORRECT = "incorrect"
    ALREADY_SOLVED = "already_solved"
    RATE_LIMITED = "rate_limited"     # not judged; retry after retry_after
    PAUSED = "paused"                 # not judged; the event is paused
    NOT_ALLOWED = "not_allowed"       # not sent or refused: policy, manual mode, auth, closed challenge

    @property
    def judged(self) -> bool:
        return self in (SubmitStatus.CORRECT, SubmitStatus.INCORRECT, SubmitStatus.ALREADY_SOLVED)


@dataclass(frozen=True)
class SubmitResult:
    status: SubmitStatus
    message: str = ""
    retry_after: float | None = None  # seconds; set with RATE_LIMITED when the platform says
    sent: bool = True                 # False when the policy gate refused before any request
    # The platform's reply body (a dict, the flag removed) when the adapter keeps it (Game Master:
    # the Hall of Fame pool fields, B-044). In memory only: no record stores it whole.
    reply: dict | None = field(default=None, compare=False, repr=False)

    @property
    def accepted(self) -> bool:
        return self.status in (SubmitStatus.CORRECT, SubmitStatus.ALREADY_SOLVED)


@dataclass(frozen=True)
class FileRef:
    name: str
    url: str | None = None


@dataclass(frozen=True)
class Challenge:
    id: str
    name: str
    category: str
    points: int | None = None
    description: str = ""
    files: tuple[FileRef, ...] = ()
    connection_info: str = ""
    solved_by_team: bool = False
    tags: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@dataclass(frozen=True)
class TeamSolve:
    challenge_id: str
    solver: str | None = None
    at: float | None = None           # epoch seconds


@dataclass(frozen=True)
class ScoreRow:
    rank: int
    team: str
    score: int


@dataclass(frozen=True)
class ChallengeSolve:
    """One solve of one challenge on the public board, by any team (B-099). The earliest is the
    challenge's first blood. `account` is the team (a users-mode event: the user) as the board names it."""
    challenge_id: str
    account: str
    at: float | None = None           # epoch seconds
    account_id: str | None = None


@dataclass(frozen=True)
class InstanceInfo:
    challenge_id: str
    state: str                        # running | stopped | starting | unknown
    connection_info: str = ""
    expires_at: float | None = None


@runtime_checkable
class PlatformAdapter(Protocol):
    kind: str

    def list_challenges(self) -> list[Challenge]: ...
    def get_challenge(self, challenge_id: str) -> Challenge: ...
    def download_files(self, challenge_id: str, dest: Path) -> list[Path]: ...
    def submit(self, challenge_id: str, flag: str) -> SubmitResult: ...
    def team_solves(self) -> list[TeamSolve]: ...
    def scoreboard(self) -> list[ScoreRow]: ...


@runtime_checkable
class InstanceCapability(Protocol):
    """Optional: adapters whose platform starts per-team challenge instances also implement this.
    Check with supports_instances(adapter); never call these on an adapter that does not."""

    def start_instance(self, challenge_id: str) -> InstanceInfo: ...
    def stop_instance(self, challenge_id: str) -> InstanceInfo: ...
    def instance_status(self, challenge_id: str) -> InstanceInfo: ...


@runtime_checkable
class SolvesCapability(Protocol):
    """Optional (B-099): adapters whose platform publishes every team's solves of a challenge. CTFd
    implements it; the Game Master's challenge_solves raises NotSupported and the manual adapter's
    NotAllowed, each naming why. Call it through challenge_solves(adapter, id)."""

    def challenge_solves(self, challenge_id: str) -> list[ChallengeSolve]: ...


def challenge_solves(adapter: object, challenge_id: str) -> list[ChallengeSolve]:
    """Every team's solves of `challenge_id`, earliest first. An adapter (or the adapter a SubmitGate
    wraps) without the call raises NotSupported naming its kind: never an empty list."""
    fn = getattr(adapter, "challenge_solves", None)
    if not callable(fn):
        raise NotSupported(f"challenge_solves: the {getattr(adapter, 'kind', type(adapter).__name__)} "
                           "adapter offers no per-challenge solves")
    return fn(challenge_id)


def supports_instances(adapter: object) -> bool:
    """Whether `adapter` offers InstanceCapability. A SubmitGate (what get_adapter returns) forwards
    instance calls through __getattr__, which a runtime_checkable isinstance never consults, so the gate
    is judged by the adapter it wraps (B-003)."""
    from .policy import SubmitGate   # local: policy imports this module
    if isinstance(adapter, SubmitGate):
        adapter = adapter._adapter
    return isinstance(adapter, InstanceCapability)
