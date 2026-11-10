"""The seam between the deck and whatever does a lane's work.

M0 plugs in a scripted driver (ctf_flightdeck.mock). M1 replaces it with an agent loop
against a model API, behind the same protocol. A driver reports each turn back with
Deck.report(lane_id, TurnReport(...)); the deck applies the rules (caps, flag format,
approvals) and the console shows the result.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Protocol

from .model import Alert, AlertKind, Challenge, Lane, Pending

if TYPE_CHECKING:
    from .deck import Deck


class Clock(Protocol):
    def now(self) -> float:
        """Seconds since the event started."""
        ...


Verifier = Callable[[str, str], bool]
"""(challenge id, flag) -> correct? The platform adapter in M2; scenario answers in M0."""


@dataclass(frozen=True)
class TurnReport:
    """What a lane did in one step. Every field is optional."""

    action: str = ""  # the command or step, one line
    output: str = ""  # short output; long output belongs in a file (M1)
    tokens: int = 0
    dollars: float | None = 0.0  # None when the price is unknown
    turn: bool = True  # counts as a model turn
    plan: str | None = None  # the lane's new plan, if it changed
    artifacts: tuple[str, ...] = ()
    alerts: tuple[Alert, ...] = ()  # M0: scripted; M3: from detectors
    clear: tuple[AlertKind, ...] = ()
    pending: Pending | None = None  # ask the player for something
    flag: str | None = None  # candidate flag
    gave_up: str | None = None  # the lane ends without a flag, with this reason


class LaneDriver(Protocol):
    """Does lane work. The deck calls these; the driver answers through deck.report()."""

    def attach(self, deck: Deck) -> None: ...

    def start(self, lane: Lane, challenge: Challenge) -> None: ...

    def pause(self, lane: Lane) -> None: ...

    def resume(self, lane: Lane) -> None: ...

    def hint(self, lane: Lane, text: str) -> None: ...

    def redirect(self, lane: Lane, text: str) -> None: ...

    def escalate(self, lane: Lane, model: str, summary: str) -> None: ...

    def approved(self, lane: Lane, pending: Pending) -> None: ...

    def rejected(self, lane: Lane, flag: str) -> None:
        """A submitted flag was wrong; the lane carries on."""
        ...

    def stop(self, lane: Lane) -> None:
        """The lane has finished (solved, killed, stopped or gave up); release it."""
        ...
