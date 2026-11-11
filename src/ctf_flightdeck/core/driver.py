"""The seam between the deck and whatever does a lane's work.

M0 plugs in a scripted driver (ctf_flightdeck.mock). M1 replaces it with an agent loop
against a model API, behind the same protocol. A driver reports each turn back with
Deck.report(lane_id, TurnReport(...)); the deck applies the rules (caps, flag format,
approvals) and the console shows the result.

Contract for drivers:
- Start a model turn only while `lane.state is LaneState.RUNNING`. The deck can move a
  lane to WAITING (an approval) or PAUSED at any report or key press; `resume()` is
  called only when the lane is RUNNING again.
- Every method returns at once; slow work belongs in the driver's own tasks.
- Call deck methods only on the thread that created the deck (the console's event
  loop). From a worker thread, hop back first (Textual: app.call_from_thread).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Protocol

from .model import Alert, AlertKind, Challenge, EscalationSummary, FileChange, Lane, Pending

if TYPE_CHECKING:
    from .deck import Deck


class Clock(Protocol):
    def now(self) -> float:
        """Seconds since the event started."""
        ...


Verifier = Callable[[str, str], bool | None]
"""(challenge id, flag) -> correct? None when the board cannot check flags (a folder of
challenges with no answers): the player submits by hand and confirms the result."""


@dataclass(frozen=True)
class TurnReport:
    """What a lane did in one step. Every field is optional."""

    action: str = ""  # the command or step, one line
    output: str = ""  # short output; long output belongs in a file (M1)
    tokens: int = 0  # prompt + completion tokens of this turn's model call(s)
    cached_tokens: int = 0  # of the prompt tokens, how many the API served from its cache
    dollars: float | None = 0.0  # None when the price is unknown
    turn: bool = True  # counts as a model turn
    plan: str | None = None  # the lane's new plan, if it changed
    artifacts: tuple[str, ...] = ()
    files: tuple[FileChange, ...] = ()  # files changed in the lane's workspace
    alerts: tuple[Alert, ...] = ()  # M0: scripted; M3: from detectors
    clear: tuple[AlertKind, ...] = ()
    pending: Pending | None = None  # ask the player for something
    flag: str | None = None  # candidate flag
    claimed: bool = True  # the lane claims `flag` (submit_flag, an L1 "solved"); False: a match scraped from text it read, never auto-submitted
    gave_up: str | None = None  # the lane ends without a flag, with this reason
    hints_taken: int = 0  # how many queued hints this turn read (oldest first)
    why: str = ""  # for spend outside a turn: what it was ("a reply dropped at escalation")
    model: str | None = None  # the model that took this turn, when it is not the lane's model now (escalated meanwhile)


def spend_only(rep: TurnReport) -> bool:
    """A report of spend outside a turn and of nothing else: tokens, cached tokens or dollars
    (None: spent at an unknown price), with no action, output, plan, artifacts, files,
    alerts, clear, approval, flag, hints or giving up. Once a lane has ended, the deck still
    counts such a report (a CLI reports a turn's cost when the turn ends, often after its
    lane has) and drops everything else."""
    spent = rep.tokens or rep.cached_tokens or rep.dollars or rep.dollars is None
    return not rep.turn and bool(spent) and not (
        rep.action or rep.output or rep.plan is not None or rep.artifacts or rep.files or rep.alerts or rep.clear
        or rep.pending is not None or rep.flag is not None or rep.gave_up is not None or rep.hints_taken
    )


class TakeoverRefused(Exception):
    """Raised by a driver's optional takeover(lane) when the player cannot have the lane's
    shell now; the message says why ("L01's workspace is not ready yet")."""


class LaneDriver(Protocol):
    """Does lane work. The deck calls these; the driver answers through deck.report()."""

    def attach(self, deck: Deck) -> None: ...

    def start(self, lane: Lane, challenge: Challenge) -> None:
        """Begin work. Raising here parks the challenge with the error as the reason."""
        ...

    def pause(self, lane: Lane) -> None:
        """The lane is PAUSED, or TAKEOVER (the player has its shell): it must not start
        anything new until resume()."""
        ...

    def resume(self, lane: Lane) -> None: ...

    def hint(self, lane: Lane, text: str) -> None: ...

    def redirect(self, lane: Lane, text: str) -> None: ...

    def escalate(self, lane: Lane, model: str, summary: EscalationSummary) -> None: ...

    def approved(self, lane: Lane, pending: Pending) -> None: ...

    def rejected(self, lane: Lane, flag: str) -> None:
        """A submitted flag was wrong; the lane carries on."""
        ...

    def declined(self, lane: Lane, pending: Pending) -> None:
        """The player said no to `pending` (a flag not submitted, the live box refused);
        the lane carries on. Declined budget stops the lane instead (stop() is called)."""
        ...

    def stop(self, lane: Lane) -> None:
        """The lane has finished (solved, killed, stopped or gave up); release it."""
        ...
