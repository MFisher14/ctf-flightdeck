"""The deck: board, queue and lanes, plus the rules and interventions that change them.

The console reads the deck and sends it interventions. A LaneDriver does each lane's
work and reports back through Deck.report(). The deck has no loop and no I/O of its
own: the M0 mock drives it from a scripted clock, M1 from real lanes. Every change is
logged as an Event with a structured payload, so the M1 run log can be written from
the event stream alone.

Rules the deck enforces:
- at most `max_lanes` lanes are active (running, waiting, paused or taken over); the
  rest wait in the queue, which drains as lanes finish, except while it is held
  (hold_queue: a failure every lane would hit) until the player lifts the hold
  (release_hold);
- before a queued lane starts, the start gate is asked (start_gate: the run's host governor,
  governor.py): while it names a limit no new lane starts, the queue stays as it is and the
  lanes at work carry on, none stopped or paused. It is no hold: nothing is asked of the
  player, autopilot stays engaged, and lanes start again when the gate clears (at the next
  lane's end, or when the run asks again: recheck_starts). One warning says when starts begin
  to be held and why, one when they are no longer. With no lane active the gate is not asked:
  one lane always starts;
- a candidate flag must match the flag format; with submit policy "confirm" it waits
  for the player's approval, with "auto" it is submitted at once;
- a board's verifier answers at once (an answers file, or never: the player submits by
  hand); a platform over the network (CTFd) gets the flag through the submitter instead
  (core/driver.py), which only queues it: the lane carries on (sending() names its flags on
  their way), and the answer comes back through platform_verdict(). One flag at a time goes
  to the platform per challenge; another waits its turn. A lane that gives up meanwhile
  ends once the answer is in. A flag that goes back to the player instead (no verdict, or
  tries counted) waits on each lane that sent it and is still at work;
- when that platform counts the tries at a challenge's flag (Challenge.limited: the board
  says so, or the platform did), a flag for it waits for the player under "auto" too, so
  flightdeck never spends one of those tries on its own; each approval says how many are
  left, and a platform's answer that first says so is a warning under "auto". The player
  can opt out of that hold (DeckConfig.submit_limited "auto": DeckConfig.holds);
- once the platform says no tries are left at a challenge's flag (its answer to a flag, or
  its count at a pull: platform_tries), the challenge is out of tries: blocked, out of the
  queue, its lanes stopped, and a warning says so, until a newer count says tries are left
  again (then it is parked for the player to queue). A flag the platform did not check for
  want of tries is never taken for wrong, nor put to the player to submit by hand: the
  platform checks no more flags for it, by hand either;
- a challenge whose flag rotates (Challenge.rotates: every that many seconds, on clock
  boundaries) has windows, counted on this machine's clock (the deck's `wall`, Unix time:
  window number = time // rotates; a platform whose clock differs from this machine's has
  its boundaries that much earlier or later, and flightdeck does not know by how much). A
  flag of it is never sent in a later window than the one a lane claimed it in (it waited
  for the player's approval, stood in line behind another flag of the challenge, or behind
  the submitter's other flags: rotated, platform_rotated), nor within ROTATE_MARGIN seconds
  of its window's end (it would die on the way). Instead of going out it is dropped: each
  open lane that sent it is told it rotated out and to fetch and submit a fresh one
  (LaneDriver.rotated), a warning says so, and nothing is recorded as wrong, so the same
  flag claimed again is a new claim. A flag of it judged wrong is remembered as not the
  flag like any other, but the first ROTATING_MISSES of them do not count toward the
  wrong-answer stop (wrong_flags): a miss there is usually a rotation, not a guess;
- approvals queue up per lane (a flag goes first) and none is ever dropped;
- a lane at 80% of a cap gets a budget alert, and at 100% it waits for approval;
- a lane that gave up while a flag of it waits is open only for that flag's answer: it takes
  no hint, new plan or escalation (no driver gives it another turn);
- team mode: a challenge a teammate solved or claimed is not worked; a teammate's
  solve stops every lane on it;
- an intervention is the player's, or autopilot's by rule (apply's `by`): the log, the lane's
  transcript and every text say which. Autopilot may escalate, fork, kill, redirect, pause,
  queue and approve a lane's budget request (within the run budget), and nothing else: it
  never answers a flag or a live-box request;
- while autopilot guards the run (Deck.autopilot, autopilot.py: from engaging it until the
  player takes the controls back), no flag goes to the platform on its own when it would
  spend the last try the platform counts at a challenge (the count is 1), `submit_limited =
  "auto"` or not: it waits for the player, and a warning says so (D20). A count the platform
  has not given is not taken for the last try;
- once the run is closing (close(): the player quit), its lanes stop at once without ending
  (each driver is told to stop its lane before close() returns), nothing raises an alert,
  asks the player or starts a lane, and what a lane reports counts its spend only, as after
  a lane's end;
- flag variants (DeckConfig.variant_tries, 0: none): when the platform judges a flag wrong (its
  answer through platform_verdict, or the board's answers file; never the player's word, a
  decline or an answer that is no verdict), the deck proposes the next-ranked other spelling
  of it (flagvariants.variants: the case, a doubled wrapper, leet...) that is not known not to
  be the flag and neither waits nor is on its way, on the lane that sent the flag (the first
  sender still open), as a candidate through _candidate: every rule above holds for it as for a
  flag the lane claims, so it is sent only where such a flag would be. It waits for the player
  where the flag it comes from went out on the player's yes, and where the challenge's
  description holds it. At most `variant_tries` are proposed per challenge in a run, one at a
  time: the next only once the platform judged the one before wrong. A wrong variant is a
  wrong flag (it counts for wrong_stop), and a right one solves the challenge. The lane's
  transcript, the approval and the submit event (`variant_of`, `variant_changes`) say which
  flag it is a variant of and what changed. See _variant.

Call the deck only from the thread that created it (see core/driver.py).
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import asdict, dataclass, replace

from .. import flagvariants, fmt
from ..text import untrusted
from .attention import ALERT_URGENCY, attention_key
from .driver import Clock, LaneDriver, Submitter, TurnReport, Verifier, spend_only
from .interventions import (
    Approve,
    Claim,
    Decline,
    Dismiss,
    Escalate,
    Fork,
    HandBack,
    Hint,
    Intervention,
    Kill,
    Outcome,
    Pause,
    Queue,
    Redirect,
    Release,
    Resume,
    TakeOver,
)
from .model import (
    COURSE_ALERTS,
    INFORMATIONAL_ALERTS,
    ME,
    Action,
    ActionKind,
    Actor,
    Alert,
    AlertKind,
    Challenge,
    ChallengeStatus,
    DeckConfig,
    EscalationSummary,
    Event,
    EventKind,
    FLAG_PENDING,
    Lane,
    LaneState,
    Pending,
    PendingKind,
    SUBMIT_POLICIES,
    Suggestion,
    UNLIMITED_LANES,
    lanes_text,
)

BUDGET_WARN = 0.8  # fraction of a cap that raises the budget alert
BUDGET_RAISE = 1.5  # approving more budget multiplies the caps by this
ROTATE_MARGIN = 8.0  # seconds: a rotating flag is not sent this close to its window's end (at most half the window)
ROTATING_MISSES = 6  # wrong flags at a rotating challenge that do not count toward the wrong-answer stop
ACTORS = {Actor.PLAYER: "the player", Actor.AUTOPILOT: "autopilot"}  # who an intervention can be by, as texts say it
BY_RULE = (Escalate, Fork, Kill, Redirect, Pause, Queue, Approve)  # what autopilot may do (an Approve: a lane's budget request only)


@dataclass
class QueueEntry:
    """A lane waiting for a free slot: triage output, a fork, or a re-queue after a kill."""

    challenge: str
    model: str
    approach: str = ""
    parent: str | None = None
    attempt: int = 1
    token_cap: int | None = None
    dollar_cap: float | None = None


MAX_STANDING = 12  # notes for every lane kept for lanes started later (Deck.tell_all)
REJECTED = "rejected by the platform"
SAID_REJECTED = "the player said the platform rejected it"
DECLINED = "the player declined to submit it"
NOT_FLAG_RANK = {DECLINED: 1, SAID_REJECTED: 2, REJECTED: 3}  # how sure: a stronger reason is kept
OUT_OF_TRIES = "out of tries: the platform checks no more flags for it"  # a blocked challenge's note, once none are left


@dataclass(frozen=True)
class _VariantOf:
    """A flag the deck proposed as a variant: of which flag (one the platform rejected), and
    what differs (flagvariants' labels, and the same in words)."""

    of: str
    changes: tuple[str, ...]
    what: str


@dataclass
class _ToPlatform:
    """A flag for the platform, handed to the submitter (`sent`) or waiting its turn on its
    challenge. `lanes`: the lanes that sent it, in order; it goes out for the first one.
    `approved`: the player said yes to it (else it went out on its own, under auto)."""

    flag: str
    lanes: list[str]
    sent: bool = False
    approved: bool = False

    @property
    def lane(self) -> str:
        return self.lanes[0]


def _tries_text(ch: Challenge) -> str:
    """The tries left at the challenge's flag, as far as flightdeck knows; "" when the
    platform does not count them."""
    left, most = ch.tries_left, ch.max_attempts
    if left is None:
        return f"{most} {'try' if most == 1 else 'tries'} in all, how many are left is not known yet" if most else ""
    if left <= 0:
        return "no tries left: the platform checks no more flags for it"
    text = f"{left} {'try' if left == 1 else 'tries'} left" + (f" of {most}" if most else "")
    return text + (": the last one" if left == 1 else "")


def _submit_detail(ch: Challenge, flag: str) -> str:
    """What a flag's approval says: the flag, the tries left when they are counted, and that
    it rotates when it does."""
    said = [_tries_text(ch)] + ([f"it rotates every {ch.rotates} s: it only goes out in the window it was found in"] if ch.rotates else [])
    said = [text for text in said if text]
    return f"submit {flag}" + (f" ({'; '.join(said)})" if said else "")


class Deck:
    def __init__(
        self, config: DeckConfig, driver: LaneDriver, clock: Clock, verify: Verifier, *,
        submitter: Submitter | None = None, wall: Callable[[], float] = time.time,
    ) -> None:
        """`verify` checks a flag at once (an answers file, or never: the player submits by
        hand). With a `submitter` (a platform over the network) the deck never calls it: a
        flag goes to the submitter, and its answer comes back through platform_verdict().
        `wall`: this machine's clock, in Unix seconds, for the windows of rotating flags only
        (`clock` counts from the run's start, and a window is a time of day)."""
        self.wall = wall
        self._claimed: dict[tuple[str, str], float] = {}  # (challenge id, flag) of a rotating challenge -> when a lane last claimed it (wall)
        self.config = config
        self.driver = driver
        self.clock = clock
        self.verify = verify
        self.submitter = submitter
        self._lines: dict[str, list[_ToPlatform]] = {}  # challenge id -> its flags for the platform: the first is sent
        self.challenges: dict[str, Challenge] = {}
        self.lanes: dict[str, Lane] = {}
        self.queue: list[QueueEntry] = []
        self.events: list[Event] = []
        self._listeners: list[Callable[[Event], None]] = []
        self._lane_seq = 0
        self._start_errors: dict[int, str] = {}  # id(queue entry) -> why its lane could not start
        self._accepted: dict[str, str] = {}  # a flag the platform (or the player) called right -> the challenge it solved
        self.waits: dict[str, str] = {}  # challenge id -> why no lane starts on it yet (wait_for): its instance is not up
        self.standing: list[str] = []  # the player's notes for every lane (tell_all): a lane started later reads them at its start
        self._not_flags: dict[str, dict[str, str]] = {}  # challenge id -> flag -> why it is known not to be the flag
        self._spent: set[str] = set()  # challenges out of tries: closed until tries come back (_out_of_tries)
        self._answered: dict[str, float] = {}  # challenge id -> when the platform last answered one of its flags
        self.held = ""  # why no more lanes start (hold_queue), "" while they do
        # asked before a queued lane starts: why none should now ("" to start), or None for no gate
        self.start_gate: Callable[[], str] | None = None
        self.gated = ""  # why the start gate holds new lanes back now, "" while it does not
        self._ended_by_hold: list[str] = []  # lanes that what the hold is about ended: release_hold queues their challenges again
        self.closing = False  # the run is closing (close()): its lanes stop without ending
        self.autopilot = None  # the run's autopilot (autopilot.Autopilot sets it), if it has one: its `guarding` is read here
        self._by = Actor.PLAYER  # who the intervention being applied is by (apply)
        self._variants: dict[str, dict[str, _VariantOf]] = {}  # challenge id -> flag the deck proposed as a variant -> of what
        self._variant_roots: dict[str, list[str]] = {}  # challenge id -> flags the platform rejected that variants come from, newest last
        self._variant_count: dict[str, int] = {}  # challenge id -> variants proposed in this run (DeckConfig.variant_tries caps it)
        self._ranked: dict[str, tuple[flagvariants.Variant, ...]] = {}  # a rejected flag -> its ranked variants
        self._kept: set[tuple[str, str]] = set()  # (challenge id, flag) autopilot's last-try rule made wait: said once
        self.listener_errors: list[str] = []  # listeners that raised (shown when the run ends)
        self._warning_listener_failure = False
        self._flag_re = re.compile(config.flag_format)
        self._thread = threading.get_ident()
        driver.attach(self)

    # ------------------------------------------------------------------ reading

    @property
    def now(self) -> float:
        return self.clock.now()

    def active_lanes(self) -> list[Lane]:
        return [lane for lane in self.lanes.values() if not lane.finished]

    def lanes_on(self, challenge_id: str) -> list[Lane]:
        """Active lanes working a challenge."""
        return [
            lane
            for lane in self.lanes.values()
            if lane.challenge_id == challenge_id and not lane.finished
        ]

    def queued(self, challenge_id: str) -> bool:
        return any(entry.challenge == challenge_id for entry in self.queue)

    def needing(self) -> list[Lane]:
        """Lanes that need the player, most urgent first."""
        now = self.now
        return sorted((lane for lane in self.lanes.values() if lane.needs_you), key=lambda lane: attention_key(lane, now))

    def totals(self) -> tuple[int, float, bool]:
        """Tokens and known dollars over all lanes, and whether any lane has no known price."""
        lanes = self.lanes.values()
        return (sum(lane.tokens for lane in lanes), sum(lane.known_dollars for lane in lanes),
                any(lane.dollars is None for lane in lanes))

    def subscribe(self, listener: Callable[[Event], None]) -> Callable[[], None]:
        """Call `listener` with every new event. Returns a function that unsubscribes."""
        self._listeners.append(listener)
        return lambda: self._listeners.remove(listener)

    def summary(self, lane: Lane) -> EscalationSummary:
        """The compact state handed to a stronger model on escalation."""
        ch = self.challenges[lane.challenge_id]
        return EscalationSummary(
            lane=lane.id,
            challenge=ch.name,
            category=ch.category,
            points=ch.points,
            solves=ch.solves,
            files=ch.files,
            plan=lane.plan,
            model=lane.model,
            turns=lane.turns,
            tokens=lane.tokens,
            tried=tuple(a.text for a in lane.actions if a.kind is ActionKind.STEP)[-4:],
            found=tuple(lane.artifacts),
            alerts=tuple(f"{a.kind.label}: {a.reason}" for a in lane.alerts),
            not_flags=tuple(f"{flag} ({why})" for flag, why in self._not_flags.get(ch.id, {}).items()),
        )

    def not_flag(self, challenge_id: str, flag: str) -> str | None:
        """Why `flag` is known not to be the flag of that challenge (rejected, or declined by
        the player), or None."""
        return self._not_flags.get(challenge_id, {}).get(flag)

    def set_max_lanes(self, most: int) -> Outcome:
        """The player changes how many lanes run at once, for the rest of the run (/config
        lanes): UNLIMITED_LANES for no limit. Never more than the event's rules allow
        (DeckConfig.lanes_ceiling). Raising it starts queued lanes in the new slots; lowering
        it stops no lane: the ones that run go on, and no new one starts until fewer run."""
        self._on_thread("set_max_lanes")
        if isinstance(most, bool) or not isinstance(most, int) or most < 1:
            return Outcome(False, "The number of lanes must be a whole number, 1 or more, or 'unlimited'")
        most = min(most, UNLIMITED_LANES)
        ceiling = self.config.lanes_ceiling
        if ceiling is not None and most > ceiling:
            return Outcome(False, f"The event's rules allow at most {ceiling} lane{'s' if ceiling != 1 else ''} at once (rules.max_lanes)")
        before = self.config.max_lanes
        if most == before:
            return Outcome(True, f"Lanes at once: {lanes_text(most)} already")
        self.config = replace(self.config, max_lanes=most)
        self._emit(EventKind.WARNING, f"the player set lanes at once to {lanes_text(most)} (it was {lanes_text(before)})",
                   data={"config": "max_lanes", "max_lanes": most, "was": before})
        self._fill()
        running = len(self.active_lanes())
        over = f"; {running} run now and go on, and no new lane starts until fewer than {most} run" if running > most else ""
        return Outcome(True, f"Lanes at once: {lanes_text(most)} for the rest of this run{over}")

    def set_submit(self, policy: str) -> Outcome:
        """The player switches auto approve on or off for the rest of the run (/config submit):
        "auto" sends a flag a lane claims at once, with every exception auto submit has
        (counted tries, the wrong-answer stop, a flag the challenge's own text holds);
        "confirm" makes every flag wait again. Never looser than the event's rules
        (DeckConfig.submit_ceiling). Flags already waiting keep waiting: they are the player's."""
        self._on_thread("set_submit")
        if policy not in SUBMIT_POLICIES:
            return Outcome(False, f"Submit is one of: {', '.join(SUBMIT_POLICIES)}")
        if policy == "auto" and self.config.submit_ceiling != "auto":
            return Outcome(False, "The event's rules do not let flightdeck submit flags by itself, so every flag waits for you")
        before = self.config.submit
        if policy == before:
            return Outcome(True, f"Submit is {policy} already")
        self.config = replace(self.config, submit=policy)
        self._emit(EventKind.WARNING, f"the player set submit to {policy} (it was {before})", data={"config": "submit", "submit": policy, "was": before})
        if policy == "auto":
            waiting = sum(1 for lane in self.lanes.values() if not lane.finished
                          for p in ([lane.pending] if lane.pending else []) + lane.waiting if p.kind is PendingKind.SUBMIT)
            rest = f"; the {waiting} waiting now still wait for you (A approves them all)" if waiting else ""
            return Outcome(True, f"Auto approve is on: a flag a lane submits goes at once, for the rest of this run{rest}")
        return Outcome(True, "Auto approve is off: every flag waits for your approval")

    def wait_for(self, challenge_id: str, why: str) -> None:
        """No lane starts on that challenge until ready() is called for it: something outside
        the deck must come first (the platform starting its instance). Its queued lanes keep
        their places, and the lanes behind them start meanwhile. Lanes already on it go on."""
        self._on_thread("wait_for")
        self.waits[challenge_id] = why
        ch = self.challenges.get(challenge_id)
        if ch is not None and not ch.closed and not ch.note:
            ch.note = why  # what the board says of it while it waits

    def ready(self, challenge_id: str) -> None:
        """What a challenge waited for is there: its queued lanes may start, in the free slots."""
        self._on_thread("ready")
        why = self.waits.pop(challenge_id, None)
        if why is not None:
            ch = self.challenges.get(challenge_id)
            if ch is not None and ch.note == why:
                ch.note = ""
            self._fill()

    def wrong_flags(self, challenge_id: str) -> int:
        """How many flags of that challenge count as wrong answers in this run (the wrong-answer
        stop reads it): those judged wrong by the platform, or by the player's word after a
        hand submit. A flag the player only declined is not one. At a challenge whose flag
        rotates, the first ROTATING_MISSES judged wrong are not counted (a flag that died on
        the way is no guess); every one after them is."""
        wrong = sum(1 for why in self._not_flags.get(challenge_id, {}).values() if why in (REJECTED, SAID_REJECTED))
        ch = self.challenges.get(challenge_id)
        return max(0, wrong - ROTATING_MISSES) if ch is not None and ch.rotates else wrong

    def rotated(self, challenge_id: str, flag: str) -> str:
        """Why `flag`, as a lane last claimed it, would be dead if it went to the platform now
        ("" when it would not, and for a challenge whose flag does not rotate): this is a
        later window than the one it was claimed in, or its window ends within the margin
        (ROTATE_MARGIN seconds, at most half a window). Windows are counted on this machine's
        clock (`wall`)."""
        ch = self.challenges[challenge_id]
        every = ch.rotates
        if not every:
            return ""
        now = self.wall()
        claimed = self._claimed.get((challenge_id, flag), now)
        if claimed // every != now // every:
            return f"it was found in an earlier {every}-second window"
        left = every - now % every
        if left < min(ROTATE_MARGIN, every / 2):
            return f"its {every}-second window ends in {left:.0f} s, before the platform would have it"
        return ""

    def variant_of(self, challenge_id: str, flag: str) -> tuple[str, str] | None:
        """When the deck proposed `flag` as a variant at that challenge: the flag it is a
        variant of (one the platform rejected) and what changed, in words. Else None."""
        variant = self._variants.get(challenge_id, {}).get(flag)
        return None if variant is None else (variant.of, variant.what)

    def variants_tried(self, challenge_id: str) -> int:
        """How many variants the deck proposed at that challenge in this run."""
        return self._variant_count.get(challenge_id, 0)

    def submitting(self, challenge_id: str) -> tuple[tuple[str, str], ...]:
        """The flags of that challenge on their way to the platform (with a submitter), whose
        answer is not in yet, as (lane id, flag): the one handed to the submitter first, then
        those waiting their turn behind it."""
        return tuple((item.lane, item.flag) for item in self._lines.get(challenge_id, ()))

    def sending(self, lane_id: str) -> tuple[str, ...]:
        """The flags of that lane on their way to the platform (also one another lane sent
        first), whose answer is not in yet: the console marks the lane while there are any."""
        lane = self.lanes.get(lane_id)
        if lane is None:
            return ()
        return tuple(item.flag for item in self._lines.get(lane.challenge_id, ()) if lane_id in item.lanes)

    def fork_model(self, model: str) -> str:
        """Default model for a fork: the next stronger one, else the weakest other one, else the same."""
        ladder = self.config.models
        if model in ladder and ladder.index(model) + 1 < len(ladder):
            return ladder[ladder.index(model) + 1]
        others = [m for m in ladder if m != model]
        return others[0] if others else model

    # ------------------------------------------------------------------ board

    def release(self, challenges: Sequence[Challenge], entries: Sequence[QueueEntry], label: str = "Release") -> None:
        """Put challenges on the board and queue the triaged entries, in order."""
        self._on_thread("release")
        seen: set[str] = set()
        for ch in challenges:
            if ch.id in self.challenges or ch.id in seen:
                raise ValueError(f"challenge {ch.id!r} is already on the board")
            seen.add(ch.id)
        known = {ch.id for ch in challenges} | set(self.challenges)
        for entry in entries:
            if entry.challenge not in known:
                raise KeyError(f"queue entry for unknown challenge {entry.challenge!r}")
            if self.config.models and entry.model not in self.config.models:
                raise ValueError(
                    f"queue entry for {entry.challenge!r} uses model {entry.model!r}, which is not in "
                    f"the model ladder ({', '.join(self.config.models)})"
                )
        for ch in challenges:
            self.challenges[ch.id] = ch
        for entry in entries:
            ch = self.challenges[entry.challenge]
            if self._workable(ch):
                self.queue.append(entry)
                if not self.lanes_on(ch.id):
                    ch.status = ChallengeStatus.QUEUED
        before = len(self.lanes)
        self._fill()
        started = len(self.lanes) - before  # a lane whose start failed is gone again
        self._emit(
            EventKind.RELEASE,
            f"{label}: {len(challenges)} challenges · {started} lanes started · {len(self.queue)} queued",
            data={
                "label": label, "challenges": [ch.id for ch in challenges], "started": started, "queued": len(self.queue),
                "event": self.config.event,  # with the names and points below, a run log names its own board
                "board": [{"id": ch.id, "name": ch.name, "category": ch.category, "points": ch.points} for ch in challenges],
            },
        )

    def set_solves(self, challenge_id: str, solves: int) -> None:
        self._on_thread("set_solves")
        self.challenges[challenge_id].solves = solves

    def teammate_solved(self, challenge_id: str, who: str, *, before_run: bool = False) -> None:
        """Team mode: a teammate solved a challenge. Its lanes stop and it leaves the queue.
        `before_run`: the solve was already in the team folder when the run started, so no
        report counts it as a solve that came during the run."""
        self._on_thread("teammate_solved")
        self._need_team("teammate_solved")
        ch = self.challenges[challenge_id]
        mark = {"before_run": True} if before_run else {}
        if ch.closed:  # we, or another teammate, got there first; keep that record
            self._emit(EventKind.TEAMMATE, f"{who} also solved {ch.name}", challenge=ch.id,
                       data={"who": who, "solved": True, **mark})
            return
        ch.status = ChallengeStatus.TEAMMATE
        ch.solved_by = who
        ch.solves += 1
        ch.note = ""
        self._drop_queued(ch.id)
        stopped = []
        for lane in self.lanes_on(ch.id):
            self._raise(
                lane,
                Alert(
                    AlertKind.TEAMMATE,
                    f"{who} solved {ch.name}, so flightdeck stopped this lane (team mode).",
                    (Suggestion("", "Nothing to do: stopping is automatic in team mode"),),
                ),
            )
            self._finish(lane, LaneState.STOPPED, f"{who} solved {ch.name}")
            stopped.append(lane.id)
        text = f"{who} solved {ch.name}"
        if stopped:
            text += f" · stopped {', '.join(stopped)}"
        self._emit(EventKind.TEAMMATE, text, challenge=ch.id, data={"who": who, "solved": True, "stopped": stopped, **mark})

    def platform_solved(self, challenge_id: str, who: str, *, before_run: bool = False) -> None:
        """The platform lists a challenge as solved by this account or its team (CTFd), solo
        or team mode: it is closed, its lanes stop and it leaves the queue. `who` says by whom
        as far as the platform tells ("you", "your team"). A solve event records it, so
        reports count it."""
        self._on_thread("platform_solved")
        ch = self.challenges[challenge_id]
        data = {"who": who, "solved": True, "source": "platform", "before_run": before_run}
        if ch.closed:
            self._emit(EventKind.TEAMMATE, f"the platform lists {ch.name} as solved ({who})", challenge=ch.id, data=data)
            return
        ch.status = ChallengeStatus.TEAMMATE
        ch.solved_by = who
        ch.note = ""
        self._drop_queued(ch.id)
        stopped = []
        for lane in self.lanes_on(ch.id):
            self._finish(lane, LaneState.STOPPED, f"the platform lists {ch.name} as solved ({who})")
            stopped.append(lane.id)
        text = f"the platform lists {ch.name} as solved ({who})" + (f" · stopped {', '.join(stopped)}" if stopped else "")
        self._emit(EventKind.TEAMMATE, text, challenge=ch.id, data={**data, "stopped": stopped})

    def platform_verdict(
        self, lane_id: str, flag: str, ok: bool | None, detail: str = "", *, tries_left: int | None = None
    ) -> None:
        """The platform's answer to a flag the submitter took for `lane_id`: True correct, False
        incorrect, None not judged or not known (paused, rate-limited, out of tries, no answer):
        then the player submits it by hand and says how it went, as for a board that cannot
        check flags, but out of tries. `detail`: the platform's words, or why there is no
        verdict (untrusted). `tries_left`: the tries left on the challenge, when the platform
        said; from then on its flags wait for the player, also under auto. On a challenge out
        of tries a count above 0 is not taken (the answer can be older than the count that
        closed it): a count asked after the answer opens it again (platform_tries).

        No tries left (tries_left 0, or 0 known before and no verdict now): the challenge is out
        of tries (_out_of_tries). A flag the platform did not check then is not
        known to be wrong: it is not remembered as wrong, no lane hears it was, and nobody is
        asked to submit it by hand, since the platform checks no more flags for the challenge;
        a wrong one (the last try) is recorded wrong first.

        It holds when the lane has ended meanwhile (killed, gave up, stopped): a right flag
        still solves the challenge, credited to that lane. When the challenge was solved
        meanwhile (by another lane, a teammate, or as the platform lists it), the answer is
        recorded and nothing reopens. Then the next flag waiting its turn on the challenge
        goes out, unless the player must decide: after an answer that is no verdict, or once
        the tries are counted, each one goes back to the lanes that sent it as an approval
        (one the player said yes to still goes on its turn, unless it would spend the last
        try). See _next_to_platform and _back_to_player."""
        self._on_thread("platform_verdict")
        lane = self.lanes[lane_id]
        ch = self.challenges[lane.challenge_id]
        line = self._lines.get(ch.id, [])
        if not line or not line[0].sent or line[0].lane != lane_id or line[0].flag != flag:
            raise ValueError(f"no flag of {lane_id} is on its way to the platform as {flag!r}")
        sent = line.pop(0)
        if not line:
            del self._lines[ch.id]
        self._answered[ch.id] = self.now  # a count of its tries asked before now may be older than this answer
        if tries_left is not None and not (tries_left and ch.id in self._spent):
            self._tries(ch, tries_left)  # out of tries, only a count asked after this answer opens it (platform_tries)
        elif tries_left is None and ok is False and ch.tries_left is not None and ch.tries_left > 1 and self._guarded():
            # the platform judged it wrong and did not say what is left: under autopilot's guard the deck counts the
            # try itself, down to 1 and no further (0 is the platform's to say), so the last one is never spent unseen
            self._tries(ch, ch.tries_left - 1)
        extra: dict[str, object] = {"detail": detail} if detail else {}
        if tries_left is not None:
            extra["tries_left"] = tries_left
        if ok is not None and detail:
            self._note(lane, f"the platform's answer to {flag}: {detail}")
        unchecked = ok is None and ch.tries_left == 0 and not ch.closed  # no try was left for it: the platform checks no more
        if unchecked:
            for each in (self.lanes[i] for i in sent.lanes):
                self._note(each, f"not checked by the platform: {flag} ({detail or 'no tries are left'}); it is not known "
                                 "to be wrong")
        elif ch.closed:  # solved meanwhile: the answer is recorded, and nothing reopens
            if ok is None:
                self._note(lane, f"no verdict from the platform on {flag} ({detail or 'no reason given'}); "
                                 f"{ch.name} was solved meanwhile")
            else:
                self._note(lane, f"submitted {flag}: {'correct' if ok else 'incorrect'}")
                self._emit(EventKind.SUBMIT, f"{lane.id} submitted {flag} for {ch.name}: {'correct' if ok else 'incorrect'} "
                           f"(it was solved meanwhile)", lane.id, ch.id,
                           data={"flag": flag, "correct": ok, "by": "platform", "solved_meanwhile": True,
                                 **self._variant_data(ch.id, flag), **extra})
                if not ok:
                    self._remember_not_flag(ch.id, flag, REJECTED)
        elif ok is None:
            self._no_verdict(sent, ch, detail)
        else:
            self._verdict(lane, flag, ok, by="platform", data=extra, approved=sent.approved,
                          also=[self.lanes[i] for i in sent.lanes[1:]])
            if not ok:
                for other in (self.lanes[i] for i in sent.lanes[1:]):  # the lanes that sent it after the first
                    if not other.finished:
                        self._note(other, f"candidate {flag} dropped: {REJECTED} on {lane.id}")
                        self.driver.rejected(other, flag)
                        self._end_if_gave_up(other)
        if ch.tries_left == 0 and not ch.closed:
            self._out_of_tries(ch, flag=flag if unchecked else None, detail=detail if unchecked else "")
        self._next_to_platform(ch, ok)

    def platform_tries(
        self, challenge_id: str, left: int, *, before_run: bool = False, asked: float | None = None
    ) -> None:
        """The platform says how many tries are left at a challenge's flag (CTFd's details at a
        pull: the tries it allows, less those this account, or its team, used). From then on
        every approval of one of its flags says the count, as after a flag's answer; at 0 the
        challenge is out of tries (_out_of_tries). `asked`: when the count was asked, on the
        deck's clock. A count above the one the deck has is taken only when it was asked
        after the platform's last answer to a flag of the challenge (a count asked before it
        can be older than a try that answer spent), and never without `asked`; taken, it
        opens a challenge out of tries again (_tries_back): the platform gives tries back
        (CTFd's timeout behaviour, or its admin). `before_run`: the platform said so before
        the run started. A solved challenge is left as it is."""
        self._on_thread("platform_tries")
        ch = self.challenges[challenge_id]
        if ch.closed or left == ch.tries_left:
            return
        if ch.tries_left is not None and left > ch.tries_left:
            answered = self._answered.get(ch.id)
            if asked is None or (answered is not None and answered >= asked):
                return
        self._tries(ch, left)
        if ch.tries_left == 0:
            self._out_of_tries(ch, before_run=before_run)
        elif ch.id in self._spent:
            self._tries_back(ch)

    def note(self, lane_id: str, text: str) -> None:
        """A flightdeck note on a lane's transcript (from a component outside the deck); none
        once the lane has ended or the run is closing."""
        self._on_thread("note")
        lane = self.lanes.get(lane_id)
        if lane is not None and not lane.finished and not self.closing:
            self._note(lane, text)

    def record_l1(
        self,
        challenge_id: str,
        engine: str,
        status: str,
        *,
        flags: Sequence[str] = (),
        seconds: float = 0.0,
        notes: str = "",
        lane_id: str | None = None,
    ) -> None:
        """A no-model (L1) solver ran on a challenge: log it as an `l1` event, and as a
        flightdeck note on the lane it ran for. Its flags are not submitted here: report
        them on the lane (TurnReport.flag) so they go through the usual approval."""
        self._on_thread("record_l1")
        ch = self.challenges[challenge_id]
        lane = self.lanes.get(lane_id) if lane_id else None
        found = f": {', '.join(flags)}" if flags else ""
        text = f"L1 {engine} on {ch.name}: {status}{found}"
        if lane is not None and not lane.finished:
            self._note(lane, f"L1 {engine}: {status}{found}" + (f" ({notes})" if notes else ""))
        self._emit(
            EventKind.L1,
            text,
            lane_id,
            challenge_id,
            data={"engine": engine, "status": status, "flags": list(flags), "seconds": seconds, "notes": notes},
        )

    def record_route(self, challenge_id: str, *, family: str = "", category: str = "", by: str = "",
                     lane_id: str | None = None) -> None:
        """A light model routed a challenge at a lane's start (agent/facts.py): the specialist
        family it suits, and a guess at its category where the board names none flightdeck
        knows. Kept on the challenge (Challenge.family, Challenge.category_guess: its category
        stays the board's), logged as a `route` event, and noted on the lane it ran for. `by`
        names the light model."""
        self._on_thread("record_route")
        ch = self.challenges[challenge_id]
        if family:
            ch.family = family
        if category:
            ch.category_guess = category
        parts = ([f"family {family}"] if family else []) + (
            [f"category {category}? (a guess: the board names none flightdeck knows)"] if category else [])
        if not parts:
            return
        lane = self.lanes.get(lane_id) if lane_id else None
        if lane is not None and not lane.finished:
            self._note(lane, f"light model ({by}) routed it: {', '.join(parts)}")
        self._emit(
            EventKind.ROUTE,
            f"light model ({by}) routed {ch.name}: {', '.join(parts)}",
            lane_id,
            challenge_id,
            data={"family": family, "category": category, "board_category": ch.category, "by": by},
        )

    def warn(self, text: str, *, challenge: str | None = None, data: dict | None = None) -> None:
        """A warning for the player that belongs to no lane (a team folder problem, a failed
        poll): a WARNING event, which the console shows and the run log keeps."""
        self._on_thread("warn")
        self._emit(EventKind.WARNING, text, challenge=challenge, data=dict(data or {}))

    def teammate_release(self, challenge_id: str, who: str) -> None:
        """Team mode: a teammate's claim is gone (released, or gone stale), so the challenge can
        be worked again. A claim someone else holds now is left alone."""
        self._on_thread("teammate_release")
        self._need_team("teammate_release")
        ch = self.challenges[challenge_id]
        if ch.claimed_by != who:
            return
        ch.claimed_by = None
        self._emit(EventKind.TEAMMATE, f"{who} no longer claims {ch.name}", challenge=ch.id, data={"who": who, "claimed": False})

    def teammate_claim(self, challenge_id: str, who: str) -> None:
        """Team mode: a teammate claimed a challenge. It is not started while they hold it."""
        self._on_thread("teammate_claim")
        self._need_team("teammate_claim")
        ch = self.challenges[challenge_id]
        if ch.claimed_by == ME:
            self._emit(
                EventKind.WARNING,
                f"{who} also claimed {ch.name}; you hold the claim",
                challenge=ch.id,
                data={"who": who, "conflict": True},
            )
            return
        ch.claimed_by = who
        if ch.status is ChallengeStatus.QUEUED and not self.lanes_on(ch.id):
            self._drop_queued(ch.id)
            ch.status = ChallengeStatus.NEW
        self._emit(EventKind.TEAMMATE, f"{who} claimed {ch.name}", challenge=ch.id, data={"who": who, "claimed": True})

    # ------------------------------------------------------------------ lane reports

    def report(self, lane_id: str, rep: TurnReport) -> None:
        """Apply what a lane did. Called by the driver after each step. Once the lane has
        ended, only spend counts (driver.spend_only): a coding-agent CLI reports a turn's cost
        when the turn ends, often after its lane has (solved mid-turn, killed), and that cost
        is the lane's and the run's all the same. Anything else in a late report (a step that
        raced a kill) is dropped. So it is for every lane once the run is closing (close()):
        the cost of a turn that quitting cut counts, and it raises no budget alert and asks
        for nothing."""
        self._on_thread("report")
        lane = self.lanes[lane_id]
        if lane.finished or self.closing:
            if spend_only(rep):
                self._spend(lane, rep)
            return
        now = self.now
        if rep.turn:
            lane.turns += 1
        if rep.hints_taken:
            del lane.hints[: rep.hints_taken]
        self._spend(lane, rep)
        lane.last_active_at = now
        if rep.action:
            lane.actions.append(Action(now, lane.turns, rep.action, rep.output, Actor.LANE, ActionKind.STEP, calls=rep.calls))
        if rep.plan is not None:
            lane.plan = rep.plan
        for item in rep.artifacts:
            if item not in lane.artifacts:
                lane.artifacts.append(item)
        for change in rep.files:
            lane.files.pop(change.path, None)
            lane.files[change.path] = replace(change, turn=lane.turns, at=now)
        if rep.turn:
            data: dict[str, object] = {
                "turn": lane.turns,
                "model": rep.model or lane.model,
                "tokens": rep.tokens,
                "cached_tokens": rep.cached_tokens,
                "dollars": None if rep.dollars_later else rep.dollars,
                "action": rep.action,
            }
            if rep.dollars_later:  # not unknown, and not $0.00: the turn_end spend event has its cost
                data["dollars_later"] = True
            self._emit(EventKind.TURN, f"{lane.id} turn {lane.turns}: {rep.action}", lane.id, lane.challenge_id, data=data)
        for kind in rep.clear:
            self._clear(lane, kind)
        for alert in rep.alerts:
            self._raise(lane, alert)
        if rep.flag is not None:
            self._candidate(lane, rep.flag, claimed=rep.claimed)
            if lane.finished:
                return  # submitted automatically and correct
        if rep.pending is not None:
            self._ask(lane, rep.pending)
        if rep.declined:
            lane.declined = True
        if rep.gave_up is not None:
            if self._has_submit(lane):
                lane.gave_up_later = rep.gave_up
                waits = ("a candidate flag waits for you" if self._flag_waits(lane)
                         else "its flag is on its way to the platform: it ends once the answer is in")
                self._note(lane, f"gave up ({rep.gave_up}), but {waits}")
            else:
                self._finish(lane, LaneState.GAVE_UP, rep.gave_up, then=ChallengeStatus.PARKED)
                return
        self._check_budget(lane)

    # ------------------------------------------------------------------ interventions

    def apply(self, iv: Intervention, *, by: Actor = Actor.PLAYER) -> Outcome:
        """Apply an intervention: the player's, or with `by` Actor.AUTOPILOT one autopilot
        makes by rule. Logged before its effects, with its outcome after; autopilot's carry
        `"by": "autopilot"` in both events (the player's carry no `by`, as before autopilot),
        and every text says autopilot where the player's says the player. Autopilot is held
        to BY_RULE here, so no rule of it can approve anything."""
        self._on_thread("apply")
        if by not in ACTORS:
            raise ValueError(f"an intervention is by the player or by autopilot, not by {by!r}")
        name = type(iv).__name__.lower()
        lane = getattr(iv, "lane", None)
        challenge = getattr(iv, "challenge", None)
        who: dict[str, object] = {"by": by.value} if by is Actor.AUTOPILOT else {}
        details = {key: value for key, value in asdict(iv).items() if not (key == "model" and value is None and isinstance(iv, Queue))}
        self._emit(EventKind.INTERVENTION, f"{name} {lane or challenge}", lane, challenge, data={"intervention": name, **details, **who})
        self._by = by
        try:
            outcome = self._not_by_rule(iv) or self._apply(iv)
        finally:
            self._by = Actor.PLAYER
        self._emit(
            EventKind.OUTCOME,
            f"{name}: {outcome.message}",
            lane,
            challenge,
            data={"intervention": name, "ok": outcome.ok, "message": outcome.message, **who},
        )
        return outcome

    def _not_by_rule(self, iv: Intervention) -> Outcome | None:
        """Why autopilot may not make this intervention (None: it may, or it is the player's).
        It never takes over, claims or declines, and the one approval it gives is more budget for
        a lane that asks for it (the run budget is the limit that counts): a flag, a live-box
        request and a lane whose spend has no price wait for the player."""
        if self._by is not Actor.AUTOPILOT:
            return None
        if not isinstance(iv, BY_RULE):
            return Outcome(False, f"Autopilot does not {type(iv).__name__.lower()}: that is the player's to do")
        if isinstance(iv, Approve):
            lane = self.lanes.get(iv.lane)
            pending = lane.pending if lane is not None else None
            if pending is None or pending.kind is not PendingKind.BUDGET:
                what = f"{iv.lane} waits for: {pending.detail}" if pending is not None else f"{iv.lane} asks for no budget"
                return Outcome(False, f"Autopilot approves only a lane's budget request, and {what}")
            if lane.no_price() and lane.dollar_cap:
                return Outcome(False, f"{iv.lane} spent something with no known cost: going on without its dollar cap is "
                                      "the player's to say")
        return None

    @property
    def _who(self) -> str:
        """Who the intervention being applied is by, as texts say it: "the player" or "autopilot"."""
        return ACTORS[self._by]

    def _apply(self, iv: Intervention) -> Outcome:
        if self.closing:
            return Outcome(False, "The run is closing: its lanes are stopping, so nothing more can be done on them")
        if isinstance(iv, Claim):
            return self._claim(iv.challenge)
        if isinstance(iv, Release):
            return self._release_claim(iv.challenge)
        if isinstance(iv, Queue):
            return self._queue(iv.challenge, iv.model)
        lane = self.lanes.get(iv.lane)
        if lane is None:
            return Outcome(False, f"No lane {iv.lane}")
        if lane.finished and isinstance(iv, Fork) and lane.state is not LaneState.SOLVED:
            return self._fork(lane, iv.approach.strip(), iv.model)  # a lane that ended (the model declined, say): try again on another model
        if lane.finished:
            hint = "; fork it to try another model (f)" if lane.state is not LaneState.SOLVED and isinstance(iv, Escalate) else ""
            return Outcome(False, f"{lane.id} has finished ({lane.state.value}){hint}")
        if lane.state is LaneState.TAKEOVER and not isinstance(iv, (HandBack, Kill)):
            return Outcome(False, f"You have {lane.id}'s shell; hand it back first")
        if lane.gave_up_later and isinstance(iv, (Hint, Redirect, Escalate)):
            return Outcome(False, self._no_more_turns(lane))
        match iv:
            case Pause():
                return self._pause(lane)
            case Resume():
                return self._resume(lane)
            case Hint(text=text):
                return self._hint(lane, text.strip())
            case Redirect(text=text):
                return self._redirect(lane, text.strip())
            case Fork(approach=approach, model=model):
                return self._fork(lane, approach.strip(), model)
            case Kill(requeue=requeue):
                return self._kill(lane, requeue)
            case Escalate():
                return self._escalate(lane)
            case TakeOver():
                return self._take_over(lane)
            case HandBack(note=note):
                return self._hand_back(lane, note.strip())
            case Approve():
                return self._approve(lane)
            case Decline():
                return self._decline(lane)
            case Dismiss():
                return self._dismiss(lane)
        raise TypeError(f"unknown intervention {iv!r}")

    def _no_more_turns(self, lane: Lane) -> str:
        """Why a lane that gave up takes no hint, new plan or escalation, and what to do
        instead: it is open only for its flag's answer (gave_up_later), and no driver gives it
        another turn."""
        if self._flag_waits(lane):
            why, then = "until you answer its flag", "answer it (a or d)"
        else:
            why, then = "for the platform's answer to its flag", "wait for that answer"
        return f"{lane.id} gave up and takes no more turns; it is open only {why}: fork it onto another model (f), or {then}"

    def _pause(self, lane: Lane) -> Outcome:
        if lane.state is LaneState.PAUSED:
            return Outcome(False, f"{lane.id} is already paused")
        lane.state = LaneState.PAUSED
        self.driver.pause(lane)
        self._note(lane, f"paused by {self._who}", self._by)
        return Outcome(True, f"Paused {lane.id}")

    def _resume(self, lane: Lane) -> Outcome:
        if lane.state is not LaneState.PAUSED:
            return Outcome(False, f"{lane.id} is not paused")
        lane.state = LaneState.WAITING if lane.pending else LaneState.RUNNING
        if lane.state is LaneState.RUNNING:
            self.driver.resume(lane)
        self._note(lane, "resumed by the player", Actor.PLAYER)
        return Outcome(True, f"Resumed {lane.id}" + (" (it waits for your approval)" if lane.pending else ""))

    def _hint(self, lane: Lane, text: str) -> Outcome:
        if not text:
            return Outcome(False, "Empty message; nothing sent")
        lane.hints.append(text)
        self._clear_course(lane)
        self.driver.hint(lane, text)
        self._note(lane, text, Actor.PLAYER, ActionKind.MESSAGE)
        return Outcome(True, f"{lane.id} reads it on its next turn")

    def _tell(self, lane: Lane, text: str) -> None:
        """One of the player's notes for every lane, to this lane: read on its next turn."""
        lane.hints.append(text)
        self.driver.hint(lane, text)
        self._note(lane, text, Actor.PLAYER, ActionKind.MESSAGE)

    def tell_all(self, text: str) -> Outcome:
        """The player's note for every lane (an organizer's ruling, a handout that was replaced,
        a format everyone gets wrong): each open lane that still takes turns reads it on its
        next turn, and every lane started later in this run reads it at its start. It changes
        no lane's course (no alert is cleared: it is not about one lane). A lane in the
        player's hands, or one that only waits for its flag's answer, is passed over and
        counted. At most MAX_STANDING notes are kept for later lanes: each is in the context
        of every lane from then on."""
        self._on_thread("tell_all")
        text = text.strip()
        if not text:
            return Outcome(False, "Empty note; nothing sent")
        if len(self.standing) >= MAX_STANDING:
            return Outcome(False, f"{MAX_STANDING} notes for every lane are standing already; a lane's own message (h) still works")
        self.standing.append(text)
        told = passed = 0
        for lane in list(self.lanes.values()):
            if lane.finished:
                continue
            if lane.state is LaneState.TAKEOVER or lane.gave_up_later:
                passed += 1
                continue
            self._tell(lane, text)
            told += 1
        rest = f"; {passed} passed over (in your hands, or waiting only for a flag's answer)" if passed else ""
        return Outcome(True, f"{told} lane{'s' if told != 1 else ''} read it on their next turn, and every lane started later{rest}")

    def _redirect(self, lane: Lane, text: str) -> Outcome:
        if not text:
            return Outcome(False, "Empty plan; nothing changed")
        if text == lane.plan:
            return Outcome(False, "Plan unchanged; nothing sent")
        lane.plan = text
        lane.approach = text  # the player's own words: an escalated lane's brief carries them
        self._clear_course(lane)
        self.driver.redirect(lane, text)
        self._note(lane, f"new plan: {text}", self._by)
        return Outcome(True, f"{lane.id} has a new plan")

    def _fork(self, lane: Lane, approach: str, model: str | None) -> Outcome:
        ch = self.challenges[lane.challenge_id]
        if not self._workable(ch):
            return Outcome(False, f"No fork: {ch.name} is {self._why_not(ch)}")
        model = model or self.fork_model(lane.model)
        if self.config.models and model not in self.config.models:
            return Outcome(False, f"No fork: {model!r} is not in the model ladder ({', '.join(self.config.models)})")
        entry = QueueEntry(
            ch.id, model, approach=approach, parent=lane.id, token_cap=lane.token_cap, dollar_cap=lane.dollar_cap
        )
        self.queue.insert(0, entry)
        started = self._fill_and_find(entry)
        error = self._start_errors.pop(id(entry), None)
        if error is not None:
            return Outcome(False, f"Fork of {lane.id} could not start: {error}")
        if started is None:
            if self.held:  # no lane starts until the player lifts the hold, whatever slots are free
                self._note(lane, f"fork queued first ({model}): the queue is held", self._by)
                return Outcome(True, f"Fork of {lane.id} ({model}) is first in the queue, which is held: {self.held}")
            if self.gated and len(self.active_lanes()) < self.config.max_lanes:  # a free slot the start gate keeps empty
                self._note(lane, f"fork queued first ({model}): no new lane starts for now", self._by)
                return Outcome(True, f"Fork of {lane.id} ({model}) is first in the queue; no new lane starts for now: {self.gated}")
            self._note(lane, f"fork queued first ({model}): all {self.config.max_lanes} lanes busy", self._by)
            return Outcome(True, f"Fork of {lane.id} ({model}) is first in the queue; all {self.config.max_lanes} lanes are busy")
        self._note(lane, f"forked to {started.id} ({model})", self._by)
        return Outcome(True, f"Forked {lane.id} → {started.id} on {model}")

    def _kill(self, lane: Lane, requeue: bool) -> Outcome:
        ch = self.challenges[lane.challenge_id]
        if requeue and self._workable(ch):
            entry = QueueEntry(
                ch.id, lane.model, attempt=lane.attempt + 1, token_cap=lane.token_cap, dollar_cap=lane.dollar_cap
            )
            self.queue.insert(0, entry)
            self._finish(lane, LaneState.KILLED, f"by {self._who}; re-queued fresh", then=ChallengeStatus.QUEUED)
            started = self._started_for(entry)
            error = self._start_errors.pop(id(entry), None)
            if error is not None:
                return Outcome(True, f"Killed {lane.id}; a fresh lane could not start on {ch.name}: {error}")
            if started is None:
                return Outcome(True, f"Killed {lane.id}; {ch.name} is first in the queue")
            return Outcome(True, f"Killed {lane.id}; fresh lane {started.id} started on {ch.name}")
        why = "" if not requeue else f" ({ch.name} is {self._why_not(ch)}, so it was parked, not re-queued)"
        dropped = sum(1 for entry in self.queue if entry.challenge == ch.id)
        self._drop_queued(ch.id)  # parking means parking: queued forks go too
        self._finish(lane, LaneState.KILLED, f"by {self._who}; parked" + why, then=ChallengeStatus.PARKED)
        others = self.lanes_on(ch.id)
        if others:
            ids = ", ".join(other.id for other in others)
            return Outcome(True, f"Killed {lane.id}; {ids} still on {ch.name}")
        message = f"Killed {lane.id}; {ch.name} is parked{why}"
        if dropped:
            message += f"; dropped {dropped} queued fork{'s' if dropped > 1 else ''}"
        return Outcome(True, message)

    def _escalate(self, lane: Lane) -> Outcome:
        stronger, why = self._stronger(lane)
        if stronger is None:
            return Outcome(False, why)
        summary = self.summary(lane)
        old, lane.model = lane.model, stronger
        self._clear_course(lane)
        self.driver.escalate(lane, stronger, summary)
        lane.actions.append(
            Action(
                self.now,
                lane.turns,
                f"escalated {old} → {stronger} with a summary",
                "\n".join(summary_lines(summary)),
                self._by,
                ActionKind.PLAYER,
            )
        )
        return Outcome(True, f"Escalated {lane.id} from {old} to {stronger}")

    def _take_over(self, lane: Lane) -> Outcome:
        lane.paused_before_takeover = lane.state is LaneState.PAUSED
        lane.state = LaneState.TAKEOVER
        self.driver.pause(lane)
        self._note(lane, "taken over by the player", Actor.PLAYER)
        return Outcome(True, f"You have {lane.id}'s shell")

    def _hand_back(self, lane: Lane, note: str) -> Outcome:
        if lane.state is not LaneState.TAKEOVER:
            return Outcome(False, f"{lane.id} is not taken over")
        if lane.paused_before_takeover:  # the player paused it before: it stays paused until Resume
            lane.state = LaneState.PAUSED
        else:
            lane.state = LaneState.WAITING if lane.pending else LaneState.RUNNING
        lane.paused_before_takeover = False
        if lane.state is LaneState.RUNNING:
            self.driver.resume(lane)
        self._note(lane, "handed back by the player" + (f": {note}" if note else ""), Actor.PLAYER)
        return Outcome(True, f"Handed {lane.id} back" + ("; it stays paused" if lane.state is LaneState.PAUSED else ""))

    def _approve(self, lane: Lane) -> Outcome:
        pending = lane.pending
        if pending is None:
            if lane.alert(AlertKind.BUDGET) is not None:  # approve more before the cap is hit
                self._raise_caps(lane)
                self._clear(lane, AlertKind.BUDGET)
                self._note(lane, f"approved more budget: {self._cap_text(lane)}", Actor.PLAYER)
                return Outcome(True, f"{lane.id}'s cap is now {self._cap_text(lane)}")
            return Outcome(False, f"{lane.id} is not waiting for an approval")
        self._note(lane, f"approved: {pending.detail}" + (" (by autopilot)" if self._by is Actor.AUTOPILOT else ""), self._by)
        ch = self.challenges[lane.challenge_id]
        if pending.kind is PendingKind.CONFIRM:
            assert pending.flag is not None
            self._verdict(lane, pending.flag, True, by="player")
            return Outcome(True, f"{pending.flag} accepted: {ch.name} solved by {lane.id}")
        if pending.kind is PendingKind.SUBMIT:
            assert pending.flag is not None
            late = self.rotated(ch.id, pending.flag)
            if late:  # it rotated out while it waited: nothing goes out, by hand either
                self._resolve(lane)
                self._rotated_out([lane], ch, pending.flag, late)
                return Outcome(False, f"Not sent: {pending.flag} rotated out ({late}); {lane.id} was told to fetch a fresh "
                                      "one and submit that")
            if self.submitter is not None:  # a platform over the network: its answer comes later
                return self._send(lane, pending.flag, approved=pending)
            verdict = self._submit(lane, pending.flag, approved=True)
            if verdict is None:
                return Outcome(True, f"Submit {pending.flag} on the platform, then: a accepted, d rejected")
            if verdict:
                return Outcome(True, f"{pending.flag} is correct: {ch.name} solved by {lane.id}")
            return Outcome(True, f"{pending.flag} was rejected; {lane.id} carries on")
        if pending.kind is PendingKind.BUDGET:
            if lane.no_price() and lane.dollar_cap:
                lane.dollar_cap = None  # no price: the player chose to go on without a dollar cap
            used = lane.budget_used()
            if used is not None and used >= 1.0:
                self._raise_caps(lane)
            self._clear(lane, AlertKind.BUDGET)
            self._resolve(lane)
            self.driver.approved(lane, pending)
            return Outcome(True, f"{lane.id}'s cap is now {self._cap_text(lane)}")
        self._resolve(lane)
        self.driver.approved(lane, pending)
        return Outcome(True, f"{lane.id} may use the live box")

    def _decline(self, lane: Lane) -> Outcome:
        pending = lane.pending
        if pending is None:
            return Outcome(False, f"{lane.id} is not waiting for an approval")
        self._note(lane, f"declined: {pending.detail}", self._by)
        if pending.kind is PendingKind.CONFIRM:
            assert pending.flag is not None
            self._verdict(lane, pending.flag, False, by="player")
            return Outcome(True, f"{pending.flag} was rejected; {lane.id} carries on")
        if pending.kind is PendingKind.BUDGET:
            self._finish(lane, LaneState.STOPPED, f"{self._who} declined more budget")
            return Outcome(True, f"Stopped {lane.id}: no more budget")
        if pending.kind is PendingKind.SUBMIT and pending.flag is not None:
            self._remember_not_flag(lane.challenge_id, pending.flag, DECLINED)
        self._resolve(lane)
        self.driver.declined(lane, pending)
        if pending.kind is PendingKind.SUBMIT and pending.flag is not None:
            self._drop_known_wrong(lane, pending.flag)
        if self._end_if_gave_up(lane):
            what = f"Not submitted: {pending.flag}" if pending.kind is PendingKind.SUBMIT else "Declined"
            return Outcome(True, f"{what}; {lane.id} had given up, so it has ended")
        if pending.kind is PendingKind.SUBMIT:
            return Outcome(True, f"Not submitted: {pending.flag}; {lane.id} carries on")
        return Outcome(True, f"{lane.id} stays off the live box")

    def _dismiss(self, lane: Lane) -> Outcome:
        """Take down the lane's most urgent alert that wants an answer, when it is about the
        lane's course; the lane is not told. Any other alert has its own answer: refused, saying
        which. (The Watch sees a course alert go during an intervention and keeps it quiet.)"""
        answerable = [a for a in lane.alerts if a.kind not in INFORMATIONAL_ALERTS]
        if not answerable:
            if lane.pending is not None:
                return Outcome(False, f"{lane.id} waits for your approval, not for an alert: approve (a) or decline (d) it")
            if lane.alerts:
                return Outcome(False, f"Nothing to dismiss on {lane.id}: its alert ({lane.alerts[0].kind.label}) needs no answer, "
                                      "flightdeck already acted")
            return Outcome(False, f"{lane.id} has no alert to dismiss")
        top = min(answerable, key=lambda a: ALERT_URGENCY[a.kind])
        if top.kind is AlertKind.FLAG:
            return Outcome(False, f"{lane.id}'s flag is not dismissed: approve (a) or decline (d) it")
        if top.kind is AlertKind.BUDGET:
            return Outcome(False, f"{lane.id}'s budget alert is not dismissed: approve more (a), escalate (e) or kill (k)")
        if top.kind not in COURSE_ALERTS:
            return Outcome(False, f"{lane.id}'s alert ({top.kind.label}) is not one to dismiss")
        self._clear(lane, top.kind)
        self._note(lane, f"dismissed the alert: {top.kind.label}", Actor.PLAYER)
        return Outcome(True, f"Dismissed {lane.id}'s alert ({top.kind.label}); the lane carries on as it was")

    def _claim(self, challenge_id: str) -> Outcome:
        if not self.config.team:
            return Outcome(False, "Claims are for team mode (start with --team)")
        ch = self.challenges.get(challenge_id)
        if ch is None:
            return Outcome(False, f"No challenge {challenge_id}")
        if ch.closed:
            return Outcome(False, f"{ch.name} is already solved")
        if ch.claimed_by == ME:
            return Outcome(False, f"You already claimed {ch.name}")
        if ch.claimed_by:
            return Outcome(False, f"{ch.name} is claimed by {ch.claimed_by}")
        ch.claimed_by = ME
        return Outcome(True, f"Claimed {ch.name}; teammates will see it")

    def _release_claim(self, challenge_id: str) -> Outcome:
        if not self.config.team:
            return Outcome(False, "Claims are for team mode (start with --team)")
        ch = self.challenges.get(challenge_id)
        if ch is None:
            return Outcome(False, f"No challenge {challenge_id}")
        if ch.claimed_by != ME:
            return Outcome(False, f"{ch.name} is not claimed by you")
        ch.claimed_by = None
        return Outcome(True, f"Released {ch.name}")

    def _queue(self, challenge_id: str, model: str | None = None) -> Outcome:
        ch = self.challenges.get(challenge_id)
        if ch is None:
            return Outcome(False, f"No challenge {challenge_id}")
        if model is not None and self.config.models and model not in self.config.models:
            return Outcome(False, f"{model!r} is not in the model ladder ({', '.join(self.config.models)})")
        if not self._workable(ch):
            return Outcome(False, f"{ch.name} is {self._why_not(ch)}")
        if self.lanes_on(ch.id):
            return Outcome(False, f"{ch.name} already has a lane ({', '.join(x.id for x in self.lanes_on(ch.id))})")
        if self.queued(ch.id):
            return Outcome(False, f"{ch.name} is already queued")
        last = next((x for x in reversed(self.lanes.values()) if x.challenge_id == ch.id), None)
        if model is None and last is None and not self.config.models:
            return Outcome(False, f"No model to start {ch.name} with: it never had a lane and no model ladder is set")
        entry = QueueEntry(
            ch.id,
            model or (last.model if last else self.config.models[0]),
            attempt=last.attempt + 1 if last else 1,
            token_cap=last.token_cap if last else None,
            dollar_cap=last.dollar_cap if last else None,
        )
        self.queue.append(entry)
        ch.status = ChallengeStatus.QUEUED
        ch.note = ""
        started = self._fill_and_find(entry)
        error = self._start_errors.pop(id(entry), None)
        if error is not None:
            return Outcome(False, f"Could not start a lane on {ch.name}: {error}")
        on = f" on {entry.model}" if model is not None else ""
        if started is None:
            return Outcome(True, f"Queued {ch.name}{on} (position {len(self.queue)})")
        return Outcome(True, f"Started {started.id} on {ch.name}{on}")

    # ------------------------------------------------------------------ internals

    def _on_thread(self, what: str) -> None:
        if threading.get_ident() != self._thread:
            raise RuntimeError(
                f"Deck.{what} was called from another thread; call it on the thread that created the "
                "deck (from a worker thread, hop back first, e.g. app.call_from_thread)"
            )

    def _need_team(self, what: str) -> None:
        if not self.config.team:
            raise RuntimeError(f"{what} needs team mode (DeckConfig.team is False)")

    def _workable(self, ch: Challenge) -> bool:
        if ch.closed or ch.status is ChallengeStatus.BLOCKED:
            return False
        return ch.claimed_by in (None, ME)

    def _why_not(self, ch: Challenge) -> str:
        if ch.closed:
            return "already solved"
        if ch.status is ChallengeStatus.BLOCKED:
            return "blocked" + (f" ({ch.note})" if ch.note else "")
        if ch.claimed_by not in (None, ME):
            return f"claimed by {ch.claimed_by}"
        return "workable"

    def _drop_queued(self, challenge_id: str) -> None:
        self.queue = [entry for entry in self.queue if entry.challenge != challenge_id]

    def hold_queue(self, reason: str, *, ended: Iterable[str] = ()) -> None:
        """Start no more lanes (the queue stays): something wrong for every lane, such as a
        model API that refuses the key or the model id, or one that keeps failing. Said once,
        as a warning.

        `ended` names the lanes that what the hold is about ended, or is ending (a model API's
        outage): the challenges they park go back on the queue when the hold is lifted
        (release_hold). They are remembered whether this call placed the hold or the queue was
        held already, so a lane the same outage ends later is named by calling this again."""
        self._on_thread("hold_queue")
        for lane_id in ended:
            if lane_id not in self._ended_by_hold:
                self._ended_by_hold.append(lane_id)
        if self.held:
            return
        self.held = reason
        self._emit(EventKind.WARNING, f"no more lanes start: {reason}", data={"held": True, "reason": reason})

    def release_hold(self) -> Outcome:
        """Lift the hold: the player has fixed what it named, so queued lanes start again, as
        many as there are free slots. The challenges that what the hold was about parked
        (hold_queue's `ended` lanes) are queued again first, in front of the queue and in the
        order their lanes ended: _requeue_parked says which count. Logged as a warning event
        with held false, the pair of the hold's own (held true), with the challenges queued
        again if any, before the lanes it lets start. Refused, changing nothing, when the queue
        is not held."""
        self._on_thread("release_hold")
        if not self.held:
            return Outcome(False, "The queue is not held: queued lanes start as slots free up")
        reason, self.held = self.held, ""
        again = self._requeue_parked()
        text, data = "the player lifted the hold on the queue: lanes start again", {"held": False, "reason": reason}
        if again:
            text += f"; queued again, parked by what it was about: {', '.join(self.challenges[cid].name for cid in again)}"
            data["requeued"] = again
        self._emit(EventKind.WARNING, text, data=data)
        before = len(self.lanes)
        self._fill()
        started = len(self.lanes) - before  # a lane whose start failed is gone again
        said = f"{len(again)} parked challenge{'' if len(again) == 1 else 's'} queued again, " if again else ""
        return Outcome(True, f"Lifted the hold on the queue: {said}{started} lane{'' if started == 1 else 's'} started, "
                             f"{len(self.queue)} queued")

    def _requeue_parked(self) -> list[str]:
        """Queue again, in front, the challenges parked by the lanes the lifted hold named
        (hold_queue's `ended`), and return their ids. Only a challenge that is still as such a
        lane left it: that lane gave up and was the last on the challenge (so not one the
        player killed, queued again since, or that a later lane parked for another reason),
        and the challenge is parked, workable and neither queued nor being worked. The new
        lane starts as `/queue` would start it: on that lane's model, with its caps."""
        lanes, self._ended_by_hold = self._ended_by_hold, []
        entries: list[QueueEntry] = []
        for lane_id in lanes:
            lane = self.lanes.get(lane_id)
            if lane is None or lane.state is not LaneState.GAVE_UP:
                continue
            ch = self.challenges[lane.challenge_id]
            last = next(x for x in reversed(self.lanes.values()) if x.challenge_id == ch.id)
            if last is not lane or ch.status is not ChallengeStatus.PARKED or not self._workable(ch):
                continue
            if self.queued(ch.id) or self.lanes_on(ch.id):
                continue
            entries.append(QueueEntry(ch.id, lane.model, attempt=lane.attempt + 1, token_cap=lane.token_cap, dollar_cap=lane.dollar_cap))
            ch.status = ChallengeStatus.QUEUED
            ch.note = ""
        self.queue[:0] = entries
        return [entry.challenge for entry in entries]

    def close(self) -> None:
        """The run is closing (the player quit, or a signal stopped it). Every open lane stops
        here, without ending, so the run log and the transcripts keep each as it was: its
        driver is told to stop it (LaneDriver.stop, as at a lane's end) before this returns,
        so before anything else can run (the run's shutdown awaits its background tasks
        next). A driver reports no step of a lane it stopped, so no step lands on the closing
        deck to be dropped whole: what a step under way spent counts when the driver reports
        it as spend (a coding-agent CLI's cost of the turn quitting cut, that step's tokens in it).
        From now on nothing raises an alert, asks the player, notes a lane or starts one, and an
        intervention is refused. What a lane reports counts as after a lane's end: its spend
        only, on the lane and so the run, with its spend event, so the totals, the transcripts
        and the scorecard have every token and dollar reported. Once: a second call does nothing."""
        self._on_thread("close")
        if self.closing:
            return
        self.closing = True
        for lane in list(self.lanes.values()):
            if not lane.finished:
                self.driver.stop(lane)

    def recheck_starts(self) -> None:
        """Ask the start gate again, and start the queued lanes it now lets start. What sets
        the gate calls this when its answer may have changed (the run's governor tick): a lane
        that ends asks by itself. While starts are held it asks with nothing queued too, so
        the warning that they are no longer held is not left waiting for a queue."""
        self._on_thread("recheck_starts")
        if self.closing:
            return
        if self.gated:
            self._gate_holds()
        self._fill()

    def _gate_holds(self) -> bool:
        """Whether the start gate holds new lanes back now. Its answer is kept (gated), with a
        warning when starts begin to be held (the gate's reason) and one when they are no
        longer: never one per time it is asked, nor one for a reason that changed meanwhile."""
        reason = self.start_gate() if self.start_gate is not None else ""
        if not isinstance(reason, str):
            raise TypeError(f"the start gate must answer with a string (\"\" to start), not {type(reason).__name__}")
        was, self.gated = self.gated, reason
        if reason and not was:
            self._emit(
                EventKind.WARNING,
                f"no new lane starts for now: {reason}; the lanes at work carry on, and queued lanes start by "
                "themselves once this machine is back within the limit ([governor] in your config)",
                data={"gated": True, "reason": reason},
            )
        elif was and not reason:
            self._emit(
                EventKind.WARNING,
                f"queued lanes start again: this machine is back within its limits (it was: {was})",
                data={"gated": False, "reason": was},
            )
        return bool(reason)

    def _fill(self) -> None:
        """Start queued lanes while there are free slots (none while the queue is held, or the
        run is closing), each after the start gate was asked, unless no lane is active."""
        while self.queue and not self.held and not self.closing and len(self.active_lanes()) < self.config.max_lanes:
            # a challenge that waits for something outside the deck (its instance on the platform)
            # is passed over, not waited behind: the next one in the queue starts
            at = next((i for i, queued in enumerate(self.queue) if queued.challenge not in self.waits), None)
            if at is None:
                break
            if self.active_lanes() and self._gate_holds():
                return
            entry = self.queue.pop(at)
            ch = self.challenges[entry.challenge]
            if self._workable(ch):
                self._start(entry, ch)
                continue
            if ch.status is ChallengeStatus.QUEUED and not self.lanes_on(ch.id) and not self.queued(ch.id):
                ch.status = ChallengeStatus.NEW
            self._emit(
                EventKind.WARNING,
                f"dropped a queued lane for {ch.name}: it is {self._why_not(ch)}",
                challenge=ch.id,
                data={"reason": self._why_not(ch)},
            )

    def _fill_and_find(self, entry: QueueEntry) -> Lane | None:
        self._fill()
        return self._started_for(entry)

    def _started_for(self, entry: QueueEntry) -> Lane | None:
        """The lane started for `entry`, or None if it is still queued."""
        if any(e is entry for e in self.queue):
            return None
        return next(
            (
                lane
                for lane in reversed(self.lanes.values())
                if lane.challenge_id == entry.challenge
                and lane.parent == entry.parent
                and lane.attempt == entry.attempt
                and not lane.finished
            ),
            None,
        )

    def _start(self, entry: QueueEntry, ch: Challenge) -> Lane | None:
        self._lane_seq += 1
        now = self.now
        lane = Lane(
            number=self._lane_seq,
            challenge_id=ch.id,
            model=entry.model,
            approach=entry.approach,
            parent=entry.parent,
            attempt=entry.attempt,
            token_cap=entry.token_cap,
            dollar_cap=entry.dollar_cap,
            started_at=now,
            last_active_at=now,
        )
        self.lanes[lane.id] = lane
        ch.status = ChallengeStatus.RUNNING
        try:
            self.driver.start(lane, ch)
        except Exception as exc:  # the driver could not start this lane: park it and say why
            del self.lanes[lane.id]
            self._start_errors[id(entry)] = str(exc)
            if not self.lanes_on(ch.id):
                ch.status = ChallengeStatus.PARKED
                ch.note = f"could not start a lane: {exc}"
            self._emit(
                EventKind.WARNING,
                f"could not start a lane on {ch.name}: {exc}",
                challenge=ch.id,
                data={"error": repr(exc)},
            )
            return None
        how = f", fork of {entry.parent}" if entry.parent else ""
        how += f", attempt {entry.attempt}" if entry.attempt > 1 else ""
        self._emit(
            EventKind.LANE_START,
            f"{lane.id} started on {ch.name} ({lane.model}{how})",
            lane.id,
            ch.id,
            data={"model": lane.model, "parent": entry.parent, "attempt": entry.attempt, "approach": entry.approach},
        )
        for text in self.standing:  # what the player told every lane before this one started
            self._tell(lane, text)
        return lane

    def _finish(self, lane: Lane, state: LaneState, result: str, then: ChallengeStatus = ChallengeStatus.PARKED) -> None:
        """End a lane, update its challenge and start whatever is queued next."""
        lane.state = state
        lane.ended_at = self.now
        lane.result = result
        lane.pending = None
        lane.waiting.clear()
        lane.hints.clear()
        self._leave_line(lane)
        self.driver.stop(lane)
        ch = self.challenges[lane.challenge_id]
        if not ch.closed and not self.lanes_on(ch.id):
            if self.queued(ch.id):
                ch.status = ChallengeStatus.QUEUED
            else:
                ch.status = then
                if then is ChallengeStatus.PARKED:
                    ch.note = f"{lane.id} {state.value}: {result}"
        self._emit(EventKind.LANE_END, f"{lane.id} {state.value}: {result}", lane.id, ch.id, data={"state": state.value, "result": result})
        self._fill()

    def _raise(self, lane: Lane, alert: Alert) -> None:
        for i, existing in enumerate(lane.alerts):
            if existing.kind is alert.kind:
                lane.alerts[i] = replace(alert, at=existing.at)  # same alert, newer reason
                return
        now = self.now
        lane.alerts.append(replace(alert, at=now))
        lane.actions.append(Action(now, lane.turns, alert.kind.label, alert.reason, Actor.DECK, ActionKind.ALERT, alert.kind))
        self._emit(
            EventKind.ALERT,
            f"{lane.id} {alert.kind.label}: {alert.reason}",
            lane.id,
            lane.challenge_id,
            alert.kind,
            data={"reason": alert.reason, "suggestions": [s.key for s in alert.suggestions]},
        )

    def _clear(self, lane: Lane, kind: AlertKind) -> None:
        lane.alerts = [a for a in lane.alerts if a.kind is not kind]

    def _clear_course(self, lane: Lane) -> None:
        lane.alerts = [a for a in lane.alerts if a.kind not in COURSE_ALERTS]

    def _ask(self, lane: Lane, pending: Pending) -> None:
        """Queue an approval. A flag goes in front of any other kind; nothing is dropped."""
        pending = replace(pending, at=self.now)
        current = lane.pending
        if current is None:
            lane.pending = pending
        elif pending.kind in FLAG_PENDING and current.kind not in FLAG_PENDING:
            lane.waiting.insert(0, current)
            lane.pending = pending
        else:
            if pending.kind in FLAG_PENDING:  # a flag waits only behind other flags
                index = next((i for i, p in enumerate(lane.waiting) if p.kind not in FLAG_PENDING), len(lane.waiting))
                lane.waiting.insert(index, pending)
            else:
                lane.waiting.append(pending)
            self._note(lane, f"also waiting for approval: {pending.detail}")
            self._sync_flag_alert(lane)
            self._emit(EventKind.PENDING, f"{lane.id} also waits for: {pending.detail}", lane.id, lane.challenge_id, data={"kind": pending.kind.value, "detail": pending.detail, "queued": True})
            return
        self._became_current(lane)

    def _became_current(self, lane: Lane) -> None:
        pending = lane.pending
        assert pending is not None
        if lane.state is LaneState.RUNNING:
            lane.state = LaneState.WAITING
        self._sync_flag_alert(lane)
        lane.actions.append(Action(self.now, lane.turns, pending.detail, "", Actor.DECK, ActionKind.APPROVAL))
        self._emit(EventKind.PENDING, f"{lane.id} waits for approval: {pending.detail}", lane.id, lane.challenge_id, data={"kind": pending.kind.value, "detail": pending.detail, "flag": pending.flag})

    def _resolve(self, lane: Lane) -> None:
        """The current approval is answered: the next one comes up, or the lane runs again."""
        lane.pending = lane.waiting.pop(0) if lane.waiting else None
        if lane.pending is not None:
            self._became_current(lane)
            return
        self._sync_flag_alert(lane)
        if lane.state is LaneState.WAITING:
            lane.state = LaneState.RUNNING

    def _has_submit(self, lane: Lane) -> bool:
        """A flag of the lane waits: for the player, or for the platform's answer."""
        return self._flag_waits(lane) or bool(self.sending(lane.id))

    def _flag_waits(self, lane: Lane) -> bool:
        """A flag of the lane waits for the player (to approve it, or to say how it went)."""
        return any(p.kind in FLAG_PENDING for p in ([lane.pending] if lane.pending else []) + lane.waiting)

    def _sync_flag_alert(self, lane: Lane) -> None:
        """The flag alert describes the flag the lane waits on now, and how many more wait."""
        pending = lane.pending
        if pending is None or pending.kind not in FLAG_PENDING:
            self._clear(lane, AlertKind.FLAG)  # 'a' would approve something else
            return
        more = sum(1 for p in lane.waiting if p.kind in FLAG_PENDING)
        if pending.kind is PendingKind.CONFIRM:
            reason = f"Submit {pending.flag} on the platform yourself, then say if it was accepted."
            answers = (Suggestion("a", "Accepted"), Suggestion("d", "Rejected"))
        else:
            reason = f"Candidate {pending.flag} matches the flag format."
            variant = self.variant_of(lane.challenge_id, pending.flag or "")
            if variant is not None:
                reason += f" It is flightdeck's variant of {variant[0]}, which the platform rejected ({variant[1]})."
            tries = _tries_text(self.challenges[lane.challenge_id])
            if tries:
                reason += f" The platform counts the tries at this challenge's flag: {tries}."
            answers = (Suggestion("a", "Approve submit"), Suggestion("d", "Decline: do not submit"))
        if more:
            reason += f" {more} more candidate{'s wait' if more > 1 else ' waits'} behind it."
        self._raise(lane, Alert(AlertKind.FLAG, reason, answers))

    def _candidate(self, lane: Lane, flag: str, *, claimed: bool = True) -> None:
        if not self._flag_re.fullmatch(flag):
            self._note(lane, f"candidate {flag} does not match the flag format; not submitted")
            return
        why = self.not_flag(lane.challenge_id, flag)
        if why is not None:  # asked before and answered: never asked, or submitted, again
            self._note(lane, f"candidate {flag} again; not asked: {why}")
            self._tell_not_flag(lane, flag, why)
            return
        self._note(lane, f"candidate flag {flag}")
        ch = self.challenges[lane.challenge_id]
        if ch.rotates:
            self._claimed[(ch.id, flag)] = self.wall()  # claimed (again) now: the window it must go out in
        queued = ([lane.pending] if lane.pending else []) + lane.waiting
        if any(p.flag == flag for p in queued):
            return  # already waiting
        if self._on_its_way(lane, flag):
            return
        if self.config.submit == "auto" and claimed and (late := self.rotated(ch.id, flag)):
            self._rotated_out([lane], ch, flag, late)  # too close to its window's end: it would die on the way
            return
        if self.config.submit == "auto" and claimed and self.submitter is None:
            self._submit(lane, flag)  # an answers file checks it, or the player submits it by hand: no try is spent
            return
        if self.config.submit == "auto" and claimed and not self.config.holds(ch):
            wrong = self.wrong_flags(ch.id)
            solved = self._accepted.get(flag)
            if solved is not None and solved != ch.id:
                # the flag of another challenge (a series sibling's files hold it, say): it is
                # almost never this one's too, and a wrong try costs, so the player decides
                other = self.challenges.get(solved)
                self._note(lane, f"{flag} is the flag that solved {other.name if other is not None else solved}, so it waits for you here")
            elif self.config.wrong_stop and wrong >= self.config.wrong_stop:
                # the wrong-answer stop: a lane that keeps guessing is not left to spray the platform
                self._note(lane, f"{wrong} flags were wrong at {ch.name}, so {flag} waits for you (wrong_stop {self.config.wrong_stop})")
            elif not self._keeps_last_try(ch):
                self._send(lane, flag)
                return
            else:
                self._last_try_waits(lane, ch, flag)  # autopilot's guard: it waits for the player, as below
        # under auto, a match scraped from text the lane read (a decoy flag.txt, an example
        # in a comment) waits for the player: a wrong try can cost a CTFd attempt. So does
        # every flag of a challenge whose tries the platform counts: flightdeck never spends
        # one of them on its own.
        self._ask(lane, Pending(PendingKind.SUBMIT, self._detail(ch, flag), flag=flag))

    def _submit(self, lane: Lane, flag: str, *, approved: bool = False) -> bool | None:
        """Submit through the board. None: the board cannot check flags, so the player
        submits by hand and confirms (the flag's approval becomes a confirmation).
        `approved`: it goes on the player's yes (else on its own, under auto)."""
        ch = self.challenges[lane.challenge_id]
        ok = self.verify(ch.id, flag)
        if ok is None:
            confirm = Pending(PendingKind.CONFIRM, f"did the platform accept {flag}? (you submit it)" + self._variant_text(ch.id, flag), flag=flag)
            if lane.pending is not None and lane.pending.flag == flag:
                lane.pending = replace(confirm, at=self.now)
                self._became_current(lane)
            else:
                self._ask(lane, confirm)
            return None
        self._verdict(lane, flag, ok, by="platform", approved=approved)
        return ok

    def _verdict(
        self, lane: Lane, flag: str, ok: bool, *, by: str, data: dict[str, object] | None = None,
        approved: bool = False, also: Sequence[Lane] = (),
    ) -> None:
        """A flag was right or wrong (the platform said, or the player for a hand submit). The
        lane may have ended before the platform's answer came: a right flag still solves the
        challenge, credited to it, and a wrong one is still known wrong. `data`: more for the
        submit event (the platform's words, the tries it said are left). A flag the deck
        proposed as a variant says so in the event (`variant_of`, `variant_changes`). After
        the platform's wrong, the next variant may be proposed (_variant): `approved` says the
        flag went out on the player's yes, `also` names the other lanes that sent it."""
        ch = self.challenges[lane.challenge_id]
        self._note(lane, f"submitted {flag}: {'correct' if ok else 'incorrect'}" + (" (you said so)" if by == "player" else ""))
        self._emit(
            EventKind.SUBMIT,
            f"{lane.id} submitted {flag} for {ch.name}: {'correct' if ok else 'incorrect'}",
            lane.id,
            ch.id,
            data={"flag": flag, "correct": ok, "by": by, **self._variant_data(ch.id, flag), **(data or {})},
        )
        if not ok:
            self._remember_not_flag(ch.id, flag, REJECTED if by == "platform" else SAID_REJECTED)
            if not lane.finished:
                if lane.pending is not None and lane.pending.flag == flag:
                    self._resolve(lane)
                else:
                    self._sync_flag_alert(lane)
                self.driver.rejected(lane, flag)
            self._drop_known_wrong(lane, flag)
            if by == "platform":  # before the lane ends for having given up: a variant of its flag keeps it open
                self._variant(ch, flag, [lane, *also], approved=approved)
            self._end_if_gave_up(lane)
            return
        self._accepted.setdefault(flag, ch.id)
        ch.status = ChallengeStatus.SOLVED
        ch.solved_by = lane.id
        ch.solves += 1
        ch.note = ""
        self._drop_queued(ch.id)
        if not lane.finished:
            self._finish(lane, LaneState.SOLVED, f"solved with {flag}")
        for other in self.lanes_on(ch.id):
            self._finish(other, LaneState.STOPPED, f"{lane.id} solved it")

    # ------------------------------------------------------------------ flags to a platform over the network

    def _send(self, lane: Lane, flag: str, *, approved: Pending | None = None) -> Outcome:
        """`flag` goes to the platform through the submitter, without waiting for the answer
        (platform_verdict() brings it): at once, or once the answer to the flag on its way
        for the same challenge is in. `approved`: the lane's approval the player just gave
        for it, answered here; the lane carries on meanwhile."""
        ch = self.challenges[lane.challenge_id]
        if approved is not None:
            self._resolve(lane)
            self.driver.approved(lane, approved)
        item = self._on_its_way(lane, flag)
        if item is not None:
            item.approved = item.approved or approved is not None  # the player's yes holds for it now
            return Outcome(True, f"{flag} is already on its way to the platform for {ch.name}")
        line = self._lines.setdefault(ch.id, [])
        line.append(_ToPlatform(flag, [lane.id], approved=approved is not None))
        if len(line) > 1:
            first = line[0]
            self._note(lane, f"waits its turn to go to the platform: {flag} (after {first.flag}, from {first.lane}: "
                             "one flag at a time per challenge)")
            return Outcome(True, f"{flag} goes to the platform once the answer to {first.flag} is in "
                                 f"(one flag at a time on {ch.name})")
        if not self._hand_over(ch):
            return Outcome(True, f"{flag} could not go to the platform: submit it by hand, then say if it was accepted")
        return Outcome(True, f"Submitting {flag} for {ch.name}; the platform's answer comes back on its own")

    def _on_its_way(self, lane: Lane, flag: str) -> _ToPlatform | None:
        """`flag` on its way to the platform for the lane's challenge already (sent, or waiting
        its turn), else None: then the lane hears its answer too, and nothing is sent again."""
        item = next((item for item in self._lines.get(lane.challenge_id, ()) if item.flag == flag), None)
        if item is not None and lane.id not in item.lanes:
            item.lanes.append(lane.id)
            self._note(lane, f"already on its way to the platform, from {item.lane}: {flag}")
        return item

    def _hand_over(self, ch: Challenge) -> bool:
        """The first flag in the challenge's line goes to the submitter. False if the
        submitter failed (a flightdeck bug, said as a warning): the player submits it by hand."""
        assert self.submitter is not None
        item = self._lines[ch.id][0]
        item.sent = True
        lane = self.lanes[item.lane]
        self._note(lane, f"sending {item.flag} to the platform; its answer comes back on its own")
        try:
            self.submitter(lane.id, ch.id, item.flag)
        except Exception as exc:  # it only queues the flag, so this is a bug: said, and the flag is not lost
            problem = f"{type(exc).__name__}: {exc}"
            self._emit(EventKind.WARNING, f"could not hand {item.flag} to the platform: {problem}", lane.id, ch.id,
                       data={"error": problem})
            self.platform_verdict(lane.id, item.flag, None, f"flightdeck could not hand it to the platform ({problem})")
            return False
        return True

    def _no_verdict(self, item: _ToPlatform, ch: Challenge, detail: str) -> None:
        """The platform did not judge a flag, or its answer is not known: the player submits it
        by hand and says how it went (a CONFIRM approval), on the lanes that sent it as
        _back_to_player says. With none open, a warning says so."""
        lanes = [self.lanes[lane_id] for lane_id in item.lanes]
        for lane in lanes:
            self._note(lane, f"no verdict from the platform on {item.flag}: {detail or 'no reason given'}")
        confirm = Pending(PendingKind.CONFIRM, f"did the platform accept {item.flag}? (you submit it)" + self._variant_text(ch.id, item.flag),
                          flag=item.flag)
        holders, others = self._back_to_player(item, confirm)
        for lane in others:
            self._end_if_gave_up(lane)
        if not holders:
            self._emit(
                EventKind.WARNING,
                f"no verdict from the platform on {item.flag} for {ch.name}, and {', '.join(item.lanes)} has ended: "
                "submit it by hand if you think it is the flag",
                challenge=ch.id,
                data={"flag": item.flag, "lanes": list(item.lanes)},
            )

    def _back_to_player(self, item: _ToPlatform, pending: Pending, why: str = "") -> tuple[list[Lane], list[Lane]]:
        """`item`'s flag, on its way to the platform no more, waits for the player as `pending`:
        on each lane that sent it and is still at work, as each would hold it had it never been
        on its way, so each hears what becomes of it. A lane that sent it and gave up does not
        hold it (the caller ends it, unless something else of it still waits); when every lane
        that sent it gave up, the first one still open holds it. `why`: why it did not go to
        the platform. Returns the lanes it waits on (none when they have all ended), and the
        others still open."""
        lanes = [self.lanes[lane_id] for lane_id in item.lanes if not self.lanes[lane_id].finished]
        holders = [lane for lane in lanes if not lane.gave_up_later] or lanes[:1]
        for lane in holders:  # none holds it already: a lane that sent it was asked nothing for it (_candidate)
            if why:
                self._note(lane, f"back to you: {item.flag} did not go to the platform ({why})")
            self._ask(lane, pending)
        ids = ", ".join(lane.id for lane in holders)
        others = [lane for lane in lanes if lane not in holders]
        for lane in others:
            self._note(lane, f"{item.flag} waits for you on {ids}" + (f": it did not go to the platform ({why})" if why else ""))
        return holders, others

    def _next_to_platform(self, ch: Challenge, ok: bool | None) -> None:
        """After an answer, the next flag waiting its turn on `ch` goes out. A flag known not to
        be the flag by now never goes out, and its lanes hear why; on a solved challenge none
        does. The player decides instead, each flag going back as an approval
        (_back_to_player): after no verdict (the platform may not judge it either), and once
        the platform counts the tries, a flag the player has not said yes to (flightdeck never
        spends a try on its own) or one whose turn would spend the last try."""
        line = self._lines.get(ch.id)
        if not line:
            return
        if ch.closed or ch.id in self._spent:  # solved, or out of tries: no flag of it goes out any more
            del self._lines[ch.id]
            return
        last = ch.tries_left is not None and ch.tries_left <= 1
        keep: list[_ToPlatform] = []
        wrong: list[tuple[_ToPlatform, str]] = []
        back: list[tuple[_ToPlatform, str]] = []
        for item in line:
            if (known := self.not_flag(ch.id, item.flag)) is not None:
                wrong.append((item, known))
            elif ok is None:
                back.append((item, "the platform gave no verdict on the flag before it"))
            elif self.config.holds(ch) and not item.approved:
                back.append((item, "the platform counts the tries at this challenge's flag"))
            elif last and self.config.holds(ch):
                back.append((item, f"the platform now says {_tries_text(ch)}"))
            elif self._keeps_last_try(ch):  # autopilot's guard: not on its own, and not on a yes given while more were left
                self._last_try_waits(self.lanes[item.lane], ch, item.flag)
                back.append((item, f"autopilot never spends a challenge's last try, and the platform says {_tries_text(ch)}"))
            else:
                keep.append(item)
        if keep:  # the line is as it stays before any lane hears: a lane's flags still in it keep it open
            self._lines[ch.id] = keep
        else:
            del self._lines[ch.id]
        ending: list[Lane] = []  # lanes that gave up end only once every flag here is placed: one may hold a later one
        for item, known in wrong:
            for lane in (self.lanes[i] for i in item.lanes):
                if not lane.finished:
                    self._note(lane, f"not sent to the platform: {item.flag} ({known})")
                    self._tell_not_flag(lane, item.flag, known)
                    ending.append(lane)
        for item, why in back:
            ending += self._back_to_player(item, Pending(PendingKind.SUBMIT, self._detail(ch, item.flag), flag=item.flag), why)[1]
        for lane in ending:
            self._end_if_gave_up(lane)
        while (line := self._lines.get(ch.id)) and not line[0].sent:
            item = line[0]
            late = self.rotated(ch.id, item.flag)
            if not late:
                self._hand_over(ch)
                break
            line.remove(item)  # it rotated out while it stood in line: the one behind it has its turn
            if not line:
                del self._lines[ch.id]
            self._rotated_out([self.lanes[i] for i in item.lanes], ch, item.flag, late)

    def platform_rotated(self, lane_id: str, flag: str) -> None:
        """The submitter did not send a flag it took for `lane_id` (the one on its way now):
        the flag rotated out while it waited there (behind other challenges' flags, or for a
        rate limit to pass: `rotated` said so when asked). As when it rotates out in the
        deck: its lanes are told to fetch a fresh one, nothing is recorded as wrong, and the
        challenge's next flag has its turn."""
        self._on_thread("platform_rotated")
        lane = self.lanes[lane_id]
        ch = self.challenges[lane.challenge_id]
        line = self._lines.get(ch.id, [])
        if not line or not line[0].sent or line[0].lane != lane_id or line[0].flag != flag:
            raise ValueError(f"no flag of {lane_id} is on its way to the platform as {flag!r}")
        late = self.rotated(ch.id, flag)
        if not late:
            raise ValueError(f"{flag!r} has not rotated out: it is still to be sent for {lane_id}")
        sent = line.pop(0)
        if not line:
            del self._lines[ch.id]
        self._rotated_out([self.lanes[i] for i in sent.lanes], ch, flag, late)
        self._next_to_platform(ch, False)  # judged or not, the platform is answering: the next flag goes as after a verdict

    def _rotated_out(self, lanes: Sequence[Lane], ch: Challenge, flag: str, why: str) -> None:
        """`flag` of a rotating challenge does not go out (`why`: rotated): each open lane of
        `lanes` is told to fetch and submit a fresh one, a warning says so, and nothing is
        remembered as wrong. A lane that had given up and waited only for this flag ends."""
        self._claimed.pop((ch.id, flag), None)
        told = [lane for lane in lanes if not lane.finished]
        for lane in told:
            self._note(lane, f"not sent: {flag} rotated out ({why}); told to fetch a fresh flag and submit that")
            self.driver.rotated(lane, flag, ch.rotates)
        who = f"; {', '.join(lane.id for lane in told)} was told to fetch a fresh one" if told else ""
        self._emit(
            EventKind.WARNING,
            f"not sent: {flag} for {ch.name} rotated out ({why}){who}. Nothing is counted as wrong",
            lanes[0].id if lanes else None, ch.id,
            data={"rotated_out": True, "flag": flag, "rotates": ch.rotates, "lanes": [lane.id for lane in lanes]},
        )
        for lane in told:
            self._end_if_gave_up(lane)

    def _keeps_last_try(self, ch: Challenge) -> bool:
        """Autopilot guards the run, and a flag for `ch` would spend the last try the platform
        counts at it: the count is 1 or less (D20: autopilot never spends a challenge's last
        try, whatever submit_limited says). A count the platform has not given is not taken for
        the last try (P21, the maintainer's call). False for a challenge whose tries the platform
        does not count, and whenever autopilot does not guard the run."""
        pilot = self.autopilot
        if pilot is None or not pilot.guarding or not ch.limited:
            return False
        return ch.tries_left is not None and ch.tries_left <= 1

    def _last_try_waits(self, lane: Lane, ch: Challenge, flag: str) -> None:
        """Say, once per flag, that autopilot's last-try rule keeps `flag` for the player: a
        note on the lane and a warning for the run (its data: autopilot "last_try"), which the
        post-flight report lists. The caller makes it wait as an approval, which raises the
        lane's flag alert; the run goes on."""
        if (ch.id, flag) in self._kept:
            return
        self._kept.add((ch.id, flag))
        tries = _tries_text(ch)
        self._note(lane, f"not sent on its own: {flag} ({tries}; autopilot never spends a challenge's last try)")
        self._emit(
            EventKind.WARNING,
            f"autopilot never spends a challenge's last try: {flag} for {ch.name} waits for you on {lane.id} ({tries})",
            lane.id, ch.id, data={"autopilot": "last_try", "flag": flag, "tries_left": ch.tries_left},
        )

    # ------------------------------------------------------------------ flag variants

    def _variant(self, ch: Challenge, flag: str, lanes: Sequence[Lane], *, approved: bool) -> None:
        """The platform judged `flag` wrong at `ch` (never the player's word): propose the next
        variant, if DeckConfig.variant_tries allows one. `lanes`: the lanes that sent `flag`,
        the first sender first. `approved`: `flag` went out on the player's yes.

        Nothing is proposed: with variant_tries 0; once the run is closing; on a challenge
        that is solved or out of tries; once `variant_tries` variants were proposed at the
        challenge in this run (a proposed one counts, sent or not); while a variant the deck
        proposed at the challenge still waits for the player or for the platform's answer
        (one at a time).

        Which one: the first variant, in rank order (flagvariants.variants), of the flag the
        chain is about: `flag`, or when `flag` is itself a variant the flag it came from, so a
        list is carried on and a variant never gets variants of its own. When that list is
        used up, the lists of the challenge's other rejected flags, the newest first. A
        variant known not to be the flag (rejected or declined, by any lane), one that waits
        for the player on a lane of the challenge and one on its way to the platform are
        passed over: so a variant two flags share, or one a lane claimed itself, is never
        proposed twice.

        Where: on the first of `lanes` still open (one that gave up and only waits for its
        flag's answer is: the variant keeps it open as its own flag would). With none open
        nothing is proposed, since nothing of an ended lane goes to the platform, and a
        warning names the variant so the player can submit it by hand.

        How: as a candidate through _candidate, so every rule on a lane's own flag holds: the
        submit policy, counted tries, the wrong-answer stop, autopilot's last-try guard, one
        flag at a time per challenge. It goes as a flag the lane claims, except that it waits
        for the player when `flag` went out on the player's yes (what needed a yes is not
        followed by a send without one) and when the challenge's description holds it (a
        planted flag waits, as agent/driver.py has it for a lane's own)."""
        tries = self.config.variant_tries
        if not tries or self.closing or ch.closed or ch.id in self._spent or ch.tries_left == 0:
            return
        proposed = self._variants.setdefault(ch.id, {})
        root = proposed[flag].of if flag in proposed else flag
        roots = self._variant_roots.setdefault(ch.id, [])
        if root in roots:
            roots.remove(root)
        roots.append(root)
        count = self._variant_count.get(ch.id, 0)
        if count >= tries or any(self._flag_open(ch, each) for each in proposed):
            return
        pick = next(
            ((of, variant) for of in reversed(roots) for variant in self._ranked_variants(of)
             if self.not_flag(ch.id, variant.value) is None and not self._flag_open(ch, variant.value)),
            None,
        )
        if pick is None:
            return
        of, variant = pick
        lane = next((each for each in lanes if not each.finished), None)
        if lane is None:
            ids = ", ".join(each.id for each in lanes)
            self._emit(
                EventKind.WARNING,
                f"{flag} was wrong for {ch.name}, and no variant is tried: {ids} has ended. The next one would be "
                f"{variant.value} ({variant.what}): submit it by hand if you think it is the flag",
                challenge=ch.id,
                data={"variant": variant.value, "variant_of": of, "variant_changes": list(variant.changes),
                      "lanes": [each.id for each in lanes]},
            )
            return
        proposed[variant.value] = _VariantOf(of, variant.changes, variant.what)
        self._variant_count[ch.id] = count + 1
        waits = ""
        if self.config.submit == "auto":
            if approved:
                waits = f"; it waits for you, as {flag} went out on your yes"
            elif variant.value in ch.description:
                waits = "; it waits for you: the challenge's description holds it"
        self._note(lane, f"variant {count + 1} of {tries} at {ch.name}: trying {variant.value}, a variant of {of}, which the "
                         f"platform rejected ({variant.what}){waits}")
        self._candidate(lane, variant.value, claimed=not waits)

    def _ranked_variants(self, flag: str) -> tuple[flagvariants.Variant, ...]:
        """The ranked variants of a rejected flag under the run's flag format, worked out once."""
        if flag not in self._ranked:
            self._ranked[flag] = flagvariants.variants(flag, self.config.flag_format)
        return self._ranked[flag]

    def _flag_open(self, ch: Challenge, flag: str) -> bool:
        """`flag` waits for the player on a lane of `ch`, or is on its way to the platform for it."""
        if any(item.flag == flag for item in self._lines.get(ch.id, ())):
            return True
        return any(
            pending.kind in FLAG_PENDING and pending.flag == flag
            for lane in self.lanes_on(ch.id) for pending in [lane.pending, *lane.waiting] if pending is not None
        )

    def _variant_text(self, challenge_id: str, flag: str) -> str:
        """What an approval adds for a flag the deck proposed as a variant; "" for any other."""
        variant = self._variants.get(challenge_id, {}).get(flag)
        return f"; flightdeck's variant of {variant.of}, which the platform rejected: {variant.what}" if variant is not None else ""

    def _variant_data(self, challenge_id: str, flag: str) -> dict[str, object]:
        """What an event adds for a flag the deck proposed as a variant; nothing for any other."""
        variant = self._variants.get(challenge_id, {}).get(flag)
        return {"variant_of": variant.of, "variant_changes": list(variant.changes)} if variant is not None else {}

    def _detail(self, ch: Challenge, flag: str) -> str:
        """What a flag's approval says: the flag, the tries left when they are counted, and for
        a variant the deck proposed, of which flag and what changed."""
        return _submit_detail(ch, flag) + self._variant_text(ch.id, flag)

    def _leave_line(self, lane: Lane) -> None:
        """An ended lane's flags still waiting their turn for the platform do not go out (one
        another lane sent too still does); the one already sent is answered all the same."""
        line = self._lines.get(lane.challenge_id)
        if not line:
            return
        for item in list(line):
            if item.sent or lane.id not in item.lanes:
                continue
            item.lanes.remove(lane.id)
            if not item.lanes:
                line.remove(item)
                self._note(lane, f"not submitted: {item.flag} (it was waiting its turn to go to the platform)")
        if not line:
            del self._lines[lane.challenge_id]

    def _guarded(self) -> bool:
        """Whether autopilot guards the run (its last-try rule holds)."""
        return self.autopilot is not None and bool(self.autopilot.guarding)

    def _tries(self, ch: Challenge, left: int) -> None:
        """The platform said how many tries are left on `ch`: its flags wait for the player from
        now on (Challenge.limited), and every approval waiting for one says how many. Under
        auto, the first time, a warning says that its flags no longer go out on their own
        (none for a challenge solved meanwhile: no flag of it goes out any more anyway; none
        at 0 either: the challenge is out of tries, which _out_of_tries says)."""
        counted = ch.limited
        ch.tries_left = max(0, left)
        if not counted and self.config.submit == "auto" and not ch.closed and ch.tries_left:
            what = ("its flags still go out without you (submit_limited auto)" if self.config.spends_tries
                    else "from now on its flags wait for you, under submit auto too")
            self._emit(EventKind.WARNING, f"the platform counts the tries at the flag of {ch.name} ({_tries_text(ch)}): {what}",
                       challenge=ch.id, data={"tries_left": ch.tries_left})
        for lane in self.lanes_on(ch.id):
            for pending in [lane.pending, *lane.waiting]:
                if pending is not None and pending.kind is PendingKind.SUBMIT and pending.flag is not None:
                    pending.detail = self._detail(ch, pending.flag)
            self._sync_flag_alert(lane)

    def _out_of_tries(self, ch: Challenge, *, flag: str | None = None, detail: str = "", before_run: bool = False) -> None:
        """No tries are left at `ch`'s flag, so the platform checks no more flags for it: it is
        out of tries, blocked with a note that says so, until the platform says tries are left
        again (_tries_back). It leaves the queue, each
        lane on it stops, saying why (a flag of it waiting for the player is never submitted,
        and the lane's transcript says so), none of its flags waiting their turn goes out (one
        already sent is answered all the same), and one warning tells the player. `flag`: a
        flag the platform did not check for want of tries, with why (`detail`): the warning
        says it is not known to be wrong. Once while it lasts: a flag left unchecked later is a
        warning of its own. `before_run`: the platform said so before the run started."""
        unchecked = ""
        if flag is not None:
            unchecked = f"{flag} is not known to be wrong: {detail}" if detail else f"{flag} was not checked: it is not known to be wrong"
        data: dict[str, object] = {"out_of_tries": True, "tries_left": 0}
        if flag is not None:
            data.update(flag=flag, checked=False)
        if ch.id in self._spent:
            if unchecked:
                self._emit(EventKind.WARNING, f"{ch.name} is out of tries: {unchecked}", challenge=ch.id, data=data)
            return
        self._spent.add(ch.id)
        self._drop_queued(ch.id)
        why = f"{ch.name} is {OUT_OF_TRIES}"
        stopped = []
        for lane in self.lanes_on(ch.id):
            for pending in [lane.pending, *lane.waiting]:
                if pending is not None and pending.kind in FLAG_PENDING and pending.flag is not None:
                    self._note(lane, f"not submitted: {pending.flag} ({why})")
            self._finish(lane, LaneState.STOPPED, why, then=ChallengeStatus.BLOCKED)
            stopped.append(lane.id)
        ch.status = ChallengeStatus.BLOCKED
        ch.note = OUT_OF_TRIES
        line = self._lines.get(ch.id)
        if line:  # what waited its turn goes nowhere: only a flag already sent is still answered
            self._lines[ch.id] = [item for item in line if item.sent]
            if not self._lines[ch.id]:
                del self._lines[ch.id]
        text = f"{why}, so flightdeck closed it" + (f" and stopped {', '.join(stopped)}" if stopped else "")
        if before_run:
            text += " (the platform said so before the run started)"
        self._emit(EventKind.WARNING, text + (f". {unchecked}" if unchecked else ""), challenge=ch.id,
                   data={**data, "stopped": stopped, "before_run": before_run})

    def _tries_back(self, ch: Challenge) -> None:
        """The platform says tries are left at the flag of `ch`, which was out of tries (CTFd's
        timeout behaviour gives them back after a wait; its admin may raise the limit or clear
        the tries): it is open again, parked, as after a lane's end, for the player to queue,
        and a warning says so. Its flags wait for the player, as a counted challenge's do."""
        self._spent.discard(ch.id)
        ch.status = ChallengeStatus.PARKED
        ch.note = f"out of tries no more: the platform says {_tries_text(ch)}"
        self._emit(EventKind.WARNING, f"{ch.name} is out of tries no more: the platform now says {_tries_text(ch)}, so "
                                      "flightdeck opened it again; queue it to work it",
                   challenge=ch.id, data={"out_of_tries": False, "tries_left": ch.tries_left})

    def _end_if_gave_up(self, lane: Lane) -> bool:
        """A lane whose driver gave up while a flag waited ends once no flag waits (nothing
        drives it any more). True if it ended."""
        if lane.gave_up_later and not lane.finished and not self._has_submit(lane):
            self._finish(lane, LaneState.GAVE_UP, lane.gave_up_later, then=ChallengeStatus.PARKED)
            return True
        return False

    def _remember_not_flag(self, challenge_id: str, flag: str, why: str) -> None:
        """`flag` is not the flag of that challenge. A weaker reason never replaces a stronger
        one (the platform's rejection is the strongest)."""
        known = self._not_flags.setdefault(challenge_id, {})
        old = known.get(flag)
        if old is None or NOT_FLAG_RANK[why] > NOT_FLAG_RANK.get(old, 0):
            known[flag] = why

    def _tell_not_flag(self, lane: Lane, flag: str, why: str) -> None:
        if why == DECLINED:
            self.driver.declined(lane, Pending(PendingKind.SUBMIT, f"submit {flag}", flag=flag))
        else:
            self.driver.rejected(lane, flag)

    def _drop_known_wrong(self, lane: Lane, flag: str) -> None:
        """`flag` just became known not to be the flag: the same flag waiting for approval on
        the challenge's other lanes is dropped (approving it would submit it again), and those
        lanes hear why."""
        why = self.not_flag(lane.challenge_id, flag)
        assert why is not None
        for other in self.lanes_on(lane.challenge_id):
            if other is lane or other.finished:
                continue
            same = lambda p: p.kind in FLAG_PENDING and p.flag == flag  # noqa: E731
            dropped = False
            before = len(other.waiting)
            other.waiting = [p for p in other.waiting if not same(p)]
            dropped = len(other.waiting) != before
            if other.pending is not None and same(other.pending):
                self._resolve(other)
                dropped = True
            elif dropped:
                self._sync_flag_alert(other)
            if dropped:
                self._note(other, f"candidate {flag} dropped: {why} on {lane.id}")
                self._tell_not_flag(other, flag, why)
                self._end_if_gave_up(other)

    def _check_budget(self, lane: Lane) -> None:
        used = lane.budget_used()
        if used is None or used < BUDGET_WARN:
            return
        cap = self._cap_text(lane)
        if used >= 1.0:
            self._raise(
                lane,
                Alert(
                    AlertKind.BUDGET,
                    f"At {used:.0%} of its cap ({cap}); it waits for approval before spending more.",
                    (Suggestion("a", "Approve 50% more budget"), Suggestion("k", "Kill the lane")),
                ),
            )
            if not any(p.kind is PendingKind.BUDGET for p in ([lane.pending] if lane.pending else []) + lane.waiting):
                self._ask(lane, Pending(PendingKind.BUDGET, f"raise the cap by 50% (now {cap})"))
        else:  # raising again keeps the first time and refreshes the numbers
            self._raise(
                lane,
                Alert(
                    AlertKind.BUDGET,
                    f"At {used:.0%} of its cap ({cap}).",
                    (
                        Suggestion("a", "Approve 50% more budget now"),
                        Suggestion("e", "Escalate to a stronger model"),
                        Suggestion("k", "Kill the lane"),
                    ),
                ),
            )

    def _spend(self, lane: Lane, rep: TurnReport) -> None:
        """Count what a report spent, on the lane and so on the run (totals()), and log what
        was spent outside a turn as a SPEND event, with the model that spent it and why. A
        lane that has ended, or any lane once the run is closing, counts it all the same and
        asks for nothing: no cap is left to enforce. A coding-agent CLI's step (dollars_later)
        leaves the lane's dollars unsettled until the CLI reports what the turn cost
        (turn_end), which is logged as a SPEND event marked turn_end: the CLI's own cost of its
        turn, not spend outside a turn. A turn whose cost never came (unreported: the CLI was
        stopped in it, or exited) leaves the lane's total not known, but no price is missing
        for it: nothing is asked, and a dollar cap holds on what is known (Lane.budget_used).
        So does a light model's first look with no known cost (light: agent/facts.py), said
        once on the lane: a first look never holds up a lane, and its few calls must not lift
        the cap off the lane's own model. Other spend with no price asks once (P7)."""
        capped = bool(lane.dollar_cap) and not lane.finished and not self.closing  # a dollar cap still to enforce
        due = lane.dollars_later  # a turn_end that settles it is logged even when it adds nothing: the log says so too
        lane.tokens += rep.tokens
        lane.cached_tokens += rep.cached_tokens
        if rep.dollars_later:
            lane.dollars_later = True
        elif rep.dollars is None:
            lane.unpriced += 1
            if rep.unreported:
                lane.unreported += 1
                if capped and lane.unreported == 1:
                    self._note(lane, f"the cost of a turn of {rep.model or lane.model} never came (its CLI did not report "
                                     f"it): the ${fmt.dollars(lane.dollar_cap)} cap holds on the "
                                     f"${fmt.dollars(lane.known_dollars)} that is known")
            elif rep.light:
                lane.light_unpriced += 1
                if capped and lane.light_unpriced == 1:
                    self._note(lane, f"{rep.why or 'a light model spent something that'} has no known cost: the "
                                     f"${fmt.dollars(lane.dollar_cap)} cap holds on the ${fmt.dollars(lane.known_dollars)} "
                                     "that is known (a light model's first look never holds up a lane)")
            elif capped and lane.unpriced - lane.unreported - lane.light_unpriced == 1:
                self._unpriced(lane, rep)  # the first spend with no price: the cap cannot be enforced any more
            lane.dollars = None
        else:
            lane.known_dollars += rep.dollars
            if lane.dollars is not None:
                lane.dollars += rep.dollars
        if rep.turn_end:
            lane.dollars_later = False
        dollars = None if rep.dollars_later else rep.dollars
        spent = rep.tokens or rep.cached_tokens or (not rep.dollars_later and dollars != 0.0)
        if rep.turn or not (spent or (rep.turn_end and due)):
            return
        data: dict[str, object] = {"tokens": rep.tokens, "cached_tokens": rep.cached_tokens, "dollars": dollars,
                                   "model": rep.model or lane.model, "why": rep.why}
        if rep.turn_end:
            data["turn_end"] = True
        if rep.unreported:
            data["unreported"] = True
        where = "in a turn of its CLI" if rep.turn_end else "outside a turn"  # a turn_end's why says when it was reported
        self._emit(EventKind.SPEND, f"{lane.id} spent {rep.tokens} tokens {where}" + (f": {rep.why}" if rep.why else ""),
                   lane.id, lane.challenge_id, data=data)

    def _unpriced(self, lane: Lane, rep: TurnReport) -> None:
        """A dollar-capped lane just spent something with no price: the cap can no longer be
        enforced. Said of the model that spent it (an escalated lane's old model, say), a
        coding-agent CLI's model too: its report of a turn with no cost, and no price for it
        in the config. (A turn whose cost the CLI never reported asks nothing: _spend.)"""
        why = f"no price for {rep.model or lane.model}"
        self._raise(
            lane,
            Alert(
                AlertKind.BUDGET,
                f"{why[0].upper()}{why[1:]}, so the ${fmt.dollars(lane.dollar_cap)} cap cannot be "
                "enforced; it waits for approval to carry on without it.",
                (Suggestion("a", "Carry on without the dollar cap"), Suggestion("k", "Kill the lane")),
            ),
        )
        if not any(p.kind is PendingKind.BUDGET for p in ([lane.pending] if lane.pending else []) + lane.waiting):
            self._ask(lane, Pending(PendingKind.BUDGET, f"carry on with no dollar cap ({why})"))

    def _raise_caps(self, lane: Lane) -> None:
        if lane.token_cap:
            lane.token_cap = int(lane.token_cap * BUDGET_RAISE)
        if lane.dollar_cap:
            lane.dollar_cap = lane.dollar_cap * BUDGET_RAISE

    def _cap_text(self, lane: Lane) -> str:
        parts = []
        if lane.token_cap:
            parts.append(f"{fmt.tokens(lane.tokens)} of {fmt.tokens(lane.token_cap)} tokens")
        if lane.dollar_cap:
            spent = fmt.dollars(lane.dollars) if lane.dollars is not None else f"{fmt.dollars(lane.known_dollars)}+"  # what is known
            parts.append(f"${spent} of ${fmt.dollars(lane.dollar_cap)}")
        return ", ".join(parts) or "no cap"

    def _stronger(self, lane: Lane) -> tuple[str | None, str]:
        ladder = self.config.models
        if not ladder:
            return None, "No model ladder is configured (DeckConfig.models is empty)"
        if lane.model not in ladder:
            return None, f"{lane.id} runs {lane.model!r}, which is not in the model ladder ({', '.join(ladder)})"
        i = ladder.index(lane.model)
        if i + 1 >= len(ladder):
            return None, f"{lane.id} is already on the strongest model ({lane.model})"
        return ladder[i + 1], ""

    def _note(self, lane: Lane, text: str, by: Actor = Actor.DECK, kind: ActionKind | None = None) -> None:
        if kind is None:
            kind = ActionKind.PLAYER if by in ACTORS else ActionKind.NOTE  # an intervention's own line: the player's, or autopilot's
        lane.actions.append(Action(self.now, lane.turns, text, "", by, kind))

    def _emit(
        self,
        kind: EventKind,
        text: str,
        lane: str | None = None,
        challenge: str | None = None,
        alert: AlertKind | None = None,
        data: dict[str, object] | None = None,
    ) -> None:
        event = Event(self.now, kind, text, lane, challenge, alert, data or {})
        self.events.append(event)
        for listener in list(self._listeners):
            try:
                listener(event)
            except Exception as exc:  # a listener that fails (the run log on a full disk) must not break
                self._listener_failed(listener, exc)  # the deck, or the lane whose report this was

    def _listener_failed(self, listener: Callable[[Event], None], exc: Exception) -> None:
        name = getattr(listener, "__qualname__", type(listener).__name__)
        problem = f"{name}: {type(exc).__name__}: {exc}"
        self.listener_errors.append(problem)
        if self._warning_listener_failure:  # the warning itself failed in a listener: never loop
            return
        self._warning_listener_failure = True
        try:
            self._emit(EventKind.WARNING, f"something that follows the run failed and missed events: {problem}",
                       data={"listener": name})
        finally:
            self._warning_listener_failure = False


def summary_lines(summary: EscalationSummary) -> list[str]:
    """The summary as display lines. Untrusted fields are folded to one line each, so a
    newline in a challenge name or a command cannot forge a line of its own."""
    def one(value: str) -> str:
        return untrusted(value, one_line=True)

    return [
        f"Challenge: {one(summary.challenge)} ({one(summary.category)}, {summary.points} pts, "
        f"{summary.solves} solves); files: {one(', '.join(summary.files)) or 'none'}",
        f"Plan: {one(summary.plan) or '(none)'}",
        f"So far: {summary.turns} turns, {fmt.tokens(summary.tokens)} tokens on {one(summary.model)}",
        "Tried: " + ("; ".join(one(t) for t in summary.tried) or "nothing yet"),
        "Found: " + (", ".join(one(f) for f in summary.found) or "nothing yet"),
        "Alerts: " + ("; ".join(one(a) for a in summary.alerts) or "none"),
    ] + (["Not the flag: " + "; ".join(one(f) for f in summary.not_flags)] if summary.not_flags else [])
