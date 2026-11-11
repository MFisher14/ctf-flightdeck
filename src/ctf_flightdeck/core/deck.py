"""The deck: board, queue and lanes, plus the rules and interventions that change them.

The console reads the deck and sends it interventions. A LaneDriver does each lane's
work and reports back through Deck.report(). The deck has no loop and no I/O of its
own: the M0 mock drives it from a scripted clock, M1 from real lanes. Every change is
logged as an Event with a structured payload, so the M1 run log can be written from
the event stream alone.

Rules the deck enforces:
- at most `max_lanes` lanes are active (running, waiting, paused or taken over); the
  rest wait in the queue, which drains as lanes finish;
- a candidate flag must match the flag format; with submit policy "confirm" it waits
  for the player's approval, with "auto" it is submitted at once;
- a board's verifier answers at once (an answers file, or never: the player submits by
  hand); a platform over the network (CTFd) gets the flag through the submitter instead
  (core/driver.py), which only queues it: the lane carries on (sending() names its flags on
  their way), and the answer comes back through platform_verdict(). One flag at a time goes
  to the platform per challenge; another waits its turn;
- when that platform counts the tries at a challenge's flag (Challenge.limited: the board
  says so, or the platform did), a flag for it waits for the player under "auto" too, so
  flightdeck never spends one of those tries on its own; each approval says how many are
  left;
- approvals queue up per lane (a flag goes first) and none is ever dropped;
- a lane at 80% of a cap gets a budget alert, and at 100% it waits for approval;
- team mode: a challenge a teammate solved or claimed is not worked; a teammate's
  solve stops every lane on it.

Call the deck only from the thread that created it (see core/driver.py).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, replace

from .. import fmt
from ..text import untrusted
from .attention import attention_key
from .driver import Clock, LaneDriver, Submitter, TurnReport, Verifier
from .interventions import (
    Approve,
    Claim,
    Decline,
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
    Suggestion,
)

BUDGET_WARN = 0.8  # fraction of a cap that raises the budget alert
BUDGET_RAISE = 1.5  # approving more budget multiplies the caps by this


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


REJECTED = "rejected by the platform"
SAID_REJECTED = "the player said the platform rejected it"
DECLINED = "the player declined to submit it"
NOT_FLAG_RANK = {DECLINED: 1, SAID_REJECTED: 2, REJECTED: 3}  # how sure: a stronger reason is kept


@dataclass
class _ToPlatform:
    """A flag for the platform, handed to the submitter (`sent`) or waiting its turn on its
    challenge. `lanes`: the lanes that sent it, in order; it goes out for the first one."""

    flag: str
    lanes: list[str]
    sent: bool = False

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
    """What a flag's approval says: the flag, and the tries left when they are counted."""
    tries = _tries_text(ch)
    return f"submit {flag}" + (f" ({tries})" if tries else "")


class Deck:
    def __init__(
        self, config: DeckConfig, driver: LaneDriver, clock: Clock, verify: Verifier, *,
        submitter: Submitter | None = None,
    ) -> None:
        """`verify` checks a flag at once (an answers file, or never: the player submits by
        hand). With a `submitter` (a platform over the network) the deck never calls it: a
        flag goes to the submitter, and its answer comes back through platform_verdict()."""
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
        self._not_flags: dict[str, dict[str, str]] = {}  # challenge id -> flag -> why it is known not to be the flag
        self.held = ""  # why no more lanes start (hold_queue), "" while they do
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

    def teammate_solved(self, challenge_id: str, who: str) -> None:
        """Team mode: a teammate solved a challenge. Its lanes stop and it leaves the queue."""
        self._on_thread("teammate_solved")
        self._need_team("teammate_solved")
        ch = self.challenges[challenge_id]
        if ch.closed:  # we, or another teammate, got there first; keep that record
            self._emit(EventKind.TEAMMATE, f"{who} also solved {ch.name}", challenge=ch.id, data={"who": who, "solved": True})
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
        self._emit(EventKind.TEAMMATE, text, challenge=ch.id, data={"who": who, "solved": True, "stopped": stopped})

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
        check flags. `detail`: the platform's words, or why there is no verdict (untrusted).
        `tries_left`: the tries left on the challenge, when the platform said; from then on its
        flags wait for the player, also under auto.

        It holds when the lane has ended meanwhile (killed, gave up, stopped): a right flag
        still solves the challenge, credited to that lane. When the challenge was solved
        meanwhile (by another lane, a teammate, or as the platform lists it), the answer is
        recorded and nothing reopens. Then the next flag waiting its turn on the challenge
        goes out, unless the player must decide: after an answer that is no verdict, or once
        the tries are counted, each one goes back to its lane as an approval."""
        self._on_thread("platform_verdict")
        lane = self.lanes[lane_id]
        ch = self.challenges[lane.challenge_id]
        line = self._lines.get(ch.id, [])
        if not line or not line[0].sent or line[0].lane != lane_id or line[0].flag != flag:
            raise ValueError(f"no flag of {lane_id} is on its way to the platform as {flag!r}")
        sent = line.pop(0)
        if not line:
            del self._lines[ch.id]
        if tries_left is not None:
            self._tries(ch, tries_left)
        extra: dict[str, object] = {"detail": detail} if detail else {}
        if tries_left is not None:
            extra["tries_left"] = tries_left
        if ok is not None and detail:
            self._note(lane, f"the platform's answer to {flag}: {detail}")
        if ch.closed:  # solved meanwhile: the answer is recorded, and nothing reopens
            if ok is None:
                self._note(lane, f"no verdict from the platform on {flag} ({detail or 'no reason given'}); "
                                 f"{ch.name} was solved meanwhile")
            else:
                self._note(lane, f"submitted {flag}: {'correct' if ok else 'incorrect'}")
                self._emit(EventKind.SUBMIT, f"{lane.id} submitted {flag} for {ch.name}: {'correct' if ok else 'incorrect'} "
                           f"(it was solved meanwhile)", lane.id, ch.id,
                           data={"flag": flag, "correct": ok, "by": "platform", "solved_meanwhile": True, **extra})
                if not ok:
                    self._remember_not_flag(ch.id, flag, REJECTED)
        elif ok is None:
            self._no_verdict(sent, ch, detail)
        else:
            self._verdict(lane, flag, ok, by="platform", data=extra)
            if not ok:
                for other in (self.lanes[i] for i in sent.lanes[1:]):  # the lanes that sent it after the first
                    if not other.finished:
                        self._note(other, f"candidate {flag} dropped: {REJECTED} on {lane.id}")
                        self.driver.rejected(other, flag)
                        self._end_if_gave_up(other)
        self._next_to_platform(ch, ok)

    def note(self, lane_id: str, text: str) -> None:
        """A flightdeck note on a lane's transcript (from a component outside the deck)."""
        self._on_thread("note")
        lane = self.lanes.get(lane_id)
        if lane is not None and not lane.finished:
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
        """Apply what a lane did. Called by the driver after each step."""
        self._on_thread("report")
        lane = self.lanes[lane_id]
        if lane.finished:
            # A step that completed after the lane ended (a real lane can race a kill).
            return
        now = self.now
        if rep.turn:
            lane.turns += 1
        if rep.hints_taken:
            del lane.hints[: rep.hints_taken]
        lane.tokens += rep.tokens
        lane.cached_tokens += rep.cached_tokens
        if rep.dollars is None:
            lane.unpriced += 1
            if lane.dollars is not None and lane.dollar_cap:
                self._unpriced(lane)
            lane.dollars = None
        else:
            lane.known_dollars += rep.dollars
            if lane.dollars is not None:
                lane.dollars += rep.dollars
        if not rep.turn and (rep.tokens or rep.dollars):
            self._emit(
                EventKind.SPEND,
                f"{lane.id} spent {rep.tokens} tokens outside a turn" + (f": {rep.why}" if rep.why else ""),
                lane.id,
                lane.challenge_id,
                data={"tokens": rep.tokens, "cached_tokens": rep.cached_tokens, "dollars": rep.dollars,
                      "model": rep.model or lane.model, "why": rep.why},
            )
        lane.last_active_at = now
        if rep.action:
            lane.actions.append(Action(now, lane.turns, rep.action, rep.output, Actor.LANE, ActionKind.STEP))
        if rep.plan is not None:
            lane.plan = rep.plan
        for item in rep.artifacts:
            if item not in lane.artifacts:
                lane.artifacts.append(item)
        for change in rep.files:
            lane.files.pop(change.path, None)
            lane.files[change.path] = replace(change, turn=lane.turns, at=now)
        if rep.turn:
            self._emit(
                EventKind.TURN,
                f"{lane.id} turn {lane.turns}: {rep.action}",
                lane.id,
                lane.challenge_id,
                data={
                    "turn": lane.turns,
                    "model": rep.model or lane.model,
                    "tokens": rep.tokens,
                    "cached_tokens": rep.cached_tokens,
                    "dollars": rep.dollars,
                    "action": rep.action,
                },
            )
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
        if rep.gave_up is not None:
            if self._has_submit(lane):
                lane.gave_up_later = rep.gave_up
                self._note(lane, f"gave up ({rep.gave_up}), but a candidate flag waits for you")
            else:
                self._finish(lane, LaneState.GAVE_UP, rep.gave_up, then=ChallengeStatus.PARKED)
                return
        self._check_budget(lane)

    # ------------------------------------------------------------------ interventions

    def apply(self, iv: Intervention) -> Outcome:
        """Apply a player intervention. Logged before its effects, with its outcome after."""
        self._on_thread("apply")
        name = type(iv).__name__.lower()
        lane = getattr(iv, "lane", None)
        challenge = getattr(iv, "challenge", None)
        self._emit(EventKind.INTERVENTION, f"{name} {lane or challenge}", lane, challenge, data={"intervention": name, **asdict(iv)})
        outcome = self._apply(iv)
        self._emit(
            EventKind.OUTCOME,
            f"{name}: {outcome.message}",
            lane,
            challenge,
            data={"intervention": name, "ok": outcome.ok, "message": outcome.message},
        )
        return outcome

    def _apply(self, iv: Intervention) -> Outcome:
        if isinstance(iv, Claim):
            return self._claim(iv.challenge)
        if isinstance(iv, Release):
            return self._release_claim(iv.challenge)
        if isinstance(iv, Queue):
            return self._queue(iv.challenge)
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
        raise TypeError(f"unknown intervention {iv!r}")

    def _pause(self, lane: Lane) -> Outcome:
        if lane.state is LaneState.PAUSED:
            return Outcome(False, f"{lane.id} is already paused")
        lane.state = LaneState.PAUSED
        self.driver.pause(lane)
        self._note(lane, "paused by the player", Actor.PLAYER)
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

    def _redirect(self, lane: Lane, text: str) -> Outcome:
        if not text:
            return Outcome(False, "Empty plan; nothing changed")
        if text == lane.plan:
            return Outcome(False, "Plan unchanged; nothing sent")
        lane.plan = text
        lane.approach = text  # the player's own words: an escalated lane's brief carries them
        self._clear_course(lane)
        self.driver.redirect(lane, text)
        self._note(lane, f"new plan: {text}", Actor.PLAYER)
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
            self._note(lane, f"fork queued first ({model}): all {self.config.max_lanes} lanes busy", Actor.PLAYER)
            return Outcome(True, f"Fork of {lane.id} ({model}) is first in the queue; all {self.config.max_lanes} lanes are busy")
        self._note(lane, f"forked to {started.id} ({model})", Actor.PLAYER)
        return Outcome(True, f"Forked {lane.id} → {started.id} on {model}")

    def _kill(self, lane: Lane, requeue: bool) -> Outcome:
        ch = self.challenges[lane.challenge_id]
        if requeue and self._workable(ch):
            entry = QueueEntry(
                ch.id, lane.model, attempt=lane.attempt + 1, token_cap=lane.token_cap, dollar_cap=lane.dollar_cap
            )
            self.queue.insert(0, entry)
            self._finish(lane, LaneState.KILLED, "by the player; re-queued fresh", then=ChallengeStatus.QUEUED)
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
        self._finish(lane, LaneState.KILLED, "by the player; parked" + why, then=ChallengeStatus.PARKED)
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
                Actor.PLAYER,
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
        self._note(lane, f"approved: {pending.detail}", Actor.PLAYER)
        ch = self.challenges[lane.challenge_id]
        if pending.kind is PendingKind.CONFIRM:
            assert pending.flag is not None
            self._verdict(lane, pending.flag, True, by="player")
            return Outcome(True, f"{pending.flag} accepted: {ch.name} solved by {lane.id}")
        if pending.kind is PendingKind.SUBMIT:
            assert pending.flag is not None
            if self.submitter is not None:  # a platform over the network: its answer comes later
                return self._send(lane, pending.flag, approved=pending)
            verdict = self._submit(lane, pending.flag)
            if verdict is None:
                return Outcome(True, f"Submit {pending.flag} on the platform, then: a accepted, d rejected")
            if verdict:
                return Outcome(True, f"{pending.flag} is correct: {ch.name} solved by {lane.id}")
            return Outcome(True, f"{pending.flag} was rejected; {lane.id} carries on")
        if pending.kind is PendingKind.BUDGET:
            if lane.dollars is None and lane.dollar_cap:
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
        self._note(lane, f"declined: {pending.detail}", Actor.PLAYER)
        if pending.kind is PendingKind.CONFIRM:
            assert pending.flag is not None
            self._verdict(lane, pending.flag, False, by="player")
            return Outcome(True, f"{pending.flag} was rejected; {lane.id} carries on")
        if pending.kind is PendingKind.BUDGET:
            self._finish(lane, LaneState.STOPPED, "the player declined more budget")
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

    def _queue(self, challenge_id: str) -> Outcome:
        ch = self.challenges.get(challenge_id)
        if ch is None:
            return Outcome(False, f"No challenge {challenge_id}")
        if not self._workable(ch):
            return Outcome(False, f"{ch.name} is {self._why_not(ch)}")
        if self.lanes_on(ch.id):
            return Outcome(False, f"{ch.name} already has a lane ({', '.join(x.id for x in self.lanes_on(ch.id))})")
        if self.queued(ch.id):
            return Outcome(False, f"{ch.name} is already queued")
        last = next((x for x in reversed(self.lanes.values()) if x.challenge_id == ch.id), None)
        if last is None and not self.config.models:
            return Outcome(False, f"No model to start {ch.name} with: it never had a lane and no model ladder is set")
        entry = QueueEntry(
            ch.id,
            last.model if last else self.config.models[0],
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
        if started is None:
            return Outcome(True, f"Queued {ch.name} (position {len(self.queue)})")
        return Outcome(True, f"Started {started.id} on {ch.name}")

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

    def hold_queue(self, reason: str) -> None:
        """Start no more lanes (the queue stays): something wrong for every lane, such as a
        model API that refuses the key or the model id. Said once, as a warning."""
        self._on_thread("hold_queue")
        if self.held:
            return
        self.held = reason
        self._emit(EventKind.WARNING, f"no more lanes start: {reason}", data={"held": True, "reason": reason})

    def _fill(self) -> None:
        """Start queued lanes while there are free slots (none while the queue is held)."""
        while self.queue and not self.held and len(self.active_lanes()) < self.config.max_lanes:
            entry = self.queue.pop(0)
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
        if any(p.kind in FLAG_PENDING for p in ([lane.pending] if lane.pending else []) + lane.waiting):
            return True
        return any(lane.id in item.lanes for item in self._lines.get(lane.challenge_id, ()))

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
        queued = ([lane.pending] if lane.pending else []) + lane.waiting
        if any(p.flag == flag for p in queued):
            return  # already waiting
        if self._on_its_way(lane, flag):
            return
        ch = self.challenges[lane.challenge_id]
        if self.config.submit == "auto" and claimed and self.submitter is None:
            self._submit(lane, flag)  # an answers file checks it, or the player submits it by hand: no try is spent
            return
        if self.config.submit == "auto" and claimed and not ch.limited:
            self._send(lane, flag)
            return
        # under auto, a match scraped from text the lane read (a decoy flag.txt, an example
        # in a comment) waits for the player: a wrong try can cost a CTFd attempt. So does
        # every flag of a challenge whose tries the platform counts: flightdeck never spends
        # one of them on its own.
        self._ask(lane, Pending(PendingKind.SUBMIT, _submit_detail(ch, flag), flag=flag))

    def _submit(self, lane: Lane, flag: str) -> bool | None:
        """Submit through the board. None: the board cannot check flags, so the player
        submits by hand and confirms (the flag's approval becomes a confirmation)."""
        ch = self.challenges[lane.challenge_id]
        ok = self.verify(ch.id, flag)
        if ok is None:
            confirm = Pending(PendingKind.CONFIRM, f"did the platform accept {flag}? (you submit it)", flag=flag)
            if lane.pending is not None and lane.pending.flag == flag:
                lane.pending = replace(confirm, at=self.now)
                self._became_current(lane)
            else:
                self._ask(lane, confirm)
            return None
        self._verdict(lane, flag, ok, by="platform")
        return ok

    def _verdict(self, lane: Lane, flag: str, ok: bool, *, by: str, data: dict[str, object] | None = None) -> None:
        """A flag was right or wrong (the platform said, or the player for a hand submit). The
        lane may have ended before the platform's answer came: a right flag still solves the
        challenge, credited to it, and a wrong one is still known wrong. `data`: more for the
        submit event (the platform's words, the tries it said are left)."""
        ch = self.challenges[lane.challenge_id]
        self._note(lane, f"submitted {flag}: {'correct' if ok else 'incorrect'}" + (" (you said so)" if by == "player" else ""))
        self._emit(
            EventKind.SUBMIT,
            f"{lane.id} submitted {flag} for {ch.name}: {'correct' if ok else 'incorrect'}",
            lane.id,
            ch.id,
            data={"flag": flag, "correct": ok, "by": by, **(data or {})},
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
            self._end_if_gave_up(lane)
            return
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
        if self._on_its_way(lane, flag):
            return Outcome(True, f"{flag} is already on its way to the platform for {ch.name}")
        line = self._lines.setdefault(ch.id, [])
        line.append(_ToPlatform(flag, [lane.id]))
        if len(line) > 1:
            first = line[0]
            self._note(lane, f"waits its turn to go to the platform: {flag} (after {first.flag}, from {first.lane}: "
                             "one flag at a time per challenge)")
            return Outcome(True, f"{flag} goes to the platform once the answer to {first.flag} is in "
                                 f"(one flag at a time on {ch.name})")
        if not self._hand_over(ch):
            return Outcome(True, f"{flag} could not go to the platform: submit it by hand, then say if it was accepted")
        return Outcome(True, f"Submitting {flag} for {ch.name}; the platform's answer comes back on its own")

    def _on_its_way(self, lane: Lane, flag: str) -> bool:
        """Whether `flag` is on its way to the platform for the lane's challenge already (sent,
        or waiting its turn): then the lane hears its answer too, and nothing is sent again."""
        item = next((item for item in self._lines.get(lane.challenge_id, ()) if item.flag == flag), None)
        if item is None:
            return False
        if lane.id not in item.lanes:
            item.lanes.append(lane.id)
            self._note(lane, f"already on its way to the platform, from {item.lane}: {flag}")
        return True

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
        by hand and says how it went (a CONFIRM approval), on the first lane that sent it and
        is still open. With none open, a warning says so."""
        lanes = [self.lanes[lane_id] for lane_id in item.lanes]
        for lane in lanes:
            self._note(lane, f"no verdict from the platform on {item.flag}: {detail or 'no reason given'}")
        ask = next((lane for lane in lanes if not lane.finished), None)
        if ask is None:
            self._emit(
                EventKind.WARNING,
                f"no verdict from the platform on {item.flag} for {ch.name}, and {', '.join(item.lanes)} has ended: "
                "submit it by hand if you think it is the flag",
                challenge=ch.id,
                data={"flag": item.flag, "lanes": list(item.lanes)},
            )
            return
        self._ask(ask, Pending(PendingKind.CONFIRM, f"did the platform accept {item.flag}? (you submit it)", flag=item.flag))
        for lane in lanes:
            if lane is not ask:
                self._end_if_gave_up(lane)

    def _next_to_platform(self, ch: Challenge, ok: bool | None) -> None:
        """After an answer, the next flag waiting its turn on `ch` goes out, unless the player
        must decide: after no verdict (the platform may not judge this one either), or once the
        platform counts the tries (flightdeck never spends one on its own). Then each flag
        waiting goes back to the first of its lanes as an approval. A flag known wrong by now
        never goes out; on a solved challenge none does."""
        line = self._lines.get(ch.id)
        if not line:
            return
        if ch.closed or ok is None or ch.limited:
            del self._lines[ch.id]
            why = (f"{ch.name} is solved" if ch.closed else "the platform gave no verdict on the flag before it"
                   if ok is None else "the platform counts the tries at this challenge's flag")
            for item in line:
                lane = next((self.lanes[i] for i in item.lanes if not self.lanes[i].finished), None)
                if lane is None or ch.closed:
                    continue
                self._note(lane, f"back to you: {item.flag} did not go to the platform ({why})")
                self._ask(lane, Pending(PendingKind.SUBMIT, _submit_detail(ch, item.flag), flag=item.flag))
            return
        while line and (why := self.not_flag(ch.id, line[0].flag)) is not None:
            item = line.pop(0)
            for lane in (self.lanes[i] for i in item.lanes):
                if not lane.finished:
                    self._note(lane, f"not sent to the platform: {item.flag} ({why})")
                    self._tell_not_flag(lane, item.flag, why)
                    self._end_if_gave_up(lane)
        if not line:
            self._lines.pop(ch.id, None)
            return
        self._hand_over(ch)

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

    def _tries(self, ch: Challenge, left: int) -> None:
        """The platform said how many tries are left on `ch`: its flags wait for the player from
        now on (Challenge.limited), and every approval waiting for one says how many."""
        ch.tries_left = max(0, left)
        for lane in self.lanes_on(ch.id):
            for pending in [lane.pending, *lane.waiting]:
                if pending is not None and pending.kind is PendingKind.SUBMIT and pending.flag is not None:
                    pending.detail = _submit_detail(ch, pending.flag)
            self._sync_flag_alert(lane)

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

    def _unpriced(self, lane: Lane) -> None:
        """A dollar-capped lane just had a turn with no price: the cap can no longer be enforced."""
        self._raise(
            lane,
            Alert(
                AlertKind.BUDGET,
                f"No price for {lane.model}, so the ${fmt.dollars(lane.dollar_cap)} cap cannot be "
                "enforced; it waits for approval to carry on without it.",
                (Suggestion("a", "Carry on without the dollar cap"), Suggestion("k", "Kill the lane")),
            ),
        )
        if not any(p.kind is PendingKind.BUDGET for p in ([lane.pending] if lane.pending else []) + lane.waiting):
            self._ask(lane, Pending(PendingKind.BUDGET, f"carry on with no dollar cap (no price for {lane.model})"))

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
            parts.append(f"${fmt.dollars(lane.dollars)} of ${fmt.dollars(lane.dollar_cap)}")
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
            kind = ActionKind.PLAYER if by is Actor.PLAYER else ActionKind.NOTE
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
