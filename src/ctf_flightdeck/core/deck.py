"""The deck: board, queue and lanes, plus the rules and interventions that change them.

The console reads the deck and sends it interventions. A LaneDriver does each lane's
work and reports back through Deck.report(). The deck has no loop and no I/O of its
own: the M0 mock drives it from a scripted clock, M1 from real lanes.

Rules the deck enforces:
- at most `max_lanes` lanes are active (running, waiting, paused or taken over);
  the rest wait in the queue, which drains as lanes finish;
- a candidate flag must match the flag format; with submit policy "confirm" it waits
  for the player's approval, with "auto" it is submitted at once;
- a lane at 80% of a cap gets a budget alert, and at 100% it waits for approval;
- team mode: a challenge a teammate solved is never worked; its lanes stop.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace

from .. import fmt
from .driver import Clock, LaneDriver, TurnReport, Verifier
from .interventions import (
    Approve,
    Claim,
    Escalate,
    Fork,
    HandBack,
    Hint,
    Intervention,
    Kill,
    Outcome,
    Pause,
    Redirect,
    Release,
    Resume,
    TakeOver,
)
from .model import (
    COURSE_ALERTS,
    ME,
    Action,
    Actor,
    Alert,
    AlertKind,
    Challenge,
    ChallengeStatus,
    DeckConfig,
    Event,
    EventKind,
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


class Deck:
    def __init__(
        self, config: DeckConfig, driver: LaneDriver, clock: Clock, verify: Verifier
    ) -> None:
        self.config = config
        self.driver = driver
        self.clock = clock
        self.verify = verify
        self.challenges: dict[str, Challenge] = {}
        self.lanes: dict[str, Lane] = {}
        self.queue: list[QueueEntry] = []
        self.events: list[Event] = []
        self._listeners: list[Callable[[Event], None]] = []
        self._lane_seq = 0
        self._flag_re = re.compile(config.flag_format)
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

    def totals(self) -> tuple[int, float, bool]:
        """Tokens and known dollars over all lanes, and whether any lane has no known price."""
        lanes = self.lanes.values()
        known = [lane.dollars for lane in lanes if lane.dollars is not None]
        return sum(lane.tokens for lane in lanes), sum(known), len(known) < len(lanes)

    def subscribe(self, listener: Callable[[Event], None]) -> Callable[[], None]:
        """Call `listener` with every new event. Returns a function that unsubscribes."""
        self._listeners.append(listener)
        return lambda: self._listeners.remove(listener)

    def summary(self, lane: Lane) -> str:
        """A compact state summary, as handed to a stronger model on escalation."""
        ch = self.challenges[lane.challenge_id]
        tried = [a.text for a in lane.actions if a.by is Actor.LANE][-4:]
        lines = [
            f"Challenge: {ch.name} ({ch.category}, {ch.points} pts, {ch.solves} solves); "
            f"files: {', '.join(ch.files) or 'none'}",
            f"Plan: {lane.plan or '(none)'}",
            f"So far: {lane.turns} turns, {fmt.tokens(lane.tokens)} tokens on {lane.model}",
            "Tried: " + ("; ".join(tried) or "nothing yet"),
            "Found: " + (", ".join(lane.artifacts) or "nothing yet"),
        ]
        if lane.alerts:
            lines.append("Alerts: " + "; ".join(f"{a.kind.label}: {a.reason}" for a in lane.alerts))
        return "\n".join(lines)

    # ------------------------------------------------------------------ board

    def release(self, challenges: Sequence[Challenge], entries: Sequence[QueueEntry], label: str = "Release") -> None:
        """Put challenges on the board and queue the triaged entries, in order."""
        for ch in challenges:
            if ch.id in self.challenges:
                raise ValueError(f"challenge {ch.id!r} is already on the board")
        for ch in challenges:
            self.challenges[ch.id] = ch
        for entry in entries:
            ch = self.challenges.get(entry.challenge)
            if ch is None:
                raise KeyError(f"queue entry for unknown challenge {entry.challenge!r}")
            if self._workable(ch):
                self.queue.append(entry)
                ch.status = ChallengeStatus.QUEUED
        before = self._lane_seq
        self._fill()
        self._emit(
            EventKind.RELEASE,
            f"{label}: {len(challenges)} challenges · {self._lane_seq - before} lanes started"
            f" · {len(self.queue)} queued",
        )

    def set_solves(self, challenge_id: str, solves: int) -> None:
        self.challenges[challenge_id].solves = solves

    def teammate_solved(self, challenge_id: str, who: str) -> None:
        """Team mode: a teammate solved a challenge. Its lanes stop and it leaves the queue."""
        self._need_team("teammate_solved")
        ch = self.challenges[challenge_id]
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
        self._emit(EventKind.TEAMMATE, text, challenge=ch.id)

    def teammate_claim(self, challenge_id: str, who: str) -> None:
        """Team mode: a teammate claimed a challenge. It is not started while they hold it."""
        self._need_team("teammate_claim")
        ch = self.challenges[challenge_id]
        ch.claimed_by = who
        if ch.status is ChallengeStatus.QUEUED:
            self._drop_queued(ch.id)
            ch.status = ChallengeStatus.NEW
        self._emit(EventKind.TEAMMATE, f"{who} claimed {ch.name}", challenge=ch.id)

    # ------------------------------------------------------------------ lane reports

    def report(self, lane_id: str, rep: TurnReport) -> None:
        """Apply what a lane did. Called by the driver after each step."""
        lane = self.lanes[lane_id]
        if lane.finished:
            # A step that completed after the lane ended (a real lane can race a kill).
            return
        now = self.now
        if rep.turn:
            lane.turns += 1
            lane.hints.clear()  # queued hints went into this turn
        lane.tokens += rep.tokens
        if rep.dollars is None or lane.dollars is None:
            lane.dollars = None
        else:
            lane.dollars += rep.dollars
        lane.last_active_at = now
        if rep.action:
            lane.actions.append(Action(now, lane.turns, rep.action, rep.output, Actor.LANE))
        if rep.plan is not None:
            lane.plan = rep.plan
        for item in rep.artifacts:
            if item not in lane.artifacts:
                lane.artifacts.append(item)
        for kind in rep.clear:
            self._clear(lane, kind)
        for alert in rep.alerts:
            self._raise(lane, alert)
        if rep.pending is not None:
            self._ask(lane, rep.pending)
        if rep.flag is not None:
            self._candidate(lane, rep.flag)
            if lane.finished:
                return
        if rep.gave_up is not None:
            self._finish(lane, LaneState.GAVE_UP, rep.gave_up, then=ChallengeStatus.PARKED)
            return
        self._check_budget(lane)

    # ------------------------------------------------------------------ interventions

    def apply(self, iv: Intervention) -> Outcome:
        """Apply a player intervention and record it in the event log."""
        outcome = self._apply(iv)
        if outcome.ok:
            self._emit(
                EventKind.INTERVENTION,
                f"{type(iv).__name__.lower()}: {outcome.message}",
                lane=getattr(iv, "lane", None),
                challenge=getattr(iv, "challenge", None),
            )
        return outcome

    def _apply(self, iv: Intervention) -> Outcome:
        if isinstance(iv, Claim):
            return self._claim(iv.challenge)
        if isinstance(iv, Release):
            return self._release_claim(iv.challenge)
        lane = self.lanes.get(iv.lane)
        if lane is None:
            return Outcome(False, f"No lane {iv.lane}")
        if lane.finished:
            return Outcome(False, f"{lane.id} has finished ({lane.state.value})")
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
        self.driver.resume(lane)
        self._note(lane, "resumed by the player", Actor.PLAYER)
        return Outcome(True, f"Resumed {lane.id}")

    def _hint(self, lane: Lane, text: str) -> Outcome:
        if not text:
            return Outcome(False, "Empty hint; nothing sent")
        lane.hints.append(text)
        self._clear_course(lane)
        self.driver.hint(lane, text)
        self._note(lane, f"hint: {text}", Actor.PLAYER)
        return Outcome(True, f"Hint queued for {lane.id}'s next turn")

    def _redirect(self, lane: Lane, text: str) -> Outcome:
        if not text:
            return Outcome(False, "Empty plan; nothing changed")
        lane.plan = text
        self._clear_course(lane)
        self.driver.redirect(lane, text)
        self._note(lane, f"redirect: {text}", Actor.PLAYER)
        return Outcome(True, f"{lane.id} has a new plan")

    def _fork(self, lane: Lane, approach: str, model: str | None) -> Outcome:
        ch = self.challenges[lane.challenge_id]
        model = model or self._other_model(lane.model)
        entry = QueueEntry(
            ch.id,
            model,
            approach=approach,
            parent=lane.id,
            token_cap=lane.token_cap,
            dollar_cap=lane.dollar_cap,
        )
        self.queue.insert(0, entry)
        started = self._fill_and_find(entry)
        if started is None:
            self._note(lane, f"fork queued first ({model}): all {self.config.max_lanes} lanes busy", Actor.PLAYER)
            return Outcome(True, f"Fork of {lane.id} ({model}) is first in the queue; all {self.config.max_lanes} lanes are busy")
        self._note(lane, f"forked to {started.id} ({model})", Actor.PLAYER)
        return Outcome(True, f"Forked {lane.id} → {started.id} on {model}")

    def _kill(self, lane: Lane, requeue: bool) -> Outcome:
        ch = self.challenges[lane.challenge_id]
        if not requeue:
            self._finish(lane, LaneState.KILLED, "by the player; parked", then=ChallengeStatus.PARKED)
            return Outcome(True, f"Killed {lane.id}; {ch.name} is parked")
        entry = QueueEntry(
            ch.id,
            lane.model,
            attempt=lane.attempt + 1,
            token_cap=lane.token_cap,
            dollar_cap=lane.dollar_cap,
        )
        self.queue.insert(0, entry)
        self._finish(lane, LaneState.KILLED, "by the player; re-queued fresh", then=ChallengeStatus.QUEUED)
        started = self._started_for(entry)
        if started is None:
            return Outcome(True, f"Killed {lane.id}; {ch.name} is first in the queue")
        return Outcome(True, f"Killed {lane.id}; fresh lane {started.id} started on {ch.name}")

    def _escalate(self, lane: Lane) -> Outcome:
        stronger = self._stronger(lane.model)
        if stronger is None:
            return Outcome(False, f"{lane.id} is already on the strongest model ({lane.model})")
        summary = self.summary(lane)
        old, lane.model = lane.model, stronger
        self._clear_course(lane)
        self.driver.escalate(lane, stronger, summary)
        lane.actions.append(
            Action(self.now, lane.turns, f"escalated {old} → {stronger} with a summary", summary, Actor.PLAYER)
        )
        return Outcome(True, f"Escalated {lane.id} from {old} to {stronger}")

    def _take_over(self, lane: Lane) -> Outcome:
        lane.state = LaneState.TAKEOVER
        self.driver.pause(lane)
        self._note(lane, "taken over by the player", Actor.PLAYER)
        return Outcome(True, f"You have {lane.id}'s shell")

    def _hand_back(self, lane: Lane, note: str) -> Outcome:
        if lane.state is not LaneState.TAKEOVER:
            return Outcome(False, f"{lane.id} is not taken over")
        lane.state = LaneState.WAITING if lane.pending else LaneState.RUNNING
        self.driver.resume(lane)
        self._note(lane, "handed back by the player" + (f": {note}" if note else ""), Actor.PLAYER)
        return Outcome(True, f"Handed {lane.id} back")

    def _approve(self, lane: Lane) -> Outcome:
        pending = lane.pending
        if pending is None:
            return Outcome(False, f"{lane.id} is not waiting for an approval")
        lane.pending = None
        if lane.state is LaneState.WAITING:
            lane.state = LaneState.RUNNING
        self._note(lane, f"approved: {pending.detail}", Actor.PLAYER)
        if pending.kind is PendingKind.SUBMIT:
            assert pending.flag is not None
            ch = self.challenges[lane.challenge_id]
            if self._submit(lane, pending.flag):
                return Outcome(True, f"{pending.flag} is correct: {ch.name} solved by {lane.id}")
            return Outcome(True, f"{pending.flag} was rejected; {lane.id} carries on")
        if pending.kind is PendingKind.BUDGET:
            if lane.token_cap:
                lane.token_cap = int(lane.token_cap * BUDGET_RAISE)
            if lane.dollar_cap:
                lane.dollar_cap = lane.dollar_cap * BUDGET_RAISE
            self._clear(lane, AlertKind.BUDGET)
            self.driver.approved(lane, pending)
            return Outcome(True, f"{lane.id}'s cap is now {self._cap_text(lane)}")
        self.driver.approved(lane, pending)
        return Outcome(True, f"{lane.id} may use the live box")

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

    # ------------------------------------------------------------------ internals

    def _need_team(self, what: str) -> None:
        if not self.config.team:
            raise RuntimeError(f"{what} needs team mode (DeckConfig.team is False)")

    def _workable(self, ch: Challenge) -> bool:
        if ch.closed or ch.status is ChallengeStatus.BLOCKED:
            return False
        return ch.claimed_by in (None, ME)

    def _drop_queued(self, challenge_id: str) -> None:
        self.queue = [entry for entry in self.queue if entry.challenge != challenge_id]

    def _fill(self) -> None:
        """Start queued lanes while there are free slots."""
        while self.queue and len(self.active_lanes()) < self.config.max_lanes:
            entry = self.queue.pop(0)
            ch = self.challenges[entry.challenge]
            if self._workable(ch):
                self._start(entry, ch)

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

    def _start(self, entry: QueueEntry, ch: Challenge) -> Lane:
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
        how = f", fork of {entry.parent}" if entry.parent else ""
        how += f", attempt {entry.attempt}" if entry.attempt > 1 else ""
        self._emit(EventKind.LANE_START, f"{lane.id} started on {ch.name} ({lane.model}{how})", lane.id, ch.id)
        self.driver.start(lane, ch)
        return lane

    def _finish(self, lane: Lane, state: LaneState, result: str, then: ChallengeStatus = ChallengeStatus.PARKED) -> None:
        """End a lane, update its challenge and start whatever is queued next."""
        lane.state = state
        lane.ended_at = self.now
        lane.result = result
        lane.pending = None
        lane.hints.clear()
        self.driver.stop(lane)
        ch = self.challenges[lane.challenge_id]
        if not ch.closed and not self.lanes_on(ch.id):
            if self.queued(ch.id):
                ch.status = ChallengeStatus.QUEUED
            else:
                ch.status = then
                if then is ChallengeStatus.PARKED:
                    ch.note = f"{lane.id} {state.value}: {result}"
        self._emit(EventKind.LANE_END, f"{lane.id} {state.value}: {result}", lane.id, ch.id)
        self._fill()

    def _raise(self, lane: Lane, alert: Alert) -> None:
        for i, existing in enumerate(lane.alerts):
            if existing.kind is alert.kind:
                lane.alerts[i] = replace(alert, at=existing.at)  # same alert, newer reason
                return
        lane.alerts.append(replace(alert, at=self.now))
        self._emit(EventKind.ALERT, f"{lane.id} {alert.kind.label}: {alert.reason}", lane.id, lane.challenge_id, alert.kind)

    def _clear(self, lane: Lane, kind: AlertKind) -> None:
        lane.alerts = [a for a in lane.alerts if a.kind is not kind]

    def _clear_course(self, lane: Lane) -> None:
        lane.alerts = [a for a in lane.alerts if a.kind not in COURSE_ALERTS]

    def _ask(self, lane: Lane, pending: Pending) -> None:
        if lane.pending is not None:
            return  # one approval at a time; the lane asks again later
        lane.pending = replace(pending, at=self.now)
        if lane.state is LaneState.RUNNING:
            lane.state = LaneState.WAITING
        self._emit(EventKind.PENDING, f"{lane.id} waits for approval: {pending.detail}", lane.id, lane.challenge_id)

    def _candidate(self, lane: Lane, flag: str) -> None:
        if not self._flag_re.fullmatch(flag):
            self._note(lane, f"candidate {flag} does not match the flag format; not submitted")
            return
        if self.config.submit == "auto":
            self._submit(lane, flag)
            return
        self._raise(
            lane,
            Alert(
                AlertKind.FLAG,
                f"Candidate {flag} matches the flag format.",
                (Suggestion("a", "Approve submit"),),
            ),
        )
        self._ask(lane, Pending(PendingKind.SUBMIT, f"submit {flag}", flag=flag))

    def _submit(self, lane: Lane, flag: str) -> bool:
        ch = self.challenges[lane.challenge_id]
        ok = self.verify(ch.id, flag)
        self._clear(lane, AlertKind.FLAG)
        self._note(lane, f"submitted {flag}: {'correct' if ok else 'incorrect'}")
        self._emit(EventKind.SUBMIT, f"{lane.id} submitted {flag} for {ch.name}: {'correct' if ok else 'incorrect'}", lane.id, ch.id)
        if not ok:
            if lane.state is LaneState.WAITING:
                lane.state = LaneState.RUNNING
            self.driver.rejected(lane, flag)
            return False
        ch.status = ChallengeStatus.SOLVED
        ch.solved_by = lane.id
        ch.solves += 1
        ch.note = ""
        self._drop_queued(ch.id)
        self._finish(lane, LaneState.SOLVED, f"solved with {flag}")
        for other in self.lanes_on(ch.id):
            self._finish(other, LaneState.STOPPED, f"{lane.id} solved it")
        return True

    def _check_budget(self, lane: Lane) -> None:
        used = lane.budget_used()
        if used is None or used < BUDGET_WARN:
            return
        suggestions = (
            Suggestion("a", "Approve 50% more budget"),
            Suggestion("e", "Escalate to a stronger model"),
            Suggestion("k", "Kill the lane"),
        )
        cap = self._cap_text(lane)
        if used >= 1.0:
            self._raise(lane, Alert(AlertKind.BUDGET, f"At {used:.0%} of its cap ({cap}); it waits for approval before spending more.", suggestions))
            self._ask(lane, Pending(PendingKind.BUDGET, f"raise the cap by 50% (now {cap})"))
        elif lane.alert(AlertKind.BUDGET) is None:
            self._raise(lane, Alert(AlertKind.BUDGET, f"At {used:.0%} of its cap ({cap}).", suggestions))

    def _cap_text(self, lane: Lane) -> str:
        parts = []
        if lane.token_cap:
            parts.append(f"{fmt.tokens(lane.tokens)} of {fmt.tokens(lane.token_cap)} tokens")
        if lane.dollar_cap:
            parts.append(f"${fmt.dollars(lane.dollars)} of ${fmt.dollars(lane.dollar_cap)}")
        return ", ".join(parts) or "no cap"

    def _stronger(self, model: str) -> str | None:
        ladder = self.config.models
        if model not in ladder:
            return ladder[-1] if ladder else None
        i = ladder.index(model)
        return ladder[i + 1] if i + 1 < len(ladder) else None

    def _other_model(self, model: str) -> str:
        """For a fork: the next stronger model, else the weakest other one, else the same."""
        stronger = self._stronger(model)
        if stronger is not None:
            return stronger
        others = [m for m in self.config.models if m != model]
        return others[0] if others else model

    def _note(self, lane: Lane, text: str, by: Actor = Actor.DECK) -> None:
        lane.actions.append(Action(self.now, lane.turns, text, "", by))

    def _emit(
        self,
        kind: EventKind,
        text: str,
        lane: str | None = None,
        challenge: str | None = None,
        alert: AlertKind | None = None,
    ) -> None:
        event = Event(self.now, kind, text, lane, challenge, alert)
        self.events.append(event)
        for listener in list(self._listeners):
            listener(event)
