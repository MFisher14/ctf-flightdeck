"""Autopilot (M5, D20): flightdeck runs an event end to end while the player is away.

Autopilot is code, never a model (D15). It subscribes to the deck, as the Watch does, and
after the deck's events it looks at the deck and acts by rule, through Deck.apply with
`by=Actor.AUTOPILOT`, so the run log, each lane's transcript and the reports tell its
interventions from the player's. It changes no policy: every stage runs as the event profile
and the config have it, so autopilot is never looser than the event's rules. It submits
nothing itself, and the deck refuses it an approval (Deck.apply: BY_RULE), so a flag, a
live-box request and everything else that waits for the player goes on waiting.

Three states:
- off: nothing here acts. A run starts off unless it was asked to engage;
- engaged: the rules below act, and the guardrails hold;
- disengaged: something needs a human, so the rules stopped and the queue is held
  (Deck.hold_queue), but the guardrails still hold, since the player is away: the deck's
  last-try rule, no refusal rerouted, and the run budget (lanes are paused at it). The player
  touching the controls ends it: their first intervention, `/unhold` or `/autopilot off`
  turns autopilot off, and `/autopilot on` engages it again.

The rules, each on what the deck shows (a lane that is paused or taken over, that waits for
the player's answer to a flag or a live-box request, or whose flag is on its way to the
platform is left alone: those are the player's):
- a lane's budget request (its own cap) is declined: the lane stops, and its challenge goes
  round again on the next model up. The run budget is the limit that counts;
- a loop alert: the lane is killed and its challenge parked for the next round;
- an effort alert (effort out of proportion to the challenge's worth): the lane is killed
  and the challenge parked for the player; it does not go round again;
- a stall alert: the lane is escalated one rung; when it cannot go up (the top rung), it is
  killed and parked;
- an "ignores the hint" or "wrong direction" alert: the lane is redirected to the alert's own
  suggestion (the detector's words, from flightdeck's tables, never a challenge's), once per
  lane and kind. A light hint judge, if configured, has had its say in the Watch already;
- the next round: when the queue is dry and no lane is running, each unsolved challenge a
  lane gave up on (or that a rule above parked) is queued on the next model up the ladder,
  lowest points first, each challenge at most once per rung. Not one whose lane ended on its
  model's refusal (no refused request goes on to another model), nor one the player parked.

The guardrails: a run budget in dollars, tokens or both is required to engage (Budget);
autopilot engages only on the Docker runtime, where a lane reaches its challenge's own
instance and nothing else (agent/egress.py); while it guards, the model client sends no
server-side refusal fallback (`refusals`); and the deck never spends a challenge's last try
on its own (Deck._keeps_last_try).

It disengages (disengage) when something needs a human: the run budget reached; spend with
no price under a budget in dollars alone; the queue held by anything else (a model API that
fails for every lane, an outage: agent/driver.py); the platform failing, or answering with a
human check (run.py tells it: platform()); the event's end (ended()). A disengage holds the
queue, logs a warning whose data is {"autopilot": "disengaged", "reason": ...} (what a
notifier listens for, and what the post-flight report lists) and stops the rules.

Autopilot never acts from inside the deck's dispatch of an event (the deck is in the middle
of a lane's report then): an event only marks that there is something to look at, and
step() does the looking, on the running event loop's next turn. With no event loop (the
mock's scripted clock, a test), whoever drives the deck calls step().
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from . import fmt
from .core.deck import Deck
from .core.interventions import Decline, Escalate, Kill, Outcome, Pause, Queue, Redirect
from .core.model import (
    FLAG_PENDING,
    ME,
    Actor,
    AlertKind,
    Challenge,
    ChallengeStatus,
    Event,
    EventKind,
    Lane,
    LaneState,
    PendingKind,
)

NEEDS_DOCKER = (
    "autopilot needs the Docker runtime: there a lane reaches its challenge's own instance and nothing else, and on "
    "this machine (runtime host) its shell reaches whatever this machine reaches, which flightdeck cannot hold back"
)
NEEDS_BUDGET = (
    "autopilot needs a run budget: set budget_dollars or budget_tokens under [autopilot] in your config, or give "
    "--budget-dollars or --budget-tokens"
)


class State(StrEnum):
    OFF = "off"
    ENGAGED = "engaged"
    DISENGAGED = "disengaged"


@dataclass(frozen=True)
class Budget:
    """The run budget: what the whole run may spend, over every lane. Either or both."""

    dollars: float | None = None
    tokens: int | None = None

    def __post_init__(self) -> None:
        d, t = self.dollars, self.tokens
        if d is not None and (isinstance(d, bool) or not isinstance(d, (int, float)) or not 0 < d < float("inf")):
            raise ValueError(f"the run budget in dollars must be a number above 0, not {d!r}")
        if t is not None and (isinstance(t, bool) or not isinstance(t, int) or t < 1):
            raise ValueError(f"the run budget in tokens must be a whole number above 0, not {t!r}")

    @property
    def set(self) -> bool:
        return self.dollars is not None or self.tokens is not None

    def text(self) -> str:
        parts = ([f"${fmt.dollars(self.dollars)}"] if self.dollars is not None else []) + (
            [f"{fmt.tokens(self.tokens)} tokens"] if self.tokens is not None else [])
        return " and ".join(parts) or "none"


class Autopilot:
    """The run's autopilot: see the module doc. Make it after the Watch and attach() it, so it
    sees the alerts the Watch raised; it starts off until engage()."""

    def __init__(
        self,
        deck: Deck,
        budget: Budget | None = None,
        *,
        refusals: Callable[[bool], None] | None = None,
    ) -> None:
        """`refusals`: called with False when autopilot starts to guard the run (the model
        client must reroute no refusal from then on) and with True when the player has the
        controls back."""
        self.deck = deck
        self.budget = budget or Budget()
        self.state = State.OFF
        self.reason = ""  # why it last disengaged
        self._refusals = refusals
        self._unsubscribe: Callable[[], None] | None = None
        self._dirty = False  # something happened on the deck since the last step
        self._scheduled = False  # a step is due on the event loop
        self._stepping = False
        self._holding = False  # the hold being placed is autopilot's own
        self._held_by = ""  # why something other than autopilot held the queue, until a step has seen it
        self._parked: set[str] = set()  # lanes a rule ended whose challenge goes round again
        self._left: set[str] = set()  # challenges that do not go round again: the player's, or not worth it
        self._tried: set[tuple[str, str]] = set()  # (challenge id, model) the next-round rule queued: once per rung
        self._redirected: set[tuple[str, AlertKind]] = set()  # (lane id, alert kind) redirected: once
        self._refused: set[str] = set()  # challenges whose refusal was said

    # ------------------------------------------------------------------ wiring

    def attach(self) -> Callable[[], None]:
        """Subscribe to the deck's events and become the deck's autopilot (Deck.autopilot).
        Returns a function that undoes both."""
        if self._unsubscribe is not None:
            raise RuntimeError("this Autopilot is already attached")
        if self.deck.autopilot is not None:
            raise RuntimeError("the deck already has an autopilot")
        unsub = self.deck.subscribe(self._on_event)
        self.deck.autopilot = self

        def detach() -> None:
            if self._unsubscribe is not None:
                unsub()
                self.deck.autopilot = None
                self._unsubscribe = None

        self._unsubscribe = detach
        return detach

    @property
    def engaged(self) -> bool:
        return self.state is State.ENGAGED

    @property
    def guarding(self) -> bool:
        """The guardrails hold: engaged, or disengaged with the player still away."""
        return self.state is not State.OFF

    # ------------------------------------------------------------------ the controls

    def cannot_engage(self) -> str:
        """Why autopilot cannot engage now ("" when it can), in one line."""
        if not self.budget.set:
            return NEEDS_BUDGET
        if not self.deck.config.containerized:
            return NEEDS_DOCKER
        if self.deck.closing:
            return "the run is closing"
        if self.deck.held:
            return f"the queue is held ({self.deck.held}): lift the hold first (/unhold), then engage autopilot"
        return self._over_budget()

    def engage(self) -> Outcome:
        """Engage autopilot: the rules act from the next step on. Refused, with the reason,
        without a run budget, off the Docker runtime, while the queue is held, and once the
        budget is spent."""
        if self.state is State.ENGAGED:
            return Outcome(False, "Autopilot is already engaged")
        why = self.cannot_engage()
        if why:
            return Outcome(False, f"Autopilot not engaged: {why}")
        self.state, self.reason = State.ENGAGED, ""
        self._guard(True)
        self.deck.warn(
            f"autopilot engaged: run budget {self.budget.text()}",
            data={"autopilot": "engaged", "budget_dollars": self.budget.dollars, "budget_tokens": self.budget.tokens},
        )
        self._wake()
        return Outcome(True, f"Autopilot engaged (run budget {self.budget.text()}); /autopilot off takes the controls back")

    def off(self, why: str = "you switched it off") -> Outcome:
        """The player takes the controls back: the rules and the guardrails stop. A hold on
        the queue stays until the player lifts it."""
        if self.state is State.OFF:
            return Outcome(False, "Autopilot is not on")
        self.state = State.OFF
        self._guard(False)
        self.deck.warn(f"autopilot off: {why}", data={"autopilot": "off", "why": why})
        held = "; the queue is still held: /unhold lifts it" if self.deck.held else ""
        return Outcome(True, f"Autopilot off: you have the controls{held}")

    def disengage(self, reason: str) -> None:
        """Something needs a human: the rules stop, the queue is held, and a warning says why
        (its data: autopilot "disengaged", and the reason). The guardrails stay until the
        player is back. Does nothing unless autopilot is engaged."""
        if self.state is not State.ENGAGED:
            return
        self.state, self.reason = State.DISENGAGED, reason
        if not self.deck.held:
            self._holding = True
            try:
                self.deck.hold_queue(f"autopilot disengaged: {reason}")
            finally:
                self._holding = False
        self.deck.warn(
            f"autopilot disengaged: {reason}. The queue is held and its rules have stopped; lanes that run go on. "
            "/unhold lifts the hold, /autopilot on engages it again",
            data={"autopilot": "disengaged", "reason": reason},
        )

    def platform(self, problem: str) -> None:
        """The platform locks flightdeck out, keeps failing, or wants a human (run.py says
        so): disengage."""
        self.disengage(f"the platform needs you: {problem}")

    def ended(self, when: str) -> bool:
        """The event's end has come. True when the run should stop now, as quitting does:
        autopilot is engaged, or disengaged with the player still away. False once the player
        has the controls (the run is theirs to end)."""
        if self.state is State.OFF:
            return False
        self.disengage(f"the event ended ({when}, event.end in the event profile): the run stops as when you quit")
        return True

    # ------------------------------------------------------------------ events

    def _on_event(self, event: Event) -> None:
        data = event.data
        if event.kind is EventKind.WARNING and "held" in data:
            if data.get("held") is True and not self._holding:
                self._held_by = str(data.get("reason") or "")
            elif data.get("held") is False and self.state is State.DISENGAGED:
                self.off("you lifted the hold on the queue")  # the player is back
                return
        elif event.kind is EventKind.INTERVENTION and data.get("by") != Actor.AUTOPILOT.value:
            self._players(event)
            if self.state is State.DISENGAGED:
                self.off("you are back at the controls")
                return
        if self.state is not State.OFF:
            self._dirty = True
            self._wake()

    def _players(self, event: Event) -> None:
        """What the player's own intervention means for the next round: a challenge they
        parked is theirs, and one they queue or fork again is back in play."""
        name, lane = event.data.get("intervention"), self.deck.lanes.get(event.lane or "")
        cid = event.challenge or (lane.challenge_id if lane is not None else None)
        if cid is None:
            return
        if name == "kill" and event.data.get("requeue") is False:
            self._left.add(cid)
        elif name in ("queue", "fork"):
            self._left.discard(cid)

    def _wake(self) -> None:
        if self._scheduled or self._stepping:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # no loop in this thread (the mock's clock, a test): whoever drives the deck calls step()
        self._scheduled = True
        loop.call_soon(self._due)

    def _due(self) -> None:
        self._scheduled = False
        self.step()

    # ------------------------------------------------------------------ one look at the deck

    def step(self) -> None:
        """Look at the deck and act: the guardrails first, then the rules, then the next
        round, until a look changes nothing. Call it on the deck's thread, outside any deck
        call (the event loop does, after each event; without one, call it yourself)."""
        if self._stepping or self.state is State.OFF or self.deck.closing:
            return
        self._stepping = True
        try:
            for _ in range(64):  # each pass acts on what the pass before changed; rules act once per lane and kind
                self._dirty = False
                self._guardrails()
                if self.state is State.ENGAGED:
                    self._rules()
                if self.state is State.ENGAGED:
                    self._next_round()
                if not self._dirty or self.state is State.OFF or self.deck.closing:
                    break
        finally:
            self._stepping = False

    def _guardrails(self) -> None:
        held, self._held_by = self._held_by, ""
        if held and self.deck.held:
            self.disengage(f"the queue was held: {held}")
        over = self._over_budget()
        if not over:
            return
        self.disengage(over)
        for lane in list(self.deck.lanes.values()):  # also once disengaged: the budget holds while the player is away
            if lane.state in (LaneState.RUNNING, LaneState.WAITING):
                self._apply(Pause(lane.id))

    def _over_budget(self) -> str:
        """Why the run cannot spend more under its budget ("" while it can): the budget is
        reached, or, under a budget in dollars alone, some spend has no price."""
        tokens, dollars, _ = self.deck.totals()
        budget = self.budget
        if budget.tokens is not None and tokens >= budget.tokens:
            return f"the run budget is reached: {fmt.tokens(tokens)} of {fmt.tokens(budget.tokens)} tokens spent"
        if budget.dollars is not None and dollars >= budget.dollars:
            return f"the run budget is reached: ${fmt.dollars(dollars)} of ${fmt.dollars(budget.dollars)} spent"
        if budget.dollars is not None and budget.tokens is None:
            blind = next((lane for lane in self.deck.lanes.values() if lane.no_price()), None)
            if blind is not None:
                return (f"spend with no price cannot be held to the ${fmt.dollars(budget.dollars)} run budget: "
                        f"{blind.id} spent something with no known cost (price its model in [prices], or give a budget in tokens)")
        return ""

    # ------------------------------------------------------------------ the rules

    def _rules(self) -> None:
        for lane in list(self.deck.lanes.values()):
            if self.state is not State.ENGAGED:
                return
            if lane.finished or lane.state in (LaneState.PAUSED, LaneState.TAKEOVER) or lane.gave_up_later:
                continue
            pending = lane.pending
            if pending is not None and pending.kind is PendingKind.BUDGET:
                if self._apply(Decline(lane.id)).ok:
                    self._parked.add(lane.id)
                continue
            if pending is not None or self.deck.sending(lane.id) or any(p.kind in FLAG_PENDING for p in lane.waiting):
                continue  # it waits for the player, or for the platform's answer: never ended under them
            if lane.alert(AlertKind.LOOP) is not None:
                if self._apply(Kill(lane.id, requeue=False)).ok:
                    self._parked.add(lane.id)
            elif lane.alert(AlertKind.EFFORT) is not None:
                if self._apply(Kill(lane.id, requeue=False)).ok:
                    self._left.add(lane.challenge_id)
            elif lane.alert(AlertKind.STALL) is not None:
                if not self._apply(Escalate(lane.id)).ok and self._apply(Kill(lane.id, requeue=False)).ok:
                    self._parked.add(lane.id)
            else:
                for kind in (AlertKind.HINT, AlertKind.DIRECTION):
                    alert = lane.alert(kind)
                    if alert is None or (lane.id, kind) in self._redirected:
                        continue
                    self._redirected.add((lane.id, kind))
                    text = next((s.text for s in alert.suggestions if s.key == "r" and s.text.strip()), "")
                    if text:
                        self._apply(Redirect(lane.id, text))
                    break

    def _next_round(self) -> None:
        deck = self.deck
        if deck.held or deck.queue or any(lane.state is LaneState.RUNNING for lane in deck.lanes.values()):
            return
        ladder = deck.config.models
        order = sorted(deck.challenges.values(), key=lambda ch: (ch.points, -ch.solves, ch.name))  # as the board is queued
        for ch in order:
            if self.state is not State.ENGAGED or deck.held:
                return
            model = self._next_model(ch, ladder)
            if model is None:
                continue
            self._tried.add((ch.id, model))
            self._apply(Queue(ch.id, model=model))

    def _next_model(self, ch: Challenge, ladder: tuple[str, ...]) -> str | None:
        """The model `ch` goes round again on, or None when it does not: solved, blocked, a
        teammate's, the player's, being worked or queued, never worked, ended on a refusal,
        or tried on the top rung already."""
        deck = self.deck
        if ch.status is not ChallengeStatus.PARKED or ch.claimed_by not in (None, ME) or ch.id in self._left:
            return None
        if deck.lanes_on(ch.id) or deck.queued(ch.id):
            return None
        lanes = [lane for lane in deck.lanes.values() if lane.challenge_id == ch.id]
        if not lanes:
            return None
        last = lanes[-1]
        if last.declined:
            self._say_refused(ch, last)
            return None
        if last.state is not LaneState.GAVE_UP and last.id not in self._parked:
            return None  # ended some other way (the player killed it, a teammate's solve): not autopilot's to restart
        rungs = [ladder.index(lane.model) for lane in lanes if lane.model in ladder]
        if not rungs or max(rungs) + 1 >= len(ladder):
            return None
        model = ladder[max(rungs) + 1]
        return None if (ch.id, model) in self._tried else model

    def _say_refused(self, ch: Challenge, lane: Lane) -> None:
        if ch.id in self._refused:
            return
        self._refused.add(ch.id)
        self.deck.warn(
            f"{lane.model} declined {ch.name} ({lane.id}): autopilot sends no refused request on to another model, so "
            "it stays parked for you",
            challenge=ch.id, data={"autopilot": "refusal", "lane": lane.id},
        )

    # ------------------------------------------------------------------ helpers

    def _apply(self, intervention) -> Outcome:
        return self.deck.apply(intervention, by=Actor.AUTOPILOT)

    def _guard(self, on: bool) -> None:
        if self._refusals is not None:
            self._refusals(not on)


def start_notes(policies, *, submit: str, spends_tries: bool, instance: str, budget: Budget, waves: bool,
                refusal_fallback: bool, agent: str | None, start=None, end=None) -> list[str]:
    """What autopilot will and will not do in this run, said before lanes start: the run's
    own policies decide, and autopilot loosens none of them. `policies`: the event profile's
    (None without one). `refusal_fallback`: the model client would otherwise send Anthropic's
    server-side refusal fallback. `agent`: the coding-agent CLI the lanes are, if any."""
    out = [f"autopilot: engaged, with a run budget of {budget.text()}; at the budget it holds the queue, pauses the "
           "lanes and disengages. /autopilot off takes the controls back at any time"]
    if submit == "auto":
        out.append("autopilot: submit is auto, so a flag a lane claims is submitted; a flag scraped from text, a "
                   "handout's own stand-in and one the flagcheck holds wait for you")
        if spends_tries:
            out.append('autopilot: submit_limited = "auto" spends a challenge\'s counted tries, but never the last one: '
                       "at the last try, or when the count is not known, the flag waits for you")
        else:
            out.append("autopilot: a flag for a challenge whose tries the platform counts waits for you")
    else:
        rules = " under this event's rules" if policies is not None else ""
        out.append(f"autopilot: submit is {submit}{rules}, so every flag waits for you")
    if instance == "confirm":
        out.append("autopilot: the instance policy is confirm, so a lane's request to reach its live instance waits for you")
    elif instance == "off":
        out.append("autopilot: the instance policy is off, so no lane reaches a live instance")
    if policies is not None:
        out.append("autopilot: new waves are pulled on the timer" if waves else
                   f"autopilot: pull is {policies.pull} in the event profile, so no later wave is pulled")
    if start is not None or end is not None:
        when = [f"{name} {value.isoformat()}" for name, value in (("starts", start), ("ends", end)) if value is not None]
        out.append(f"autopilot: the event {' and '.join(when)}" + ("; the run stops at the end, as when you quit" if end is not None else ""))
    out.append("autopilot: by rule it declines a lane's own budget request, kills a looping lane and one whose effort is "
               "out of proportion, escalates a stalled lane one rung, redirects a lane that ignores the hint, and sends "
               "unsolved challenges round again on the next model up; it approves nothing and submits nothing itself")
    if agent is not None:
        out.append(f"autopilot: lanes are {agent}, whose CLI talks to its own API: flightdeck reroutes no refusal, and "
                   "cannot see or change what the CLI does with one")
    elif refusal_fallback:
        out.append("autopilot: Anthropic's server-side refusal fallback is off while autopilot guards the run: a request "
                   "a model declines is not run again on another model")
    else:
        out.append("autopilot: a request a model declines is never sent on to another model or provider")
    return out
