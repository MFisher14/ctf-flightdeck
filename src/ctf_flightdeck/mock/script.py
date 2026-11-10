"""Scripted lanes for the M0 mock: each lane follows a script instead of calling a model.

A Script is a list of Steps (one model turn each) plus branches that interventions
switch to: a hint, a redirect, an escalation or a live-box approval can put the lane
on a different path, so every intervention has a visible effect. Nothing here runs a
command; the commands are display text.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ..core.driver import TurnReport
from ..core.model import Alert, AlertKind, Challenge, Lane, LaneState, Pending, PendingKind

if TYPE_CHECKING:
    from ..core.deck import Deck

SECONDS_PER_TICK = 20.0
"""Simulated seconds per clock tick."""

MODELS = ("glm", "sonnet", "opus")
"""Model ladder for the mock, weakest to strongest."""

MOCK_PRICES = {"glm": 1.0, "sonnet": 4.8, "opus": 9.0}
"""Invented blended dollars per million tokens. M1 takes real prices from the provider."""

AlertFactory = Callable[[Lane, Challenge], Alert]


@dataclass(frozen=True)
class Step:
    do: str = ""  # the lane's action, shown as the last action
    out: str = ""  # short output
    tokens: int | None = None  # None: grows with the turn number (context grows)
    plan: str | None = None
    artifacts: tuple[str, ...] = ()
    alert: Alert | AlertFactory | None = None  # a factory sees the lane after this turn
    clear: tuple[AlertKind, ...] = ()
    pending: Pending | None = None
    flag: str | None = None
    gave_up: str | None = None
    every: int = 1  # ticks until the lane's next step
    team_only: bool = False  # skipped in solo mode


@dataclass(frozen=True)
class Script:
    plan: str
    steps: tuple[Step, ...]
    repeat_from: int | None = None  # after the last step, carry on from this index
    on_hint: tuple[Step, ...] = ()
    on_redirect: tuple[Step, ...] = ()
    on_escalate: tuple[Step, ...] = ()
    on_box: tuple[Step, ...] = ()  # after live-box access is approved
    fresh: Script | None = None  # for a fresh attempt after a kill and re-queue
    fork: Script | None = None  # for a fork of the lane
    base_tokens: int = 4_000
    growth: int = 180  # extra tokens per turn as the context grows


@dataclass
class _Run:
    lane: Lane
    script: Script
    steps: tuple[Step, ...]
    repeat_from: int | None
    next_at: float
    index: int = 0
    inserted: list[Step] = field(default_factory=list)  # acknowledgements go first


class ScriptedDriver:
    """LaneDriver for the mock. step() is called by the fake clock on every tick."""

    def __init__(self, scripts: Mapping[str, Script], prices: Mapping[str, float] = MOCK_PRICES) -> None:
        self.scripts = scripts
        self.prices = prices
        self.runs: dict[str, _Run] = {}
        self._deck: Deck | None = None

    @property
    def deck(self) -> Deck:
        if self._deck is None:
            raise RuntimeError("ScriptedDriver is not attached to a deck")
        return self._deck

    # ------------------------------------------------------------------ LaneDriver

    def attach(self, deck: Deck) -> None:
        self._deck = deck

    def start(self, lane: Lane, challenge: Challenge) -> None:
        script = self.scripts.get(challenge.id)
        if script is None:
            raise KeyError(f"no script for challenge {challenge.id!r}")
        if lane.parent and script.fork:
            script = script.fork
        elif lane.attempt > 1 and script.fresh:
            script = script.fresh
        run = _Run(lane, script, script.steps, script.repeat_from, next_at=self.deck.now + SECONDS_PER_TICK)
        self.runs[lane.id] = run
        # A fork's plan is the approach the player typed, if any.
        self.deck.report(lane.id, TurnReport(plan=lane.approach or script.plan, turn=False))

    def pause(self, lane: Lane) -> None:
        """Nothing to do: step() only moves running lanes."""

    def resume(self, lane: Lane) -> None:
        run = self.runs.get(lane.id)
        if run is not None:
            run.next_at = min(run.next_at, self.deck.now + SECONDS_PER_TICK)

    def hint(self, lane: Lane, text: str) -> None:
        run = self.runs[lane.id]
        if run.script.on_hint:
            self._branch(run, run.script.on_hint)
        else:
            run.inserted.append(Step(do=f"reads the hint: {text}", out="adjusting the next steps"))

    def redirect(self, lane: Lane, text: str) -> None:
        run = self.runs[lane.id]
        if run.script.on_redirect:
            self._branch(run, run.script.on_redirect)
        else:
            run.inserted.append(Step(do=f"switches to the new plan: {text}", out="dropping the old plan"))

    def escalate(self, lane: Lane, model: str, summary: str) -> None:
        run = self.runs[lane.id]
        if run.script.on_escalate:
            self._branch(run, run.script.on_escalate)
        else:
            run.inserted.append(Step(do=f"{model} picks up from the summary", out="re-reading the handout with fresh eyes"))

    def approved(self, lane: Lane, pending: Pending) -> None:
        run = self.runs[lane.id]
        if pending.kind is PendingKind.LIVE_BOX and run.script.on_box:
            self._branch(run, run.script.on_box)

    def rejected(self, lane: Lane, flag: str) -> None:
        self.runs[lane.id].inserted.append(Step(do=f"{flag} was rejected; re-checking the last step"))

    def stop(self, lane: Lane) -> None:
        self.runs.pop(lane.id, None)

    # ------------------------------------------------------------------ clock

    def step(self, now: float) -> None:
        """Advance every running lane whose next step is due."""
        for run in list(self.runs.values()):
            if run.lane.state is LaneState.RUNNING and now >= run.next_at:
                self._advance(run, now)

    def _advance(self, run: _Run, now: float) -> None:
        step = self._next_step(run)
        lane = run.lane
        if step is None:  # the script has ended without an outcome; the lane idles
            run.next_at = now + SECONDS_PER_TICK
            return
        tokens = step.tokens
        if tokens is None:
            tokens = run.script.base_tokens + run.script.growth * (lane.turns + 1)
        price = self.prices.get(lane.model)
        dollars = None if price is None else tokens * price / 1_000_000
        alert = step.alert
        self.deck.report(
            lane.id,
            TurnReport(
                action=step.do,
                output=step.out,
                tokens=tokens,
                dollars=dollars,
                plan=step.plan,
                artifacts=step.artifacts,
                alerts=(alert,) if isinstance(alert, Alert) else (),
                clear=step.clear,
                pending=step.pending,
                flag=step.flag,
                gave_up=step.gave_up,
            ),
        )
        if alert is not None and not isinstance(alert, Alert) and not lane.finished:
            challenge = self.deck.challenges[lane.challenge_id]
            self.deck.report(lane.id, TurnReport(turn=False, alerts=(alert(lane, challenge),)))
        run.next_at = now + step.every * SECONDS_PER_TICK

    def _next_step(self, run: _Run) -> Step | None:
        if run.inserted:
            return run.inserted.pop(0)
        team = self.deck.config.team
        for _ in range(len(run.steps) + 1):
            if run.index >= len(run.steps):
                if run.repeat_from is None:
                    return None
                run.index = run.repeat_from
            step = run.steps[run.index]
            run.index += 1
            if step.team_only and not team:
                continue
            return step
        return None

    def _branch(self, run: _Run, steps: tuple[Step, ...]) -> None:
        run.steps = steps
        run.index = 0
        run.repeat_from = None
        run.inserted.clear()
        run.next_at = self.deck.now + SECONDS_PER_TICK
