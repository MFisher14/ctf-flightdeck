"""The fake world: a scripted clock that plays a scenario into a real Deck.

Each tick advances simulated time, lets other teams' solve counts drift, applies the
scenario's timeline (releases, teammate solves and claims) and moves every running
scripted lane whose next step is due. Nothing ticks on its own: the console calls
tick() from a timer, tests and screenshots call it directly.
"""

from __future__ import annotations

import random

from ..core.deck import Deck, QueueEntry
from ..core.model import DeckConfig
from . import scenarios
from .scenarios import ReleaseAt, Scenario, TeammateClaim, TeammateSolve
from .script import MODELS, SECONDS_PER_TICK, ScriptedDriver


class ManualClock:
    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class FakeWorld:
    def __init__(
        self,
        scenario: Scenario,
        *,
        max_lanes: int | None = None,
        team: bool | None = None,
        containerized: bool | None = None,
    ) -> None:
        self.scenario = scenario
        self.config = DeckConfig(
            event=scenario.event,
            team=scenario.team if team is None else team,
            containerized=scenario.containerized if containerized is None else containerized,
            max_lanes=scenario.max_lanes if max_lanes is None else max_lanes,
            flag_format=scenarios.FLAG_FORMAT,
            submit="confirm",
            models=MODELS,
        )
        self.flags = scenarios.flags_for(scenario)
        self.clock = ManualClock(scenario.start_at)
        self.driver = ScriptedDriver(scenarios.scripts_for(scenario))
        self.deck = Deck(self.config, self.driver, self.clock, verify=self._verify)
        self.ticks = 0
        self.skipped: list[str] = []  # timeline events that need team mode, in solo mode
        self._drift = random.Random(f"{scenario.seed}:solves")
        self._play(0)
        self.tick(scenario.prerun)

    def tick(self, n: int = 1) -> None:
        for _ in range(n):
            self.ticks += 1
            self.clock.advance(SECONDS_PER_TICK)
            self._drift_solves()
            self._play(self.ticks)
            self.driver.step(self.clock.now())

    def _verify(self, challenge_id: str, flag: str) -> bool:
        return self.flags.get(challenge_id) == flag

    def _play(self, tick: int) -> None:
        for at, event in self.scenario.timeline:
            if at != tick:
                continue
            match event:
                case ReleaseAt(ids=ids, label=label):
                    specs = [self.scenario.spec(cid) for cid in ids]
                    entries = [
                        QueueEntry(s.id, s.model, token_cap=s.token_cap) for s in specs
                    ]
                    self.deck.release([s.challenge() for s in specs], entries, label)
                case TeammateSolve(challenge=cid, who=who):
                    if self.config.team:
                        self.deck.teammate_solved(cid, who)
                    else:
                        self.skipped.append(f"{who} solves {cid}")
                case TeammateClaim(challenge=cid, who=who):
                    if self.config.team:
                        self.deck.teammate_claim(cid, who)
                    else:
                        self.skipped.append(f"{who} claims {cid}")

    def _drift_solves(self) -> None:
        """Other teams keep solving: low-point challenges gain solves faster."""
        for ch in self.deck.challenges.values():
            if self._drift.random() < min(0.2, 4.0 / ch.points):
                self.deck.set_solves(ch.id, ch.solves + 1)
