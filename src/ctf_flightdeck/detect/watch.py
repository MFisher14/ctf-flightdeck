"""The Watch: it runs the detectors after every turn and raises or clears their alerts.

The Watch observes the deck; it never steers a lane. It subscribes to the deck's events.
On each TURN event it runs every detector for that lane and, through `deck.report` with
`turn=False`, raises or refreshes the alert a detector signals and clears an open alert a
detector no longer signals. It never raises an alert the player just answered: it watches
INTERVENTION and OUTCOME events to see which course alerts an intervention cleared, and
holds that alert's kind quiet for `quiet_turns` turns of that lane.

Finished, paused and taken-over lanes are not checked. The Watch raises nothing itself
beyond the detectors' signals, so a scripted or external driver that reports its own alerts
is unaffected for kinds no detector owns.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from ..core.deck import Deck
from ..core.driver import TurnReport
from ..core.model import (
    COURSE_ALERTS,
    AlertKind,
    Event,
    EventKind,
    Lane,
    LaneState,
)
from .base import Detector, DetectConfig

ANSWERING_STATES = frozenset({LaneState.RUNNING, LaneState.WAITING})


class Watch:
    """Runs the detectors after every turn and raises/clears alerts through the deck."""

    def __init__(self, deck: Deck, detectors: Sequence[Detector], config: DetectConfig | None = None) -> None:
        self.deck = deck
        self.detectors = list(detectors)
        self.config = config or DetectConfig()
        self._unsubscribe: Callable[[], None] | None = None
        self._answered: dict[str, dict[AlertKind, int]] = {}  # lane id -> kind -> turn it was answered
        self._snapshot: dict[str, set[AlertKind]] = {}  # lane id -> course alerts open when an intervention began

    def attach(self) -> Callable[[], None]:
        """Subscribe to the deck's events. Returns a function that unsubscribes."""
        if self._unsubscribe is not None:
            raise RuntimeError("this Watch is already attached")
        unsub = self.deck.subscribe(self._on_event)

        def detach() -> None:
            if self._unsubscribe is not None:
                unsub()
                self._unsubscribe = None

        self._unsubscribe = detach
        return detach

    # ------------------------------------------------------------------ events

    def _on_event(self, event: Event) -> None:
        if event.lane is None:
            return
        if event.kind is EventKind.TURN:
            self._run(event.lane)
        elif event.kind is EventKind.INTERVENTION:
            self._begin_intervention(event.lane)
        elif event.kind is EventKind.OUTCOME:
            self._end_intervention(event.lane)
        elif event.kind is EventKind.LANE_END:
            self._answered.pop(event.lane, None)
            self._snapshot.pop(event.lane, None)

    def _begin_intervention(self, lane_id: str) -> None:
        lane = self.deck.lanes.get(lane_id)
        if lane is None:
            return
        self._snapshot[lane_id] = {a.kind for a in lane.alerts if a.kind in COURSE_ALERTS}

    def _end_intervention(self, lane_id: str) -> None:
        before = self._snapshot.pop(lane_id, None)
        if not before:
            return
        lane = self.deck.lanes.get(lane_id)
        if lane is None:
            return
        open_now = {a.kind for a in lane.alerts}
        cleared = before - open_now
        if not cleared:
            return
        answered = self._answered.setdefault(lane_id, {})
        for kind in cleared:
            answered[kind] = lane.turns

    # ------------------------------------------------------------------ the detectors

    def _run(self, lane_id: str) -> None:
        lane = self.deck.lanes.get(lane_id)
        if lane is None or not self._checkable(lane):
            return
        challenge = self.deck.challenges.get(lane.challenge_id)
        if challenge is None:
            return
        now = self.deck.now
        raises = []
        clears: list[AlertKind] = []
        answered = self._answered.get(lane_id, {})
        for detector in self.detectors:
            kind = detector.kind
            signal = detector.check(lane, challenge, now)
            if signal is not None:
                if signal.kind is not kind:
                    raise RuntimeError(
                        f"detector {type(detector).__name__} is registered for {kind} but returned a {signal.kind} signal"
                    )
                answered_turn = answered.get(kind)
                if answered_turn is not None and lane.turns - answered_turn < self.config.quiet_turns:
                    continue  # the player answered this alert within the quiet period; stay silent
                raises.append(signal.alert())
            elif lane.alert(kind) is not None:
                clears.append(kind)
        if raises or clears:
            self.deck.report(lane_id, TurnReport(turn=False, clear=tuple(clears), alerts=tuple(raises)))

    @staticmethod
    def _checkable(lane: Lane) -> bool:
        return not lane.finished and lane.state not in (LaneState.PAUSED, LaneState.TAKEOVER)
