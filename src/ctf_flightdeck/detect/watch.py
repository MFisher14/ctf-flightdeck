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

Attach it last. The Watch reports from inside the deck's dispatch of the TURN event, so a
listener subscribed after it receives the alert before the turn that caused it. Attach it
after every listener that records events (EventLog, TranscriptLog), as run.py does; the
console's listener only redraws, so its place does not matter.

The optional hint judge (judge.HintJudge, the light model's). Nothing waits for it: a new
rules HINT signal is raised at once, as the rules have it, and the Watch asks the judge in
the background, on the deck's event loop (the loop the deck's thread runs). When the judge
says the lane is following the hint, the Watch takes the alert down, notes why on the lane,
and keeps it down while that verdict stands (`judge_every_turns` turns); when it says the
lane is not, the alert stays. A judge that cannot answer (the light model refused, failed,
took too long, or said neither yes nor no) never hides an alert: the rules' answer stands, the
alert's reason says it is unconfirmed. Without a judge the Watch needs no event loop at all.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import replace

from ..core.deck import Deck
from ..core.driver import TurnReport
from ..core.model import (
    COURSE_ALERTS,
    AlertKind,
    Challenge,
    Event,
    EventKind,
    Lane,
    LaneState,
)
from .base import DetectConfig, Detector, Signal, quote
from .hints import Technique
from .judge import HintJudge

ANSWERING_STATES = frozenset({LaneState.RUNNING, LaneState.WAITING})


class Watch:
    """Runs the detectors after every turn and raises/clears alerts through the deck."""

    def __init__(
        self,
        deck: Deck,
        detectors: Sequence[Detector],
        config: DetectConfig | None = None,
        *,
        judge: HintJudge | None = None,
    ) -> None:
        self.deck = deck
        self.detectors = list(detectors)
        self.config = config or DetectConfig()
        self.judge = judge
        self._unsubscribe: Callable[[], None] | None = None
        self._answered: dict[str, dict[AlertKind, int]] = {}  # lane id -> kind -> turn it was answered
        self._snapshot: dict[str, set[AlertKind]] = {}  # lane id -> course alerts open when an intervention began
        self._judging: dict[str, asyncio.Task[None]] = {}  # lane id -> the judge call in flight for it
        self._unconfirmed: dict[str, str] = {}  # lane id -> why its open HINT alert is unconfirmed

    def attach(self) -> Callable[[], None]:
        """Subscribe to the deck's events (attach it last: see the module doc). Returns a
        function that unsubscribes."""
        if self._unsubscribe is not None:
            raise RuntimeError("this Watch is already attached")
        unsub = self.deck.subscribe(self._on_event)

        def detach() -> None:
            if self._unsubscribe is not None:
                unsub()
                self._unsubscribe = None

        self._unsubscribe = detach
        return detach

    async def drain(self) -> None:
        """Wait until no hint-judge call is in flight (and its alert, if any, is raised)."""
        while self._judging:
            await asyncio.gather(*list(self._judging.values()), return_exceptions=True)

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
            self._unconfirmed.pop(event.lane, None)
            for detector in self.detectors:
                forget = getattr(detector, "forget", None)
                if callable(forget):
                    forget(event.lane)
            if self.judge is not None:
                self.judge.forget(event.lane)

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

    def _run(self, lane_id: str, only: AlertKind | None = None) -> None:
        lane = self.deck.lanes.get(lane_id)
        if lane is None or not self._checkable(lane):
            return
        challenge = self.deck.challenges.get(lane.challenge_id)
        if challenge is None:
            return
        now = self.deck.now
        raises = []
        clears: list[AlertKind] = []
        ask: Technique | None = None  # the hint judge is asked about this, once the alert is up
        withdrawn = False  # the judge took an open hint alert down
        answered = self._answered.get(lane_id, {})
        for detector in self.detectors:
            kind = detector.kind
            if only is not None and kind is not only:
                continue
            signal = detector.check(lane, challenge, now)
            if signal is not None:
                if signal.kind is not kind:
                    raise RuntimeError(
                        f"detector {type(detector).__name__} is registered for {kind} but returned a {signal.kind} signal"
                    )
                answered_turn = answered.get(kind)
                if answered_turn is not None and lane.turns - answered_turn < self.config.quiet_turns:
                    continue  # the player answered this alert within the quiet period; stay silent
                if kind is AlertKind.HINT and self.judge is not None:
                    signal, ask = self._gate(lane, signal)
                    if signal is None:  # the judge says the lane follows the hint
                        if lane.alert(kind) is not None:
                            clears.append(kind)
                            withdrawn = True
                        continue
                raises.append(signal.alert())
            elif lane.alert(kind) is not None:
                clears.append(kind)
                if kind is AlertKind.HINT:
                    self._unconfirmed.pop(lane_id, None)
        if raises or clears:
            self.deck.report(lane_id, TurnReport(turn=False, clear=tuple(clears), alerts=tuple(raises)))
        if withdrawn:
            assert self.judge is not None
            self.deck.note(lane_id, f"hint alert withdrawn: the light model ({self.judge.light.label}) judged that "
                                    f"{lane_id} is using the hinted technique")
        if ask is not None:
            self._consult(lane_id, challenge, ask)  # after the alert is up: nothing waits for the judge

    @staticmethod
    def _checkable(lane: Lane) -> bool:
        return not lane.finished and lane.state not in (LaneState.PAUSED, LaneState.TAKEOVER)

    # ------------------------------------------------------------------ the hint judge

    def _gate(self, lane: Lane, signal: Signal) -> tuple[Signal | None, Technique | None]:
        """A rules HINT signal, as the judge would have it, and the technique to ask the judge
        about (None: no need). With no recent verdict the signal is raised (or an open alert
        kept, with any note it had) at once, as the rules have it, and the judge is asked. A
        verdict that the lane follows the hint keeps it down, open or not (None); one that it
        does not raises it; no verdict raises it saying it is unconfirmed."""
        assert self.judge is not None
        verdict = self.judge.recent(lane)
        if verdict is None:
            if signal.technique is None:
                raise RuntimeError("a HINT signal must name its technique for the hint judge (Signal.technique)")
            note = self._unconfirmed.get(lane.id) if lane.alert(AlertKind.HINT) is not None else None
            if note is None:
                self._unconfirmed.pop(lane.id, None)
                return signal, signal.technique
            return replace(signal, reason=f"{signal.reason} {note}"), signal.technique
        if verdict.confirmed is False:
            self._unconfirmed.pop(lane.id, None)
            return None, None
        if verdict.confirmed is True:
            self._unconfirmed.pop(lane.id, None)
            return signal, None
        note = f"Not confirmed: {quote(verdict.reason, 200)}."
        self._unconfirmed[lane.id] = note
        return replace(signal, reason=f"{signal.reason} {note}"), None

    def _consult(self, lane_id: str, challenge: Challenge, technique: Technique) -> None:
        if lane_id in self._judging:
            return  # already asked; its answer settles the lane's alert
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            raise RuntimeError(
                "the Watch's hint judge is asked on the deck's event loop, and no event loop is running "
                "in this thread: call the deck from its loop, or make the Watch without a judge"
            ) from None
        self._judging[lane_id] = loop.create_task(self._ask(lane_id, challenge, technique))

    async def _ask(self, lane_id: str, challenge: Challenge, technique: Technique) -> None:
        assert self.judge is not None
        lane = self.deck.lanes.get(lane_id)
        try:
            if lane is None or lane.finished:
                return
            try:
                await self.judge.judge(lane, challenge, technique, deck=self.deck)
            except Exception as exc:  # the light engine answers its own failures; this is a bug or a closed client
                self.judge.failed(lane, f"the hint judge failed: {type(exc).__name__}: {exc}", deck=self.deck)
        finally:
            self._judging.pop(lane_id, None)
        # Once the judge has recorded an outcome (a judge that left none is not asked again
        # until the next turn), settle the alert raised meanwhile.
        if self._unsubscribe is not None and self.judge.recent(lane) is not None:
            self._settle(lane_id)

    def _settle(self, lane_id: str) -> None:
        """The judge's verdict is in for an alert raised as the rules had it: check the lane's
        hint again, so the verdict applies at once (taken down, confirmed, or marked unconfirmed).
        A lane that is paused or taken over gets it at its next turn."""
        self._run(lane_id, only=AlertKind.HINT)

    async def aclose(self) -> None:
        """Close the hint judge's light model, if there is one (after the lanes stopped)."""
        if self.judge is not None:
            await self.judge.aclose()
