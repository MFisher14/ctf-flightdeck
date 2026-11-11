"""The Watch raises, refreshes and clears detector alerts through a real Deck, and holds an
alert quiet for a few turns after the player answers it. A recording driver stands in for
lane work; the deck and the Watch are the real thing, never mocked."""

from __future__ import annotations

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import AlertKind, Challenge, DeckConfig, LaneState
from ctf_flightdeck.detect.base import DetectConfig
from ctf_flightdeck.detect.detectors import default_detectors
from ctf_flightdeck.detect.watch import Watch

MODELS = ("small", "big")


class Clock:
    def __init__(self) -> None:
        self.t = 100.0

    def now(self) -> float:
        return self.t


class RecDriver:
    """Records what the deck asks of it and does no work."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def attach(self, deck) -> None:
        self.deck = deck

    def start(self, lane, challenge) -> None:
        self.calls.append(("start", lane.id))

    def __getattr__(self, name):  # pause/resume/hint/redirect/escalate/approved/rejected/declined/stop
        def record(*args, **kwargs):
            self.calls.append((name, args))

        return record


def harness(config: DetectConfig | None = None, *, category="misc", points=500, solves=0, description=""):
    clock, driver = Clock(), RecDriver()
    deck = Deck(
        DeckConfig(event="t", flag_format=r"t\{\w+\}", models=MODELS, max_lanes=4),
        driver,
        clock,
        verify=lambda cid, flag: False,
    )
    deck.release(
        [Challenge("c1", "Test", category, points, solves=solves, description=description)],
        [QueueEntry("c1", "small")],
    )
    watch = Watch(deck, default_detectors(config), config)
    detach = watch.attach()
    return deck, watch, detach


def run_step(deck: Deck, command: str, output: str = "") -> None:
    deck.report("L01", TurnReport(action=command, output=output, turn=True))


# ---------------------------------------------------------------------- raise / refresh / clear


def test_watch_raises_a_loop_alert_after_the_third_repeat():
    deck, _watch, _detach = harness()
    lane = deck.lanes["L01"]
    run_step(deck, "$ run x")
    run_step(deck, "$ run x")
    assert lane.alert(AlertKind.LOOP) is None
    run_step(deck, "$ run x")
    alert = lane.alert(AlertKind.LOOP)
    assert alert is not None and "3 times" in alert.reason


def test_watch_refreshes_the_reason_and_keeps_the_raise_time():
    deck, _watch, _detach = harness()
    lane = deck.lanes["L01"]
    for _ in range(3):
        run_step(deck, "$ run x")
    first = lane.alert(AlertKind.LOOP)
    assert first is not None and "3 times" in first.reason
    run_step(deck, "$ run x")  # a fourth repeat: same alert, new count
    second = lane.alert(AlertKind.LOOP)
    assert second is not None and "4 times" in second.reason
    assert second.at == first.at  # refreshed in place, not re-raised


def test_watch_clears_the_alert_once_the_loop_breaks():
    deck, _watch, _detach = harness()
    lane = deck.lanes["L01"]
    for _ in range(3):
        run_step(deck, "$ run x")
    assert lane.alert(AlertKind.LOOP) is not None
    for i in range(4):  # four distinct commands push the repeats out of the window
        run_step(deck, f"$ different {i}")
    assert lane.alert(AlertKind.LOOP) is None


# ---------------------------------------------------------------------- the quiet period


def test_watch_stays_quiet_for_quiet_turns_after_the_player_answers():
    cfg = DetectConfig(quiet_turns=3)
    deck, _watch, _detach = harness(cfg)
    lane = deck.lanes["L01"]
    for _ in range(3):
        run_step(deck, "$ loop")
    assert lane.alert(AlertKind.LOOP) is not None
    assert deck.apply(iv.Hint("L01", "stop repeating that")).ok
    assert lane.alert(AlertKind.LOOP) is None  # the hint cleared it
    run_step(deck, "$ loop")  # turn 4: loop still holds, but it was just answered
    assert lane.alert(AlertKind.LOOP) is None
    run_step(deck, "$ loop")  # turn 5: still within the quiet window
    assert lane.alert(AlertKind.LOOP) is None
    run_step(deck, "$ loop")  # turn 6: the quiet window has passed
    assert lane.alert(AlertKind.LOOP) is not None


def test_a_non_answering_intervention_does_not_start_a_quiet_period():
    deck, _watch, _detach = harness()
    lane = deck.lanes["L01"]
    for _ in range(3):
        run_step(deck, "$ loop")
    assert lane.alert(AlertKind.LOOP) is not None
    # Pause does not clear the course alert, so it is not "answered"; but a paused lane is
    # not checked, so the alert simply stays until the lane runs again.
    assert deck.apply(iv.Pause("L01")).ok
    assert lane.alert(AlertKind.LOOP) is not None
    assert deck.apply(iv.Resume("L01")).ok
    run_step(deck, "$ loop")  # back to running: the loop still holds and is refreshed, not suppressed
    assert lane.alert(AlertKind.LOOP) is not None


# ---------------------------------------------------------------------- lanes that are not checked


def test_paused_and_taken_over_lanes_are_not_checked():
    deck, _watch, _detach = harness()
    lane = deck.lanes["L01"]
    run_step(deck, "$ loop")
    run_step(deck, "$ loop")
    assert deck.apply(iv.Pause("L01")).ok
    run_step(deck, "$ loop")  # a third repeat, but the lane is paused
    assert lane.alert(AlertKind.LOOP) is None
    assert deck.apply(iv.Resume("L01")).ok and lane.state is LaneState.RUNNING
    run_step(deck, "$ loop")  # now running: the window still holds four repeats
    assert lane.alert(AlertKind.LOOP) is not None


def test_detach_stops_the_watch():
    deck, watch, detach = harness()
    lane = deck.lanes["L01"]
    with pytest.raises(RuntimeError):
        watch.attach()  # already attached: re-attaching is refused
    detach()
    for _ in range(4):  # four repeats that would raise a loop if the watch were still listening
        run_step(deck, "$ run y")
    assert lane.alert(AlertKind.LOOP) is None
