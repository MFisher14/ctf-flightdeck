"""The Watch raises, refreshes and clears detector alerts through a real Deck, and holds an
alert quiet for a few turns after the player answers it. A recording driver stands in for
lane work; the deck and the Watch are the real thing, never mocked."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from ctf_flightdeck.agent.tools import Toolbox
from ctf_flightdeck.agent.workspace import HostWorkspace
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


def harness(config: DetectConfig | None = None, *, category="misc", points=500, solves=0, description="",
            files: tuple[str, ...] = (), submit: str = "confirm"):
    clock, driver = Clock(), RecDriver()
    deck = Deck(
        DeckConfig(event="t", flag_format=r"t\{\w+\}", models=MODELS, max_lanes=4, submit=submit),
        driver,
        clock,
        verify=lambda cid, flag: False,
    )
    deck.release(
        [Challenge("c1", "Test", category, points, solves=solves, description=description, files=files)],
        [QueueEntry("c1", "small")],
    )
    watch = Watch(deck, default_detectors(config), config)
    detach = watch.attach()
    return deck, watch, detach


def run_step(deck: Deck, command: str, output: str = "", **report) -> None:
    deck.report("L01", TurnReport(action=command, output=output, turn=True, **report))


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


def test_a_taken_over_lane_is_not_checked():
    deck, _watch, _detach = harness()
    lane = deck.lanes["L01"]
    run_step(deck, "$ loop")
    run_step(deck, "$ loop")
    assert deck.apply(iv.TakeOver("L01")).ok and lane.state is LaneState.TAKEOVER
    run_step(deck, "$ loop")  # the turn the take-over cut short still reports, as a turn
    assert lane.alert(AlertKind.LOOP) is None
    assert deck.apply(iv.HandBack("L01")).ok and lane.state is LaneState.RUNNING
    run_step(deck, "$ loop")
    assert lane.alert(AlertKind.LOOP) is not None


# ---------------------------------------------------------------------- what the real tools report


def test_distinct_silent_commands_through_the_real_toolbox_are_not_a_loop(tmp_path: Path):
    # The Toolbox reports a command that printed nothing as "(no output)", so four different
    # setup commands came back with the same output text. Harmless commands in a scratch folder.
    async def results():
        handout = tmp_path / "handout"
        handout.mkdir()
        workspace = HostWorkspace(tmp_path / "lane", handout)
        await workspace.prepare()
        box = Toolbox(workspace)
        commands = ["mkdir -p work", "touch work/notes.txt", "cp work/notes.txt work/copy.txt", "chmod 600 work/copy.txt"]
        try:
            return [await box.call("shell", json.dumps({"command": c}), turn=i + 1, index=0) for i, c in enumerate(commands)]
        finally:
            await workspace.close()

    deck, _watch, _detach = harness()
    lane = deck.lanes["L01"]
    for result in asyncio.run(results()):
        assert result.output == "(no output)"
        run_step(deck, result.action, result.output)
    assert lane.turns == 4 and lane.alert(AlertKind.LOOP) is None


HISS = "A numbers station. Mostly hiss, but there is a picture in it if you scan it slowly enough."


def test_hint_comes_back_after_the_quiet_period_when_a_redirect_did_not_take():
    # Answering HINT with its own redirect prefill makes the player's words the lane's plan:
    # they are no sign the lane decodes SSTV, so once the quiet period is over the alert returns.
    deck, _watch, _detach = harness(DetectConfig(quiet_turns=3), category="for", description=HISS)
    lane = deck.lanes["L01"]
    for i in range(5):
        run_step(deck, f"$ python3 diff_channels.py --try {i} left.wav right.wav", f"max |L-R| = 0.00{i}")
    alert = lane.alert(AlertKind.HINT)
    assert alert is not None and lane.turns == 5
    prefill = next(s.text for s in alert.suggestions if s.key == "r")
    assert "SSTV" in prefill
    assert deck.apply(iv.Redirect("L01", prefill)).ok and lane.alert(AlertKind.HINT) is None
    for i in range(5, 7):  # turns 6 and 7: quiet
        run_step(deck, f"$ python3 diff_channels.py --try {i} left.wav right.wav", "max |L-R| = 0.01")
        assert lane.alert(AlertKind.HINT) is None
    run_step(deck, "$ python3 diff_channels.py --try 7 left.wav right.wav", "max |L-R| = 0.01")  # turn 8
    assert lane.alert(AlertKind.HINT) is not None
    # once the lane does decode SSTV, the alert clears
    run_step(deck, "$ sstv -d hiss.wav -o out.png", "decoded")
    assert lane.alert(AlertKind.HINT) is None


def test_every_call_of_a_turn_reported_as_a_step_counts_in_the_turn_windows():
    # What the detectors see once the driver reports each tool call of a turn as its own step
    # (the first with the turn, the others right after it, in the same turn).
    deck, _watch, _detach = harness(category="for", description=HISS)
    lane = deck.lanes["L01"]
    run_step(deck, "$ file hiss.wav", "RIFF WAVE audio")
    deck.report("L01", TurnReport(action="$ sstv -d hiss.wav -o out.png", output="decoded 40%", turn=False))
    for turn in range(2, 9):  # seven more turns of three calls each, none of them SSTV
        run_step(deck, f"$ ls part{turn}", "part.wav")
        for call in ("$ xxd part.wav | head -2", "$ file part.wav"):
            deck.report("L01", TurnReport(action=call, output=f"turn {turn}", turn=False))
    assert lane.turns == 8 and lane.alert(AlertKind.HINT) is None  # SSTV ran in turn 1: within 8 turns
    run_step(deck, "$ ls part9", "part.wav")  # turn 9: the SSTV call has left the window
    assert lane.alert(AlertKind.HINT) is not None


def test_direction_through_the_deck_sees_a_compound_source_read():
    deck, _watch, _detach = harness(category="Web Exploitation", files=("app.py", "requirements.txt"))
    lane = deck.lanes["L01"]
    run_step(deck, "$ cd /work && cat app.py", "from flask import Flask")
    for command in ("$ ffuf -w raft.txt -u $T/FUZZ", "$ gobuster dir -u $T -w big.txt", "$ feroxbuster -u $T"):
        run_step(deck, command, "...")
    assert lane.alert(AlertKind.DIRECTION) is None
    other, _watch2, _detach2 = harness(category="Web Exploitation", files=("app.py", "requirements.txt"))
    for command in ("$ ffuf -w raft.txt -u $T/FUZZ", "$ gobuster dir -u $T -w big.txt", "$ feroxbuster -u $T"):
        run_step(other, command, "...")
    assert other.lanes["L01"].alert(AlertKind.DIRECTION) is not None


def test_effort_is_not_raised_on_the_first_turn_of_a_zero_point_challenge():
    deck, _watch, _detach = harness(points=0, solves=0)
    lane = deck.lanes["L01"]
    run_step(deck, "$ ls", "README.txt", tokens=2_000)
    assert lane.alert(AlertKind.EFFORT) is None
    for i in range(7):
        run_step(deck, f"$ cat part{i}", f"part {i}", tokens=1_000)
    assert lane.turns == 8 and lane.alert(AlertKind.EFFORT) is not None  # the 8-turn floor


# ---------------------------------------------------------------------- stall, dated through the deck


def first_stall(*reports: dict) -> int | None:
    """The turn STALL is first raised, for a lane that reports these turns then nothing new."""
    deck, _watch, _detach = harness(points=10_000, submit="auto")  # a wrong flag keeps the lane running
    lane = deck.lanes["L01"]
    for i, extra in enumerate(list(reports) + [{}] * 15, start=1):
        run_step(deck, f"$ step {i}", f"out {i}", **extra)
        assert lane.state is LaneState.RUNNING
        if lane.alert(AlertKind.STALL) is not None:
            return lane.turns
    return None


def test_stall_comes_stall_turns_after_a_plan_set_in_the_first_turn():
    assert first_stall({"plan": "A"}) == 11


def test_stall_comes_stall_turns_after_a_candidate_flag():
    assert first_stall({}, {}, {"flag": "t{guess}"}) == 13  # the deck notes the flag after the turn's event


def test_stall_comes_stall_turns_after_a_plan_change():
    assert first_stall({}, {}, {"plan": "B"}) == 13
    assert first_stall() == 10  # nothing ever: ten idle turns from the start
