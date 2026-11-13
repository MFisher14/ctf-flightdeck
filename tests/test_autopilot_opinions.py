"""Autopilot's second and third opinion on a timer (`[autopilot] second_after`, `third_after`):
a fork onto another ladder model, by rule, once per challenge. On test_autopilot.py's World: a
real deck, a recording driver and a manual clock; each test calls Autopilot.step() where a
run's event loop would (the last one checks the timer that wakes it on a loop)."""

from __future__ import annotations

import asyncio

import pytest

from ctf_flightdeck.autopilot import Autopilot, Budget, State, start_notes
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import Actor, ChallengeStatus, EventKind, Pending, PendingKind
from ctf_flightdeck.platform.manual import load_board
from ctf_flightdeck.postflight import report, summary

from test_autopilot import World, ch, engaged
from test_postflight import FLAGS, Script, write_board


def on(world: World, cid: str) -> list[tuple[str, str, str | None]]:
    """The open lanes on a challenge: (lane id, model, the lane it was forked from)."""
    return [(lane.id, lane.model, lane.parent) for lane in world.deck.lanes_on(cid)]


def at(world: World, seconds: float) -> None:
    world.clock.advance(seconds - world.deck.now)
    world.pilot.step()


def forks(world: World):
    return world.events(EventKind.INTERVENTION, intervention="fork")


# ---------------------------------------------------------------------- the second opinion


def test_off_by_default_no_lane_is_forked_however_long_it_runs():
    world = engaged()
    assert (world.pilot.second_after, world.pilot.third_after) == (0, 0)
    world.release(ch("a"))
    at(world, 100_000)
    assert on(world, "a") == [("L01", "small", None)] and not forks(world)


def test_the_second_opinion_comes_at_the_time_on_the_next_rung_and_only_once():
    world = engaged(second_after=180)
    world.release(ch("a"))
    at(world, 179)
    assert on(world, "a") == [("L01", "small", None)]  # not before its time
    at(world, 180)
    assert on(world, "a") == [("L01", "small", None), ("L02", "mid", "L01")]
    (fork,) = forks(world)
    assert fork.data["by"] == "autopilot" and fork.data["model"] == "mid" and fork.lane == "L01"  # told apart from the player (P28)
    notes = [action.text for action in world.deck.lanes["L01"].actions]
    assert "autopilot: a second opinion, on mid: L01 has run 180 s on small without a solve" in notes
    assert "forked to L02 (mid)" in notes
    world.deck.apply(iv.Kill("L02", requeue=False), by=Actor.AUTOPILOT)
    at(world, 5000)  # one lane again, long past the time: the challenge has had its second opinion
    assert len(forks(world)) == 1


def test_the_timer_runs_from_the_lanes_own_start():
    world = engaged(second_after=180, max_lanes=1)
    world.release(ch("a", 100), ch("b", 200))  # one slot: b starts when a's lane ends
    at(world, 170)
    world.deck.report("L01", TurnReport(flag="t{a}"))
    world.deck.apply(iv.Approve("L01"))  # the player's yes ...
    world.deck.apply(iv.Approve("L01"))  # ... and the hand submit is confirmed: a is solved, b starts at 170
    assert world.deck.challenges["a"].status is ChallengeStatus.SOLVED and on(world, "b") == [("L02", "small", None)]
    assert world.pilot.engaged  # the player's answer leaves an engaged autopilot engaged
    at(world, 349)
    assert not forks(world)
    at(world, 350)
    assert [event.lane for event in forks(world)] == ["L02"]


@pytest.mark.parametrize(("ladder", "model", "expected"), [
    (("small", "mid", "big"), "small", "mid"),  # the next rung up
    (("small", "mid", "big"), "mid", "big"),
    (("small", "mid", "big"), "big", "small"),  # at the top: another model of the ladder
    (("small", "big"), "big", "small"),
])
def test_the_second_opinion_is_on_a_different_model(ladder, model, expected):
    world = engaged(second_after=60, models=ladder)
    world.release(ch("a"), model=model)
    at(world, 60)
    assert on(world, "a") == [("L01", model, None), ("L02", expected, "L01")]


def test_with_a_one_model_ladder_the_rule_does_nothing_and_says_so_once_at_engage():
    world = World(second_after=60, third_after=120, models=("only",))
    assert world.pilot.engage().ok
    (said,) = world.warnings("no_opinion")
    assert said.text == ("autopilot: second_after is set, but the model ladder has 1 model and a second opinion needs another "
                         "model: autopilot gives no second opinion (nor a third) in this run")
    assert said.data == {"autopilot": "no_opinion", "which": "second", "models": 1}
    world.release(ch("a"), model="only")
    at(world, 500)
    assert on(world, "a") == [("L01", "only", None)] and not forks(world)
    world.pilot.off()
    assert world.pilot.engage().ok
    assert len(world.warnings("no_opinion")) == 1  # once


def test_a_ladder_long_enough_says_nothing_at_engage():
    world = engaged(second_after=60, third_after=120)
    assert not world.warnings("no_opinion")


def test_the_first_rejected_flag_brings_the_second_opinion_at_once():
    world = World(second_after=180, submit="auto", platform=True)
    world.pilot.engage()
    world.release(ch("a"))
    at(world, 10)
    world.deck.report("L01", TurnReport(flag="t{no}"))
    assert world.sent == [("L01", "a", "t{no}")]
    world.pilot.step()
    assert not forks(world)  # the flag is on its way: nothing until the platform has answered
    world.deck.platform_verdict("L01", "t{no}", False, "Incorrect")
    world.pilot.step()
    assert on(world, "a") == [("L01", "small", None), ("L02", "mid", "L01")]  # at 10 s, not 180
    assert "autopilot: a second opinion, on mid: a flag of L01 was wrong" in [a.text for a in world.deck.lanes["L01"].actions]


def test_a_right_flag_brings_no_second_opinion():
    world = World(second_after=180, submit="auto", platform=True)
    world.pilot.engage()
    world.release(ch("a"))
    world.deck.report("L01", TurnReport(flag="t{yes}"))
    world.deck.platform_verdict("L01", "t{yes}", True, "Correct")
    at(world, 1000)
    assert not forks(world) and world.deck.challenges["a"].status is ChallengeStatus.SOLVED


def test_no_second_opinion_when_two_lanes_are_already_on_the_challenge():
    world = engaged(second_after=180)
    world.release(ch("a"))
    world.deck.apply(iv.Fork("L01", model="big"), by=Actor.AUTOPILOT)  # a second lane, however it came
    before = len(forks(world))
    at(world, 1000)
    assert len(forks(world)) == before and len(on(world, "a")) == 2


def test_no_second_opinion_once_disengaged_or_switched_off():
    world = engaged(second_after=180)
    world.release(ch("a"))
    world.pilot.disengage("a test says so")
    at(world, 1000)
    assert world.pilot.state is State.DISENGAGED and not forks(world)
    world.pilot.off()
    at(world, 2000)
    assert not forks(world)


def test_no_second_opinion_once_the_run_budget_is_spent():
    world = engaged(second_after=180, budget=Budget(tokens=5000))
    world.release(ch("a"))
    world.turn("L01", tokens=5000)
    at(world, 1000)
    assert world.pilot.state is State.DISENGAGED and "the run budget is reached" in world.pilot.reason
    assert not forks(world) and len(world.deck.lanes) == 1


def test_no_second_opinion_while_the_queue_is_held():
    world = engaged(second_after=180)
    world.release(ch("a"))
    world.deck.hold_queue("the key was refused")
    at(world, 1000)
    assert not forks(world)


@pytest.mark.parametrize("how", ["paused", "taken over", "flag waits", "live box", "gave up with a flag"])
def test_a_lane_that_is_the_players_is_not_forked(how):
    world = engaged(second_after=180)
    world.release(ch("a"))
    if how == "paused":
        world.deck.apply(iv.Pause("L01"))
    elif how == "taken over":
        world.deck.apply(iv.TakeOver("L01"))
    elif how == "flag waits":
        world.deck.report("L01", TurnReport(flag="t{maybe}"))
    elif how == "live box":
        world.deck.report("L01", TurnReport(pending=Pending(PendingKind.LIVE_BOX, "use the live box")))
    else:
        world.deck.report("L01", TurnReport(flag="t{maybe}", gave_up="out of ideas"))
        assert world.deck.lanes["L01"].gave_up_later
    at(world, 1000)
    assert world.pilot.engaged and not forks(world) and len(world.deck.lanes) == 1


def test_a_lane_freed_again_gets_its_second_opinion_then():
    world = World(second_after=180, submit="auto", platform=True)
    world.pilot.engage()
    world.release(ch("a"))
    world.deck.report("L01", TurnReport(flag="t{scraped}", claimed=False))  # waits for the player
    at(world, 1000)
    assert not forks(world)
    world.deck.apply(iv.Decline("L01"))  # the player answers: the lane carries on, and autopilot is still engaged
    world.pilot.step()
    assert [event.lane for event in forks(world)] == ["L01"]


def test_a_solved_blocked_or_teammates_challenge_gets_none():
    world = engaged(second_after=180)
    world.release(ch("a"), ch("b"))
    world.deck.challenges["a"].status = ChallengeStatus.BLOCKED
    world.deck.challenges["b"].claimed_by = "ana"
    at(world, 1000)
    assert not forks(world)


def test_with_no_free_slot_the_fork_is_queued_first_and_not_asked_for_again():
    world = engaged(second_after=180, max_lanes=1)
    world.release(ch("a", 100), ch("b", 200))
    at(world, 180)
    (fork,) = forks(world)
    (outcome,) = world.events(EventKind.OUTCOME, intervention="fork")
    assert outcome.data["ok"] is True and outcome.data["message"] == "Fork of L01 (mid) is first in the queue; all 1 lanes are busy"
    assert [(entry.challenge, entry.model, entry.parent) for entry in world.deck.queue][0] == ("a", "mid", "L01")
    at(world, 400)
    assert len(forks(world)) == 1


# ---------------------------------------------------------------------- the third


def test_the_third_opinion_comes_at_its_time_on_a_model_neither_lane_runs_and_only_once():
    world = engaged(second_after=180, third_after=480)
    world.release(ch("a"))
    at(world, 180)
    at(world, 479)
    assert len(on(world, "a")) == 2
    at(world, 480)
    assert on(world, "a") == [("L01", "small", None), ("L02", "mid", "L01"), ("L03", "big", "L01")]
    assert [(event.lane, event.data["model"], event.data["by"]) for event in forks(world)] == [
        ("L01", "mid", "autopilot"), ("L01", "big", "autopilot")]
    assert "autopilot: a third opinion, on big: L01 started 480 s ago, and L01 and L02 have no solve" in [
        a.text for a in world.deck.lanes["L01"].actions]
    world.deck.apply(iv.Kill("L03", requeue=False), by=Actor.AUTOPILOT)
    at(world, 5000)
    assert len(forks(world)) == 2  # once


def test_the_third_takes_the_model_left_when_the_two_hold_the_top():
    world = engaged(second_after=60, third_after=120)
    world.release(ch("a"), model="mid")
    at(world, 60)
    at(world, 120)
    assert [model for _, model, _ in on(world, "a")] == ["mid", "big", "small"]


def test_the_third_needs_a_third_model_and_says_so_at_engage():
    world = World(second_after=60, third_after=120, models=("small", "big"))
    assert world.pilot.engage().ok
    (said,) = world.warnings("no_opinion")
    assert said.text == ("autopilot: third_after is set, but the model ladder has 2 models and a third opinion needs a third "
                         "model: autopilot gives no third opinion in this run")
    world.release(ch("a"))
    at(world, 60)
    at(world, 500)
    assert [model for _, model, _ in on(world, "a")] == ["small", "big"]  # the second came, no third


def test_the_third_alone_follows_a_second_lane_the_player_forked():
    world = World(third_after=300)
    world.release(ch("a"))
    world.deck.apply(iv.Fork("L01", model="big"))  # the player's own second lane
    world.pilot.engage()
    at(world, 299)
    assert len(on(world, "a")) == 2
    at(world, 300)
    assert on(world, "a")[-1] == ("L03", "mid", "L01")


def test_no_third_while_one_of_the_two_lanes_waits_for_the_player():
    world = engaged(second_after=60, third_after=120)
    world.release(ch("a"))
    at(world, 60)
    world.deck.report("L02", TurnReport(flag="t{maybe}"))  # under submit confirm: it waits for the player
    at(world, 1000)
    assert len(forks(world)) == 1


# ---------------------------------------------------------------------- validation, notes, the report, the loop


@pytest.mark.parametrize(("bad", "problem"), [
    ({"second_after": -1}, "second_after must be a whole number of seconds, 0 or more"),
    ({"second_after": 1.5}, "second_after must be a whole number of seconds, 0 or more"),
    ({"third_after": True}, "third_after must be a whole number of seconds, 0 or more"),
    ({"second_after": 180, "third_after": 180}, r"third_after \(180\) must be more than second_after \(180\)"),
    ({"second_after": 180, "third_after": 90}, r"third_after \(90\) must be more than second_after \(180\)"),
])
def test_bad_timers_are_refused(bad, problem):
    world = World()
    with pytest.raises(ValueError, match=problem):
        Autopilot(world.deck, Budget(dollars=1.0), **bad)


def test_the_start_notes_say_the_opinions_only_when_they_are_set():
    common = dict(submit="confirm", spends_tries=False, instance="auto", budget=Budget(dollars=5.0), waves=False,
                  refusal_fallback=False, agent=None)
    assert not any("opinion" in line for line in start_notes(None, **common))
    both = start_notes(None, **common, second_after=180, third_after=480)
    assert ("autopilot: more opinions by rule, each once per challenge: a second lane on another model of the ladder once a "
            "challenge's only lane has run 180 s unsolved, or at once when a flag of it is judged wrong; a third lane on a "
            "third model once the first of two lanes has run 480 s") in both
    (third,) = [line for line in start_notes(None, **common, third_after=480) if "opinion" in line]
    assert "second lane" not in third and "480 s" in third


def test_the_post_flight_report_counts_the_fork_as_autopilots_never_as_the_players(tmp_path):
    board = load_board(write_board(tmp_path / "board"))
    run = Script(tmp_path / "run", flags=FLAGS, max_lanes=4)
    pilot = Autopilot(run.deck, Budget(tokens=1_000_000), second_after=180)
    pilot.attach()
    assert pilot.engage().ok
    run.release([b.challenge for b in board.challenges], ["alpha"])
    alpha = run.lane("alpha")
    run.at(10)
    run.turn(alpha, "ls")
    run.at(180)
    pilot.step()
    record = run.close()
    text = report(record)
    assert "## Interventions\n\nNo interventions in this run.\n" in text
    section = text.split("## Autopilot\n", 1)[1].split("\n## ", 1)[0]
    assert "Autopilot made 1 intervention by rule (0 refused)" in section
    assert f"autopilot: fork {alpha} on " in section and f"→ Forked {alpha} → L02 on " in section
    assert "you: " not in section
    assert "Autopilot: 1 intervention by rule" in summary(record)


def test_on_a_running_event_loop_a_timer_brings_the_second_opinion_with_no_event_to_wake_it():
    async def play() -> World:
        world = engaged(second_after=1)
        world.release(ch("a"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)  # autopilot has looked: nothing is due, and its alarm is set for 1 s from now
        assert not forks(world)
        world.clock.advance(1)  # the deck's clock moves on; no deck event tells autopilot
        await asyncio.sleep(1.3)
        return world

    world = asyncio.run(play())
    assert on(world, "a") == [("L01", "small", None), ("L02", "mid", "L01")]


def test_the_alarm_is_dropped_when_autopilot_is_switched_off():
    async def play() -> World:
        world = engaged(second_after=1)
        world.release(ch("a"))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        world.pilot.off()
        world.clock.advance(5)
        await asyncio.sleep(1.3)
        return world

    world = asyncio.run(play())
    assert not forks(world) and world.pilot.state is State.OFF
