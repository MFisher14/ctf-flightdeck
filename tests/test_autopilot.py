"""Autopilot (M5, D20) on a real deck: its rules, its guardrails and every way it disengages.

A recording driver stands in for lane work and a manual clock moves time, as in
test_postflight.py. No event loop runs in these tests, so each one calls Autopilot.step()
where a run's loop would (the last test checks that a running loop does it on its own).
"""

from __future__ import annotations

import asyncio

import pytest

from ctf_flightdeck.autopilot import NEEDS_BUDGET, NEEDS_DOCKER, Autopilot, Budget, State, start_notes
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import (
    Actor,
    Alert,
    AlertKind,
    Challenge,
    ChallengeStatus,
    DeckConfig,
    EventKind,
    LaneState,
    Pending,
    PendingKind,
    Suggestion,
)
from ctf_flightdeck.mock.world import ManualClock

LADDER = ("small", "mid", "big")
FLAG_FORMAT = r"t\{[^{}]+\}"


class RecordingDriver:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def attach(self, deck):
        self.deck = deck

    def start(self, lane, challenge):
        self.calls.append(("start", lane.id, challenge.id, lane.model))

    def pause(self, lane):
        self.calls.append(("pause", lane.id))

    def resume(self, lane):
        self.calls.append(("resume", lane.id))

    def hint(self, lane, text):
        self.calls.append(("hint", lane.id, text))

    def redirect(self, lane, text):
        self.calls.append(("redirect", lane.id, text))

    def escalate(self, lane, model, summary):
        self.calls.append(("escalate", lane.id, model))

    def approved(self, lane, pending):
        self.calls.append(("approved", lane.id, pending.kind))

    def rejected(self, lane, flag):
        self.calls.append(("rejected", lane.id, flag))

    def declined(self, lane, pending):
        self.calls.append(("declined", lane.id, pending.kind))

    def stop(self, lane):
        self.calls.append(("stop", lane.id))


class World:
    """A deck with an autopilot attached (off until a test engages it)."""

    def __init__(self, *, budget=Budget(dollars=10.0), submit="confirm", submit_limited="confirm", containerized=True,
                 platform=False, max_lanes=4, models=LADDER, verify=lambda cid, flag: None, **rules) -> None:
        self.driver = RecordingDriver()
        self.sent: list[tuple[str, str, str]] = []  # what the deck handed to the platform's submitter
        self.refusals: list[bool] = []
        config = DeckConfig(event="test", max_lanes=max_lanes, flag_format=FLAG_FORMAT, models=models, submit=submit,
                            submit_limited=submit_limited, containerized=containerized)
        submitter = (lambda lane, cid, flag: self.sent.append((lane, cid, flag))) if platform else None
        self.clock = ManualClock(0.0)
        self.deck = Deck(config, self.driver, self.clock, verify, submitter=submitter)
        self.pilot = Autopilot(self.deck, budget, refusals=self.refusals.append, **rules)  # second_after, third_after
        self.pilot.attach()

    def release(self, *challenges: Challenge, model="small", **caps) -> None:
        self.deck.release(list(challenges), [QueueEntry(ch.id, model, **caps) for ch in challenges])

    def lane(self, cid: str):
        (lane,) = self.deck.lanes_on(cid)
        return lane

    def turn(self, lane_id: str, **more) -> None:
        self.deck.report(lane_id, TurnReport(action="step", tokens=more.pop("tokens", 1000), dollars=more.pop("dollars", 0.01), **more))

    def alert(self, lane_id: str, kind: AlertKind, *suggestions: Suggestion) -> None:
        self.deck.report(lane_id, TurnReport(turn=False, alerts=(Alert(kind, f"a {kind.value} reason", tuple(suggestions)),)))

    def events(self, kind: EventKind, **data):
        return [e for e in self.deck.events if e.kind is kind and all(e.data.get(k) == v for k, v in data.items())]

    def warnings(self, what: str):
        return self.events(EventKind.WARNING, autopilot=what)


def ch(cid: str, points: int = 100, **more) -> Challenge:
    return Challenge(cid, cid.title(), "misc", points, **more)


def engaged(**options) -> World:
    world = World(**options)
    assert world.pilot.engage().ok
    return world


# ---------------------------------------------------------------------- engaging


def test_engaging_needs_a_run_budget_and_says_so():
    world = World(budget=Budget())
    world.release(ch("a"))
    outcome = world.pilot.engage()
    assert (outcome.ok, outcome.message) == (False, f"Autopilot not engaged: {NEEDS_BUDGET}")
    assert world.pilot.state is State.OFF and not world.warnings("engaged")
    world.alert(world.lane("a").id, AlertKind.LOOP)
    world.pilot.step()
    assert world.lane("a").state is LaneState.RUNNING  # off: no rule acts


def test_engaging_needs_the_docker_runtime_and_says_why():
    world = World(containerized=False)
    outcome = world.pilot.engage()
    assert (outcome.ok, outcome.message) == (False, f"Autopilot not engaged: {NEEDS_DOCKER}")
    assert not world.pilot.guarding


def test_engaging_is_refused_while_the_queue_is_held_and_once_the_budget_is_spent():
    world = World(budget=Budget(tokens=5000))
    world.release(ch("a"))
    world.deck.hold_queue("the key was refused")
    assert world.pilot.engage().message == (
        "Autopilot not engaged: the queue is held (the key was refused): lift the hold first (/unhold), then engage autopilot")
    world.deck.release_hold()
    world.turn(world.lane("a").id, tokens=5000)
    assert world.pilot.engage().message == "Autopilot not engaged: the run budget is reached: 5k of 5k tokens spent"
    assert world.pilot.state is State.OFF


def test_engaging_logs_the_budget_and_switches_the_refusal_fallback_off():
    world = engaged(budget=Budget(dollars=2.5, tokens=40000))
    (event,) = world.warnings("engaged")
    assert event.data == {"autopilot": "engaged", "budget_dollars": 2.5, "budget_tokens": 40000}
    assert event.text == "autopilot engaged: run budget $2.50 and 40k tokens"
    assert world.refusals == [False]  # no refusal is rerouted from now on
    assert world.pilot.engage().message == "Autopilot is already engaged"


@pytest.mark.parametrize("bad", [{"dollars": 0}, {"dollars": -1.0}, {"dollars": float("inf")}, {"tokens": 0}, {"tokens": 2.5}, {"dollars": True}])
def test_a_budget_that_is_no_budget_is_refused(bad):
    with pytest.raises(ValueError, match="the run budget in"):
        Budget(**bad)


# ---------------------------------------------------------------------- the rules


def test_a_lanes_budget_request_is_approved_so_its_cap_creeps_up_and_it_stays_on_its_model():
    """P20 (the maintainer's call): a lane at its own cap gets more, step by step; the run
    budget, not the lane's cap, is what stops the spend."""
    world = engaged(budget=Budget(tokens=100_000))
    world.release(ch("a"), token_cap=1000)
    lane = world.lane("a")
    world.turn(lane.id, tokens=1000)  # at its cap: it asks for more
    assert lane.pending is not None and lane.pending.kind is PendingKind.BUDGET
    world.pilot.step()
    assert lane.pending is None and lane.state is LaneState.RUNNING and lane.model == "small"
    assert lane.token_cap > 1000
    first_raise = lane.token_cap
    world.turn(lane.id, tokens=first_raise - 1000)  # at its new cap: it asks again, and gets more again
    assert lane.pending is not None and lane.pending.kind is PendingKind.BUDGET
    world.pilot.step()
    assert lane.pending is None and lane.token_cap > first_raise
    approvals = world.events(EventKind.INTERVENTION, intervention="approve")
    assert len(approvals) == 2 and all(event.data["by"] == "autopilot" for event in approvals)
    assert [action.text for action in lane.actions if action.text.startswith("approved:")][-1].endswith("(by autopilot)")
    assert len([candidate for candidate in world.deck.lanes.values() if candidate.challenge_id == "a"]) == 1  # no restart


def test_a_lanes_budget_request_waits_for_the_player_once_the_run_budget_is_spent():
    world = engaged(budget=Budget(tokens=1500))
    world.release(ch("a"), token_cap=1000)
    lane = world.lane("a")
    world.turn(lane.id, tokens=1000)  # at its cap, with 500 tokens of run budget left: approved
    world.pilot.step()
    assert lane.pending is None
    world.turn(lane.id, tokens=600)  # past the run budget
    world.pilot.step()
    assert not world.events(EventKind.INTERVENTION, intervention="approve")[1:]  # only the first was approved
    assert not world.pilot.engaged  # the budget disengaged it


def test_a_lane_whose_spend_has_no_price_is_not_given_more_by_autopilot():
    world = engaged(budget=Budget(tokens=100_000))
    world.release(ch("a"), dollar_cap=1.0)
    lane = world.lane("a")
    world.turn(lane.id, tokens=100, dollars=None)  # no price: under a dollar cap it asks the player once (P7)
    assert lane.pending is not None and lane.pending.kind is PendingKind.BUDGET
    refused = world.deck.apply(iv.Approve(lane.id), by=Actor.AUTOPILOT)
    assert not refused.ok and "no known cost" in refused.message
    world.pilot.step()
    assert lane.pending is not None and lane.dollar_cap == 1.0  # it waits for the player


def test_a_looping_lane_is_killed_and_parked_then_taken_up_a_rung():
    world = engaged()
    world.release(ch("a"), ch("b"))
    a, b = world.lane("a"), world.lane("b")
    world.alert(a.id, AlertKind.LOOP)
    world.pilot.step()
    assert (a.state, a.result) == (LaneState.KILLED, "by autopilot; parked")
    assert world.deck.challenges["a"].status is ChallengeStatus.PARKED  # b still runs: no next round yet
    assert b.state is LaneState.RUNNING
    world.deck.report(b.id, TurnReport(turn=False, gave_up="nothing found"))
    world.pilot.step()
    assert {lane.challenge_id: lane.model for lane in world.deck.active_lanes()} == {"a": "mid", "b": "mid"}


def test_effort_out_of_proportion_kills_the_lane_and_its_challenge_goes_round_again_one_rung_up():
    """P23 (the maintainer's call): an effort alert is handled as a loop is."""
    world = engaged()
    world.release(ch("a"))
    lane = world.lane("a")
    world.alert(lane.id, AlertKind.EFFORT)
    world.pilot.step()
    assert (lane.state, lane.result) == (LaneState.KILLED, "by autopilot; parked")
    world.pilot.step()  # the queue is dry and no lane runs: the next round
    (again,) = world.deck.active_lanes()
    assert (again.challenge_id, again.model, again.attempt) == ("a", "mid", 2)


def test_a_stalled_lane_escalates_one_rung_and_at_the_top_is_killed_and_parked():
    world = engaged()
    world.release(ch("a"))
    lane = world.lane("a")
    world.alert(lane.id, AlertKind.STALL)
    world.pilot.step()
    assert lane.model == "mid" and lane.state is LaneState.RUNNING and lane.alert(AlertKind.STALL) is None
    assert ("escalate", lane.id, "mid") in world.driver.calls
    assert lane.actions[-1].by is Actor.AUTOPILOT and lane.actions[-1].text == "escalated small → mid with a summary"
    world.alert(lane.id, AlertKind.STALL)
    world.pilot.step()
    assert lane.model == "big" and lane.state is LaneState.RUNNING  # one rung at a time
    world.alert(lane.id, AlertKind.STALL)
    world.pilot.step()
    assert (lane.state, lane.result) == (LaneState.KILLED, "by autopilot; parked")
    assert world.deck.active_lanes() == [] and not world.deck.queue  # tried on the top rung: nothing goes round again


def test_unsolved_challenges_go_round_again_lowest_points_first_once_per_rung_then_autopilot_idles():
    world = engaged(max_lanes=1)
    world.release(ch("dear", 500), ch("cheap", 50))
    order = []
    for _ in range(12):  # each lane gives up as soon as it starts
        active = world.deck.active_lanes()
        if not active:
            break
        (lane,) = active
        order.append((lane.challenge_id, lane.model))
        world.deck.report(lane.id, TurnReport(turn=False, gave_up="nothing found"))
        world.pilot.step()
    assert order == [
        ("dear", "small"), ("cheap", "small"),  # as the test released them
        ("cheap", "mid"), ("dear", "mid"),  # round two: lowest points first
        ("cheap", "big"), ("dear", "big"),  # round three, the top rung
    ]
    assert not world.deck.queue and world.pilot.engaged  # every challenge tried on the top rung: it idles, still engaged
    queued = [(e.challenge, e.data["model"]) for e in world.events(EventKind.INTERVENTION, intervention="queue")]
    assert sorted(queued) == sorted(set(queued)) and len(queued) == 4  # each challenge at most once per rung
    assert all(e.data["by"] == "autopilot" for e in world.events(EventKind.INTERVENTION, intervention="queue"))


def test_the_next_round_waits_until_the_queue_is_dry_and_no_lane_runs():
    world = engaged(max_lanes=1)
    world.release(ch("a", 10), ch("b", 20))
    world.deck.report(world.lane("a").id, TurnReport(turn=False, gave_up="nothing found"))  # b starts from the queue
    world.pilot.step()
    assert [(lane.challenge_id, lane.model) for lane in world.deck.active_lanes()] == [("b", "small")]
    assert not world.events(EventKind.INTERVENTION, intervention="queue")


def test_a_lane_that_ignores_the_hint_is_redirected_to_the_alerts_suggestion_once():
    world = engaged()
    world.release(ch("a"))
    lane = world.lane("a")
    suggestion = Suggestion("r", "Redirect with the hinted technique", "Follow the description's hint: decode the base64")
    world.alert(lane.id, AlertKind.HINT, suggestion, Suggestion("h", "Hint", "The description points at base64."))
    world.pilot.step()
    assert lane.plan == "Follow the description's hint: decode the base64" and lane.alert(AlertKind.HINT) is None
    assert world.driver.calls.count(("redirect", lane.id, suggestion.text)) == 1
    assert lane.actions[-1].by is Actor.AUTOPILOT and lane.actions[-1].text == f"new plan: {suggestion.text}"
    world.alert(lane.id, AlertKind.HINT, Suggestion("r", "Redirect", "Follow the description's hint: try rot13"))
    world.pilot.step()
    assert lane.plan == suggestion.text and lane.alert(AlertKind.HINT) is not None  # once per lane: the second waits for you
    assert len(world.events(EventKind.INTERVENTION, intervention="redirect")) == 1


def test_a_wrong_way_lane_is_redirected_to_its_suggestion_and_an_alert_with_none_is_left():
    world = engaged()
    world.release(ch("a"), ch("b"))
    a, b = world.lane("a"), world.lane("b")
    world.alert(a.id, AlertKind.DIRECTION, Suggestion("r", "Redirect: read the source", "Read the source in the handout before attacking the instance."))
    world.alert(b.id, AlertKind.DIRECTION, Suggestion("f", "Fork with a source-first approach", "Read the source first"))
    world.pilot.step()
    assert a.plan == "Read the source in the handout before attacking the instance."
    assert b.plan == "" and b.alert(AlertKind.DIRECTION) is not None and b.state is LaneState.RUNNING


def test_no_rule_touches_a_lane_that_is_the_players_or_holds_a_flag():
    world = engaged()
    world.release(ch("paused"), ch("taken"), ch("flag"), ch("box"))
    paused, taken, flag, box = (world.lane(cid) for cid in ("paused", "taken", "flag", "box"))
    world.deck.apply(iv.Pause(paused.id))
    world.deck.apply(iv.TakeOver(taken.id))
    world.deck.report(flag.id, TurnReport(flag="t{maybe}"))
    world.deck.report(box.id, TurnReport(turn=False, pending=Pending(PendingKind.LIVE_BOX, "reach the instance")))
    for lane in (paused, flag, box):
        world.alert(lane.id, AlertKind.LOOP)
    world.pilot.step()
    assert [lane.state for lane in (paused, taken, flag, box)] == [
        LaneState.PAUSED, LaneState.TAKEOVER, LaneState.WAITING, LaneState.WAITING]
    assert flag.pending.flag == "t{maybe}" and box.pending.kind is PendingKind.LIVE_BOX  # nothing was answered for you
    assert not [e for e in world.events(EventKind.INTERVENTION) if e.data.get("by") == "autopilot"]


def test_the_deck_refuses_autopilot_an_approval_and_any_answer_to_a_flag():
    world = engaged()
    world.release(ch("a"))
    lane = world.lane("a")
    world.deck.report(lane.id, TurnReport(flag="t{maybe}"))
    approve = world.deck.apply(iv.Approve(lane.id), by=Actor.AUTOPILOT)
    assert (approve.ok, approve.message) == (
        False, f"Autopilot approves only a lane's budget request, and {lane.id} waits for: submit t{{maybe}}")
    decline = world.deck.apply(iv.Decline(lane.id), by=Actor.AUTOPILOT)
    assert (decline.ok, decline.message) == (False, "Autopilot does not decline: that is the player's to do")
    assert lane.pending is not None and lane.pending.flag == "t{maybe}" and world.deck.not_flag("a", "t{maybe}") is None
    for refused in (iv.TakeOver(lane.id), iv.Hint(lane.id, "x"), iv.Claim("a"), iv.Dismiss(lane.id)):
        assert not world.deck.apply(refused, by=Actor.AUTOPILOT).ok
    with pytest.raises(ValueError, match="by the player or by autopilot"):
        world.deck.apply(iv.Pause(lane.id), by=Actor.LANE)


def test_a_challenge_whose_model_declined_is_never_sent_on_to_another_model():
    world = engaged()
    world.release(ch("a"))
    lane = world.lane("a")
    world.deck.report(lane.id, TurnReport(turn=False, action="small declined", gave_up="the model declined", declined=True))
    world.pilot.step()
    world.pilot.step()
    assert world.deck.active_lanes() == [] and not world.deck.queue
    (said,) = world.warnings("refusal")  # once
    assert said.text == ("small declined A (L01): autopilot sends no refused request on to another model, so it stays "
                         "parked for you")


def test_a_challenge_the_player_parked_stays_parked_until_they_queue_it():
    world = engaged()
    world.release(ch("a"))
    world.deck.apply(iv.Kill(world.lane("a").id, requeue=False))
    world.pilot.step()
    assert world.deck.active_lanes() == [] and not world.deck.queue
    world.deck.apply(iv.Queue("a"))
    lane = world.lane("a")
    assert lane.model == "small"  # the player's queue: the model it had
    world.deck.report(lane.id, TurnReport(turn=False, gave_up="nothing found"))
    world.pilot.step()
    assert world.lane("a").model == "mid"  # back in play, so it goes round again


def test_autopilots_interventions_are_logged_as_its_own_and_the_players_as_before():
    world = engaged()
    world.release(ch("a"), ch("b"))
    world.alert(world.lane("a").id, AlertKind.LOOP)
    world.pilot.step()
    world.deck.apply(iv.Kill(world.lane("b").id, requeue=False))
    mine, theirs = world.events(EventKind.INTERVENTION, intervention="kill")
    assert mine.data == {"intervention": "kill", "lane": "L01", "requeue": False, "by": "autopilot"}
    assert theirs.data == {"intervention": "kill", "lane": "L02", "requeue": False}  # no `by`: as before autopilot
    outcomes = world.events(EventKind.OUTCOME, intervention="kill")
    assert [o.data.get("by") for o in outcomes] == ["autopilot", None]
    assert world.deck.lanes["L02"].result == "by the player; parked"


# ---------------------------------------------------------------------- the run budget


def disengaged(world: World):
    (event,) = world.warnings("disengaged")
    return event


def test_at_the_dollar_budget_autopilot_holds_the_queue_pauses_the_lanes_and_disengages():
    world = engaged(budget=Budget(dollars=1.0), max_lanes=2)
    world.release(ch("a"), ch("b"), ch("c"))
    a, b = world.lane("a"), world.lane("b")
    world.turn(a.id, dollars=0.6)
    world.pilot.step()
    assert world.pilot.engaged and a.state is LaneState.RUNNING  # under the budget
    world.turn(b.id, dollars=0.4)
    world.pilot.step()
    reason = "the run budget is reached: $1.00 of $1.00 spent"
    assert world.pilot.state is State.DISENGAGED and world.pilot.reason == reason
    assert disengaged(world).data == {"autopilot": "disengaged", "reason": reason}
    assert world.deck.held == f"autopilot disengaged: {reason}"
    assert (a.state, b.state) == (LaneState.PAUSED, LaneState.PAUSED)
    assert a.actions[-1].text == "paused by autopilot" and a.actions[-1].by is Actor.AUTOPILOT
    world.deck.report(a.id, TurnReport(turn=False, gave_up="nothing found"))
    world.pilot.step()
    assert [lane.challenge_id for lane in world.deck.active_lanes()] == ["b"]  # no new lane starts: c stays queued
    assert [entry.challenge for entry in world.deck.queue] == ["c"]


def test_at_the_token_budget_autopilot_disengages():
    world = engaged(budget=Budget(tokens=3000))
    world.release(ch("a"))
    world.turn(world.lane("a").id, tokens=2999)
    world.pilot.step()
    assert world.pilot.engaged
    world.turn(world.lane("a").id, tokens=1)
    world.pilot.step()
    assert disengaged(world).data["reason"] == "the run budget is reached: 3k of 3k tokens spent"
    assert world.lane("a").state is LaneState.PAUSED


def test_spend_with_no_price_disengages_under_a_budget_in_dollars_alone():
    world = engaged(budget=Budget(dollars=5.0))
    world.release(ch("a"))
    lane = world.lane("a")
    world.turn(lane.id, dollars=None)
    world.pilot.step()
    assert disengaged(world).data["reason"] == (
        "spend with no price cannot be held to the $5.00 run budget: L01 spent something with no known cost "
        "(price its model in [prices], or give a budget in tokens)")
    assert lane.state is LaneState.PAUSED and world.deck.held


def test_spend_with_no_price_is_held_by_a_token_budget_when_there_is_one():
    world = engaged(budget=Budget(dollars=5.0, tokens=100000))
    world.release(ch("a"))
    world.turn(world.lane("a").id, dollars=None)
    world.pilot.step()
    assert world.pilot.engaged and not world.deck.held


def test_the_budget_still_pauses_lanes_after_a_disengage_for_another_reason():
    world = engaged(budget=Budget(tokens=2000))
    world.release(ch("a"))
    lane = world.lane("a")
    world.pilot.platform("CTFd keeps failing")
    assert world.pilot.state is State.DISENGAGED and lane.state is LaneState.RUNNING  # lanes that run go on
    world.turn(lane.id, tokens=2000)
    world.pilot.step()
    assert lane.state is LaneState.PAUSED  # the player is still away: the budget holds
    assert len(world.warnings("disengaged")) == 1


# ---------------------------------------------------------------------- disengaging, and taking the controls back


def test_a_hold_placed_by_anything_else_disengages_with_its_reason():
    world = engaged()
    world.release(ch("a"), ch("b"))
    world.deck.hold_queue("the model API keeps failing: 3 lanes in a row ended on it")
    world.pilot.step()
    reason = "the queue was held: the model API keeps failing: 3 lanes in a row ended on it"
    assert disengaged(world).data == {"autopilot": "disengaged", "reason": reason}
    assert world.deck.held == "the model API keeps failing: 3 lanes in a row ended on it"  # the first hold's own reason stays
    world.alert(world.lane("a").id, AlertKind.LOOP)
    world.pilot.step()
    assert world.lane("a").state is LaneState.RUNNING  # its rules have stopped


def test_the_platform_needing_a_human_disengages():
    world = engaged()
    world.release(ch("a"))
    world.pilot.platform("CTFd answered with a page for a person, not its API's JSON (HTTP 403)")
    assert disengaged(world).data["reason"] == (
        "the platform needs you: CTFd answered with a page for a person, not its API's JSON (HTTP 403)")
    assert world.deck.held.startswith("autopilot disengaged: the platform needs you")


def test_the_events_end_disengages_and_says_the_run_should_stop_unless_the_player_has_the_controls():
    world = engaged()
    assert world.pilot.ended("2026-11-15T09:00:00+00:00") is True
    assert disengaged(world).data["reason"] == (
        "the event ended (2026-11-15T09:00:00+00:00, event.end in the event profile): the run stops as when you quit")
    assert world.pilot.ended("2026-11-15T09:00:00+00:00") is True  # disengaged, the player still away: it stops all the same
    world.pilot.off()
    assert world.pilot.ended("2026-11-15T09:00:00+00:00") is False  # the player's run now


def test_disengage_does_nothing_unless_engaged():
    world = World()
    world.pilot.disengage("nothing")
    assert world.pilot.state is State.OFF and not world.deck.held and not world.warnings("disengaged")


def test_the_player_takes_the_controls_back_and_the_rules_stop():
    world = engaged()
    world.release(ch("a"))
    outcome = world.pilot.off()
    assert (outcome.ok, outcome.message) == (True, "Autopilot off: you have the controls")
    assert world.pilot.state is State.OFF and not world.pilot.guarding
    assert world.warnings("off")[0].data == {"autopilot": "off", "why": "you switched it off"}
    assert world.refusals == [False, True]  # the client's own behaviour is back
    world.alert(world.lane("a").id, AlertKind.LOOP)
    world.pilot.step()
    assert world.lane("a").state is LaneState.RUNNING
    assert world.pilot.off().message == "Autopilot is not on"


def test_after_a_disengage_lifting_the_hold_leaves_autopilot_off_until_it_is_engaged_again():
    world = engaged()
    world.release(ch("a"))
    world.pilot.platform("CTFd keeps failing")
    assert world.pilot.guarding and world.refusals == [False]  # disengaged: the guardrails stay
    assert world.deck.release_hold().ok
    assert world.pilot.state is State.OFF and world.refusals == [False, True]
    assert world.warnings("off")[0].data["why"] == "you lifted the hold on the queue"
    world.alert(world.lane("a").id, AlertKind.LOOP)
    world.pilot.step()
    assert world.lane("a").state is LaneState.RUNNING  # off until /autopilot on
    assert world.pilot.engage().ok
    world.pilot.step()
    assert world.deck.lanes["L01"].state is LaneState.KILLED  # engaged again: the loop alert is answered by rule


def test_the_players_first_intervention_after_a_disengage_takes_the_controls_back():
    world = engaged(budget=Budget(tokens=1000))
    world.release(ch("a"))
    lane = world.lane("a")
    world.turn(lane.id, tokens=1000)
    world.pilot.step()
    assert lane.state is LaneState.PAUSED and world.pilot.state is State.DISENGAGED
    assert world.deck.apply(iv.Resume(lane.id)).ok  # the player is back
    assert world.pilot.state is State.OFF
    world.turn(lane.id, tokens=1000)
    world.pilot.step()
    assert lane.state is LaneState.RUNNING  # theirs: it is not paused again


def test_autopilots_own_interventions_do_not_count_as_the_player_coming_back():
    world = engaged(budget=Budget(tokens=1000))
    world.release(ch("a"))
    world.turn(world.lane("a").id, tokens=1000)
    world.pilot.step()  # disengages, then pauses the lane itself
    assert world.pilot.state is State.DISENGAGED


# ---------------------------------------------------------------------- the last try


def counted(world: World, cid: str, *, most: int, left: int | None):
    world.release(ch(cid, max_attempts=most))
    if left is not None:
        world.deck.platform_tries(cid, left)
    return world.lane(cid)


def spending(**more) -> World:
    """Submit auto on a platform, with submit_limited auto: the player opted in to spending counted tries (D21)."""
    return World(submit="auto", submit_limited="auto", platform=True, **more)


def test_under_autopilot_a_counted_challenges_flag_goes_out_while_more_than_one_try_is_left():
    world = spending()
    world.pilot.engage()
    lane = counted(world, "a", most=3, left=2)
    world.deck.report(lane.id, TurnReport(flag="t{one}"))
    assert world.sent == [(lane.id, "a", "t{one}")] and lane.pending is None


def test_under_autopilot_a_flag_whose_try_count_is_not_known_goes_out_as_auto_submit_sends_it():
    """P21 (the maintainer's call): only a known last try waits; a count the platform has not
    given is not taken for one."""
    world = spending()
    world.pilot.engage()
    lane = counted(world, "a", most=3, left=None)
    world.deck.report(lane.id, TurnReport(flag="t{one}"))
    assert world.sent == [(lane.id, "a", "t{one}")]
    assert lane.pending is None and not world.warnings("last_try")


@pytest.mark.parametrize(("left", "tries"), [(1, "1 try left of 3: the last one")])
def test_under_autopilot_the_last_try_is_never_spent_even_with_submit_limited_auto(left, tries):
    world = spending()
    world.pilot.engage()
    lane = counted(world, "a", most=3, left=left)
    world.deck.report(lane.id, TurnReport(flag="t{one}"))
    assert world.sent == []  # nothing went to the platform
    assert lane.pending is not None and (lane.pending.kind, lane.pending.flag) == (PendingKind.SUBMIT, "t{one}")
    assert lane.alert(AlertKind.FLAG) is not None  # the alert the console shows
    (warning,) = world.warnings("last_try")
    assert warning.data == {"autopilot": "last_try", "flag": "t{one}", "tries_left": left}
    assert warning.text == f"autopilot never spends a challenge's last try: t{{one}} for A waits for you on {lane.id} ({tries})"
    assert world.pilot.engaged and not world.deck.held  # the run goes on
    assert world.deck.apply(iv.Approve(lane.id)).ok  # the player may spend it
    assert world.sent == [(lane.id, "a", "t{one}")]


def test_without_autopilot_submit_limited_auto_spends_the_last_try_as_d21_says():
    world = spending()
    lane = counted(world, "a", most=3, left=1)
    world.deck.report(lane.id, TurnReport(flag="t{one}"))
    assert world.sent == [(lane.id, "a", "t{one}")] and not world.warnings("last_try")


def test_the_last_try_stays_guarded_after_a_disengage_and_is_the_players_once_they_are_back():
    world = spending()
    world.pilot.engage()
    world.release(ch("a", max_attempts=3), ch("b", max_attempts=3))
    world.deck.platform_tries("a", 1)
    world.deck.platform_tries("b", 1)
    world.pilot.platform("CTFd keeps failing")  # disengaged: the player is still away
    world.deck.report(world.lane("a").id, TurnReport(flag="t{one}"))
    assert world.sent == [] and world.lane("a").pending is not None
    world.pilot.off()
    world.deck.report(world.lane("b").id, TurnReport(flag="t{two}"))
    assert world.sent == [(world.lane("b").id, "b", "t{two}")]  # the player's own opt-in again (D21)


def test_a_flag_waiting_its_turn_goes_back_to_the_player_once_the_answer_before_it_leaves_one_try():
    world = spending()
    world.pilot.engage()
    lane = counted(world, "a", most=3, left=2)
    world.deck.report(lane.id, TurnReport(flag="t{one}"))
    world.deck.report(lane.id, TurnReport(flag="t{two}"))  # waits its turn behind t{one}
    assert world.sent == [(lane.id, "a", "t{one}")]
    world.deck.platform_verdict(lane.id, "t{one}", False, "Incorrect", tries_left=1)
    assert world.sent == [(lane.id, "a", "t{one}")]  # t{two} did not go
    assert lane.pending is not None and lane.pending.flag == "t{two}"
    assert [w.data["flag"] for w in world.warnings("last_try")] == ["t{two}"]


def test_under_the_guard_the_deck_counts_a_wrong_try_the_platform_did_not_count_for_it():
    world = spending()
    world.pilot.engage()
    lane = counted(world, "a", most=3, left=2)
    world.deck.report(lane.id, TurnReport(flag="t{one}"))
    world.deck.platform_verdict(lane.id, "t{one}", False, "Incorrect")  # no count in the answer
    assert world.deck.challenges["a"].tries_left == 1
    world.deck.report(lane.id, TurnReport(flag="t{two}"))
    assert world.sent == [(lane.id, "a", "t{one}")] and lane.pending.flag == "t{two}"
    world.deck.apply(iv.Approve(lane.id))
    world.deck.platform_verdict(lane.id, "t{two}", False, "Incorrect")
    ch_a = world.deck.challenges["a"]  # the deck never counts down to 0 itself: out of tries is the platform's to say
    assert ch_a.tries_left == 1 and ch_a.status is not ChallengeStatus.BLOCKED


def test_autopilot_submits_nothing_itself_a_scraped_flag_waits_under_submit_auto():
    world = World(submit="auto", platform=True)
    world.pilot.engage()
    world.release(ch("a"))
    lane = world.lane("a")
    world.deck.report(lane.id, TurnReport(flag="t{scraped}", claimed=False))
    world.pilot.step()
    assert world.sent == [] and lane.pending.flag == "t{scraped}" and lane.state is LaneState.WAITING
    world.deck.report(lane.id, TurnReport(flag="t{claimed}"))
    assert world.sent == [(lane.id, "a", "t{claimed}")]  # as the deck does without autopilot


# ---------------------------------------------------------------------- the start notes


def test_the_start_notes_say_what_this_runs_policies_leave_autopilot():
    confirm = start_notes(object(), submit="confirm", spends_tries=False, instance="confirm", budget=Budget(dollars=5.0),
                          waves=True, refusal_fallback=True, agent=None)
    assert "autopilot: submit is confirm under this event's rules, so every flag waits for you" in confirm
    assert "autopilot: the instance policy is confirm, so a lane's request to reach its live instance waits for you" in confirm
    assert any("server-side refusal fallback is off" in line for line in confirm)
    auto = start_notes(None, submit="auto", spends_tries=True, instance="auto", budget=Budget(tokens=1000), waves=False,
                       refusal_fallback=False, agent=None)
    assert any(line.startswith("autopilot: submit is auto, so a flag a lane claims is submitted") for line in auto)
    assert any("never the last one" in line for line in auto)
    assert not any("every flag waits" in line or "waves" in line for line in auto)
    assert auto[0].startswith("autopilot: engaged, with a run budget of 1k tokens")


# ---------------------------------------------------------------------- on an event loop


def test_on_a_running_event_loop_autopilot_acts_after_the_event_without_being_asked():
    async def play() -> World:
        world = engaged()
        world.release(ch("a"))
        lane = world.lane("a")
        world.alert(lane.id, AlertKind.LOOP)
        assert lane.state is LaneState.RUNNING  # never from inside the deck's dispatch
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        return world

    world = asyncio.run(play())
    assert world.deck.lanes["L01"].state is LaneState.KILLED
