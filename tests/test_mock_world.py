"""The mock world: scenarios play out, scripted lanes react to interventions."""

from __future__ import annotations

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.model import AlertKind, ChallengeStatus, EventKind, LaneState, PendingKind
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.world import FakeWorld


def world(name: str, **kw) -> FakeWorld:
    return FakeWorld(scenarios.get(name), **kw)


def active_lane(w: FakeWorld, cid: str):
    lanes = w.deck.lanes_on(cid)
    assert len(lanes) == 1, f"expected one active lane on {cid}, got {[x.id for x in lanes]}"
    return lanes[0]


def run_until(w: FakeWorld, cond, limit: int = 120, max_lanes: int | None = None) -> None:
    for _ in range(limit):
        if cond():
            return
        w.tick()
        if max_lanes is not None:
            assert len(w.deck.active_lanes()) <= max_lanes
    assert cond(), f"condition not reached within {limit} ticks"


def fired(w: FakeWorld) -> set[AlertKind]:
    return {e.alert for e in w.deck.events if e.kind is EventKind.ALERT}


def test_default_scenario_fires_every_alert_kind_within_30_ticks_of_opening():
    w = world("default")
    run_until(w, lambda: fired(w) == set(AlertKind), limit=30)


@pytest.mark.parametrize("name", list(scenarios.SCENARIOS))
def test_every_scenario_runs_and_respects_max_lanes(name):
    w = world(name)
    run_until(w, lambda: w.ticks >= 200, limit=250, max_lanes=w.config.max_lanes)
    assert w.deck.lanes, "no lane ever started"


def test_wave_drop_starts_16_lanes_and_queues_27():
    w = world("wave")
    assert w.deck.challenges == {}
    run_until(w, lambda: w.deck.challenges, limit=5)
    assert len(w.deck.challenges) == 43
    assert len(w.deck.active_lanes()) == 16
    assert len(w.deck.queue) == 27


def test_wave_queue_drains_when_the_player_keeps_up():
    w = world("wave")
    deck = w.deck

    def keep_up():
        for lane in deck.active_lanes():
            if lane.pending is not None:
                deck.apply(iv.Approve(lane.id))
            elif lane.alert(AlertKind.LOOP) or lane.alert(AlertKind.STALL):
                deck.apply(iv.Kill(lane.id, requeue=False))
        return w.ticks > 2 and not deck.queue

    run_until(w, keep_up, limit=400, max_lanes=16)
    assert sum(ch.status is ChallengeStatus.SOLVED for ch in deck.challenges.values()) >= 16


def test_sstv_redirect_to_the_hinted_technique_finds_the_flag():
    w = world("sstv")
    lane = active_lane(w, "static-hiss")
    run_until(w, lambda: lane.alert(AlertKind.HINT) is not None)
    alert = lane.alert(AlertKind.HINT)
    assert "slow-scan" in alert.reason
    suggestion = alert.suggestions[0]
    assert suggestion.key == "r" and "SSTV" in suggestion.text
    assert w.deck.apply(iv.Redirect(lane.id, suggestion.text)).ok
    run_until(w, lambda: lane.pending is not None, limit=10)
    assert lane.pending.kind is PendingKind.SUBMIT
    assert "decoded.png" in lane.artifacts
    assert w.deck.apply(iv.Approve(lane.id)).ok
    assert w.deck.challenges["static-hiss"].status is ChallengeStatus.SOLVED


def test_sstv_lane_keeps_comparing_channels_if_nobody_steps_in():
    w = world("sstv")
    lane = active_lane(w, "static-hiss")
    w.tick(60)
    assert lane.pending is None and lane.alert(AlertKind.HINT) is not None
    assert "decoded.png" not in lane.artifacts


def test_overthinking_fires_effort_vs_value_at_40_turns_and_a_hint_fixes_it():
    w = world("overthinking")
    lane = active_lane(w, "second-guess")
    run_until(w, lambda: lane.alert(AlertKind.EFFORT) is not None, limit=20)
    assert lane.turns >= 40
    reason = lane.alert(AlertKind.EFFORT).reason
    assert "50-point" in reason and "teams have solved" in reason
    w.deck.apply(iv.Hint(lane.id, "It's simpler than this"))
    run_until(w, lambda: lane.pending is not None, limit=5)
    assert lane.pending.kind is PendingKind.SUBMIT


def test_overthinking_kill_and_requeue_gives_a_fresh_lane_that_starts_simple():
    w = world("overthinking")
    lane = active_lane(w, "second-guess")
    run_until(w, lambda: lane.alert(AlertKind.EFFORT) is not None, limit=20)
    assert w.deck.apply(iv.Kill(lane.id, requeue=True)).ok
    fresh = active_lane(w, "second-guess")
    assert fresh.attempt == 2 and fresh.turns == 0
    run_until(w, lambda: fresh.pending is not None, limit=6)
    assert fresh.turns <= 3


def test_web_wrong_way_fork_reads_the_source_and_finds_the_flag():
    w = world("web")
    lane = active_lane(w, "paper-trail")
    run_until(w, lambda: lane.alert(AlertKind.DIRECTION) is not None)
    reason = lane.alert(AlertKind.DIRECTION).reason
    assert "paper_trail_src.zip" in reason
    assert w.deck.apply(iv.Fork(lane.id, approach="Source first")).ok
    fork = next(x for x in w.deck.lanes_on("paper-trail") if x is not lane)
    assert fork.plan == "Source first"
    run_until(w, lambda: fork.pending is not None, limit=6)
    assert "src/" in fork.artifacts
    assert lane.pending is None  # the original lane is still fuzzing


def test_team_scenario_teammate_solve_stops_the_lane_by_itself():
    w = world("team")
    lane = active_lane(w, "night-shift")
    run_until(w, lambda: lane.finished, limit=20)
    assert lane.state is LaneState.STOPPED
    assert "bravo" in lane.alert(AlertKind.TEAMMATE).reason
    assert w.deck.challenges["night-shift"].status is ChallengeStatus.TEAMMATE
    assert not w.deck.lanes_on("night-shift")


def test_box_in_use_then_live_box_approval_leads_to_the_flag():
    w = world("team")
    lane = active_lane(w, "harbor-master")
    run_until(w, lambda: lane.alert(AlertKind.TEAMMATE) is not None, limit=20)
    assert "delta" in lane.alert(AlertKind.TEAMMATE).reason
    run_until(w, lambda: lane.pending is not None, limit=60)
    assert lane.alert(AlertKind.TEAMMATE) is None  # delta released the box
    assert lane.pending.kind is PendingKind.LIVE_BOX
    w.deck.apply(iv.Approve(lane.id))
    run_until(w, lambda: lane.pending is not None, limit=10)
    assert lane.pending.kind is PendingKind.SUBMIT


def test_solo_mode_skips_teammate_events():
    w = world("team", team=False)
    w.tick(40)
    assert AlertKind.TEAMMATE not in fired(w)
    assert w.deck.challenges["night-shift"].status is not ChallengeStatus.TEAMMATE
    assert w.skipped  # recorded, not silently dropped


def test_flag_scenario_approve_submit_updates_the_board():
    w = world("flag")
    lane = active_lane(w, "ticket-desk")
    run_until(w, lambda: lane.pending is not None, limit=12)
    ch = w.deck.challenges["ticket-desk"]
    solves = ch.solves
    assert w.deck.apply(iv.Approve(lane.id)).ok
    assert (ch.status, ch.solved_by, ch.solves) == (ChallengeStatus.SOLVED, lane.id, solves + 1)


def test_loop_hint_breaks_the_loop():
    w = world("wave")
    run_until(w, lambda: w.deck.challenges, limit=5)
    lane = active_lane(w, "gearbox")
    run_until(w, lambda: lane.alert(AlertKind.LOOP) is not None, limit=20)
    assert "4 times" in lane.alert(AlertKind.LOOP).reason
    w.deck.apply(iv.Hint(lane.id, lane.alert(AlertKind.LOOP).suggestions[0].text))
    run_until(w, lambda: lane.pending is not None, limit=6)
    assert "rounds.py" in lane.artifacts


def test_stall_escalation_switches_model_and_gets_unstuck():
    w = world("wave")
    run_until(w, lambda: w.deck.challenges, limit=5)
    lane = active_lane(w, "quiet-ledger")
    run_until(w, lambda: lane.alert(AlertKind.STALL) is not None, limit=30)
    model = lane.model
    assert w.deck.apply(iv.Escalate(lane.id)).ok
    assert lane.model != model
    run_until(w, lambda: lane.pending is not None, limit=8)
    assert "private key" in lane.artifacts


def test_budget_cap_makes_the_lane_wait_until_more_is_approved():
    w = world("wave")
    run_until(w, lambda: w.deck.challenges, limit=5)
    lane = active_lane(w, "deep-archive")
    run_until(w, lambda: lane.pending is not None, limit=30)
    assert lane.pending.kind is PendingKind.BUDGET
    turns = lane.turns
    w.tick(5)
    assert lane.turns == turns  # it waits
    w.deck.apply(iv.Approve(lane.id))
    run_until(w, lambda: lane.turns > turns, limit=3)


def test_overrides_from_the_command_line():
    w = world("default", max_lanes=4, team=False, containerized=False)
    assert (w.config.max_lanes, w.config.team, w.config.containerized) == (4, False, False)
    assert len(w.deck.active_lanes()) <= 4


def test_world_is_deterministic():
    a, b = world("default"), world("default")
    a.tick(40)
    b.tick(40)
    assert [e.text for e in a.deck.events] == [e.text for e in b.deck.events]


def test_unknown_scenario_names_the_choices():
    with pytest.raises(KeyError, match="default"):
        scenarios.get("nope")
