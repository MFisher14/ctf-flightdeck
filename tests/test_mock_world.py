"""The mock world: scenarios play out on a scripted clock and scripted lanes react to interventions.

Everything runs on FakeWorld's manual clock: no timers and no sleeps. Every wait is a bounded
loop (run_until) that fails with the tick it gave up at.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable

import pytest

from ctf_flightdeck import fmt
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.model import (
    ActionKind,
    AlertKind,
    ChallengeStatus,
    Event,
    EventKind,
    Lane,
    LaneState,
    PendingKind,
)
from ctf_flightdeck.mock import scenarios
from ctf_flightdeck.mock.scenarios import ReleaseAt, Scenario, Spec, TeammateClaim, TeammateSolve
from ctf_flightdeck.mock.script import MOCK_PRICES, Script, Step
from ctf_flightdeck.mock.world import FakeWorld

# ---------------------------------------------------------------------- helpers


def world(name: str, **kw) -> FakeWorld:
    return FakeWorld(scenarios.get(name), **kw)


def custom_world(*specs: Spec) -> FakeWorld:
    """A one-off scenario of synthetic challenges, all released at tick 0."""
    scenario = Scenario(
        name="synthetic",
        summary="built by a test",
        specs=specs,
        timeline=((0, ReleaseAt(tuple(s.id for s in specs), "Board")),),
    )
    return FakeWorld(scenario)


def wave_after_drop() -> FakeWorld:
    w = world("wave")
    run_until(w, lambda: w.deck.challenges, limit=3)
    return w


def active_lane(w: FakeWorld, cid: str) -> Lane:
    lanes = w.deck.lanes_on(cid)
    assert len(lanes) == 1, f"expected one active lane on {cid}, got {[x.id for x in lanes]}"
    return lanes[0]


def run_until(w: FakeWorld, cond: Callable[[], object], limit: int, max_lanes: int | None = None) -> None:
    """Tick until cond() is true, at most `limit` ticks. With max_lanes, check the cap after every tick."""
    for _ in range(limit):
        if cond():
            return
        w.tick()
        if max_lanes is not None:
            active = len(w.deck.active_lanes())
            assert active <= max_lanes, f"{active} lanes active at tick {w.ticks}, over the cap of {max_lanes}"
    assert cond(), f"condition not met within {limit} ticks (world at tick {w.ticks})"


def fired(w: FakeWorld) -> set[AlertKind]:
    return {e.alert for e in w.deck.events if e.kind is EventKind.ALERT}


def steps(lane: Lane) -> list[str]:
    """The lane's own steps (one per model turn), oldest first."""
    return [a.text for a in lane.actions if a.kind is ActionKind.STEP]


def turn_events(w: FakeWorld, lane: Lane) -> list[Event]:
    return [e for e in w.deck.events if e.kind is EventKind.TURN and e.lane == lane.id]


def number(pattern: str, text: str) -> int:
    match = re.search(pattern, text)
    assert match, f"{pattern!r} not found in {text!r}"
    return int(match.group(1))


def amount(text: str) -> float:
    """A compact amount as fmt writes it: 950, 493k, 1.2M, 2.37."""
    scale = {"k": 1e3, "M": 1e6}.get(text[-1], 1.0)
    return float(text.rstrip("kM")) * scale


def timeline_tick(w: FakeWorld, kind: type, challenge: str) -> int:
    return next(at for at, ev in w.scenario.timeline if isinstance(ev, kind) and ev.challenge == challenge)


# ---------------------------------------------------------------------- whole scenarios

# The lanes in the default scenario that act out each alert from CONSOLE-SPEC.
CUE_LANES = {
    AlertKind.HINT: ("static-hiss",),
    AlertKind.EFFORT: ("second-guess",),
    AlertKind.DIRECTION: ("paper-trail",),
    AlertKind.LOOP: ("ratchet-run",),
    AlertKind.STALL: ("quiet-ledger",),
    AlertKind.BUDGET: ("deep-archive",),
    AlertKind.TEAMMATE: ("harbor-master", "night-shift"),  # box in use; teammate solved
    AlertKind.FLAG: ("ticket-desk",),
}


def test_default_scenario_fires_every_alert_kind_within_30_ticks_of_opening():
    w = world("default")
    assert w.ticks == w.scenario.prerun > 0  # it opens on an event in progress
    assert set(CUE_LANES) == set(AlertKind)
    run_until(w, lambda: fired(w) == set(AlertKind), limit=30)
    sources: dict[AlertKind, set[str]] = defaultdict(set)
    for e in w.deck.events:
        if e.kind is EventKind.ALERT:
            sources[e.alert].add(e.challenge)
    for kind, cids in CUE_LANES.items():
        for cid in cids:
            assert cid in sources[kind], f"{kind.value} never fired on {cid}; it fired on {sorted(sources[kind])}"


# The autopilot scenario holds its queue and warns by design (it disengages at its budget): its own tests are below.
PLAYER_FLOWN = [name for name in scenarios.SCENARIOS if scenarios.get(name).autopilot_tokens is None]


@pytest.mark.parametrize("cap", [None, 2], ids=["own-cap", "cap-2"])
@pytest.mark.parametrize("name", PLAYER_FLOWN)
def test_every_scenario_runs_200_ticks_without_exceeding_its_lane_cap(name, cap):
    w = world(name, max_lanes=cap)
    limit = w.config.max_lanes
    assert limit == (w.scenario.max_lanes if cap is None else cap)
    workable = sum(1 for s in w.scenario.specs if s.status is ChallengeStatus.NEW)
    start, peak = w.ticks, len(w.deck.active_lanes())
    for _ in range(200):
        w.tick()
        active = len(w.deck.active_lanes())
        assert active <= limit, f"{active} lanes active at tick {w.ticks}, over the cap of {limit}"
        assert not w.deck.queue or active == limit, (
            f"tick {w.ticks}: {len(w.deck.queue)} queued while only {active} of {limit} lanes are busy"
        )
        peak = max(peak, active)
    assert w.ticks == start + 200
    assert peak == min(limit, workable)  # the cap is reached whenever there is enough work
    assert [e.text for e in w.deck.events if e.kind is EventKind.WARNING] == []
    # Challenges solved or blocked before the board opened keep that status and never get a lane.
    settled = {s.id: s.status for s in w.scenario.specs if s.status is not ChallengeStatus.NEW}
    assert {cid: w.deck.challenges[cid].status for cid in settled} == settled
    assert [lane.id for lane in w.deck.lanes.values() if lane.challenge_id in settled] == []


def test_wave_drop_puts_43_challenges_up_starts_16_lanes_and_queues_27():
    w = world("wave")
    deck = w.deck
    drop = next(at for at, ev in w.scenario.timeline if isinstance(ev, ReleaseAt))
    w.tick(drop - 1)
    assert deck.challenges == {} and deck.lanes == {}
    w.tick()
    assert len(deck.challenges) == 43
    assert len(deck.active_lanes()) == 16
    assert len(deck.queue) == 27
    # In triage order: the first 16 start, the other 27 wait in that order.
    order = [s.id for s in scenarios.WAVE]
    assert [lane.challenge_id for lane in deck.active_lanes()] == order[:16]
    assert [entry.challenge for entry in deck.queue] == order[16:]
    assert {deck.challenges[cid].status for cid in order[16:]} == {ChallengeStatus.QUEUED}
    (release,) = [e for e in deck.events if e.kind is EventKind.RELEASE]
    assert (release.data["started"], release.data["queued"]) == (16, 27)


def test_wave_queue_drains_when_the_player_keeps_up():
    w = world("wave")
    deck = w.deck

    def keep_up() -> bool:
        for lane in deck.active_lanes():
            if lane.finished:  # a solve in this same pass can stop a sibling
                continue
            if lane.pending is not None:
                assert deck.apply(iv.Approve(lane.id)).ok
            elif lane.alert(AlertKind.LOOP) or lane.alert(AlertKind.STALL):
                assert deck.apply(iv.Kill(lane.id, requeue=False)).ok
        return bool(deck.challenges) and not deck.queue

    run_until(w, keep_up, limit=200, max_lanes=16)
    solved = [ch for ch in deck.challenges.values() if ch.status is ChallengeStatus.SOLVED]
    assert len(solved) >= 16
    assert all(ch.solved_by in deck.lanes for ch in solved)


def test_wave_queue_stays_full_while_approvals_go_unanswered():
    """Lanes waiting for the player keep their slots, so the drain above is the player's doing."""
    w = wave_after_drop()
    w.tick(200)
    assert len(w.deck.active_lanes()) == 16
    assert w.deck.queue
    assert any(lane.state is LaneState.WAITING for lane in w.deck.active_lanes())


def test_other_teams_keep_solving_and_cheap_challenges_gain_solves_faster():
    w = world("default")
    board = {cid: ch.solves for cid, ch in w.deck.challenges.items()}  # the early board, at opening
    seen = dict(board)
    for _ in range(100):
        w.tick()
        for cid in board:
            now = w.deck.challenges[cid].solves
            assert now >= seen[cid], f"{cid} lost solves at tick {w.ticks}"
            seen[cid] = now
    gained = {cid: seen[cid] - board[cid] for cid in board}
    points = {cid: w.deck.challenges[cid].points for cid in board}
    cheap = [gained[cid] for cid in board if points[cid] <= 50]
    dear = [gained[cid] for cid in board if points[cid] >= 200]
    assert cheap and dear
    assert sum(cheap) / len(cheap) > 2 * sum(dear) / len(dear), gained


# ---------------------------------------------------------------------- SSTV (static-hiss)


def sstv_lane() -> tuple[FakeWorld, Lane]:
    w = world("sstv")
    lane = active_lane(w, "static-hiss")
    run_until(w, lambda: lane.alert(AlertKind.HINT) is not None, limit=20)
    return w, lane


def spent(lane: Lane) -> int:
    return number(r"spent (\d+) turns", lane.alert(AlertKind.HINT).reason)


def test_sstv_off_hint_alert_mentions_slow_scan_and_suggests_redirect_then_hint():
    _, lane = sstv_lane()
    alert = lane.alert(AlertKind.HINT)
    assert "slow-scan" in alert.reason
    assert [s.key for s in alert.suggestions] == ["r", "h"]
    assert "SSTV" in alert.suggestions[0].text


def test_sstv_unanswered_off_hint_alert_is_raised_again_with_a_growing_turn_count():
    w, lane = sstv_lane()
    first = lane.alert(AlertKind.HINT)
    # Every step after the opening `file` and `sox` works on the stereo channels.
    assert spent(lane) == lane.turns - 2
    counts = [spent(lane)]
    for _ in range(30):
        w.tick()
        assert lane.alert(AlertKind.HINT) is not None, f"the alert went away by itself at tick {w.ticks}"
        if spent(lane) != counts[-1]:
            assert spent(lane) == lane.turns - 2  # raised again on this turn, with this turn's count
            counts.append(spent(lane))
    assert len(counts) >= 3, counts
    assert counts == sorted(set(counts)), counts  # each raise counts more turns than the last
    assert [a.kind for a in lane.alerts].count(AlertKind.HINT) == 1  # raised again, not stacked
    assert lane.alert(AlertKind.HINT).at == first.at  # still waiting since the first raise
    assert lane.pending is None and "decoded.png" not in lane.artifacts


def test_sstv_redirect_with_the_first_suggestion_decodes_the_picture_and_asks_to_submit():
    w, lane = sstv_lane()
    redirect = lane.alert(AlertKind.HINT).suggestions[0]
    assert redirect.key == "r"
    turns = lane.turns
    assert w.deck.apply(iv.Redirect(lane.id, redirect.text)).ok
    assert lane.plan == redirect.text
    assert lane.alert(AlertKind.HINT) is None
    w.tick()
    assert lane.turns == turns + 1
    assert "decoded.png" in lane.artifacts  # decoded on its very next turn
    run_until(w, lambda: lane.pending is not None, limit=3)
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["static-hiss"]


def test_sstv_hint_with_the_second_suggestion_also_leads_to_the_sstv_decode():
    w, lane = sstv_lane()
    hint = lane.alert(AlertKind.HINT).suggestions[1]
    assert hint.key == "h"
    done = len(steps(lane))
    assert w.deck.apply(iv.Hint(lane.id, hint.text)).ok
    run_until(w, lambda: lane.pending is not None, limit=4)
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["static-hiss"]
    assert "decoded.png" in lane.artifacts
    assert steps(lane)[done].startswith("re-reads the description")  # the hint is what it acts on first
    assert "slow-scan" in lane.plan
    assert lane.hints == []


def test_sstv_looping_script_carries_on_from_repeat_from_not_from_the_start():
    w = world("sstv")
    lane = active_lane(w, "static-hiss")
    script = scenarios.scripts_for(w.scenario)["static-hiss"]
    assert script.repeat_from  # loops, and not from the first step
    loop = [s.do for s in script.steps[script.repeat_from :]]
    run_until(w, lambda: lane.turns >= len(script.steps) + 2 * len(loop), limit=60)
    expected = [s.do for s in script.steps]
    while len(expected) < lane.turns:
        expected += loop
    assert steps(lane) == expected[: lane.turns]
    assert steps(lane).count("file static_hiss.wav") == 1  # the opening step is never repeated


def test_static_hiss_records_an_added_file_then_a_modified_one():
    w = world("sstv")
    lane = active_lane(w, "static-hiss")
    run_until(w, lambda: "split_channels.py" in lane.files, limit=10)
    split = lane.files["split_channels.py"]
    assert (split.status, split.added, split.removed) == ("added", 13, 0)  # a new 13-line script
    assert split.turn == lane.turns
    run_until(w, lambda: "diff_channels.py" in lane.files, limit=4)
    assert lane.files["diff_channels.py"].status == "added"
    run_until(w, lambda: lane.files["diff_channels.py"].status == "modified", limit=12)
    diff = lane.files["diff_channels.py"]
    assert (diff.added, diff.removed) == (9, 1)  # the --window hunk: 9 lines in, 1 out
    assert diff.turn == lane.turns
    assert list(lane.files)[-1] == "diff_channels.py"  # newest change last
    assert lane.files["split_channels.py"] == split  # untouched since it was written


# ---------------------------------------------------------------------- overthinking (second-guess)

EFFORT_REASON = re.compile(r"(\d+) turns, (\S+) tokens and \$(\S+) on a (\d+)-point challenge that (\d+) teams")


def overthinking_lane() -> tuple[FakeWorld, Lane]:
    w = world("overthinking")
    lane = active_lane(w, "second-guess")
    run_until(w, lambda: lane.alert(AlertKind.EFFORT) is not None, limit=20)
    return w, lane


def effort_numbers(reason: str) -> tuple[int, float, float, int, int]:
    match = EFFORT_REASON.match(reason)
    assert match, reason
    turns, tokens, dollars, points, solves = match.groups()
    return int(turns), amount(tokens), float(dollars), int(points), int(solves)


def test_overthinking_effort_alert_fires_at_40_turns_on_a_50_pointer_many_teams_solved():
    w, lane = overthinking_lane()
    reason = lane.alert(AlertKind.EFFORT).reason
    assert lane.turns == 40  # CONSOLE-SPEC: a 50-point challenge with 300 solves, at 40 turns
    assert "50-point" in reason and "teams have solved" in reason
    # The numbers are the lane's and the board's as of the turn that raised it.
    ch = w.deck.challenges["second-guess"]
    assert reason.startswith(f"{lane.turns} turns, {fmt.tokens(lane.tokens)} tokens and ${fmt.dollars(lane.dollars)} ")
    assert f"that {ch.solves} teams have solved" in reason
    assert effort_numbers(reason)[4] >= 300


def test_overthinking_ignored_effort_alert_comes_back_with_larger_numbers():
    w, lane = overthinking_lane()
    first = lane.alert(AlertKind.EFFORT)
    run_until(w, lambda: lane.alert(AlertKind.EFFORT).reason != first.reason, limit=20)
    again = lane.alert(AlertKind.EFFORT)
    old_turns, old_tokens, old_dollars, _, _ = effort_numbers(first.reason)
    turns, tokens, dollars, _, _ = effort_numbers(again.reason)
    assert turns == lane.turns > old_turns
    assert tokens > old_tokens and dollars > old_dollars
    assert again.at == first.at


def test_overthinking_hint_leads_to_a_submit_within_a_few_ticks():
    w, lane = overthinking_lane()
    hint = lane.alert(AlertKind.EFFORT).suggestions[0]
    assert hint.key == "h"
    assert w.deck.apply(iv.Hint(lane.id, hint.text)).ok
    run_until(w, lambda: lane.pending is not None, limit=3)
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["second-guess"]
    assert lane.alert(AlertKind.EFFORT) is None


def test_overthinking_kill_and_requeue_starts_a_fresh_lane_that_submits_within_3_turns():
    w, lane = overthinking_lane()
    assert w.deck.apply(iv.Kill(lane.id, requeue=True)).ok
    assert lane.state is LaneState.KILLED
    fresh = active_lane(w, "second-guess")
    assert fresh is not lane
    assert (fresh.attempt, fresh.turns) == (2, 0)
    run_until(w, lambda: fresh.pending is not None, limit=6)
    assert fresh.turns <= 3
    assert fresh.pending.kind is PendingKind.SUBMIT
    assert fresh.pending.flag == w.flags["second-guess"]


# ---------------------------------------------------------------------- web wrong way (paper-trail)


def web_lane() -> tuple[FakeWorld, Lane]:
    w = world("web")
    lane = active_lane(w, "paper-trail")
    run_until(w, lambda: lane.alert(AlertKind.DIRECTION) is not None, limit=20)
    return w, lane


def test_web_wrong_way_alert_names_the_handout_and_redirect_builds_the_exploit():
    w, lane = web_lane()
    alert = lane.alert(AlertKind.DIRECTION)
    assert w.deck.challenges["paper-trail"].files == ("paper_trail_src.zip",)
    assert "paper_trail_src.zip" in alert.reason
    scans = sum(1 for s in steps(lane) if s.startswith(scenarios.SCANNERS))
    assert alert.reason.startswith(f"{scans} brute-force scans")
    redirect = alert.suggestions[0]
    assert redirect.key == "r"
    assert w.deck.apply(iv.Redirect(lane.id, redirect.text)).ok
    run_until(w, lambda: lane.pending is not None, limit=4)
    assert lane.files["exploit.py"].status == "added"
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["paper-trail"]


def test_web_fork_with_an_approach_reads_the_source_while_the_parent_keeps_fuzzing():
    w, lane = web_lane()
    approach = "Open export.py from the handout and trace how it picks the file"
    assert w.deck.apply(iv.Fork(lane.id, approach=approach)).ok
    fork = next(x for x in w.deck.lanes_on("paper-trail") if x is not lane)
    assert fork.parent == lane.id
    assert fork.plan == approach
    parent_done = len(steps(lane))
    run_until(w, lambda: fork.pending is not None, limit=5)
    assert steps(fork)[0].startswith("unzip -o paper_trail_src.zip")
    assert "src/" in fork.artifacts
    assert fork.pending.kind is PendingKind.SUBMIT
    assert fork.pending.flag == w.flags["paper-trail"]
    run_until(w, lambda: len(steps(lane)) >= parent_done + 2, limit=6)
    since = steps(lane)[parent_done:]
    assert all(s.startswith(scenarios.SCANNERS) for s in since), since
    assert lane.state is LaneState.RUNNING and lane.pending is None
    assert "src/" not in lane.artifacts


# ---------------------------------------------------------------------- team and solo


def test_team_teammate_solve_stops_the_night_shift_lane_by_itself():
    w = world("team")
    lane = active_lane(w, "night-shift")
    at = timeline_tick(w, TeammateSolve, "night-shift")
    run_until(w, lambda: lane.finished, limit=at + 1)
    assert w.ticks == at
    assert lane.state is LaneState.STOPPED
    alert = lane.alert(AlertKind.TEAMMATE)
    assert alert is not None and "wren" in alert.reason
    ch = w.deck.challenges["night-shift"]
    assert (ch.status, ch.solved_by) == (ChallengeStatus.TEAMMATE, "wren")
    assert not w.deck.lanes_on("night-shift")


def test_team_box_in_use_names_heron_then_live_box_approval_leads_to_a_submit():
    w = world("team")
    lane = active_lane(w, "harbor-master")
    run_until(w, lambda: lane.alert(AlertKind.TEAMMATE) is not None, limit=20)
    assert "heron" in lane.alert(AlertKind.TEAMMATE).reason
    assert steps(lane)[-1] == "request the live instance"
    assert lane.state is LaneState.RUNNING  # kept off the box, still working on the handout
    run_until(w, lambda: lane.pending is not None, limit=60)
    assert lane.pending.kind is PendingKind.LIVE_BOX
    assert lane.alert(AlertKind.TEAMMATE) is None  # heron released the box first
    assert w.deck.apply(iv.Approve(lane.id)).ok
    run_until(w, lambda: lane.pending is not None, limit=4)
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["harbor-master"]


def test_team_claim_from_the_timeline_takes_the_challenge_out_of_the_queue():
    w = world("team")
    ch = w.deck.challenges["holiday-snap"]
    assert w.deck.queued("holiday-snap")  # every lane is busy, so it waits its turn
    w.tick(timeline_tick(w, TeammateClaim, "holiday-snap") - w.ticks)
    assert ch.claimed_by == "heron"
    assert not w.deck.queued("holiday-snap")
    assert ch.status is ChallengeStatus.NEW
    w.tick(60)
    assert all(lane.challenge_id != "holiday-snap" for lane in w.deck.lanes.values())


def test_solo_mode_skips_the_teammate_events_and_records_them():
    w = world("team", team=False)
    harbor = active_lane(w, "harbor-master")
    last = max(at for at, _ in w.scenario.timeline)
    for _ in range(last + 40):
        w.tick()
        assert w.deck.challenges["night-shift"].status is not ChallengeStatus.TEAMMATE, f"tick {w.ticks}"
    assert AlertKind.TEAMMATE not in fired(w)
    assert [e.text for e in w.deck.events if e.kind is EventKind.TEAMMATE] == []
    assert w.skipped == ["heron claims holiday-snap", "wren solves night-shift", "wren solves lucky-sevens"]
    assert w.deck.challenges["holiday-snap"].claimed_by is None
    assert "request the live instance" not in steps(harbor)  # a team-only step


# ---------------------------------------------------------------------- flag, loop, stall, budget


def test_flag_scenario_approving_the_submit_marks_ticket_desk_solved_by_the_lane():
    w = world("flag")
    lane = active_lane(w, "ticket-desk")
    run_until(w, lambda: lane.pending is not None, limit=12)
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["ticket-desk"]
    assert lane.alert(AlertKind.FLAG) is not None
    ch = w.deck.challenges["ticket-desk"]
    solves = ch.solves
    assert w.deck.apply(iv.Approve(lane.id)).ok
    assert (ch.status, ch.solved_by, ch.solves) == (ChallengeStatus.SOLVED, lane.id, solves + 1)
    assert lane.state is LaneState.SOLVED


def test_loop_alert_counts_the_repeats_and_the_count_grows_when_raised_again():
    w = wave_after_drop()
    lane = active_lane(w, "ratchet-run")
    run_until(w, lambda: lane.alert(AlertKind.LOOP) is not None, limit=10)

    def ran() -> int:
        return number(r"ran (\d+) times", lane.alert(AlertKind.LOOP).reason)

    def in_a_row() -> int:  # how many times the last command ran back to back
        done = steps(lane)
        return next((i for i, s in enumerate(reversed(done)) if s != done[-1]), len(done))

    first = ran()
    assert first == in_a_row() >= 2
    assert "python3 angr_solve.py ratchet_run" in lane.alert(AlertKind.LOOP).reason
    run_until(w, lambda: ran() != first, limit=3)
    assert ran() == in_a_row() > first


def test_loop_hint_makes_the_lane_lift_the_rounds_and_find_the_flag():
    w = wave_after_drop()
    lane = active_lane(w, "ratchet-run")
    run_until(w, lambda: lane.alert(AlertKind.LOOP) is not None, limit=10)
    hint = lane.alert(AlertKind.LOOP).suggestions[0]
    assert hint.key == "h"
    assert w.deck.apply(iv.Hint(lane.id, hint.text)).ok
    run_until(w, lambda: lane.pending is not None, limit=3)
    assert "rounds.py" in lane.artifacts
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["ratchet-run"]
    assert lane.alert(AlertKind.LOOP) is None


def test_stall_escalation_moves_to_a_stronger_model_that_recovers_the_key():
    w = wave_after_drop()
    lane = active_lane(w, "quiet-ledger")
    run_until(w, lambda: lane.alert(AlertKind.STALL) is not None, limit=25)
    assert f"the last new finding ({lane.artifacts[-1]})" in lane.alert(AlertKind.STALL).reason
    assert lane.model == "glm"
    assert w.deck.apply(iv.Escalate(lane.id)).ok
    assert lane.model == "sonnet"
    assert lane.alert(AlertKind.STALL) is None
    run_until(w, lambda: lane.pending is not None, limit=6)
    assert "private key" in lane.artifacts
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["quiet-ledger"]
    last = turn_events(w, lane)[-1]  # turns after the escalation are paid at the stronger model's price
    assert last.data["dollars"] == pytest.approx(last.data["tokens"] * MOCK_PRICES["sonnet"] / 1e6)


def test_budget_cap_makes_deep_archive_wait_without_turns_until_more_is_approved():
    w = wave_after_drop()
    lane = active_lane(w, "deep-archive")
    cap = lane.token_cap
    assert cap
    run_until(w, lambda: lane.pending is not None, limit=20)
    assert lane.pending.kind is PendingKind.BUDGET
    assert lane.state is LaneState.WAITING and lane.tokens >= cap
    frozen = (lane.turns, lane.tokens, len(steps(lane)))
    w.tick(5)
    assert (lane.turns, lane.tokens, len(steps(lane))) == frozen
    assert w.deck.apply(iv.Approve(lane.id)).ok
    assert lane.token_cap == cap * 3 // 2  # 50% more
    assert lane.pending is None and lane.state is LaneState.RUNNING
    run_until(w, lambda: lane.turns > frozen[0], limit=2)
    run_until(w, lambda: lane.pending is not None, limit=8)
    assert lane.pending.kind is PendingKind.SUBMIT
    assert lane.pending.flag == w.flags["deep-archive"]


# ---------------------------------------------------------------------- the scripted driver


def test_paused_taken_over_and_waiting_lanes_take_no_steps():
    w = wave_after_drop()
    deck = w.deck
    paused, taken, waiting = (active_lane(w, cid) for cid in ("ratchet-run", "quiet-ledger", "deep-archive"))
    run_until(w, lambda: waiting.pending is not None, limit=20)
    assert waiting.pending.kind is PendingKind.BUDGET  # at its cap with steps still to take
    assert deck.apply(iv.Pause(paused.id)).ok
    assert deck.apply(iv.TakeOver(taken.id)).ok
    lanes = (paused, taken, waiting)
    frozen = [(lane.turns, len(steps(lane))) for lane in lanes]
    w.tick(6)
    assert [(lane.turns, len(steps(lane))) for lane in lanes] == frozen
    assert [lane.state for lane in lanes] == [LaneState.PAUSED, LaneState.TAKEOVER, LaneState.WAITING]
    assert deck.apply(iv.Resume(paused.id)).ok
    assert deck.apply(iv.HandBack(taken.id)).ok
    w.tick()
    assert (paused.turns, taken.turns) == (frozen[0][0] + 1, frozen[1][0] + 1)  # back at work at once


def test_redirect_on_a_lane_without_a_branch_switches_to_the_new_plan_on_its_next_turn():
    w = world("sstv")
    lane = active_lane(w, "muddy-footprints")
    assert scenarios.scripts_for(w.scenario)["muddy-footprints"].on_redirect == ()  # a generic lane
    run_until(w, lambda: lane.turns >= 2, limit=10)
    turns = lane.turns
    text = "Mount the image and list the deleted files first"
    assert w.deck.apply(iv.Redirect(lane.id, text)).ok
    assert lane.plan == text
    run_until(w, lambda: lane.turns > turns, limit=4)
    assert lane.turns == turns + 1
    assert steps(lane)[-1] == f"switches to the new plan: {text}"


def test_escalate_on_a_lane_without_a_branch_hands_over_on_its_next_turn():
    w = world("sstv")
    lane = active_lane(w, "muddy-footprints")
    assert scenarios.scripts_for(w.scenario)["muddy-footprints"].on_escalate == ()  # a generic lane
    run_until(w, lambda: lane.turns >= 2, limit=10)
    turns = lane.turns
    assert w.deck.apply(iv.Escalate(lane.id)).ok
    assert lane.model == "sonnet"
    run_until(w, lambda: lane.turns > turns, limit=4)
    assert lane.turns == turns + 1
    assert steps(lane)[-1] == "sonnet picks up from the summary"


def test_hint_on_a_lane_without_a_branch_is_read_on_its_next_turn_and_not_before():
    w = world("sstv")
    lane = active_lane(w, "muddy-footprints")
    script = scenarios.scripts_for(w.scenario)["muddy-footprints"]
    assert script.on_hint == ()  # a generic lane
    assert script.steps[0].every >= 2  # a turn every 2+ ticks, so there is a tick between hint and turn
    run_until(w, lambda: lane.turns >= 2, limit=10)  # it has just taken a turn
    turns = lane.turns
    text = "The partition table lies; check the slack space"
    assert w.deck.apply(iv.Hint(lane.id, text)).ok
    assert lane.hints == [text]
    w.tick()
    assert lane.turns == turns
    assert lane.hints == [text]  # sent, not read yet
    run_until(w, lambda: lane.turns > turns, limit=3)
    assert lane.turns == turns + 1
    assert steps(lane)[-1] == f"reads the hint: {text}"
    assert lane.hints == []


def test_rejected_flag_makes_the_lane_recheck_on_its_next_turn():
    def guesser(flag: str) -> Script:
        return Script(
            plan="Guess the flag",
            steps=(Step("guess", "mock{not_it}", flag="mock{not_it}"), Step("look again", "nothing new")),
            repeat_from=1,
        )

    w = custom_world(Spec("decoy", "misc", "Decoy", 100, "Synthetic: the lane's first guess is wrong.", script=guesser))
    lane = active_lane(w, "decoy")
    run_until(w, lambda: lane.pending is not None, limit=3)
    assert lane.pending.flag == "mock{not_it}" != w.flags["decoy"]
    turns = lane.turns
    assert w.deck.apply(iv.Approve(lane.id)).ok
    assert lane.pending is None and lane.state is LaneState.RUNNING
    assert w.deck.challenges["decoy"].status is not ChallengeStatus.SOLVED
    run_until(w, lambda: lane.turns > turns, limit=2)
    assert steps(lane)[-1] == "mock{not_it} was rejected; re-checking the last step"


def test_alert_factory_step_counts_as_one_turn_and_sees_the_lane_after_it():
    w = world("overthinking")
    lane = active_lane(w, "second-guess")
    for _ in range(20):
        turns, events = lane.turns, len(turn_events(w, lane))
        w.tick()
        if lane.alert(AlertKind.EFFORT) is not None:
            break
    else:
        pytest.fail("the effort alert never fired")
    assert lane.turns == turns + 1
    assert len(turn_events(w, lane)) == events + 1
    assert lane.alert(AlertKind.EFFORT).reason.startswith(f"{lane.turns} turns, ")


def test_dollars_are_tokens_times_the_model_price():
    def flat(flag: str) -> Script:
        return Script(plan="Probe", steps=(Step("probe", "ok", tokens=10_000),), repeat_from=0)

    w = custom_world(
        Spec("cheap", "misc", "Cheap", 100, "Synthetic.", model="glm", script=flat),
        Spec("dear", "misc", "Dear", 100, "Synthetic.", model="sonnet", script=flat),
    )
    cheap, dear = active_lane(w, "cheap"), active_lane(w, "dear")
    w.tick(3)
    assert cheap.tokens == dear.tokens == 30_000
    assert cheap.dollars == pytest.approx(30_000 * MOCK_PRICES["glm"] / 1e6)
    assert dear.dollars == pytest.approx(30_000 * MOCK_PRICES["sonnet"] / 1e6)
    assert dear.dollars == pytest.approx(4.8 * cheap.dollars)


def test_every_turn_in_the_default_scenario_costs_its_tokens_at_its_model_price():
    w = world("default")
    w.tick(20)
    turns = [e for e in w.deck.events if e.kind is EventKind.TURN]
    assert {w.deck.lanes[e.lane].model for e in turns} >= {"glm", "sonnet"}
    for e in turns:
        price = MOCK_PRICES[w.deck.lanes[e.lane].model]  # no escalation here, so the model never changed
        assert e.data["dollars"] == pytest.approx(e.data["tokens"] * price / 1e6), e.text


def test_turn_tokens_grow_with_the_turn_number_when_a_step_names_none():
    def growing(flag: str) -> Script:
        return Script(plan="Grow", steps=(Step("a"), Step("b"), Step("c")), base_tokens=1_000, growth=100)

    w = custom_world(Spec("grow", "misc", "Grow", 100, "Synthetic.", script=growing))
    lane = active_lane(w, "grow")
    w.tick(3)
    assert [e.data["tokens"] for e in turn_events(w, lane)] == [1_100, 1_200, 1_300]
    assert lane.tokens == 3_600
    assert lane.dollars == pytest.approx(3_600 * MOCK_PRICES["glm"] / 1e6)


# ---------------------------------------------------------------------- world settings


def test_command_line_overrides_replace_the_scenario_settings():
    plain = world("default")
    assert (plain.config.max_lanes, plain.config.team, plain.config.containerized) == (16, True, True)
    w = world("default", max_lanes=4, team=False, containerized=False)
    assert (w.config.max_lanes, w.config.team, w.config.containerized) == (4, False, False)
    assert len(w.deck.active_lanes()) == 4 and w.deck.queue  # the lower cap binds at once
    run_until(w, lambda: w.ticks >= 70, limit=40, max_lanes=4)
    assert AlertKind.TEAMMATE not in fired(w)
    assert len(w.skipped) == 3  # solo: the three teammate events are skipped
    assert world("sstv", team=True).config.team is True
    with pytest.raises(ValueError, match="max_lanes"):
        world("default", max_lanes=0)


def test_two_worlds_of_the_same_scenario_play_out_identically():
    a, b = world("default"), world("default")
    a.tick(40)
    b.tick(40)
    texts = [e.text for e in a.deck.events]
    assert texts and texts == [e.text for e in b.deck.events]
    # Other teams' solve counts drift at random; the scenario's seed makes them repeat too.
    assert {c.id: c.solves for c in a.deck.challenges.values()} == {c.id: c.solves for c in b.deck.challenges.values()}


def test_unknown_scenario_fails_naming_every_choice():
    with pytest.raises(KeyError) as info:
        scenarios.get("nope")
    message = str(info.value)
    assert "nope" in message
    for name in scenarios.SCENARIOS:
        assert name in message


# ---------------------------------------------------------------------- the autopilot scenario


def test_the_autopilot_scenario_shows_the_chip_a_rule_firing_and_a_disengage(tmp_path):
    """`flightdeck mock -s autopilot`: autopilot is engaged from the start, kills the looping
    lane and escalates the stalled one by rule, declines a lane's budget request, and
    disengages at its run budget, holding the queue and pausing the lanes."""
    from ctf_flightdeck.console import views
    from ctf_flightdeck.core.model import EventKind, LaneState
    from ctf_flightdeck.mock import scenarios, screenshots
    from ctf_flightdeck.mock.world import FakeWorld

    world = FakeWorld(scenarios.get("autopilot"))
    deck, pilot = world.deck, world.pilot
    assert pilot.engaged and "╱ AUTOPILOT ╱" in views.header(deck, mock="MOCK · autopilot", width=200).plain
    for _ in range(60):
        if not pilot.engaged:
            break
        world.tick()
    by_rule = [(e.data["intervention"], e.lane) for e in deck.events
               if e.kind is EventKind.INTERVENTION and e.data.get("by") == "autopilot"]
    assert [step for step in by_rule if step[0] != "pause"] == [("kill", "L01"), ("decline", "L03"), ("escalate", "L02")]
    assert deck.lanes["L01"].result == "by autopilot; parked" and deck.lanes["L02"].model == "sonnet"
    assert deck.lanes["L03"].result == "autopilot declined more budget"
    assert pilot.state.value == "disengaged" and pilot.reason.startswith("the run budget is reached: ")
    assert deck.held == f"autopilot disengaged: {pilot.reason}"
    assert all(lane.state is LaneState.PAUSED for lane in deck.active_lanes()) and deck.active_lanes()
    header = views.header(deck, mock="MOCK · autopilot", width=200).plain
    assert "╱ AUTOPILOT ╱" not in header and "queue held: autopilot disengaged: the run budget is reached" in header
    assert len(deck.lanes) > 0 and max(len(deck.active_lanes()), 1) <= deck.config.max_lanes
    tokens = deck.totals()[0]
    world.tick(5)
    assert deck.totals()[0] == tokens  # at the budget nothing spends any more

    result = screenshots.capture("autopilot", tmp_path)
    names = [path.name for path in result.saved]
    assert names[:3] == ["01-open.svg", "02-autopilot-rule.svg", "03-autopilot-disengaged.svg"]
    assert not [line for line in result.skipped if line.startswith("autopilot")]
    rule, off = (tmp_path / names[1]).read_text(encoding="utf-8"), (tmp_path / names[2]).read_text(encoding="utf-8")
    assert "AUTOPILOT" in rule.replace("&#160;", " ") and "autopilot&#160;disengaged" in off


def test_the_autopilot_scenario_on_the_host_runtime_says_why_autopilot_is_not_engaged():
    from ctf_flightdeck.core.model import EventKind
    from ctf_flightdeck.mock import scenarios
    from ctf_flightdeck.mock.world import FakeWorld

    world = FakeWorld(scenarios.get("autopilot"), containerized=False)
    assert not world.pilot.guarding
    (said,) = [e for e in world.deck.events if e.kind is EventKind.WARNING and e.data.get("autopilot") == "not engaged"]
    assert said.text.startswith("Autopilot not engaged: autopilot needs the Docker runtime")
    world.tick(30)
    assert not [e for e in world.deck.events if e.data.get("by") == "autopilot"]


def test_a_scenario_without_autopilot_has_no_autopilot_moments(tmp_path):
    from ctf_flightdeck.mock import screenshots

    result = screenshots.capture("flag", tmp_path)
    assert not [path for path in result.saved if "autopilot" in path.name]
    assert not [line for line in result.skipped if "autopilot" in line]
