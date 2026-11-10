"""The deck's own rules, with a minimal recording driver standing in for lane work."""

from __future__ import annotations

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import (
    ME,
    Alert,
    AlertKind,
    Challenge,
    ChallengeStatus,
    DeckConfig,
    EventKind,
    LaneState,
    Pending,
    PendingKind,
)


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def now(self) -> float:
        return self.t


class RecordingDriver:
    """Records what the deck asked of it; does no work of its own."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.deck: Deck | None = None

    def attach(self, deck):
        self.deck = deck

    def start(self, lane, challenge):
        self.calls.append(("start", lane.id, challenge.id))

    def pause(self, lane):
        self.calls.append(("pause", lane.id))

    def resume(self, lane):
        self.calls.append(("resume", lane.id))

    def hint(self, lane, text):
        self.calls.append(("hint", lane.id, text))

    def redirect(self, lane, text):
        self.calls.append(("redirect", lane.id, text))

    def escalate(self, lane, model, summary):
        self.calls.append(("escalate", lane.id, model, summary))

    def approved(self, lane, pending):
        self.calls.append(("approved", lane.id, pending.kind))

    def rejected(self, lane, flag):
        self.calls.append(("rejected", lane.id, flag))

    def stop(self, lane):
        self.calls.append(("stop", lane.id))

    def named(self, name):
        return [c for c in self.calls if c[0] == name]


def good_flag(cid: str) -> str:
    return f"t{{{cid.replace('-', '_')}}}"


def make_deck(n=5, max_lanes=2, team=False, submit="confirm", token_cap=None):
    clock, driver = Clock(), RecordingDriver()
    config = DeckConfig(
        event="test",
        team=team,
        max_lanes=max_lanes,
        flag_format=r"t\{\w+\}",
        submit=submit,
        models=("small", "mid", "big"),
    )
    deck = Deck(config, driver, clock, verify=lambda cid, flag: flag == good_flag(cid))
    challenges = [Challenge(f"c{i}", f"Chall {i}", "misc", 100, solves=10) for i in range(n)]
    deck.release(challenges, [QueueEntry(c.id, "small", token_cap=token_cap) for c in challenges])
    return deck, driver, clock


def lane_on(deck, cid):
    (lane,) = deck.lanes_on(cid)
    return lane


def solve(deck, lane):
    deck.report(lane.id, TurnReport(action="solve.py", tokens=10, flag=good_flag(lane.challenge_id)))
    return deck.apply(iv.Approve(lane.id))


# ---------------------------------------------------------------------- queue and max_lanes


def test_wave_of_43_starts_16_lanes_and_queues_27():
    deck, driver, _ = make_deck(n=43, max_lanes=16)
    assert len(deck.active_lanes()) == 16
    assert len(deck.queue) == 27
    statuses = [ch.status for ch in deck.challenges.values()]
    assert statuses.count(ChallengeStatus.RUNNING) == 16
    assert statuses.count(ChallengeStatus.QUEUED) == 27
    # lanes start in triage order
    assert [c[2] for c in driver.named("start")] == [f"c{i}" for i in range(16)]


def test_queue_drains_in_order_and_never_exceeds_max_lanes():
    deck, driver, _ = make_deck(n=7, max_lanes=3)
    while deck.active_lanes():
        assert len(deck.active_lanes()) <= 3
        lane = min(deck.active_lanes(), key=lambda lane: lane.number)
        assert solve(deck, lane).ok
    assert deck.queue == []
    assert all(ch.status is ChallengeStatus.SOLVED for ch in deck.challenges.values())
    assert [c[2] for c in driver.named("start")] == [f"c{i}" for i in range(7)]


def test_blocked_and_already_solved_challenges_are_not_queued():
    clock, driver = Clock(), RecordingDriver()
    deck = Deck(DeckConfig(event="t", max_lanes=4), driver, clock, verify=lambda c, f: False)
    blocked = Challenge("b", "B", "misc", 100, status=ChallengeStatus.BLOCKED)
    done = Challenge("d", "D", "misc", 100, status=ChallengeStatus.SOLVED, solved_by=ME)
    fresh = Challenge("f", "F", "misc", 100)
    deck.release([blocked, done, fresh], [QueueEntry(c.id, "m") for c in (blocked, done, fresh)])
    assert [c[2] for c in driver.named("start")] == ["f"]
    assert blocked.status is ChallengeStatus.BLOCKED and done.status is ChallengeStatus.SOLVED


def test_release_rejects_duplicate_challenges():
    deck, _, _ = make_deck(n=1)
    with pytest.raises(ValueError):
        deck.release([Challenge("c0", "again", "misc", 1)], [])


# ---------------------------------------------------------------------- reports, flags, budget


def test_report_updates_counters_and_idle():
    deck, _, clock = make_deck(n=1)
    lane = lane_on(deck, "c0")
    clock.t += 300
    assert lane.idle(clock.t) == 300
    deck.report(lane.id, TurnReport(action="ls", output="a b", tokens=1500, dollars=0.25, artifacts=("a",)))
    assert (lane.turns, lane.tokens, lane.dollars) == (1, 1500, 0.25)
    assert lane.idle(clock.t) == 0
    assert lane.last_action == "ls" and lane.artifacts == ["a"]
    deck.report(lane.id, TurnReport(action="ls", tokens=100, dollars=None))
    assert lane.dollars is None  # one unpriced turn makes the lane's dollars unknown


def test_flag_waits_for_approval_then_solves_and_frees_the_slot():
    deck, driver, _ = make_deck(n=3, max_lanes=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(action="solve.py", flag=good_flag("c0")))
    assert lane.state is LaneState.WAITING
    assert lane.alert(AlertKind.FLAG) is not None
    assert lane.pending.kind is PendingKind.SUBMIT
    assert deck.challenges["c0"].status is ChallengeStatus.RUNNING  # nothing submitted yet
    out = deck.apply(iv.Approve(lane.id))
    assert out.ok
    ch = deck.challenges["c0"]
    assert (ch.status, ch.solved_by, ch.solves) == (ChallengeStatus.SOLVED, lane.id, 11)
    assert lane.state is LaneState.SOLVED
    assert [c[2] for c in driver.named("start")] == ["c0", "c1"]  # the queue moved on


def test_candidate_that_does_not_match_the_format_is_not_submitted():
    deck, _, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="FLAG{nope}"))
    assert lane.pending is None and lane.alert(AlertKind.FLAG) is None
    assert lane.state is LaneState.RUNNING


def test_rejected_flag_lets_the_lane_carry_on():
    deck, driver, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{wrong}"))
    deck.apply(iv.Approve(lane.id))
    assert lane.state is LaneState.RUNNING
    assert deck.challenges["c0"].status is ChallengeStatus.RUNNING
    assert driver.named("rejected") == [("rejected", lane.id, "t{wrong}")]


def test_auto_submit_policy_submits_without_approval():
    deck, _, _ = make_deck(n=1, submit="auto")
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=good_flag("c0")))
    assert lane.state is LaneState.SOLVED and lane.pending is None


def test_budget_alert_at_80_percent_and_approval_at_the_cap():
    deck, driver, _ = make_deck(n=1, token_cap=1000)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(tokens=799))
    assert lane.alert(AlertKind.BUDGET) is None
    deck.report(lane.id, TurnReport(tokens=1))
    assert lane.alert(AlertKind.BUDGET) is not None
    assert lane.state is LaneState.RUNNING
    deck.report(lane.id, TurnReport(tokens=200))
    assert lane.state is LaneState.WAITING
    assert lane.pending.kind is PendingKind.BUDGET
    deck.apply(iv.Approve(lane.id))
    assert lane.token_cap == 1500
    assert lane.state is LaneState.RUNNING
    assert lane.alert(AlertKind.BUDGET) is None
    assert driver.named("approved") == [("approved", lane.id, PendingKind.BUDGET)]


def test_live_box_request_waits_for_approval():
    deck, driver, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(pending=Pending(PendingKind.LIVE_BOX, "connect")))
    assert lane.state is LaneState.WAITING
    assert deck.apply(iv.Approve(lane.id)).ok
    assert lane.state is LaneState.RUNNING
    assert driver.named("approved") == [("approved", lane.id, PendingKind.LIVE_BOX)]


def test_gave_up_parks_the_challenge_and_starts_the_next():
    deck, driver, _ = make_deck(n=2, max_lanes=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(gave_up="no lead"))
    assert lane.state is LaneState.GAVE_UP
    assert deck.challenges["c0"].status is ChallengeStatus.PARKED
    assert "no lead" in deck.challenges["c0"].note
    assert [c[2] for c in driver.named("start")] == ["c0", "c1"]


def test_late_report_after_the_lane_ended_changes_nothing():
    deck, _, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.apply(iv.Kill(lane.id, requeue=False))
    deck.report(lane.id, TurnReport(tokens=500, flag=good_flag("c0")))
    assert lane.tokens == 0 and lane.state is LaneState.KILLED


# ---------------------------------------------------------------------- team mode


def test_teammate_solve_stops_the_lane_and_frees_its_slot():
    deck, driver, _ = make_deck(n=3, max_lanes=2, team=True)
    lane = lane_on(deck, "c0")
    deck.teammate_solved("c0", "bravo")
    assert lane.state is LaneState.STOPPED
    alert = lane.alert(AlertKind.TEAMMATE)
    assert alert is not None and "bravo" in alert.reason
    ch = deck.challenges["c0"]
    assert (ch.status, ch.solved_by) == (ChallengeStatus.TEAMMATE, "bravo")
    assert ("stop", lane.id) in driver.calls
    assert lane_on(deck, "c2")  # the queued challenge took the slot


def test_teammate_solve_of_a_queued_challenge_means_it_never_starts():
    deck, driver, _ = make_deck(n=4, max_lanes=1, team=True)
    deck.teammate_solved("c2", "bravo")
    assert not deck.queued("c2")
    for _ in range(3):
        lane = deck.active_lanes()[0]
        solve(deck, lane)
    assert "c2" not in [c[2] for c in driver.named("start")]


def test_teammate_claim_keeps_a_challenge_out_of_the_queue():
    deck, driver, _ = make_deck(n=3, max_lanes=1, team=True)
    deck.teammate_claim("c1", "delta")
    assert not deck.queued("c1")
    assert deck.challenges["c1"].claimed_by == "delta"
    solve(deck, lane_on(deck, "c0"))
    assert [c[2] for c in driver.named("start")] == ["c0", "c2"]


def test_teammate_events_need_team_mode():
    deck, _, _ = make_deck(n=1, team=False)
    with pytest.raises(RuntimeError):
        deck.teammate_solved("c0", "bravo")


def test_claim_and_release_only_in_team_mode():
    solo, _, _ = make_deck(n=1, team=False)
    assert not solo.apply(iv.Claim("c0")).ok
    deck, _, _ = make_deck(n=2, team=True)
    assert deck.apply(iv.Claim("c1")).ok
    assert deck.challenges["c1"].claimed_by == ME
    assert not deck.apply(iv.Claim("c1")).ok  # already ours
    assert deck.apply(iv.Release("c1")).ok
    assert deck.challenges["c1"].claimed_by is None
    deck.teammate_claim("c0", "delta")
    assert not deck.apply(iv.Claim("c0")).ok


# ---------------------------------------------------------------------- interventions


def test_pause_and_resume():
    deck, driver, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    assert deck.apply(iv.Pause(lane.id)).ok
    assert lane.state is LaneState.PAUSED
    assert not deck.apply(iv.Pause(lane.id)).ok
    assert deck.apply(iv.Resume(lane.id)).ok
    assert lane.state is LaneState.RUNNING
    assert driver.named("pause") == [("pause", lane.id)] and driver.named("resume") == [("resume", lane.id)]


def test_resume_returns_to_waiting_when_an_approval_is_pending():
    deck, _, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=good_flag("c0")))
    deck.apply(iv.Pause(lane.id))
    deck.apply(iv.Resume(lane.id))
    assert lane.state is LaneState.WAITING


def test_hint_is_queued_for_the_next_turn_and_answers_course_alerts():
    deck, driver, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(alerts=(Alert(AlertKind.EFFORT, "too much"),)))
    assert deck.apply(iv.Hint(lane.id, "  try rot13  ")).ok
    assert lane.hints == ["try rot13"]
    assert lane.alert(AlertKind.EFFORT) is None
    assert driver.named("hint") == [("hint", lane.id, "try rot13")]
    deck.report(lane.id, TurnReport(action="rot13"))
    assert lane.hints == []
    assert not deck.apply(iv.Hint(lane.id, "   ")).ok


def test_redirect_replaces_the_plan():
    deck, driver, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(plan="fuzz everything", alerts=(Alert(AlertKind.DIRECTION, "fuzzing"),)))
    assert deck.apply(iv.Redirect(lane.id, "read the source")).ok
    assert lane.plan == "read the source"
    assert lane.alert(AlertKind.DIRECTION) is None
    assert driver.named("redirect") == [("redirect", lane.id, "read the source")]


def test_fork_starts_a_sibling_on_another_model_when_a_slot_is_free():
    deck, _, _ = make_deck(n=1, max_lanes=2)
    lane = lane_on(deck, "c0")
    out = deck.apply(iv.Fork(lane.id, approach="source first"))
    assert out.ok
    siblings = deck.lanes_on("c0")
    assert len(siblings) == 2
    fork = next(s for s in siblings if s is not lane)
    assert (fork.parent, fork.model, fork.approach) == (lane.id, "mid", "source first")


def test_fork_goes_first_in_the_queue_when_all_lanes_are_busy():
    deck, _, _ = make_deck(n=3, max_lanes=2)
    lane = lane_on(deck, "c0")
    out = deck.apply(iv.Fork(lane.id, model="big"))
    assert out.ok and "queue" in out.message
    assert len(deck.active_lanes()) == 2
    assert (deck.queue[0].challenge, deck.queue[0].parent, deck.queue[0].model) == ("c0", lane.id, "big")


def test_kill_and_requeue_starts_a_fresh_attempt():
    deck, _, _ = make_deck(n=3, max_lanes=1)
    lane = lane_on(deck, "c0")
    assert deck.apply(iv.Kill(lane.id, requeue=True)).ok
    assert lane.state is LaneState.KILLED
    fresh = lane_on(deck, "c0")
    assert fresh is not lane and fresh.attempt == 2 and fresh.turns == 0


def test_kill_and_park():
    deck, _, _ = make_deck(n=2, max_lanes=1)
    lane = lane_on(deck, "c0")
    deck.apply(iv.Kill(lane.id, requeue=False))
    assert deck.challenges["c0"].status is ChallengeStatus.PARKED
    assert not deck.queued("c0")
    assert lane_on(deck, "c1")


def test_escalate_moves_up_the_ladder_with_a_summary():
    deck, driver, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(action="ls -la", plan="look around", alerts=(Alert(AlertKind.STALL, "stuck"),)))
    assert deck.apply(iv.Escalate(lane.id)).ok
    assert lane.model == "mid"
    assert lane.alert(AlertKind.STALL) is None
    (_, _, model, summary) = driver.named("escalate")[0]
    assert model == "mid" and "ls -la" in summary and "look around" in summary
    deck.apply(iv.Escalate(lane.id))
    assert lane.model == "big"
    assert not deck.apply(iv.Escalate(lane.id)).ok  # nothing stronger


def test_take_over_and_hand_back():
    deck, _, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    assert deck.apply(iv.TakeOver(lane.id)).ok
    assert lane.state is LaneState.TAKEOVER
    assert not deck.apply(iv.Hint(lane.id, "x")).ok  # hand back first
    assert deck.apply(iv.HandBack(lane.id)).ok
    assert lane.state is LaneState.RUNNING


def test_finished_lanes_refuse_interventions():
    deck, _, _ = make_deck(n=2, max_lanes=1)
    lane = lane_on(deck, "c0")
    solve(deck, lane)
    for intervention in (iv.Pause(lane.id), iv.Hint(lane.id, "x"), iv.Approve(lane.id), iv.Kill(lane.id)):
        assert not deck.apply(intervention).ok


def test_interventions_are_logged_as_events():
    deck, _, _ = make_deck(n=1)
    lane = lane_on(deck, "c0")
    deck.apply(iv.Hint(lane.id, "look closer"))
    deck.apply(iv.Pause(lane.id))
    texts = [e.text for e in deck.events if e.kind is EventKind.INTERVENTION]
    assert texts == [f"hint: Hint queued for {lane.id}'s next turn", f"pause: Paused {lane.id}"]


def test_config_rejects_bad_values():
    with pytest.raises(ValueError):
        DeckConfig(event="t", max_lanes=0)
    with pytest.raises(ValueError):
        DeckConfig(event="t", submit="manual")
