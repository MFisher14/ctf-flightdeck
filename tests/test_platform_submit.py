"""Flags to a platform that answers over the network (CTFd), at the deck: the submitter takes
a flag and returns at once, the lane carries on, and the platform's answer comes back later
through Deck.platform_verdict(). And the tries a platform counts at a challenge's flag
(Challenge.max_attempts and tries_left), with a submitter or a verifier that answers at once.

A recording driver, verifier and submitter stand in for lane work and for the platform (the
first two from test_deck.py); the deck itself is never mocked. tests/test_ctfd_submits.py
plays the same through a real run, against the fake CTFd.
"""

from __future__ import annotations

import asyncio
import json
import threading

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import DECLINED, REJECTED, Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import AlertKind, Challenge, ChallengeStatus, DeckConfig, EventKind, LaneState, PendingKind
from ctf_flightdeck.platform.manual import BoardError, cannot_check, load_board

from test_deck import FLAG_FORMAT, MODELS, Clock, RecordingDriver, RecordingVerifier, events, fork, lane_on


class RecordingSubmitter:
    """The platform over the network: notes each flag handed over and answers none; a test
    answers it with deck.platform_verdict() when it likes. `fail` makes it raise."""

    def __init__(self, fail: str = "") -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.fail = fail

    def __call__(self, lane_id: str, challenge_id: str, flag: str) -> None:
        if self.fail:
            raise RuntimeError(self.fail)
        self.calls.append((lane_id, challenge_id, flag))

    def flags(self) -> list[str]:
        return [flag for *_, flag in self.calls]


def chall(cid: str, **fields) -> Challenge:
    return Challenge(cid, f"Chall {cid[1:]}", "misc", 100, solves=10, **fields)


def platform_deck(*challenges: Challenge, submit: str = "auto", team: bool = False, submitter=None, verify=None):
    """A deck with a lane on each challenge (c0 and c1 by default). Its flags go to the
    `submitter` (a RecordingSubmitter by default), or with submitter=False to `verify`."""
    driver = RecordingDriver()
    if submitter is None:
        submitter = RecordingSubmitter()
    config = DeckConfig(event="test", team=team, max_lanes=4, flag_format=FLAG_FORMAT, submit=submit, models=MODELS)
    deck = Deck(config, driver, Clock(), verify=verify or RecordingVerifier(), submitter=submitter or None)
    challenges = challenges or (chall("c0"), chall("c1"))
    deck.release(list(challenges), [QueueEntry(ch.id, MODELS[0]) for ch in challenges])
    return deck, driver, submitter


def notes(lane) -> list[str]:
    return [action.text for action in lane.actions]


# ---------------------------------------------------------------------- the answer comes later


def test_an_auto_flag_goes_to_the_submitter_and_the_lane_carries_on_until_the_answer():
    deck, driver, submitter = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
    assert submitter.calls == [(lane.id, "c0", "t{c0}")] and deck.verify.calls == []  # never the verifier
    assert lane.state is LaneState.RUNNING and lane.pending is None and not lane.needs_you
    assert deck.submitting("c0") == ((lane.id, "t{c0}"),)
    assert lane.last_action == "sending t{c0} to the platform; its answer comes back on its own"  # the fleet's row says so
    assert events(deck, EventKind.SUBMIT) == []  # nothing is known yet
    deck.report(lane.id, TurnReport(action="ls"))  # the lane works on meanwhile
    assert lane.turns == 2 and lane.state is LaneState.RUNNING
    deck.platform_verdict(lane.id, "t{c0}", True, "Correct")
    ch = deck.challenges["c0"]
    assert (ch.status, ch.solved_by, ch.solves) == (ChallengeStatus.SOLVED, lane.id, 11)
    assert lane.state is LaneState.SOLVED and deck.submitting("c0") == ()
    (submit,) = events(deck, EventKind.SUBMIT)
    assert submit.lane == lane.id and submit.data == {"flag": "t{c0}", "correct": True, "by": "platform", "detail": "Correct"}


def test_approving_a_flag_hands_it_over_answers_the_approval_and_the_verdict_comes_later():
    deck, driver, submitter = platform_deck(submit="confirm")
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{wrong}"))
    assert lane.pending.kind is PendingKind.SUBMIT and submitter.calls == []
    out = deck.apply(iv.Approve(lane.id))
    assert out.ok and out.message == "Submitting t{wrong} for Chall 0; the platform's answer comes back on its own"
    assert lane.pending is None and lane.state is LaneState.RUNNING and lane.alert(AlertKind.FLAG) is None
    assert ("approved", lane.id, PendingKind.SUBMIT) in driver.calls  # the driver wakes the lane: it carries on
    assert submitter.calls == [(lane.id, "c0", "t{wrong}")] and deck.verify.calls == []
    assert driver.named("rejected") == []
    deck.platform_verdict(lane.id, "t{wrong}", False, "Incorrect")
    assert driver.named("rejected") == [(lane.id, "t{wrong}")]
    assert deck.not_flag("c0", "t{wrong}") == REJECTED and lane.state is LaneState.RUNNING
    assert deck.challenges["c0"].status is ChallengeStatus.RUNNING
    assert "the platform's answer to t{wrong}: Incorrect" in notes(lane)
    assert events(deck, EventKind.SUBMIT)[-1].data["correct"] is False


def test_no_verdict_from_the_platform_asks_the_player_to_submit_by_hand_and_says_why():
    deck, driver, _ = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{maybe}"))
    deck.platform_verdict(lane.id, "t{maybe}", None, "CTFd is paused, so it did not check the flag")
    assert (lane.pending.kind, lane.pending.flag) == (PendingKind.CONFIRM, "t{maybe}") and lane.state is LaneState.WAITING
    assert "no verdict from the platform on t{maybe}: CTFd is paused, so it did not check the flag" in notes(lane)
    assert deck.not_flag("c0", "t{maybe}") is None and events(deck, EventKind.SUBMIT) == []
    assert deck.apply(iv.Approve(lane.id)).ok  # the player: "it was accepted"
    assert lane.state is LaneState.SOLVED and events(deck, EventKind.SUBMIT)[-1].data["by"] == "player"


# ---------------------------------------------------------------------- one flag at a time per challenge


def test_one_flag_at_a_time_goes_to_the_platform_for_a_challenge_and_the_next_one_after_the_answer():
    deck, _, submitter = platform_deck()
    lane, other = lane_on(deck, "c0"), lane_on(deck, "c1")
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.report(lane.id, TurnReport(flag="t{b}"))
    deck.report(other.id, TurnReport(flag="t{x}"))  # another challenge's flag does not wait
    assert submitter.calls == [(lane.id, "c0", "t{a}"), (other.id, "c1", "t{x}")]
    assert deck.submitting("c0") == ((lane.id, "t{a}"), (lane.id, "t{b}"))
    assert "waits its turn to go to the platform: t{b} (after t{a}, from L01: one flag at a time per challenge)" in notes(lane)
    deck.platform_verdict(lane.id, "t{a}", False)
    assert submitter.calls[-1] == (lane.id, "c0", "t{b}") and deck.submitting("c0") == ((lane.id, "t{b}"),)
    deck.platform_verdict(lane.id, "t{b}", False)
    assert deck.submitting("c0") == () and submitter.flags() == ["t{a}", "t{x}", "t{b}"]


def test_an_approved_flag_waits_its_turn_behind_the_one_on_its_way():
    deck, _, submitter = platform_deck(submit="confirm")
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    for each, flag in ((lane, "t{a}"), (sibling, "t{b}")):
        deck.report(each.id, TurnReport(flag=flag))
    assert deck.apply(iv.Approve(lane.id)).ok
    out = deck.apply(iv.Approve(sibling.id))
    assert out.ok and out.message == "t{b} goes to the platform once the answer to t{a} is in (one flag at a time on Chall 0)"
    assert submitter.flags() == ["t{a}"] and sibling.pending is None and sibling.state is LaneState.RUNNING
    deck.platform_verdict(lane.id, "t{a}", False)
    assert submitter.calls[-1] == (sibling.id, "c0", "t{b}")


def test_a_flag_waiting_its_turn_never_goes_out_once_the_challenge_is_solved():
    deck, _, submitter = platform_deck()
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    deck.report(lane.id, TurnReport(flag="t{c0}"))
    deck.report(sibling.id, TurnReport(flag="t{other}"))
    assert deck.submitting("c0") == ((lane.id, "t{c0}"), (sibling.id, "t{other}"))
    deck.platform_verdict(lane.id, "t{c0}", True)
    assert sibling.state is LaneState.STOPPED and deck.submitting("c0") == ()
    assert submitter.flags() == ["t{c0}"]


def test_after_no_verdict_the_flags_waiting_their_turn_go_back_to_the_player():
    deck, _, submitter = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.report(lane.id, TurnReport(flag="t{b}"))
    deck.platform_verdict(lane.id, "t{a}", None, "no answer from CTFd")  # it may not judge the next one either
    queued = [lane.pending, *lane.waiting]
    assert [(p.kind, p.flag) for p in queued] == [(PendingKind.CONFIRM, "t{a}"), (PendingKind.SUBMIT, "t{b}")]
    assert deck.submitting("c0") == () and submitter.flags() == ["t{a}"]
    assert "back to you: t{b} did not go to the platform (the platform gave no verdict on the flag before it)" in notes(lane)
    deck.apply(iv.Decline(lane.id))  # t{a}: the player says the platform rejected it
    assert deck.apply(iv.Approve(lane.id)).ok  # t{b}: the player sends it now
    assert submitter.calls[-1] == (lane.id, "c0", "t{b}")


def test_a_flag_already_on_its_way_is_not_sent_again_and_every_lane_that_found_it_hears_the_answer():
    deck, driver, submitter = platform_deck()
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    deck.report(lane.id, TurnReport(flag="t{same}"))
    deck.report(sibling.id, TurnReport(flag="t{same}"))
    assert submitter.flags() == ["t{same}"] and sibling.pending is None
    assert f"already on its way to the platform, from {lane.id}: t{{same}}" in notes(sibling)
    deck.platform_verdict(lane.id, "t{same}", False)
    assert driver.named("rejected") == [(lane.id, "t{same}"), (sibling.id, "t{same}")]
    deck.report(sibling.id, TurnReport(flag="t{same}"))  # known wrong now: never sent again
    assert submitter.flags() == ["t{same}"]


def test_under_confirm_approving_a_flag_another_lane_already_sent_does_not_send_it_again():
    deck, _, submitter = platform_deck(submit="confirm")
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    for each in (lane, sibling):
        deck.report(each.id, TurnReport(flag="t{same}"))
    deck.apply(iv.Approve(lane.id))
    out = deck.apply(iv.Approve(sibling.id))
    assert out.ok and out.message == "t{same} is already on its way to the platform for Chall 0"
    assert submitter.flags() == ["t{same}"] and sibling.pending is None


# ---------------------------------------------------------------------- an answer that comes late


@pytest.mark.parametrize("requeue", [False, True])
def test_an_answer_that_comes_after_the_lane_was_killed_still_solves_the_challenge_for_it(requeue):
    deck, driver, _ = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{c0}"))
    assert deck.apply(iv.Kill(lane.id, requeue=requeue)).ok and lane.state is LaneState.KILLED
    fresh = deck.lanes_on("c0")
    assert len(fresh) == (1 if requeue else 0)
    deck.platform_verdict(lane.id, "t{c0}", True, "Correct")
    ch = deck.challenges["c0"]
    assert (ch.status, ch.solved_by, ch.solves, ch.note) == (ChallengeStatus.SOLVED, lane.id, 11, "")
    assert lane.state is LaneState.KILLED  # it ended as it ended: nothing reopens, nothing ends twice
    assert len([e for e in deck.events if e.kind is EventKind.LANE_END and e.lane == lane.id]) == 1
    assert all(other.state is LaneState.STOPPED and other.result == f"{lane.id} solved it" for other in fresh)
    submit = events(deck, EventKind.SUBMIT)[-1]
    assert (submit.lane, submit.data["correct"]) == (lane.id, True)


def test_a_wrong_answer_after_the_lane_ended_is_still_remembered_and_its_lane_is_left_alone():
    deck, driver, _ = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{wrong}"))
    deck.apply(iv.Kill(lane.id, requeue=False))
    deck.platform_verdict(lane.id, "t{wrong}", False)
    assert deck.not_flag("c0", "t{wrong}") == REJECTED and driver.named("rejected") == []  # nothing tells a stopped lane
    assert deck.challenges["c0"].status is ChallengeStatus.PARKED and lane.state is LaneState.KILLED


@pytest.mark.parametrize("ok", [True, False, None])
def test_an_answer_after_a_teammate_solved_the_challenge_is_recorded_and_reopens_nothing(ok):
    deck, driver, submitter = platform_deck(team=True)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{late}"))
    deck.report(lane.id, TurnReport(flag="t{next}"))  # waits its turn: it never goes out now
    deck.teammate_solved("c0", "bravo")
    assert lane.state is LaneState.STOPPED and deck.submitting("c0") == ((lane.id, "t{late}"),)
    mark = len(deck.events)
    deck.platform_verdict(lane.id, "t{late}", ok, "the platform's words")
    ch = deck.challenges["c0"]
    assert (ch.status, ch.solved_by, ch.solves) == (ChallengeStatus.TEAMMATE, "bravo", 11)  # the teammate's solve stays
    assert lane.state is LaneState.STOPPED and lane.pending is None and deck.submitting("c0") == ()
    assert submitter.flags() == ["t{late}"] and driver.named("rejected") == []
    late = events(deck, EventKind.SUBMIT, since=mark)
    if ok is None:
        assert late == [] and lane.actions[-1].text.endswith("Chall 0 was solved meanwhile")
    else:
        (event,) = late
        assert event.data["correct"] is ok and event.data["solved_meanwhile"] is True


def test_a_lane_that_gave_up_while_its_flag_was_on_its_way_ends_once_the_answer_is_in():
    deck, _, _ = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{maybe}"))
    deck.report(lane.id, TurnReport(turn=False, gave_up="the model gave up"))
    assert not lane.finished  # its flag's answer is not in yet
    assert notes(lane)[-1] == "gave up (the model gave up), but its flag is on its way to the platform: it ends once the answer is in"
    deck.platform_verdict(lane.id, "t{maybe}", False)
    assert lane.state is LaneState.GAVE_UP and lane.result == "the model gave up"


def test_a_lane_that_gave_up_while_its_flag_waits_for_the_player_says_so():
    deck, _, _ = platform_deck(submit="confirm")
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{maybe}"))
    deck.report(lane.id, TurnReport(turn=False, gave_up="the model gave up"))
    assert notes(lane)[-1] == "gave up (the model gave up), but a candidate flag waits for you"
    assert deck.apply(iv.Decline(lane.id)).ok and lane.state is LaneState.GAVE_UP


def test_sending_names_each_lanes_flags_on_their_way_until_their_answer_is_in():
    deck, _, _ = platform_deck()
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    other = lane_on(deck, "c1")
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.report(sibling.id, TurnReport(flag="t{a}"))  # already on its way: its answer is the sibling's too
    deck.report(sibling.id, TurnReport(flag="t{b}"))  # waits its turn
    assert (deck.sending(lane.id), deck.sending(sibling.id), deck.sending(other.id)) == (("t{a}",), ("t{a}", "t{b}"), ())
    deck.platform_verdict(lane.id, "t{a}", False)
    assert (deck.sending(lane.id), deck.sending(sibling.id)) == ((), ("t{b}",))
    deck.platform_verdict(sibling.id, "t{b}", False)
    assert deck.sending(sibling.id) == () and deck.sending("L99") == ()


def test_a_lane_that_ends_takes_its_flags_waiting_their_turn_with_it():
    deck, _, submitter = platform_deck()
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.report(sibling.id, TurnReport(flag="t{b}"))
    deck.apply(iv.Kill(sibling.id, requeue=False))
    assert "not submitted: t{b} (it was waiting its turn to go to the platform)" in notes(sibling)
    deck.platform_verdict(lane.id, "t{a}", False)
    assert submitter.flags() == ["t{a}"] and deck.submitting("c0") == ()


# ---------------------------------------------------------------------- failures said loudly


def test_the_answer_to_a_flag_that_is_not_on_its_way_is_refused():
    deck, _, _ = platform_deck()
    lane = lane_on(deck, "c0")
    with pytest.raises(ValueError, match="no flag of L01 is on its way to the platform"):
        deck.platform_verdict(lane.id, "t{never}", True)
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.report(lane.id, TurnReport(flag="t{b}"))
    with pytest.raises(ValueError):
        deck.platform_verdict(lane.id, "t{b}", True)  # waiting its turn: not sent, so no answer can be its
    assert deck.challenges["c0"].status is ChallengeStatus.RUNNING


def test_platform_verdict_must_be_called_on_the_decks_thread():
    deck, _, _ = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{c0}"))
    errors: list[Exception] = []

    def worker() -> None:
        try:
            deck.platform_verdict(lane.id, "t{c0}", True)
        except Exception as exc:  # collected for the main thread to check
            errors.append(exc)

    thread = threading.Thread(target=worker)
    thread.start()
    thread.join(timeout=5)
    assert len(errors) == 1 and "another thread" in str(errors[0]) and lane.state is LaneState.RUNNING
    deck.platform_verdict(lane.id, "t{c0}", True)
    assert lane.state is LaneState.SOLVED


def test_a_submitter_that_fails_is_a_warning_and_the_flag_waits_for_the_player():
    deck, _, _ = platform_deck(submitter=RecordingSubmitter(fail="the queue is closed"))
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{c0}"))
    (warning,) = events(deck, EventKind.WARNING)
    assert warning.text == "could not hand t{c0} to the platform: RuntimeError: the queue is closed"
    assert (lane.pending.kind, lane.pending.flag) == (PendingKind.CONFIRM, "t{c0}") and deck.submitting("c0") == ()


# ---------------------------------------------------------------------- limited tries


def test_under_auto_a_flag_for_a_challenge_with_limited_tries_waits_for_the_player():
    deck, _, submitter = platform_deck(chall("c0", max_attempts=3))
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{c0}"))  # claimed: it would go out at once on another challenge
    assert lane.pending.kind is PendingKind.SUBMIT and lane.state is LaneState.WAITING
    assert lane.pending.detail == "submit t{c0} (3 tries in all, how many are left is not known yet)"
    assert "The platform counts the tries at this challenge's flag" in lane.alert(AlertKind.FLAG).reason
    assert submitter.calls == [] and deck.verify.calls == []
    assert deck.apply(iv.Approve(lane.id)).ok  # the player's yes sends it
    assert submitter.flags() == ["t{c0}"]


@pytest.mark.parametrize("verify, state", [(None, LaneState.SOLVED), (cannot_check, LaneState.WAITING)],
                         ids=["answers", "no answers"])
def test_without_a_platform_a_limited_challenges_flag_spends_no_try_and_goes_on_at_once(verify, state):
    # an answers file checks it here, or the player submits it by hand: nothing to approve first
    deck, _, _ = platform_deck(chall("c0", max_attempts=3), submitter=False, verify=verify)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{c0}"))
    assert lane.state is state
    if verify is cannot_check:
        assert lane.pending.kind is PendingKind.CONFIRM  # "did the platform accept it? (you submit it)", asked once


def test_a_tries_remaining_answer_switches_the_challenge_to_confirm_for_the_rest_of_the_run():
    deck, _, submitter = platform_deck()
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.report(lane.id, TurnReport(flag="t{b}"))  # waits its turn behind t{a}
    deck.platform_verdict(lane.id, "t{a}", False, "Incorrect. You have 2 tries remaining.", tries_left=2)
    ch = deck.challenges["c0"]
    assert ch.tries_left == 2 and ch.limited
    assert submitter.flags() == ["t{a}"]  # t{b} did not go out on its own: it is the player's call now
    assert (lane.pending.kind, lane.pending.detail) == (PendingKind.SUBMIT, "submit t{b} (2 tries left)")
    deck.report(lane.id, TurnReport(flag="t{c}"))  # a new claimed flag waits too
    assert [p.detail for p in lane.waiting] == ["submit t{c} (2 tries left)"] and submitter.flags() == ["t{a}"]
    assert events(deck, EventKind.SUBMIT)[-1].data["tries_left"] == 2
    (warning,) = events(deck, EventKind.WARNING)  # the switch is said, once
    assert warning.text == ("the platform counts the tries at the flag of Chall 0 (2 tries left): from now on its flags "
                            "wait for you, under submit auto too")
    assert (warning.challenge, warning.data) == ("c0", {"tries_left": 2})
    deck.apply(iv.Approve(lane.id))
    deck.platform_verdict(lane.id, "t{b}", False, "Incorrect. You have 1 try remaining.", tries_left=1)
    assert ch.tries_left == 1 and len(events(deck, EventKind.WARNING)) == 1


def test_under_confirm_a_tries_remaining_answer_is_no_warning():
    deck, _, _ = platform_deck(submit="confirm")
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.apply(iv.Approve(lane.id))
    deck.platform_verdict(lane.id, "t{a}", False, "Incorrect. You have 2 tries remaining.", tries_left=2)
    assert deck.challenges["c0"].tries_left == 2 and events(deck, EventKind.WARNING) == []  # every flag waits anyway


def test_a_count_of_tries_that_comes_after_the_challenge_was_solved_is_no_warning():
    deck, _, _ = platform_deck(team=True)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{late}"))
    deck.teammate_solved("c0", "bravo")
    deck.platform_verdict(lane.id, "t{late}", False, "Incorrect. You have 2 tries remaining.", tries_left=2)
    assert deck.challenges["c0"].tries_left == 2 and events(deck, EventKind.WARNING) == []  # no flag of it goes out anyway


def test_flightdeck_never_spends_the_last_try_on_its_own_and_the_approval_says_it_is_the_last():
    deck, _, submitter = platform_deck(chall("c0", max_attempts=3))
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.apply(iv.Approve(lane.id))
    deck.platform_verdict(lane.id, "t{a}", False, "Incorrect. You have 1 try remaining.", tries_left=1)
    deck.report(lane.id, TurnReport(flag="t{b}"))
    assert lane.pending.detail == "submit t{b} (1 try left of 3: the last one)" and submitter.flags() == ["t{a}"]
    assert "1 try left of 3: the last one" in lane.alert(AlertKind.FLAG).reason


def test_under_confirm_a_waiting_approval_follows_the_platforms_count_of_tries():
    deck, _, submitter = platform_deck(chall("c0", max_attempts=5), submit="confirm")
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.report(sibling.id, TurnReport(flag="t{b}"))
    assert sibling.pending.detail == "submit t{b} (5 tries in all, how many are left is not known yet)"
    deck.apply(iv.Approve(lane.id))
    deck.platform_verdict(lane.id, "t{a}", False, "Incorrect. You have 4 tries remaining.", tries_left=4)
    assert sibling.pending.detail == "submit t{b} (4 tries left of 5)"  # what the player answers is the count now
    assert "4 tries left of 5" in sibling.alert(AlertKind.FLAG).reason
    assert submitter.flags() == ["t{a}"]  # nothing else went out


def test_out_of_tries_the_approval_says_the_platform_checks_no_more_flags():
    deck, _, _ = platform_deck(submit="confirm")
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{a}"))
    deck.apply(iv.Approve(lane.id))
    deck.platform_verdict(lane.id, "t{a}", None, "CTFd did not check the flag: this account has no tries left", tries_left=0)
    deck.report(lane.id, TurnReport(flag="t{b}"))
    assert [p.detail for p in lane.waiting] == ["submit t{b} (no tries left: the platform checks no more flags for it)"]


def test_a_flag_known_wrong_by_its_turn_does_not_go_out_and_its_lane_hears_why():
    deck, driver, submitter = platform_deck()
    lane = lane_on(deck, "c0")
    sibling = fork(deck, lane)
    third = fork(deck, lane)
    deck.report(third.id, TurnReport(flag="t{b}", claimed=False))  # scraped: it waits for the player
    deck.report(lane.id, TurnReport(flag="t{a}"))  # claimed: on its way
    deck.report(sibling.id, TurnReport(flag="t{b}"))  # claimed: waits its turn behind t{a}
    assert deck.submitting("c0") == ((lane.id, "t{a}"), (sibling.id, "t{b}"))
    deck.apply(iv.Decline(third.id))  # the player: t{b} is not the flag
    deck.platform_verdict(lane.id, "t{a}", False)
    assert submitter.flags() == ["t{a}"] and deck.submitting("c0") == ()
    assert f"not sent to the platform: t{{b}} ({DECLINED})" in notes(sibling)
    assert (sibling.id, PendingKind.SUBMIT, "t{b}") in driver.named("declined")


# ---------------------------------------------------------------------- the board says how many tries


def board_with(tmp_path, **specs) -> object:
    for name, spec in specs.items():
        folder = tmp_path / "board" / name
        folder.mkdir(parents=True)
        (folder / "challenge.json").write_text(json.dumps({"name": name.title(), "category": "misc", "points": 50, **spec}))
    return tmp_path / "board"


def test_a_board_challenge_can_say_how_many_tries_the_platform_allows(tmp_path):
    board = load_board(board_with(tmp_path, capped={"max_attempts": 2}, free={}, zero={"max_attempts": 0}))
    found = {item.challenge.id: item.challenge for item in board.challenges}
    assert {cid: (ch.max_attempts, ch.tries_left, ch.limited) for cid, ch in found.items()} == {
        "capped": (2, None, True), "free": (0, None, False), "zero": (0, None, False)}


@pytest.mark.parametrize("value", [-1, "3", 2.5, True, None])
def test_a_board_refuses_tries_that_are_not_a_whole_number(tmp_path, value):
    with pytest.raises(BoardError, match='"max_attempts" must be a whole number, 0 or more'):
        load_board(board_with(tmp_path, odd={"max_attempts": value}))


# ---------------------------------------------------------------------- the console shows it


def test_the_fleet_marks_a_lane_whose_flag_is_on_its_way_to_the_platform():
    from textual.widgets import DataTable

    from ctf_flightdeck.console.app import FlightdeckApp

    deck, _, _ = platform_deck(submit="confirm")
    lane, other = lane_on(deck, "c0"), lane_on(deck, "c1")
    deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
    deck.report(other.id, TurnReport(action="solve.py", flag="t{c1}"))  # waits for the player: that chip stays
    app = FlightdeckApp(deck, refresh_seconds=None)

    def chips() -> tuple[str, str]:
        lanes = app.fleet.query_one("#lanes", DataTable)
        return tuple(str(lanes.get_cell(each.id, "!")).strip() for each in (lane, other))

    async def main() -> None:
        async with app.run_test(size=(160, 46)) as pilot:
            await pilot.pause()
            assert chips() == ("flag", "flag")
            assert deck.apply(iv.Approve(lane.id)).ok  # on its way: nothing to answer, so no alert
            app.refresh_view()
            await pilot.pause()
            assert chips() == ("sending", "flag")
            deck.platform_verdict(lane.id, "t{c0}", False, "Incorrect")
            app.refresh_view()
            await pilot.pause()
            assert chips() == ("", "flag")

    asyncio.run(main())
