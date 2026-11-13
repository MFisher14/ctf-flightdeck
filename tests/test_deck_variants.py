"""Flag variants in the deck (DeckConfig.variant_tries): after the platform's wrong, the next
other spelling of the flag is proposed on the lane, through the path a lane's own flag takes.

The deck is real; test_deck's recording driver stands in for lane work, and a recording
submitter (test_platform_submit) for the platform, which a test answers with
deck.platform_verdict(). Every flag is invented. Under the test format t\\{\\w+\\} the variants
of t{ABCD} are, in rank order: t{abcd} (lower case), t{Abcd} (a capital per word), t{4BCD}
(letters to leet), t{4bcd}, t{4bcd} being both at once.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import DECLINED, Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import AlertKind, Challenge, ChallengeStatus, DeckConfig, EventKind, LaneState, PendingKind
from ctf_flightdeck.flagvariants import MAX_VARIANTS, variants
from test_deck import FLAG_FORMAT, MODELS, Clock, RecordingDriver, events, fork, lane_on
from test_platform_submit import RecordingSubmitter, asked, notes

WRONG = "t{ABCD}"
RANKED = ["t{abcd}", "t{Abcd}", "t{4BCD}", "t{4bcd}"]


def variant_deck(*challenges: Challenge, submit: str = "auto", submitter=None, verify=None, **config):
    """A deck with a lane on c0 (and on any other challenge given): its flags go to a recording
    submitter, or with submitter=False to `verify` (a board's answers file)."""
    if submitter is None:
        submitter = RecordingSubmitter()
    deck = Deck(DeckConfig(event="t", flag_format=FLAG_FORMAT, models=MODELS, submit=submit, max_lanes=4, **config),
                RecordingDriver(), Clock(), verify or (lambda cid, flag: None), submitter=submitter or None)
    challenges = challenges or (Challenge("c0", "C", "misc", 100),)
    deck.release(list(challenges), [QueueEntry(ch.id, MODELS[0]) for ch in challenges])
    return deck, submitter


def wrong(deck, lane, flag, **more):
    deck.platform_verdict(lane.id, flag, False, "Incorrect", **more)


def submits(deck) -> list[dict]:
    return [dict(e.data) for e in events(deck, EventKind.SUBMIT)]


def test_the_test_format_ranks_the_variants_as_these_tests_take_them():
    assert [v.value for v in variants(WRONG, FLAG_FORMAT)] == RANKED


def test_off_by_default_no_variant_is_ever_proposed():
    deck, platform = variant_deck()
    assert deck.config.variant_tries == 0
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG] and lane.pending is None and deck.submitting("c0") == ()
    assert deck.variants_tried("c0") == 0 and deck.variant_of("c0", "t{abcd}") is None
    assert not any("variant" in text for text in notes(lane))


def test_after_a_wrong_flag_the_next_ranked_variant_goes_out_one_at_a_time_up_to_the_budget():
    deck, platform = variant_deck(variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    assert platform.flags() == [WRONG]  # nothing before the platform's answer
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG, "t{abcd}"] and platform.calls[-1] == (lane.id, "c0", "t{abcd}")  # one, not the list
    assert deck.submitting("c0") == ((lane.id, "t{abcd}"),) and deck.variants_tried("c0") == 1
    wrong(deck, lane, "t{abcd}")
    assert platform.flags() == [WRONG, "t{abcd}", "t{Abcd}"]  # the same list carried on, not the variants of t{abcd}
    wrong(deck, lane, "t{Abcd}")
    assert platform.flags() == [WRONG, "t{abcd}", "t{Abcd}"] and deck.variants_tried("c0") == 2  # the budget is spent
    assert deck.submitting("c0") == () and lane.pending is None and lane.state is LaneState.RUNNING
    assert deck.wrong_flags("c0") == 3  # a wrong variant is a wrong flag
    assert ("rejected", lane.id, "t{abcd}") in deck.driver.calls  # and the lane hears it is not the flag


def test_the_budget_is_per_challenge():
    deck, platform = variant_deck(Challenge("c0", "C", "misc", 100), Challenge("c1", "D", "misc", 100), variant_tries=1)
    first, second = lane_on(deck, "c0"), lane_on(deck, "c1")
    for lane in (first, second):
        deck.report(lane.id, TurnReport(flag=WRONG))
        wrong(deck, lane, WRONG)
        wrong(deck, lane, "t{abcd}")
    assert platform.calls == [(first.id, "c0", WRONG), (first.id, "c0", "t{abcd}"), (second.id, "c1", WRONG), (second.id, "c1", "t{abcd}")]
    deck.report(first.id, TurnReport(flag="t{EFGH}"))  # c0's one variant is used: another wrong flag gets none
    wrong(deck, first, "t{EFGH}")
    assert platform.flags()[-1] == "t{EFGH}" and deck.variants_tried("c0") == 1


def test_the_transcript_the_approval_and_the_event_say_which_flag_a_variant_is_of_and_what_changed():
    deck, platform = variant_deck(submit="confirm", variant_tries=3)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    assert lane.pending.detail == f"submit {WRONG}"  # the lane's own flag says nothing of variants
    assert deck.apply(iv.Approve(lane.id)).ok
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG]  # under confirm the variant waits for the player, as every flag does
    assert (lane.pending.kind, lane.pending.flag) == (PendingKind.SUBMIT, "t{abcd}")
    assert lane.pending.detail == f"submit t{{abcd}}; flightdeck's variant of {WRONG}, which the platform rejected: lower case"
    assert f"variant 1 of 3 at C: trying t{{abcd}}, a variant of {WRONG}, which the platform rejected (lower case)" in notes(lane)
    alert = lane.alert(AlertKind.FLAG)
    assert alert is not None and f"It is flightdeck's variant of {WRONG}, which the platform rejected (lower case)." in alert.reason
    assert deck.variant_of("c0", "t{abcd}") == (WRONG, "lower case") and deck.variant_of("c0", WRONG) is None
    assert deck.apply(iv.Approve(lane.id)).ok and platform.flags() == [WRONG, "t{abcd}"]
    wrong(deck, lane, "t{abcd}")
    own, variant = submits(deck)
    assert "variant_of" not in own and "variant_changes" not in own
    assert (variant["flag"], variant["correct"], variant["variant_of"], variant["variant_changes"]) == ("t{abcd}", False, WRONG, ["case:lower"])
    assert lane.pending.flag == "t{Abcd}" and lane.pending.detail.endswith(f"variant of {WRONG}, which the platform rejected: Title_Case per word")


def test_a_variant_that_is_the_flag_solves_the_challenge_for_its_lane():
    deck, platform = variant_deck(variant_tries=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG)
    deck.platform_verdict(lane.id, "t{abcd}", True, "Correct")
    ch = deck.challenges["c0"]
    assert ch.status is ChallengeStatus.SOLVED and ch.solved_by == lane.id
    assert lane.state is LaneState.SOLVED and lane.result == "solved with t{abcd}"
    assert submits(deck)[-1] == {"flag": "t{abcd}", "correct": True, "by": "platform", "variant_of": WRONG,
                                 "variant_changes": ["case:lower"], "detail": "Correct"}


def test_a_boards_answers_file_judges_a_variant_at_once():
    checked: list[str] = []

    def verify(cid: str, flag: str) -> bool:
        checked.append(flag)
        return flag == "t{Abcd}"

    deck, _ = variant_deck(submitter=False, verify=verify, variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    assert checked == [WRONG, "t{abcd}", "t{Abcd}"] and lane.state is LaneState.SOLVED
    assert deck.challenges["c0"].solved_by == lane.id and submits(deck)[-1]["variant_of"] == WRONG


def test_once_wrong_stop_is_reached_a_variant_waits_for_the_player():
    deck, platform = variant_deck(variant_tries=3, wrong_stop=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG, "t{abcd}"]  # one wrong flag so far: the variant goes
    wrong(deck, lane, "t{abcd}")  # the wrong variant is the second wrong flag
    assert platform.flags() == [WRONG, "t{abcd}"] and asked(lane) == [(PendingKind.SUBMIT, "t{Abcd}")]
    assert "2 flags were wrong at C, so t{Abcd} waits for you (wrong_stop 2)" in notes(lane)
    assert deck.apply(iv.Approve(lane.id)).ok and platform.flags()[-1] == "t{Abcd}"  # the player's yes sends it
    wrong(deck, lane, "t{Abcd}")
    assert asked(lane) == [(PendingKind.SUBMIT, "t{4BCD}")] and len(platform.calls) == 3


def test_a_variant_of_a_flag_that_went_out_on_the_players_yes_waits_for_the_player_too():
    deck, platform = variant_deck(variant_tries=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG, claimed=False))  # scraped, not claimed: it waits under auto
    assert asked(lane) == [(PendingKind.SUBMIT, WRONG)] and deck.apply(iv.Approve(lane.id)).ok
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG] and asked(lane) == [(PendingKind.SUBMIT, "t{abcd}")]
    assert any(text.endswith(f"(lower case); it waits for you, as {WRONG} went out on your yes") for text in notes(lane))


def test_a_variant_the_challenges_description_holds_waits_for_the_player():
    deck, platform = variant_deck(Challenge("c0", "C", "misc", 100, description="The flag looks like t{abcd}."), variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG] and asked(lane) == [(PendingKind.SUBMIT, "t{abcd}")]
    assert any(text.endswith("it waits for you: the challenge's description holds it") for text in notes(lane))


def test_once_the_platform_counts_the_tries_a_variant_waits_and_says_how_many_are_left():
    deck, platform = variant_deck(variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG, tries_left=3)  # the platform's answer says it counts the tries
    assert platform.flags() == [WRONG] and asked(lane) == [(PendingKind.SUBMIT, "t{abcd}")]
    assert lane.pending.detail == f"submit t{{abcd}} (3 tries left); flightdeck's variant of {WRONG}, which the platform rejected: lower case"
    deck.platform_tries("c0", 2)  # a newer count keeps what the approval says about the variant
    assert lane.pending.detail == f"submit t{{abcd}} (2 tries left); flightdeck's variant of {WRONG}, which the platform rejected: lower case"


def test_a_challenge_with_counted_tries_never_gets_a_variant_sent_on_its_own():
    deck, platform = variant_deck(Challenge("c0", "C", "misc", 100, max_attempts=5), variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    assert platform.flags() == [] and deck.apply(iv.Approve(lane.id)).ok
    wrong(deck, lane, WRONG, tries_left=4)
    assert platform.flags() == [WRONG] and asked(lane) == [(PendingKind.SUBMIT, "t{abcd}")]


def test_no_variant_once_the_challenge_is_out_of_tries():
    deck, platform = variant_deck(variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG, tries_left=0)
    assert platform.flags() == [WRONG] and deck.variants_tried("c0") == 0 and lane.state is LaneState.STOPPED
    assert not any(e.data.get("variant") for e in events(deck, EventKind.WARNING))


def test_under_autopilots_guard_a_variant_never_spends_the_last_try():
    deck, platform = variant_deck(variant_tries=2, submit_limited="auto")
    deck.autopilot = SimpleNamespace(guarding=True)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG, tries_left=2)
    assert platform.flags() == [WRONG, "t{abcd}"]  # the player opted in to spending counted tries: it goes
    wrong(deck, lane, "t{abcd}", tries_left=1)
    assert platform.flags() == [WRONG, "t{abcd}"] and asked(lane) == [(PendingKind.SUBMIT, "t{Abcd}")]  # the last one waits
    kept = [e.data for e in events(deck, EventKind.WARNING) if e.data.get("autopilot") == "last_try"]
    assert [d["flag"] for d in kept] == ["t{Abcd}"]


def test_only_the_platforms_own_wrong_gets_variants():
    # the player's word after a hand submit (a board that cannot check flags)
    deck, _ = variant_deck(submitter=False, submit="confirm", variant_tries=3)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    assert deck.apply(iv.Approve(lane.id)).ok and lane.pending.kind is PendingKind.CONFIRM
    assert deck.apply(iv.Decline(lane.id)).ok and deck.wrong_flags("c0") == 1  # "the platform rejected it", the player says
    assert lane.pending is None and deck.variants_tried("c0") == 0
    # a flag the player declined to submit
    deck, platform = variant_deck(submit="confirm", variant_tries=3)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    assert deck.apply(iv.Decline(lane.id)).ok and lane.pending is None and deck.variants_tried("c0") == 0
    # an answer that is no verdict (rate-limited, paused): the flag goes back to the player, without variants
    deck, platform = variant_deck(variant_tries=3)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    deck.platform_verdict(lane.id, WRONG, None, "the platform is paused")
    assert asked(lane) == [(PendingKind.CONFIRM, WRONG)] and platform.flags() == [WRONG]
    assert deck.apply(iv.Decline(lane.id)).ok and lane.pending is None and deck.variants_tried("c0") == 0


def test_a_declined_variant_ends_the_chain_and_is_never_proposed_again():
    deck, platform = variant_deck(submit="confirm", variant_tries=3)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    deck.apply(iv.Approve(lane.id))
    wrong(deck, lane, WRONG)
    assert lane.pending.flag == "t{abcd}" and deck.apply(iv.Decline(lane.id)).ok
    assert lane.pending is None and deck.not_flag("c0", "t{abcd}") == DECLINED  # a decline is not the platform's wrong: no next one
    deck.report(lane.id, TurnReport(flag="t{EFGH}"))
    deck.apply(iv.Approve(lane.id))
    wrong(deck, lane, "t{EFGH}")
    assert lane.pending.flag == "t{efgh}"  # the next wrong flag gets its own
    deck.apply(iv.Approve(lane.id))
    wrong(deck, lane, "t{efgh}")
    assert lane.pending.flag == "t{Efgh}" and platform.flags() == [WRONG, "t{EFGH}", "t{efgh}"]  # t{abcd} never came back


def test_a_variant_known_wrong_or_already_under_way_is_passed_over():
    deck, platform = variant_deck(variant_tries=4, wrong_stop=0)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag="t{abcd}"))  # the lane's own flag, wrong; its one variant is t{4bcd}
    wrong(deck, lane, "t{abcd}")
    wrong(deck, lane, "t{4bcd}")
    assert platform.flags() == ["t{abcd}", "t{4bcd}"] and deck.submitting("c0") == ()  # that list is used up
    deck.report(lane.id, TurnReport(flag=WRONG))  # two of its variants are known wrong by now
    deck.report(lane.id, TurnReport(flag="t{Abcd}"))  # and the lane claims a third itself: it waits its turn
    wrong(deck, lane, WRONG)
    assert [flag for _, flag in deck.submitting("c0")] == ["t{Abcd}", "t{4BCD}"]  # the variant: the first one left
    assert deck.variant_of("c0", "t{4BCD}") == (WRONG, "letters to leet") and deck.variant_of("c0", "t{Abcd}") is None
    wrong(deck, lane, "t{Abcd}")
    wrong(deck, lane, "t{4BCD}")
    assert platform.flags() == ["t{abcd}", "t{4bcd}", WRONG, "t{Abcd}", "t{4BCD}"]  # nothing sent twice
    assert deck.variants_tried("c0") == 2 and deck.submitting("c0") == ()  # and nothing is left to try


def test_a_variant_the_lane_claims_itself_later_is_not_sent_twice_and_stays_a_variant():
    deck, platform = variant_deck(variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG)
    deck.report(lane.id, TurnReport(flag="t{abcd}"))  # the lane comes to the same spelling while it is on its way
    assert platform.flags() == [WRONG, "t{abcd}"] and lane.pending is None
    wrong(deck, lane, "t{abcd}")
    assert submits(deck)[-1]["variant_of"] == WRONG and platform.flags() == [WRONG, "t{abcd}", "t{Abcd}"]
    deck.report(lane.id, TurnReport(flag="t{abcd}"))  # and again once it is known wrong: never asked, never sent
    assert len(platform.calls) == 3 and "candidate t{abcd} again; not asked: rejected by the platform" in notes(lane)


def test_when_the_lane_has_ended_no_variant_goes_out_and_a_warning_names_it():
    deck, platform = variant_deck(variant_tries=2)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    assert deck.apply(iv.Kill(lane.id)).ok and lane.finished
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG] and lane.pending is None and deck.variants_tried("c0") == 0
    (warning,) = [e for e in events(deck, EventKind.WARNING) if e.data.get("variant")]
    assert warning.text == (f"{WRONG} was wrong for C, and no variant is tried: {lane.id} has ended. The next one would be "
                            "t{abcd} (lower case): submit it by hand if you think it is the flag")
    assert dict(warning.data) == {"variant": "t{abcd}", "variant_of": WRONG, "variant_changes": ["case:lower"], "lanes": [lane.id]}


def test_a_lane_that_gave_up_stays_open_for_its_variants_answer_and_ends_after_it():
    deck, platform = variant_deck(variant_tries=1)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    deck.report(lane.id, TurnReport(turn=False, gave_up="the model gave up"))
    assert not lane.finished  # open for its flag's answer
    wrong(deck, lane, WRONG)
    assert platform.flags() == [WRONG, "t{abcd}"] and not lane.finished  # and now for the variant's
    wrong(deck, lane, "t{abcd}")
    assert lane.state is LaneState.GAVE_UP and platform.flags() == [WRONG, "t{abcd}"]


def test_with_several_lanes_on_a_challenge_one_variant_goes_out_on_the_first_sender_still_open():
    deck, platform = variant_deck(variant_tries=3, wrong_stop=0)
    first = lane_on(deck, "c0")
    second = fork(deck, first)
    deck.report(first.id, TurnReport(flag=WRONG))
    deck.report(second.id, TurnReport(flag=WRONG))  # the same flag from the sibling: it hears the answer too
    wrong(deck, first, WRONG)
    assert platform.calls == [(first.id, "c0", WRONG), (first.id, "c0", "t{abcd}")]  # once, on the first sender
    assert not any("variant 1 of 3" in text for text in notes(second))
    deck.report(second.id, TurnReport(flag="t{EFGH}"))  # the sibling's own wrong flag, while the variant is under way
    assert deck.apply(iv.Kill(first.id)).ok
    wrong(deck, first, "t{abcd}")  # the variant's lane has ended: the chain stops with a warning
    assert [flag for _, flag in deck.submitting("c0")] == ["t{EFGH}"] and deck.variants_tried("c0") == 1
    assert [e.data["variant"] for e in events(deck, EventKind.WARNING) if e.data.get("variant")] == ["t{Abcd}"]
    wrong(deck, second, "t{EFGH}")  # one at a time held while t{abcd} was under way; now the sibling's flag gets its own
    assert platform.calls[-1] == (second.id, "c0", "t{efgh}") and deck.variant_of("c0", "t{efgh}") == ("t{EFGH}", "lower case")
    wrong(deck, second, "t{efgh}")
    assert platform.calls[-1] == (second.id, "c0", "t{Efgh}") and deck.variants_tried("c0") == 3
    wrong(deck, second, "t{Efgh}")
    assert len(platform.calls) == 5 and deck.submitting("c0") == ()  # the budget is the challenge's, not the lane's


def test_when_the_first_sender_has_ended_the_variant_goes_on_the_next_lane_that_sent_the_flag():
    deck, platform = variant_deck(variant_tries=1)
    first = lane_on(deck, "c0")
    second = fork(deck, first)
    deck.report(first.id, TurnReport(flag=WRONG))
    deck.report(second.id, TurnReport(flag=WRONG))
    assert deck.apply(iv.Kill(first.id)).ok
    wrong(deck, first, WRONG)
    assert platform.calls == [(first.id, "c0", WRONG), (second.id, "c0", "t{abcd}")]
    assert any("variant 1 of 1 at C: trying t{abcd}" in text for text in notes(second))


def test_only_one_proposed_variant_is_open_at_a_time_across_the_lanes_of_a_challenge():
    deck, platform = variant_deck(submit="confirm", variant_tries=3)
    first = lane_on(deck, "c0")
    second = fork(deck, first)
    deck.report(first.id, TurnReport(flag=WRONG))
    deck.apply(iv.Approve(first.id))
    wrong(deck, first, WRONG)
    assert asked(first) == [(PendingKind.SUBMIT, "t{abcd}")]  # the variant waits for the player on the first lane
    deck.report(second.id, TurnReport(flag="t{EFGH}"))
    deck.apply(iv.Approve(second.id))
    wrong(deck, second, "t{EFGH}")
    assert asked(second) == [] and deck.variants_tried("c0") == 1  # nothing new while that one waits
    deck.apply(iv.Approve(first.id))
    wrong(deck, first, "t{abcd}")
    assert asked(first) == [(PendingKind.SUBMIT, "t{Abcd}")]  # its list is carried on first
    assert platform.flags() == [WRONG, "t{EFGH}", "t{abcd}"]


def test_a_variant_judged_after_the_challenge_was_solved_says_so_in_its_event_and_starts_nothing():
    deck, platform = variant_deck(variant_tries=3, wrong_stop=0)
    lane = lane_on(deck, "c0")
    deck.report(lane.id, TurnReport(flag=WRONG))
    wrong(deck, lane, WRONG)
    deck.platform_solved("c0", "your team")
    wrong(deck, lane, "t{abcd}")
    last = submits(deck)[-1]
    assert (last["flag"], last["solved_meanwhile"], last["variant_of"]) == ("t{abcd}", True, WRONG)
    assert platform.flags() == [WRONG, "t{abcd}"] and deck.variants_tried("c0") == 1


def test_variant_tries_must_be_a_whole_number_within_the_list():
    assert DeckConfig(event="t", variant_tries=MAX_VARIANTS).variant_tries == MAX_VARIANTS
    for bad in (-1, MAX_VARIANTS + 1, True, 1.0, "2"):
        with pytest.raises(ValueError, match=f"variant_tries must be a whole number from 0 to {MAX_VARIANTS}"):
            DeckConfig(event="t", variant_tries=bad)
