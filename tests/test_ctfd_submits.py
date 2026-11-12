"""Flags to CTFd in a real run: from one worker off the console's loop, one at a time, with
CTFd's answer applied when it comes; the tries CTFd counts, from the pull and from its
answers; and the flags still on their way when the run ends.

The CTFd is tests/fake_ctfd.py and the model tests/fake_model.py, both on 127.0.0.1 (the
setup is test_event_run.py's): nothing real is contacted and nothing is mocked in between.
A fake CTFd that holds its answers stands in for a slow one: the test lets them go.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.model import ChallengeStatus, LaneState, PendingKind
from ctf_flightdeck.platform.ctfd import Attempt, CTFdVerifier, Verdict
from ctf_flightdeck.run import RunOptions, prepare_run

from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd, Reply, sample
from fake_model import FakeModelServer
from test_ctfd import pulled
from test_event_run import Model, config, event, log, play, platform_solves, submit, three, token, wait_for  # noqa: F401

ATTEMPT = "/api/v1/challenges/attempt"


def auto_run(tmp_path, fake, server, *, max_lanes: int = 1, **options):
    """A CTFd run under the submit policy auto, its lanes on the fake model."""
    return prepare_run(RunOptions(board=tmp_path / "board", event=event(tmp_path, url=fake.base_url, submit="auto"),
                                  config=config(tmp_path, server.base_url, max_lanes=max_lanes), **options))


def submits(run) -> list[tuple[str, bool, str]]:
    """(flag, correct, by) of each submit event in the run log."""
    return [(e["data"]["flag"], e["data"]["correct"], e["data"]["by"]) for e in log(run) if e["kind"] == "submit"]


# ---------------------------------------------------------------------- a slow CTFd


def test_a_slow_ctfd_holds_up_neither_the_console_nor_the_lane(tmp_path, token):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        fake.hold_attempts = threading.Event()
        run = auto_run(tmp_path, fake, server)

        async def body(run):
            lane = run.deck.lanes["L01"]
            # CTFd has the flag and holds its answer; this runs on the console's loop all the while
            await wait_for(lambda: len(fake.to(ATTEMPT)) == 1, "the flag at CTFd")
            assert run.deck.submitting("warmup") == ((lane.id, "test{hello}"),)
            assert "sending test{hello} to the platform; its answer comes back on its own" in [a.text for a in lane.actions]
            turns = lane.turns
            await wait_for(lambda: lane.turns >= turns + 2, "the lane's next turns while CTFd thinks")
            assert lane.state is LaneState.RUNNING and run.deck.challenges["warmup"].status is ChallengeStatus.RUNNING
            assert run.deck.apply(iv.Hint(lane.id, "keep going")).ok  # the player is answered at once too
            fake.hold_attempts.set()
            await wait_for(lambda: lane.state is LaneState.SOLVED, "CTFd's answer")

        play(run, body)
    assert submits(run) == [("test{hello}", True, "platform")] and run.deck.submitting("warmup") == ()
    assert [r.json for r in fake.to(ATTEMPT)] == [{"challenge_id": 1, "submission": "test{hello}"}]


def test_one_flag_goes_to_ctfd_at_a_time_for_a_challenge(tmp_path, token):
    model = Model({"Warmup": [submit("test{nope}"), submit("test{hello}")]})
    with FakeCTFd(three()) as fake, FakeModelServer(responder=model) as server:
        fake.hold_attempts = threading.Event()
        run = auto_run(tmp_path, fake, server)

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: len(run.deck.submitting("warmup")) == 2, "the second flag behind the first")
            assert run.deck.submitting("warmup") == ((lane.id, "test{nope}"), (lane.id, "test{hello}"))
            await asyncio.sleep(0.2)
            assert [r.json["submission"] for r in fake.to(ATTEMPT)] == ["test{nope}"]  # never two at once
            fake.hold_attempts.set()
            await wait_for(lambda: lane.state is LaneState.SOLVED, "both answers")

        play(run, body)
    assert submits(run) == [("test{nope}", False, "platform"), ("test{hello}", True, "platform")]


def test_a_solve_ctfd_lists_while_our_flag_is_on_its_way_waits_for_that_flags_answer(tmp_path, token):
    with FakeCTFd(three()) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        fake.hold_attempts = threading.Event()
        run = auto_run(tmp_path, fake, server, solves_seconds=0.05)

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: len(fake.to(ATTEMPT)) == 1, "the flag at CTFd")
            assert fake.solved == {1}  # CTFd took it; its answer has not come back yet
            polls = len(fake.to("/api/v1/teams/me/solves"))
            await wait_for(lambda: len(fake.to("/api/v1/teams/me/solves")) >= polls + 3, "polls that list it solved")
            assert not run.deck.challenges["warmup"].closed  # the solve may be this very flag's
            fake.hold_attempts.set()
            await wait_for(lambda: lane.state is LaneState.SOLVED, "CTFd's answer")

        play(run, body)
    assert run.deck.challenges["warmup"].solved_by == "L01" and platform_solves(run) == []


# ---------------------------------------------------------------------- the end of the run


def test_flags_on_their_way_when_the_run_ends_are_named_as_not_known_to_have_been_submitted(tmp_path, token):
    model = Model({"Warmup": [submit("test{nope}"), submit("test{hello}")], "Baby RSA": [submit("test{rsa}")]})
    with FakeCTFd(three()) as fake, FakeModelServer(responder=model) as server:
        fake.hold_attempts = threading.Event()
        run = auto_run(tmp_path, fake, server, max_lanes=2)

        async def main() -> tuple[list[str], list[str]]:
            run.release()
            try:
                await wait_for(
                    lambda: len(fake.to(ATTEMPT)) == 1 and len(run.deck.submitting("warmup")) == 2
                    and run.deck.submitting("baby-rsa"), "three flags on their way, one of them at CTFd",
                )
                sent = [r.json["submission"] for r in fake.to(ATTEMPT)]
            finally:
                await run.shutdown()
                fake.hold_attempts.set()  # the worker's thread may end now
            await asyncio.sleep(0.5)  # a submit worker still going would now take CTFd's answer and send the next flag
            return sent, [r.json["submission"] for r in fake.to(ATTEMPT)]

        (sent,), after = asyncio.run(main())
        run.close()
    assert after == [sent]  # the worker stopped with the run: nothing went to CTFd after it
    lanes = {"test{nope}": "L01, Warmup", "test{hello}": "L01, Warmup", "test{rsa}": "L02, Baby RSA"}
    waiting = next(flag for flag in ("test{nope}", "test{rsa}") if flag != sent)
    assert sorted(e for e in run.errors if e.startswith("CTFd: ")) == sorted([
        f"CTFd: {sent} ({lanes[sent]}) was on its way to CTFd when the run ended, so it is not known to have been "
        "submitted: check the challenge on CTFd before you submit it again",
        f"CTFd: {waiting} ({lanes[waiting]}) was not submitted: it was waiting to go to CTFd when the run ended",
        "CTFd: test{hello} (L01, Warmup) was not submitted: it was waiting for the answer to another flag of that "
        "challenge when the run ended",
    ])


# ---------------------------------------------------------------------- the tries CTFd counts


def test_under_auto_a_ctfd_challenge_with_limited_tries_waits_for_the_player(tmp_path, token):
    capped = FakeChallenge(1, "Warmup", category="Misc", value=50, flag="test{hello}", max_attempts=3)
    with FakeCTFd([capped]) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        run = auto_run(tmp_path, fake, server)

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the flag")
            assert (lane.pending.kind, lane.pending.detail) == (  # CTFd's details say none of the 3 is used yet
                PendingKind.SUBMIT, "submit test{hello} (3 tries left of 3)")
            await asyncio.sleep(0.2)
            assert fake.to(ATTEMPT) == []  # nothing went to CTFd without the player
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.state is LaneState.SOLVED, "CTFd's answer")

        play(run, body)
    assert json.loads((tmp_path / "board" / "warmup" / "challenge.json").read_text())["max_attempts"] == 3
    assert run.deck.challenges["warmup"].max_attempts == 3


def test_a_wrong_flag_ctfd_answers_with_the_tries_left_switches_the_challenge_to_confirm(tmp_path, token):
    left = {"success": True, "data": {"status": "incorrect", "message": "Incorrect. You have 2 tries remaining."}}
    model = Model({"Warmup": [submit("test{nope}"), submit("test{maybe}")]})
    with FakeCTFd(three()) as fake, FakeModelServer(responder=model) as server:
        fake.script("POST", ATTEMPT, Reply(200, left))  # the board does not know the limit; CTFd's answer says it
        run = auto_run(tmp_path, fake, server)

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None and lane.pending.flag == "test{maybe}", "the next flag")
            assert lane.pending.detail == "submit test{maybe} (2 tries left)" and run.deck.challenges["warmup"].tries_left == 2
            await asyncio.sleep(0.2)
            assert [r.json["submission"] for r in fake.to(ATTEMPT)] == ["test{nope}"]

        play(run, body)
    (wrong,) = [e["data"] for e in log(run) if e["kind"] == "submit"]
    assert (wrong["flag"], wrong["correct"], wrong["tries_left"]) == ("test{nope}", False, 2)
    assert wrong["detail"] == "Incorrect. You have 2 tries remaining."


@pytest.mark.parametrize("lockout, said", [
    ("ratelimited", "Not accepted. You have 0 tries remaining"),  # CTFd 3.8.9
    ("incorrect", "You have 0 tries remaining"),  # an older CTFd
], ids=["CTFd 3.8.9", "older CTFd"])
def test_out_of_tries_on_ctfd_the_challenge_closes_for_the_run_and_its_unchecked_flag_is_never_called_wrong(
    tmp_path, token, lockout, said
):
    # the rehearsal's Two Strikes: a wrong flag through flightdeck, the team's last try spent by a teammate on CTFd,
    # then the lane's right flag, which CTFd answers out of tries without checking it
    capped = FakeChallenge(1, "Warmup", category="Misc", value=50, flag="test{hello}", max_attempts=2)
    model = Model({"Warmup": [submit("test{nope}"), submit("test{hello}")]})
    with FakeCTFd([capped], lockout=lockout) as fake, FakeModelServer(responder=model) as server:
        run = auto_run(tmp_path, fake, server)

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None and lane.pending.flag == "test{nope}", "the wrong flag")
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.pending is not None and lane.pending.flag == "test{hello}", "the right flag")
            assert lane.pending.detail == "submit test{hello} (1 try left of 2: the last one)"
            fake.teammate_fails(1)  # the teammate spends the team's last try
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.finished, "CTFd's answer")

        play(run, body)
    ch, lane = run.deck.challenges["warmup"], run.deck.lanes["L01"]
    assert (ch.status, ch.tries_left, ch.note) == (ChallengeStatus.BLOCKED, 0, "out of tries: the platform checks no more flags for it")
    assert (lane.state, lane.result) == (LaneState.STOPPED, "Warmup is out of tries: the platform checks no more flags for it")
    assert [r.json["submission"] for r in fake.to(ATTEMPT)] == ["test{nope}", "test{hello}"]
    assert submits(run) == [("test{nope}", False, "platform")]  # the right flag is never recorded wrong
    assert run.deck.not_flag("warmup", "test{hello}") is None and run.deck.not_flag("warmup", "test{nope}") is not None
    assert not [e for e in log(run) if e["kind"] == "pending" and e["data"]["kind"] == "confirm"]  # no hand submit asked
    (warning,) = [e for e in log(run) if e["kind"] == "warning"]  # one, and no advice to wait
    assert warning["text"] == (
        "Warmup is out of tries: the platform checks no more flags for it, so flightdeck closed it and stopped L01. "
        "test{hello} is not known to be wrong: CTFd did not check the flag: this account has no tries "
        f"left on this challenge (CTFd says: {said})"
    )
    assert warning["data"] == {"out_of_tries": True, "tries_left": 0, "flag": "test{hello}", "checked": False,
                               "stopped": ["L01"], "before_run": False}


def test_a_new_run_knows_the_tries_already_used_on_ctfd(tmp_path, token):
    board = [FakeChallenge(1, "Warmup", category="Misc", value=50, flag="test{hello}", max_attempts=2),
             FakeChallenge(2, "Baby RSA", category="Crypto", value=100, flag="test{rsa}", max_attempts=2)]
    with FakeCTFd(board) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        fake.teammate_fails(1)  # one of Warmup's two tries is gone before the run
        fake.teammate_fails(2, 2)  # and both of Baby RSA's
        run = auto_run(tmp_path, fake, server, max_lanes=2)
        notes = run.notes()

        async def body(run):
            (lane,) = run.deck.lanes.values()
            await wait_for(lambda: lane.pending is not None, "the flag")
            assert lane.pending.detail == "submit test{hello} (1 try left of 2: the last one)"

        play(run, body)
    assert [lane.challenge_id for lane in run.deck.lanes.values()] == ["warmup"]  # no lane on Baby RSA
    rsa = run.deck.challenges["baby-rsa"]
    assert (rsa.status, rsa.tries_left, rsa.note) == (ChallengeStatus.BLOCKED, 0, "out of tries: the platform checks no more flags for it")
    assert run.deck.challenges["warmup"].tries_left == 1 and fake.to(ATTEMPT) == []
    assert "Warmup: CTFd allows 2 tries at its flag and 1 is left; each of its flags waits for you" in notes
    assert ("Baby RSA: CTFd says no tries are left at its flag (2 allowed), so it is out of tries: no lane works it "
            "and flightdeck sends no flag for it while CTFd says so") in notes
    (warning,) = [e for e in log(run) if e["kind"] == "warning"]
    assert warning["challenge"] == "baby-rsa" and warning["text"] == (
        "Baby RSA is out of tries: the platform checks no more flags for it, so flightdeck closed it "
        "(the platform said so before the run started)"
    )
    assert (warning["data"]["before_run"], warning["data"]["stopped"]) == (True, [])


def test_each_wave_reads_the_tries_a_teammate_spent_and_none_left_stops_the_lane_before_its_flag_goes(tmp_path, token):
    capped = FakeChallenge(1, "Warmup", category="Misc", value=50, flag="test{hello}", max_attempts=2)
    with FakeCTFd([capped]) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{maybe}")]})) as server:
        run = auto_run(tmp_path, fake, server, wave_seconds=0.05)

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the flag")
            assert lane.pending.detail == "submit test{maybe} (2 tries left of 2)"
            fake.teammate_fails(1)
            await wait_for(lambda: lane.pending.detail == "submit test{maybe} (1 try left of 2: the last one)",
                           "the count a wave reads")
            fake.teammate_fails(1)
            await wait_for(lambda: lane.finished, "the wave that finds no try left")

        play(run, body)
    lane = run.deck.lanes["L01"]
    assert fake.to(ATTEMPT) == []  # the flag that waited for the player never went
    assert run.deck.challenges["warmup"].status is ChallengeStatus.BLOCKED
    assert (lane.state, lane.result) == (LaneState.STOPPED, "Warmup is out of tries: the platform checks no more flags for it")
    assert "not submitted: test{maybe} (Warmup is out of tries: the platform checks no more flags for it)" in [
        a.text for a in lane.actions]


def test_a_new_run_works_a_challenge_whose_ctfd_count_of_tries_takes_partial_answers(tmp_path, token):
    # CTFd's limit counts wrong flags only; its details count the partial answers too: 2 of 2 used, yet 1 try is left
    two_parts = FakeChallenge(1, "Two Parts", category="Misc", value=50, flag="test{both}", partial=("test{half}",),
                              max_attempts=2)
    with FakeCTFd([two_parts]) as fake, FakeModelServer(responder=Model({"Two Parts": [submit("test{both}")]})) as server:
        fake.teammate_partials(1)
        fake.teammate_fails(1)
        run = auto_run(tmp_path, fake, server)
        notes = run.notes()

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the flag")
            assert lane.pending.detail == "submit test{both} (2 tries in all, how many are left is not known yet)"
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.state is LaneState.SOLVED, "CTFd's answer")

        play(run, body)
    assert submits(run) == [("test{both}", True, "platform")] and fake.solved == {1}
    assert not [note for note in notes if "Two Parts" in note] and not [e for e in log(run) if e["kind"] == "warning"]


def test_under_ctfds_timeout_behaviour_a_wave_that_finds_tries_left_again_opens_the_challenge(tmp_path, token):
    capped = FakeChallenge(1, "Warmup", category="Misc", value=50, flag="test{hello}", max_attempts=2)
    window = {"id": 1, "name": "Warmup", "value": 50, "category": "Misc", "description": "", "max_attempts": 2,
              "attempts": 2, "logic": "any", "solved_by_me": False, "files": [], "type": "standard", "solves": 0}
    with FakeCTFd([capped]) as fake, FakeModelServer(responder=Model({})) as server:
        # the first pull comes inside CTFd's timeout: both tries used; the waves come after it (the fake's own count)
        fake.script("GET", "/api/v1/challenges/1", Reply(200, {"success": True, "data": window}))
        run = auto_run(tmp_path, fake, server, wave_seconds=0.05)

        async def body(run):
            ch = run.deck.challenges["warmup"]
            assert (ch.status, ch.tries_left, run.deck.lanes) == (ChallengeStatus.BLOCKED, 0, {})
            await wait_for(lambda: ch.status is ChallengeStatus.PARKED, "a wave that finds the tries back")
            assert (ch.tries_left, ch.note) == (2, "out of tries no more: the platform says 2 tries left of 2")
            assert run.deck.apply(iv.Queue("warmup")).ok
            assert [lane.challenge_id for lane in run.deck.active_lanes()] == ["warmup"]

        play(run, body)
    closed, opened = [e for e in log(run) if e["kind"] == "warning"]
    assert closed["data"]["out_of_tries"] is True and closed["data"]["before_run"] is True
    assert opened["challenge"] == "warmup" and opened["text"] == (
        "Warmup is out of tries no more: the platform now says 2 tries left of 2, so flightdeck opened it again; "
        "queue it to work it"
    )
    assert opened["data"] == {"out_of_tries": False, "tries_left": 2}


MINUTE = {"success": True, "data": {"status": "ratelimited", "message": "Not accepted. You have 0 tries remaining"}}


def test_a_no_tries_answer_that_is_ctfds_limit_within_a_minute_leaves_the_challenge_open(tmp_path, token):
    # CTFd 3.8.9 says it too once the account made as many tries as the limit within a minute, refused ones among them
    capped = FakeChallenge(1, "Warmup", category="Misc", value=50, flag="test{hello}", max_attempts=2)
    with FakeCTFd([capped]) as fake, FakeModelServer(responder=Model({"Warmup": [submit("test{hello}")]})) as server:
        fake.teammate_fails(1)  # one try of the two is spent
        run = auto_run(tmp_path, fake, server)

        async def body(run):
            lane = run.deck.lanes["L01"]
            await wait_for(lambda: lane.pending is not None, "the flag")
            fake.script("POST", ATTEMPT, Reply(403, MINUTE))
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.pending is not None and lane.pending.kind is PendingKind.CONFIRM, "a hand submit")

        play(run, body)
    ch, lane = run.deck.challenges["warmup"], run.deck.lanes["L01"]
    assert (ch.status, ch.tries_left, lane.finished) == (ChallengeStatus.RUNNING, 1, False)
    assert run.deck.not_flag("warmup", "test{hello}") is None and submits(run) == []
    (warning,) = [e for e in log(run) if e["kind"] == "warning"]
    assert warning["text"] == (
        "CTFd did not judge test{hello} for Warmup: CTFd did not check the flag (CTFd says: Not accepted. You have 0 "
        "tries remaining), but it counts 1 of its 2 tries as used, so that was its limit on tries within a minute, "
        "which passes: wait a minute, then submit it by hand"
    )


def test_a_pull_carries_the_tries_ctfd_allows_onto_the_board(tmp_path):
    board = [FakeChallenge(1, "Capped", max_attempts=3), FakeChallenge(2, "Free"), FakeChallenge(3, "Unsaid", max_attempts=None)]
    with FakeCTFd(board) as fake:
        result = pulled(fake, tmp_path / "board")
    found = {item.challenge.id: item.challenge for item in result.board.challenges}
    assert {cid: ch.max_attempts for cid, ch in found.items()} == {"capped": 3, "free": 0, "unsaid": 0}
    spec = json.loads((tmp_path / "board" / "capped" / "challenge.json").read_text())
    assert spec["max_attempts"] == 3
    assert "max_attempts" not in json.loads((tmp_path / "board" / "free" / "challenge.json").read_text())


def test_a_pull_reads_the_tries_left_from_the_attempts_ctfds_details_say_are_used(tmp_path):
    board = [FakeChallenge(1, "One Used", max_attempts=2), FakeChallenge(2, "All Used", max_attempts=2),
             FakeChallenge(3, "Solved", max_attempts=3), FakeChallenge(4, "Any Number")]
    with FakeCTFd(board) as fake:
        fake.teammate_fails(1)
        fake.teammate_fails(2, 2)
        fake.teammate_fails(3)
        fake.solved = {3}  # solved: its tries no longer matter
        fake.teammate_fails(4, 5)  # no limit, so no count
        result = pulled(fake, tmp_path / "board")
    assert result.tries == {"one-used": 1, "all-used": 0} and result.tries_unread == ()


def test_a_pull_reads_no_tries_left_from_a_count_that_can_hold_partial_answers(tmp_path):
    # CTFd's limit counts wrong flags only; its details count partial answers too, on a challenge whose logic takes them
    board = [FakeChallenge(1, "Two Parts", max_attempts=2, partial=("test{half}",)),
             FakeChallenge(2, "Team Flag", max_attempts=2, logic="team"),
             FakeChallenge(3, "Untouched", max_attempts=2, partial=("test{half}",)),
             FakeChallenge(4, "Plain", max_attempts=2)]
    with FakeCTFd(board) as fake:
        fake.teammate_partials(1)
        fake.teammate_fails(1)  # 2 of 2 used as the details count them, 1 as the limit does
        fake.teammate_fails(2, 2)  # wrong flags all, but nothing CTFd tells a player says so
        fake.teammate_fails(4, 2)
        result = pulled(fake, tmp_path / "board")
    assert result.tries == {"untouched": 2, "plain": 0} and result.tries_unread == ()


def test_a_pull_from_a_ctfd_whose_details_do_not_say_the_attempts_counts_none(tmp_path):
    with FakeCTFd([FakeChallenge(1, "Capped", max_attempts=2)]) as fake:
        older = {"id": 1, "name": "Capped", "value": 100, "category": "misc", "description": "", "max_attempts": 2,
                 "files": [], "type": "standard", "solves": 0}  # an older CTFd: no "attempts"
        fake.script("GET", "/api/v1/challenges/1", Reply(200, {"success": True, "data": older}))
        result = pulled(fake, tmp_path / "board")
    assert [b.challenge.id for b in result.board.challenges] == ["capped"]
    assert result.tries == {} and result.tries_unread == ()  # its approvals say how many are left is not known yet


@pytest.mark.parametrize("value", ["1", -1, 1.5, True])
def test_a_count_of_tries_used_that_is_not_one_is_said_and_the_challenge_is_pulled_all_the_same(tmp_path, value):
    with FakeCTFd([FakeChallenge(1, "Capped", max_attempts=2)]) as fake:
        odd = {"id": 1, "name": "Capped", "value": 100, "category": "misc", "description": "", "max_attempts": 2,
               "attempts": value, "files": [], "type": "standard", "solves": 0}
        fake.script("GET", "/api/v1/challenges/1", Reply(200, {"success": True, "data": odd}))
        result = pulled(fake, tmp_path / "board")
    assert [b.challenge.id for b in result.board.challenges] == ["capped"] and result.tries == {}
    assert result.tries_unread == ('challenge 1 ("Capped"): CTFd\'s count of its tries used (attempts) is not a whole number, '
                                   "so how many are left is not known",)


def test_a_pull_again_asks_ctfd_for_the_tries_used_of_each_limited_challenge_pulled_before_and_no_other(tmp_path):
    board = [FakeChallenge(1, "Capped", max_attempts=3), FakeChallenge(2, "Free")]
    with FakeCTFd(board) as fake:
        assert pulled(fake, tmp_path / "board").tries == {"capped": 3}
        fake.teammate_fails(1, 2)  # a teammate spends two tries on CTFd, outside flightdeck
        again = pulled(fake, tmp_path / "board")
        asked = [r.route for r in fake.requests if r.route.startswith("/api/v1/challenges/") and r.method == "GET"]
    assert again.added == () and again.tries == {"capped": 1}
    assert asked == ["/api/v1/challenges/1", "/api/v1/challenges/2", "/api/v1/challenges/1"]  # Free is not asked again


def test_a_pull_again_that_cannot_read_a_challenges_tries_says_why_and_goes_on(tmp_path):
    with FakeCTFd([FakeChallenge(1, "Capped", max_attempts=3), FakeChallenge(2, "Free")]) as fake:
        pulled(fake, tmp_path / "board")
        fake.script("GET", "/api/v1/challenges/1", *[Reply(500, {"message": "the database is broken"})] * 3)
        again = pulled(fake, tmp_path / "board")
    assert again.tries == {} and len(again.board.challenges) == 2
    (line,) = again.tries_unread
    assert line.startswith('challenge 1 ("Capped"): could not read how many of its tries are used: ')
    assert "HTTP 500" in line and "the database is broken" in line


@pytest.mark.parametrize("value", ["3", -1, 2.5, True])
def test_a_pull_leaves_out_a_challenge_whose_tries_are_not_a_count_and_says_why(tmp_path, value):
    with FakeCTFd([FakeChallenge(1, "Odd", max_attempts=value), FakeChallenge(2, "Fine")]) as fake:
        result = pulled(fake, tmp_path / "board")
    assert [item.challenge.id for item in result.board.challenges] == ["fine"]
    (problem,) = result.problems
    assert "its max_attempts (the tries CTFd allows) is not a whole number, 0 or more" in problem


def test_the_verifiers_submit_returns_its_verdict_and_sets_nothing():
    with FakeCTFd(sample() + [FakeChallenge(6, "Two Tries", max_attempts=2, flag="test{two}")]) as fake:
        with CTFdVerifier(fake.base_url, TOKEN, {"warmup": 1, "two-tries": 6}) as verify:
            assert verify.submit("two-tries", "test{a}") == Verdict(
                False, Attempt("incorrect", "Incorrect. You have 1 try remaining.", tries_left=1))
            assert verify.submit("warmup", "test{hello}") == Verdict(True, Attempt("correct", "Correct"))
            assert (verify.last_error, verify.last_attempt) == (None, None)  # a call from any thread changes nothing
            unpulled = verify.submit("not-pulled", "test{x}")
            assert unpulled.ok is None and "was not pulled from CTFd" in unpulled.error and unpulled.attempt is None


def test_a_no_tries_answer_is_ctfds_limit_within_a_minute_when_its_details_count_fewer_tries_used():
    # CTFd's lockout counts wrong flags; its details count them among the rest: fewer used than the limit, no lockout
    with FakeCTFd([FakeChallenge(6, "Two Tries", max_attempts=2, flag="test{two}")]) as fake:
        fake.teammate_fails(6)
        fake.script("POST", ATTEMPT, Reply(403, MINUTE))
        with CTFdVerifier(fake.base_url, TOKEN, {"two-tries": 6}) as verify:
            verdict = verify.submit("two-tries", "test{two}")
        asked = [(r.method, r.route) for r in fake.requests]
    assert verdict.ok is None and verdict.attempt == Attempt("ratelimited", "Not accepted. You have 0 tries remaining", 1)
    assert verdict.error == (
        "CTFd did not check the flag (CTFd says: Not accepted. You have 0 tries remaining), but it counts 1 of its 2 "
        "tries as used, so that was its limit on tries within a minute, which passes: wait a minute, then submit it by hand"
    )
    assert asked == [("POST", ATTEMPT), ("GET", "/api/v1/challenges/6")]


@pytest.mark.parametrize("case", ["all used", "older CTFd", "partial answers", "no details", "solved", "late"])
def test_a_no_tries_answer_stands_when_ctfds_details_do_not_show_tries_left(case):
    lockout = "incorrect" if case == "older CTFd" else "ratelimited"
    partial = ("test{half}",) if case == "partial answers" else ()
    with FakeCTFd([FakeChallenge(6, "Two Tries", max_attempts=2, flag="test{two}", partial=partial)], lockout=lockout) as fake:
        if case in ("all used", "older CTFd"):
            fake.teammate_fails(6, 2)  # CTFd answers out of tries on its own
        else:
            fake.teammate_fails(6)
            fake.script("POST", ATTEMPT, Reply(403, MINUTE))
        if case == "partial answers":
            fake.teammate_partials(6)  # 2 of 2 used as the details count them: the minute's limit, or the lockout
        elif case == "no details":
            fake.script("GET", "/api/v1/challenges/6", *[Reply(500, {"message": "the database is broken"})] * 2)
        elif case == "solved":
            fake.solved = {6}  # a teammate's solve meanwhile: the run's poll of the solves closes it
        elif case == "late":  # details that would show a try left, a byte every 0.2 s: past the verifier's timeout
            one_left = {"id": 6, "max_attempts": 2, "attempts": 1, "logic": "any", "solved_by_me": False}
            fake.script("GET", "/api/v1/challenges/6", Reply(200, {"success": True, "data": one_left}, drip=0.2))
        with CTFdVerifier(fake.base_url, TOKEN, {"two-tries": 6}, timeout=1.0) as verify:
            started = time.monotonic()
            verdict = verify.submit("two-tries", "test{two}")
            took = time.monotonic() - started
    assert verdict.ok is None and (verdict.attempt.status, verdict.attempt.tries_left) == ("locked_out", 0)
    assert verdict.error.startswith("CTFd did not check the flag: this account has no tries left on this challenge")
    assert took < 2.5  # the flag and the details within the one timeout
