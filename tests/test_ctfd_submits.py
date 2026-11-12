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
            assert (lane.pending.kind, lane.pending.detail) == (
                PendingKind.SUBMIT, "submit test{hello} (3 tries in all, how many are left is not known yet)")
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
        "Warmup is out of tries: the platform checks no more flags for it, so flightdeck closed it for this run and "
        "stopped L01. test{hello} is not known to be wrong: CTFd did not check the flag: this account has no tries "
        f"left on this challenge (CTFd says: {said})"
    )
    assert warning["data"] == {"out_of_tries": True, "tries_left": 0, "flag": "test{hello}", "checked": False,
                               "stopped": ["L01"], "before_run": False}


def test_a_pull_carries_the_tries_ctfd_allows_onto_the_board(tmp_path):
    board = [FakeChallenge(1, "Capped", max_attempts=3), FakeChallenge(2, "Free"), FakeChallenge(3, "Unsaid", max_attempts=None)]
    with FakeCTFd(board) as fake:
        result = pulled(fake, tmp_path / "board")
    found = {item.challenge.id: item.challenge for item in result.board.challenges}
    assert {cid: ch.max_attempts for cid, ch in found.items()} == {"capped": 3, "free": 0, "unsaid": 0}
    spec = json.loads((tmp_path / "board" / "capped" / "challenge.json").read_text())
    assert spec["max_attempts"] == 3
    assert "max_attempts" not in json.loads((tmp_path / "board" / "free" / "challenge.json").read_text())


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
