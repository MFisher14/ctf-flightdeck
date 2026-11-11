"""Flags to CTFd: the tries CTFd counts, from the pull and from its answers, and the verdict
the verifier's submit() returns.

The CTFd is tests/fake_ctfd.py on 127.0.0.1: nothing real is contacted and nothing is mocked
in between.
"""

from __future__ import annotations

import json

import pytest

from ctf_flightdeck.platform.ctfd import Attempt, CTFdVerifier, Verdict

from fake_ctfd import TOKEN, FakeChallenge, FakeCTFd, sample
from test_ctfd import pulled


# ---------------------------------------------------------------------- the tries CTFd counts


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
