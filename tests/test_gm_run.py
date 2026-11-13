"""`flightdeck play BOARD --event EVENT.toml` on a Game Master event: answers go to the Game
Master through the deck's submitter under the profile's submit policy, its words come back as
verdicts (or as no verdict), and its solved list is read back.

The Game Master is tests/fake_gm.py and the model tests/fake_model.py, both on 127.0.0.1 (the
run setup is test_event_run.py's): nothing real is contacted and nothing is mocked in between.
Each board is pulled from the fake first, as `flightdeck gm pull` does. A lane's fake model
submits what a test scripts for its challenge, in the board's answer format, answer{...}.
"""

from __future__ import annotations

import asyncio
import json
import re
import threading
import time
from collections import deque
from pathlib import Path

import pytest

from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.model import ChallengeStatus, LaneState, PendingKind
from ctf_flightdeck.platform.gamemaster import GameMasterClient, pull
from ctf_flightdeck.platform.manual import cannot_check
from ctf_flightdeck.run import RunError, RunOptions, prepare_run

from fake_gm import TOKEN, FakeAttempt, FakeGM, Reply, sample
from fake_model import FakeModelServer, tool_call_reply
from test_event_run import config, log, model_api, play, platform_solves, submit, wait_for  # noqa: F401

TOKEN_VAR = "FLIGHTDECK_TEST_GM_TOKEN"
FLAG = "flag{0123456789abcdef0123456789abcdef}"  # the fake's flag for a solved challenge: never shown by flightdeck
RIGHT = {"challenge": "metadata-day-01", "answers": {"d01-author": "Alice Example"}}


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, TOKEN)


def one() -> list[FakeAttempt]:
    """One started challenge with one answer."""
    return [sample()[0]]


def two_answers() -> list[FakeAttempt]:
    """One started challenge with two answers: two challenges on the board."""
    return [sample()[2]]


def board(tmp_path: Path, fake: FakeGM, **options) -> Path:
    """The board `flightdeck gm pull` writes from the fake, in tmp_path/board."""

    async def run():
        async with GameMasterClient(fake.url, TOKEN, backoff=0.001) as client:
            return await pull(client, tmp_path / "board", event="Fake GM", **options)

    asyncio.run(run())
    fake.requests.clear()
    return tmp_path / "board"


def event(tmp_path: Path, url: str, *, flag_format: str | None = None, board: Path | None = None, **policies: str) -> Path:
    lines = ["[event]", 'name = "Fake GM"', 'platform = "gamemaster"', f'url = "{url}"', f'token_env = "{TOKEN_VAR}"']
    if flag_format is not None:
        lines.append(f"flag_format = '{flag_format}'")
    if board is not None:
        lines.append(f"board = '{board}'")
    lines += ["[rules]", "ai_allowed = true", "platform_automation = true", 'live_targets = "allowed"']
    if policies:
        lines += ["[policies]", *[f'{stage} = "{policy}"' for stage, policy in policies.items()]]
    path = tmp_path / "event.toml"
    path.write_text("\n".join(lines) + "\n")
    return path


class Model:
    """The fake model's responder: a lane gets the replies scripted for the first key its brief
    holds (a challenge's name, or "Question (<answer id>)"), in order, then lists files slowly."""

    def __init__(self, scripts: dict[str, list[dict]]) -> None:
        self.scripts = {key: deque(replies) for key, replies in scripts.items()}
        self.lock = threading.Lock()

    def __call__(self, record: dict) -> dict:
        brief = record["json"]["messages"][1]["content"]
        with self.lock:
            for key, queue in self.scripts.items():
                if key in brief and queue:
                    return queue.popleft()
        time.sleep(0.02)
        return tool_call_reply("shell", {"command": "ls"})


def gm_run(tmp_path, fake, server, *, submit_policy: str = "auto", max_lanes: int = 1, flag_format: str | None = None, **options):
    """A Game Master run on the board pulled from the fake, its lanes on the fake model."""
    folder = tmp_path / "board" if (tmp_path / "board").exists() else board(tmp_path, fake)
    profile = event(tmp_path, fake.url, flag_format=flag_format, submit=submit_policy)
    return prepare_run(RunOptions(board=folder, event=profile, config=config(tmp_path, server.base_url, max_lanes=max_lanes), **options))


def submits(run) -> list[tuple[str, bool, str]]:
    return [(e["data"]["flag"], e["data"]["correct"], e["data"]["by"]) for e in log(run) if e["kind"] == "submit"]


def gm_warnings(run) -> list[str]:
    return [e["text"] for e in log(run) if e["kind"] == "warning" and e["data"].get("source") == "gamemaster"]


def lane_on(run, challenge_id: str):
    return next(lane for lane in run.deck.lanes.values() if lane.challenge_id == challenge_id)


# ---------------------------------------------------------------------- verdicts


def test_a_right_answer_goes_to_the_game_master_unwrapped_and_solves_the_challenge(tmp_path, token):
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        run = gm_run(tmp_path, fake, server)

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").state is LaneState.SOLVED, "the solve")

        play(run, body)
        assert fake.submissions() == [RIGHT] and fake.starts == []  # what the braces hold, sent once; nothing started
    assert submits(run) == [("answer{Alice Example}", True, "platform")]
    assert run.deck.challenges["who-wrote-it"].status is ChallengeStatus.SOLVED
    assert any(n.startswith("answers go to the Game Master at ") for n in run.notes())
    everything = run.log.path.read_text() + "\n".join(run.notes()) + "\n".join(a.text for a in lane_on(run, "who-wrote-it").actions)
    assert FLAG not in everything and TOKEN not in everything  # the Game Master's flag and the token are shown nowhere


def test_a_wrong_answer_is_recorded_wrong_and_the_next_one_still_goes(tmp_path, token):
    model = Model({"Who Wrote It": [submit("answer{Bob}"), submit("answer{Alice Example}")]})
    with FakeGM(one()) as fake, FakeModelServer(responder=model) as server:
        run = gm_run(tmp_path, fake, server)

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").state is LaneState.SOLVED, "the solve")

        play(run, body)
        assert [s["answers"]["d01-author"] for s in fake.submissions()] == ["Bob", "Alice Example"]
    assert submits(run) == [("answer{Bob}", False, "platform"), ("answer{Alice Example}", True, "platform")]
    assert run.deck.not_flag("who-wrote-it", "answer{Bob}") is not None


def test_under_confirm_an_answer_waits_for_the_player_and_goes_only_on_their_yes(tmp_path, token):
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        run = gm_run(tmp_path, fake, server, submit_policy="confirm")

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").pending is not None, "the approval")
            lane = lane_on(run, "who-wrote-it")
            assert lane.pending.kind is PendingKind.SUBMIT and lane.pending.flag == "answer{Alice Example}"
            await asyncio.sleep(0.2)
            assert fake.submissions() == []  # nothing goes without the player's yes
            assert run.deck.apply(iv.Approve(lane.id)).ok
            await wait_for(lambda: lane.state is LaneState.SOLVED, "the solve")

        play(run, body)
        assert fake.submissions() == [RIGHT]


def test_a_candidate_that_is_not_in_the_answer_format_never_reaches_the_game_master(tmp_path, token):
    model = Model({"Who Wrote It": [submit("Alice Example"), submit("flag{not_the_format}")]})
    with FakeGM(one()) as fake, FakeModelServer(responder=model) as server:
        run = gm_run(tmp_path, fake, server)

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").turns >= 4, "the lane's turns")

        play(run, body)
        assert fake.submissions() == []
    assert submits(run) == [] and run.deck.challenges["who-wrote-it"].status is not ChallengeStatus.SOLVED


def test_an_event_profiles_flag_format_says_what_an_answer_looks_like_and_what_part_is_sent(tmp_path, token):
    """A format without an "answer" group: the whole candidate is the answer."""
    hashes = [FakeAttempt("hash-day-03", "Which Hash", started=True, answers={"h": "0123456789abcdef0123456789abcdef"})]
    model = Model({"Which Hash": [submit("answer{0123456789abcdef0123456789abcdef}"), submit("0123456789abcdef0123456789abcdef")]})
    with FakeGM(hashes) as fake, FakeModelServer(responder=model) as server:
        run = gm_run(tmp_path, fake, server, flag_format="[0-9a-f]{32}")

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "which-hash").state is LaneState.SOLVED, "the solve")

        play(run, body)
        assert fake.submissions() == [{"challenge": "hash-day-03", "answers": {"h": "0123456789abcdef0123456789abcdef"}}]
    assert run.deck.config.flag_format == "[0-9a-f]{32}"


def test_each_answer_of_one_attempt_is_a_challenge_of_its_own_accepted_then_correct(tmp_path, token):
    model = Model({"Question (m4-a)": [submit("answer{pixel}")], "Question (m4-b)": [submit("answer{nokia 3310}")]})
    with FakeGM(two_answers()) as fake, FakeModelServer(responder=model) as server:
        run = gm_run(tmp_path, fake, server)  # one lane at a time: m4-a's challenge first

        async def body(run):
            await wait_for(lambda: len(run.deck.lanes) == 2 and all(l.state is LaneState.SOLVED for l in run.deck.lanes.values()),
                           "both answers")

        play(run, body)
        assert fake.submissions() == [
            {"challenge": "mobile-day-04", "answers": {"m4-a": "pixel"}},
            {"challenge": "mobile-day-04", "answers": {"m4-b": "nokia 3310"}},
        ]
    assert submits(run) == [("answer{pixel}", True, "platform"), ("answer{nokia 3310}", True, "platform")]
    details = [e["data"]["detail"] for e in log(run) if e["kind"] == "submit"]
    assert details == ["accepted, 1 more of the attempt's answers wanted", "CORRECT"]
    assert {c.status for c in run.deck.challenges.values()} == {ChallengeStatus.SOLVED} and platform_solves(run) == []


def test_already_solved_closes_the_challenge_as_the_platforms_solve_and_is_never_a_wrong_answer(tmp_path, token):
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Bob}")]})) as server:
        run = gm_run(tmp_path, fake, server)
        fake.challenges["metadata-day-01"].solved = True  # solved elsewhere since the run read the list

        async def body(run):
            await wait_for(lambda: run.deck.challenges["who-wrote-it"].closed, "the challenge closed")

        play(run, body)
        assert len(fake.submissions()) == 1
    ch = run.deck.challenges["who-wrote-it"]
    assert ch.status is ChallengeStatus.TEAMMATE and ch.solved_by == "your account"
    assert platform_solves(run) == [("who-wrote-it", "your account", False)]
    assert submits(run) == [] and run.deck.not_flag("who-wrote-it", "answer{Bob}") is None  # not checked: not known wrong
    assert gm_warnings(run) == []  # news, not an error


def unstart(fake: FakeGM) -> None:
    fake.challenges["metadata-day-01"].started = False


def expire(fake: FakeGM) -> None:
    fake.challenges["metadata-day-01"].expired = True


@pytest.mark.parametrize("arrange, word", [
    (unstart, "start_required"),
    (expire, "attempt_expired"),
    (lambda fake: fake.script("POST", "submit", Reply(400, {"error": "invalid_answers"})), "invalid_answers"),
    (lambda fake: fake.script("POST", "submit", Reply(400, {"error": "invalid_request"})), "invalid_request"),
    (lambda fake: fake.script("POST", "submit", Reply(413, {"error": "payload_too_large"})), "payload_too_large"),
    (lambda fake: fake.script("POST", "submit", Reply(409, {"error": "training_rotation_invalid"})), "training_rotation_invalid"),
    (lambda fake: fake.script("POST", "submit", Reply(200, {"result": "partially_correct"})), "partially_correct"),
    (lambda fake: fake.script("POST", "submit", Reply(403, {"result": "incorrect"})), "incorrect"),
])
def test_a_refusal_or_an_unknown_word_is_no_verdict_the_answer_goes_back_to_the_player(tmp_path, token, arrange, word):
    """The right answer, refused: never taken for wrong, sent once, and the player is asked."""
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        run = gm_run(tmp_path, fake, server)
        arrange(fake)
        told: list[str] = []
        assert run.gm.needs_human == run.autopilot.platform  # autopilot is told the platform needs a human
        run.gm.needs_human = told.append

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").pending is not None, "the answer back")
            lane = lane_on(run, "who-wrote-it")
            assert lane.pending.kind is PendingKind.CONFIRM and lane.pending.flag == "answer{Alice Example}"
            await asyncio.sleep(0.2)

        play(run, body)
        assert fake.submissions() == [RIGHT]  # once
    assert submits(run) == [] and run.deck.not_flag("who-wrote-it", "answer{Alice Example}") is None
    (warning,) = gm_warnings(run)
    assert warning.startswith("the Game Master did not judge answer{Alice Example} for Who Wrote It: ") and word in warning
    assert len(told) == 1 and word in told[0]
    assert not run.deck.challenges["who-wrote-it"].closed


def test_an_answer_with_no_reply_is_not_known_and_goes_back_to_the_player(tmp_path, token):
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        run = gm_run(tmp_path, fake, server)
        fake.hold_submits = threading.Event()
        run.gm.submit_seconds = 0.3

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").pending is not None, "the answer back")
            assert lane_on(run, "who-wrote-it").pending.kind is PendingKind.CONFIRM

        try:
            play(run, body)
        finally:
            fake.hold_submits.set()
    (warning,) = gm_warnings(run)
    assert "no complete answer from the Game Master within 0.3 s; the answer may have reached it" in warning


# ---------------------------------------------------------------------- a rate limit


def test_a_rate_limited_answer_is_sent_again_after_the_wait_the_game_master_asks(tmp_path, token):
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        run = gm_run(tmp_path, fake, server)
        fake.limited, fake.retry_after = 2, "7"
        waits: list[float] = []

        async def nap(seconds: float) -> None:
            waits.append(seconds)

        run.gm.sleep = nap

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").state is LaneState.SOLVED, "the solve")

        play(run, body)
        assert fake.submissions() == [RIGHT] * 3  # the same answer: the two refused ones judged nothing
    assert waits == [8.0, 8.0] and submits(run) == [("answer{Alice Example}", True, "platform")]
    notes = [a.text for a in lane_on(run, "who-wrote-it").actions]
    assert any("the Game Master rate-limited the submission of answer{Alice Example} and did not check it; flightdeck sends it "
               "again in 8s (send 2 of 4)" in note for note in notes)
    assert gm_warnings(run) == []


def test_an_answer_rate_limited_every_time_goes_back_to_the_player_after_the_last_send(tmp_path, token):
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        run = gm_run(tmp_path, fake, server)
        fake.limited = 50
        waits: list[float] = []

        async def nap(seconds: float) -> None:
            waits.append(seconds)

        run.gm.sleep = nap

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").pending is not None, "the answer back")
            assert lane_on(run, "who-wrote-it").pending.kind is PendingKind.CONFIRM

        play(run, body)
        assert len(fake.submissions()) == 4  # one send and three more, no further
    assert waits == [65.0, 65.0, 65.0]  # the Game Master named no wait
    (warning,) = gm_warnings(run)
    assert "rate-limited the submission and did not check the answer" in warning
    assert run.deck.not_flag("who-wrote-it", "answer{Alice Example}") is None


# ---------------------------------------------------------------------- the guards on a lane that guesses


def test_the_wrong_answer_stop_holds_for_a_game_master(tmp_path, token):
    """P34: after three wrong answers at a challenge, the next one waits for the player under auto too."""
    guesses = [submit(f"answer{{guess {n}}}") for n in range(1, 5)]
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": guesses})) as server:
        run = gm_run(tmp_path, fake, server)
        assert run.deck.config.wrong_stop == 3

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").pending is not None, "the fourth guess")
            lane = lane_on(run, "who-wrote-it")
            assert lane.pending.kind is PendingKind.SUBMIT and lane.pending.flag == "answer{guess 4}"
            await asyncio.sleep(0.2)

        play(run, body)
        assert [s["answers"]["d01-author"] for s in fake.submissions()] == ["guess 1", "guess 2", "guess 3"]
    assert [ok for _, ok, _ in submits(run)] == [False, False, False]


# ---------------------------------------------------------------------- the solved list


def test_what_the_game_master_lists_as_solved_is_closed_at_the_start_and_as_the_run_goes(tmp_path, token):
    with FakeGM(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        run = gm_run(tmp_path, fake, server, max_lanes=4, solves_seconds=0.05)
        assert [r.path for r in fake.requests] == ["/?op=list&all=true"]  # the one read before the run starts

        async def body(run):
            deck = run.deck
            assert deck.challenges["packed"].status is ChallengeStatus.TEAMMATE  # listed solved before the run: no lane
            assert sorted(lane.challenge_id for lane in deck.lanes.values()) == ["two-phones-m4-a", "two-phones-m4-b", "who-wrote-it"]
            fake.challenges["mobile-day-04"].solved = True  # solved elsewhere, both answers
            await wait_for(lambda: deck.challenges["two-phones-m4-a"].closed and deck.challenges["two-phones-m4-b"].closed,
                           "the poll that lists it solved")
            assert lane_on(run, "two-phones-m4-a").state is LaneState.STOPPED
            assert not deck.challenges["who-wrote-it"].closed

        play(run, body)
        assert all(r.method == "GET" for r in fake.requests) and fake.starts == []  # a run starts no attempt
    assert platform_solves(run) == [
        ("packed", "your account", True), ("two-phones-m4-a", "your account", False), ("two-phones-m4-b", "your account", False)]


def test_a_solved_list_that_cannot_be_read_is_a_warning_once_and_autopilot_is_told(tmp_path, token):
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({})) as server:
        run = gm_run(tmp_path, fake, server, solves_seconds=0.05)
        told: list[str] = []
        run.gm.needs_human = told.append
        run.gm.client.max_retries = 0
        fake.script("GET", "list", *[Reply(500, {"error": "internal"})] * 4)

        async def body(run):
            await wait_for(lambda: len(fake.sent("GET", "list")) >= 7, "the polls")

        play(run, body)
    (warning,) = gm_warnings(run)  # once while the same failure lasts
    assert warning.startswith("could not read the solved list from the Game Master: ") and "HTTP 500" in warning
    assert len(told) == 1 and "has failed 3 times in a row" in told[0]


# ---------------------------------------------------------------------- the end of the run


def test_answers_on_their_way_when_the_run_ends_are_named(tmp_path, token):
    model = Model({"Who Wrote It": [submit("answer{Bob}"), submit("answer{Alice Example}")]})
    with FakeGM(one()) as fake, FakeModelServer(responder=model) as server:
        run = gm_run(tmp_path, fake, server)
        fake.hold_submits = threading.Event()

        async def main():
            run.release()
            try:
                await wait_for(lambda: len(fake.submissions()) == 1 and len(run.deck.submitting("who-wrote-it")) == 2,
                               "one answer at the Game Master, one behind it")
            finally:
                await run.shutdown()
                fake.hold_submits.set()
            await asyncio.sleep(0.3)

        asyncio.run(main())
        run.close()
        assert len(fake.submissions()) == 1  # the worker stopped with the run
    assert sorted(e for e in run.errors if e.startswith("Game Master: ")) == [
        "Game Master: answer{Alice Example} (L01, Who Wrote It) was not submitted: it was waiting for the answer to "
        "another flag of that challenge when the run ended",
        "Game Master: answer{Bob} (L01, Who Wrote It) was on its way to the Game Master when the run ended, so it is not "
        "known to have been submitted: check the challenge there before you submit it again",
    ]


# ---------------------------------------------------------------------- what stops a run, and what uses no platform


def test_a_board_that_was_not_pulled_from_this_game_master_stops_the_run(tmp_path, token):
    with FakeGM(one()) as fake, FakeGM(one()) as other:
        folder = board(tmp_path, other)
        with pytest.raises(RunError, match="this board was pulled from .* Pull the board first"):
            prepare_run(RunOptions(board=folder, event=event(tmp_path, fake.url, submit="auto"), config=config(tmp_path)))
        (tmp_path / "plain" / "c").mkdir(parents=True)
        (tmp_path / "plain" / "c" / "challenge.json").write_text(json.dumps({"name": "C", "category": "misc", "points": 1}))
        with pytest.raises(RunError, match="not a board pulled from a Game Master"):
            prepare_run(RunOptions(board=tmp_path / "plain", event=event(tmp_path, fake.url, submit="auto"), config=config(tmp_path)))
        with pytest.raises(RunError, match="a Game Master event needs the board folder"):
            prepare_run(RunOptions(event=event(tmp_path, fake.url, submit="auto"), config=config(tmp_path)))
        assert fake.requests == [] and other.requests == [] and not (tmp_path / "runs").exists()


def test_a_missing_or_refused_token_stops_the_run_and_is_never_shown(tmp_path, monkeypatch):
    with FakeGM(one()) as fake:
        folder = board(tmp_path, fake)
        profile = event(tmp_path, fake.url, submit="auto")
        monkeypatch.delenv(TOKEN_VAR, raising=False)
        with pytest.raises(RunError, match=f"the Game Master token variable {TOKEN_VAR} .* is not set or is empty"):
            prepare_run(RunOptions(board=folder, event=profile, config=config(tmp_path)))
        assert fake.requests == []
        monkeypatch.setenv(TOKEN_VAR, "a-token-the-fake-refuses-3")
        with pytest.raises(RunError) as caught:
            prepare_run(RunOptions(board=folder, event=profile, config=config(tmp_path)))
        assert [r.method for r in fake.requests] == ["GET"]
    assert "could not read the Game Master's list" in str(caught.value) and "refused the token (HTTP 401)" in str(caught.value)
    assert "a-token-the-fake-refuses-3" not in str(caught.value) and not (tmp_path / "runs").exists()


def test_under_submit_manual_nothing_goes_to_the_game_master_and_no_token_is_read(tmp_path, monkeypatch):
    monkeypatch.delenv(TOKEN_VAR, raising=False)
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        folder = board(tmp_path, fake)
        profile = event(tmp_path, fake.url, submit="manual")
        run = prepare_run(RunOptions(board=folder, event=profile, config=config(tmp_path, server.base_url, max_lanes=1)))
        assert run.gm is None and run.deck.verify is cannot_check and run.deck.submitter is None

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").pending is not None, "the answer")
            assert lane_on(run, "who-wrote-it").pending.kind is PendingKind.CONFIRM  # you submit it, then say how it went

        play(run, body)
        assert fake.requests == []


def test_the_pulled_board_plays_as_a_plain_folder_board_without_an_event(tmp_path):
    """`flightdeck play DEST`: the board's own answer format is the deck's, and the player submits by hand."""
    with FakeGM(one()) as fake, FakeModelServer(responder=Model({"Who Wrote It": [submit("answer{Alice Example}")]})) as server:
        folder = board(tmp_path, fake)
        run = prepare_run(RunOptions(board=folder, submit="auto", config=config(tmp_path, server.base_url, max_lanes=1)))
        assert re.fullmatch(run.deck.config.flag_format, "answer{Alice Example}") and run.gm is None

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_on(run, "who-wrote-it").pending is not None, "the answer")
            assert lane_on(run, "who-wrote-it").pending.kind is PendingKind.CONFIRM

        play(run, body)
        assert fake.requests == []


def test_answers_cannot_be_checked_against_a_file_in_a_game_master_run(tmp_path, token):
    with FakeGM(one()) as fake:
        folder = board(tmp_path, fake)
        (tmp_path / "answers.json").write_text("{}")
        with pytest.raises(RunError, match="--answers checks flags against a file"):
            prepare_run(RunOptions(board=folder, answers=tmp_path / "answers.json", event=event(tmp_path, fake.url, submit="auto"),
                                   config=config(tmp_path)))
        assert fake.requests == []
