"""The agent driver end to end: a real Deck, the driver, real HTTP to a fake OpenAI-compatible
server, and real subprocesses in host workspaces under tmp_path.

Lanes are asyncio tasks, so each test runs one coroutine with asyncio.run() and waits for
the deck to reach a state (bounded, ~10 s at most).
"""

from __future__ import annotations

import asyncio
import shutil
import threading
import time
from pathlib import Path

import pytest

from ctf_flightdeck.agent.client import ModelClient
from ctf_flightdeck.agent.driver import AgentDriver
from ctf_flightdeck.agent.tools import TOOLS
from ctf_flightdeck.agent.workspace import HostWorkspace
from ctf_flightdeck.clock import RunClock
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.model import Challenge, ChallengeStatus, DeckConfig, LaneState, PendingKind
from ctf_flightdeck.pricing import Price

from fake_model import FakeModelServer, FakeReply, text_reply, tool_call_reply, tool_calls_reply

FLAG = r"t\{[a-z0-9_]+\}"
MODELS = ("small", "big")


async def until(cond, what: str, timeout: float = 10.0) -> None:
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.01)


def handout(tmp_path: Path, name: str = "note", files: dict[str, str] | None = None) -> Path:
    folder = tmp_path / "board" / name
    folder.mkdir(parents=True)
    for file, text in (files or {"note.txt": "the flag is t{note}\n"}).items():
        (folder / file).write_text(text)
    return folder


class Lab:
    """A deck with the agent driver against a fake model server, host workspaces in tmp."""

    def __init__(self, tmp_path: Path, server: FakeModelServer, *, verify=None, max_lanes: int = 2,
                 prices: dict[str, Price] | None = None, handouts: dict[str, Path] | None = None) -> None:
        self.tmp = tmp_path
        self.server = server
        self.handouts = handouts or {"note": handout(tmp_path)}
        self.client = ModelClient(server.base_url, "sk-test-not-a-real-key", max_retries=0, backoff=0.0)
        self.driver = AgentDriver(
            self.client,
            lambda lane, ch: HostWorkspace(tmp_path / "runs" / lane.id / "work", self.handouts[ch.id]),
            run_id="run1",
            files={cid: sorted(p.name for p in path.iterdir()) if path.is_dir() else [] for cid, path in self.handouts.items()},
            prices=prices or {},
        )
        config = DeckConfig(event="t", flag_format=FLAG, models=MODELS, max_lanes=max_lanes)
        self.deck = Deck(config, self.driver, RunClock(), verify or (lambda cid, flag: flag == "t{note}"))

    def release(self, *ids: str) -> None:
        ids = ids or tuple(self.handouts)
        challenges = [Challenge(cid, cid.title(), "misc", 50, solves=10, description=f"About {cid}.") for cid in ids]
        self.deck.release(challenges, [QueueEntry(cid, "small") for cid in ids])

    def lane(self, cid: str = "note"):
        (lane,) = [x for x in self.deck.lanes.values() if x.challenge_id == cid]
        return lane

    async def finish(self) -> None:
        await self.driver.shutdown()
        await self.client.aclose()


def run(coro) -> None:
    asyncio.run(coro)


def last_user(request: dict) -> str:
    return next(m["content"] for m in reversed(request["json"]["messages"]) if m["role"] == "user")


def tool_messages(request: dict) -> list[dict]:
    return [m for m in request["json"]["messages"] if m["role"] == "tool"]


# ---------------------------------------------------------------------- a lane from start to flag


def test_a_lane_reads_the_handout_submits_a_flag_and_is_solved_when_approved(tmp_path):
    server = FakeModelServer([
        tool_call_reply("shell", {"command": "cat note.txt"}, cost=0.001),
        tool_calls_reply([("set_plan", {"plan": "read the note"}), ("submit_flag", {"flag": "t{note}"})], cost=0.002),
    ])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.pending is not None, "the candidate flag")
            first, second = server.requests
            messages = first["json"]["messages"]
            assert [m["role"] for m in messages] == ["system", "user"]
            assert "Challenge: Note (misc, 50 points, 10 solves)" in messages[1]["content"]
            assert "About note." in messages[1]["content"] and "note.txt" in messages[1]["content"]
            assert first["json"]["session_id"] == "flightdeck-run1-L01"
            assert [t["function"]["name"] for t in first["json"]["tools"]] == [t["function"]["name"] for t in TOOLS]
            assert "provider" not in first["json"]
            (result,) = tool_messages(second)
            assert result["content"].startswith("exit 0") and "the flag is t{note}" in result["content"]
            assert (lane.pending.kind, lane.pending.flag) == (PendingKind.SUBMIT, "t{note}")
            assert lane.turns == 2 and lane.tokens == 240 and lane.dollars == pytest.approx(0.003)
            assert lane.plan == "read the note"
            assert lane.actions[0].text == "$ cat note.txt"
            assert lab.deck.apply(iv.Approve(lane.id)).ok
            assert lane.state is LaneState.SOLVED
            assert lab.deck.challenges["note"].status is ChallengeStatus.SOLVED
            await until(lambda: lab.driver.runs[lane.id].closed, "the workspace closes")
            assert len(server.requests) == 2  # nothing more was asked of the model
            await lab.finish()

    run(main())


def test_files_the_lane_writes_show_as_changed_files_with_a_diff(tmp_path):
    server = FakeModelServer([
        tool_call_reply("shell", {"command": "printf 'hi\\n' > out.txt"}),
        tool_call_reply("submit_flag", {"flag": "t{note}"}),
    ])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.pending is not None, "the candidate flag")
            change = lane.files["out.txt"]
            assert change.status == "added" and "+hi" in change.diff and change.turn == 1
            assert "note.txt" not in lane.files  # copied in at the start, not changed by the lane
            await lab.finish()

    run(main())


def test_the_api_key_never_reaches_a_lanes_shell(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "player-secret-value-PLAYER-SECRET-VALUE")
    server = FakeModelServer([tool_call_reply("shell", {"command": "env"}), text_reply("done")])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            await until(lambda: len(server.requests) >= 2, "the second model call")
            (result,) = tool_messages(server.requests[1])
            assert "PLAYER-SECRET-VALUE" not in result["content"] and "OPENROUTER_API_KEY" not in result["content"]
            assert "sk-test-not-a-real-key" not in result["content"]
            await lab.finish()

    run(main())


# ---------------------------------------------------------------------- the player steers


def test_a_paused_lane_asks_the_model_nothing_and_a_hint_goes_into_its_next_turn(tmp_path):
    server = FakeModelServer([text_reply("thinking"), text_reply("still thinking")])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            assert lab.deck.apply(iv.Pause(lane.id)).ok  # before the lane's task has run at all
            await asyncio.sleep(0.3)
            assert server.requests == []
            assert lab.deck.apply(iv.Hint(lane.id, "try xor with the date")).ok
            assert lab.deck.apply(iv.Resume(lane.id)).ok
            await until(lambda: len(server.requests) >= 1, "the first model call")
            assert last_user(server.requests[0]) == "Message from the player: try xor with the date"
            await until(lambda: lane.turns >= 1, "the turn report")
            assert lane.hints == []  # taken by that turn
            await lab.finish()

    run(main())


def test_a_reply_without_tool_calls_gets_a_nudge(tmp_path):
    server = FakeModelServer([text_reply("I think it is base64."), text_reply("ok")])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: len(server.requests) >= 2, "the second model call")
            assert "no tool was called" in last_user(server.requests[1])
            assert lane.actions[0].text == "says: I think it is base64."
            await lab.finish()

    run(main())


@pytest.mark.parametrize(
    "answer, note",
    [
        (iv.Approve, "t{wrong} was submitted and it is not correct."),
        (iv.Decline, "The player did not submit t{wrong}"),
    ],
    ids=["rejected", "declined"],
)
def test_the_next_turn_hears_what_became_of_a_candidate_flag(tmp_path, answer, note):
    server = FakeModelServer([tool_call_reply("submit_flag", {"flag": "t{wrong}"}), text_reply("ok")])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.pending is not None, "the candidate flag")
            assert len(server.requests) == 1  # the lane waits for the player
            assert lab.deck.apply(answer(lane.id)).ok
            await until(lambda: len(server.requests) >= 2, "the next model call")
            assert note in last_user(server.requests[1])
            await lab.finish()

    run(main())


def test_a_candidate_that_does_not_match_the_flag_format_is_not_submitted_and_the_lane_hears_why(tmp_path):
    server = FakeModelServer([tool_call_reply("submit_flag", {"flag": "FLAG{nope}"}), text_reply("ok")])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: len(server.requests) >= 2, "the next model call")
            assert lane.pending is None
            assert "FLAG{nope} does not match the flag format" in last_user(server.requests[1])
            await lab.finish()

    run(main())


def test_two_flags_in_one_reply_wait_as_two_approvals(tmp_path):
    server = FakeModelServer([tool_calls_reply([("submit_flag", {"flag": "t{one}"}), ("submit_flag", {"flag": "t{two}"})])])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.pending is not None, "the candidate flags")
            assert lane.pending.flag == "t{one}" and [p.flag for p in lane.waiting] == ["t{two}"]
            assert lane.turns == 1
            await lab.finish()

    run(main())


def test_escalation_moves_the_lane_to_the_stronger_model_in_a_fresh_context(tmp_path):
    gate = threading.Event()

    def responder(record):
        n = sum(1 for r in server.requests if r["path"].endswith("/chat/completions"))
        if n == 1:
            return tool_call_reply("shell", {"command": "ls"})
        if n == 2:
            gate.wait(5)  # the old model is still thinking when the player escalates
            return tool_call_reply("shell", {"command": "touch from-the-old-model"}, prompt_tokens=300, completion_tokens=30)
        return tool_call_reply("submit_flag", {"flag": "t{big}"})  # then the lane waits for the player

    server = FakeModelServer(responder=responder)

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: len(server.requests) >= 2, "the second call, to the old model")
            tokens = lane.tokens
            assert lab.deck.apply(iv.Escalate(lane.id)).ok
            gate.set()
            await until(lambda: lane.pending is not None, "the stronger model's candidate")
            assert len(server.requests) == 3
            request = server.requests[2]["json"]
            assert request["model"] == "big"
            assert request["session_id"] == "flightdeck-run1-L01-e1"
            roles = [m["role"] for m in request["messages"]]
            assert roles == ["system", "user", "user"]  # fresh: no old tool calls, no stale reply
            assert "Another model worked on this challenge before you" in request["messages"][2]["content"]
            assert lane.tokens == tokens + 330 + 120  # the stale reply was dropped but its tokens counted
            assert not (tmp_path / "runs" / lane.id / "work" / "from-the-old-model").exists()
            await lab.finish()

    run(main())


def test_killing_a_lane_while_the_model_thinks_cancels_it_and_asks_nothing_more(tmp_path):
    def slow(request):
        time.sleep(0.5)  # the model is thinking
        return tool_call_reply("shell", {"command": "touch should-not-exist"})

    server = FakeModelServer(responder=slow)

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: len(server.requests) >= 1, "the first model call")
            assert lab.deck.apply(iv.Kill(lane.id, requeue=False)).ok
            run_ = lab.driver.runs[lane.id]
            await until(lambda: run_.task.done() and run_.closed, "the lane's task to end")
            await asyncio.sleep(0.7)  # past the slow reply
            assert len(server.requests) == 1
            assert not (tmp_path / "runs" / lane.id / "work" / "should-not-exist").exists()
            await lab.finish()

    run(main())


def test_a_model_api_error_ends_the_lane_with_the_reason(tmp_path):
    server = FakeModelServer([FakeReply(400, {"error": {"message": "no such model: small"}})])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.finished, "the lane to end")
            assert lane.state is LaneState.GAVE_UP
            assert "model API error" in lane.result and "no such model: small" in lane.result
            assert "sk-test-not-a-real-key" not in lane.result
            await lab.finish()

    run(main())


def test_a_workspace_that_cannot_be_prepared_ends_the_lane_with_the_reason(tmp_path):
    server = FakeModelServer([text_reply("never asked")])

    async def main():
        with server:
            lab = Lab(tmp_path, server, handouts={"note": tmp_path / "missing-handout"})
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.finished, "the lane to end")
            assert lane.state is LaneState.GAVE_UP and "could not prepare the workspace" in lane.result
            assert server.requests == []
            await lab.finish()

    run(main())


# ---------------------------------------------------------------------- cost and concurrency


@pytest.mark.parametrize(
    "prices, reported, expected",
    [
        ({}, 0.004, 0.004),  # the API's figure
        ({"small": Price(input=10.0, output=50.0)}, None, (100 * 10.0 + 20 * 50.0) / 1e6),  # the config's price
        ({}, None, None),  # neither: unknown
    ],
    ids=["reported", "config-price", "unknown"],
)
def test_a_turns_cost_comes_from_the_api_else_the_config_price_else_it_is_unknown(tmp_path, prices, reported, expected):
    server = FakeModelServer([tool_calls_reply([("shell", {"command": "true"}), ("submit_flag", {"flag": "t{x}"})], cost=reported)])

    async def main():
        with server:
            lab = Lab(tmp_path, server, prices=prices)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.pending is not None, "the first turn's candidate")
            assert lane.turns == 1
            if expected is None:
                assert lane.dollars is None
            else:
                assert lane.dollars == pytest.approx(expected)
            await lab.finish()

    run(main())


def test_lanes_run_side_by_side_each_in_its_own_session(tmp_path):
    def by_lane(request):
        lane = request["json"]["session_id"].rsplit("-", 1)[-1]
        return tool_call_reply("submit_flag", {"flag": f"t{{{lane.lower()}}}"})

    server = FakeModelServer(responder=by_lane)

    async def main():
        with server:
            handouts = {"alpha": handout(tmp_path, "alpha"), "beta": handout(tmp_path, "beta")}
            lab = Lab(tmp_path, server, handouts=handouts)
            lab.release("alpha", "beta")
            a, b = lab.lane("alpha"), lab.lane("beta")
            await until(lambda: a.pending is not None and b.pending is not None, "both candidates")
            assert (a.pending.flag, b.pending.flag) == ("t{l01}", "t{l02}")
            sessions = {r["json"]["session_id"]: last_user(r) for r in server.requests}
            assert "Challenge: Alpha" in sessions["flightdeck-run1-L01"]
            assert "Challenge: Beta" in sessions["flightdeck-run1-L02"]
            await lab.finish()

    run(main())


def test_starting_a_lane_with_no_running_event_loop_parks_the_challenge_with_the_reason(tmp_path):
    server = FakeModelServer()
    with server:
        lab = Lab(tmp_path, server)
        lab.release()  # outside asyncio.run: no loop
        ch = lab.deck.challenges["note"]
        assert ch.status is ChallengeStatus.PARKED and "event loop" in ch.note
        assert lab.deck.lanes == {}


# ---------------------------------------------------------------------- failures end a lane loudly


def test_a_workspace_that_breaks_under_the_lane_ends_it_with_the_reason(tmp_path):
    def responder(record):
        shutil.rmtree(tmp_path / "runs" / "L01" / "work")  # the workspace vanishes mid-run
        return tool_call_reply("shell", {"command": "ls"})

    server = FakeModelServer(responder=responder)

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.finished, "the lane to end")
            assert lane.state is LaneState.GAVE_UP and "the workspace failed" in lane.result
            await lab.finish()

    run(main())


def test_an_unexpected_error_ends_the_lane_loudly_instead_of_its_task_dying_quietly(tmp_path):
    class Broken:
        async def chat(self, *args, **kwargs):
            raise RuntimeError("a flightdeck bug")

        async def aclose(self):
            pass

    server = FakeModelServer()

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.driver.client = Broken()  # a collaborator that fails in a way nothing expects
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.finished, "the lane to end")
            assert lane.state is LaneState.GAVE_UP
            assert lane.result == "flightdeck error: RuntimeError: a flightdeck bug"
            assert lab.driver.errors == ["L01: RuntimeError: a flightdeck bug"]
            await lab.finish()

    run(main())


def test_a_turn_that_changes_many_files_reports_the_first_fifty_and_tells_the_lane(tmp_path):
    server = FakeModelServer([
        tool_call_reply("shell", {"command": "for i in $(seq 1 60); do echo $i > f$i.txt; done"}),
        tool_call_reply("submit_flag", {"flag": "t{note}"}),
    ])

    async def main():
        with server:
            lab = Lab(tmp_path, server)
            lab.release()
            lane = lab.lane()
            await until(lambda: lane.pending is not None, "the candidate flag")
            assert len(lane.files) == 50
            assert "That turn changed 60 files; the console lists the first 50." in last_user(server.requests[1])
            await lab.finish()

    run(main())
