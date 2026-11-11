"""Anthropic first, OpenRouter when it keeps failing: FallbackClient, alone and under the driver.

Two real fake servers on 127.0.0.1: FakeAnthropicServer for the primary (through the real
SDK) and FakeModelServer, OpenAI-compatible, for the fallback. The lane tests run a real
Deck and AgentDriver on host workspaces in tmp_path, as tests/test_agent_driver.py does.
No real API is called, and no key here is real.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from ctf_flightdeck.agent.anthropic_client import CONTENT_KEY, AnthropicClient
from ctf_flightdeck.agent.client import ModelClient, ModelError
from ctf_flightdeck.agent.driver import AgentDriver
from ctf_flightdeck.agent.fallback import FallbackClient, api_name, build_client, client_for
from ctf_flightdeck.agent.prompts import system_prompt
from ctf_flightdeck.agent.workspace import HostWorkspace
from ctf_flightdeck.clock import RunClock
from ctf_flightdeck.config import load_config
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.model import Challenge, DeckConfig, LaneState, PendingKind
from ctf_flightdeck.pricing import Price
from fake_anthropic import FakeAnthropicServer, error, refusal, text_message, tool_message
from fake_model import FakeModelServer, error_reply, text_reply, tool_call_reply

KEY = "test-anthropic-key-8Zt3-not-real"
SPARE_KEY = "test-openrouter-key-2Mw6-not-real"
FLAG = r"t\{[a-z0-9_]+\}"
MODELS = ("claude-haiku-5-5", "claude-sonnet-5-5")
LADDER = {"claude-haiku-5-5": "anthropic/claude-haiku-5.5", "claude-sonnet-5-5": "anthropic/claude-sonnet-5.5"}
OVERLOADED = error(529, "overloaded_error", "Overloaded")
MESSAGES = [{"role": "system", "content": "You are a test lane."}, {"role": "user", "content": "Read the note."}]


def pair(anthropic_url: str, openrouter_url: str, *, models=None, max_retries: int = 1) -> FallbackClient:
    primary = AnthropicClient(anthropic_url, KEY, max_retries=max_retries, backoff=0.001)
    fallback = ModelClient(openrouter_url, SPARE_KEY, max_retries=0, backoff=0.0)
    return FallbackClient(primary, fallback, LADDER if models is None else models,
                          primary_name="Anthropic", fallback_name="OpenRouter")


def sent_to(server) -> int:
    return len(server.requests)


# ---------------------------------------------------------------------- the client alone


def test_a_retryable_failure_moves_the_call_to_the_fallback_with_its_model_and_a_notice():
    with FakeAnthropicServer([OVERLOADED, OVERLOADED]) as claude, FakeModelServer([text_reply("from openrouter")]) as router:
        async def run():
            async with pair(claude.base_url, router.base_url) as client:
                return await client.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="lane-1")

        reply = asyncio.run(run())
        assert sent_to(claude) == 2 and sent_to(router) == 1  # the primary's own retries first
        request = router.requests[0]
    assert reply.content == "from openrouter"
    assert request["json"]["model"] == "anthropic/claude-haiku-5.5" and request["json"]["session_id"] == "lane-1"
    assert request["headers"]["authorization"] == f"Bearer {SPARE_KEY}"
    assert reply.notice == (
        "moved to OpenRouter (anthropic/claude-haiku-5.5) for the rest of this context: Anthropic failed: "
        "the Anthropic API answered HTTP 529 (overloaded_error): Overloaded; gave up after 2 tries"
    )


def test_the_session_stays_on_the_fallback_for_the_rest_of_its_context_and_says_so_once():
    with FakeAnthropicServer([OVERLOADED, OVERLOADED, text_message("never asked")]) as claude, \
            FakeModelServer([text_reply("one"), text_reply("two")]) as router:
        async def run():
            async with pair(claude.base_url, router.base_url) as client:
                messages = list(MESSAGES)
                first = await client.chat("claude-haiku-5-5", messages, [], session_id="lane-1")
                messages += [first.message, {"role": "user", "content": "go on"}]
                second = await client.chat("claude-haiku-5-5", messages, [], session_id="lane-1")
                return first, second, client.moved("lane-1")

        first, second, moved = asyncio.run(run())
        assert sent_to(claude) == 2  # nothing more went to the primary in that context
    assert (first.content, second.content, moved) == ("one", "two", "anthropic/claude-haiku-5.5")
    assert first.notice and second.notice == ""


def test_a_fresh_context_or_another_session_tries_the_primary_again():
    with FakeAnthropicServer([OVERLOADED, OVERLOADED, text_message("primary again"), text_message("and again")]) as claude, \
            FakeModelServer([text_reply("fallback")]) as router:
        async def run():
            async with pair(claude.base_url, router.base_url) as client:
                moved = await client.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="lane-1")
                refreshed = await client.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="lane-1")  # a new list
                escalated = await client.chat("claude-sonnet-5-5", list(MESSAGES), [], session_id="lane-1-e1")
                return moved, refreshed, escalated

        moved, refreshed, escalated = asyncio.run(run())
        assert sent_to(router) == 1 and sent_to(claude) == 4
    assert (moved.content, refreshed.content, escalated.content) == ("fallback", "primary again", "and again")


@pytest.mark.parametrize("answer", [
    error(400, "invalid_request_error", "messages: bad"),
    error(401, "authentication_error", "invalid x-api-key"),
    refusal("cyber"),
], ids=["400", "401", "refusal"])
def test_a_failure_another_api_would_not_change_does_not_fall_back(answer):
    with FakeAnthropicServer([answer]) as claude, FakeModelServer([text_reply("never")]) as router:
        async def run():
            async with pair(claude.base_url, router.base_url) as client:
                await client.chat("claude-sonnet-5-5", list(MESSAGES), [], session_id="lane-1")

        with pytest.raises(ModelError) as info:
            asyncio.run(run())
        assert sent_to(router) == 0 and sent_to(claude) == 1
    assert "OpenRouter" not in str(info.value) and not info.value.retryable


def test_a_model_with_no_fallback_model_fails_loudly_saying_so():
    with FakeAnthropicServer([OVERLOADED, OVERLOADED]) as claude, FakeModelServer([text_reply("never")]) as router:
        async def run():
            async with pair(claude.base_url, router.base_url, models={}) as client:
                await client.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="lane-1")

        with pytest.raises(ModelError) as info:
            asyncio.run(run())
        assert sent_to(router) == 0
    assert "no fallback: [fallback] ladder has no model for claude-haiku-5-5" in str(info.value)
    assert info.value.status == 529 and info.value.retryable


def test_when_the_fallback_fails_too_the_error_says_where_and_chains_nothing():
    with FakeAnthropicServer([OVERLOADED, OVERLOADED]) as claude, \
            FakeModelServer([error_reply(500, f"upstream echoed {SPARE_KEY}")]) as router:
        async def run():
            async with pair(claude.base_url, router.base_url) as client:
                await client.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="lane-1")

        with pytest.raises(ModelError) as info:
            asyncio.run(run())
    err = info.value
    assert str(err).endswith("(on OpenRouter, where this context moved when Anthropic failed)")
    assert "HTTP 500" in str(err) and SPARE_KEY not in str(err) and KEY not in str(err)
    assert err.__cause__ is None and err.__context__ is None


def test_the_move_waits_at_the_retry_gate_and_a_gate_that_stops_it_sends_the_fallback_nothing():
    class Stop(Exception):
        pass

    gates = []

    async def gate():
        gates.append(sent_to(claude))
        if len(gates) == 2:  # the first gate is the primary's own retry, the second is the move
            raise Stop()

    with FakeAnthropicServer([OVERLOADED, OVERLOADED]) as claude, FakeModelServer([text_reply("never")]) as router:
        async def run():
            async with pair(claude.base_url, router.base_url) as client:
                await client.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="lane-1", before_retry=gate)

        with pytest.raises(Stop):
            asyncio.run(run())
        assert sent_to(router) == 0
    assert gates == [1, 2]


def test_closing_the_pair_closes_both_clients():
    async def run():
        client = pair("http://127.0.0.1:9", "http://127.0.0.1:9/v1")
        await client.aclose()
        for inner in (client.primary, client.fallback):
            with pytest.raises(RuntimeError, match="closed"):
                await inner.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="s")

    asyncio.run(run())


def test_apis_are_named_for_the_player():
    assert api_name("anthropic", "https://api.anthropic.com") == "Anthropic"
    assert api_name("openai", "https://openrouter.ai/api/v1") == "OpenRouter"
    assert api_name("openai", "https://api.openai.com/v1") == "OpenAI"
    assert api_name("openai", "http://127.0.0.1:11434/v1") == "127.0.0.1"


def test_the_lanes_client_follows_the_config(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    path.write_text('[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-haiku-5-5", "claude-sonnet-5-5"]\n')
    alone = build_client(load_config(path), KEY, None)
    assert isinstance(alone, AnthropicClient)
    path.write_text(path.read_text() + '[fallback]\nladder = ["anthropic/claude-haiku-5.5", "anthropic/claude-sonnet-5.5"]\n')
    both = build_client(load_config(path), KEY, SPARE_KEY)
    assert isinstance(both, FallbackClient) and isinstance(both.primary, AnthropicClient)
    assert isinstance(both.fallback, ModelClient)
    assert both.models == LADDER and (both.primary_name, both.fallback_name) == ("Anthropic", "OpenRouter")
    assert isinstance(client_for("openai", "https://openrouter.ai/api/v1", None), ModelClient)
    for client in (alone, both):
        asyncio.run(client.aclose())


# ---------------------------------------------------------------------- lanes under the driver


async def until(cond, what: str, timeout: float = 10.0) -> None:
    end = time.monotonic() + timeout
    while not cond():
        if time.monotonic() > end:
            raise AssertionError(f"timed out waiting for {what}")
        await asyncio.sleep(0.01)


class Lab:
    """A deck with the agent driver on a given client, host workspaces in tmp."""

    def __init__(self, tmp_path: Path, client, *, prices: dict[str, Price] | None = None) -> None:
        folder = tmp_path / "board" / "note"
        folder.mkdir(parents=True)
        (folder / "note.txt").write_text("the flag is t{note}\n")
        self.client = client
        self.driver = AgentDriver(
            client,
            lambda lane, ch: HostWorkspace(tmp_path / "runs" / lane.id / "work", folder),
            run_id="run1",
            files={"note": ["note.txt"]},
            prices=prices or {},
        )
        config = DeckConfig(event="t", flag_format=FLAG, models=MODELS, max_lanes=1)
        self.deck = Deck(config, self.driver, RunClock(), lambda cid, flag: flag == "t{note}")
        self.deck.release([Challenge("note", "Note", "misc", 50, solves=10, description="About note.")],
                          [QueueEntry("note", MODELS[0])])
        (self.lane,) = self.deck.lanes.values()

    def notes(self) -> list[str]:
        return [a.text for a in self.lane.actions]

    async def finish(self) -> None:
        await self.driver.shutdown()
        await self.client.aclose()


def test_a_lane_on_anthropic_reads_the_handout_and_hands_over_a_flag(tmp_path):
    scripted = [
        tool_message("shell", {"command": "cat note.txt"}, call_id="toolu_1", input_tokens=900, output_tokens=40,
                     cache_read=0, cache_write=800),
        tool_message("submit_flag", {"flag": "t{note}"}, call_id="toolu_2", signature="fake-signature-2",
                     input_tokens=100, output_tokens=30, cache_read=1700),
    ]
    claude = FakeAnthropicServer(json.loads(json.dumps(scripted)))

    async def main():
        with claude:
            lab = Lab(tmp_path, AnthropicClient(claude.base_url, KEY, max_retries=0),
                      prices={"claude-haiku-5-5": Price(input=0.10, output=0.50, cached_input=0.01)})
            lane = lab.lane
            await until(lambda: lane.pending is not None or lane.finished, "the candidate flag")
            assert lane.pending is not None, lane.result
            first, second = (r["json"] for r in claude.requests)
            assert first["system"] == [{"type": "text", "text": system_prompt(FLAG), "cache_control": {"type": "ephemeral"}}]
            assert [m["role"] for m in first["messages"]] == ["user"]
            assert "Challenge: Note (misc, 50 points, 10 solves)" in first["messages"][0]["content"][0]["text"]
            assistant, results = second["messages"][1], second["messages"][2]
            assert assistant == {"role": "assistant", "content": scripted[0]["content"]}  # thinking included, unchanged
            (result,) = results["content"]
            assert result["type"] == "tool_result" and result["tool_use_id"] == "toolu_1"
            assert result["content"].startswith("exit 0") and "the flag is t{note}" in result["content"]
            assert (lane.pending.kind, lane.pending.flag) == (PendingKind.SUBMIT, "t{note}")
            assert lane.turns == 2 and lane.tokens == (1700 + 40) + (1800 + 30) and lane.cached_tokens == 1700
            # haiku at $0.10 / $0.50 / $0.01 per million: (1700 x 0.10 + 40 x 0.50) + (100 x 0.10 + 1700 x 0.01 + 30 x 0.50)
            assert lane.dollars == pytest.approx((170 + 20 + 10 + 17 + 15) / 1_000_000)
            assert lab.deck.apply(iv.Approve(lane.id)).ok and lane.state is LaneState.SOLVED
            await lab.finish()

    asyncio.run(main())


def test_a_refusal_ends_the_lane_saying_the_model_declined_with_its_category_and_its_tokens_count(tmp_path):
    claude = FakeAnthropicServer([refusal("cyber", input_tokens=1200, output_tokens=0)])
    router = FakeModelServer([text_reply("never asked")])

    async def main():
        with claude, router:
            lab = Lab(tmp_path, pair(claude.base_url, router.base_url))
            lane = lab.lane
            await until(lambda: lane.finished, "the lane to end")
            assert lane.state is LaneState.GAVE_UP and lane.result == "the model declined (cyber)"
            assert any(a.text == "claude-haiku-5-5 declined" for a in lane.actions)
            assert lane.tokens == 1200
            assert sent_to(router) == 0  # a refusal never moves a lane
            await lab.finish()

    asyncio.run(main())


def test_after_a_529_the_lane_moves_to_openrouter_says_so_and_stays_there(tmp_path):
    claude = FakeAnthropicServer([
        tool_message("shell", {"command": "cat note.txt"}, call_id="toolu_1"),
        OVERLOADED, OVERLOADED,
    ])
    router = FakeModelServer([
        tool_call_reply("shell", {"command": "echo still here"}),
        tool_call_reply("submit_flag", {"flag": "t{note}"}),
    ])

    async def main():
        with claude, router:
            lab = Lab(tmp_path, pair(claude.base_url, router.base_url))
            lane = lab.lane
            await until(lambda: lane.pending is not None or lane.finished, "the candidate flag")
            assert lane.pending is not None, lane.result
            assert sent_to(claude) == 3 and sent_to(router) == 2  # after the move, every call went to OpenRouter
            moved = [t for t in lab.notes() if "moved to OpenRouter" in t]
            assert moved == [
                "L01 moved to OpenRouter (anthropic/claude-haiku-5.5) for the rest of this context: Anthropic failed: "
                "the Anthropic API answered HTTP 529 (overloaded_error): Overloaded; gave up after 2 tries"
            ]
            for request in router.requests:
                body = request["json"]
                assert body["model"] == "anthropic/claude-haiku-5.5" and body["session_id"] == "flightdeck-run1-L01"
                text = json.dumps(body)
                assert CONTENT_KEY not in text and "fake-signature-1" not in text  # no Anthropic blocks to OpenRouter
            carried = router.requests[0]["json"]["messages"]  # the turn Anthropic answered, in OpenAI form
            assert [m["role"] for m in carried] == ["system", "user", "assistant", "tool"]
            assert carried[2]["tool_calls"] == [
                {"id": "toolu_1", "type": "function", "function": {"name": "shell", "arguments": '{"command": "cat note.txt"}'}}
            ]
            assert carried[3]["tool_call_id"] == "toolu_1" and "the flag is t{note}" in carried[3]["content"]
            await lab.finish()

    asyncio.run(main())


def test_escalating_a_moved_lane_tries_anthropic_again_on_the_stronger_model(tmp_path):
    claude = FakeAnthropicServer([OVERLOADED, OVERLOADED, tool_message("submit_flag", {"flag": "t{big}"},
                                                                       model="claude-sonnet-5-5")])
    router = FakeModelServer([tool_call_reply("shell", {"command": "echo on openrouter"})], responder=lambda r: text_reply("waiting"))

    async def main():
        with claude, router:
            lab = Lab(tmp_path, pair(claude.base_url, router.base_url))
            lane = lab.lane
            await until(lambda: lane.turns >= 1, "the first turn, on OpenRouter")
            assert lab.deck.apply(iv.Escalate(lane.id)).ok
            await until(lambda: lane.pending is not None or lane.finished, "the stronger model's candidate")
            assert lane.pending is not None, lane.result
            last = claude.requests[-1]
            assert last["json"]["model"] == "claude-sonnet-5-5"  # Anthropic again, in the escalated context
            assert last["headers"]["anthropic-beta"] == "server-side-fallback-2026-07-01"
            await lab.finish()

    asyncio.run(main())


def test_a_context_refresh_tries_anthropic_again(tmp_path):
    claude = FakeAnthropicServer([OVERLOADED, OVERLOADED, tool_message("submit_flag", {"flag": "t{note}"})])
    router = FakeModelServer([tool_call_reply("shell", {"command": "echo long"}, prompt_tokens=60_000)])

    async def main():
        with claude, router:
            lab = Lab(tmp_path, pair(claude.base_url, router.base_url))
            lab.driver.compact_at = 50_000
            lane = lab.lane
            await until(lambda: lane.pending is not None or lane.finished, "the candidate flag")
            assert lane.pending is not None, lane.result
            assert sent_to(router) == 1 and sent_to(claude) == 3
            refreshed = claude.requests[2]["json"]["messages"]
            assert "60,000 prompt tokens" in refreshed[-1]["content"][-1]["text"]  # the fresh context's summary
            await lab.finish()

    asyncio.run(main())


def test_a_400_does_not_move_the_lane_and_ends_it_with_the_reason(tmp_path):
    claude = FakeAnthropicServer([error(400, "invalid_request_error", "messages.0: something the API refused")])
    router = FakeModelServer([text_reply("never asked")])

    async def main():
        with claude, router:
            lab = Lab(tmp_path, pair(claude.base_url, router.base_url))
            lane = lab.lane
            await until(lambda: lane.finished, "the lane to end")
            assert lane.state is LaneState.GAVE_UP
            assert lane.result == ("model API error: the Anthropic API answered HTTP 400 (invalid_request_error): "
                                   "messages.0: something the API refused")
            assert sent_to(router) == 0 and not any("moved to" in t for t in lab.notes())
            await lab.finish()

    asyncio.run(main())
