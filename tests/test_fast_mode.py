"""Fast mode on the Anthropic API ([api] fast), through the real SDK to the fake Anthropic server.

The fake refuses `speed: "fast"` where the real API would (a model without fast mode, or a
research-preview model without its beta header), so a request flightdeck builds wrong fails
here too. No test calls the real API, and no key here is real.
"""

from __future__ import annotations

import asyncio
import time
from datetime import date

import pytest

from ctf_flightdeck.agent import fastmode
from ctf_flightdeck.agent.anthropic_client import AnthropicClient
from ctf_flightdeck.agent.client import ModelError, Reply
from ctf_flightdeck.agent.fallback import build_client, client_for
from ctf_flightdeck.config import load_config
from fake_anthropic import FAST_BETA, FALLBACK_BETA, FakeAnthropicServer, error, refusal, text_message

KEY = "test-anthropic-key-4Rq9-not-real"  # synthetic
MESSAGES = [{"role": "system", "content": "You are a test lane."}, {"role": "user", "content": "Read the note."}]


def chat(client: AnthropicClient, model: str, *, session: str = "flightdeck-run1-L01", **options) -> Reply:
    return asyncio.run(_chat(client, model, session, **options))


async def _chat(client, model, session, **options):
    return await client.chat(model, MESSAGES, [], session_id=session, **options)


def calls(base_url: str, *steps, fast=(), **options) -> list:
    """Run each (model, session) step through one client on one loop; the replies or errors."""

    async def run():
        out = []
        options.setdefault("max_retries", 1)
        options.setdefault("backoff", 0.001)
        async with AnthropicClient(base_url, KEY, fast=fast, **options) as client:
            for model, session in steps:
                try:
                    out.append(await client.chat(model, MESSAGES, [], session_id=session))
                except ModelError as exc:
                    out.append(exc)
        return out

    return asyncio.run(run())


def betas(request: dict) -> set[str]:
    return {b.strip() for b in request["headers"].get("anthropic-beta", "").split(",") if b.strip()}


# ---------------------------------------------------------------------- which requests are fast


def test_a_listed_model_is_called_in_fast_mode_and_the_rest_of_the_ladder_is_not():
    with FakeAnthropicServer([text_message("a"), text_message("b")]) as server:
        calls(server.base_url, ("claude-opus-5-5", "s1"), ("claude-sonnet-5-5", "s2"), fast=["claude-opus-5-5"])
        fast, standard = server.requests
    assert fast["json"]["speed"] == "fast" and FAST_BETA not in betas(fast)  # generally available: no beta flag
    assert FALLBACK_BETA in betas(fast)  # the refusal fallback still rides along
    assert "speed" not in standard["json"]


def test_a_research_preview_model_carries_the_fast_mode_beta():
    with FakeAnthropicServer([text_message("a")]) as server:
        (reply,) = calls(server.base_url, ("claude-opus-5", "s1"), fast=["claude-opus-5"])
        (request,) = server.requests
    assert isinstance(reply, Reply)
    assert request["json"]["speed"] == "fast" and {FAST_BETA, FALLBACK_BETA} <= betas(request)


def test_without_a_fast_list_nothing_is_fast():
    with FakeAnthropicServer([text_message("a")]) as server:
        calls(server.base_url, ("claude-opus-5-5", "s1"))
        assert "speed" not in server.requests[0]["json"]


@pytest.mark.parametrize("model, says", [
    ("claude-sonnet-5-5", "fast mode cannot be used: claude-sonnet-5-5 has no fast mode; fast mode is for claude-opus-5-5, "
                          "claude-fable-5-2, claude-mythos-5-2, claude-opus-5 (research preview)"),
    ("claude-haiku-5-5", "claude-haiku-5-5 has no fast mode"),
])
def test_a_model_the_skill_does_not_list_for_fast_mode_is_refused_with_the_reason(model, says):
    with pytest.raises(ValueError) as caught:
        AnthropicClient("http://127.0.0.1:9", KEY, fast=[model])
    assert says in str(caught.value)


def test_fast_mode_on_opus_4_8_is_refused_from_the_day_it_is_removed(monkeypatch):
    monkeypatch.setattr(fastmode, "today", lambda: date(2026, 11, 29))
    assert AnthropicClient("http://127.0.0.1:9", KEY, fast=["claude-opus-4-8"]).fast == {"claude-opus-4-8"}
    monkeypatch.setattr(fastmode, "today", lambda: date(2026, 11, 30))
    with pytest.raises(ValueError, match="fast mode on claude-opus-4-8 was removed on 2026-11-30"):
        AnthropicClient("http://127.0.0.1:9", KEY, fast=["claude-opus-4-8"])


def test_the_config_list_reaches_the_lanes_client(tmp_path):
    with FakeAnthropicServer([text_message("a")]) as server:
        path = tmp_path / "config.toml"
        path.write_text(
            f'[api]\nprovider = "anthropic"\nbase_url = "{server.base_url}"\nfast = ["claude-opus-5-5"]\n'
            '[models]\nladder = ["claude-haiku-5-5", "claude-opus-5-5"]\n'
        )
        client = build_client(load_config(path), KEY, None)
        assert client.fast == {"claude-opus-5-5"}
        asyncio.run(_close_after(client, client.chat("claude-opus-5-5", MESSAGES, [], session_id="s")))
        assert server.requests[0]["json"]["speed"] == "fast"


async def _close_after(client, call):
    try:
        return await call
    finally:
        await client.aclose()


def test_an_openai_compatible_api_takes_no_fast_list():
    with pytest.raises(ValueError, match="fast mode is a feature of the Anthropic Messages API"):
        client_for("openai", "http://127.0.0.1:9/v1", None, fast=["claude-opus-5-5"])


# ---------------------------------------------------------------------- fast mode's own rate limit


RATE_LIMITED = error(429, "rate_limit_error", "rate limited", headers={"retry-after": "30"})  # a wait no test sits out
BUSY = error(429, "rate_limit_error", "rate limited")  # no retry-after: a retry waits the (tiny) backoff


def test_a_fast_mode_429_goes_on_at_standard_speed_at_once_and_says_so():
    with FakeAnthropicServer([RATE_LIMITED, text_message("on it")]) as server:
        begun = time.monotonic()
        (reply,) = calls(server.base_url, ("claude-opus-5-5", "s1"), fast=["claude-opus-5-5"], backoff=5.0)
        waited = time.monotonic() - begun
        first, second = server.requests
    assert first["json"]["speed"] == "fast" and "speed" not in second["json"]
    assert reply.content == "on it"
    assert "fast mode's own rate limit was reached (HTTP 429)" in reply.notice
    assert "goes on at standard speed" in reply.notice and "prompt cache" in reply.notice
    assert waited < 4.0  # not the retry-after's 30 s, nor a backoff: the standard limit is another one


def test_the_lane_session_stays_at_standard_speed_and_another_session_is_fast_again():
    with FakeAnthropicServer([RATE_LIMITED, text_message("1"), text_message("2"), text_message("3")]) as server:
        replies = calls(server.base_url, ("claude-opus-5-5", "s1"), ("claude-opus-5-5", "s1"), ("claude-opus-5-5", "s2"),
                        fast=["claude-opus-5-5"])
        speeds = [r["json"].get("speed") for r in server.requests]
    assert speeds == ["fast", None, None, "fast"]  # s1 drops once and stays; s2 (an escalation, say) tries fast again
    assert [bool(r.notice) for r in replies] == [True, False, False]  # said once, when it happened


def test_the_drop_to_standard_is_not_a_try_but_a_standard_429_is():
    with FakeAnthropicServer([RATE_LIMITED, BUSY]) as server:
        async def run():
            async with AnthropicClient(server.base_url, KEY, max_retries=0, backoff=0.001, fast=["claude-opus-5-5"]) as c:
                return await c.chat("claude-opus-5-5", MESSAGES, [], session_id="s1")

        with pytest.raises(ModelError) as caught:
            asyncio.run(run())
        assert len(server.requests) == 2  # fast, then standard; the standard 429 used the one try
    assert "gave up after 1 tries" in str(caught.value) and caught.value.retryable


def test_a_429_on_a_standard_request_is_retried_as_before():
    with FakeAnthropicServer([BUSY, text_message("ok")]) as server:
        (reply,) = calls(server.base_url, ("claude-opus-5-5", "s1"))
        assert reply.content == "ok" and reply.notice == ""
        assert [r["json"].get("speed") for r in server.requests] == [None, None]


def test_the_retry_gate_holds_the_standard_speed_try():
    gate = []

    async def before_retry():
        gate.append(len(server.requests))

    with FakeAnthropicServer([RATE_LIMITED, text_message("ok")]) as server:
        async def run():
            async with AnthropicClient(server.base_url, KEY, max_retries=0, fast=["claude-opus-5-5"]) as c:
                return await c.chat("claude-opus-5-5", MESSAGES, [], session_id="s1", before_retry=before_retry)

        asyncio.run(run())
    assert gate == [1]  # awaited once: after the fast 429, before the standard try


# ---------------------------------------------------------------------- the price of a fast call


@pytest.mark.parametrize("speed, expected", [
    ("fast", (2_000 * 8.0 + 1_000 * 8.0 + 100 * 40.0) / 1e6),  # cached tokens at the fast input rate too
    (None, (2_000 * 8.0 + 1_000 * 8.0 + 100 * 40.0) / 1e6),  # the API did not say: priced as asked, fast
    ("standard", None),  # it ran at standard speed: the config's price applies, as for any call
])
def test_a_fast_call_is_priced_at_the_fast_rate(speed, expected):
    body = text_message("ok", model="claude-opus-5-5", input_tokens=2_000, cache_read=1_000, output_tokens=100, speed=speed)
    with FakeAnthropicServer([body]) as server:
        (reply,) = calls(server.base_url, ("claude-opus-5-5", "s1"), fast=["claude-opus-5-5"])
    assert reply.usage.speed == (speed or "")
    assert reply.usage.cost == (pytest.approx(expected) if expected is not None else None)


def test_a_standard_call_carries_no_cost_from_the_client():
    with FakeAnthropicServer([text_message("ok", speed="standard")]) as server:
        (reply,) = calls(server.base_url, ("claude-opus-5-5", "s1"))
    assert reply.usage.cost is None and reply.usage.speed == "standard"


def test_a_fast_refusal_is_paid_at_the_fast_rate():
    with FakeAnthropicServer([refusal("cyber", model="claude-opus-5-5", input_tokens=1_000, output_tokens=0)]) as server:
        (failure,) = calls(server.base_url, ("claude-opus-5-5", "s1"), fast=["claude-opus-5-5"])
    assert isinstance(failure, ModelError) and failure.declined
    assert failure.usage.cost == pytest.approx(1_000 * 8.0 / 1e6)


# ---------------------------------------------------------------------- the light role's options


def test_effort_goes_out_only_to_models_that_take_it_and_server_fallback_can_be_left_out():
    with FakeAnthropicServer([text_message("a"), text_message("b")]) as server:
        calls(server.base_url, ("claude-sonnet-5-5", "s1"), ("claude-haiku-4-5", "s2"), effort="low", server_fallback=False)
        sonnet, haiku = server.requests
    assert sonnet["json"]["output_config"] == {"effort": "low"}
    assert "fallbacks" not in sonnet["json"] and not betas(sonnet)  # a refusal stays a refusal
    assert "output_config" not in haiku["json"]  # Claude Haiku 4.5 rejects effort


def test_an_unknown_effort_is_refused():
    with pytest.raises(ValueError, match="effort must be one of low, medium, high, xhigh, max"):
        AnthropicClient("http://127.0.0.1:9", KEY, effort="lowest")


# ---------------------------------------------------------------------- a lane in fast mode, in a run


def test_a_run_names_its_fast_models_and_a_lane_says_when_it_drops_to_standard_speed(tmp_path, monkeypatch):
    import json

    from ctf_flightdeck.run import RunOptions, prepare_run
    from fake_anthropic import tool_message

    monkeypatch.setenv("FLIGHTDECK_TEST_ANTHROPIC_KEY", KEY)
    root = tmp_path / "board"
    (root / "note").mkdir(parents=True)
    (root / "note" / "note.txt").write_text("nothing here\n")
    (root / "note" / "challenge.json").write_text(json.dumps({"name": "Note", "category": "misc", "points": 50,
                                                              "description": "Read the note."}))
    (root / "board.json").write_text(json.dumps({"event": "Fast Test", "flag_format": r"t\{[a-z0-9_]+\}"}))
    first = []

    def responder(record):
        if not first:
            first.append(record)
            return RATE_LIMITED
        return tool_message("shell", {"command": "ls"}, model="claude-opus-5-5", speed="standard")

    with FakeAnthropicServer(responder=responder) as server:
        path = tmp_path / "config.toml"
        path.write_text(
            f'[api]\nprovider = "anthropic"\nbase_url = "{server.base_url}"\nkey_env = "FLIGHTDECK_TEST_ANTHROPIC_KEY"\n'
            'fast = ["claude-opus-5-5"]\n[models]\nladder = ["claude-opus-5-5"]\n'
            '[lanes]\nruntime = "host"\nmax_lanes = 1\ndollar_cap = false\ntoken_cap = false\n'
            f'[run]\ndir = "{tmp_path / "runs"}"\n'
        )
        run = prepare_run(RunOptions(board=root, config=path))
        assert any(n.startswith("fast mode: claude-opus-5-5 ($8 / $40 per million tokens)") for n in run.notes())

        async def main():
            run.release()
            (lane,) = run.deck.lanes.values()
            for _ in range(2000):
                if lane.turns >= 2:
                    break
                await asyncio.sleep(0.01)
            await run.shutdown()
            return lane

        lane = asyncio.run(main())
        run.close()
        # the run first asks the Models API (GET /v1/models) whether the ladder is served; then come the calls
        speeds = [r["json"].get("speed") for r in server.requests if r["path"] == "/v1/messages"]
    assert speeds[:3] == ["fast", None, None]  # the 429 moved the lane to standard speed, and it stayed there
    assert any("fast mode's own rate limit was reached (HTTP 429)" in a.text for a in lane.actions)
