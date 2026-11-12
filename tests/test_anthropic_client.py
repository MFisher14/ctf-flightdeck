"""The Anthropic client, over real HTTP to the fake Anthropic server, through the real SDK.

Nothing is mocked: each test starts a FakeAnthropicServer on 127.0.0.1, scripts its replies
and reads back what the SDK sent. The fake answers 400, as the API would, to a request that
breaks the API's rules (fake_anthropic.contract), so a translation that the real API would
refuse fails here too. Backoffs are a millisecond so retries stay fast. No test calls the
real API, and no key here is real.
"""

from __future__ import annotations

import asyncio
import copy
import json
import socket
import time

import anthropic
import pytest

from ctf_flightdeck.agent.anthropic_client import (
    CONTENT_KEY,
    DEFAULT_MAX_TOKENS,
    FALLBACK_BETA,
    AnthropicClient,
    to_anthropic,
)
from ctf_flightdeck.agent.client import ModelError, Reply, ToolCall, Usage, call_dollars
from ctf_flightdeck.agent.tools import TOOLS
from ctf_flightdeck.config import ANTHROPIC_BASE_URL
from ctf_flightdeck.pricing import Price
from fake_anthropic import FakeAnthropicServer, attempt, error, message, refusal, text_message, thinking, tool_message
from fake_model import FakeReply

KEY = "test-anthropic-key-4Rq9-not-real"  # synthetic; the shape of no real provider's key
SESSION = "flightdeck-run1-L01"
SYSTEM = "You are a test lane."
MESSAGES = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": "Read the note."}]
HAIKU = Price(0.10, 0.50, 0.01, 0.125)  # dollars per million: input, output, cache reads, 5-minute cache writes
OPUS = Price(4.0, 20.0, 0.20, 5.0)
FALLBACK_BLOCK = {"type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-4-8"},
                  "trigger": {"type": "refusal", "category": "cyber"}}


def chat(base_url: str, messages: list[dict] | None = None, *, model: str = "claude-haiku-5-5", tools=None,
         key: str = KEY, timeout: float = 5.0, max_retries: int = 2, backoff: float = 0.001, **options) -> Reply:
    """One chat() through a fresh client on a fresh event loop."""

    async def run() -> Reply:
        async with AnthropicClient(base_url, key, timeout=timeout, max_retries=max_retries, backoff=backoff) as client:
            return await client.chat(model, messages if messages is not None else MESSAGES, tools or [],
                                     session_id=SESSION, **options)

    return asyncio.run(run())


def fails(base_url: str, **kwargs) -> ModelError:
    with pytest.raises(ModelError) as info:
        chat(base_url, **kwargs)
    return info.value


def closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def turn(server: FakeAnthropicServer, messages: list[dict], **kwargs) -> Reply:
    """A chat() whose reply goes into `messages`, as the driver keeps the history."""
    reply = chat(server.base_url, messages, **kwargs)
    messages.append(reply.message)
    return reply


# ---------------------------------------------------------------------- the request


def test_the_system_prompt_is_cached_with_the_tools_and_the_tail_is_cached_automatically():
    with FakeAnthropicServer([text_message("hello")]) as server:
        chat(server.base_url, tools=TOOLS)
        (request,) = server.requests
    body = request["json"]
    assert body["system"] == [{"type": "text", "text": SYSTEM, "cache_control": {"type": "ephemeral"}}]
    assert body["cache_control"] == {"type": "ephemeral"}  # automatic caching for the growing conversation
    assert body["messages"] == [{"role": "user", "content": [{"type": "text", "text": "Read the note."}]}]
    assert body["model"] == "claude-haiku-5-5" and body["max_tokens"] == DEFAULT_MAX_TOKENS == 16_000
    for absent in ("temperature", "top_p", "top_k", "tool_choice", "thinking"):  # the models choose; none is forced
        assert absent not in body
    assert request["path"] == "/v1/messages"


def test_tools_become_name_description_and_input_schema_in_the_same_order():
    with FakeAnthropicServer([text_message("hello")]) as server:
        chat(server.base_url, tools=TOOLS)
    tools = server.requests[0]["json"]["tools"]
    assert tools == [
        {"name": t["function"]["name"], "description": t["function"]["description"], "input_schema": t["function"]["parameters"]}
        for t in TOOLS
    ]


def test_a_given_max_tokens_is_sent_and_a_bad_one_is_refused_before_anything_is_sent():
    with FakeAnthropicServer([text_message("hello")]) as server:
        chat(server.base_url, max_tokens=512)
        with pytest.raises(ValueError, match="max_tokens"):
            chat(server.base_url, max_tokens=0)
    assert [r["json"]["max_tokens"] for r in server.requests] == [512]


def test_a_temperature_is_refused_before_anything_is_sent_never_dropped_quietly():
    with FakeAnthropicServer([text_message("hello")]) as server:
        with pytest.raises(ValueError, match="temperature"):
            chat(server.base_url, temperature=0.0)
    assert server.requests == []


@pytest.mark.parametrize("model, fallback", [
    ("claude-haiku-5-5", False),  # Claude Haiku 5.5 has no server-side fallback (a list is a 400 there)
    ("claude-sonnet-5-5", True),
    ("claude-opus-5-5", True),
])
def test_sonnet_and_opus_carry_the_server_side_refusal_fallback_and_haiku_does_not(model, fallback):
    with FakeAnthropicServer([text_message("hello", model=model)]) as server:
        chat(server.base_url, model=model)
        (request,) = server.requests
    betas = request["headers"].get("anthropic-beta", "")
    if fallback:
        assert request["json"]["fallbacks"] == "default" and betas == FALLBACK_BETA
    else:
        assert "fallbacks" not in request["json"] and FALLBACK_BETA not in betas


def test_a_tool_round_goes_back_as_tool_use_then_one_user_turn_of_its_tool_results_and_a_note_after_them():
    two_calls = message(
        [thinking("sig-a"),
         {"type": "tool_use", "id": "toolu_a", "name": "shell", "input": {"command": "ls"}},
         {"type": "tool_use", "id": "toolu_b", "name": "read_file", "input": {"path": "note.txt"}}],
        stop_reason="tool_use",
    )
    with FakeAnthropicServer([two_calls, text_message("done")]) as server:
        history = list(MESSAGES)
        reply = turn(server, history)
        history += [
            {"role": "tool", "tool_call_id": reply.tool_calls[0].id, "content": "note.txt"},
            {"role": "tool", "tool_call_id": reply.tool_calls[1].id, "content": "the flag is t{x}"},
            {"role": "user", "content": "Message from the player: check the date"},
        ]
        chat(server.base_url, history)
        sent = server.requests[1]["json"]["messages"]
    assert [m["role"] for m in sent] == ["user", "assistant", "user"]  # alternating: the fake refuses anything else
    assert sent[2]["content"] == [
        {"type": "tool_result", "tool_use_id": "toolu_a", "content": "note.txt"},
        {"type": "tool_result", "tool_use_id": "toolu_b", "content": "the flag is t{x}"},
        {"type": "text", "text": "Message from the player: check the date"},
    ]


def test_consecutive_user_messages_become_one_turn_so_the_request_alternates():
    messages = [*MESSAGES, {"role": "user", "content": "L1 found nothing."}]
    with FakeAnthropicServer([text_message("ok")]) as server:
        chat(server.base_url, messages)
    assert server.requests[0]["json"]["messages"] == [
        {"role": "user", "content": [{"type": "text", "text": "Read the note."}, {"type": "text", "text": "L1 found nothing."}]}
    ]


def test_thinking_and_every_other_block_go_back_exactly_as_the_api_sent_them():
    blocks = [
        {"type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-5"},
         "trigger": {"type": "refusal", "category": "cyber"}},
        {"type": "thinking", "thinking": "", "signature": "c2lnbmF0dXJlLW9uZQ=="},
        {"type": "redacted_thinking", "data": "b3BhcXVlLWJsb2I="},
        {"type": "text", "text": "Looking at it.", "citations": None},
        {"type": "some_future_block", "payload": {"x": [1, 2, {"y": None}]}},
        {"type": "tool_use", "id": "toolu_x", "name": "shell", "input": {"command": "cat note.txt", "n": 1.5}},
    ]
    sent_back = copy.deepcopy(blocks)
    with FakeAnthropicServer([message(blocks, stop_reason="tool_use", model="claude-opus-5"), text_message("done")]) as server:
        history = list(MESSAGES)
        reply = turn(server, history, model="claude-opus-5-5")
        assert reply.message[CONTENT_KEY] == sent_back
        history.append({"role": "tool", "tool_call_id": "toolu_x", "content": "exit 0"})
        chat(server.base_url, history, model="claude-opus-5-5")
        assistant = server.requests[1]["json"]["messages"][1]
    assert assistant == {"role": "assistant", "content": sent_back}  # unchanged, in order, unknown fields too
    assert reply.message[CONTENT_KEY] == sent_back  # sending them did not change the history


def test_an_assistant_message_from_an_openai_style_api_becomes_text_and_tool_use_blocks():
    openai_turn = {
        "role": "assistant",
        "content": "Reading it.",
        "reasoning": "an OpenRouter field the Messages API does not take",
        "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "shell", "arguments": '{"command": "ls"}'}},
            {"id": "call_2", "type": "function", "function": {"name": "shell", "arguments": '{"command": "ls'}},
        ],
    }
    turns = to_anthropic([MESSAGES[1], openai_turn,
                          {"role": "tool", "tool_call_id": "call_1", "content": "a"},
                          {"role": "tool", "tool_call_id": "call_2", "content": "error: arguments are not JSON"}])
    assert turns[1] == {"role": "assistant", "content": [
        {"type": "text", "text": "Reading it."},
        {"type": "tool_use", "id": "call_1", "name": "shell", "input": {"command": "ls"}},
        {"type": "tool_use", "id": "call_2", "name": "shell", "input": {}},  # it ran with broken JSON, and was told so
    ]}


def test_an_empty_assistant_turn_is_left_out_rather_than_sent_empty():
    with FakeAnthropicServer([message([], stop_reason="end_turn"), text_message("now something")]) as server:
        history = list(MESSAGES)
        reply = turn(server, history)
        assert reply.content == "" and reply.tool_calls == ()
        history.append({"role": "user", "content": "Use your tools."})
        assert chat(server.base_url, history).content == "now something"  # the fake refuses an empty turn
    assert [m["role"] for m in server.requests[1]["json"]["messages"]] == ["user"]


def test_a_system_message_after_the_start_is_refused_loudly():
    with pytest.raises(ValueError, match="system message"):
        to_anthropic([MESSAGES[1], {"role": "system", "content": "late"}])


# ---------------------------------------------------------------------- the reply


def test_a_tool_use_reply_gives_its_text_calls_stop_reason_model_and_a_history_message_both_apis_can_read():
    body = tool_message("shell", {"command": "cat note.txt"}, call_id="toolu_7", text="Reading the note.",
                        model="claude-sonnet-5-5")
    with FakeAnthropicServer([body]) as server:
        reply = chat(server.base_url, model="claude-sonnet-5-5")
    assert reply.content == "Reading the note."
    assert reply.tool_calls == (ToolCall("toolu_7", "shell", '{"command": "cat note.txt"}'),)
    assert (reply.finish_reason, reply.model, reply.notice) == ("tool_use", "claude-sonnet-5-5", "")
    assert reply.message == {
        "role": "assistant",
        "content": "Reading the note.",
        "tool_calls": [{"id": "toolu_7", "type": "function", "function": {"name": "shell", "arguments": '{"command": "cat note.txt"}'}}],
        CONTENT_KEY: body["content"],
    }


def test_usage_counts_cache_reads_and_writes_in_the_prompt_and_says_which_is_which_with_no_cost():
    body = text_message("ok", input_tokens=100, output_tokens=50, cache_read=4000, cache_write=900)
    with FakeAnthropicServer([body]) as server:
        usage = chat(server.base_url).usage
    assert usage == Usage(prompt_tokens=5000, completion_tokens=50, cached_tokens=4000, cost=None, cache_write_tokens=900)
    assert usage.parts() == (usage,) and call_dollars(usage, "claude-haiku-5-5", {"claude-haiku-5-5": HAIKU}.get) == (
        pytest.approx((100 * 0.10 + 4000 * 0.01 + 900 * 0.125 + 50 * 0.50) / 1e6))  # each at its own rate


def test_a_call_the_refusal_fallback_ran_on_two_models_is_told_per_model_and_counted_once():
    # usage.iterations: the attempt on the model asked for, declined, then the fallback's, which
    # answered; the top-level counts are the fallback attempt's, and are not counted again
    body = message(
        [FALLBACK_BLOCK, {"type": "text", "text": "Here is how."}], model="claude-opus-4-8",
        iterations=[attempt("claude-opus-5-5", input_tokens=300, cache_read=6000, cache_write=700),
                    attempt("claude-opus-4-8", kind="fallback_message", input_tokens=400, output_tokens=90, cache_write=6600)],
    )
    assert body["usage"]["input_tokens"] == 400  # the fake reports the top level as the API does
    with FakeAnthropicServer([body]) as server:
        reply = chat(server.base_url, model="claude-opus-5-5")
    usage = reply.usage
    assert usage == Usage(prompt_tokens=7000, completion_tokens=90, cache_write_tokens=6600, model="claude-opus-4-8",
                          more=(Usage(prompt_tokens=7000, cached_tokens=6000, cache_write_tokens=700),))
    assert sum(part.total for part in usage.parts()) == 7000 + 7090
    prices = {"claude-opus-5-5": OPUS, "claude-opus-4-8": Price(5.0, 25.0, 0.50, 6.25)}
    assert call_dollars(usage, "claude-opus-5-5", prices.get) == pytest.approx(
        (300 * 4.0 + 6000 * 0.20 + 700 * 5.0) / 1e6 + (400 * 5.0 + 6600 * 6.25 + 90 * 25.0) / 1e6)
    assert call_dollars(usage, "claude-opus-5-5", {"claude-opus-5-5": OPUS}.get) is None  # the fallback's model: no price


def test_an_attempt_that_names_no_model_ran_on_the_one_asked_for_and_the_fallbacks_on_the_one_that_answered():
    body = message([{"type": "text", "text": "ok"}], model="claude-sonnet-5",
                   iterations=[attempt(None, input_tokens=50), attempt(None, kind="fallback_message", input_tokens=60)])
    with FakeAnthropicServer([body]) as server:
        usage = chat(server.base_url, model="claude-sonnet-5-5").usage
    assert (usage.model, usage.prompt_tokens) == ("claude-sonnet-5", 60)
    assert [(part.model, part.prompt_tokens) for part in usage.more] == [("", 50)]


def test_attempts_on_one_model_are_summed_and_a_reply_with_no_attempts_listed_is_its_top_level_usage():
    body = message([{"type": "text", "text": "ok"}], model="claude-opus-5-5",
                   iterations=[attempt("claude-opus-5-5", input_tokens=10, output_tokens=1),
                               attempt("claude-opus-5-5", input_tokens=20, output_tokens=2)])
    with FakeAnthropicServer([body, message([{"type": "text", "text": "ok"}], iterations=[])]) as server:
        summed = chat(server.base_url, model="claude-opus-5-5").usage
        plain = chat(server.base_url).usage
    assert summed == Usage(prompt_tokens=30, completion_tokens=3)
    assert plain == Usage(prompt_tokens=100, completion_tokens=20)


def test_a_refusal_is_a_declined_error_naming_its_category_never_retried_and_its_tokens_counted():
    with FakeAnthropicServer([refusal("cyber", input_tokens=700, output_tokens=0), text_message("never sent")]) as server:
        err = fails(server.base_url, model="claude-sonnet-5-5", max_retries=3)
        assert len(server.requests) == 1
    assert str(err) == "the model declined (cyber)"
    assert err.declined and not err.retryable and err.status == 200
    assert err.usage == Usage(prompt_tokens=700, completion_tokens=0, cached_tokens=0, cost=None)


def test_a_refusal_the_fallback_declined_too_carries_every_attempt():
    declined = refusal("cyber", model="claude-sonnet-5",
                       iterations=[attempt("claude-sonnet-5-5", input_tokens=800), attempt("claude-sonnet-5", input_tokens=900)])
    with FakeAnthropicServer([declined]) as server:
        err = fails(server.base_url, model="claude-sonnet-5-5")
    assert err.declined
    assert [(part.model, part.prompt_tokens) for part in err.usage.parts()] == [("claude-sonnet-5", 900), ("", 800)]


def test_a_refusal_without_a_category_says_so_and_its_explanation_is_made_safe():
    with FakeAnthropicServer([refusal(None, explanation="declined\x1b[31m here\nfor reasons")]) as server:
        err = fails(server.base_url)
    text = str(err)
    assert text.startswith("the model declined (no category given): declined")
    assert text.endswith("for reasons") and "\x1b" not in text and "\n" not in text


def test_an_answer_from_the_server_side_fallback_leaves_a_notice_for_the_lane():
    switched = message([
        {"type": "fallback", "from": {"model": "claude-opus-5-5"}, "to": {"model": "claude-opus-5"},
         "trigger": {"type": "refusal", "category": "cyber"}},
        {"type": "text", "text": "Here is how."},
    ], model="claude-opus-5")
    with FakeAnthropicServer([switched]) as server:
        reply = chat(server.base_url, model="claude-opus-5-5")
    assert reply.notice == "Anthropic's refusal fallback: claude-opus-5-5 declined (cyber), claude-opus-5 answered"
    assert reply.content == "Here is how." and reply.model == "claude-opus-5"


@pytest.mark.parametrize("body, says", [
    (FakeReply(200, "<html>Bad Gateway</html>"), "not a JSON message"),
    (FakeReply(200, "[1, 2, 3]"), "not a JSON message"),
    (FakeReply(200, '"just a string"'), "not a JSON message"),
    ({"id": "msg_1", "type": "message"}, "without a list of content blocks"),
    ({"type": "error", "error": {"type": "api_error", "message": "upstream died"}}, "upstream died"),
    (message([{"type": "tool_use", "name": "shell", "input": {}}], stop_reason="tool_use"), "without an id"),
    (message([{"type": "tool_use", "id": "t", "name": "shell", "input": "ls"}], stop_reason="tool_use"), "not an object"),
    (FakeReply(200, '{"content": [{"type": "text", "text": "x", "score": NaN}], "stop_reason": "end_turn"}'), "NaN"),
], ids=["html", "json-list", "json-string", "no-content", "error-in-200", "tool-use-without-id", "input-not-object", "nan"])
def test_a_2xx_reply_that_makes_no_sense_fails_at_once_and_is_not_retried(body, says):
    with FakeAnthropicServer([body, text_message("never sent")]) as server:
        err = fails(server.base_url, max_retries=2)
        assert len(server.requests) == 1
    assert says in str(err)
    assert err.status == 200 and err.retryable is False and not err.declined


# ---------------------------------------------------------------------- retries


@pytest.mark.parametrize("status, kind", [(408, "timeout_error"), (409, "conflict"), (429, "rate_limit_error"),
                                          (500, "api_error"), (503, "api_error"), (529, "overloaded_error")])
def test_a_status_that_means_not_now_is_tried_again(status, kind):
    with FakeAnthropicServer([error(status, kind, "not now"), text_message("now")]) as server:
        assert chat(server.base_url).content == "now"
        assert len(server.requests) == 2


def test_the_sdk_makes_no_tries_of_its_own():
    # the SDK's default is 2 retries; ours are off at 0, so the driver's gate sees every one
    with FakeAnthropicServer([error(529, "overloaded_error", "Overloaded")] * 3) as server:
        err = fails(server.base_url, max_retries=0)
        assert len(server.requests) == 1
    assert err.status == 529 and err.retryable


def test_the_servers_x_should_retry_header_wins_as_it_does_in_the_sdk():
    with FakeAnthropicServer([error(503, "api_error", "do not", headers={"x-should-retry": "false"}), text_message("x")]) as server:
        err = fails(server.base_url)
        assert len(server.requests) == 1 and not err.retryable
    with FakeAnthropicServer([error(400, "invalid_request_error", "try me", headers={"x-should-retry": "true"}),
                              text_message("again")]) as server:
        assert chat(server.base_url).content == "again"


def test_when_every_try_fails_the_error_is_retryable_and_names_the_last_status_and_the_tries():
    replies = [error(429, "rate_limit_error", "slow down"), error(529, "overloaded_error", "Overloaded")] + [
        error(529, "overloaded_error", "Overloaded")]
    with FakeAnthropicServer(replies) as server:
        err = fails(server.base_url, max_retries=2)
        assert len(server.requests) == 3
    assert str(err) == "the Anthropic API answered HTTP 529 (overloaded_error): Overloaded; gave up after 3 tries"
    assert err.status == 529 and err.retryable is True and not err.declined


@pytest.mark.parametrize("status, kind", [(400, "invalid_request_error"), (401, "authentication_error"),
                                          (403, "permission_error"), (404, "not_found_error"), (413, "request_too_large")])
def test_any_other_failing_status_fails_at_once_with_the_servers_message(status, kind):
    with FakeAnthropicServer([error(status, kind, "you sent something wrong"), text_message("never sent")]) as server:
        err = fails(server.base_url)
        assert len(server.requests) == 1
    assert err.status == status and err.retryable is False
    assert str(err) == f"the Anthropic API answered HTTP {status} ({kind}): you sent something wrong"


def test_a_retry_after_header_sets_the_wait():
    with FakeAnthropicServer([error(529, "overloaded_error", "busy", headers={"Retry-After": "0.3"}), text_message("ok")]) as server:
        start = time.monotonic()
        assert chat(server.base_url, backoff=0.001).content == "ok"
        assert time.monotonic() - start >= 0.3


def test_before_retry_is_awaited_before_each_retry_and_what_it_raises_comes_out():
    class Stop(Exception):
        pass

    gates: list[int] = []

    async def gate() -> None:
        gates.append(len(server.requests))
        if len(gates) == 2:
            raise Stop()

    with FakeAnthropicServer([error(529, "overloaded_error", "busy")] * 5) as server:
        with pytest.raises(Stop):
            chat(server.base_url, max_retries=4, before_retry=gate)
        assert len(server.requests) == 2  # the second gate stopped the third try
    assert gates == [1, 2]  # after each failed try, before the next


def test_a_refused_connection_is_tried_again_then_fails_as_retryable_with_no_status():
    err = fails(f"http://127.0.0.1:{closed_port()}", max_retries=1)
    assert err.status is None and err.retryable is True
    assert "no answer from the Anthropic API" in str(err) and "2 tries" in str(err)


def test_a_try_that_takes_too_long_is_given_up_on_and_tried_again():
    count = {"n": 0}

    def slow_first(record: dict) -> dict:
        count["n"] += 1
        if count["n"] == 1:
            time.sleep(0.6)
        return text_message("on the second try")

    with FakeAnthropicServer(responder=slow_first) as server:
        reply = chat(server.base_url, timeout=0.3, max_retries=1)
        assert len(server.requests) == 2
    assert reply.content == "on the second try"


def test_a_redirect_is_not_followed_so_the_key_goes_nowhere_else():
    with FakeAnthropicServer([FakeReply(307, None, {"Location": "/v1/elsewhere"}), text_message("never")]) as server:
        err = fails(server.base_url)
        assert len(server.requests) == 1  # the SDK's own client would have followed it
    assert err.status == 307 and err.retryable is False


# ---------------------------------------------------------------------- the key stays secret


def test_the_key_goes_in_the_authorization_header_only():
    with FakeAnthropicServer([text_message("a")]) as server:
        chat(server.base_url)
        (request,) = server.requests
    assert request["headers"]["authorization"] == f"Bearer {KEY}"
    assert "x-api-key" not in request["headers"]
    assert KEY not in json.dumps(request["json"])


def test_no_credential_and_no_base_url_comes_from_the_environment(monkeypatch):
    elsewhere = f"http://127.0.0.1:{closed_port()}"
    monkeypatch.setenv("ANTHROPIC_API_KEY", "decoy-api-key-from-env")
    monkeypatch.setenv("ANTHROPIC_AUTH_TOKEN", "decoy-auth-token-from-env")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", elsewhere)
    monkeypatch.setenv("ANTHROPIC_PROFILE", "decoy-profile")
    with FakeAnthropicServer([text_message("here")]) as server:
        assert chat(server.base_url).content == "here"  # the configured server, not ANTHROPIC_BASE_URL
        (request,) = server.requests
    headers = json.dumps(request["headers"])
    assert request["headers"]["authorization"] == f"Bearer {KEY}"
    assert "decoy" not in headers


def test_the_config_default_is_the_sdks_own_base_url(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    sdk = anthropic.AsyncAnthropic(api_key="fake-key-for-a-default-check")  # constructing it sends nothing
    try:
        assert str(sdk.base_url).rstrip("/") == ANTHROPIC_BASE_URL
    finally:
        asyncio.run(sdk.close())


ECHO = f"invalid x-api-key {KEY}"  # a server that repeats the key back in its error text


@pytest.mark.parametrize("replies", [
    [error(401, "authentication_error", ECHO)],
    [error(529, "overloaded_error", ECHO)] * 3,
    [FakeReply(200, {"type": "error", "error": {"type": "api_error", "message": ECHO}})],
    [refusal("cyber", explanation=ECHO)],
], ids=["401", "529-every-try", "error-in-200", "refusal"])
def test_an_error_never_shows_the_key_even_when_the_server_echoes_it(replies):
    with FakeAnthropicServer(replies) as server:
        err = fails(server.base_url, max_retries=2)
    assert KEY not in str(err) and KEY not in repr(err) and KEY not in repr(err.args)
    assert "[key]" in str(err)  # the echo was there, and the key was cut out of it


def test_an_error_chains_nothing_that_holds_the_request():
    # an SDK exception holds the request, and the request holds the Authorization header
    unreachable = fails(f"http://127.0.0.1:{closed_port()}", max_retries=0)
    with FakeAnthropicServer([error(401, "authentication_error", "no"), FakeReply(200, "not json"),
                              error(529, "overloaded_error", "busy"), refusal("bio")]) as server:
        refused = fails(server.base_url)
        garbled = fails(server.base_url)
        overloaded = fails(server.base_url, max_retries=0)
        declined = fails(server.base_url)
    for err in (unreachable, refused, garbled, overloaded, declined):
        assert err.__cause__ is None and err.__context__ is None


def test_the_clients_repr_names_the_endpoint_but_never_the_key():
    client = AnthropicClient("https://user:pw@api.example.test/?tag=1", KEY)
    try:
        for text in (repr(client), str(client)):
            assert KEY not in text and "pw" not in text and "tag" not in text
            assert "https://api.example.test/" in text
    finally:
        asyncio.run(client.aclose())


@pytest.mark.parametrize("bad", [None, "", f"{KEY} {KEY}", f"{KEY}\n", f"{KEY}é"],
                         ids=["none", "empty", "space", "newline", "non-ascii"])
def test_no_key_or_a_key_no_header_can_carry_is_refused_without_showing_it(bad):
    with pytest.raises(ValueError, match="needs an API key") as info:
        AnthropicClient("http://127.0.0.1:9", bad)
    assert KEY not in str(info.value)


def test_lanes_can_share_one_client_at_the_same_time():
    import threading

    together = threading.Barrier(4, timeout=5)  # answered only once all four are in flight

    def echo(record: dict) -> dict:
        together.wait()
        return text_message(f"for {record['json']['messages'][0]['content'][0]['text']}")

    async def run() -> list[Reply]:
        async with AnthropicClient(server.base_url, KEY, max_retries=0) as client:
            return await asyncio.gather(*(
                client.chat("claude-haiku-5-5", [{"role": "user", "content": f"lane {n}"}], [], session_id=f"s{n}")
                for n in range(4)
            ))

    with FakeAnthropicServer(responder=echo) as server:
        replies = asyncio.run(run())
    assert [r.content for r in replies] == [f"for lane {n}" for n in range(4)]


def test_a_closed_client_refuses_to_call():
    async def run() -> None:
        client = AnthropicClient("http://127.0.0.1:9", KEY)
        await client.aclose()
        await client.chat("claude-haiku-5-5", MESSAGES, [], session_id=SESSION)

    with pytest.raises(RuntimeError, match="closed"):
        asyncio.run(run())


# ---------------------------------------------------------------------- the fake server keeps the API's rules


@pytest.mark.parametrize("messages, says", [
    ([{"role": "user", "content": "hi", "_anthropic_content": []}], "Extra inputs"),
    ([{"role": "user", "content": [{"type": "text", "text": "hi", "_private": 1}]}], "Extra inputs"),
    ([{"role": "assistant", "content": "hi"}], "first message"),
    ([{"role": "user", "content": "a"}, {"role": "user", "content": "b"}], "alternate"),
    ([{"role": "user", "content": "a"},
      {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "shell", "input": {}}]},
      {"role": "user", "content": "no result"}], "without tool_result"),
    ([{"role": "user", "content": [{"type": "text", "text": "x"}, {"type": "tool_result", "tool_use_id": "t1", "content": "r"}]}],
     "come first"),
    ([{"role": "user", "content": "   "}], "non-whitespace"),
], ids=["private-message-key", "private-block-key", "assistant-first", "same-role-twice", "missing-result",
        "result-after-text", "blank-text"])
def test_the_fake_server_refuses_what_the_real_api_would(messages, says):
    import httpx

    with FakeAnthropicServer([text_message("never")]) as server:
        answer = httpx.post(server.base_url + "/v1/messages", json={"model": "m", "max_tokens": 5, "messages": messages})
    assert answer.status_code == 400 and says in answer.json()["error"]["message"]


def test_the_fake_server_refuses_sampling_parameters_a_forced_tool_and_fallbacks_without_their_beta():
    import httpx

    base = {"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": "hi"}]}
    with FakeAnthropicServer() as server:
        for extra, says in [({"temperature": 0}, "temperature"), ({"tool_choice": {"type": "any"}}, "tool_choice"),
                            ({"fallbacks": "default"}, "fallback beta")]:
            answer = httpx.post(server.base_url + "/v1/messages", json={**base, **extra})
            assert answer.status_code == 400 and says in answer.json()["error"]["message"], extra
