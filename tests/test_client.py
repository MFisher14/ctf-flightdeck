"""The model API client, over real HTTP to the fake model server.

Nothing is mocked: each test starts a FakeModelServer on 127.0.0.1, scripts its replies and
reads back what the client sent. pytest has no async support here, so each call runs on a
fresh event loop with asyncio.run(). Backoffs are a millisecond so the retries stay fast; the
tests about waiting use waits that are short but long enough to measure.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import socket
import struct
import threading
import time
from collections.abc import Callable

import httpx
import pytest

from ctf_flightdeck.agent.client import (
    MAX_WAIT,
    ModelClient,
    ModelError,
    Reply,
    ToolCall,
    Usage,
    retry_delay,
)
from fake_model import (
    FakeModelServer,
    FakeReply,
    error_reply,
    text_reply,
    tool_call_reply,
    tool_calls_reply,
)

KEY = "test-key-7Qk2-not-a-real-one"  # synthetic; the shape of no real provider's key
SESSION = "lane-L01-a1"
MESSAGES = [
    {"role": "system", "content": "You are a test."},
    {"role": "user", "content": "Say hello."},
]
SHELL = {
    "type": "function",
    "function": {
        "name": "shell",
        "description": "Run a command in the workspace.",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
}


def call(
    base_url: str,
    *,
    key: str | None = None,
    tools: list[dict] | None = None,
    session_id: str = SESSION,
    timeout: float = 5.0,
    max_retries: int = 2,
    backoff: float = 0.001,
    transport: httpx.AsyncBaseTransport | None = None,
    app_name: str = "ctf-flightdeck",
    **options,
) -> Reply:
    """One chat() through a fresh client on a fresh event loop."""

    async def run() -> Reply:
        async with ModelClient(
            base_url,
            key,
            timeout=timeout,
            max_retries=max_retries,
            backoff=backoff,
            transport=transport,
            app_name=app_name,
        ) as client:
            return await client.chat("fake/model", MESSAGES, tools or [], session_id=session_id, **options)

    return asyncio.run(run())


def fails(base_url: str, **kwargs) -> ModelError:
    with pytest.raises(ModelError) as info:
        call(base_url, **kwargs)
    return info.value


def closed_port() -> int:
    """A loopback port nothing listens on: connecting to it is refused."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class CountingTransport(httpx.AsyncBaseTransport):
    """httpx's real transport, counting the requests it is asked to send and when, and
    noting when its connection pool is closed."""

    def __init__(self) -> None:
        self.inner = httpx.AsyncHTTPTransport()
        self.sent = 0
        self.times: list[float] = []  # time.monotonic() as each request set off
        self.closed = False

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        self.sent += 1
        self.times.append(time.monotonic())
        return await self.inner.handle_async_request(request)

    async def aclose(self) -> None:
        self.closed = True
        await self.inner.aclose()


def reply_with_message(message: dict) -> dict:
    body = text_reply("unused")
    body["choices"][0]["message"] = message
    return body


class RawServer:
    """A loopback HTTP server for the misbehaviour the fake model server will not show.

    Each connection's request is read in full, then `answer(conn, number)` writes what it
    likes (number counts the connections from 0) and the connection is closed. A failed
    try never reuses its connection, so `connections` counts the tries.
    """

    def __init__(self, answer: Callable[[socket.socket, int], None]) -> None:
        self._answer = answer
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.05)  # so the accept loop sees the stop flag
        self.base_url = f"http://127.0.0.1:{self._listener.getsockname()[1]}/v1"
        self.connections = 0
        self._stop = threading.Event()
        self._workers: list[threading.Thread] = []
        self._acceptor = threading.Thread(target=self._accept, name="raw-server", daemon=True)

    def __enter__(self) -> RawServer:
        self._acceptor.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._acceptor.join()
        for worker in self._workers:
            worker.join(5.0)
        self._listener.close()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            worker = threading.Thread(target=self._serve, args=(conn, self.connections), daemon=True)
            self.connections += 1
            self._workers.append(worker)
            worker.start()

    def _serve(self, conn: socket.socket, number: int) -> None:
        with conn:
            conn.settimeout(5.0)
            try:
                read_request(conn)
                self._answer(conn, number)
            except OSError:  # the client hung up first: it gave up on the try
                pass


def read_request(conn: socket.socket) -> None:
    """Read one HTTP request, its head and its Content-Length body, off the connection."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            return
        body += chunk


def http_200(body: dict) -> tuple[bytes, bytes]:
    """The head and the body of a complete HTTP/1.1 200 answer carrying `body` as JSON."""
    data = json.dumps(body).encode()
    head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(data)
    return head, data


def trickle(conn: socket.socket, data: bytes) -> None:
    """Send `data` a byte every 50 ms: each wait for bytes is short, the whole answer is not."""
    for byte in data:
        conn.sendall(bytes([byte]))
        time.sleep(0.05)


# ------------------------------------------------------------------ the request


def test_the_body_holds_the_model_the_messages_and_the_session_id_and_nothing_unasked():
    with FakeModelServer([text_reply("hello")]) as server:
        call(server.base_url, tools=[])
        (request,) = server.requests
    # exact: no provider object (it would switch off sticky routing), no tools, no tool_choice,
    # no max_tokens or temperature
    assert request["json"] == {"model": "fake/model", "messages": MESSAGES, "session_id": SESSION}
    assert request["path"] == "/v1/chat/completions"


def test_tools_are_sent_with_tool_choice_auto_and_still_no_provider():
    with FakeModelServer([text_reply("hello")]) as server:
        call(server.base_url, tools=[SHELL])
        body = server.requests[0]["json"]
    assert body["tools"] == [SHELL]
    assert body["tool_choice"] == "auto"
    assert "provider" not in body
    assert body["session_id"] == SESSION


def test_max_tokens_and_temperature_are_sent_when_given_even_a_zero_temperature():
    with FakeModelServer([text_reply("hello")]) as server:
        call(server.base_url, max_tokens=512, temperature=0.0)
        body = server.requests[0]["json"]
    assert body["max_tokens"] == 512
    assert "temperature" in body and body["temperature"] == 0.0


def test_the_key_goes_in_the_authorization_header_only_and_only_when_there_is_one():
    with FakeModelServer([text_reply("a"), text_reply("b")]) as server:
        call(server.base_url, key=KEY)
        call(server.base_url, key=None)
        with_key, without_key = server.requests
    assert with_key["headers"]["authorization"] == f"Bearer {KEY}"
    assert "authorization" not in without_key["headers"]
    for request in (with_key, without_key):
        assert request["headers"]["x-title"] == "ctf-flightdeck"
        assert request["headers"]["content-type"] == "application/json"
        assert KEY not in json.dumps(request["json"])


def test_the_app_name_is_sent_as_x_title():
    with FakeModelServer([text_reply("a")]) as server:
        call(server.base_url, app_name="practice-run")
    assert server.requests[0]["headers"]["x-title"] == "practice-run"


@pytest.mark.parametrize("suffix", ["", "/"])
def test_a_base_url_with_or_without_a_trailing_slash_reaches_chat_completions(suffix):
    with FakeModelServer([text_reply("a")]) as server:
        assert call(server.base_url + suffix).content == "a"
    assert [r["path"] for r in server.requests] == ["/v1/chat/completions"]


def test_a_session_id_over_256_characters_is_refused_before_anything_is_sent():
    with FakeModelServer([text_reply("a")]) as server:
        with pytest.raises(ValueError, match="session_id"):
            call(server.base_url, session_id="s" * 257)
        with pytest.raises(ValueError, match="session_id"):
            call(server.base_url, session_id="")
        assert server.requests == []
        call(server.base_url, session_id="s" * 256)
    assert server.requests[0]["json"]["session_id"] == "s" * 256


@pytest.mark.parametrize("base_url", ["openrouter.ai/api/v1", "ftp://example.test/v1", "http://"])
def test_a_base_url_that_is_not_an_http_url_is_refused(base_url):
    with pytest.raises(ValueError, match="base_url"):
        ModelClient(base_url, None)


@pytest.mark.parametrize("bad", ["", f"{KEY} {KEY}", f"{KEY}\n", f"{KEY}é"], ids=["empty", "space", "newline", "non-ascii"])
def test_a_key_no_header_can_carry_is_refused_without_showing_it(bad):
    with pytest.raises(ValueError, match="API key") as info:
        ModelClient("http://127.0.0.1:9/v1", bad)
    assert KEY not in str(info.value)


def test_a_closed_client_refuses_to_call():
    async def run() -> None:
        client = ModelClient("http://127.0.0.1:9/v1", None)
        await client.aclose()
        await client.chat("fake/model", MESSAGES, [], session_id=SESSION)

    with pytest.raises(RuntimeError, match="closed"):
        asyncio.run(run())


@pytest.mark.parametrize("how", ["aclose", "async with"])
def test_closing_the_client_closes_its_connection_pool(how):
    transport = CountingTransport()

    async def run() -> None:
        if how == "aclose":
            client = ModelClient(server.base_url, None, transport=transport)
            await client.chat("fake/model", MESSAGES, [], session_id=SESSION)
            assert not transport.closed
            await client.aclose()
        else:
            async with ModelClient(server.base_url, None, transport=transport) as client:
                await client.chat("fake/model", MESSAGES, [], session_id=SESSION)
                assert not transport.closed

    with FakeModelServer([text_reply("a")]) as server:
        asyncio.run(run())
    assert transport.closed


def test_a_client_built_with_the_defaults_has_the_documented_timeout_retries_and_backoff():
    client = ModelClient("http://127.0.0.1:9/v1", None)
    try:
        assert (client.timeout, client.max_retries, client.backoff) == (180.0, 4, 1.0)
    finally:
        asyncio.run(client.aclose())


def test_lanes_can_share_one_client_at_the_same_time():
    def echo_session(request: dict) -> dict:
        return text_reply(f"for {request['json']['session_id']}")

    async def run() -> list[Reply]:
        async with ModelClient(server.base_url, None) as client:
            return await asyncio.gather(
                *(client.chat("fake/model", MESSAGES, [], session_id=f"lane-{n}") for n in range(4))
            )

    with FakeModelServer(responder=echo_session) as server:
        replies = asyncio.run(run())
    assert [r.content for r in replies] == [f"for lane-{n}" for n in range(4)]


# ------------------------------------------------------------------ the reply


def test_a_text_reply_gives_its_content_finish_reason_model_and_message():
    with FakeModelServer([text_reply("Hello, player.", model="vendor/answering-model")]) as server:
        reply = call(server.base_url)
    assert reply.content == "Hello, player."
    assert reply.tool_calls == ()
    assert reply.finish_reason == "stop"
    assert reply.model == "vendor/answering-model"
    assert reply.message == {"role": "assistant", "content": "Hello, player."}


def test_several_tool_calls_come_back_in_order_with_the_message_for_the_history():
    calls = [("shell", {"command": "ls -la"}), ("read_file", {"path": "notes.txt"})]
    with FakeModelServer([tool_calls_reply(calls)]) as server:
        reply = call(server.base_url, tools=[SHELL])
    assert reply.tool_calls == (
        ToolCall("call_1", "shell", '{"command": "ls -la"}'),
        ToolCall("call_2", "read_file", '{"path": "notes.txt"}'),
    )
    assert reply.content == ""  # the message's content was null
    assert reply.finish_reason == "tool_calls"
    assert reply.message["role"] == "assistant"
    assert reply.message["content"] is None  # as returned
    assert [c["id"] for c in reply.message["tool_calls"]] == ["call_1", "call_2"]
    assert reply.message["tool_calls"][1]["function"] == {"name": "read_file", "arguments": '{"path": "notes.txt"}'}


def test_arguments_that_are_not_valid_json_are_kept_exactly_as_sent():
    broken = '{"command": "ls -la'
    with FakeModelServer([tool_call_reply("shell", broken, call_id="call_x", content="Listing.")]) as server:
        reply = call(server.base_url, tools=[SHELL])
    assert reply.tool_calls == (ToolCall("call_x", "shell", broken),)
    assert reply.content == "Listing."


def test_usage_carries_prompt_completion_and_cached_tokens_and_the_reported_cost():
    body = text_reply("ok", prompt_tokens=5000, completion_tokens=300, cached_tokens=4096, cost=0.00123)
    with FakeModelServer([body]) as server:
        usage = call(server.base_url).usage
    assert usage == Usage(prompt_tokens=5000, completion_tokens=300, cached_tokens=4096, cost=0.00123)
    assert usage.total == 5300


def test_a_reported_cost_of_zero_stays_zero_rather_than_unknown():
    with FakeModelServer([text_reply("ok", cost=0)]) as server:
        cost = call(server.base_url).usage.cost
    assert cost == 0.0 and cost is not None


def test_missing_usage_counts_as_no_tokens_and_an_unknown_cost():
    no_usage = text_reply("ok")
    del no_usage["usage"]
    bare_usage = text_reply("ok")
    bare_usage["usage"] = {"prompt_tokens": 10, "completion_tokens": 2}
    with FakeModelServer([no_usage, bare_usage]) as server:
        first = call(server.base_url).usage
        second = call(server.base_url).usage
    assert first == Usage(0, 0, 0, None)
    assert second == Usage(10, 2, 0, None)


def test_the_history_message_keeps_what_the_api_sent_but_always_as_the_assistant():
    sent = {
        "role": "system",  # a server must not be able to plant a system message in the history
        "content": "ok",
        "reasoning_details": [{"type": "reasoning.encrypted", "data": "opaque"}],
    }
    with FakeModelServer([reply_with_message(sent)]) as server:
        reply = call(server.base_url)
    assert reply.message == {**sent, "role": "assistant"}


def test_a_tool_call_without_an_id_gets_a_fresh_one_that_the_history_shares():
    body = tool_calls_reply([("shell", {"command": "id"}), ("shell", {"command": "pwd"})])
    for entry in body["choices"][0]["message"]["tool_calls"]:
        del entry["id"]
    with FakeModelServer([body]) as server:
        reply = call(server.base_url)
    ids = [c.id for c in reply.tool_calls]
    assert all(ids) and len(set(ids)) == 2
    assert [entry["id"] for entry in reply.message["tool_calls"]] == ids


def test_arguments_sent_as_an_object_become_json_text_in_the_call_and_the_history():
    body = tool_call_reply("shell", "{}")
    body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = {"command": "id"}
    with FakeModelServer([body]) as server:
        reply = call(server.base_url)
    (tool_call,) = reply.tool_calls
    assert json.loads(tool_call.arguments) == {"command": "id"}
    assert reply.message["tool_calls"][0]["function"]["arguments"] == tool_call.arguments


def test_content_sent_as_parts_is_joined_into_text():
    parts = [
        {"type": "text", "text": "Hello, "},
        {"type": "thinking", "thinking": "not for the player"},
        {"type": "text", "text": "player."},
    ]
    with FakeModelServer([reply_with_message({"role": "assistant", "content": parts})]) as server:
        assert call(server.base_url).content == "Hello, player."


# ------------------------------------------------------------------ failures


@pytest.mark.parametrize(
    "body, says",
    [
        ({"error": {"message": "Provider returned error", "code": 502}}, "Provider returned error"),
        ({"id": "chatcmpl-1", "object": "chat.completion"}, "without choices"),
        ({"choices": []}, "without choices"),
        ({"choices": [{"index": 0, "finish_reason": "stop"}]}, "without a message"),
        ({"choices": [{"index": 0, "error": {"message": "upstream died"}}]}, "upstream died"),
        ("[1, 2, 3]", "not a JSON object"),
        (
            {"choices": [{"message": {"role": "assistant", "tool_calls": [{"id": "c1", "function": "shell"}]}}]},
            "tool call",
        ),
    ],
    ids=["error-object", "no-choices", "empty-choices", "no-message", "choice-error", "not-an-object", "bad-tool-call"],
)
def test_a_2xx_reply_that_is_an_error_or_makes_no_sense_fails_at_once(body, says):
    with FakeModelServer([FakeReply(200, body), text_reply("never sent")]) as server:
        err = fails(server.base_url)
        assert len(server.requests) == 1
    assert says in str(err)
    assert err.status == 200 and err.retryable is False


def test_an_error_field_that_is_null_or_empty_is_no_error():
    null_error, empty_error = text_reply("fine"), text_reply("also fine")
    null_error["error"] = None
    empty_error["error"] = {}
    with FakeModelServer([null_error, empty_error]) as server:
        assert call(server.base_url).content == "fine"
        assert call(server.base_url).content == "also fine"


def test_a_transport_error_a_retry_cannot_fix_fails_at_once():
    # a body that claims to be gzip but is not: httpx cannot decode it, and never will
    lying = FakeReply(200, "plain text", {"Content-Encoding": "gzip"})
    with FakeModelServer([lying, lying, lying]) as server:
        err = fails(server.base_url, max_retries=2)
        assert len(server.requests) == 1
    assert err.retryable is False and err.status is None
    assert "DecodingError" in str(err)


def test_a_reply_that_is_not_json_fails_with_a_safe_snippet_of_it():
    with FakeModelServer([FakeReply(200, "<html>\x1b[31mBad Gateway</html>")]) as server:
        err = fails(server.base_url)
    assert "not JSON" in str(err) and "Bad Gateway" in str(err)
    assert "\x1b" not in str(err)


# valid JSON, but nested far deeper than Python's parser can follow (it raises RecursionError)
DEEP = '{"error": ' + "[" * 200_000 + "]" * 200_000 + "}"


@pytest.mark.parametrize("status", [200, 400])
def test_a_body_nested_too_deep_to_parse_fails_at_once_as_a_model_error(status):
    with FakeModelServer([FakeReply(status, DEEP), text_reply("never sent")]) as server:
        err = fails(server.base_url)
        assert len(server.requests) == 1
    assert err.status == status and err.retryable is False


@pytest.mark.parametrize("number", ["NaN", "Infinity", "-Infinity", "1e400"])
def test_a_reply_holding_a_number_json_cannot_carry_is_refused_before_it_reaches_the_history(number):
    # Python's parser takes these (1e400 becomes infinity), but a message holding one could
    # never be sent back: the next request's body would fail to encode
    message = '{"role": "assistant", "content": "thinking", "logprobs": %s}' % number
    raw = '{"choices": [{"message": %s, "finish_reason": "stop"}], "model": "fake/model"}' % message
    with FakeModelServer([FakeReply(200, raw), text_reply("never sent")]) as server:
        err = fails(server.base_url)
        assert len(server.requests) == 1
    assert "not JSON" in str(err)
    assert err.status == 200 and err.retryable is False


@pytest.mark.parametrize("status", [400, 401, 403, 404, 413, 422])
def test_any_other_failing_status_fails_at_once_with_the_servers_message(status):
    with FakeModelServer([error_reply(status, "you sent something wrong"), text_reply("never sent")]) as server:
        err = fails(server.base_url)
        assert len(server.requests) == 1
    assert err.status == status and err.retryable is False
    assert "you sent something wrong" in str(err)


def test_the_servers_error_text_is_made_safe_and_cut_to_300_characters():
    # right-to-left override and pop, zero-width space, left-to-right isolate and pop
    invisible = "\u202e\u202c\u200b\u2066\u2069"
    message = "line one\nline two \x1b]0;title\x07 \u202edesrever\u202c zero\u200bwidth \u2066isolated\u2069 " + "A" * 1000
    with FakeModelServer([error_reply(400, message)]) as server:
        err = fails(server.base_url)
    text = str(err)
    assert "\n" not in text and "\x1b" not in text and "\x07" not in text
    assert not any(ch in text for ch in invisible)
    assert text.count("\ufffd") == len(invisible)  # each one shows as a mark, as text.untrusted() makes it
    servers_part = text.split(": ", 1)[1]
    assert servers_part.startswith("line one")
    assert len(servers_part) <= 300


def test_a_redirect_is_not_followed():
    with FakeModelServer([FakeReply(307, None, {"Location": "/v1/elsewhere"})]) as server:
        err = fails(server.base_url, key=KEY)
        assert len(server.requests) == 1  # following it would have sent the key on a second request
    assert err.status == 307 and err.retryable is False


# ------------------------------------------------------------------ retries


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503, 504])
def test_a_status_that_means_not_now_is_tried_again(status):
    with FakeModelServer([error_reply(status, "not now"), text_reply("now")]) as server:
        assert call(server.base_url).content == "now"
        assert len(server.requests) == 2


def test_a_429_whose_body_is_nested_too_deep_to_parse_is_still_tried_again():
    with FakeModelServer([FakeReply(429, DEEP), text_reply("now")]) as server:
        assert call(server.base_url).content == "now"
        assert len(server.requests) == 2


def test_when_every_try_fails_the_error_is_retryable_and_names_the_last_status():
    replies = [error_reply(429, "slow down"), error_reply(503, "overloaded"), text_reply("one try too many")]
    with FakeModelServer(replies) as server:
        err = fails(server.base_url, max_retries=1)
        assert len(server.requests) == 2
    assert err.status == 503 and err.retryable is True
    assert "HTTP 503" in str(err) and "overloaded" in str(err) and "2 tries" in str(err)
    assert "slow down" not in str(err)


def test_when_the_last_try_gets_no_answer_the_error_has_no_status_though_an_earlier_one_did():
    def too_slow(request: dict) -> dict:
        time.sleep(0.6)  # past the client's timeout
        return text_reply("too late")

    with FakeModelServer([error_reply(502, "bad gateway")], responder=too_slow) as server:
        err = fails(server.base_url, timeout=0.25, max_retries=1)
        assert len(server.requests) == 2
    assert err.status is None and err.retryable is True
    assert "bad gateway" not in str(err)


def test_no_retries_means_one_try():
    with FakeModelServer([error_reply(429, "slow down"), text_reply("never sent")]) as server:
        err = fails(server.base_url, max_retries=0)
        assert len(server.requests) == 1
    assert err.status == 429 and err.retryable is True


def test_a_client_built_with_the_defaults_makes_five_tries():
    busy = error_reply(500, "busy", headers={"Retry-After": "0"})  # no wait, whatever the backoff

    async def run() -> None:
        async with ModelClient(server.base_url, None) as client:
            await client.chat("fake/model", MESSAGES, [], session_id=SESSION)

    with FakeModelServer([busy] * 5 + [text_reply("one try too many")]) as server:
        with pytest.raises(ModelError) as info:
            asyncio.run(run())
        assert len(server.requests) == 5
    assert info.value.retryable is True and "5 tries" in str(info.value)


def test_a_retry_after_header_sets_the_wait_instead_of_the_backoff():
    # Retry-After: 0 must cut a 5-second backoff to nothing...
    with FakeModelServer([error_reply(429, "slow down", headers={"Retry-After": "0"}), text_reply("ok")]) as server:
        start = time.monotonic()
        assert call(server.base_url, backoff=5.0).content == "ok"
        assert time.monotonic() - start < 3.0
    # ...and Retry-After: 0.3 must stretch a 1-millisecond one.
    with FakeModelServer([error_reply(503, "busy", headers={"Retry-After": "0.3"}), text_reply("ok")]) as server:
        start = time.monotonic()
        assert call(server.base_url, backoff=0.001).content == "ok"
        assert time.monotonic() - start >= 0.3


def gaps(times: list[float]) -> list[float]:
    return [later - earlier for earlier, later in itertools.pairwise(times)]


def test_the_waits_between_tries_double_from_the_backoff_and_none_follows_the_last():
    arrivals: list[float] = []

    def failing(request: dict) -> FakeReply:
        arrivals.append(time.monotonic())
        return error_reply(500, "upstream exploded")

    with FakeModelServer(responder=failing) as server:
        err = fails(server.base_url, max_retries=2, backoff=0.2)
        ended = time.monotonic()
    assert len(arrivals) == 3
    first, second = gaps(arrivals)
    assert first >= 0.2 and second >= 0.4  # doubling from the backoff (a steady 0.2 s fails)
    assert first + second < 1.0  # not from twice the backoff, which waits 0.4 + 0.8 s
    assert ended - arrivals[-1] < 0.5  # no wait after the last try (it would be 0.8 s)
    assert err.status == 500 and err.retryable is True


def test_a_try_that_times_out_is_tried_again():
    count = itertools.count()

    def slow_first(request: dict) -> dict:
        if next(count) == 0:
            time.sleep(0.5)
        return text_reply("on the second try")

    with FakeModelServer(responder=slow_first) as server:
        reply = call(server.base_url, timeout=0.2, max_retries=1)
        assert len(server.requests) == 2
    assert reply.content == "on the second try"


def test_an_answer_that_trickles_in_is_given_up_on_when_the_try_runs_out_of_time():
    # httpx's own timeouts bound each wait for bytes, and every byte here comes in 50 ms;
    # only a deadline on the whole try stops the first answer, which would take over 10 s
    def first_trickles(conn: socket.socket, number: int) -> None:
        head, data = http_200(text_reply("too late" if number == 0 else "on the second try"))
        conn.sendall(head)
        if number == 0:
            trickle(conn, data)
        else:
            conn.sendall(data)

    with RawServer(first_trickles) as server:
        start = time.monotonic()
        reply = call(server.base_url, timeout=0.3, max_retries=1)
        elapsed = time.monotonic() - start
    assert reply.content == "on the second try"
    assert server.connections == 2
    assert elapsed < 2.0


def test_when_the_last_try_runs_out_of_time_the_error_says_so_and_is_retryable():
    def trickles(conn: socket.socket, number: int) -> None:
        head, data = http_200(text_reply("too late"))
        conn.sendall(head)  # a status line came, but no complete answer
        trickle(conn, data)

    with RawServer(trickles) as server:
        start = time.monotonic()
        err = fails(server.base_url, key=KEY, timeout=0.25, max_retries=0)
        elapsed = time.monotonic() - start
    assert err.status is None and err.retryable is True
    assert "timed out after 0.25 s" in str(err) and KEY not in str(err)
    assert err.__cause__ is None and err.__context__ is None
    assert 0.25 <= elapsed < 0.45  # the deadline is the timeout itself, not a multiple of it


def test_a_refused_connection_is_tried_again_after_the_same_waits_then_fails_as_retryable():
    transport = CountingTransport()
    err = fails(f"http://127.0.0.1:{closed_port()}/v1", max_retries=2, backoff=0.2, transport=transport)
    ended = time.monotonic()
    assert transport.sent == 3
    first, second = gaps(transport.times)
    assert first >= 0.2 and second >= 0.4  # a transport error waits as a failing status does
    assert first + second < 1.0
    assert ended - transport.times[-1] < 0.5
    assert err.status is None and err.retryable is True
    assert "no answer from the model API" in str(err) and "3 tries" in str(err)


def hang_up(conn: socket.socket, number: int) -> None:
    """Answer nothing: the request was read, so closing sends a plain FIN."""


def reset(conn: socket.socket, number: int) -> None:
    """Answer nothing, and make closing send a TCP reset instead of a FIN."""
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


@pytest.mark.parametrize(
    "drop, error", [(hang_up, "RemoteProtocolError"), (reset, "ReadError")], ids=["hang-up", "reset"]
)
def test_a_connection_dropped_before_the_answer_is_tried_again_then_fails_as_retryable(drop, error):
    with RawServer(drop) as server:
        err = fails(server.base_url, key=KEY, max_retries=2)
    assert server.connections == 3
    assert err.status is None and err.retryable is True
    assert error in str(err) and "3 tries" in str(err)
    assert KEY not in str(err)


def test_the_wait_doubles_from_the_backoff_and_stops_at_30_seconds():
    assert MAX_WAIT == 30.0
    assert [retry_delay(n, 0.5) for n in range(8)] == [0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0]
    assert retry_delay(10_000, 1.0) == 30.0


def test_a_numeric_retry_after_wins_over_the_backoff_and_is_capped_too():
    assert retry_delay(3, 1.0, "2") == 2.0
    assert retry_delay(3, 1.0, "0") == 0.0
    assert retry_delay(0, 1.0, " 1.5 ") == 1.5
    assert retry_delay(0, 1.0, "3600") == 30.0


@pytest.mark.parametrize("value", ["Wed, 21 Oct 2015 07:28:00 GMT", "-1", "soon", "", "inf", "nan"])
def test_a_retry_after_that_is_not_a_number_of_seconds_leaves_the_backoff(value):
    assert retry_delay(2, 1.0, value) == 4.0


# ------------------------------------------------------------------ the key stays secret

ECHO = f"invalid key {KEY}"  # a server that repeats the key back in its error text


@pytest.mark.parametrize(
    "replies",
    [
        [error_reply(401, ECHO)],
        [FakeReply(200, f"<html>{ECHO}</html>")],
        [error_reply(429, ECHO)] * 3,
        [FakeReply(200, {"error": {"message": ECHO, "code": 502}})],
    ],
    ids=["401", "not-json", "429-every-try", "error-in-200"],
)
def test_an_error_never_shows_the_key_even_when_the_server_echoes_it(replies):
    with FakeModelServer(replies) as server:
        err = fails(server.base_url, key=KEY, max_retries=2)
    assert KEY not in str(err) and KEY not in repr(err)
    assert "invalid key [key]" in str(err)  # the echo was there, and the key was cut out of it


def test_an_error_chains_nothing_that_holds_the_request_or_the_servers_raw_text():
    # an httpx error holds the request (and its Authorization header); a parse error holds
    # the server's text before the key was cut out of it
    unreachable = fails(f"http://127.0.0.1:{closed_port()}/v1", key=KEY, max_retries=0)
    replies = [FakeReply(200, f"not json {ECHO}"), FakeReply(200, {"error": {"message": ECHO}})]
    with FakeModelServer(replies) as server:
        garbled = fails(server.base_url, key=KEY)
        reported = fails(server.base_url, key=KEY)
    for err in (unreachable, garbled, reported):
        assert err.__cause__ is None and err.__context__ is None


def test_the_clients_repr_names_the_endpoint_but_never_the_key():
    client = ModelClient("https://user:pw@api.example.test/v1/?tag=1", KEY)
    try:
        for text in (repr(client), str(client)):
            assert KEY not in text and "pw" not in text and "tag" not in text
            assert "https://api.example.test/v1/chat/completions" in text
    finally:
        asyncio.run(client.aclose())


# ------------------------------------------------------------------ the fake server itself


def post(server: FakeModelServer, path: str = "/chat/completions", **kwargs) -> httpx.Response:
    return httpx.post(server.base_url + path, json={"model": "m"}, **kwargs)


def test_the_fake_server_records_the_path_lower_case_headers_and_json():
    with FakeModelServer([text_reply("x")]) as server:
        post(server, headers={"X-Probe": "Yes"})
    (record,) = server.requests
    assert record["path"] == "/v1/chat/completions"
    assert record["headers"]["x-probe"] == "Yes"
    assert record["json"] == {"model": "m"}


def test_the_fake_server_takes_scripted_replies_first_then_asks_the_responder():
    asked: list[dict] = []

    def responder(request: dict) -> dict:
        asked.append(request)
        return text_reply("from the responder")

    with FakeModelServer([text_reply("scripted")], responder=responder) as server:
        server.add(error_reply(503, "added later"))
        answers = [post(server) for _ in range(3)]
    assert answers[0].json()["choices"][0]["message"]["content"] == "scripted"
    assert answers[1].status_code == 503 and answers[1].json()["error"]["message"] == "added later"
    assert answers[2].json()["choices"][0]["message"]["content"] == "from the responder"
    assert asked == [server.requests[2]]


def test_the_fake_server_answers_500_when_it_runs_out_of_replies():
    with FakeModelServer([text_reply("only one")]) as server:
        first, second = post(server), post(server)
    assert first.status_code == 200
    assert second.status_code == 500 and "out of scripted replies" in second.json()["error"]["message"]


def test_the_fake_server_answers_404_off_the_chat_path_and_keeps_the_reply():
    with FakeModelServer([text_reply("kept")]) as server:
        miss = post(server, "/completions")
        hit = post(server)
    assert miss.status_code == 404
    assert hit.json()["choices"][0]["message"]["content"] == "kept"


def test_the_fake_server_sends_a_str_body_raw_and_its_headers():
    with FakeModelServer([FakeReply(429, "not json at all", {"Retry-After": "7"})]) as server:
        answer = post(server)
    assert answer.status_code == 429
    assert answer.text == "not json at all"
    assert answer.headers["retry-after"] == "7"


def test_the_fake_server_stops_at_once_while_a_client_keeps_its_connection_open():
    with httpx.Client() as keeps_alive:
        with FakeModelServer([text_reply("x")]) as server:
            keeps_alive.post(server.base_url + "/chat/completions", json={})
            start = time.monotonic()
        assert time.monotonic() - start < 2.0


def test_leaving_the_fake_server_waits_for_a_request_still_being_answered():
    def slow(request: dict) -> dict:
        time.sleep(0.3)
        return text_reply("late")

    def send(server: FakeModelServer) -> None:
        try:
            post(server)
        except httpx.HTTPError:
            pass  # the server hangs up on it while leaving

    with FakeModelServer(responder=slow) as server:
        sender = threading.Thread(target=send, args=(server,))
        sender.start()
        deadline = time.monotonic() + 5.0
        while not server.requests and time.monotonic() < deadline:
            time.sleep(0.01)
        assert server.requests, "the request never arrived"
    still_answering = [t for t in threading.enumerate() if t.name == "fake-model-request"]
    sender.join()
    assert still_answering == []


def test_the_reply_builders_make_complete_chat_completion_bodies():
    body = tool_call_reply(
        "shell",
        {"command": "ls"},
        call_id="call_9",
        content="Looking.",
        prompt_tokens=7,
        completion_tokens=3,
        cached_tokens=5,
        cost=0.5,
        model="vendor/m",
    )
    assert body["object"] == "chat.completion" and body["id"] and body["model"] == "vendor/m"
    (choice,) = body["choices"]
    assert choice["finish_reason"] == "tool_calls"
    assert choice["message"] == {
        "role": "assistant",
        "content": "Looking.",
        "tool_calls": [
            {"id": "call_9", "type": "function", "function": {"name": "shell", "arguments": '{"command": "ls"}'}}
        ],
    }
    assert body["usage"] == {
        "prompt_tokens": 7,
        "completion_tokens": 3,
        "total_tokens": 10,
        "prompt_tokens_details": {"cached_tokens": 5},
        "cost": 0.5,
    }
    plain = text_reply("hi")
    assert plain["choices"][0]["finish_reason"] == "stop"
    assert plain["choices"][0]["message"] == {"role": "assistant", "content": "hi"}
    assert "cost" not in plain["usage"] and plain["usage"]["prompt_tokens_details"] == {"cached_tokens": 0}
