"""A lane's calls to a model server: the reply cap ([api] max_tokens) and the time one try may
take ([api] timeout), from the config to the request.

Servers are the fakes on 127.0.0.1 (fake_model.py, fake_anthropic.py); an API anywhere else is
only named in a config, never contacted.
"""

from __future__ import annotations

import asyncio
import itertools
import json
import re
import time
from pathlib import Path

import pytest

from ctf_flightdeck.agent.anthropic_client import DEFAULT_MAX_TOKENS, AnthropicClient
from ctf_flightdeck.agent.client import DEFAULT_TIMEOUT, ModelClient
from ctf_flightdeck.agent.fallback import FallbackClient, build_client
from ctf_flightdeck.config import (
    LOCAL_MAX_TOKENS,
    ConfigError,
    example_config,
    lane_max_tokens,
    load_config,
)
from fake_anthropic import FakeAnthropicServer
from fake_anthropic import text_message as claude_says
from fake_model import FakeModelServer, error_reply, text_reply, tool_call_reply

LADDER = '[models]\nladder = ["m/small", "m/big"]\n'
LOCAL = "http://127.0.0.1:11434/v1"
SENTINEL = "zqSentinelValue4471"  # a string value no error may show: it could be a key pasted in the wrong place
KEY = "test-anthropic-key-4Rk8-not-real"  # synthetic, for the fake Anthropic server
MESSAGES = [{"role": "system", "content": "You are a test lane."}, {"role": "user", "content": "Read the note."}]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    """No FLIGHTDECK_CONFIG from the player's shell, and a home directory of our own."""
    monkeypatch.delenv("FLIGHTDECK_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def write(tmp_path: Path, text: str, name: str = "config.toml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def error(path: Path) -> str:
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    return str(caught.value)


# ---------------------------------------------------------------------- the config


def test_api_and_fallback_each_take_a_timeout_and_a_reply_cap(tmp_path):
    text = (f'[api]\nbase_url = "{LOCAL}"\nkey_env = ""\ntimeout = 600\nmax_tokens = 4096\n' + LADDER
            + '[fallback]\nladder = ["a/1", "a/2"]\ntimeout = 90.5\nmax_tokens = 2048\n')
    config = load_config(write(tmp_path, text))
    assert (config.api.timeout, config.api.max_tokens) == (600.0, 4096)
    assert isinstance(config.api.timeout, float)
    assert (config.fallback.timeout, config.fallback.max_tokens) == (90.5, 2048)
    unset = load_config(write(tmp_path, LADDER + '[fallback]\nladder = ["a/1", "a/2"]\n'))
    assert (unset.api.timeout, unset.api.max_tokens, unset.fallback.timeout, unset.fallback.max_tokens) == (None,) * 4


BAD = {
    "max_tokens zero": ("[api]\nmax_tokens = 0\n", "api.max_tokens", "(got 0)"),
    "max_tokens negative": ("[api]\nmax_tokens = -8\n", "api.max_tokens", "(got -8)"),
    "max_tokens a fraction": ("[api]\nmax_tokens = 512.5\n", "api.max_tokens", "(got 512.5)"),
    "max_tokens a string": ('[api]\nmax_tokens = "8192"\n', "api.max_tokens", "(got a string)"),
    "max_tokens true": ("[api]\nmax_tokens = true\n", "api.max_tokens", "(got true)"),
    "max_tokens over a million": ("[api]\nmax_tokens = 1000001\n", "api.max_tokens", "(got 1000001)"),
    "timeout zero": ("[api]\ntimeout = 0\n", "api.timeout", "(got 0)"),
    "timeout negative": ("[api]\ntimeout = -1.5\n", "api.timeout", "(got -1.5)"),
    "timeout nan": ("[api]\ntimeout = nan\n", "api.timeout", "(got nan)"),
    "timeout infinite": ("[api]\ntimeout = inf\n", "api.timeout", "(got inf)"),
    "timeout over an hour": ("[api]\ntimeout = 3601\n", "api.timeout", "(got 3601)"),
    "timeout a string": ('[api]\ntimeout = "600"\n', "api.timeout", "(got a string)"),
    "timeout true": ("[api]\ntimeout = true\n", "api.timeout", "(got true)"),
    "timeout a huge whole number": ("[api]\ntimeout = " + "9" * 400 + "\n", "api.timeout", "must be a number of seconds"),
    "fallback max_tokens": ('[fallback]\nladder = ["a/1", "a/2"]\nmax_tokens = 0\n', "fallback.max_tokens", "(got 0)"),
    "fallback timeout": ('[fallback]\nladder = ["a/1", "a/2"]\ntimeout = -3\n', "fallback.timeout", "(got -3)"),
}


@pytest.mark.parametrize("table, key, got", BAD.values(), ids=BAD.keys())
def test_a_bad_timeout_or_reply_cap_is_an_error_naming_the_file_and_the_key(tmp_path, table, key, got):
    path = write(tmp_path, LADDER + table)
    message = error(path)
    assert message.startswith(f"{path}: {key} "), message
    assert got in message


def test_the_errors_say_what_is_wanted(tmp_path):
    assert "must be a whole number of tokens from 1 to 1000000" in error(write(tmp_path, LADDER + "[api]\nmax_tokens = 0\n"))
    assert "must be a number of seconds above 0 and at most 3600" in error(write(tmp_path, LADDER + "[api]\ntimeout = 0\n"))


@pytest.mark.parametrize("table, key", [
    (f'[api]\nmax_tokens = "{SENTINEL}"\n', "api.max_tokens"),
    (f'[api]\ntimeout = "{SENTINEL}"\n', "api.timeout"),
    (f'[fallback]\nladder = ["a/1", "a/2"]\ntimeout = "{SENTINEL}"\n', "fallback.timeout"),
])
def test_the_errors_never_show_a_string_value(tmp_path, table, key):
    message = error(write(tmp_path, LADDER + table))
    assert key in message and SENTINEL not in message


@pytest.mark.parametrize("url", ["http://127.0.0.1:11434/v1", "http://localhost:8080/v1", "http://[::1]:8000/v1"])
def test_a_server_on_this_machine_gets_8192_unless_the_config_says_otherwise(url):
    assert lane_max_tokens("openai", url, None) == LOCAL_MAX_TOKENS == 8192
    assert lane_max_tokens("openai", url, 1024) == 1024


@pytest.mark.parametrize("url", ["https://openrouter.ai/api/v1", "https://api.openai.com/v1", "http://10.0.0.5:11434/v1"])
def test_any_other_openai_compatible_api_gets_no_reply_cap_unless_the_config_sets_one(url):
    assert lane_max_tokens("openai", url, None) is None  # OpenAI's reasoning models refuse max_tokens
    assert lane_max_tokens("openai", url, 4096) == 4096


def test_the_anthropic_api_keeps_its_clients_own_cap_unless_the_config_sets_one():
    assert lane_max_tokens("anthropic", "https://api.anthropic.com", None) is None
    assert lane_max_tokens("anthropic", "http://127.0.0.1:9999", None) is None  # even a proxy on this machine
    assert lane_max_tokens("anthropic", "https://api.anthropic.com", 32000) == 32000


def test_the_example_says_what_the_keys_do_and_its_lines_load_once_uncommented(tmp_path):
    text = example_config()
    prose = " ".join(line.lstrip("#").strip() for line in text.splitlines())
    for words in ("OpenAI's own API refuses max_tokens on its reasoning models", "mlx_lm.server's own default is 512",
                  "`flightdeck init` writes 600 for a server on this machine", "Default 180, or 600 with provider"):
        assert words in prose, words
    filled = text.replace("ladder = []", 'ladder = ["vendor/small-model", "vendor/big-model"]')
    filled, n = re.subn(r"^# (timeout = 180|max_tokens = 8192)$", r"\1", filled, flags=re.M)
    assert n == 2
    config = load_config(write(tmp_path, filled))
    assert (config.api.timeout, config.api.max_tokens) == (180.0, 8192)


# ---------------------------------------------------------------------- a lane's calls


def lanes_config(tmp_path: Path, api: str, extra: str = "") -> Path:
    return write(tmp_path, f"[api]\n{api}\n" + LADDER + extra)


def chat(client, *, max_tokens: int | None = None, session_id: str = "lane-1"):
    """One call as a lane's driver makes it (no max_tokens of its own), then the client closed."""

    async def run():
        try:
            return await client.chat("m/small", list(MESSAGES), [], session_id=session_id, max_tokens=max_tokens)
        finally:
            await client.aclose()

    return asyncio.run(run())


def test_a_lane_call_to_a_server_on_this_machine_asks_for_at_most_8192_tokens(tmp_path):
    with FakeModelServer([text_reply("ok")]) as server:
        client = build_client(load_config(lanes_config(tmp_path, f'base_url = "{server.base_url}"\nkey_env = ""')), None, None)
        chat(client)
        (request,) = server.chats()
    assert request["json"]["max_tokens"] == 8192


def test_the_configured_cap_is_sent_and_a_calls_own_cap_still_wins(tmp_path):
    with FakeModelServer([text_reply("ok"), text_reply("ok")]) as server:
        path = lanes_config(tmp_path, f'base_url = "{server.base_url}"\nkey_env = ""\nmax_tokens = 2048')
        chat(build_client(load_config(path), None, None))
        chat(build_client(load_config(path), None, None), max_tokens=256)  # the light role gives its own
        first, second = server.chats()
    assert (first["json"]["max_tokens"], second["json"]["max_tokens"]) == (2048, 256)


def test_an_api_elsewhere_gets_no_cap_unless_the_config_sets_one(tmp_path):
    openrouter = 'base_url = "https://openrouter.ai/api/v1"\nkey_env = ""'
    plain = build_client(load_config(lanes_config(tmp_path, openrouter)), None, None)
    capped = build_client(load_config(lanes_config(tmp_path, openrouter + "\nmax_tokens = 4096")), None, None)
    assert isinstance(plain, ModelClient) and plain.max_tokens is None  # never contacted here
    assert capped.max_tokens == 4096
    for client in (plain, capped):
        asyncio.run(client.aclose())
    with FakeModelServer([text_reply("ok")]) as server:  # a client with no cap sends none
        chat(ModelClient(server.base_url, None, max_tokens=None))
        assert "max_tokens" not in server.chats()[0]["json"]


def test_each_api_has_its_own_cap_and_timeout(tmp_path):
    spare = ('[fallback]\nbase_url = "https://openrouter.ai/api/v1"\nkey_env = ""\nladder = ["a/1", "a/2"]\n'
             "max_tokens = 1000\ntimeout = 45\n")
    both = build_client(load_config(lanes_config(tmp_path, f'base_url = "{LOCAL}"\nkey_env = ""\ntimeout = 300', spare)),
                        None, None)
    assert isinstance(both, FallbackClient)
    assert (both.primary.max_tokens, both.primary.timeout) == (8192, 300.0)
    assert (both.fallback.max_tokens, both.fallback.timeout) == (1000, 45.0)
    asyncio.run(both.aclose())
    bare = spare.replace("max_tokens = 1000\ntimeout = 45\n", "")
    unset = build_client(load_config(lanes_config(tmp_path, f'base_url = "{LOCAL}"\nkey_env = ""', bare)), None, None)
    assert (unset.primary.timeout, unset.fallback.timeout, unset.fallback.max_tokens) == (DEFAULT_TIMEOUT, 180.0, None)
    asyncio.run(unset.aclose())


def test_a_call_that_moves_to_the_fallback_gets_the_fallbacks_own_cap():
    with FakeModelServer([error_reply(503, "busy")]) as first, FakeModelServer([text_reply("from the fallback")]) as second:
        primary = ModelClient(first.base_url, None, max_retries=0, max_tokens=8192)
        fallback = ModelClient(second.base_url, None, max_retries=0, max_tokens=1000)
        pair = FallbackClient(primary, fallback, {"m/small": "a/1"}, primary_name="here", fallback_name="there")
        reply = chat(pair)
        assert reply.content == "from the fallback"
        assert first.chats()[0]["json"]["max_tokens"] == 8192 and second.chats()[0]["json"]["max_tokens"] == 1000


def anthropic_config(tmp_path: Path, url: str, extra: str = "") -> Path:
    return write(tmp_path, f'[api]\nprovider = "anthropic"\nbase_url = "{url}"\n{extra}\n'
                           '[models]\nladder = ["claude-haiku-5-5"]\n')


def test_the_anthropic_client_sends_its_own_cap_even_on_this_machine_unless_the_config_sets_one(tmp_path):
    with FakeAnthropicServer([claude_says("ok"), claude_says("ok")]) as server:
        chat(build_client(load_config(anthropic_config(tmp_path, server.base_url)), KEY, None))
        chat(build_client(load_config(anthropic_config(tmp_path, server.base_url, "max_tokens = 3000")), KEY, None))
        own, configured = (r["json"] for r in server.requests)
    assert own["max_tokens"] == DEFAULT_MAX_TOKENS == 16_000
    assert configured["max_tokens"] == 3000


def slow_first(reply_late, reply_in_time):
    """A responder whose first answer takes 2 s; the ones after it come at once. A reply that
    is not the first proves the first try was given up before its answer came."""
    count = itertools.count()

    def answer(request: dict):
        if next(count) == 0:
            time.sleep(2.0)
            return reply_late
        return reply_in_time

    return answer


def test_the_configured_timeout_bounds_each_try_of_a_lane_call(tmp_path):
    with FakeModelServer(responder=slow_first(text_reply("too late"), text_reply("in time"))) as server:
        api = f'base_url = "{server.base_url}"\nkey_env = ""\ntimeout = 0.5'
        client = build_client(load_config(lanes_config(tmp_path, api)), None, None)
        assert client.timeout == 0.5
        reply = chat(client)  # the first try is given up at 0.5 s, and a retry answers
        assert reply.content == "in time" and len(server.chats()) >= 2
    default = build_client(load_config(lanes_config(tmp_path, f'base_url = "{LOCAL}"\nkey_env = ""')), None, None)
    assert default.timeout == DEFAULT_TIMEOUT == 180.0 and default.max_retries == 4  # the retries are as before
    asyncio.run(default.aclose())


def test_the_configured_timeout_bounds_each_try_of_an_anthropic_call(tmp_path):
    with FakeAnthropicServer(responder=slow_first(claude_says("too late"), claude_says("in time"))) as server:
        client = build_client(load_config(anthropic_config(tmp_path, server.base_url, "timeout = 0.5")), KEY, None)
        assert isinstance(client, AnthropicClient) and client.timeout == 0.5
        reply = chat(client)
        assert reply.content == "in time" and len(server.requests) >= 2
    default = build_client(load_config(anthropic_config(tmp_path, "https://api.anthropic.com")), KEY, None)
    assert default.timeout == 600.0  # the Anthropic client's own, unchanged
    asyncio.run(default.aclose())


def test_a_lane_in_a_run_asks_a_server_on_this_machine_for_at_most_8192_tokens_every_turn(tmp_path):
    from ctf_flightdeck.run import RunOptions, prepare_run

    root = tmp_path / "board"
    (root / "note").mkdir(parents=True)
    (root / "note" / "note.txt").write_text("nothing here\n")
    (root / "note" / "challenge.json").write_text(json.dumps({"name": "Note", "category": "misc", "points": 50}))
    (root / "board.json").write_text(json.dumps({"event": "Limits", "flag_format": r"t\{[a-z]+\}"}))
    with FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "ls"})) as server:
        path = write(tmp_path, f'[api]\nbase_url = "{server.base_url}"\nkey_env = ""\n' + LADDER
                     + '[lanes]\nmax_lanes = 1\nruntime = "host"\ntoken_cap = false\ndollar_cap = false\n'
                     + f'[run]\ndir = "{tmp_path / "runs"}"\n')
        run = prepare_run(RunOptions(board=root, config=path))

        async def main():
            run.release()
            for _ in range(2000):
                if len(server.chats()) >= 3:
                    break
                await asyncio.sleep(0.01)
            await run.shutdown()

        asyncio.run(main())
        run.close()
        # a call cut off by the shutdown can reach the server without its body: not a call that was made
        asked = [request["json"]["max_tokens"] for request in server.chats() if request["json"]]
    assert len(asked) >= 3 and set(asked) == {8192}


def test_a_client_refuses_a_cap_that_is_not_a_positive_whole_number():
    for bad in (0, -1, True, 2.5):
        with pytest.raises(ValueError, match="max_tokens must be a positive whole number"):
            ModelClient(LOCAL, None, max_tokens=bad)
        with pytest.raises(ValueError, match="max_tokens must be a positive whole number"):
            AnthropicClient("https://api.anthropic.com", KEY, max_tokens=bad)


def test_extra_body_adds_a_servers_own_fields_to_every_request_and_never_the_clients_own():
    fields = {"reasoning_effort": "none", "chat_template_kwargs": {"enable_thinking": False}}
    with FakeModelServer([text_reply("ok")]) as server:
        client = ModelClient(server.base_url, None, max_retries=0, extra_body=fields)
        fields["chat_template_kwargs"]["enable_thinking"] = True  # the client keeps a copy of its own
        chat(client, max_tokens=64)
        body = server.chats()[0]["json"]
    assert body["reasoning_effort"] == "none" and body["chat_template_kwargs"] == {"enable_thinking": False}
    assert (body["model"], body["max_tokens"], body["session_id"]) == ("m/small", 64, "lane-1")
    for taken in ("model", "messages", "max_tokens", "tools", "session_id", "provider"):
        with pytest.raises(ValueError, match=f"extra_body may not set {taken}"):
            ModelClient(LOCAL, None, extra_body={taken: 1})
    with pytest.raises(ValueError, match="extra_body must be JSON"):
        ModelClient(LOCAL, None, extra_body={"x": float("nan")})
