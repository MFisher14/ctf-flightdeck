"""[api] context and [fallback] context: the context a lane's server gives its model, and the
refresh point it sets (config.lane_refresh_at, the driver's compact_at): a lane continues in a
fresh context with a summary before it outgrows a server that would drop its oldest messages.

The run and the lane are flightdeck's own (prepare_run, the agent driver) against a fake model
server on 127.0.0.1 (fake_model.py) and host workspaces under tmp_path; no real model is called."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fake_model import FakeModelServer, tool_call_reply
from light_kit import Lab, challenge, handout, until

from ctf_flightdeck.agent.driver import COMPACT_AT
from ctf_flightdeck.config import ConfigError, lane_refresh_at, parse_config, refresh_point
from ctf_flightdeck.run import RunOptions, prepare_run

OLLAMA = "http://127.0.0.1:11434/v1"


def config_text(api: str = "", fallback: str = "", *, base_url: str = OLLAMA, provider: str = "openai",
                key_env: str = "") -> str:
    text = (f'[api]\nprovider = "{provider}"\nbase_url = "{base_url}"\nkey_env = "{key_env}"\n{api}'
            '[models]\nladder = ["small", "big"]\n')
    if fallback:
        text += f'[fallback]\nbase_url = "http://127.0.0.1:8080/v1"\nkey_env = ""\nladder = ["s", "b"]\n{fallback}'
    return text


def refresh_at(text: str, tmp_path: Path) -> int:
    return lane_refresh_at(parse_config(text, tmp_path / "config.toml"), COMPACT_AT)


@pytest.mark.parametrize(("api", "fallback", "expected"), [
    ("", "", 50_000),  # no context stated: the driver's own refresh point (COMPACT_AT)
    ("context = 32768\n", "", 16_384),  # Ollama's default from 23 GiB: two replies of up to 8192 less
    ("context = 65536\n", "", 49_152),  # OLLAMA_CONTEXT_LENGTH=65536
    ("context = 262144\n", "", 50_000),  # a larger context never refreshes later than the default
    ("context = 32768\nmax_tokens = 4096\n", "", 24_576),  # a smaller reply cap leaves less room to keep
    ("context = 65536\n", "context = 32768\n", 16_384),  # a lane can move to the fallback: the smaller wins
    ("", "context = 24576\n", 8_192),  # the least a context may leave a lane: MIN_REFRESH
])
def test_a_stated_context_sets_the_point_a_lane_is_refreshed_at(api, fallback, expected, tmp_path):
    assert refresh_at(config_text(api, fallback), tmp_path) == expected


def test_the_anthropic_api_leaves_room_for_its_own_default_reply(tmp_path):
    """The Anthropic client sends 16000 as max_tokens unless [api] sets one."""
    text = config_text("context = 48000\n", base_url="https://api.anthropic.com", provider="anthropic",
                       key_env="ANTHROPIC_API_KEY")
    assert refresh_at(text, tmp_path) == 48_000 - 2 * 16_000 == refresh_point(48_000, 16_000)


@pytest.mark.parametrize(("api", "fallback", "message"), [
    ("context = 4096\n", "", "api.context leaves a lane too little room: it is refreshed 16384 tokens before the context "
                             "ends, room for two replies of up to 8192 (the default reply cap), and a context under 24576 "
                             "tokens leaves it less than 8192. Give the server a longer context (Ollama: "
                             "OLLAMA_CONTEXT_LENGTH=65536, then restart it) and set this to it (got 4096)"),
    ("context = 24575\n", "", "(got 24575)"),
    ("context = 20000\nmax_tokens = 8192\n", "", "room for two replies of up to 8192 (api.max_tokens)"),
    ("", "context = 4096\n", "fallback.context leaves a lane too little room"),
    ("context = 0\n", "", "api.context must be a whole number of tokens from 1 to 10000000"),
    ("context = 32768.5\n", "", "api.context must be a whole number of tokens from 1 to 10000000"),
    ("context = 20000000\n", "", "(got 20000000)"),
    ("context = true\n", "", "(got true)"),
    ('context = "65536"\n', "", "(got a string)"),
])
def test_a_context_a_lane_cannot_work_in_is_refused_with_its_value(api, fallback, message, tmp_path):
    with pytest.raises(ConfigError) as caught:
        parse_config(config_text(api, fallback), tmp_path / "config.toml")
    assert message in str(caught.value), str(caught.value)


def test_a_context_for_an_api_elsewhere_needs_its_reply_cap_stated_too(tmp_path):
    """flightdeck sends no max_tokens to an OpenAI-compatible API on another host, so the reply's
    length is that server's, and no room can be kept for it without [api] max_tokens."""
    elsewhere = config_text("context = 131072\n", base_url="https://models.example.test/v1", key_env="EXAMPLE_KEY")
    with pytest.raises(ConfigError, match=r"api\.context needs api\.max_tokens too"):
        parse_config(elsewhere, tmp_path / "config.toml")
    capped = config_text("context = 131072\nmax_tokens = 16384\n", base_url="https://models.example.test/v1",
                         key_env="EXAMPLE_KEY")
    assert refresh_at(capped, tmp_path) == 50_000


def test_a_run_gives_its_lanes_the_refresh_point_its_config_states(tmp_path):
    board = handout(tmp_path, "note", {"note.txt": "hello\n"}).parent
    (board / "note" / "challenge.json").write_text('{"name": "Note", "category": "misc", "points": 50, "solves": 1, '
                                                   '"description": "Read the note."}')
    (board / "board.json").write_text('{"event": "Test", "flag_format": "t\\\\{[a-z0-9_]+\\\\}"}')
    with FakeModelServer() as server:
        for context, expected in (("", COMPACT_AT), ("context = 32768\n", 16_384)):
            path = tmp_path / "config.toml"
            path.write_text(config_text(context, base_url=server.base_url)
                            + f'[lanes]\nruntime = "host"\n[run]\ndir = "{tmp_path / "runs"}"\n')
            run = prepare_run(RunOptions(board=board, config=path))
            try:
                assert run.driver.compact_at == expected
            finally:
                run.close()


def test_a_lane_on_a_32768_token_server_is_refreshed_at_16384_prompt_tokens_and_not_before(tmp_path):
    """The point the config sets, as the driver keeps it: a call whose prompt reached 16,383
    tokens goes on in the same context; the next, at 16,384, is followed by a fresh one."""
    point = refresh_at(config_text("context = 32768\n"), tmp_path)
    assert point == 16_384
    lanes = FakeModelServer([
        tool_call_reply("shell", {"command": "echo one"}, prompt_tokens=point - 1),
        tool_call_reply("shell", {"command": "echo two"}, prompt_tokens=point),
        tool_call_reply("submit_flag", {"flag": "t{note}"}),
    ])

    async def main():
        with lanes:
            lab = Lab(tmp_path, lanes, {"c1": handout(tmp_path, "c1", {"note.txt": "hi\n"})}, compact_at=point)
            lab.release(challenge("c1"))
            lane = lab.lane("c1")
            await until(lambda: lane.pending is not None, "the candidate flag")
            second, third = lanes.chats()[1]["json"], lanes.chats()[2]["json"]
            assert [m["role"] for m in second["messages"]] == ["system", "user", "assistant", "tool"]  # not refreshed
            assert [m["role"] for m in third["messages"]] == ["system", "user", "user"]  # fresh, with the summary
            assert any("context refreshed at 16,384 prompt tokens" in a.text for a in lane.actions)
            await lab.finish()

    asyncio.run(main())
