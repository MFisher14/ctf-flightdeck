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


def roles(request: dict) -> list[str]:
    return [m["role"] for m in request["json"]["messages"]]


DROPPED = "left out messages of this context"


def run_lane(tmp_path: Path, replies: list[dict], *, compact_at: int | None = COMPACT_AT):
    """One lane on `replies` (the last submits a flag): the requests the lanes model got, what the
    lane's transcript says, and the driver's `fits`."""
    lanes = FakeModelServer(replies + [tool_call_reply("submit_flag", {"flag": "t{note}"})])
    seen = {}

    async def main():
        with lanes:
            lab = Lab(tmp_path, lanes, {"c1": handout(tmp_path, "c1", {"note.txt": "hi\n"})}, compact_at=compact_at)
            lab.release(challenge("c1"))
            lane = lab.lane("c1")
            await until(lambda: lane.pending is not None, "the candidate flag")
            seen.update(sent=[roles(chat) for chat in lanes.chats()], texts=[a.text for a in lane.actions],
                        fits=dict(lab.driver.fits))
            await lab.finish()

    asyncio.run(main())
    return seen["sent"], seen["texts"], seen["fits"]


def shell(n: int, tokens: int, model: str = "fake/model") -> dict:
    return tool_call_reply("shell", {"command": f"echo {n}"}, prompt_tokens=tokens, model=model)


def test_a_lane_whose_server_drops_messages_is_refreshed_at_once_and_from_then_on_sooner(tmp_path):
    """No [api] context, so the refresh point is the driver's 50,000, and the server's count
    stops growing at about 28,300 while the context grows, as Ollama 0.34.2's did past its
    32,768-token default (docs/MODELS.md): the lane is refreshed after the first call that
    counted no more than the one before, the player is told once what to set, and the lane's
    next context on that model is refreshed when it reaches the 28,300 where the drop was seen."""
    sent, texts, fits = run_lane(tmp_path, [
        shell(1, 23_600),
        shell(2, 28_300),
        shell(3, 28_290),  # the context grew by a turn, yet the server counted less: it dropped messages
        shell(4, 12_000),  # the first call of a fresh context: not judged against the old one
        shell(5, 28_300),  # under the driver's 50,000, but the count where the drop was seen
    ])
    assert sent[2] == ["system", "user"] + ["assistant", "tool"] * 2  # the call the server dropped from
    assert sent[3] == ["system", "user", "user"]  # fresh, with the summary, right after it
    assert sent[4] == ["system", "user", "user", "assistant", "tool"]  # 12,000: not refreshed
    assert sent[5] == ["system", "user", "user"]  # refreshed at 28,300
    assert fits == {"small": 28_300}
    assert len([t for t in texts if DROPPED in t]) == 1, texts
    assert len([t for t in texts if "OLLAMA_CONTEXT_LENGTH=65536" in t]) == 1, texts
    assert any("context refreshed at 28,290 prompt tokens" in t for t in texts), texts
    assert any("context refreshed at 28,300 prompt tokens" in t for t in texts), texts


def test_a_second_drop_on_the_same_model_is_said_without_the_hint_and_lowers_the_refresh_point(tmp_path):
    """The hint to set OLLAMA_CONTEXT_LENGTH comes the first time for each model, not on every
    drop; and a later drop at a smaller count lowers the model's refresh point to it."""
    sent, texts, fits = run_lane(tmp_path, [
        shell(1, 23_600),
        shell(2, 28_300),
        shell(3, 28_290),  # the first drop: fits 28,300, refreshed at once
        shell(4, 12_000),  # a fresh context: not judged
        shell(5, 20_000),  # under 28,300: not refreshed
        shell(6, 19_000),  # the second drop, at a smaller count: fits 20,000, refreshed at once
        shell(7, 12_000),  # a fresh context: not judged
        shell(8, 20_000),  # under 28,300, but at the lowered point: refreshed
    ])
    assert fits == {"small": 20_000}
    assert len([t for t in texts if DROPPED in t]) == 2, texts
    assert len([t for t in texts if "OLLAMA_CONTEXT_LENGTH=65536" in t]) == 1, texts
    assert sent[5] == ["system", "user", "user"] + ["assistant", "tool"] * 2  # grown, not refreshed at 20,000
    assert sent[6] == ["system", "user", "user"]  # fresh after the second drop
    assert sent[8] == ["system", "user", "user"]  # refreshed at the lowered 20,000
    assert any("context refreshed at 19,000 prompt tokens" in t for t in texts), texts
    assert any("context refreshed at 20,000 prompt tokens" in t for t in texts), texts


@pytest.mark.parametrize("replies", [
    [shell(1, 20_000), shell(2, 20_500)],  # the count grew with the context: nothing dropped
    [shell(1, 900), shell(2, 900)],  # too small to be a lane's request (a fake's): not judged
    [shell(1, 20_000, "fake/a"), shell(2, 15_000, "fake/b")],  # another model answered: its count is its own
])
def test_a_count_that_is_not_a_drop_leaves_the_lane_in_its_context(replies, tmp_path):
    sent, texts, fits = run_lane(tmp_path, replies)
    assert sent[2] == ["system", "user"] + ["assistant", "tool"] * 2  # the same context, grown
    assert fits == {}
    assert not [t for t in texts if DROPPED in t or "context refreshed" in t], texts


def test_a_run_that_never_refreshes_says_the_server_dropped_messages_and_goes_on(tmp_path):
    sent, texts, fits = run_lane(tmp_path, [shell(1, 28_300), shell(2, 28_300)], compact_at=None)
    assert sent[2] == ["system", "user"] + ["assistant", "tool"] * 2  # not refreshed
    assert any(DROPPED in t and "never refreshes a lane" in t for t in texts), texts
    assert not [t for t in texts if "context refreshed" in t], texts


CRAMPED = "is too small for a lane"


def test_a_server_context_a_fresh_context_nearly_fills_is_said_once_and_not_refreshed_into(tmp_path):
    """Ollama at its 4,096-token default: the drop is seen at 3,900 and the lane is refreshed,
    but its fresh context alone counts 3,500 of them. Refreshing at 3,900 from then on would
    replace the context on nearly every call, so the model never saw a tool's output: the lane
    goes on in its context instead, and the player is told once that the server's is too small."""
    sent, texts, fits = run_lane(tmp_path, [
        shell(1, 3_000),
        shell(2, 3_900),
        shell(3, 3_890),  # the drop: fits 3,900, refreshed at once
        shell(4, 3_500),  # the first call of the fresh context: it takes 3,500 of the 3,900
        shell(5, 3_950),  # past 3,900: not refreshed, told why
        shell(6, 3_940),  # another drop: not said again, not refreshed
        shell(7, 3_960),
    ])
    assert fits == {"small": 3_900}
    assert sent[3] == ["system", "user", "user"]  # the refresh after the drop
    assert sent[5] == ["system", "user", "user"] + ["assistant", "tool"] * 2  # grown, not refreshed at 3,950
    assert sent[7] == ["system", "user", "user"] + ["assistant", "tool"] * 4  # nor after the second drop
    assert len([t for t in texts if DROPPED in t]) == 1, texts
    told = [t for t in texts if CRAMPED in t]
    assert len(told) == 1 and "takes 3,500 of them" in told[0] and "from 3,900 prompt tokens on" in told[0], texts
    assert len([t for t in texts if "context refreshed" in t]) == 1, texts


def test_a_fresh_context_with_room_under_the_point_is_still_refreshed_at_it(tmp_path):
    """The other side of the line: a fresh context of 2,900 leaves a quarter of the 3,900 free,
    so the lane is refreshed there as before, and nothing says the server is too small."""
    sent, texts, fits = run_lane(tmp_path, [
        shell(1, 3_000),
        shell(2, 3_900),
        shell(3, 3_890),  # the drop: refreshed at once
        shell(4, 2_900),  # the fresh context takes under three quarters of 3,900
        shell(5, 3_950),  # refreshed
    ])
    assert sent[5] == ["system", "user", "user"]
    assert not [t for t in texts if CRAMPED in t], texts
