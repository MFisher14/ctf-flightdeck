"""The Anthropic effort of each ladder model ([api] effort), from the config to a lane's request.

Through the real SDK to the fake Anthropic server, which refuses an output_config.effort where
the real API would (a model that takes none, a level that model does not take), from its own
copy of Anthropic's table: a request flightdeck builds wrong fails here too. No test calls the
real API, and no key here is real.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from ctf_flightdeck.agent.anthropic_client import EFFORT_LEVELS, AnthropicClient
from ctf_flightdeck.agent.client import ModelClient, ModelError
from ctf_flightdeck.agent.fallback import FallbackClient, build_client, client_for
from ctf_flightdeck.agent.refusal import FALLBACK_TARGETS
from ctf_flightdeck.config import ConfigError, example_config, load_config
from fake_anthropic import EFFORTS, FakeAnthropicServer, error, text_message, tool_message
from fake_model import FakeModelServer, text_reply

KEY = "test-anthropic-key-6Hd2-not-real"  # synthetic
SPARE_KEY = "test-openrouter-key-9Kp4-not-real"  # synthetic
MESSAGES = [{"role": "system", "content": "You are a test lane."}, {"role": "user", "content": "Read the note."}]
LADDER = '[models]\nladder = ["claude-haiku-5-5", "claude-opus-5-5"]\n'


def write(tmp_path, api: str, models: str = LADDER, rest: str = ""):
    path = tmp_path / "config.toml"
    path.write_text(f"[api]\n{api}\n{models}{rest}")
    return path


def anthropic(effort: str, base_url: str = "http://127.0.0.1:9") -> str:
    return f'provider = "anthropic"\nbase_url = "{base_url}"\neffort = {effort}'


async def _chats(client, *models: str) -> None:
    try:
        for i, model in enumerate(models):
            await client.chat(model, list(MESSAGES), [], session_id=f"lane-{i}")
    finally:
        await client.aclose()


# ---------------------------------------------------------------------- the config


def test_the_config_takes_an_effort_per_ladder_model_and_none_by_default(tmp_path):
    config = load_config(write(tmp_path, anthropic('{ "claude-opus-5-5" = "high", "claude-haiku-5-5" = "low" }')))
    assert config.api.effort == (("claude-opus-5-5", "high"), ("claude-haiku-5-5", "low"))
    assert load_config(write(tmp_path, 'provider = "anthropic"')).api.effort == ()


PASTED = "pasted-into-the-wrong-place-not-real"  # synthetic: what an error must never show


@pytest.mark.parametrize("api, models, says", [
    (anthropic('"high"'), LADDER,
     'api.effort must be a table of a model id from models.ladder and its effort level, as in '
     'effort = { "claude-opus-5-5" = "high" } (got a string)'),
    ('effort = { "claude-opus-5-5" = "high" }', LADDER,  # the default provider: an OpenAI-compatible API
     'api.effort is output_config.effort, a feature of the Anthropic Messages API: it needs [api] provider = "anthropic"'),
    (anthropic('{ "claude-sonnet-5-5" = "high" }'), LADDER,
     "api.effort.claude-sonnet-5-5 is not for a model in models.ladder: effort is set per ladder model"),
    (anthropic(f'{{ "claude-opus-5-5" = "high", "{PASTED}" = "high" }}'), LADDER,
     "api.effort (entry 2) is not for a model in models.ladder: effort is set per ladder model"),
    (anthropic('{ "claude-haiku-4-5" = "low" }'), '[models]\nladder = ["claude-haiku-4-5", "claude-opus-5-5"]\n',
     "api.effort (entry 1) names a model that takes no effort (output_config.effort): Anthropic documents it for "
     "claude-fable-5, "),
    (anthropic('{ "claude-opus-5-5" = "highest" }'), LADDER,
     "api.effort.claude-opus-5-5 must be one of low, medium, high, xhigh, max: the effort levels that model takes"),
    (anthropic(f'{{ "claude-opus-5-5" = "{PASTED}" }}'), LADDER,
     "api.effort.claude-opus-5-5 must be one of low, medium, high, xhigh, max: the effort levels that model takes"),
    (anthropic('{ "claude-sonnet-4-6" = "xhigh" }'), '[models]\nladder = ["claude-sonnet-4-6"]\n',
     "api.effort.claude-sonnet-4-6 must be one of low, medium, high, max: the effort levels that model takes"),
    (anthropic('{ "claude-opus-4-5" = "max" }'), '[models]\nladder = ["claude-opus-4-5"]\n',
     "api.effort.claude-opus-4-5 must be one of low, medium, high: the effort levels that model takes"),
    (anthropic('{ "claude-opus-5-5" = 3 }'), LADDER,
     "api.effort.claude-opus-5-5 must be an effort level, a string (got 3)"),
])
def test_a_bad_effort_is_an_error_that_names_the_key_and_shows_no_pasted_string(tmp_path, api, models, says):
    with pytest.raises(ConfigError) as caught:
        load_config(write(tmp_path, api, models))
    assert says in str(caught.value)
    assert PASTED not in str(caught.value)


def test_the_example_shows_the_effort_line_and_it_loads_once_uncommented(tmp_path):
    text = example_config()
    line = '# effort = { "claude-opus-5-5" = "high" }'
    assert line in text
    assert "A model with\n# no entry is sent none and runs at Anthropic's default for it" in text
    filled = (text.replace(line, line[2:]).replace('provider = "openai"', 'provider = "anthropic"')
              .replace('base_url = "https://openrouter.ai/api/v1"\n', "").replace('key_env = "OPENROUTER_API_KEY"\n', "")
              .replace("ladder = []", 'ladder = ["claude-haiku-5-5", "claude-opus-5-5"]'))
    path = tmp_path / "config.toml"
    path.write_text(filled)
    assert load_config(path).api.effort == (("claude-opus-5-5", "high"),)


# ---------------------------------------------------------------------- the request


def test_the_lanes_client_sends_each_models_effort_and_none_for_a_model_with_no_entry(tmp_path):
    with FakeAnthropicServer([text_message("a"), text_message("b")]) as server:
        config = load_config(write(tmp_path, anthropic('{ "claude-opus-5-5" = "xhigh" }', server.base_url)))
        asyncio.run(_chats(build_client(config, KEY, None), "claude-opus-5-5", "claude-haiku-5-5"))
        opus, haiku = (r["json"] for r in server.requests)
    assert opus["output_config"] == {"effort": "xhigh"}
    assert "output_config" not in haiku  # no entry: none sent, the model's own default


def test_the_client_refuses_an_effort_the_api_would_refuse_and_the_fake_api_refuses_it_too():
    for efforts, says in (({"claude-haiku-4-5": "low"}, "efforts: the entry for 'claude-haiku-4-5' names a model that takes no effort"),
                          ({"claude-sonnet-4-6": "xhigh"}, "must be one of low, medium, high, max")):
        with pytest.raises(ValueError) as caught:
            AnthropicClient("http://127.0.0.1:9", KEY, efforts=efforts)
        assert says in str(caught.value)
    assert EFFORTS == EFFORT_LEVELS  # the fake's own copy of Anthropic's table and flightdeck's say the same
    with FakeAnthropicServer([text_message("never sent")]) as server:
        # the light role's client-wide effort is not checked per level: the fake answers as the API would
        client = AnthropicClient(server.base_url, KEY, effort="xhigh", max_retries=0)
        with pytest.raises(ModelError, match="output_config.effort: Input should be one of low, medium, high, max"):
            asyncio.run(_chats(client, "claude-sonnet-4-6"))


def test_an_openai_compatible_api_takes_no_effort():
    with pytest.raises(ValueError, match="effort \\(output_config.effort\\) is a feature of the Anthropic Messages API"):
        client_for("openai", "http://127.0.0.1:9/v1", None, efforts={"claude-opus-5-5": "high"})


# ---------------------------------------------------------------------- the two edges


def test_every_model_the_refusal_fallback_answers_with_takes_the_levels_of_the_model_it_answers_for():
    """The server-side refusal fallback runs the same request again on another model, effort
    and all: a level that model refused would turn a rescue into an error."""
    assert FALLBACK_TARGETS  # something to check
    for model, targets in FALLBACK_TARGETS.items():
        for target in targets:
            assert set(EFFORT_LEVELS[model]) <= set(EFFORT_LEVELS[target]), (model, target)


def test_a_lane_that_moves_to_the_fallback_api_is_sent_no_effort_there_and_its_notice_says_so(tmp_path):
    overloaded = error(529, "overloaded_error", "Overloaded")
    with FakeAnthropicServer([overloaded, overloaded]) as claude, FakeModelServer([text_reply("from openrouter"), text_reply("again")]) as router:
        primary = AnthropicClient(claude.base_url, KEY, max_retries=0, efforts={"claude-opus-5-5": "high"})
        client = FallbackClient(primary, ModelClient(router.base_url, SPARE_KEY, max_retries=0),
                                {"claude-opus-5-5": "anthropic/claude-opus-5.5", "claude-haiku-5-5": "anthropic/claude-haiku-5.5"},
                                primary_name="Anthropic", fallback_name="OpenRouter", efforts={"claude-opus-5-5": "high"})

        async def run():
            try:
                return (await client.chat("claude-opus-5-5", list(MESSAGES), [], session_id="lane-1"),
                        await client.chat("claude-haiku-5-5", list(MESSAGES), [], session_id="lane-2"))
            finally:
                await client.aclose()

        opus, haiku = asyncio.run(run())
        assert claude.requests[0]["json"]["output_config"] == {"effort": "high"}
        for request in router.requests:
            assert "output_config" not in request["json"] and "reasoning_effort" not in request["json"]
    assert opus.notice.startswith(
        "moved to OpenRouter (anthropic/claude-opus-5.5) for the rest of this context (without [api] effort high, "
        "which is for Anthropic only): Anthropic failed: ")
    assert haiku.notice.startswith(  # no effort set for it: nothing to say
        "moved to OpenRouter (anthropic/claude-haiku-5.5) for the rest of this context: Anthropic failed: ")


def test_build_client_gives_the_fallback_client_the_efforts_and_the_fallback_api_none(tmp_path):
    config = load_config(write(
        tmp_path, anthropic('{ "claude-opus-5-5" = "high" }'),
        rest='[fallback]\nprovider = "anthropic"\nbase_url = "http://127.0.0.1:9"\nkey_env = "FLIGHTDECK_TEST_SPARE"\n'
             'ladder = ["claude-haiku-5-5", "claude-opus-5-5"]\n',
    ))
    client = build_client(config, KEY, SPARE_KEY)
    try:
        assert isinstance(client, FallbackClient)
        assert client.efforts == {"claude-opus-5-5": "high"} == client.primary.efforts
        assert client.fallback.efforts == {}  # even an Anthropic fallback: [api] effort is for [api]
    finally:
        asyncio.run(client.aclose())


# ---------------------------------------------------------------------- a lane, in a run


def test_a_run_names_its_efforts_and_every_call_of_a_lane_carries_its_models_effort(tmp_path, monkeypatch):
    from ctf_flightdeck.run import RunOptions, prepare_run

    monkeypatch.setenv("FLIGHTDECK_TEST_ANTHROPIC_KEY", KEY)
    root = tmp_path / "board"
    (root / "note").mkdir(parents=True)
    (root / "note" / "note.txt").write_text("nothing here\n")
    (root / "note" / "challenge.json").write_text(json.dumps({"name": "Note", "category": "misc", "points": 50,
                                                              "description": "Read the note."}))
    (root / "board.json").write_text(json.dumps({"event": "Effort Test", "flag_format": r"t\{[a-z0-9_]+\}"}))

    def responder(record):
        return tool_message("shell", {"command": "ls"}, model=record["json"]["model"])

    with FakeAnthropicServer(responder=responder) as server:
        path = write(
            tmp_path,
            anthropic('{ "claude-opus-5-5" = "high" }', server.base_url) + '\nkey_env = "FLIGHTDECK_TEST_ANTHROPIC_KEY"',
            rest=f'[lanes]\nruntime = "host"\nmax_lanes = 1\ndollar_cap = false\ntoken_cap = false\n[run]\ndir = "{tmp_path / "runs"}"\n',
        )
        run = prepare_run(RunOptions(board=root, config=path, model="claude-opus-5-5"))
        assert "effort: claude-opus-5-5 at high (any other ladder model runs at Anthropic's default for it)" in run.notes()

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
        sent = [r["json"] for r in server.requests if r["path"] == "/v1/messages"]
    assert lane.turns >= 2 and len(sent) >= 2
    assert {body["model"] for body in sent} == {"claude-opus-5-5"}
    assert all(body["output_config"] == {"effort": "high"} for body in sent)
