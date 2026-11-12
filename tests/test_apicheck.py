"""The model API check before a run (apicheck.py): the key, the ladder's models, the server.

Against the fake OpenAI-compatible server (tests/fake_model.py) and the fake Anthropic API
(tests/fake_anthropic.py, through the real SDK), both on 127.0.0.1. The keys are synthetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_flightdeck.apicheck import Api, CheckFailed, check, key_url, listed_models, missing

from fake_anthropic import FakeAnthropicServer
from fake_model import FakeModelServer, FakeReply

KEY = "fake-model-key-for-the-check-0001"
SOURCE = Path("/home/player/.config/ctf-flightdeck/config.toml")


def openai_api(base_url: str, ladder: tuple[str, ...], *, key: str | None = KEY, key_env: str = "MY_MODEL_KEY",
               table: str = "api") -> Api:
    return Api(table, "openai", base_url, key, key_env if key is not None else "", ladder)


def anthropic_api(base_url: str, ladder: tuple[str, ...], *, key: str = KEY) -> Api:
    return Api("api", "anthropic", base_url, key, "MY_CLAUDE_KEY", ladder)


# ---------------------------------------------------------------------- an OpenAI-style API


def test_a_ladder_model_the_server_does_not_list_stops_the_run_with_the_closest_ids():
    with FakeModelServer(models=["qwen2.5-coder:7b", "llama3:latest"]) as server:
        with pytest.raises(CheckFailed) as caught:
            check(openai_api(server.base_url, ("llama3", "qwen2.5-coder-7b"), key=None), source=SOURCE)
    assert str(caught.value) == (
        f"the model API at {server.base_url} does not serve qwen2.5-coder-7b (closest it lists: qwen2.5-coder:7b), so "
        f"every lane on it would fail at its first call: change models.ladder in {SOURCE} to ids it serves (or pull the "
        "model into your server), then start again"
    )  # llama3 is llama3:latest


def test_a_ladder_the_server_lists_passes_with_no_note_and_sends_the_key():
    with FakeModelServer(models=["fake/small", "fake/big"], key=KEY) as server:
        assert check(openai_api(server.base_url, ("fake/small", "fake/big"))) == []
    (request,) = server.requests
    assert request["path"] == "/v1/models" and request["headers"]["authorization"] == f"Bearer {KEY}"


def test_a_key_the_api_refuses_stops_the_run_naming_its_variable_never_the_key():
    wrong = "fake-wrong-key-never-shown-0002"
    with FakeModelServer(models=["m"], key=KEY) as server:
        with pytest.raises(CheckFailed) as caught:
            check(openai_api(server.base_url, ("m",), key=wrong), source=SOURCE)
        with pytest.raises(CheckFailed) as none:
            check(openai_api(server.base_url, ("m",), key=None), source=SOURCE)
    said = str(caught.value)
    assert said.startswith(f"the model API at {server.base_url} refused the key in MY_MODEL_KEY (HTTP 401: fake model "
                           "server: no valid key in the request): put the right key in MY_MODEL_KEY")
    assert wrong not in said
    assert str(none.value).startswith(f"the model API at {server.base_url} wants a key (HTTP 401: fake model server: no "
                                      f"valid key in the request): name the variable that holds it in api.key_env in {SOURCE}")


def test_nothing_answering_on_this_machine_stops_the_run_and_says_to_start_the_server():
    with pytest.raises(CheckFailed) as caught:
        check(openai_api("http://127.0.0.1:9/v1", ("m",), key=None), source=SOURCE)
    said = str(caught.value)
    assert said.startswith("nothing answers at http://127.0.0.1:9/v1 (ConnectError")
    assert said.endswith(f"start your local model server (it must speak the OpenAI API with tool calling), or fix "
                         f"api.base_url in {SOURCE}, then start again")


@pytest.mark.parametrize(
    "answer, note",
    [
        (None, "does not list its models (GET /models answered HTTP 404), so flightdeck could not check models.ladder"),
        (FakeReply(503, {"error": {"message": "overloaded, try later"}}),
         "GET /models answered HTTP 503 (Service Unavailable) (overloaded, try later); the run goes on, unchecked"),
        (FakeReply(403, {"error": {"message": "missing scope api.model.read"}}),
         "GET /models answered HTTP 403 (Forbidden) (missing scope api.model.read); the run goes on, unchecked"),
        (FakeReply(200, {"models": ["m"]}), "GET /models answered with something that is not a model list"),
    ],
)
def test_an_api_that_does_not_list_its_models_is_a_note_and_the_run_goes_on(answer, note):
    with FakeModelServer(models=answer) as server:
        (said,) = check(openai_api(server.base_url, ("m",), key=None))
    assert note in said and server.base_url in said


def test_an_api_whose_model_list_is_public_is_asked_whether_it_takes_the_key():
    wrong = "fake-wrong-key-never-shown-0003"
    with FakeModelServer(models=["vendor/a"], key=KEY, public_models=True) as server:
        url = f"{server.base_url}/key"
        assert check(openai_api(server.base_url, ("vendor/a",)), key_check=url) == []
        with pytest.raises(CheckFailed, match="refused the key in MY_MODEL_KEY \\(HTTP 401"):
            check(openai_api(server.base_url, ("vendor/a",), key=wrong), key_check=url)
    assert [r["path"] for r in server.requests] == ["/v1/models", "/v1/key", "/v1/models", "/v1/key"]


def test_openrouter_is_the_api_asked_for_its_key_and_its_variants_are_its_models():
    assert key_url("https://openrouter.ai/api/v1") == "https://openrouter.ai/api/v1/key"
    assert key_url("https://api.openai.com/v1") is None and key_url("http://127.0.0.1:11434/v1") is None
    listed = ["vendor/a", "vendor/b:free"]
    assert missing(["vendor/a:nitro", "vendor/b:free", "@preset/mine", "vendor/c"], listed, openrouter=True) == ["vendor/c"]
    assert missing(["vendor/a:nitro"], listed) == ["vendor/a:nitro"]  # elsewhere a tag is a different model


def test_only_a_list_of_model_objects_is_a_model_list():
    assert listed_models({"object": "list", "data": [{"id": "a"}, {"id": "b"}]}) == ["a", "b"]
    for body in ({"data": [{"id": ""}]}, {"data": ["a"]}, {"data": {"id": "a"}}, [], "x", {"models": []}):
        assert listed_models(body) is None


def test_the_fallback_api_is_named_as_such():
    with FakeModelServer(models=["anthropic/claude-haiku-5.5"]) as server:
        api = openai_api(server.base_url, ("anthropic/claude-haiku-5", ), key=None, table="fallback")
        with pytest.raises(CheckFailed) as caught:
            check(api, source=SOURCE)
    assert str(caught.value).startswith(f"the [fallback] API at {server.base_url} does not serve anthropic/claude-haiku-5 "
                                        "(closest it lists: anthropic/claude-haiku-5.5)")
    assert f"change fallback.ladder in {SOURCE}" in str(caught.value)


def test_a_key_no_header_can_carry_is_refused_before_any_request():
    with FakeModelServer(models=["m"]) as server:
        with pytest.raises(CheckFailed, match="the key in MY_MODEL_KEY is empty or holds characters an HTTP header cannot carry"):
            check(openai_api(server.base_url, ("m",), key="two words"))
    assert server.requests == []


# ---------------------------------------------------------------------- the Anthropic API


CLAUDE = ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"]


def test_anthropic_models_are_checked_through_the_models_api():
    with FakeAnthropicServer(models=CLAUDE, key=KEY) as server:
        assert check(anthropic_api(server.base_url, tuple(CLAUDE))) == []
        with pytest.raises(CheckFailed) as caught:
            check(anthropic_api(server.base_url, ("claude-haiku-5.5", "claude-opus-5-5")), source=SOURCE)
    assert str(caught.value).startswith(
        f"the model API at {server.base_url} does not serve claude-haiku-5.5 (closest it lists: claude-haiku-5-5"
    )
    assert server.requests[0]["headers"]["authorization"] == f"Bearer {KEY}"  # as the SDK sends it
    assert {r["path"].split("?")[0] for r in server.requests} == {"/v1/models", "/v1/models/claude-haiku-5.5"}


def test_an_anthropic_alias_resolves_and_a_retired_model_stops_the_run():
    models = [{"id": "claude-haiku-4-5-20251001"}, {"id": "claude-old-1", "lifecycle": "retired"},
              {"id": "claude-soon-2", "lifecycle": "deprecated", "retires_at": "2026-12-01T00:00:00Z"}]
    with FakeAnthropicServer(models=models, aliases={"claude-haiku-4-5": "claude-haiku-4-5-20251001"}) as server:
        notes = check(anthropic_api(server.base_url, ("claude-haiku-4-5", "claude-soon-2")))
        with pytest.raises(CheckFailed) as caught:
            check(anthropic_api(server.base_url, ("claude-haiku-4-5", "claude-old-1")), source=SOURCE)
    assert notes == ["claude-soon-2 is deprecated on the Anthropic API and retires on 2026-12-01: move models.ladder to a "
                     "newer model before then"]
    assert str(caught.value) == (
        "claude-old-1 is retired on the Anthropic API, so every lane on it would fail at its first call: change "
        f"models.ladder in {SOURCE}, then start again"
    )


def test_an_anthropic_key_refused_stops_the_run_and_an_api_with_no_models_api_is_a_note():
    wrong = "fake-wrong-claude-key-0004"
    with FakeAnthropicServer(models=CLAUDE, key=KEY) as server:
        with pytest.raises(CheckFailed) as caught:
            check(anthropic_api(server.base_url, ("claude-haiku-5-5",), key=wrong))
    said = str(caught.value)
    assert said.startswith(f"the model API at {server.base_url} refused the key in MY_CLAUDE_KEY (HTTP 401: invalid "
                           "x-api-key)") and wrong not in said
    with FakeAnthropicServer() as plain:  # a proxy that speaks Messages but has no Models API
        (note,) = check(anthropic_api(plain.base_url, ("claude-haiku-5-5",)))
    assert note.startswith(f"the model API at {plain.base_url} does not list its models (GET /models answered HTTP 404)")


def test_nothing_answering_for_the_anthropic_api_stops_the_run():
    with pytest.raises(CheckFailed) as caught:
        check(anthropic_api("http://127.0.0.1:9", ("claude-haiku-5-5",)), source=SOURCE)
    assert str(caught.value).startswith("nothing answers at http://127.0.0.1:9 (")
