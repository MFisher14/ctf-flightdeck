"""[light] thinking: a light model on this machine is asked to answer without reasoning first.

As served, a model that reasons first spends a light job's few hundred tokens reasoning and
answers nothing. With thinking off, each request of the openai engine carries
light.THINKING_OFF ("reasoning_effort": "none", read by Ollama's /v1; "chat_template_kwargs":
{"enable_thinking": false}, read by mlx_lm.server). Never to an API elsewhere unless the player
sets thinking = false: it may refuse fields it does not know.

Servers are the fakes on 127.0.0.1; an API elsewhere is only named, never contacted.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path

import pytest

from ctf_flightdeck import light as L
from ctf_flightdeck.config import ConfigError, LightConfig, example_config, light_thinking, load_config
from ctf_flightdeck.detect.hints import lexicon
from fake_model import FakeModelServer, text_reply, tool_call_reply

LADDER = '[models]\nladder = ["m/small"]\n'
LOCAL = "http://127.0.0.1:11434/v1"
OPENAI_LIGHT = f'[light]\nengine = "openai"\nmodel = "qwen3.5:9b"\nbase_url = "{LOCAL}"\nkey_env = ""\n'
SENTINEL = "zqSentinelValue4471"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    """No config from the player's shell or home: FLIGHTDECK_CONFIG names a file that does not exist."""
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "no-config-here.toml"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def write(tmp_path: Path, text: str, name: str = "config.toml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# ---------------------------------------------------------------------- the config


def test_thinking_is_read_and_unset_until_the_player_sets_it(tmp_path):
    assert load_config(write(tmp_path, LADDER + OPENAI_LIGHT)).light.thinking is None
    assert load_config(write(tmp_path, LADDER + OPENAI_LIGHT + "thinking = true\n")).light.thinking is True
    assert load_config(write(tmp_path, LADDER + OPENAI_LIGHT + "thinking = false\n")).light.thinking is False


@pytest.mark.parametrize("table, says", [
    (OPENAI_LIGHT + 'thinking = "no"\n', "light.thinking must be true or false"),
    (OPENAI_LIGHT + "thinking = 0\n", "light.thinking must be true or false"),
    ("[light]\nthinking = false\n", 'light.thinking is for the openai engine (a model on an OpenAI-compatible server), not "rules"'),
    ('[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nthinking = false\n', 'light.thinking is for the openai engine'),
    ('[light]\nengine = "cactus"\nthinking = true\n', 'not "cactus"'),
])
def test_a_bad_thinking_is_an_error_naming_the_file_and_the_key(tmp_path, table, says):
    path = write(tmp_path, LADDER + table)
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    assert str(caught.value).startswith(f"{path}: ") and says in str(caught.value)


def test_a_thinking_error_never_shows_a_string_value(tmp_path):
    with pytest.raises(ConfigError) as caught:
        load_config(write(tmp_path, LADDER + OPENAI_LIGHT + f'thinking = "{SENTINEL}"\n'))
    assert "light.thinking" in str(caught.value) and SENTINEL not in str(caught.value)


@pytest.mark.parametrize("url", [LOCAL, "http://localhost:8080/v1", "http://[::1]:8080/v1"])
def test_thinking_is_off_by_default_for_an_openai_light_model_on_this_machine(url):
    assert light_thinking(LightConfig("openai", "m", url, "")) is False
    assert light_thinking(LightConfig("openai", "m", url, "", thinking=True)) is True  # the player's word wins


def test_thinking_is_left_as_served_elsewhere_unless_the_player_turns_it_off():
    remote = LightConfig("openai", "m", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY")
    assert light_thinking(remote) is True
    assert light_thinking(LightConfig("openai", "m", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY",
                                      thinking=False)) is False


def test_the_example_explains_thinking_and_its_line_loads_once_uncommented(tmp_path):
    text = example_config()
    prose = " ".join(line.lstrip("#").strip() for line in text.splitlines())
    for words in ('"reasoning_effort": "none", which Ollama reads', 'which mlx_lm.server reads',
                  "Default: false for a server on this machine", "--thinking on|off"):
        assert words in prose, words
    filled = text.replace("ladder = []", 'ladder = ["vendor/small-model"]').replace('engine = "rules"   #', 'engine = "openai"   #')
    filled, n = re.subn(r"^#   (model = .*|base_url = .*|key_env = .*|thinking = .*)$", r"\1", filled, flags=re.M)
    assert n == 4
    light = load_config(write(tmp_path, filled)).light
    assert (light.engine, light.base_url, light.thinking) == ("openai", LOCAL, False)


# ---------------------------------------------------------------------- the light role's requests


def judged(engine: L.Light) -> L.Answer:
    """One hint-judge job, then the engine closed."""

    async def go():
        try:
            return await engine.judge_hint(lexicon().get("sstv"), "a slow scan picture", ["$ ls"])
        finally:
            await engine.aclose()

    return asyncio.run(go())


def test_a_light_model_on_this_machine_is_asked_for_thinking_off_with_each_request():
    with FakeModelServer([text_reply("yes")]) as server:
        answer = judged(L.build(LightConfig("openai", "qwen3.5:9b", server.base_url, ""), None))
        (request,) = server.chats()
    body = request["json"]
    assert answer.choice == "yes"
    assert body["reasoning_effort"] == "none" and body["chat_template_kwargs"] == {"enable_thinking": False}
    assert (body["model"], body["max_tokens"], body["temperature"]) == ("qwen3.5:9b", 256, 0.0)  # the job's own cap


def test_thinking_on_sends_neither_field():
    with FakeModelServer([text_reply("yes")]) as server:
        judged(L.build(LightConfig("openai", "qwen3.5:9b", server.base_url, "", thinking=True), None))
        body = server.chats()[0]["json"]
    assert "reasoning_effort" not in body and "chat_template_kwargs" not in body


def test_an_api_elsewhere_gets_neither_field_unless_the_player_turns_thinking_off(monkeypatch):
    remote = L.build(LightConfig("openai", "m", "https://openrouter.ai/api/v1", ""), None)
    off = L.build(LightConfig("openai", "m", "https://openrouter.ai/api/v1", "", thinking=False), None)
    assert remote.client.extra_body == {} and off.client.extra_body == L.THINKING_OFF  # neither contacted here
    for engine in (remote, off):
        asyncio.run(engine.aclose())
    monkeypatch.setattr(L, "on_this_machine", lambda url: False)  # the fake server, as if it were elsewhere
    with FakeModelServer([text_reply("yes")]) as server:
        judged(L.build(LightConfig("openai", "m", server.base_url, ""), None))
        body = server.chats()[0]["json"]
    assert "reasoning_effort" not in body and "chat_template_kwargs" not in body


def test_in_a_run_the_hint_judge_on_this_machine_is_asked_for_thinking_off_and_the_run_says_so(tmp_path):
    from ctf_flightdeck.run import RunOptions, prepare_run

    root = tmp_path / "board"
    (root / "static").mkdir(parents=True)
    (root / "static" / "audio.txt").write_text("not really audio\n")
    hinted = "A numbers station. There is a picture in it if you scan it slowly enough."
    (root / "static" / "challenge.json").write_text(json.dumps(
        {"name": "Static Hiss", "category": "forensics", "points": 500, "solves": 1, "description": hinted}))
    (root / "board.json").write_text(json.dumps({"event": "Thinking", "flag_format": r"t\{[a-z]+\}"}))
    with FakeModelServer(responder=lambda request: tool_call_reply("shell", {"command": "ls"})) as lanes, \
            FakeModelServer([text_reply("yes")] * 20) as judge:
        path = write(tmp_path, f'[api]\nbase_url = "{lanes.base_url}"\nkey_env = ""\n[models]\nladder = ["m/small"]\n'
                     '[lanes]\nmax_lanes = 1\nruntime = "host"\ntoken_cap = false\ndollar_cap = false\n'
                     f'[run]\ndir = "{tmp_path / "runs"}"\n'
                     f'[light]\nengine = "openai"\nmodel = "light/m"\nbase_url = "{judge.base_url}"\nkey_env = ""\n')
        run = prepare_run(RunOptions(board=root, config=path))

        async def main():
            run.release()
            for _ in range(2000):
                if judge.chats():
                    break
                await asyncio.sleep(0.01)
            await run.shutdown()

        asyncio.run(main())
        run.close()
        asked = [request["json"] for request in judge.chats()]
    assert asked and all(body["reasoning_effort"] == "none" for body in asked)
    assert all(body["chat_template_kwargs"] == {"enable_thinking": False} for body in asked)
    (note,) = [note for note in run.notes() if note.startswith("light model: openai light/m judges")]
    assert note.endswith("; thinking off: each request asks it to answer without reasoning first ([light] thinking)")


# ---------------------------------------------------------------------- eval-local


def eval_local(tmp_path: Path, *args: str):
    """`flightdeck eval-local` over one hint case, with the options given."""
    import typer
    from typer.testing import CliRunner

    from ctf_flightdeck import localmodel_cli

    case = {"kind": "hint", "input": {"name": "C", "category": "misc", "description": "a slow scan tv signal"},
            "expected": "sstv"}
    cases = tmp_path / "cases.jsonl"
    cases.write_text(json.dumps(case) + "\n")
    root = typer.Typer()
    root.add_typer(localmodel_cli.app)
    return CliRunner().invoke(root, ["eval-local", "--cases", str(cases), *args])


def columns(output: str) -> list[str]:
    """The scorecard's column labels after the rules' (cells are 2+ spaces apart)."""
    for line in output.splitlines():
        cells = re.split(r"\s{2,}", line.strip())
        if cells[0] == "cases":
            return cells[2:]
    raise AssertionError(f"no scorecard in: {output}")


def cut_off(content: str) -> dict:
    reply = text_reply(content)
    reply["choices"][0]["finish_reason"] = "length"
    return reply


def test_eval_local_asks_a_model_on_this_machine_for_thinking_off_and_its_column_says_so(tmp_path):
    with FakeModelServer([text_reply("sstv")]) as server:
        result = eval_local(tmp_path, "--base-url", server.base_url, "--model", "qwen3.5:9b")
        body = server.chats()[0]["json"]
    assert result.exit_code == 0, result.output
    assert columns(result.output) == ["openai qwen3.5:9b (thinking off)"]
    assert body["reasoning_effort"] == "none" and body["chat_template_kwargs"] == {"enable_thinking": False}


def test_thinking_on_sends_neither_field_and_its_column_says_so(tmp_path):
    with FakeModelServer([text_reply("sstv")]) as server:
        result = eval_local(tmp_path, "--base-url", server.base_url, "--model", "qwen3.5:9b", "--thinking", "on")
        body = server.chats()[0]["json"]
    assert result.exit_code == 0, result.output
    assert columns(result.output) == ["openai qwen3.5:9b (thinking on)"]
    assert "reasoning_effort" not in body and "chat_template_kwargs" not in body


def test_every_openai_column_gets_the_option(tmp_path):
    with FakeModelServer([text_reply("sstv")]) as one, FakeModelServer([text_reply("sstv")]) as two:
        result = eval_local(tmp_path, "--base-url", one.base_url, "--model", "a", "--compare", f"openai:b@{two.base_url}",
                            "--thinking", "OFF")
        sent = [one.chats()[0]["json"], two.chats()[0]["json"]]
    assert result.exit_code == 0, result.output
    assert columns(result.output) == ["openai a (thinking off)", "openai b (thinking off)"]
    assert all(body["reasoning_effort"] == "none" for body in sent)


def test_a_server_elsewhere_is_left_thinking_unless_asked(tmp_path, monkeypatch):
    monkeypatch.setattr(L, "on_this_machine", lambda url: False)  # the fake server, as if it were elsewhere
    with FakeModelServer([text_reply("sstv"), text_reply("sstv")]) as server:
        default = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m")
        asked = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m", "--thinking", "off")
        first, second = (request["json"] for request in server.chats())
    assert columns(default.output) == ["openai m (thinking on)"] and "reasoning_effort" not in first
    assert columns(asked.output) == ["openai m (thinking off)"] and second["reasoning_effort"] == "none"


def test_by_default_eval_local_measures_with_light_thinking_as_the_players_config_sets_it(tmp_path, monkeypatch):
    config = write(tmp_path, LADDER + OPENAI_LIGHT + "thinking = true\n")
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(config))
    with FakeModelServer([text_reply("sstv"), text_reply("sstv")]) as server:
        default = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m")
        overridden = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m", "--thinking", "off")
        first, second = (request["json"] for request in server.chats())
    assert default.exit_code == 0, default.output
    assert columns(default.output) == ["openai m (thinking on)"] and "reasoning_effort" not in first
    assert f"flightdeck: thinking on, as [light] thinking in {config} says (--thinking on|off overrides it)" in default.output
    assert columns(overridden.output) == ["openai m (thinking off)"] and second["reasoning_effort"] == "none"
    assert "as [light] thinking in" not in overridden.output


def test_a_config_that_cannot_be_read_stops_eval_local_before_any_call_unless_thinking_is_given(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(write(tmp_path, "[models]\nladder = []\n")))
    with FakeModelServer([text_reply("sstv")]) as server:
        stopped = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m")
        assert server.chats() == []
        given = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m", "--thinking", "off")
    assert stopped.exit_code == 2
    assert "--thinking takes its default from [light] thinking in your config, which cannot be read" in stopped.output
    assert "models.ladder is empty" in stopped.output and "give --thinking on or off" in stopped.output
    assert given.exit_code == 0, given.output


def test_a_bad_thinking_option_or_one_without_an_openai_engine_is_refused(tmp_path):
    bad = eval_local(tmp_path, "--base-url", LOCAL, "--model", "m", "--thinking", "maybe")
    assert bad.exit_code == 2 and "--thinking must be on or off" in bad.output
    rules = eval_local(tmp_path, "--engine", "rules", "--thinking", "off")
    assert rules.exit_code == 2 and "--thinking is for an openai engine" in rules.output


def test_a_model_that_answers_nothing_is_pointed_at_the_thinking_setting(tmp_path):
    with FakeModelServer([cut_off("<think>\nThe description"), cut_off("<think>\nHmm")]) as server:
        on = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m", "--thinking", "on")
        off = eval_local(tmp_path, "--base-url", server.base_url, "--model", "m")
    assert on.exit_code == off.exit_code == 1
    assert "for this evaluation (--thinking off asks for it)." in on.output
    assert ("(it was asked to: check that its server reads reasoning_effort, as Ollama does, or chat_template_kwargs, "
            "as mlx_lm.server does).") in off.output
