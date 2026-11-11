"""[light] thinking: a light model on this machine is asked to answer without reasoning first.

As served, a model that reasons first spends a light job's few hundred tokens reasoning and
answers nothing. With thinking off, each request of the openai engine carries
light.THINKING_OFF ("reasoning_effort": "none", read by Ollama's /v1; "chat_template_kwargs":
{"enable_thinking": false}, read by mlx_lm.server). Never to an API elsewhere unless the player
sets thinking = false: it may refuse fields it does not know.

Servers are the fakes on 127.0.0.1; an API elsewhere is only named, never contacted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ctf_flightdeck.config import ConfigError, LightConfig, example_config, light_thinking, load_config

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
