"""A lane's calls to a model server: the reply cap ([api] max_tokens) and the time one try may
take ([api] timeout), from the config to the request.

Servers are the fakes on 127.0.0.1 (fake_model.py, fake_anthropic.py); an API anywhere else is
only named in a config, never contacted.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from ctf_flightdeck.config import (
    LOCAL_MAX_TOKENS,
    ConfigError,
    example_config,
    lane_max_tokens,
    load_config,
)

LADDER = '[models]\nladder = ["m/small", "m/big"]\n'
LOCAL = "http://127.0.0.1:11434/v1"
SENTINEL = "zqSentinelValue4471"  # a string value no error may show: it could be a key pasted in the wrong place


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
