"""The config's [light] table (the light model) and [api] fast (fast mode on the Anthropic API).

Every test reads a real file in tmp_path; keys come from monkeypatched variables, never from
the player's environment or keys file (conftest points FLIGHTDECK_KEYS at a missing file).
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest

from ctf_flightdeck.agent import fastmode
from ctf_flightdeck.config import (
    LIGHT_TIMEOUT,
    ConfigError,
    LightConfig,
    example_config,
    light_key,
    load_config,
)
from ctf_flightdeck.pricing import Price

LADDER = '[models]\nladder = ["vendor/small", "vendor/big"]\n'
CLAUDE = '[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5"]\n'
OLLAMA = '[light]\nengine = "openai"\nmodel = "local-model"\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n'
SENTINEL = "zqSentinelValue4471"  # letters and digits only, like many real keys
FAKE_KEY = "fake-light-key-for-tests-0451"  # not a real key, and not shaped like one


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    monkeypatch.delenv("FLIGHTDECK_CONFIG", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    return path


def error(path: Path) -> str:
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    return str(caught.value)


# ---------------------------------------------------------------------- [light]


def test_without_a_light_table_the_light_role_is_rules_only(tmp_path):
    assert load_config(write(tmp_path, LADDER)).light == LightConfig(engine="rules")
    assert light_key(load_config(write(tmp_path, LADDER))) is None


def test_an_open_weight_model_on_this_machine_needs_no_key(tmp_path, monkeypatch):
    config = load_config(write(tmp_path, LADDER + OLLAMA + "timeout = 12.5\n"))
    assert config.light == LightConfig("openai", "local-model", "http://127.0.0.1:11434/v1", "", 12.5, None)
    assert light_key(config) is None


def test_the_anthropic_engine_has_the_sdks_url_and_variable_by_default_and_reads_its_key(tmp_path, monkeypatch):
    text = LADDER + '[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nprice = { input = 0.1, output = 0.5, cached_input = 0.01 }\n'
    config = load_config(write(tmp_path, text))
    assert config.light == LightConfig(
        "anthropic", "claude-haiku-5-5", "https://api.anthropic.com", "ANTHROPIC_API_KEY", LIGHT_TIMEOUT,
        Price(0.1, 0.5, 0.01),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", FAKE_KEY)
    assert light_key(config) == FAKE_KEY
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    with pytest.raises(ConfigError) as caught:
        light_key(config)
    message = str(caught.value)
    assert "light.key_env names the variable ANTHROPIC_API_KEY, which is not set" in message
    assert 'engine = "rules"' in message and FAKE_KEY not in message


def test_cactus_takes_only_a_timeout(tmp_path):
    assert load_config(write(tmp_path, LADDER + '[light]\nengine = "cactus"\ntimeout = 5\n')).light == LightConfig("cactus", timeout=5.0)


LIGHT_ERRORS = {
    "unknown key": ('[light]\nengine = "rules"\nmodle = "x"\n', "unknown key light.modle"),
    "unknown engine": ('[light]\nengine = "ollama"\n', 'light.engine must be "rules" or "openai" or "anthropic" or "cactus"'),
    "rules with a model": ('[light]\nmodel = "x"\n', 'light.model is for the openai and anthropic engines, not "rules"'),
    "cactus with a url": ('[light]\nengine = "cactus"\nbase_url = "http://127.0.0.1:1/v1"\n', "light.base_url is for the openai"),
    "rules with a price": ('[light]\nprice = { input = 1, output = 2 }\n', "light.price is for the openai"),
    "openai without a model": ('[light]\nengine = "openai"\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = ""\n', "light.model is required for the openai engine"),
    "openai without a url": ('[light]\nengine = "openai"\nmodel = "m"\nkey_env = ""\n', 'light.base_url is required for the openai engine (it has no default): for a server on this machine, base_url = "http://127.0.0.1:11434/v1" (Ollama)'),
    "openai without key_env": ('[light]\nengine = "openai"\nmodel = "m"\nbase_url = "http://127.0.0.1:11434/v1"\n', 'light.key_env is required for the openai engine'),
    "anthropic without a model": ('[light]\nengine = "anthropic"\n', "light.model is required for the anthropic engine: the model id (for example claude-haiku-5-5)"),
    "anthropic without a key": ('[light]\nengine = "anthropic"\nmodel = "claude-haiku-5-5"\nkey_env = ""\n', "light.key_env is empty, but the Anthropic API needs a key"),
    "anthropic url with /v1": ('[light]\nengine = "anthropic"\nmodel = "m"\nbase_url = "https://api.anthropic.com/v1"\n', "light.base_url ends in /v1"),
    "url with a password": (OLLAMA.replace("http://127.0.0.1", "http://me:pw@127.0.0.1"), "light.base_url must not carry a user name or password"),
    "key_env in lower case": (OLLAMA.replace('key_env = ""', 'key_env = "my_key"'), "light.key_env must be the name of an environment variable"),
    "model with a space": (OLLAMA.replace('"local-model"', '"local model"'), "light.model must be a model id"),
    "model not a string": (OLLAMA.replace('"local-model"', "3"), "light.model must be a string"),
    "timeout zero": ('[light]\ntimeout = 0\n', "light.timeout must be a positive number of seconds (got 0)"),
    "timeout negative": ('[light]\ntimeout = -1\n', "light.timeout must be a positive number of seconds"),
    "timeout infinite": ('[light]\ntimeout = inf\n', "light.timeout must be a positive number of seconds"),
    "timeout true": ('[light]\ntimeout = true\n', "light.timeout must be a positive number of seconds (got true)"),
    "price missing output": (OLLAMA + "price = { input = 1 }\n", "light.price.output is required"),
    "price negative": (OLLAMA + "price = { input = -1, output = 1 }\n", "light.price.input must be a number of dollars"),
    "price not a table": (OLLAMA + "price = 3\n", "light.price must be a table of dollars per million tokens"),
    "price unknown key": (OLLAMA + "price = { input = 1, output = 1, write = 2 }\n", "unknown key light.price.write"),
    "light not a table": ("light = 1\n", "light must be a table"),
}


@pytest.mark.parametrize("text, says", LIGHT_ERRORS.values(), ids=LIGHT_ERRORS.keys())
def test_a_bad_light_table_is_an_error_that_names_the_key(tmp_path, text, says):
    path = write(tmp_path, LADDER + text if not text.startswith("light =") else text + LADDER)
    message = error(path)
    assert message.startswith(f"{path}: ") and says in message


LIGHT_STRINGS = {
    "engine": (f'[light]\nengine = "{SENTINEL}"\n', "light.engine"),
    "model": (f'[light]\nengine = "openai"\nmodel = " {SENTINEL}"\nbase_url = "http://127.0.0.1:1/v1"\nkey_env = ""\n', "light.model"),
    "base_url": (f'[light]\nengine = "openai"\nmodel = "m"\nbase_url = "{SENTINEL}"\nkey_env = ""\n', "light.base_url"),
    "key_env holding a key": (f'[light]\nengine = "anthropic"\nmodel = "m"\nkey_env = "sk-{SENTINEL}"\n', "light.key_env"),
    "timeout": (f'[light]\ntimeout = "{SENTINEL}"\n', "light.timeout"),
}


@pytest.mark.parametrize("text, key", LIGHT_STRINGS.values(), ids=LIGHT_STRINGS.keys())
def test_light_errors_never_show_a_string_value(tmp_path, text, key):
    message = error(write(tmp_path, LADDER + text))
    assert key in message and SENTINEL not in message


# ---------------------------------------------------------------------- [api] fast


def test_fast_mode_is_set_per_ladder_model_on_the_anthropic_api(tmp_path):
    config = load_config(write(tmp_path, CLAUDE.replace('provider = "anthropic"\n', 'provider = "anthropic"\nfast = ["claude-opus-5-5"]\n')))
    assert config.api.fast == ("claude-opus-5-5",)
    assert load_config(write(tmp_path, CLAUDE)).api.fast == ()


def fast(models: str, *, api: str = CLAUDE) -> str:
    return api.replace('provider = "anthropic"\n', f'provider = "anthropic"\nfast = {models}\n')


FAST_ERRORS = {
    "not the anthropic api": (LADDER + '[api]\nfast = ["vendor/big"]\n', 'api.fast is fast mode, a feature of the Anthropic Messages API: it needs [api] provider = "anthropic"'),
    "not a list": (fast('"claude-opus-5-5"'), "api.fast must be a list of model ids from models.ladder (got a string)"),
    "not in the ladder": (fast('["claude-fable-5-2"]'), "api.fast[0] is not a model in models.ladder"),
    "no fast mode": (fast('["claude-opus-5-5", "claude-sonnet-5-5"]'), "api.fast[1] names a model with no fast mode; fast mode is for claude-opus-5-5, claude-fable-5-2"),
    "listed twice": (fast('["claude-opus-5-5", "claude-opus-5-5"]'), "api.fast[1] repeats api.fast[0]"),
    "not a string": (fast("[5]"), "api.fast[0] must be a model id from models.ladder (got 5)"),
}


@pytest.mark.parametrize("text, says", FAST_ERRORS.values(), ids=FAST_ERRORS.keys())
def test_fast_mode_is_refused_with_the_reason(tmp_path, text, says):
    message = error(write(tmp_path, text))
    assert says in message


def test_an_unlisted_model_in_fast_is_never_shown(tmp_path):
    api = f'[api]\nprovider = "anthropic"\n[models]\nladder = ["{SENTINEL}"]\n'
    message = error(write(tmp_path, fast(f'["{SENTINEL}"]', api=api)))
    assert "api.fast[0] names a model with no fast mode" in message and SENTINEL not in message


def test_fast_mode_on_opus_4_8_ends_on_the_day_anthropic_removes_it(tmp_path, monkeypatch):
    text = fast('["claude-opus-4-8"]', api='[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-opus-4-8"]\n')
    monkeypatch.setattr(fastmode, "today", lambda: date(2026, 11, 29))
    assert load_config(write(tmp_path, text)).api.fast == ("claude-opus-4-8",)
    monkeypatch.setattr(fastmode, "today", lambda: date(2026, 11, 30))
    message = error(write(tmp_path, text))
    assert "api.fast[0]: fast mode on claude-opus-4-8 was removed on 2026-11-30" in message
    assert "claude-opus-4-8 (research preview" not in message  # no longer offered either


# ---------------------------------------------------------------------- the example


def filled(example: str) -> str:
    return example.replace("ladder = []", 'ladder = ["vendor/small-model", "vendor/big-model"]')


def test_the_example_recommends_a_local_open_weight_model_and_loads_as_rules(tmp_path):
    text = example_config()
    assert "[light]" in text and 'engine = "rules"' in text
    for words in ("open-weight", "http://127.0.0.1:11434/v1", "http://127.0.0.1:8080/v1", 'key_env = ""', "eval-local",
                  "not endorsements", "Qwen3.5 9B", "Phi-4-mini", "the rules' answer stands", "# fast = "):
        assert words in text, words
    assert load_config(write(tmp_path, filled(text))).light == LightConfig()


def test_the_example_openai_lines_load_once_uncommented(tmp_path):
    text = filled(example_config()).replace('engine = "rules"   #', 'engine = "openai"   #')
    text, n = re.subn(r"^#   (model = .*|base_url = .*|key_env = .*|timeout = .*|price = .*)$", r"\1", text, flags=re.M)
    assert n == 5
    light = load_config(write(tmp_path, text)).light
    assert (light.engine, light.base_url, light.key_env, light.timeout) == ("openai", "http://127.0.0.1:11434/v1", "", 30.0)
    assert light.price == Price(0.10, 0.50)
