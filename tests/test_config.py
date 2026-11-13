"""The player's config file: defaults, validation, the API key variable and the example.

Every test reads a real file in tmp_path. Environment variables are set with monkeypatch,
so the player's own FLIGHTDECK_CONFIG or API key never leaks into a test (or out of one).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from ctf_flightdeck.config import (
    L1Config,
    ApiConfig,
    Config,
    ConfigError,
    FallbackConfig,
    LaneConfig,
    api_key,
    default_config_path,
    example_config,
    expand,
    fallback_key,
    load_config,
)
from ctf_flightdeck.pricing import Price

LADDER = '[models]\nladder = ["vendor/small", "vendor/big"]\n'
FAKE_KEY = "fake-key-value-for-tests-0451"  # not a real key, and not shaped like one


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


# ---------------------------------------------------------------------- defaults and values


def test_a_config_with_only_the_ladder_has_the_documented_defaults(tmp_path):
    path = write(tmp_path, LADDER)
    config = load_config(path)
    assert config.models == ("vendor/small", "vendor/big")
    assert (config.api.base_url, config.api.key_env) == ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY")
    lanes = config.lanes
    assert (lanes.max_lanes, lanes.runtime, lanes.image) == (4, "docker", "ctf-flightdeck-lane:1")
    assert (lanes.token_cap, lanes.dollar_cap, lanes.submit) == (400_000, 2.0, "confirm")
    assert config.prices == {}
    assert config.run_dir == tmp_path / "home" / ".local/share/ctf-flightdeck/runs"
    assert config.source == path


def test_every_key_is_read(tmp_path):
    path = write(
        tmp_path,
        """
[api]
base_url = "http://127.0.0.1:11434/v1/"
key_env = ""

[models]
ladder = ["local/tiny", "local/mid", "local/large"]

[prices."local/tiny"]
input = 0.5
output = 1

[prices."local/large"]
input = 3.0
output = 15.0
cached_input = 0.3

[lanes]
max_lanes = 12
runtime = "host"
image = "registry.example/lab:1.2"
token_cap = 50000
dollar_cap = 7
submit = "auto"

[run]
dir = "/srv/flightdeck runs"
""",
    )
    config = load_config(path)
    assert config.api == ApiConfig(base_url="http://127.0.0.1:11434/v1/", key_env="")
    assert config.models == ("local/tiny", "local/mid", "local/large")
    assert config.prices == {
        "local/tiny": Price(input=0.5, output=1.0),
        "local/large": Price(input=3.0, output=15.0, cached_input=0.3),
    }
    assert config.lanes == LaneConfig(
        max_lanes=12, runtime="host", image="registry.example/lab:1.2", token_cap=50_000, dollar_cap=7.0, submit="auto"
    )
    assert isinstance(config.lanes.dollar_cap, float)
    assert config.run_dir == Path("/srv/flightdeck runs")


AGENTS = '[agents]\ncodex = ["cx-small", "cx-big"]\nclaude = ["sonnet", "opus"]\n'
CLAUDE = '[api]\nprovider = "anthropic"\n[models]\nladder = ["claude-haiku-5-5", "claude-sonnet-5-5"]\n'


def test_a_price_takes_a_rate_for_tokens_written_to_the_cache(tmp_path):
    config = load_config(write(tmp_path, CLAUDE + (
        '[prices."claude-sonnet-5-5"]\ninput = 2\noutput = 10\ncached_input = 0.1\ncache_write = 2.5\n'
        '[prices."claude-haiku-5-5"]\ninput = 0.1\noutput = 0.5\ncache_write = 0\n'
    )))
    assert config.prices == {
        "claude-sonnet-5-5": Price(input=2.0, output=10.0, cached_input=0.1, cache_write=2.5),
        "claude-haiku-5-5": Price(input=0.1, output=0.5, cache_write=0.0),
    }


@pytest.mark.parametrize("value", ["-1", '"cheap"', "true", "inf", "nan", "[2.5]"])
def test_a_cache_write_rate_that_is_not_a_non_negative_number_is_an_error_naming_the_key(tmp_path, value):
    path = write(tmp_path, LADDER + f'[prices."vendor/small"]\ninput = 1\noutput = 2\ncache_write = {value}\n')
    message = error(path)
    assert message.startswith(f'{path}: prices."vendor/small".cache_write must be a number of dollars per million tokens, 0 or more')
    assert "cheap" not in message


def test_with_the_anthropic_api_a_model_its_refusal_fallback_answers_with_can_have_a_price(tmp_path):
    """The fallback's attempt bills at its own model's rates: claude-sonnet-5 answers for claude-sonnet-5-5."""
    config = load_config(write(tmp_path, CLAUDE + '[prices."claude-sonnet-5"]\ninput = 2\noutput = 10\ncache_write = 2.5\n'))
    assert config.prices == {"claude-sonnet-5": Price(input=2.0, output=10.0, cache_write=2.5)}


@pytest.mark.parametrize("text, says", [
    # not the Anthropic API: no refusal fallback, so no model outside the ladders has a price
    (CLAUDE.replace('provider = "anthropic"', 'provider = "openai"') + '[prices."claude-sonnet-5"]\ninput = 1\noutput = 2\n',
     "prices.claude-sonnet-5 is for a model that is not in models.ladder or in an [agents] ladder"),
    # claude-opus-4-8 answers for claude-opus-5-5 and the Fable models, none of them in this ladder
    (CLAUDE + '[prices."claude-opus-4-8"]\ninput = 5\noutput = 25\n',
     "prices.claude-opus-4-8 is for a model that is not in models.ladder or in an [agents] ladder, nor one "
     "Anthropic's refusal fallback answers with for the ladder (claude-sonnet-5)"),
], ids=["openai", "not this ladder's"])
def test_a_price_for_a_model_no_lane_and_no_refusal_fallback_of_the_ladder_runs_is_an_error(tmp_path, text, says):
    path = write(tmp_path, text)
    assert error(path) == f"{path}: {says}"


def test_a_model_in_an_agents_ladder_can_have_a_price(tmp_path):
    """codex reports its tokens but no cost: a price under the CLI's own model name prices them."""
    config = load_config(write(tmp_path, LADDER + AGENTS + (
        '[prices."vendor/small"]\ninput = 0.5\noutput = 1\n'
        '[prices.cx-small]\ninput = 1.25\noutput = 10\ncached_input = 0.125\n'
        '[prices.opus]\ninput = 4\noutput = 20\n'
    )))
    assert config.agents == {"codex": ("cx-small", "cx-big"), "claude": ("sonnet", "opus")}
    assert config.prices == {
        "vendor/small": Price(input=0.5, output=1.0),
        "cx-small": Price(input=1.25, output=10.0, cached_input=0.125),
        "opus": Price(input=4.0, output=20.0),
    }


@pytest.mark.parametrize("text, key", [
    (LADDER + AGENTS + '[prices.cx-smal]\ninput = 1\noutput = 2\n', "prices.cx-smal"),  # in no ladder
    (LADDER + '[prices.cx-small]\ninput = 1\noutput = 2\n', "prices.cx-small"),  # no [agents] names it
    (LADDER + AGENTS + '[prices.cx-small]\ninput = -1\noutput = 2\n', "prices.cx-small.input"),
    (LADDER + AGENTS + '[prices.cx-small]\ninput = 1\noutput = "cheap"\n', "prices.cx-small.output"),
    (LADDER + AGENTS + '[prices.cx-small]\ninput = 1\noutput = 2\ncached_input = true\n', "prices.cx-small.cached_input"),
    (LADDER + AGENTS + '[prices.cx-small]\ninput = 1\noutput = inf\n', "prices.cx-small.output"),
    (LADDER + AGENTS + '[prices.cx-small]\ninput = 1\n', "prices.cx-small.output"),
    (LADDER + AGENTS + '[prices.cx-small]\ninput = 1\noutput = 2\noutput_cached = 1\n', "prices.cx-small.output_cached"),
], ids=["in no ladder", "no agents table", "negative", "a string", "a boolean", "infinite", "no output", "unknown key"])
def test_a_bad_price_for_an_agents_model_is_an_error_naming_the_key(tmp_path, text, key):
    path = write(tmp_path, text)
    message = error(path)
    assert message.startswith(f"{path}: ") and f" {key} " in message[len(str(path)):]
    if key.count(".") == 1:  # the table itself
        assert message == f"{path}: {key} is for a model that is not in models.ladder or in an [agents] ladder"
    assert "cheap" not in message  # a string is never shown: it could be a key pasted into the wrong place


def test_the_config_command_lists_the_prices_of_agents_models_too(tmp_path):
    from typer.testing import CliRunner

    from ctf_flightdeck import cli

    path = write(tmp_path, '[api]\nkey_env = ""\n' + LADDER + AGENTS + '[prices."vendor/big"]\ninput = 1\noutput = 2\n'
                 "[prices.cx-small]\ninput = 1\noutput = 2\n")
    result = CliRunner().invoke(cli.app, ["config", "--path", str(path)])
    assert result.exit_code == 0, result.output
    assert "prices from config: vendor/big, cx-small" in result.output.splitlines()


def test_the_openai_dialect_is_the_default_and_anthropic_brings_its_own_url_and_key_variable(tmp_path):
    assert load_config(write(tmp_path, LADDER)).api.provider == "openai"
    config = load_config(write(tmp_path, LADDER + '[api]\nprovider = "anthropic"\n'))
    assert config.api == ApiConfig(base_url="https://api.anthropic.com", key_env="ANTHROPIC_API_KEY", provider="anthropic")
    assert config.fallback is None
    other = load_config(write(tmp_path, LADDER + '[api]\nprovider = "anthropic"\nbase_url = "https://proxy.example"\nkey_env = "MY_CLAUDE_KEY"\n'))
    assert (other.api.base_url, other.api.key_env) == ("https://proxy.example", "MY_CLAUDE_KEY")


def test_a_fallback_table_is_read_with_its_ladder_and_its_providers_defaults(tmp_path):
    text = (
        '[api]\nprovider = "anthropic"\n'
        '[models]\nladder = ["claude-haiku-5-5", "claude-opus-5-5"]\n'
        '[fallback]\nladder = ["anthropic/claude-haiku-5.5", "anthropic/claude-opus-5.5"]\n'
    )
    config = load_config(write(tmp_path, text))
    assert config.fallback == FallbackConfig(
        provider="openai", base_url="https://openrouter.ai/api/v1", key_env="OPENROUTER_API_KEY",
        ladder=("anthropic/claude-haiku-5.5", "anthropic/claude-opus-5.5"),
    )
    spare = load_config(write(tmp_path, LADDER + '[fallback]\nprovider = "anthropic"\nladder = ["m1", "m1"]\n')).fallback
    # another provider's defaults; two models may share one fallback model
    assert (spare.provider, spare.base_url, spare.key_env, spare.ladder) == (
        "anthropic", "https://api.anthropic.com", "ANTHROPIC_API_KEY", ("m1", "m1"))


def test_false_disables_a_cap_and_an_absent_cap_keeps_its_default(tmp_path):
    config = load_config(write(tmp_path, LADDER + "[lanes]\ntoken_cap = false\n"))
    assert (config.lanes.token_cap, config.lanes.dollar_cap) == (None, 2.0)
    config = load_config(write(tmp_path, LADDER + "[lanes]\ndollar_cap = false\n"))
    assert (config.lanes.token_cap, config.lanes.dollar_cap) == (400_000, None)


def test_counted_tries_wait_for_the_player_unless_the_config_opts_in(tmp_path):
    assert load_config(write(tmp_path, LADDER)).lanes.submit_limited == "confirm"
    assert load_config(write(tmp_path, LADDER)).lanes.wrong_stop == 3
    assert load_config(write(tmp_path, LADDER + "[lanes]\nwrong_stop = 0\n")).lanes.wrong_stop == 0
    for bad in ("-1", "1.5", '"3"', "true"):
        assert "lanes.wrong_stop must be a whole number, 0 or more" in error(write(tmp_path, LADDER + f"[lanes]\nwrong_stop = {bad}\n"))
    assert load_config(write(tmp_path, LADDER + '[lanes]\nsubmit_limited = "auto"\n')).lanes.submit_limited == "auto"
    for bad in ("true", '"yes"', '"off"'):
        assert 'lanes.submit_limited must be "auto" or "confirm"' in error(write(tmp_path, LADDER + f"[lanes]\nsubmit_limited = {bad}\n"))


def test_the_run_dir_expands_the_home_directory(tmp_path):
    config = load_config(write(tmp_path, LADDER + '[run]\ndir = "~/ctf/runs"\n'))
    assert config.run_dir == tmp_path / "home" / "ctf" / "runs"


def test_expand_turns_a_home_it_cannot_find_into_a_config_error(monkeypatch, tmp_path):
    def no_home(self):
        raise RuntimeError("Could not determine home directory")

    monkeypatch.setattr(Path, "expanduser", no_home)
    with pytest.raises(ConfigError) as exc:
        expand(tmp_path / "runs")
    assert "starts with ~ for a user that does not exist" in str(exc.value)


# ---------------------------------------------------------------------- where the file is


def test_the_default_path_is_the_home_config_unless_FLIGHTDECK_CONFIG_names_another(monkeypatch, tmp_path):
    home = tmp_path / "home"
    assert default_config_path() == home / ".config" / "ctf-flightdeck" / "config.toml"
    monkeypatch.setenv("FLIGHTDECK_CONFIG", "~/events/this-one.toml")
    assert default_config_path() == home / "events" / "this-one.toml"
    monkeypatch.setenv("FLIGHTDECK_CONFIG", "")  # set but empty counts as not set
    assert default_config_path() == home / ".config" / "ctf-flightdeck" / "config.toml"


def test_load_config_without_a_path_reads_the_file_FLIGHTDECK_CONFIG_names(monkeypatch, tmp_path):
    path = write(tmp_path, LADDER + "[lanes]\nmax_lanes = 9\n", name="event.toml")
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(path))
    config = load_config()
    assert (config.source, config.lanes.max_lanes) == (path, 9)


def test_a_missing_file_names_the_path_and_how_to_create_it(tmp_path):
    path = tmp_path / "config.toml"
    message = error(path)
    assert str(path) in message
    assert f"flightdeck config --example > {path}" in message
    assert "mkdir" not in message  # the folder is there already


def test_a_missing_config_points_a_new_player_at_init(tmp_path, monkeypatch):
    custom = tmp_path / "elsewhere.toml"
    assert f"Run `flightdeck init --path {custom}`" in error(custom)
    usual = tmp_path / "usual.toml"
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(usual))
    assert "Run `flightdeck init`: it asks a few questions" in error(usual)


def test_a_missing_file_in_a_missing_folder_says_to_create_the_folder_too(tmp_path):
    path = tmp_path / "not-yet" / "config.toml"
    message = error(path)
    assert f"mkdir -p {path.parent} && flightdeck config --example > {path}" in message


def test_load_config_without_a_path_says_where_it_looked(tmp_path):
    with pytest.raises(ConfigError, match=re.escape(str(tmp_path / "home" / ".config" / "ctf-flightdeck" / "config.toml"))):
        load_config()


@pytest.mark.parametrize(
    "content, expected",
    [
        (b"[models]\nladder = [\n", "not valid TOML"),
        (b"[models]\nladder = ['a']\n\xff\xfe\n", "not UTF-8"),
    ],
    ids=["bad TOML", "not UTF-8"],
)
def test_a_file_that_is_not_toml_names_the_file(tmp_path, content, expected):
    path = tmp_path / "config.toml"
    path.write_bytes(content)
    message = error(path)
    assert str(path) in message and expected in message


def test_a_directory_is_not_a_config_file(tmp_path):
    message = error(tmp_path)
    assert str(tmp_path) in message and "directory" in message


# ---------------------------------------------------------------------- unknown tables and keys


@pytest.mark.parametrize(
    "text, key",
    [
        (LADDER + "[lane]\nmax_lanes = 2\n", "[lane]"),
        ('ladder = ["vendor/small"]\n' + LADDER, "ladder"),
        (LADDER + "[lanes]\nmax_lane = 2\n", "lanes.max_lane"),
        (LADDER + '[api]\nkey = "x"\n', "api.key"),
        ('[models]\nladder = ["vendor/small"]\ndefault = "vendor/small"\n', "models.default"),
        (LADDER + '[prices."vendor/small"]\ninput = 1\noutput = 2\ninptu = 3\n', 'prices."vendor/small".inptu'),
        (LADDER + '[run]\npath = "/tmp/runs"\n', "run.path"),
        (LADDER + '[fallback]\nladder = ["a", "b"]\nmodels = ["a", "b"]\n', "fallback.models"),
    ],
    ids=["table", "top-level key", "lanes key", "api key", "models key", "price key", "run key", "fallback key"],
)
def test_an_unknown_table_or_key_is_an_error_naming_the_file_and_key(tmp_path, text, key):
    path = write(tmp_path, text)
    message = error(path)
    assert message.startswith(f"{path}: ")
    assert "unknown" in message and key in message[len(str(path)):]


# ---------------------------------------------------------------------- bad values

BAD_VALUES = {
    "runtime not known": (LADDER + '[lanes]\nruntime = "podman"\n', "lanes.runtime"),
    "runtime not a string": (LADDER + "[lanes]\nruntime = 1\n", "lanes.runtime"),
    "runtime in capitals": (LADDER + '[lanes]\nruntime = "Docker"\n', "lanes.runtime"),
    "no lanes": (LADDER + "[lanes]\nmax_lanes = 0\n", "lanes.max_lanes"),
    "lanes true": (LADDER + "[lanes]\nmax_lanes = true\n", "lanes.max_lanes"),
    "lanes fraction": (LADDER + "[lanes]\nmax_lanes = 2.5\n", "lanes.max_lanes"),
    "token cap zero": (LADDER + "[lanes]\ntoken_cap = 0\n", "lanes.token_cap"),
    "token cap negative": (LADDER + "[lanes]\ntoken_cap = -5\n", "lanes.token_cap"),
    "token cap true": (LADDER + "[lanes]\ntoken_cap = true\n", "lanes.token_cap"),
    "token cap fraction": (LADDER + "[lanes]\ntoken_cap = 1500.5\n", "lanes.token_cap"),
    "token cap string": (LADDER + '[lanes]\ntoken_cap = "lots"\n', "lanes.token_cap"),
    "dollar cap zero": (LADDER + "[lanes]\ndollar_cap = 0\n", "lanes.dollar_cap"),
    "dollar cap negative": (LADDER + "[lanes]\ndollar_cap = -1.0\n", "lanes.dollar_cap"),
    "dollar cap infinite": (LADDER + "[lanes]\ndollar_cap = inf\n", "lanes.dollar_cap"),
    "dollar cap nan": (LADDER + "[lanes]\ndollar_cap = nan\n", "lanes.dollar_cap"),
    "dollar cap true": (LADDER + "[lanes]\ndollar_cap = true\n", "lanes.dollar_cap"),
    "submit not known": (LADDER + '[lanes]\nsubmit = "yolo"\n', "lanes.submit"),
    "image empty": (LADDER + '[lanes]\nimage = ""\n', "lanes.image"),
    "image is an option": (LADDER + '[lanes]\nimage = "--privileged"\n', "lanes.image"),
    "image with a space": (LADDER + '[lanes]\nimage = "debian bookworm"\n', "lanes.image"),
    "image with a NUL": (LADDER + '[lanes]\nimage = "debian\\u0000:x"\n', "lanes.image"),
    "base_url ftp": (LADDER + '[api]\nbase_url = "ftp://models.example/v1"\n', "api.base_url"),
    "base_url leading space": (LADDER + '[api]\nbase_url = " https://models.example/v1"\n', "api.base_url"),
    "base_url with a newline": (LADDER + '[api]\nbase_url = "https://models.exa\\nmple/v1"\n', "api.base_url"),
    "base_url with a tab": (LADDER + '[api]\nbase_url = "https://models.example/v1\\t"\n', "api.base_url"),
    "base_url no scheme": (LADDER + '[api]\nbase_url = "models.example/v1"\n', "api.base_url"),
    "base_url no host": (LADDER + '[api]\nbase_url = "https://"\n', "api.base_url"),
    "base_url bad port": (LADDER + '[api]\nbase_url = "https://models.example:99999/v1"\n', "api.base_url"),
    "base_url with a password": (LADDER + '[api]\nbase_url = "https://me:pw@models.example/v1"\n', "api.base_url"),
    "key_env not a name": (LADDER + '[api]\nkey_env = "my key"\n', "api.key_env"),
    "key_env starts with a digit": (LADDER + '[api]\nkey_env = "1KEY"\n', "api.key_env"),
    "key_env in lower case": (LADDER + '[api]\nkey_env = "my_api_key"\n', "api.key_env"),
    "key_env in mixed case": (LADDER + '[api]\nkey_env = "OpenRouter_Key"\n', "api.key_env"),
    "key_env too long": (LADDER + f'[api]\nkey_env = "{"K" * 65}"\n', "api.key_env"),
    "key_env not a string": (LADDER + "[api]\nkey_env = 5\n", "api.key_env"),
    "api not a table": ("api = 5\n" + LADDER, "api"),
    "no ladder": ("[lanes]\nmax_lanes = 2\n", "models.ladder"),
    "empty ladder": ("[models]\nladder = []\n", "models.ladder"),
    "ladder not a list": ('[models]\nladder = "vendor/small"\n', "models.ladder"),
    "ladder entry not a string": ('[models]\nladder = ["vendor/small", 3]\n', "models.ladder[1]"),
    "ladder entry empty": ('[models]\nladder = ["vendor/small", ""]\n', "models.ladder[1]"),
    "ladder entry blank": ('[models]\nladder = ["vendor/small", "  "]\n', "models.ladder[1]"),
    "ladder entry padded": ('[models]\nladder = ["vendor/small", " vendor/big"]\n', "models.ladder[1]"),
    "ladder repeats": ('[models]\nladder = ["vendor/small", "vendor/big", "vendor/small"]\n', "models.ladder[2]"),
    "price for a model not in the ladder": (
        LADDER + '[prices."vendor/smal"]\ninput = 1\noutput = 2\n',
        'prices."vendor/smal"',
    ),
    "price negative": (LADDER + '[prices."vendor/small"]\ninput = -1\noutput = 2\n', 'prices."vendor/small".input'),
    "price missing output": (LADDER + '[prices."vendor/small"]\ninput = 1\n', 'prices."vendor/small".output'),
    "price nan": (LADDER + '[prices."vendor/small"]\ninput = nan\noutput = 2\n', 'prices."vendor/small".input'),
    "price infinite": (LADDER + '[prices."vendor/small"]\ninput = 1\noutput = inf\n', 'prices."vendor/small".output'),
    "price string": (LADDER + '[prices."vendor/small"]\ninput = "cheap"\noutput = 2\n', 'prices."vendor/small".input'),
    "price true": (
        LADDER + '[prices."vendor/small"]\ninput = 1\noutput = 2\ncached_input = true\n',
        'prices."vendor/small".cached_input',
    ),
    "price not a table": (LADDER + '[prices]\n"vendor/small" = 1\n', 'prices."vendor/small"'),
    "run dir relative": (LADDER + '[run]\ndir = "runs"\n', "run.dir"),
    "run dir not a string": (LADDER + "[run]\ndir = 5\n", "run.dir"),
    "run dir empty": (LADDER + '[run]\ndir = ""\n', "run.dir"),
    "provider not known": (LADDER + '[api]\nprovider = "claude"\n', "api.provider"),
    "provider in capitals": (LADDER + '[api]\nprovider = "Anthropic"\n', "api.provider"),
    "anthropic without a key": (LADDER + '[api]\nprovider = "anthropic"\nkey_env = ""\n', "api.key_env"),
    "anthropic base_url with /v1": (LADDER + '[api]\nprovider = "anthropic"\nbase_url = "https://api.anthropic.com/v1"\n', "api.base_url"),
    "fallback without a ladder": (LADDER + '[fallback]\nkey_env = "OPENROUTER_API_KEY"\n', "fallback.ladder"),
    "fallback ladder too short": (LADDER + '[fallback]\nladder = ["other/small"]\n', "fallback.ladder"),
    "fallback ladder too long": (LADDER + '[fallback]\nladder = ["a/1", "a/2", "a/3"]\n', "fallback.ladder"),
    "fallback ladder not a list": (LADDER + '[fallback]\nladder = "a/1"\n', "fallback.ladder"),
    "fallback ladder entry empty": (LADDER + '[fallback]\nladder = ["a/1", ""]\n', "fallback.ladder[1]"),
    "fallback ladder entry padded": (LADDER + '[fallback]\nladder = ["a/1", "a/2 "]\n', "fallback.ladder[1]"),
    "fallback provider not known": (LADDER + '[fallback]\nprovider = "x"\nladder = ["a/1", "a/2"]\n', "fallback.provider"),
    "fallback base_url ftp": (LADDER + '[fallback]\nbase_url = "ftp://x.example/v1"\nladder = ["a/1", "a/2"]\n', "fallback.base_url"),
    "fallback key_env lower case": (LADDER + '[fallback]\nkey_env = "my_key"\nladder = ["a/1", "a/2"]\n', "fallback.key_env"),
    "fallback anthropic without a key": (
        LADDER + '[fallback]\nprovider = "anthropic"\nkey_env = ""\nladder = ["a/1", "a/2"]\n', "fallback.key_env"),
    "fallback not a table": ("fallback = 1\n" + LADDER, "fallback"),
}


@pytest.mark.parametrize("text, key", BAD_VALUES.values(), ids=BAD_VALUES.keys())
def test_a_bad_value_is_an_error_naming_the_file_and_key(tmp_path, text, key):
    path = write(tmp_path, text)
    message = error(path)
    assert message.startswith(f"{path}: ")
    assert key in message[len(str(path)):]


def test_errors_show_the_number_that_was_wrong(tmp_path):
    assert "(got 0)" in error(write(tmp_path, LADDER + "[lanes]\nmax_lanes = 0\n"))
    assert "(got -2.5)" in error(write(tmp_path, LADDER + "[lanes]\ndollar_cap = -2.5\n"))


SENTINEL = "zqSentinelValue4471"  # letters and digits only, like many real keys, so gsk_ + it is a valid name

STRING_VALUES = {
    "runtime": (LADDER + f'[lanes]\nruntime = "{SENTINEL}"\n', "lanes.runtime"),
    "submit": (LADDER + f'[lanes]\nsubmit = "{SENTINEL}"\n', "lanes.submit"),
    "image": (LADDER + f'[lanes]\nimage = "-{SENTINEL}"\n', "lanes.image"),
    "max_lanes": (LADDER + f'[lanes]\nmax_lanes = "{SENTINEL}"\n', "lanes.max_lanes"),
    "token_cap": (LADDER + f'[lanes]\ntoken_cap = "{SENTINEL}"\n', "lanes.token_cap"),
    "base_url scheme": (LADDER + f'[api]\nbase_url = "{SENTINEL}"\n', "api.base_url"),
    "base_url password": (LADDER + f'[api]\nbase_url = "https://user:{SENTINEL}@models.example/v1"\n', "api.base_url"),
    "key_env holding a key": (LADDER + f'[api]\nkey_env = "sk-{SENTINEL}"\n', "api.key_env"),
    "key_env holding a key without a dash": (LADDER + f'[api]\nkey_env = "gsk_{SENTINEL}"\n', "api.key_env"),
    "ladder entry": (f'[models]\nladder = [" {SENTINEL}"]\n', "models.ladder[0]"),
    "ladder not a list": (f'[models]\nladder = "{SENTINEL}"\n', "models.ladder"),
    "price": (LADDER + f'[prices."vendor/small"]\ninput = "{SENTINEL}"\noutput = 1\n', 'prices."vendor/small".input'),
    "run dir": (LADDER + f'[run]\ndir = "{SENTINEL}"\n', "run.dir"),
    "provider": (LADDER + f'[api]\nprovider = "{SENTINEL}"\n', "api.provider"),
    "fallback key_env holding a key": (LADDER + f'[fallback]\nkey_env = "sk-{SENTINEL}"\nladder = ["a", "b"]\n', "fallback.key_env"),
    "fallback ladder entry": (LADDER + f'[fallback]\nladder = ["a", " {SENTINEL}"]\n', "fallback.ladder[1]"),
    "fallback base_url": (LADDER + f'[fallback]\nbase_url = "{SENTINEL}"\nladder = ["a", "b"]\n', "fallback.base_url"),
}


@pytest.mark.parametrize("text, key", STRING_VALUES.values(), ids=STRING_VALUES.keys())
def test_errors_never_show_a_string_value(tmp_path, text, key):
    """A string could be the API key pasted into the wrong place, so errors describe it instead."""
    message = error(write(tmp_path, text))
    assert key in message
    assert SENTINEL not in message


# ---------------------------------------------------------------------- the API key


def keyed(tmp_path, key_env: str) -> Config:
    return load_config(write(tmp_path, LADDER + f'[api]\nkey_env = "{key_env}"\n'))


def test_api_key_reads_the_variable_key_env_names(monkeypatch, tmp_path):
    monkeypatch.setenv("FLIGHTDECK_TEST_KEY", FAKE_KEY)
    monkeypatch.setenv("OPENROUTER_API_KEY", "some-other-value")
    assert api_key(keyed(tmp_path, "FLIGHTDECK_TEST_KEY")) == FAKE_KEY


def test_api_key_drops_whitespace_around_the_value(monkeypatch, tmp_path):
    monkeypatch.setenv("FLIGHTDECK_TEST_KEY", f"  {FAKE_KEY}\n")
    assert api_key(keyed(tmp_path, "FLIGHTDECK_TEST_KEY")) == FAKE_KEY


def test_a_server_that_needs_no_key_gets_none(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    assert api_key(keyed(tmp_path, "")) is None


@pytest.mark.parametrize("value", [None, "", "   "], ids=["unset", "empty", "blank"])
def test_a_missing_key_is_an_error_naming_the_variable_and_never_a_value(monkeypatch, tmp_path, value):
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)  # a key is around, just not in the variable named
    if value is None:
        monkeypatch.delenv("FLIGHTDECK_TEST_KEY", raising=False)
    else:
        monkeypatch.setenv("FLIGHTDECK_TEST_KEY", value)
    config = keyed(tmp_path, "FLIGHTDECK_TEST_KEY")
    with pytest.raises(ConfigError) as caught:
        api_key(config)
    message = str(caught.value)
    assert "FLIGHTDECK_TEST_KEY" in message and str(config.source) in message
    assert FAKE_KEY not in message and FAKE_KEY not in repr(caught.value)


KEY_CORE = "FakeTestKey0451xYz"  # synthetic: no real key, and no shape the secret scan knows
PASTED_KEYS = {
    "with dashes": f"sk-{FAKE_KEY}",
    "gsk_ prefix": f"gsk_{KEY_CORE}",
    "hf_ prefix": f"hf_{KEY_CORE}",
    "fw_ prefix": f"fw_{KEY_CORE}",
    "32 bare letters and digits": (KEY_CORE * 2)[:32],
    "64 lower-case hex": "fade" + "0451beef" * 7 + "0451",
}


@pytest.mark.parametrize("pasted", PASTED_KEYS.values(), ids=PASTED_KEYS.keys())
def test_a_key_pasted_into_key_env_is_refused_and_never_shown(tmp_path, pasted):
    """Many keys are only letters, digits and _, so they look like variable names. The error
    that says a variable is not set would name the key itself; key_env must be upper case."""
    with pytest.raises(ConfigError) as caught:
        load_config(write(tmp_path, LADDER + f'[api]\nkey_env = "{pasted}"\n'))
    message = str(caught.value)
    assert "api.key_env" in message
    assert pasted not in message and KEY_CORE not in message and pasted[4:20] not in message


@pytest.mark.parametrize("pasted", PASTED_KEYS.values(), ids=PASTED_KEYS.keys())
def test_api_key_never_shows_a_key_pasted_into_key_env(monkeypatch, pasted):
    """A config built in code skips load_config's check; api_key() still refuses to show it,
    whether or not a variable of that name happens to be set."""
    config = Config(ApiConfig(key_env=pasted), ("m",), {}, LaneConfig(), Path("/runs"), None)
    monkeypatch.delenv(pasted, raising=False)
    with pytest.raises(ConfigError) as caught:
        api_key(config)
    message = str(caught.value)
    assert "api.key_env" in message
    assert pasted not in message and KEY_CORE not in message and pasted[4:20] not in message
    monkeypatch.setenv(pasted, FAKE_KEY)
    with pytest.raises(ConfigError) as caught:
        api_key(config)
    assert pasted not in str(caught.value)


FALLBACK = '[fallback]\nkey_env = "FLIGHTDECK_SPARE_KEY"\nladder = ["other/small", "other/big"]\n'


def test_fallback_key_reads_its_own_variable_and_none_without_a_fallback(monkeypatch, tmp_path):
    monkeypatch.setenv("FLIGHTDECK_SPARE_KEY", f" {FAKE_KEY} ")
    monkeypatch.setenv("OPENROUTER_API_KEY", "the-primary-value")
    assert fallback_key(load_config(write(tmp_path, LADDER + FALLBACK))) == FAKE_KEY
    assert fallback_key(load_config(write(tmp_path, LADDER))) is None


def test_fallback_key_comes_from_the_keys_file_too(monkeypatch, tmp_path):
    keys = tmp_path / "keys.env"
    keys.write_text(f"FLIGHTDECK_SPARE_KEY={FAKE_KEY}\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    monkeypatch.delenv("FLIGHTDECK_SPARE_KEY", raising=False)
    assert fallback_key(load_config(write(tmp_path, LADDER + FALLBACK))) == FAKE_KEY


def test_a_missing_fallback_key_names_its_variable_and_the_way_out(monkeypatch, tmp_path):
    monkeypatch.delenv("FLIGHTDECK_SPARE_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    config = load_config(write(tmp_path, LADDER + FALLBACK))
    with pytest.raises(ConfigError) as caught:
        fallback_key(config)
    message = str(caught.value)
    assert "fallback.key_env names the variable FLIGHTDECK_SPARE_KEY, which is not set" in message
    assert "or remove [fallback] from the config" in message and FAKE_KEY not in message


def test_a_missing_anthropic_key_never_suggests_running_without_one(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(ConfigError) as caught:
        api_key(load_config(write(tmp_path, LADDER + '[api]\nprovider = "anthropic"\n')))
    message = str(caught.value)
    assert "api.key_env names the variable ANTHROPIC_API_KEY, which is not set" in message
    assert 'key_env = ""' not in message  # the Anthropic API needs a key


@pytest.mark.parametrize("name", ["OPENROUTER_API_KEY", "HF_TOKEN", "_KEY", "KEY2", "K" * 64])
def test_upper_case_variable_names_are_taken(monkeypatch, tmp_path, name):
    monkeypatch.setenv(name, FAKE_KEY)
    config = keyed(tmp_path, name)
    assert config.api.key_env == name
    assert api_key(config) == FAKE_KEY


def test_no_config_error_contains_the_key_in_the_environment(monkeypatch, tmp_path):
    """The key sits in the environment while every kind of config error is raised."""
    monkeypatch.setenv("OPENROUTER_API_KEY", FAKE_KEY)
    texts = []
    for text in [*(case for case, _ in BAD_VALUES.values()), LADDER + "[lanes]\nmax_lane = 1\n"]:
        with pytest.raises(ConfigError) as caught:
            load_config(write(tmp_path, text))
        texts.append(str(caught.value))
    with pytest.raises(ConfigError) as caught:
        load_config(tmp_path / "missing.toml")
    texts.append(str(caught.value))
    monkeypatch.delenv("OPENROUTER_API_KEY")
    with pytest.raises(ConfigError) as caught:
        api_key(load_config(write(tmp_path, LADDER)))
    texts.append(str(caught.value))
    assert len(texts) == len(BAD_VALUES) + 3
    assert not [text for text in texts if FAKE_KEY in text]


# ---------------------------------------------------------------------- the example


def filled(example: str) -> str:
    text, n = re.subn(r"^ladder = \[\]$", 'ladder = ["vendor/small-model", "vendor/big-model"]', example, flags=re.M)
    assert n == 1, "the example should have exactly one empty ladder line to fill in"
    return text


def test_the_example_is_toml_that_asks_for_the_ladder(tmp_path):
    tomllib.loads(example_config())
    message = error(write(tmp_path, example_config()))
    assert "models.ladder is empty" in message


def test_the_example_with_the_ladder_filled_in_has_every_default(tmp_path):
    path = write(tmp_path, filled(example_config()))
    config = load_config(path)
    assert config == Config(
        api=ApiConfig(),
        models=("vendor/small-model", "vendor/big-model"),
        prices={},
        lanes=LaneConfig(),
        run_dir=tmp_path / "home" / ".local/share/ctf-flightdeck/runs",
        source=path,
    )


def test_the_example_shows_every_key(tmp_path):
    """Every table and key the loader takes appears in the example, so none is undocumented."""
    text = example_config()
    for table in ("[api]", "[models]", "[prices.", "[lanes]", "[run]"):
        assert table in text
    for key in ("provider", "base_url", "key_env", "ladder", "input", "output", "cached_input", "max_lanes", "runtime",
                "image", "token_cap", "dollar_cap", "submit", "dir", "context"):
        assert re.search(rf"^(# )?{key} = ", text, flags=re.M), key
    assert "# [fallback]" in text


def test_the_example_says_what_auto_submit_fast_mode_l1_flags_and_agent_credentials_do_today():
    text = " ".join(line.lstrip("# ") for line in example_config().splitlines())  # comments as running text
    # auto submits only what a lane claims; everything else still waits
    assert '"auto": a flag a lane claims goes at once; the rest wait for you' in text
    assert '"auto": submitted at once' not in text
    # an L1 engine's flag follows the submit policy; a match in a text engine's output never goes alone
    assert ("a flag an engine returns as its result waits for your approval, or goes at once under submit = \"auto\"; a match "
            "in what a text engine printed always waits.") in text
    # fast mode's rate limit: standard speed until the lane's session ends, which an escalation does
    assert "on a 429 the lane goes on at standard speed for the rest of its session (until an escalation) and says so." in text
    # coding-agent CLIs: a key or a token, by name
    assert ("They use the CLI's own key or token (claude: ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN; codex: CODEX_API_KEY, "
            "or a saved login on the host), never the [api] above.") in text


def test_the_example_fallback_block_loads_once_uncommented(tmp_path):
    text, n = re.subn(r"^# (\[fallback\]|provider = .*|base_url = .*|key_env = .*|ladder = .*)$", r"\1",
                      filled(example_config()), flags=re.M)
    assert n == 5
    config = load_config(write(tmp_path, text))
    assert config.fallback == FallbackConfig("openai", "https://openrouter.ai/api/v1", "OPENROUTER_API_KEY",
                                             ("vendor/small-model", "vendor/big-model"))


def test_the_example_price_block_loads_once_uncommented(tmp_path):
    text, n = re.subn(r"^# (\[prices\..*|input = .*|output = .*|cached_input = .*)$", r"\1", filled(example_config()), flags=re.M)
    assert n == 4
    config = load_config(write(tmp_path, text))
    price = config.prices["vendor/small-model"]
    assert (price.input, price.output, price.cached_input) == (0.10, 0.40, 0.02)



def test_the_default_lane_image_is_the_one_flightdeck_builds():
    from ctf_flightdeck.lane import IMAGE

    assert LaneConfig().image == IMAGE


def test_the_l1_table_names_a_pack_and_how_many_engines_run_at_once(tmp_path):
    config = load_config(write(tmp_path, LADDER + '[l1]\npack = "~/solvers"\nconcurrency = 2\n'))
    assert config.l1 == L1Config(pack=Path("~/solvers").expanduser(), concurrency=2)
    assert load_config(write(tmp_path, LADDER)).l1 == L1Config(pack=None, concurrency=4)  # no pack: no L1 stage
    own = load_config(write(tmp_path, LADDER + '[l1]\npack = "~/solvers"\nimage = "my-pack:1"\n'))
    assert own.l1.image == "my-pack:1" and config.l1.image is None  # unset: engines run in the lane image


@pytest.mark.parametrize(
    "table, message",
    [
        ('pack = "solvers"', "l1.pack must be an absolute path or start with ~"),
        ("pack = 3", "l1.pack must be a string"),
        ("concurrency = 0", "l1.concurrency must be a whole number, at least 1"),
        ('image = "-v /:/host"', "l1.image must be a docker image name"),
        ('image = ""', "l1.image must not be empty"),
        ('lane_tools = "yes"', "l1.lane_tools must be true or false"),
        ('lane_tools = true', "l1.lane_tools needs a pack"),
        ('engines = "x"', "l1.engines"),
    ],
)
def test_a_bad_l1_table_is_an_error_that_names_the_key(tmp_path, table, message):
    with pytest.raises(ConfigError, match=re.escape(message)):
        load_config(write(tmp_path, LADDER + f"[l1]\n{table}\n"))


@pytest.mark.parametrize(
    "text, what",
    [
        ("[models]\nladder = [\"a\"]\nx = " + "9" * 5000 + "\n", "ValueError"),  # a number too long for Python to read
        ("a = " + "[" * 2000 + "]" * 2000 + "\n", "RecursionError"),
    ],
)
def test_a_config_toml_cannot_read_is_a_config_error_not_a_crash(tmp_path, text, what):
    message = error(write(tmp_path, text))
    assert "cannot be read as TOML" in message and what in message


def test_a_path_for_a_user_that_does_not_exist_is_a_config_error(tmp_path, monkeypatch):
    with pytest.raises(ConfigError, match="for a user that does not exist"):
        load_config(Path("~no-such-user-5150/config.toml"))
    monkeypatch.setenv("FLIGHTDECK_CONFIG", "~no-such-user-5150/config.toml")
    with pytest.raises(ConfigError, match=r"\$FLIGHTDECK_CONFIG starts with ~ for a user that does not exist"):
        load_config()



# ---------------------------------------------------------------------- [autopilot]


def test_the_autopilot_table_is_read_and_is_off_with_no_budget_by_default(tmp_path):
    from ctf_flightdeck.config import AutopilotConfig

    plain = load_config(write(tmp_path, filled(example_config())))
    assert plain.autopilot == AutopilotConfig(engage=False, budget_dollars=None, budget_tokens=None)
    text = filled(example_config()) + "\n[autopilot]\nengage = true\nbudget_dollars = 12\nbudget_tokens = 3000000\n"
    text = text.replace("\n[autopilot]\n#", "\n#", 1)  # the example's own, commented table gives way to this one
    assert load_config(write(tmp_path, text)).autopilot == AutopilotConfig(engage=True, budget_dollars=12.0, budget_tokens=3000000)


@pytest.mark.parametrize(("body", "problem"), [
    ("engage = true", "autopilot.engage is true, and autopilot needs a run budget: set budget_dollars or budget_tokens beside it"),
    ("budget_dollars = 0", "autopilot.budget_dollars must be a number above 0: the whole run's budget in dollars (got 0)"),
    ("budget_tokens = 1.5", "autopilot.budget_tokens must be a whole number above 0: the whole run's budget in tokens (got 1.5)"),
    ('engage = "yes"', "autopilot.engage must be true or false (got a string)"),
    ("budget = 5", "autopilot.budget"),
])
def test_a_bad_autopilot_table_is_refused_naming_the_key(tmp_path, body, problem):
    text = filled(example_config()).replace("\n[autopilot]\n#", "\n#", 1) + f"\n[autopilot]\n{body}\n"
    assert problem in error(write(tmp_path, text))


def test_the_example_shows_the_autopilot_table():
    text = example_config()
    assert "\n[autopilot]\n" in text
    for key in ("engage", "budget_dollars", "budget_tokens"):
        assert re.search(rf"^# {key} = ", text, flags=re.M), key
    said = " ".join(line.lstrip("# ") for line in text.splitlines())
    assert "never spends a challenge's last try, and reroutes no request a model declined" in said
    assert "It needs the Docker runtime and a run budget" in said


# ---------------------------------------------------------------------- [governor]


def test_the_governor_table_is_read_and_is_on_with_its_defaults_when_there_is_none(tmp_path):
    from ctf_flightdeck.config import GovernorConfig

    plain = load_config(write(tmp_path, filled(example_config())))  # the example's table is all comments
    assert plain.governor == GovernorConfig(enabled=True, max_load_per_cpu=3.0, min_free_ram_mb=2048, min_free_disk_mb=10240)
    assert load_config(write(tmp_path, LADDER)).governor == GovernorConfig()  # no table at all
    body = "enabled = false\nmax_load_per_cpu = 2\nmin_free_ram_mb = 4096\nmin_free_disk_mb = 0\n"
    text = filled(example_config()).replace("\n[governor]\n#", "\n#", 1) + f"\n[governor]\n{body}"
    assert load_config(write(tmp_path, text)).governor == GovernorConfig(
        enabled=False, max_load_per_cpu=2.0, min_free_ram_mb=4096, min_free_disk_mb=0)
    one = load_config(write(tmp_path, LADDER + "[governor]\nmax_load_per_cpu = 1.5\n")).governor  # the rest keep their defaults
    assert one == GovernorConfig(max_load_per_cpu=1.5)


@pytest.mark.parametrize(("body", "problem"), [
    ('enabled = "no"', "governor.enabled must be true or false (got a string)"),
    ("enabled = 0", "governor.enabled must be true or false (got 0)"),
    ("max_load_per_cpu = -1", "governor.max_load_per_cpu must be a number from 0 to 1000: the load average per CPU above which no "
                              "new lane starts (0: no limit) (got -1)"),
    ("max_load_per_cpu = nan", "governor.max_load_per_cpu must be a number from 0 to 1000"),
    ("max_load_per_cpu = inf", "governor.max_load_per_cpu must be a number from 0 to 1000"),
    ("max_load_per_cpu = true", "governor.max_load_per_cpu must be a number from 0 to 1000"),
    ("min_free_ram_mb = 1.5", "governor.min_free_ram_mb must be a whole number of MiB from 0 to 1073741824: the RAM available below "
                              "which no new lane starts (0: no limit) (got 1.5)"),
    ("min_free_ram_mb = -1", "governor.min_free_ram_mb must be a whole number of MiB"),
    ('min_free_disk_mb = "10 GB"', "governor.min_free_disk_mb must be a whole number of MiB from 0 to 1073741824: the free disk at "
                                   "the run folder below which no new lane starts (0: no limit) (got a string)"),
    ("min_free_disk_mb = 9999999999999", "governor.min_free_disk_mb must be a whole number of MiB"),
    ("max_load = 3", "governor.max_load"),
])
def test_a_bad_governor_table_is_refused_naming_the_key(tmp_path, body, problem):
    assert problem in error(write(tmp_path, LADDER + f"[governor]\n{body}\n"))


def test_the_example_shows_the_governor_table_with_the_defaults_it_has():
    from ctf_flightdeck.config import GovernorConfig

    text = example_config()
    assert "\n[governor]\n" in text
    defaults = GovernorConfig()
    for key in ("enabled", "max_load_per_cpu", "min_free_ram_mb", "min_free_disk_mb"):
        shown = re.search(rf"^# {key} = (\S+) ", text, flags=re.M)
        assert shown, key
        assert tomllib.loads(f"value = {shown.group(1)}")["value"] == getattr(defaults, key), key  # the example shows the default
    said = " ".join(line.lstrip("# ") for line in text.splitlines())
    assert "no NEW lane starts" in said and "it never stops or pauses one" in said and "one lane always starts" in said
