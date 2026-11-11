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
    ApiConfig,
    Config,
    ConfigError,
    LaneConfig,
    api_key,
    default_config_path,
    example_config,
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
    assert (lanes.max_lanes, lanes.runtime, lanes.image) == (4, "docker", "debian:bookworm-slim")
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


def test_false_disables_a_cap_and_an_absent_cap_keeps_its_default(tmp_path):
    config = load_config(write(tmp_path, LADDER + "[lanes]\ntoken_cap = false\n"))
    assert (config.lanes.token_cap, config.lanes.dollar_cap) == (None, 2.0)
    config = load_config(write(tmp_path, LADDER + "[lanes]\ndollar_cap = false\n"))
    assert (config.lanes.token_cap, config.lanes.dollar_cap) == (400_000, None)


def test_the_run_dir_expands_the_home_directory(tmp_path):
    config = load_config(write(tmp_path, LADDER + '[run]\ndir = "~/ctf/runs"\n'))
    assert config.run_dir == tmp_path / "home" / "ctf" / "runs"


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
    ],
    ids=["table", "top-level key", "lanes key", "api key", "models key", "price key", "run key"],
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
    "base_url ftp": (LADDER + '[api]\nbase_url = "ftp://models.example/v1"\n', "api.base_url"),
    "base_url no scheme": (LADDER + '[api]\nbase_url = "models.example/v1"\n', "api.base_url"),
    "base_url no host": (LADDER + '[api]\nbase_url = "https://"\n', "api.base_url"),
    "base_url bad port": (LADDER + '[api]\nbase_url = "https://models.example:99999/v1"\n', "api.base_url"),
    "base_url with a password": (LADDER + '[api]\nbase_url = "https://me:pw@models.example/v1"\n', "api.base_url"),
    "key_env not a name": (LADDER + '[api]\nkey_env = "my key"\n', "api.key_env"),
    "key_env starts with a digit": (LADDER + '[api]\nkey_env = "1KEY"\n', "api.key_env"),
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


SENTINEL = "zq-sentinel-value-4471"

STRING_VALUES = {
    "runtime": (LADDER + f'[lanes]\nruntime = "{SENTINEL}"\n', "lanes.runtime"),
    "submit": (LADDER + f'[lanes]\nsubmit = "{SENTINEL}"\n', "lanes.submit"),
    "image": (LADDER + f'[lanes]\nimage = "-{SENTINEL}"\n', "lanes.image"),
    "max_lanes": (LADDER + f'[lanes]\nmax_lanes = "{SENTINEL}"\n', "lanes.max_lanes"),
    "token_cap": (LADDER + f'[lanes]\ntoken_cap = "{SENTINEL}"\n', "lanes.token_cap"),
    "base_url scheme": (LADDER + f'[api]\nbase_url = "{SENTINEL}"\n', "api.base_url"),
    "base_url password": (LADDER + f'[api]\nbase_url = "https://user:{SENTINEL}@models.example/v1"\n', "api.base_url"),
    "key_env holding a key": (LADDER + f'[api]\nkey_env = "sk-{SENTINEL}"\n', "api.key_env"),
    "ladder entry": (f'[models]\nladder = [" {SENTINEL}"]\n', "models.ladder[0]"),
    "ladder not a list": (f'[models]\nladder = "{SENTINEL}"\n', "models.ladder"),
    "price": (LADDER + f'[prices."vendor/small"]\ninput = "{SENTINEL}"\noutput = 1\n', 'prices."vendor/small".input'),
    "run dir": (LADDER + f'[run]\ndir = "{SENTINEL}"\n', "run.dir"),
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


def test_a_key_pasted_into_key_env_is_never_shown():
    """A config built in code skips load_config's check; api_key() still refuses to echo it."""
    config = Config(ApiConfig(key_env=f"sk-{FAKE_KEY}"), ("m",), {}, LaneConfig(), Path("/runs"), None)
    with pytest.raises(ConfigError) as caught:
        api_key(config)
    assert "api.key_env" in str(caught.value)
    assert FAKE_KEY not in str(caught.value)


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
    for key in ("base_url", "key_env", "ladder", "input", "output", "cached_input", "max_lanes", "runtime",
                "image", "token_cap", "dollar_cap", "submit", "dir"):
        assert re.search(rf"^(# )?{key} = ", text, flags=re.M), key


def test_the_example_price_block_loads_once_uncommented(tmp_path):
    text, n = re.subn(r"^# (\[prices\..*|input = .*|output = .*|cached_input = .*)$", r"\1", filled(example_config()), flags=re.M)
    assert n == 4
    config = load_config(write(tmp_path, text))
    price = config.prices["vendor/small-model"]
    assert (price.input, price.output, price.cached_input) == (0.10, 0.40, 0.02)
