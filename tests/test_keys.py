"""The player's keys file: keys kept outside the repository, readable by the owner only, never shown."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from ctf_flightdeck.config import ConfigError, api_key, load_config
from ctf_flightdeck.keys import KeysError, environment, load_keys, source
from ctf_flightdeck.setup import Answers, doctor, report, write_config

SECRET = "value-that-must-never-show-5150"


@pytest.fixture
def keys(tmp_path, monkeypatch):
    path = tmp_path / "keys.env"
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(path))
    monkeypatch.delenv("FLIGHTDECK_TEST_KEY", raising=False)

    def write(text: str, mode: int = 0o600) -> Path:
        path.write_text(text)
        path.chmod(mode)
        return path

    return write


def test_the_keys_file_reads_names_comments_export_and_quotes(keys):
    path = keys(f'# my keys\n\nexport FLIGHTDECK_TEST_KEY="{SECRET}"\nOTHER = \'two words\'\nPLAIN=x=y\n')
    assert load_keys(path) == {"FLIGHTDECK_TEST_KEY": SECRET, "OTHER": "two words", "PLAIN": "x=y"}


def test_no_keys_file_is_no_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "absent.env"))
    assert load_keys() == {}


def test_a_keys_file_others_can_read_is_refused_naming_the_fix(keys):
    path = keys(f"FLIGHTDECK_TEST_KEY={SECRET}\n", mode=0o644)
    with pytest.raises(KeysError, match=f"other users can read it; keep it to yourself with: chmod 600 {path}"):
        load_keys(path)


def test_a_bad_line_is_named_by_number_never_by_its_text(keys):
    path = keys(f"FLIGHTDECK_TEST_KEY={SECRET}\n{SECRET}\n")
    with pytest.raises(KeysError) as caught:
        load_keys(path)
    assert "line 2 is not NAME=value" in str(caught.value) and SECRET not in str(caught.value)


def test_the_environment_wins_over_the_file(keys):
    keys("FLIGHTDECK_TEST_KEY=from-the-file\n")
    assert environment({"PATH": "/bin"})["FLIGHTDECK_TEST_KEY"] == "from-the-file"
    assert environment({"FLIGHTDECK_TEST_KEY": "from-the-shell"})["FLIGHTDECK_TEST_KEY"] == "from-the-shell"
    assert source("FLIGHTDECK_TEST_KEY", {}) == "keys file"
    assert source("FLIGHTDECK_TEST_KEY", {"FLIGHTDECK_TEST_KEY": "x"}) == "environment"


def test_the_api_key_comes_from_the_keys_file_and_doctor_says_where_without_showing_it(keys, tmp_path):
    keys(f"FLIGHTDECK_TEST_KEY={SECRET}\n")
    cfg = write_config(Answers("https://openrouter.ai/api/v1", "FLIGHTDECK_TEST_KEY", ("a/b",), "host"), tmp_path / "c.toml")
    assert api_key(load_config(cfg)) == SECRET
    checks = doctor(cfg, environ={"FLIGHTDECK_KEYS": os.environ["FLIGHTDECK_KEYS"]})
    found = {c.name: c for c in checks}["api key"]
    assert found.ok and found.detail == "FLIGHTDECK_TEST_KEY is set (in your keys file)"
    assert SECRET not in report(checks)[0]


def test_a_missing_key_says_to_put_it_in_the_keys_file(keys, tmp_path):
    keys("SOMETHING_ELSE=x\n")
    cfg = write_config(Answers("https://openrouter.ai/api/v1", "FLIGHTDECK_TEST_KEY", ("a/b",), "host"), tmp_path / "c.toml")
    with pytest.raises(ConfigError, match="put FLIGHTDECK_TEST_KEY=<your key> in .*keys.env \\(chmod 600\\), or export it"):
        api_key(load_config(cfg))
