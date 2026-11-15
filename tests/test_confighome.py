"""flightdeck's config folder follows $XDG_CONFIG_HOME (confighome.py, P94), and a file left at
~/.config/ctf-flightdeck when it points elsewhere is found and said, never ignored in silence."""

from __future__ import annotations

from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from ctf_flightdeck import addchallenge, cli, confighome, keys
from ctf_flightdeck.config import default_config_path, load_config
from ctf_flightdeck.setup import Answers, doctor, write_config

ANSWERS = Answers("https://openrouter.ai/api/v1", "", ("vendor/a",), "host")


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    """A home of the test's own, with neither FLIGHTDECK_CONFIG nor FLIGHTDECK_KEYS set."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("FLIGHTDECK_CONFIG", raising=False)
    monkeypatch.delenv("FLIGHTDECK_KEYS", raising=False)
    return home


@pytest.fixture
def xdg(tmp_path, home, monkeypatch) -> Path:
    """$XDG_CONFIG_HOME set to a folder outside ~/.config."""
    base = tmp_path / "xdg"
    base.mkdir()
    monkeypatch.setenv("XDG_CONFIG_HOME", str(base))
    return base


def old(home: Path) -> Path:
    return home / ".config" / "ctf-flightdeck"


def keys_file(path: Path, text: str = "SOME_TOKEN=from-this-file\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o600)
    return path


def test_without_xdg_config_home_the_folder_is_under_dot_config(home):
    assert default_config_path() == old(home) / "config.toml"
    assert keys.keys_path() == old(home) / "keys.env"
    assert confighome.notes() == []


def test_an_absolute_xdg_config_home_holds_the_config_the_keys_and_the_themes(xdg):
    assert default_config_path() == xdg / "ctf-flightdeck" / "config.toml"
    assert keys.keys_path() == xdg / "ctf-flightdeck" / "keys.env"
    assert keys.keys_file_named() == f"your keys file ({xdg / 'ctf-flightdeck' / 'keys.env'})"
    path = write_config(ANSWERS, default_config_path())
    (path.parent / "themes").mkdir()
    (path.parent / "themes" / "dusk.toml").write_text('base = "flightdeck"\n[colors]\naccent = "#ff5fd7"\n')
    path.write_text(path.read_text() + '\n[console]\ntheme = "dusk"\n')
    assert load_config().console.theme == "dusk"  # read from the themes folder under $XDG_CONFIG_HOME
    assert confighome.notes() == []  # nothing at the old place: nothing to say


@pytest.mark.parametrize("value", ["relative/config", "", "~/somewhere"])
def test_an_xdg_config_home_that_is_not_an_absolute_path_is_ignored(home, monkeypatch, value):
    monkeypatch.setenv("XDG_CONFIG_HOME", value)
    keys_file(old(home) / "keys.env")
    assert default_config_path() == old(home) / "config.toml"
    assert keys.keys_path() == old(home) / "keys.env"
    assert confighome.notes() == []


def test_xdg_config_home_at_dot_config_itself_is_the_usual_folder_and_says_nothing(home, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    write_config(ANSWERS, old(home) / "config.toml")
    assert default_config_path() == old(home) / "config.toml"
    assert confighome.notes() == []


def test_a_config_and_keys_only_at_the_old_place_are_read_there_and_said(home, xdg):
    write_config(ANSWERS, old(home) / "config.toml")
    keys_file(old(home) / "keys.env")
    assert default_config_path() == old(home) / "config.toml"
    assert load_config().source == old(home) / "config.toml"
    assert keys.keys_path() == old(home) / "keys.env"
    assert keys.load_keys() == {"SOME_TOKEN": "from-this-file"}
    lines = confighome.notes()
    assert len(lines) == 2
    assert lines[0].startswith("~/.config/ctf-flightdeck/config.toml is read from the old place")
    assert lines[1].startswith("~/.config/ctf-flightdeck/keys.env is read from the old place")
    assert all(str(xdg / "ctf-flightdeck") in line for line in lines)
    assert not any("from-this-file" in line for line in lines)  # never a file's content


def test_with_a_file_at_both_places_the_new_one_is_read_and_the_old_one_is_said_not_to_be(home, xdg):
    write_config(ANSWERS, old(home) / "config.toml")
    new = write_config(ANSWERS, xdg / "ctf-flightdeck" / "config.toml")
    keys_file(old(home) / "keys.env", "SOME_TOKEN=old\n")
    keys_file(xdg / "ctf-flightdeck" / "keys.env", "SOME_TOKEN=new\n")
    assert default_config_path() == new
    assert keys.load_keys() == {"SOME_TOKEN": "new"}
    lines = confighome.notes()
    assert [line.split(" is ")[0] for line in lines] == ["~/.config/ctf-flightdeck/config.toml", "~/.config/ctf-flightdeck/keys.env"]
    assert all(" is not read: " in line for line in lines)


def test_each_file_is_found_on_its_own(home, xdg):
    """The config at the new place and the keys only at the old one: each is read where it is."""
    new = write_config(ANSWERS, xdg / "ctf-flightdeck" / "config.toml")
    keys_file(old(home) / "keys.env")
    assert default_config_path() == new
    assert keys.keys_path() == old(home) / "keys.env"
    assert confighome.notes() == [confighome.notes()[0]] and "keys.env is read from the old place" in confighome.notes()[0]


def test_a_file_the_player_names_is_never_said_to_be_left_behind(home, xdg, tmp_path, monkeypatch):
    write_config(ANSWERS, old(home) / "config.toml")
    keys_file(old(home) / "keys.env")
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "mine.toml"))
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(tmp_path / "mine.env"))
    assert default_config_path() == tmp_path / "mine.toml"
    assert keys.keys_path() == tmp_path / "mine.env"
    assert confighome.notes() == []


def test_a_themes_folder_left_beside_the_config_that_is_not_read_is_said(home, xdg):
    write_config(ANSWERS, xdg / "ctf-flightdeck" / "config.toml")
    (old(home) / "themes").mkdir(parents=True)
    assert confighome.notes() == [
        f"~/.config/ctf-flightdeck/themes is not read: your themes are read from {xdg / 'ctf-flightdeck' / 'themes'}, "
        "beside the config that is read; move the theme files there"
    ]


def test_init_writes_the_config_under_xdg_config_home(home, xdg):
    result = CliRunner().invoke(cli.app, ["init", "--provider", "openrouter", "--models", "a/b", "--host"])
    assert result.exit_code == 0, result.output
    assert (xdg / "ctf-flightdeck" / "config.toml").is_file()
    assert not old(home).exists()


def test_a_command_says_once_on_stderr_which_file_it_reads_from_the_old_place(home, xdg):
    write_config(ANSWERS, old(home) / "config.toml")
    result = CliRunner().invoke(cli.app, ["config"])
    assert result.exit_code == 0, result.output
    assert f"config: {old(home) / 'config.toml'}" in result.stdout
    said = [line for line in result.stderr.splitlines() if "config.toml is read from the old place" in line]
    assert len(said) == 1 and said[0].startswith("flightdeck: ")


@pytest.mark.parametrize("given", [["config", "--path", "{mine}"], ["config", "--path={mine}"],
                                   ["pack", "info", "--config", "{mine}"], ["records", "--config={mine}", "latest"]])
def test_a_command_given_a_config_of_its_own_says_nothing_of_the_old_config(home, xdg, tmp_path, given):
    """The config the command reads is the one named: the one left at the old place is not
    read, and no line says it is (nor of a themes folder, which is beside the named config)."""
    write_config(ANSWERS, old(home) / "config.toml")
    (old(home) / "themes").mkdir()
    keys_file(old(home) / "keys.env")  # still read from the old place: --config names no keys file
    mine = write_config(ANSWERS, tmp_path / "mine.toml")
    result = CliRunner().invoke(cli.app, [arg.format(mine=mine) for arg in given])
    if given[0] == "config":
        assert result.exit_code == 0, result.output
        assert f"config: {mine}" in result.stdout
    assert "config.toml" not in result.stderr and "themes" not in result.stderr
    said = [line for line in result.stderr.splitlines() if "keys.env is read from the old place" in line]
    assert len(said) == 1


def test_without_a_config_option_the_same_commands_say_the_old_config(home, xdg):
    """The other half of the test above: what silences the line is the option, not the command."""
    write_config(ANSWERS, old(home) / "config.toml")
    for given in (["config"], ["pack", "info"], ["records", "latest"], ["config", "--", "--path"]):
        result = CliRunner().invoke(cli.app, given)
        assert "config.toml is read from the old place" in result.stderr, given


def test_every_option_that_names_a_config_file_is_one_the_root_callback_knows():
    """cli.CONFIG_OPTIONS is what keeps the line above from being said of a config the command
    does not read: a new option for a config file under another name would bring it back."""
    root = typer.main.get_command(cli.app)
    seen = set()

    def walk(command) -> None:
        for param in command.params:
            names_a_file = param.name in ("config", "path") or any("config" in opt for opt in param.opts)
            if names_a_file and not getattr(param, "is_flag", False):  # eval-local's --from-config is a flag
                assert set(param.opts) <= set(cli.CONFIG_OPTIONS), (command.name, param.opts)
                seen.update(param.opts)
        for sub in getattr(command, "commands", {}).values():
            walk(sub)

    walk(root)
    assert seen == set(cli.CONFIG_OPTIONS)


def test_doctor_has_the_config_folder_as_a_check_and_not_also_on_stderr(home, xdg, monkeypatch):
    write_config(ANSWERS, old(home) / "config.toml")
    checks = {c.name: c for c in doctor(environ={"XDG_CONFIG_HOME": str(xdg)})}
    assert checks["config"].ok and str(old(home) / "config.toml") in checks["config"].detail
    found = checks["config folder"]
    assert not found.ok and not found.essential
    assert "config.toml is read from the old place" in found.detail
    assert found.fix == f"keep flightdeck's files in {xdg / 'ctf-flightdeck'}"
    monkeypatch.setattr("ctf_flightdeck.setup.doctor", lambda *a, **k: [])
    result = CliRunner().invoke(cli.app, ["doctor"])
    assert "read from the old place" not in result.stderr


def test_doctor_with_nothing_left_behind_has_no_config_folder_check(home, xdg):
    write_config(ANSWERS, xdg / "ctf-flightdeck" / "config.toml")
    assert "config folder" not in {c.name for c in doctor(environ={"XDG_CONFIG_HOME": str(xdg)})}


def test_neither_config_folder_is_ever_attached_to_a_challenge(home, xdg):
    write_config(ANSWERS, old(home) / "config.toml")
    write_config(ANSWERS, xdg / "ctf-flightdeck" / "config.toml")
    for place in (old(home), xdg / "ctf-flightdeck"):
        assert addchallenge.refusal(place / "config.toml") == f"{place / 'config.toml'} is in flightdeck's config folder: it is never attached"
