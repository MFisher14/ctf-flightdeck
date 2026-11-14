"""An event on a plugin's platform: what pre-flight says of its profile, the link between a
plugin and the deck (platform/plugin_run.py), and whole runs through `prepare_run`.

Plugins here are synthetic, in tmp_path: plugin_kit's adapter answers from a file, and
fake_platform's talks HTTP to a stand-in platform on 127.0.0.1. Nothing real is contacted.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_flightdeck import config as configs
from ctf_flightdeck import preflight
from ctf_flightdeck.config import ConfigError, load_config
from ctf_flightdeck.preflight import PLUGIN_BOARD, Policies, ProfileError, check, describe, load_profile

from plugin_kit import make_plugin

CONFIG = '[api]\nbase_url = "http://127.0.0.1:11434/v1"\nkey_env = "{key_env}"\n\n[models]\nladder = ["local-model"]\n\n[lanes]\nruntime = "host"\n'
TOKEN_SET = {"ACME_TOKEN": "set"}
NO_TABLE = ('event.platform is not "ctfd", "manual" or "gamemaster", and names no plugin in your config ({has}). '
            "`flightdeck plugin add FOLDER` adds one, after showing you what it runs")


# ---------------------------------------------------------------------- pre-flight


def player_config(tmp_path: Path, *plugins: str, key_env: str = "", toml: str | None = None):
    """The player's config, with a [plugins.NAME] table and a synthetic plugin folder for each name."""
    text = CONFIG.format(key_env=key_env)
    for name in plugins:
        folder = make_plugin(tmp_path / "plugins" / name, name=name, toml=toml)
        text += f'\n[plugins.{name}]\npath = "{folder}"\n'
    path = tmp_path / "config.toml"
    path.write_text(text)
    return load_config(path)


def profile_file(tmp_path: Path, *, platform: str = "acme", url: str | None = "https://ctf.example.test",
                 token_env: str | None = "ACME_TOKEN", board: str | None = "board", automation: bool = True, **policies: str) -> Path:
    lines = ["[event]", 'name = "Quals"', f'platform = "{platform}"']
    lines += [f'{key} = "{value}"' for key, value in (("url", url), ("token_env", token_env), ("board", board)) if value is not None]
    lines += ["[rules]", "ai_allowed = true", f"platform_automation = {str(automation).lower()}", 'live_targets = "off"']
    if policies:
        lines += ["[policies]", *[f'{stage} = "{policy}"' for stage, policy in policies.items()]]
    path = tmp_path / "event.toml"
    path.write_text("\n".join(lines) + "\n")
    return path


def checked(tmp_path: Path, config, *, environ=TOKEN_SET, **fields) -> tuple[list[str], list[str]]:
    """(the refusals, the warnings but the one about the flag format) of check() for a profile."""
    loaded, chosen = load_profile(profile_file(tmp_path, **fields))
    problems = check(loaded, chosen, max_lanes=4, environ=environ, model_config=config)
    return ([p.message for p in problems if p.refuse],
            [p.message for p in problems if not p.refuse and not p.message.startswith("event.flag_format is not set")])


def test_a_profile_on_a_plugin_the_player_added_passes_the_check_and_says_what_a_run_does(tmp_path):
    config = player_config(tmp_path, "acme")
    assert checked(tmp_path, config) == ([], [])
    loaded, chosen = load_profile(profile_file(tmp_path, pull="confirm"))
    lines = describe(loaded, chosen, environ=TOKEN_SET, config=config)
    assert lines[0] == "event     Quals · acme (a plugin) at https://ctf.example.test · solo"
    assert "token     $ACME_TOKEN (set), given only to the acme plugin" in lines
    assert f"pull      confirm  {PLUGIN_BOARD['confirm']} (the rules allow auto)" in lines
    assert "token     $ACME_TOKEN (NOT set), given only to the acme plugin" in describe(loaded, chosen, environ={}, config=config)
    by_policy = {}
    for policy in ("auto", "manual", "off"):
        loaded, chosen = load_profile(profile_file(tmp_path, pull=policy))
        by_policy[policy] = next(line for line in describe(loaded, chosen, environ={}, config=config) if line.startswith("pull"))
    assert "at the start and again every 5 minutes" in by_policy["auto"]
    assert all("it plays the board `flightdeck plugin pull` wrote" in by_policy[policy] for policy in ("manual", "off"))
    assert not any("a folder board: nothing to fetch" in line for line in by_policy.values())  # never said to be a manual board


@pytest.mark.parametrize("plugins, has", [((), "your config has no [plugins] table"), (("acme", "other"), "your config has: acme, other")])
def test_a_platform_no_table_of_the_config_names_is_refused_and_its_value_is_not_shown(tmp_path, plugins, has):
    """The profile may be a teammate's: its word for the platform selects nothing by itself,
    is never played as a folder board, and is not echoed."""
    config = player_config(tmp_path, *plugins)
    (tmp_path / "board").mkdir()  # a folder a manual profile would play
    refusals, warnings = checked(tmp_path, config, platform="harbourctf")
    assert refusals == [NO_TABLE.format(has=has)] and warnings == []
    loaded, chosen = load_profile(profile_file(tmp_path, platform="harbourctf"))
    lines = describe(loaded, chosen, environ=TOKEN_SET, config=config)
    assert lines[0] == "event     Quals · a plugin's platform (not in your config) · solo"
    assert not any(line.startswith("token") for line in lines)
    assert "harbourctf" not in "\n".join(refusals + lines)


@pytest.mark.parametrize("config", [None, ConfigError("/no/such/config.toml: no such file")])
def test_without_a_config_nothing_says_the_plugin_was_added_so_the_run_is_refused(tmp_path, config):
    refusals, _ = checked(tmp_path, config)
    assert refusals == ["event.platform names a plugin's platform, and your config could not be read, so flightdeck cannot "
                        "tell whether you added it"]


def test_a_platform_value_shaped_like_a_token_is_refused_when_the_profile_loads_and_never_shown(tmp_path):
    shaped = "ctfd_" + "0123456789abcdef"  # ctfd_ and 16 hex digits: a plugin's name by its letters, a token by its shape
    assert configs.PLUGIN_NAME.fullmatch(shaped)
    with pytest.raises(ProfileError) as refused:
        load_profile(profile_file(tmp_path, platform=shaped))
    assert shaped not in str(refused.value)
    assert str(refused.value) == (f'{tmp_path / "event.toml"}: event.platform must be "ctfd", "manual", "gamemaster" or the name '
                                  "of a plugin you added (lower-case letters, digits, - and _)")


@pytest.mark.parametrize("variable, key_env, said", [
    ("OPENAI_API_KEY", "", "event.token_env names OPENAI_API_KEY, a variable for another service's key, not a token for this "
                           "platform: flightdeck would hand its value to the acme plugin. Name the variable that holds your "
                           "token for it, like ACME_TOKEN"),
    ("MY_MODEL_KEY", "MY_MODEL_KEY", "event.token_env names MY_MODEL_KEY (api.key_env in your config), a variable for another "
                                     "service's key, not a token for this platform: flightdeck would hand its value to the acme "
                                     "plugin. Name the variable that holds your token for it, like ACME_TOKEN"),
    ("OTHER_API_KEY", "", "event.token_env names OTHER_API_KEY, a name ending in _API_KEY like other services' key variables "
                          "(a name with ACME in it is fine), not a token for this platform: flightdeck would hand its value to "
                          "the acme plugin. Name the variable that holds your token for it, like ACME_TOKEN"),
])
def test_a_token_variable_that_holds_another_services_key_is_refused(tmp_path, variable, key_env, said):
    config = player_config(tmp_path, "acme", key_env=key_env)
    refusals, _ = checked(tmp_path, config, token_env=variable, environ={variable: "set"})
    assert refusals == [said]
    assert checked(tmp_path, config, token_env="ACME_API_KEY", environ={"ACME_API_KEY": "set"})[0] == []  # the platform's own


def test_a_plugin_profile_must_name_the_url_and_the_token_variable_the_plugin_takes(tmp_path):
    config = player_config(tmp_path, "acme")
    assert checked(tmp_path, config, url=None, token_env=None)[0] == [
        "event.url is required for a plugin's platform: the address its adapter talks to",
        'event.token_env is required for platform "acme": the name of the environment variable that holds your token',
    ]
    _, warnings = checked(tmp_path, config, environ={})
    assert warnings == ["the acme token variable ACME_TOKEN (event.token_env) is not set or is empty: export your token in it"]
    _, warnings = checked(tmp_path, config, url="http://ctf.example.test")
    assert warnings == ["event.url is http, not https: the token the acme plugin is given would cross the network unencrypted"]
    assert checked(tmp_path, config, url="http://127.0.0.1:8000") == ([], [])


def test_a_plugin_that_takes_no_token_needs_no_token_variable(tmp_path):
    config = player_config(tmp_path, "acme", toml='name = "acme"\napi = 1\ncommand = ["{python}", "adapter.py"]\ntoken = false\n')
    assert checked(tmp_path, config, token_env=None, environ={}) == ([], [])
    # one named all the same does nothing, a model key's variable included: its value is never handed over
    assert checked(tmp_path, config, token_env="OPENAI_API_KEY", environ={}) == ([], [
        "event.token_env does nothing in this run: the acme plugin takes no token (token = false in its plugin.toml)"])


def test_a_plugin_whose_manifest_cannot_be_used_refuses_the_run_with_its_reason(tmp_path):
    config = player_config(tmp_path, "acme", toml='name = "acme"\napi = 2\ncommand = ["{python}", "adapter.py"]\n')
    (refusal,) = checked(tmp_path, config)[0]
    assert refusal.startswith("plugin acme speaks plugin API 2, and this flightdeck (")
    config = player_config(tmp_path, "acme", toml='name = "other"\napi = 1\ncommand = ["{python}", "adapter.py"]\n')
    (refusal,) = checked(tmp_path, config)[0]
    assert refusal.endswith("says another name than [plugins.acme] in your config: the two must match")


def test_a_board_that_is_a_file_is_refused_and_one_not_there_yet_is_fine(tmp_path):
    config = player_config(tmp_path, "acme")
    assert not (tmp_path / "board").exists() and checked(tmp_path, config) == ([], [])  # a pull makes it
    (tmp_path / "board").write_text("not a folder")
    assert checked(tmp_path, config)[0] == [f"event.board: {tmp_path / 'board'}: is not a directory"]


def test_a_run_that_uses_the_plugin_for_nothing_says_so(tmp_path):
    config = player_config(tmp_path, "acme")
    unused = "this run does not use the acme plugin: pull and submit are both by hand"
    assert checked(tmp_path, config, pull="manual", submit="manual", environ={}) == ([], [unused])
    assert checked(tmp_path, config, automation=False, environ={}) == ([], [unused])  # the rules forbid scripts on the platform
    assert checked(tmp_path, config, pull="manual", submit="confirm") == ([], [])
    refusals, _ = checked(tmp_path, config, automation=False, pull="auto")
    assert refusals == ['the pull policy "auto" is looser than the rules allow (rules.platform_automation = false): it must be '
                        '"manual" or "off"']


def test_the_names_a_plugin_may_not_take_are_the_platforms_flightdeck_has_built_in():
    assert set(configs.RESERVED_PLATFORMS) == set(preflight.PLATFORMS)


def test_policies_is_what_a_plugin_profile_gets_by_default(tmp_path):
    """Like any platform flightdeck uses: the board is pulled, and each flag waits for a yes."""
    _, chosen = load_profile(profile_file(tmp_path))
    assert chosen == Policies(pull="auto", l1="auto", agents="auto", submit="confirm", instance="off")
