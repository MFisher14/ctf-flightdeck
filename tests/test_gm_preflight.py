"""Pre-flight for a Game Master event profile (platform = "gamemaster"): what it must name,
what check() refuses and warns of, and what describe() says a run will do."""

from __future__ import annotations

from pathlib import Path

import pytest

from ctf_flightdeck.preflight import GM_BOARD, EventProfile, Policies, check, describe, load_profile

TOKEN_SET = {"GM_TOKEN": "set"}


def profile(**fields) -> EventProfile:
    base = dict(name="Fake GM", platform="gamemaster", url="https://gm.example.org", token_env="GM_TOKEN",
                flag_format=r"answer\{(?P<answer>[^{}]+)\}", ai_allowed=True, platform_automation=True, live_targets="allowed")
    return EventProfile(**{**base, **fields})


def policies(submit: str = "confirm", pull: str = "auto") -> Policies:
    return Policies(pull=pull, l1="auto", agents="auto", submit=submit, instance="auto")


def write(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "event.toml"
    path.write_text(
        '[event]\nname = "Fake GM"\nplatform = "gamemaster"\nurl = "https://gm.example.org/"\ntoken_env = "GM_TOKEN"\n'
        f'{extra}[rules]\nai_allowed = true\nplatform_automation = true\nlive_targets = "allowed"\n'
    )
    return path


def test_a_game_master_profile_loads_with_its_url_token_variable_and_board(tmp_path):
    loaded, chosen = load_profile(write(tmp_path, "board = 'pulled'\n"))
    assert (loaded.platform, loaded.url, loaded.token_env) == ("gamemaster", "https://gm.example.org", "GM_TOKEN")
    assert loaded.board == tmp_path / "pulled" and chosen.submit == "confirm"


def test_a_complete_game_master_profile_passes_the_check(tmp_path):
    assert check(profile(), policies(), max_lanes=4, environ=TOKEN_SET) == []
    assert check(profile(board=tmp_path), policies(), max_lanes=4, environ=TOKEN_SET) == []  # its board may be named too


@pytest.mark.parametrize("missing, said", [
    ("url", 'event.url is required for platform "gamemaster"'),
    ("token_env", 'event.token_env is required for platform "gamemaster"'),
])
def test_a_game_master_profile_needs_its_url_and_token_variable(missing, said):
    problems = check(profile(**{missing: None}), policies(), max_lanes=4, environ=TOKEN_SET)
    assert [p.refuse for p in problems] == [True] and problems[0].message.startswith(said)


@pytest.mark.parametrize("pull", ["auto", "confirm", "manual", "off"])
def test_the_pull_policy_refuses_nothing_since_a_run_never_pulls(pull):
    assert check(profile(), policies(pull=pull), max_lanes=4, environ=TOKEN_SET) == []


def test_a_token_variable_that_is_not_set_is_a_warning_only_when_submit_uses_the_platform():
    (problem,) = check(profile(), policies(submit="auto"), max_lanes=4, environ={})
    assert not problem.refuse
    assert problem.message == "the Game Master token variable GM_TOKEN (event.token_env) is not set or is empty: export your token in it"
    assert check(profile(), policies(submit="manual"), max_lanes=4, environ={}) == []


@pytest.mark.parametrize("name", ["OPENAI_API_KEY", "GITHUB_TOKEN", "SOME_SERVICE_API_KEY"])
def test_a_token_variable_that_is_another_services_key_is_refused(name):
    (problem,) = check(profile(token_env=name), policies(), max_lanes=4, environ={name: "set"})
    assert problem.refuse and f"event.token_env names {name}" in problem.message
    assert "not a Game Master token: flightdeck would send its value to https://gm.example.org" in problem.message


def test_a_token_variable_with_gm_in_its_name_is_accepted():
    assert check(profile(token_env="GM_API_KEY"), policies(), max_lanes=4, environ={"GM_API_KEY": "set"}) == []


def test_plain_http_to_another_machine_warns_and_loopback_does_not():
    (problem,) = check(profile(url="http://gm.example.org"), policies(), max_lanes=4, environ=TOKEN_SET)
    assert problem.message == "event.url is http, not https: the Game Master token would cross the network unencrypted"
    assert check(profile(url="http://127.0.0.1:8765"), policies(), max_lanes=4, environ=TOKEN_SET) == []


def test_a_named_board_that_is_no_directory_is_refused(tmp_path):
    (problem,) = check(profile(board=tmp_path / "nope"), policies(), max_lanes=4, environ=TOKEN_SET)
    assert problem.refuse and problem.message.endswith("no such directory")


def test_describe_says_where_answers_go_and_that_a_run_pulls_and_starts_nothing():
    lines = describe(profile(), policies(), environ=TOKEN_SET)
    assert lines[0] == "event     Fake GM · a Game Master at https://gm.example.org · solo"
    assert "token     $GM_TOKEN (set), sent only to https://gm.example.org" in lines
    (pull,) = [line for line in lines if line.startswith("pull ")]
    assert pull.endswith(GM_BOARD) and "pulls nothing and starts no attempt" in pull
