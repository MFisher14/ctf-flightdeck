"""Pre-flight: event profiles, the stage policies the rules allow, and the checks before a run.

Profiles are real files in tmp_path. check() and describe() get their environment as a plain
mapping, so the player's own variables never reach a test (or leave one); the CLI tests set
and clear variables with monkeypatch. The deck in the submit tests is the real one, with a
recording driver and verifier standing in for lanes and the platform.
"""

from __future__ import annotations

import errno
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest
import typer
from typer.testing import CliRunner

from ctf_flightdeck import preflight_cli
from ctf_flightdeck.config import Config, ConfigError, load_config
from ctf_flightdeck.core.deck import Deck, QueueEntry
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.interventions import Approve
from ctf_flightdeck.core.model import Challenge, DeckConfig, LaneState, PendingKind
from ctf_flightdeck.platform.manual import cannot_check
from ctf_flightdeck.preflight import (
    MAX_PROFILE_BYTES,
    STAGES,
    EventProfile,
    Policies,
    Policy,
    Problem,
    ProfileError,
    allowed,
    check,
    deck_submit,
    defaults,
    describe,
    example_profile,
    lane_network,
    load_profile,
    looser,
    strictest,
)

AUTO, CONFIRM, MANUAL, OFF = Policy.AUTO, Policy.CONFIRM, Policy.MANUAL, Policy.OFF
TOKEN_ENV = "TEST_CTFD_TOKEN"
FAKE_TOKEN = "fake-platform-token-for-tests-7731"  # not a real token, and not shaped like one
FAKE_KEY = "fake-model-key-for-tests-2208"
# Shaped like CTFd API tokens (ctfd_ and 64 hex digits; older CTFd: 64 hex digits), but made up.
# Built here, so this file never holds a token shape for the secret guard to find.
CTFD_SHAPED = "ctfd_" + "0123456789abcdef" * 4
HEX_SHAPED = "deadbeef" * 8
CONFIRM_ON_HOST = (
    'the instance policy is "confirm", but lanes run on this machine (runtime host): a lane asks you '
    "before its http tool may reach the instance, but its shell has this machine's network and can "
    "reach it before you answer. The docker runtime enforces it (no network until you allow it)"
)

EVENT_CTFD = {
    "name": '"Harbour Lights CTF"',
    "platform": '"ctfd"',
    "url": '"https://ctf.example.org/"',
    "token_env": f'"{TOKEN_ENV}"',
    "flag_format": r"'hl\{[^}]+\}'",
    "team": "true",
}
RULES_OPEN = {"ai_allowed": "true", "platform_automation": "true", "live_targets": '"allowed"'}


def toml(event=None, rules=None, policies=None, extra: str = "") -> str:
    """A profile from tables of key -> TOML value as written. None leaves a table out."""
    lines = []
    for name, table in (("event", event), ("rules", rules), ("policies", policies)):
        if table is not None:
            lines.append(f"[{name}]")
            lines.extend(f"{key} = {value}" for key, value in table.items())
    return "\n".join(lines) + "\n" + extra


def write(tmp_path: Path, text: str, name: str = "event.toml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def load_error(path: Path) -> str:
    with pytest.raises(ProfileError) as caught:
        load_profile(path)
    return str(caught.value)


def profile(**fields) -> EventProfile:
    """A ctfd profile that passes every check, with `fields` changed."""
    base = dict(
        name="Harbour Lights CTF",
        platform="ctfd",
        url="https://ctf.example.org",
        token_env=TOKEN_ENV,
        flag_format=r"hl\{[^}]+\}",
        ai_allowed=True,
        platform_automation=True,
        live_targets="allowed",
    )
    return EventProfile(**{**base, **fields})


def manual(tmp_path: Path, **fields) -> EventProfile:
    """A manual profile with a board folder that exists, with `fields` changed."""
    board = tmp_path / "board"
    board.mkdir(exist_ok=True)
    return profile(**{"platform": "manual", "url": None, "token_env": None, "board": board, **fields})


def policies(pull=AUTO, l1=AUTO, agents=AUTO, submit=CONFIRM, instance=AUTO) -> Policies:
    return Policies(pull=pull, l1=l1, agents=agents, submit=submit, instance=instance)


def as_tuple(p: Policies) -> tuple[str, ...]:
    return tuple(getattr(p, stage).value for stage in STAGES)


TOKEN_SET = {TOKEN_ENV: FAKE_TOKEN}


def refusals(problems: list[Problem]) -> list[str]:
    return [p.message for p in problems if p.refuse]


def warnings(problems: list[Problem]) -> list[str]:
    return [p.message for p in problems if not p.refuse]


def passing(chosen: Policies) -> list[Problem]:
    """What check() says of policies that break no rule, with the runtime unknown: nothing (the
    host's own warnings are tested on their own)."""
    return []


def model_config(tmp_path: Path, *, key_env: str = "TEST_MODEL_KEY", extra: str = "") -> Config:
    path = tmp_path / "config.toml"
    path.write_text(f'[api]\nkey_env = "{key_env}"\n[models]\nladder = ["fake/small"]\n{extra}', encoding="utf-8")
    return load_config(path)


# ---------------------------------------------------------------------- loading a profile


def test_a_ctfd_profile_reads_every_key(tmp_path):
    rules = {**RULES_OPEN, "live_targets": '"confirm"', "max_lanes": "8"}
    path = write(tmp_path, toml(EVENT_CTFD, rules))
    loaded, _ = load_profile(path)
    assert loaded == EventProfile(
        name="Harbour Lights CTF",
        platform="ctfd",
        url="https://ctf.example.org",  # the trailing / is dropped
        token_env=TOKEN_ENV,
        board=None,
        flag_format=r"hl\{[^}]+\}",
        team=True,
        ai_allowed=True,
        platform_automation=True,
        live_targets="confirm",
        max_lanes=8,
        explicit=frozenset(),
        source=path,
    )
    assert re.fullmatch(loaded.flag_format, "hl{lamp_room}")


def test_a_manual_board_is_found_relative_to_the_profile_or_under_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    event = {"name": '"Practice"', "platform": '"manual"'}
    folder = tmp_path / "events" / "practice"
    folder.mkdir(parents=True)
    loaded, _ = load_profile(write(folder, toml({**event, "board": '"board"'}, RULES_OPEN)))
    assert loaded.board == folder / "board"
    loaded, _ = load_profile(write(folder, toml({**event, "board": '"~/ctf/board"'}, RULES_OPEN)))
    assert loaded.board == tmp_path / "home" / "ctf" / "board"
    loaded, _ = load_profile(write(folder, toml({**event, "board": '"/srv/boards/one"'}, RULES_OPEN)))
    assert loaded.board == Path("/srv/boards/one")
    assert (loaded.url, loaded.token_env, loaded.team, loaded.max_lanes) == (None, None, False, None)


def test_a_relative_board_stays_where_the_profile_is_when_the_working_directory_changes(tmp_path, monkeypatch):
    folder = tmp_path / "events"
    folder.mkdir()
    write(folder, toml({"name": '"Practice"', "platform": '"manual"', "board": '"board"'}, RULES_OPEN))
    monkeypatch.chdir(tmp_path)
    loaded, _ = load_profile(Path("events/event.toml"))
    assert loaded.board == folder / "board"
    assert loaded.board.is_absolute()


def test_a_profile_path_under_a_home_that_does_not_exist_is_an_error():
    assert load_error(Path("~no-such-player-6631/event.toml")) == (
        "~no-such-player-6631/event.toml: starts with ~ for a home directory that cannot be found"
    )


def test_policies_the_profile_sets_are_kept_and_the_rest_derived(tmp_path):
    path = write(tmp_path, toml(EVENT_CTFD, {**RULES_OPEN, "live_targets": '"confirm"'}, {"l1": '"manual"', "agents": '"confirm"'}))
    loaded, chosen = load_profile(path)
    assert as_tuple(chosen) == ("auto", "manual", "confirm", "confirm", "confirm")
    assert loaded.explicit == {"l1", "agents"}
    assert all(isinstance(getattr(chosen, stage), Policy) for stage in STAGES)


def test_an_empty_policies_table_derives_every_stage(tmp_path):
    path = write(tmp_path, toml(EVENT_CTFD, RULES_OPEN, {}))
    loaded, chosen = load_profile(path)
    assert loaded.explicit == frozenset()
    assert chosen == defaults(loaded)


def test_a_policy_looser_than_the_rules_loads_and_check_refuses_it(tmp_path):
    rules = {**RULES_OPEN, "ai_allowed": "false"}
    loaded, chosen = load_profile(write(tmp_path, toml(EVENT_CTFD, rules, {"agents": '"auto"'})))
    assert chosen.agents is AUTO  # kept as asked, so check() can name it
    assert len(refusals(check(loaded, chosen, max_lanes=4, environ=TOKEN_SET))) == 1


# ---------------------------------------------------------------------- policies from the rules

DERIVED = [
    # ai_allowed, platform_automation, live_targets -> pull, l1, agents, submit, instance
    (True, True, "allowed", ("auto", "auto", "auto", "confirm", "auto")),
    (True, True, "confirm", ("auto", "auto", "auto", "confirm", "confirm")),
    (True, True, "off", ("auto", "auto", "auto", "confirm", "off")),
    (False, True, "allowed", ("auto", "auto", "off", "confirm", "auto")),
    (True, False, "allowed", ("manual", "auto", "auto", "manual", "auto")),
    (False, False, "off", ("manual", "auto", "off", "manual", "off")),
]


@pytest.mark.parametrize("ai, platform, live, expected", DERIVED)
def test_a_profile_without_policies_gets_them_from_its_rules(tmp_path, ai, platform, live, expected):
    rules = {"ai_allowed": str(ai).lower(), "platform_automation": str(platform).lower(), "live_targets": f'"{live}"'}
    event = {"name": '"Practice"', "platform": '"manual"', "board": '"board"'}
    loaded, chosen = load_profile(write(tmp_path, toml(event, rules)))
    assert as_tuple(chosen) == expected
    assert as_tuple(defaults(loaded)) == expected


@pytest.mark.parametrize("ai, platform, live, expected", DERIVED)
def test_allowed_is_the_loosest_the_rules_permit(ai, platform, live, expected):
    loosest = allowed(profile(ai_allowed=ai, platform_automation=platform, live_targets=live))
    # the same as the derived policies, except that submit may be auto when the platform may be scripted
    assert as_tuple(loosest) == expected[:3] + ("auto" if platform else "manual",) + expected[4:]


def test_submit_defaults_to_confirm_but_a_request_for_auto_is_kept(tmp_path):
    loaded, chosen = load_profile(write(tmp_path, toml(EVENT_CTFD, RULES_OPEN)))
    assert chosen.submit is CONFIRM
    loaded, chosen = load_profile(write(tmp_path, toml(EVENT_CTFD, RULES_OPEN, {"submit": '"auto"'})))
    assert chosen.submit is AUTO
    assert check(loaded, chosen, max_lanes=4, environ=TOKEN_SET) == []


# ---------------------------------------------------------------------- strictness

ORDER = ["auto", "confirm", "manual", "off"]  # loosest first, as documented


@pytest.mark.parametrize("a", range(4))
@pytest.mark.parametrize("b", range(4))
def test_strictness_runs_auto_confirm_manual_off(a, b):
    assert looser(Policy(ORDER[a]), Policy(ORDER[b])) is (a < b)
    assert looser(ORDER[a], ORDER[b]) is (a < b)  # plain strings too
    assert strictest(ORDER[a], ORDER[b]).value == ORDER[max(a, b)]


def test_strictest_of_many_policies():
    assert strictest(AUTO, OFF, CONFIRM) is OFF
    assert strictest(CONFIRM, AUTO) is CONFIRM
    assert strictest(MANUAL) is MANUAL


def test_policies_take_plain_strings_and_refuse_unknown_ones():
    p = Policies(pull="auto", l1="confirm", agents="manual", submit="off", instance="auto")
    assert (p.pull, p.l1, p.agents, p.submit, p.instance) == (AUTO, CONFIRM, MANUAL, OFF, AUTO)
    assert all(type(getattr(p, stage)) is Policy for stage in STAGES)
    with pytest.raises(ValueError, match="submit policy"):
        Policies(pull="auto", l1="auto", agents="auto", submit="sometimes", instance="auto")


# ---------------------------------------------------------------------- refusals

LOOSER = [
    # rules changed, stage, requested policy, the rule the refusal names
    ({"ai_allowed": False}, "agents", AUTO, "rules.ai_allowed = false"),
    ({"ai_allowed": False}, "agents", MANUAL, "rules.ai_allowed = false"),
    ({"platform_automation": False}, "pull", AUTO, "rules.platform_automation = false"),
    ({"platform_automation": False}, "pull", CONFIRM, "rules.platform_automation = false"),
    ({"platform_automation": False}, "submit", AUTO, "rules.platform_automation = false"),
    ({"platform_automation": False}, "submit", CONFIRM, "rules.platform_automation = false"),
    ({"live_targets": "confirm"}, "instance", AUTO, 'rules.live_targets = "confirm"'),
    ({"live_targets": "off"}, "instance", CONFIRM, 'rules.live_targets = "off"'),
    ({"live_targets": "off"}, "instance", MANUAL, 'rules.live_targets = "off"'),
]


@pytest.mark.parametrize("rules, stage, policy, rule", LOOSER)
def test_a_policy_looser_than_the_rules_allow_is_refused_naming_the_rule(tmp_path, rules, stage, policy, rule):
    event = manual(tmp_path, **rules)  # a folder board: no platform checks in the way
    chosen = defaults(event)
    problems = check(event, Policies(**{**dict(chosen.items()), stage: policy}), max_lanes=4, environ={})
    assert len(refusals(problems)) == 1, problems
    message = refusals(problems)[0]
    assert f'the {stage} policy "{policy}" is looser than the rules allow' in message
    assert rule in message
    assert check(event, chosen, max_lanes=4, environ={}) == passing(chosen)  # the derived policies pass


@pytest.mark.parametrize("rules", [{}, {"ai_allowed": False}, {"platform_automation": False}, {"live_targets": "confirm"}, {"live_targets": "off"}])
@pytest.mark.parametrize("stage", STAGES)
def test_any_policy_as_strict_as_the_rules_allow_or_stricter_passes(tmp_path, rules, stage):
    event = manual(tmp_path, **rules)
    limit = getattr(allowed(event), stage)
    for policy in ORDER[ORDER.index(limit):]:
        chosen = Policies(**{**dict(defaults(event).items()), stage: policy})
        assert check(event, chosen, max_lanes=4, environ={}) == passing(chosen), (stage, policy)


@pytest.mark.parametrize("missing, key", [("url", "event.url"), ("token_env", "event.token_env")])
def test_a_ctfd_profile_needs_its_url_and_token_variable(missing, key):
    problems = check(profile(**{missing: None}), policies(), max_lanes=4, environ=TOKEN_SET)
    assert len(refusals(problems)) == 1
    assert refusals(problems)[0].startswith(f'{key} is required for platform "ctfd"')


def test_a_manual_profile_needs_a_board_that_is_a_directory(tmp_path):
    problems = check(manual(tmp_path, board=None), policies(), max_lanes=4, environ={})
    assert refusals(problems) == ['event.board is required for platform "manual": the folder of challenge folders']
    gone = tmp_path / "gone"
    assert refusals(check(manual(tmp_path, board=gone), policies(), max_lanes=4, environ={})) == [f"event.board: {gone}: no such directory"]
    afile = tmp_path / "board.txt"
    afile.write_text("not a folder")
    assert refusals(check(manual(tmp_path, board=afile), policies(), max_lanes=4, environ={})) == [f"event.board: {afile}: is not a directory"]


def test_a_board_whose_name_is_too_long_is_refused_with_the_reason(tmp_path, env):
    # pathlib's is_dir() raises for this (ENAMETOOLONG): one name longer than any file system allows
    name = "\x1b[2J" + "b" * 1000
    problems = check(manual(tmp_path, board=tmp_path / name), policies(), max_lanes=4, environ={})
    reason = f"cannot be read ({os.strerror(errno.ENAMETOOLONG)})"
    assert refusals(problems) == [f"event.board: {tmp_path}/^[[2J{'b' * 1000}: {reason}"]
    event = {"name": '"Practice"', "platform": '"manual"', "board": f'"{"b" * 1000}"', "flag_format": "'x'"}
    result = invoke(str(write(tmp_path, toml(event, RULES_OPEN))))
    assert result.exit_code == 2, result.output
    assert f"refuse: event.board: {tmp_path}/{'b' * 1000}: {reason}" in result.stdout.splitlines()


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0, reason="not run: as root, a folder with no permissions can still be searched")
def test_a_board_in_a_folder_the_player_cannot_open_is_refused_with_the_reason(tmp_path):
    locked = tmp_path / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0o000)  # pathlib's is_dir() raises PermissionError for what is inside
    try:
        problems = check(manual(tmp_path, board=locked / "inner" / "board"), policies(), max_lanes=4, environ={})
    finally:
        locked.chmod(0o755)
    assert refusals(problems) == [f"event.board: {locked}/inner/board: cannot be read ({os.strerror(errno.EACCES)})"]


@pytest.mark.parametrize("pull", [MANUAL, OFF])
def test_a_ctfd_profile_that_may_not_pull_has_no_board_and_is_refused(pull):
    problems = check(profile(), policies(pull=pull), max_lanes=4, environ=TOKEN_SET)
    assert len(refusals(problems)) == 1
    assert f'platform "ctfd" with the pull policy "{pull}"' in refusals(problems)[0]
    assert 'use platform = "manual"' in refusals(problems)[0]
    assert check(profile(), policies(pull=CONFIRM), max_lanes=4, environ=TOKEN_SET) == []


LANES_START = [AUTO, CONFIRM, MANUAL]  # agents policies under which lanes run: on their own, on a yes, when queued


@pytest.mark.parametrize("agents", LANES_START)
def test_more_lanes_than_the_rules_allow_is_refused(agents):
    bounded = profile(max_lanes=8)
    problems = check(bounded, policies(agents=agents), max_lanes=9, environ=TOKEN_SET)
    assert refusals(problems) == [
        "9 lanes at once is more than the rules allow (rules.max_lanes = 8): run with --max-lanes 8 or fewer, "
        "or lower [lanes] max_lanes in your config"
    ]
    assert check(bounded, policies(agents=agents), max_lanes=8, environ=TOKEN_SET) == []
    assert check(bounded, policies(agents=agents), max_lanes=None, environ=TOKEN_SET) == []  # not known yet: not checked
    assert check(profile(), policies(agents=agents), max_lanes=40, environ=TOKEN_SET) == []  # the rules set no bound
    assert check(bounded, policies(agents=OFF), max_lanes=9, environ=TOKEN_SET) == []  # no lanes at all


OTHER_KEYS = [
    "OPENROUTER_API_KEY",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "ANTHROPIC_AUTH_TOKEN",  # Claude Code's
    "HF_TOKEN",
    "MISTRAL_API_KEY",
    "GROQ_API_KEY",
    "XAI_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "GITLAB_TOKEN",
]


@pytest.mark.parametrize("name", OTHER_KEYS)
def test_a_token_variable_that_holds_another_services_key_is_refused(name):
    shared = profile(token_env=name, url="https://collector.example.net")  # a teammate's profile, say
    problems = check(shared, policies(), max_lanes=4, environ={name: FAKE_KEY})
    assert refusals(problems) == [
        f"event.token_env names {name}, a variable for another service's key, not a CTFd token: flightdeck would "
        "send its value to https://collector.example.net. Name the variable that holds your CTFd token, like CTFD_TOKEN"
    ]
    assert FAKE_KEY not in str(problems)


@pytest.mark.parametrize(
    "name, suffix",
    [
        ("NEWMODEL_API_KEY", "_API_KEY"),
        ("SMS_AUTH_TOKEN", "_AUTH_TOKEN"),
        ("CHAT_OAUTH_TOKEN", "_OAUTH_TOKEN"),
        ("STORAGE_ACCESS_KEY", "_ACCESS_KEY"),
        ("SHOP_SECRET_KEY", "_SECRET_KEY"),
        ("DEPLOY_PRIVATE_KEY", "_PRIVATE_KEY"),
        ("CLOUD_SESSION_TOKEN", "_SESSION_TOKEN"),
    ],
)
def test_a_token_variable_named_like_another_services_key_is_refused(name, suffix):
    problems = check(profile(token_env=name), policies(), max_lanes=4, environ={name: FAKE_KEY})
    assert refusals(problems) == [
        f"event.token_env names {name}, a name ending in {suffix} like other services' key variables (a name with "
        "CTFD in it is fine), not a CTFd token: flightdeck would send its value to https://ctf.example.org. Name the "
        "variable that holds your CTFd token, like CTFD_TOKEN"
    ]


@pytest.mark.parametrize("name", ["CTFD_API_KEY", "HARBOUR_CTFD_AUTH_TOKEN", "CTFD_TOKEN", "HARBOUR_TOKEN", "EVENT_API_TOKEN"])
def test_a_token_variable_with_ctfd_in_its_name_or_no_key_suffix_is_accepted(name):
    assert check(profile(token_env=name), policies(), max_lanes=4, environ={name: FAKE_TOKEN}) == []


def test_a_token_variable_that_is_the_configs_api_key_variable_is_refused(tmp_path):
    config = model_config(tmp_path, key_env="MY_LAB_KEY")
    env = {"MY_LAB_KEY": FAKE_KEY}
    problems = check(profile(token_env="MY_LAB_KEY"), policies(), max_lanes=4, environ=env, model_config=config)
    assert len(refusals(problems)) == 1
    assert "event.token_env names MY_LAB_KEY (api.key_env in your config)" in refusals(problems)[0]
    assert FAKE_KEY not in str(problems)


@pytest.mark.parametrize("agents", LANES_START)
def test_rules_that_forbid_live_targets_refuse_lanes_on_the_host(agents):
    closed = profile(live_targets="off")
    chosen = policies(agents=agents, instance=OFF)
    problems = check(closed, chosen, max_lanes=4, environ=TOKEN_SET, runtime="host")
    assert len(refusals(problems)) == 1
    assert 'rules.live_targets = "off"' in refusals(problems)[0] and "docker runtime" in refusals(problems)[0]
    assert check(closed, chosen, max_lanes=4, environ=TOKEN_SET, runtime="docker") == []
    assert check(closed, chosen, max_lanes=4, environ=TOKEN_SET, runtime=None) == []
    assert check(closed, policies(agents=OFF, instance=OFF), max_lanes=4, environ=TOKEN_SET, runtime="host") == []


@pytest.mark.parametrize("instance", [MANUAL, OFF])
def test_keeping_lanes_off_instances_by_choice_on_the_host_is_a_warning(instance):
    problems = check(profile(), policies(instance=instance), max_lanes=4, environ=TOKEN_SET, runtime="host")
    assert refusals(problems) == []
    assert len(warnings(problems)) == 1 and f'the instance policy is "{instance}"' in warnings(problems)[0]
    assert check(profile(), policies(instance=instance), max_lanes=4, environ=TOKEN_SET, runtime="docker") == []


@pytest.mark.parametrize("runtime", ["docker", "host", None])
@pytest.mark.parametrize("agents", LANES_START)
def test_instance_confirm_warns_only_where_a_lanes_shell_can_reach_the_instance_first(agents, runtime):
    # A lane asks before its first model call; in docker it has no network until the player says
    # yes, but on the host its shell has this machine's network all along.
    for rules in ("confirm", "allowed"):  # required by the rules, or chosen
        event = profile(live_targets=rules)
        problems = check(event, policies(agents=agents, instance=CONFIRM), max_lanes=4, environ=TOKEN_SET, runtime=runtime)
        assert problems == ([Problem(False, CONFIRM_ON_HOST)] if runtime == "host" else []), rules
        assert check(event, policies(agents=OFF, instance=CONFIRM), max_lanes=4, environ=TOKEN_SET, runtime=runtime) == []  # no lanes
    for instance in (AUTO, MANUAL, OFF):
        assert check(profile(), policies(agents=agents, instance=instance), max_lanes=4, environ=TOKEN_SET, runtime="docker") == []


def test_an_unknown_runtime_is_a_programming_error():
    with pytest.raises(ValueError, match="runtime"):
        check(profile(), policies(), max_lanes=4, environ=TOKEN_SET, runtime="vm")


# ---------------------------------------------------------------------- warnings and the token


@pytest.mark.parametrize("env", [{}, {TOKEN_ENV: ""}, {TOKEN_ENV: "  \n"}, {"OTHER_TOKEN": FAKE_TOKEN}])
def test_an_unset_or_empty_token_variable_is_a_warning_not_a_refusal(env):
    problems = check(profile(), policies(), max_lanes=4, environ=env)
    assert problems == [
        Problem(False, f"the CTFd token variable {TOKEN_ENV} (event.token_env) is not set or is empty: export your CTFd API token in it")
    ]


def test_a_set_token_variable_is_not_reported():
    assert check(profile(), policies(), max_lanes=4, environ=TOKEN_SET) == []


class Secret(str):
    """A token's value: showing, formatting or comparing it in any way fails the test."""

    def __str__(self):
        raise AssertionError("the token was turned into text")

    __repr__ = __str__

    def __format__(self, spec):
        raise AssertionError("the token was formatted")

    def __eq__(self, other):
        raise AssertionError("the token was compared")

    __hash__ = str.__hash__


class Environ(Mapping):
    """An environment that records which variables were asked for and refuses to be listed."""

    def __init__(self, values):
        self.values = dict(values)
        self.asked: list[str] = []

    def __getitem__(self, key):
        self.asked.append(key)
        return self.values[key]

    def __iter__(self):
        raise AssertionError("the whole environment was listed")

    def __len__(self):
        raise AssertionError("the whole environment was counted")


def test_check_and_describe_only_learn_whether_the_token_is_set():
    env = Environ({TOKEN_ENV: Secret(FAKE_TOKEN), "UNRELATED_SECRET": Secret("other-value")})
    problems = check(profile(), policies(), max_lanes=4, environ=env)
    lines = describe(profile(), policies(), environ=env)
    assert problems == []
    assert set(env.asked) == {TOKEN_ENV}
    assert f"token     ${TOKEN_ENV} (set), sent only to https://ctf.example.org" in lines
    assert FAKE_TOKEN not in "\n".join(lines)
    assert describe(profile(), policies(), environ={})[2] == f"token     ${TOKEN_ENV} (NOT set), sent only to https://ctf.example.org"


def test_the_profile_keeps_the_variables_name_never_its_value(tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, FAKE_TOKEN)
    loaded, chosen = load_profile(write(tmp_path, toml(EVENT_CTFD, RULES_OPEN)))
    assert FAKE_TOKEN not in repr(loaded) and FAKE_TOKEN not in repr(chosen)
    assert check(loaded, chosen, max_lanes=4) == []  # reads os.environ by default


@pytest.mark.parametrize("agents", LANES_START)
def test_agents_without_a_usable_model_config_warn_with_the_reason(tmp_path, agents):
    missing = tmp_path / "missing.toml"
    with pytest.raises(ConfigError) as caught:
        load_config(missing)
    problems = check(profile(), policies(agents=agents), max_lanes=4, environ=TOKEN_SET, model_config=caught.value)
    assert warnings(problems) == [f'the agents policy is "{agents}", but no model config could be loaded: {caught.value}']
    assert str(missing) in warnings(problems)[0]
    assert check(profile(), policies(agents=OFF), max_lanes=4, environ=TOKEN_SET, model_config=caught.value) == []
    assert check(profile(), policies(agents=agents), max_lanes=4, environ=TOKEN_SET, model_config=None) == []


def test_a_token_variable_that_is_the_configs_fallback_key_variable_is_refused(tmp_path):
    config = model_config(tmp_path, extra='[fallback]\nkey_env = "MY_SPARE_KEY"\nladder = ["other/small"]\n')
    env = {"MY_SPARE_KEY": FAKE_KEY, "TEST_MODEL_KEY": FAKE_KEY}
    problems = check(profile(token_env="MY_SPARE_KEY"), policies(), max_lanes=4, environ=env, model_config=config)
    assert len(refusals(problems)) == 1
    assert "event.token_env names MY_SPARE_KEY (fallback.key_env in your config)" in refusals(problems)[0]
    assert FAKE_KEY not in str(problems)


@pytest.mark.parametrize("agents", LANES_START)
def test_agents_whose_fallback_key_variable_is_unset_warn_naming_it(tmp_path, agents):
    config = model_config(tmp_path, extra='[fallback]\nkey_env = "MY_SPARE_KEY"\nladder = ["other/small"]\n')
    env = {**TOKEN_SET, "TEST_MODEL_KEY": FAKE_KEY}
    (warning,) = warnings(check(profile(), policies(agents=agents), max_lanes=4, environ=env, model_config=config))
    assert f'the agents policy is "{agents}", but the fallback API key variable MY_SPARE_KEY (fallback.key_env in' in warning
    assert check(profile(), policies(agents=agents), max_lanes=4, environ={**env, "MY_SPARE_KEY": FAKE_KEY}, model_config=config) == []


@pytest.mark.parametrize("agents", LANES_START)
def test_agents_whose_api_key_variable_is_unset_warn_naming_it(tmp_path, agents):
    config = model_config(tmp_path)
    problems = check(profile(), policies(agents=agents), max_lanes=4, environ=TOKEN_SET, model_config=config)
    assert len(warnings(problems)) == 1
    assert f'the agents policy is "{agents}", but the API key variable TEST_MODEL_KEY (api.key_env in' in warnings(problems)[0]
    env = {**TOKEN_SET, "TEST_MODEL_KEY": FAKE_KEY}
    assert check(profile(), policies(agents=agents), max_lanes=4, environ=env, model_config=config) == []
    assert check(profile(), policies(agents=agents), max_lanes=4, environ=TOKEN_SET, model_config=model_config(tmp_path, key_env="")) == []
    assert check(profile(), policies(agents=OFF), max_lanes=4, environ=TOKEN_SET, model_config=config) == []  # no lanes, no key needed


@pytest.mark.parametrize(
    "url, warned",
    [
        ("http://ctf.example.org", True),
        ("http://10.0.0.7:8000", True),
        ("https://ctf.example.org", False),
        ("http://127.0.0.1:8000", False),
        ("http://localhost:8000", False),
        ("http://ctf.localhost:8000", False),  # *.localhost is loopback too (RFC 6761)
        ("http://localhost.example.org", True),  # but not a name that only starts with it
        ("http://[::1]:8000", False),
    ],
)
def test_plain_http_to_another_machine_warns_that_the_token_would_travel_in_clear(url, warned):
    problems = check(profile(url=url), policies(), max_lanes=4, environ=TOKEN_SET)
    expected = ["event.url is http, not https: the CTFd token would cross the network unencrypted"] if warned else []
    assert warnings(problems) == expected


def test_keys_for_the_other_platform_are_reported_as_unused(tmp_path):
    problems = check(manual(tmp_path, url="https://ctf.example.org"), policies(), max_lanes=4, environ={})
    assert problems == [Problem(False, 'event.url is only for platform "ctfd", so this manual profile does not use it')]
    problems = check(profile(board=tmp_path), policies(), max_lanes=4, environ=TOKEN_SET)
    assert problems == [Problem(False, 'event.board is only for platform "manual", so this ctfd profile does not use it')]


def test_a_missing_flag_format_is_a_warning():
    problems = check(profile(flag_format=None), policies(), max_lanes=4, environ=TOKEN_SET)
    assert len(problems) == 1 and not problems[0].refuse
    assert problems[0].message.startswith("event.flag_format is not set")


def test_refusals_come_before_warnings():
    problems = check(profile(flag_format=None, url=None, max_lanes=2), policies(), max_lanes=3, environ={})
    assert [p.refuse for p in problems] == [True, True, False, False]


# ---------------------------------------------------------------------- errors in the file


@pytest.mark.parametrize(
    "extra, named",
    [
        ("[rule]\nai_allowed = true\n", "unknown table [rule]"),
        ("year = 2026\n", "unknown key year"),
    ],
)
def test_an_unknown_table_or_top_level_key_is_an_error(tmp_path, extra, named):
    message = load_error(write(tmp_path, extra + toml(EVENT_CTFD, RULES_OPEN)))
    assert named in message and "the known tables are [event], [rules], [policies]" in message
    assert message.startswith(f"{tmp_path / 'event.toml'}: ")


@pytest.mark.parametrize(
    "table, key, named",
    [
        ("event", "nmae", "event.nmae"),
        ("event", "token", "event.token"),
        ("rules", "ai", "rules.ai"),
        ("policies", "submitt", "policies.submitt"),
        ("policies", '"hand in"', 'policies."hand in"'),
    ],
)
def test_an_unknown_key_is_an_error_naming_it(tmp_path, table, key, named):
    tables = {"event": dict(EVENT_CTFD), "rules": dict(RULES_OPEN), "policies": {}}
    tables[table][key] = '"auto"'
    message = load_error(write(tmp_path, toml(**tables)))
    assert f"unknown key {named}" in message
    assert message.startswith(f"{tmp_path / 'event.toml'}: ")


BAD_VALUES = [
    ("event", "platform", '"ctfe"', 'event.platform must be "ctfd" or "manual" (got a string)'),
    ("event", "platform", "1", 'event.platform must be "ctfd" or "manual" (got 1)'),
    ("rules", "live_targets", '"maybe"', 'rules.live_targets must be "allowed", "confirm" or "off"'),
    ("policies", "submit", '"sometimes"', 'policies.submit must be "auto", "confirm", "manual" or "off" (got a string)'),
    ("policies", "pull", "true", 'policies.pull must be "auto", "confirm", "manual" or "off" (got true)'),
    ("rules", "max_lanes", "0", "rules.max_lanes must be a whole number, at least 1 (got 0)"),
    ("rules", "max_lanes", "true", "rules.max_lanes must be a whole number, at least 1 (got true)"),
    ("rules", "max_lanes", "2.5", "rules.max_lanes must be a whole number, at least 1 (got 2.5)"),
    ("rules", "max_lanes", '"8"', "rules.max_lanes must be a whole number, at least 1 (got a string)"),
    ("rules", "ai_allowed", '"yes"', "rules.ai_allowed must be true or false (got a string)"),
    ("rules", "platform_automation", "1", "rules.platform_automation must be true or false (got 1)"),
    ("event", "team", '"true"', "event.team must be true or false (got a string)"),
    ("event", "name", '""', "event.name must not be empty"),
    ("event", "name", "[1]", "event.name must be a string (got a list)"),
    ("event", "flag_format", "'hl\\{('", 'event.flag_format does not compile as a regular expression (missing ), unterminated subpattern at position 4): "hl\\{("'),
    ("event", "url", '"ftp://ctf.example.org"', "event.url must start with https:// (or http://) and name a host"),
    ("event", "url", '"https://"', "event.url must start with https:// (or http://) and name a host"),
    ("event", "url", '"https://ctf.example.org:99999"', "event.url must start with https:// (or http://) and name a host"),
    ("event", "url", '"https://player:hunter2@ctf.example.org"', "event.url must not carry a user name or password"),
    ("event", "url", '"https://ctf.example.org/?team=1"', "event.url must be the site's address, with no query"),
    ("event", "url", '"https://ctf.example.org/#top"', "event.url must be the site's address, with no query"),
    ("event", "url", '"https://ctf.example.org/?"', "event.url must be the site's address, with no query"),
    ("event", "url", '"https://ctf example.org"', "event.url must not contain spaces or control characters"),
    # urlsplit drops tabs and newlines without a word, so they must be refused before it sees them
    ("event", "url", '"https://ctf.exa\\tmple.org"', "event.url must not contain spaces or control characters"),
    ("event", "url", '"https://ctf.example.org/\\u001b[2J"', "event.url must not contain spaces or control characters"),
    ("event", "url", '"https://ctf.example.org/\\u202e"', "event.url must not contain spaces or control characters"),
    ("event", "token_env", '"my token"', "event.token_env must be the name of an environment variable"),
    ("event", "token_env", '"9LIVES"', "event.token_env must be the name of an environment variable"),
    (
        "event", "token_env", '"ctfd_token"',
        "event.token_env must be the name of an environment variable, like CTFD_TOKEN (upper-case letters, digits "
        "and _, not starting with a digit, at most 64 characters), not the token itself",
    ),
    ("event", "token_env", '"' + "T" * 65 + '"', "event.token_env must be the name of an environment variable, like CTFD_TOKEN"),
    ("event", "token_env", f'"{CTFD_SHAPED}"', "event.token_env looks like a CTFd API token itself, not the name of the variable"),
    ("event", "token_env", f'"{HEX_SHAPED}"', "event.token_env looks like a CTFd API token itself, not the name of the variable"),
]


@pytest.mark.parametrize("table, key, value, expected", BAD_VALUES)
def test_a_bad_value_is_an_error_naming_the_key(tmp_path, table, key, value, expected):
    tables = {"event": dict(EVENT_CTFD), "rules": dict(RULES_OPEN), "policies": {}}
    tables[table][key] = value
    message = load_error(write(tmp_path, toml(**tables)))
    assert message.startswith(f"{tmp_path / 'event.toml'}: {expected}"), message


def test_a_board_under_a_home_that_does_not_exist_is_an_error(tmp_path):
    event = {"name": '"Practice"', "platform": '"manual"', "board": '"~no-such-player-6631/board"'}
    message = load_error(write(tmp_path, toml(event, RULES_OPEN)))
    assert "event.board starts with ~ for a home directory that cannot be found" in message


@pytest.mark.parametrize(
    "drop, expected",
    [
        ("event.name", "event.name is required: the event's name"),
        ("event.platform", 'event.platform is required: "ctfd"'),
        ("rules.ai_allowed", "rules.ai_allowed is required: true if the event's rules allow AI"),
        ("rules.platform_automation", "rules.platform_automation is required: true if the rules allow scripts"),
        ("rules.live_targets", 'rules.live_targets is required: "allowed", "confirm" or "off"'),
    ],
)
def test_a_missing_required_key_says_what_it_is_for(tmp_path, drop, expected):
    tables = {"event": dict(EVENT_CTFD), "rules": dict(RULES_OPEN)}
    table, key = drop.split(".")
    del tables[table][key]
    assert expected in load_error(write(tmp_path, toml(**tables)))


@pytest.mark.parametrize("table", ["event", "rules"])
def test_a_missing_table_is_an_error(tmp_path, table):
    tables = {"event": EVENT_CTFD, "rules": RULES_OPEN, table: None}
    assert f"the [{table}] table is missing" in load_error(write(tmp_path, toml(**tables)))


@pytest.mark.parametrize(
    "top, tables, expected",
    [
        ("rules = 5\n", {"event": EVENT_CTFD}, "rules must be a table ([rules]) (got 5)"),
        ("event = [1]\n", {"rules": RULES_OPEN}, "event must be a table ([event]) (got a list)"),
        # a teammate's "make everything manual" must not be read as no [policies] (looser, derived ones)
        ('policies = "manual"\n', {"event": EVENT_CTFD, "rules": RULES_OPEN}, "policies must be a table ([policies]) (got a string)"),
    ],
)
def test_a_table_that_is_not_a_table_is_an_error(tmp_path, top, tables, expected):
    path = write(tmp_path, top + toml(**tables))
    assert load_error(path) == f"{path}: {expected}"


@pytest.mark.parametrize("pasted", ["pasted-secret-value-5150", CTFD_SHAPED, HEX_SHAPED])
def test_error_messages_never_show_a_string_from_the_profile(tmp_path, pasted):
    for table, key in [("event", "token_env"), ("event", "platform"), ("event", "url"), ("rules", "live_targets"), ("policies", "agents"), ("rules", "ai_allowed")]:
        tables = {"event": dict(EVENT_CTFD), "rules": dict(RULES_OPEN), "policies": {}}
        tables[table][key] = f'"{pasted}"'
        message = load_error(write(tmp_path, toml(**tables)))
        assert pasted not in message, (table, key)
        assert f"{table}.{key}" in message


@pytest.mark.parametrize("pasted", [CTFD_SHAPED, HEX_SHAPED])
def test_a_token_pasted_into_token_env_is_refused_and_never_shown(tmp_path, env, pasted):
    path = write(tmp_path, toml({**EVENT_CTFD, "token_env": f'"{pasted}"'}, RULES_OPEN))
    message = load_error(path)
    assert message == (
        f"{path}: event.token_env looks like a CTFd API token itself, not the name of the variable that holds it: "
        'export the token (export CTFD_TOKEN=...) and name that variable here, like token_env = "CTFD_TOKEN"'
    )
    result = invoke(str(path), "--config", str(config_file(tmp_path)))
    assert result.exit_code == 2
    assert result.stdout == "" and result.stderr == f"flightdeck: {message}\n"
    # A profile built in code cannot carry one either, so describe() and check() never get one to show.
    with pytest.raises(ValueError) as built:
        profile(token_env=pasted)
    assert str(built.value).startswith("token_env must be the name of an environment variable, like CTFD_TOKEN")
    assert pasted not in str(built.value)


def test_token_env_is_an_upper_case_name_of_at_most_64_characters(tmp_path):
    longest = "T" * 64
    loaded, _ = load_profile(write(tmp_path, toml({**EVENT_CTFD, "token_env": f'"{longest}"'}, RULES_OPEN)))
    assert loaded.token_env == longest
    assert check(loaded, defaults(loaded), max_lanes=4, environ={longest: FAKE_TOKEN}) == []
    for bad in ("T" * 65, "ctfd_token", "Ctfd_Token", "9LIVES", "MY TOKEN", ""):
        with pytest.raises(ValueError, match="^token_env must be the name of an environment variable"):
            profile(token_env=bad)


def test_a_profile_that_cannot_be_read_says_why(tmp_path):
    missing = tmp_path / "missing.toml"
    message = load_error(missing)
    assert message.startswith(f"{missing}: no such file") and "flightdeck preflight --example >" in message
    assert load_error(tmp_path) == f"{tmp_path}: is a directory, not an event profile"
    garbled = tmp_path / "garbled.toml"
    garbled.write_bytes(b"[event]\nname = \"\xff\xfe\"\n")
    assert load_error(garbled) == f"{garbled}: is not UTF-8 text"
    broken = write(tmp_path, "[event\nname = 1\n", "broken.toml")
    assert load_error(broken).startswith(f"{broken}: is not valid TOML")
    huge = tmp_path / "huge.toml"
    huge.write_bytes(b"#" * 1_000_001)
    assert load_error(huge) == f"{huge}: is over 1000 KB, too big for an event profile"


def test_a_profile_of_exactly_the_size_limit_loads(tmp_path):
    body = toml(EVENT_CTFD, RULES_OPEN).encode("utf-8")
    padded = body + b"#" * (MAX_PROFILE_BYTES - len(body) - 1) + b"\n"  # a comment fills it up
    assert len(padded) == MAX_PROFILE_BYTES == 1_000_000
    path = tmp_path / "padded.toml"
    path.write_bytes(padded)
    loaded, _ = load_profile(path)
    assert loaded.name == "Harbour Lights CTF"
    path.write_bytes(padded + b"\n")  # one byte more
    assert load_error(path) == f"{path}: is over 1000 KB, too big for an event profile"


@pytest.mark.parametrize(
    "max_lanes, reason",
    [
        ("9" * 5000, "it holds a number too long to read"),  # int() refuses it: ValueError, not TOMLDecodeError
        ("[" * 5000 + "]" * 5000, "its arrays or tables are nested too deeply to read"),  # RecursionError
    ],
)
def test_a_profile_tomllib_cannot_read_is_an_error_not_a_crash(tmp_path, env, max_lanes, reason):
    path = write(tmp_path, toml(EVENT_CTFD, {**RULES_OPEN, "max_lanes": max_lanes}))
    previous = sys.get_int_max_str_digits()
    sys.set_int_max_str_digits(4300)  # Python's default, whatever PYTHONINTMAXSTRDIGITS says
    try:
        message = load_error(path)
        result = invoke(str(path))
    finally:
        sys.set_int_max_str_digits(previous)
    assert message == f"{path}: is not valid TOML: {reason}"
    assert result.exit_code == 2 and result.stderr == f"flightdeck: {message}\n"


def test_a_toml_error_that_quotes_a_key_shows_it_safely(tmp_path):
    # tomllib quotes the key with repr(), which escapes control characters but not every
    # invisible one: a Hangul filler is printable to Python.
    filler = "\N{HANGUL FILLER}"
    path = write(tmp_path, f'["{filler}"]\n["{filler}"]\n' + toml(EVENT_CTFD, RULES_OPEN))
    message = load_error(path)
    assert message == f"{path}: is not valid TOML: Cannot declare ('\N{REPLACEMENT CHARACTER}',) twice (at line 2, column 5)"
    assert filler not in message


@pytest.mark.parametrize("char, code, shown", [("\\u001b", "U+001B", "^["), ("\\u009b", "U+009B", "\N{REPLACEMENT CHARACTER}")])
def test_a_bad_flag_format_is_shown_safely(tmp_path, env, char, code, shown):
    # The regular expression engine would put the character after "(?" into its message as it
    # is: a control character is refused before it compiles, and shown made visible.
    event = {"name": '"Practice"', "platform": '"manual"', "board": '"board"', "flag_format": f'"(?{char})"'}
    path = write(tmp_path, toml(event, RULES_OPEN))
    message = load_error(path)
    assert message == (
        f"{path}: event.flag_format must have no control, invisible or bidirectional character, but it has {code} "
        f'at position 2: "(?{shown})"'
    )
    result = invoke(str(path))
    assert result.exit_code == 2 and result.stderr == f"flightdeck: {message}\n"
    assert "\x1b" not in result.stderr and "\x9b" not in result.stderr


def test_profile_fields_are_checked_when_built_in_code():
    with pytest.raises(ValueError, match="platform"):
        profile(platform="ctfe")
    with pytest.raises(ValueError, match="live_targets"):
        profile(live_targets="sometimes")
    with pytest.raises(ValueError, match="stages that do not exist"):
        profile(explicit=frozenset({"deploy"}))


# ---------------------------------------------------------------------- lane network


@pytest.mark.parametrize(
    "instance, urls, network",
    [
        (AUTO, ("http://127.0.0.1:8080",), "bridge"),
        (CONFIRM, ("http://127.0.0.1:8080",), "none"),  # connected when the player allows it
        (MANUAL, ("http://127.0.0.1:8080",), "none"),
        (OFF, ("http://127.0.0.1:8080",), "none"),
        (AUTO, (), "none"),
        (CONFIRM, [], "none"),
    ],
)
def test_a_docker_lane_gets_a_network_only_for_an_instance_it_may_reach(instance, urls, network):
    assert lane_network(policies(instance=instance), urls) == network


# ---------------------------------------------------------------------- the submit policy on a real deck


class Clock:
    def now(self) -> float:
        return 100.0


class Driver:
    """Does no lane work; the deck needs one to start lanes."""

    def attach(self, deck): ...
    def start(self, lane, challenge): ...
    def pause(self, lane): ...
    def resume(self, lane): ...
    def hint(self, lane, text): ...
    def redirect(self, lane, text): ...
    def escalate(self, lane, model, summary): ...
    def approved(self, lane, pending): ...
    def rejected(self, lane, flag): ...
    def declined(self, lane, pending): ...
    def stop(self, lane): ...


class Platform:
    """Stands in for the board's verifier (CTFd, an answers file): records every flag handed to it."""

    def __init__(self) -> None:
        self.flags: list[tuple[str, str]] = []

    def __call__(self, challenge_id: str, flag: str) -> bool:
        self.flags.append((challenge_id, flag))
        return flag == "hl{lamp}"


def lane_finds_a_flag(submit: Policy) -> tuple[Deck, Platform]:
    """A run's deck set up as deck_submit() says, with one lane that reports a candidate flag."""
    how = deck_submit(submit)
    platform = Platform()
    deck = Deck(DeckConfig(event="t", submit=how.policy, flag_format=r"hl\{\w+\}"), Driver(), Clock(), platform if how.platform else cannot_check)
    deck.release([Challenge("lamp", "Lamp", "misc", 50)], [QueueEntry("lamp", "fake/small")])
    deck.report("L01", TurnReport(action="cat note.txt", flag="hl{lamp}"))
    return deck, platform


def test_submit_auto_hands_the_flag_to_the_platform_at_once():
    deck, platform = lane_finds_a_flag(AUTO)
    assert platform.flags == [("lamp", "hl{lamp}")]
    assert deck.lanes["L01"].state is LaneState.SOLVED


def test_submit_confirm_waits_for_the_players_approval_then_hands_the_flag_over():
    deck, platform = lane_finds_a_flag(CONFIRM)
    assert platform.flags == []
    assert deck.lanes["L01"].pending.kind is PendingKind.SUBMIT
    outcome = deck.apply(Approve("L01"))
    assert outcome.ok, outcome.message
    assert platform.flags == [("lamp", "hl{lamp}")]
    assert deck.lanes["L01"].state is LaneState.SOLVED


@pytest.mark.parametrize("submit", [MANUAL, OFF])
def test_submit_manual_and_off_never_reach_the_platform_and_ask_the_player_at_once(submit):
    assert deck_submit(submit).platform is False
    deck, platform = lane_finds_a_flag(submit)
    assert platform.flags == []
    lane = deck.lanes["L01"]
    assert lane.pending.kind is PendingKind.CONFIRM  # "submit it yourself, then say if it was accepted"
    assert lane.state is LaneState.WAITING


# ---------------------------------------------------------------------- describe


def test_describe_shows_every_stage_with_its_meaning_and_what_the_rules_would_allow(tmp_path):
    event = profile(max_lanes=8, team=True, live_targets="confirm")
    lines = describe(event, policies(l1=OFF, instance=CONFIRM), environ=TOKEN_SET)
    assert lines[0] == "event     Harbour Lights CTF · ctfd at https://ctf.example.org · team"
    assert lines[1] == "rules     AI allowed · platform automation allowed · live targets confirm · at most 8 lanes"
    assert "flags     hl\\{[^}]+\\}" in lines
    assert "l1        off      no L1 solvers (the rules allow auto)" in lines
    assert "submit    confirm  each flag is submitted after you approve it (the rules allow auto)" in lines
    assert "instance  confirm  each lane asks you before it reaches its challenge's live instance" in lines
    assert lines[-1] == "network   a docker lane has no network until you allow it its instance, then an open one (bridge: any host)"
    assert [line.split()[0] for line in lines[4:9]] == list(STAGES)
    loose = describe(event, policies(instance=AUTO), environ=TOKEN_SET)
    assert "instance  auto     lanes may reach their challenge's live instance (looser than the rules allow: at most confirm)" in loose
    assert loose[-1] == "network   a docker lane gets an open network (bridge: any host) if its challenge has a live instance, else none"
    assert describe(event, policies(instance=OFF), environ=TOKEN_SET)[-1] == 'network   docker lanes get no network (instance "off")'
    assert describe(event, policies(instance=MANUAL), environ=TOKEN_SET)[-1] == 'network   docker lanes get no network (instance "manual")'


NO_PACK_SAID = (
    "there is no [l1] pack in your config, so nothing runs at this stage: set pack = \"FOLDER\" under [l1] in it "
    "(a folder of engines; `flightdeck l1 import` makes their manifests), or give play --pack FOLDER"
)


@pytest.mark.parametrize("l1", [AUTO, CONFIRM, MANUAL])
def test_describe_says_nothing_runs_at_the_l1_stage_when_the_config_names_no_pack_and_how_to_set_one(tmp_path, l1):
    without = load_config(config_file(tmp_path))
    pack = tmp_path / "pack"
    (tmp_path / "with.toml").write_text(config_file(tmp_path).read_text() + f'[l1]\npack = "{pack}"\n')
    with_pack = load_config(tmp_path / "with.toml")
    note = "" if l1 is AUTO else " (the rules allow auto)"
    assert f"l1        {l1.value:<9}{NO_PACK_SAID}{note}" in describe(profile(), policies(l1=l1), environ=TOKEN_SET, config=without)
    meaning = {AUTO: "your no-model solvers run on each challenge", CONFIRM: "your no-model solvers run after you say yes",
               MANUAL: "flightdeck lists the solvers that match; you run them"}[l1]
    for known in (with_pack, ConfigError("no config file"), None):  # a pack, or no config to tell: as before
        assert f"l1        {l1.value:<9}{meaning}{note}" in describe(profile(), policies(l1=l1), environ=TOKEN_SET, config=known)
    off = describe(profile(), policies(l1=OFF), environ=TOKEN_SET, config=without)
    assert "l1        off      no L1 solvers (the rules allow auto)" in off


def test_describe_says_under_submit_auto_only_a_flag_a_lane_claims_goes_at_once_and_counted_tries_always_wait():
    lines = describe(profile(), policies(submit=AUTO), environ=TOKEN_SET)
    assert (
        "submit    auto     a flag a lane claims goes to the platform at once (a model's submit_flag, a coding agent's "
        "FLAG: line, a flag an L1 engine returns as its result); any other match waits for your approval, and so does "
        "every flag of a challenge whose tries the platform counts"
    ) in lines


def test_describe_draws_a_hostile_profile_safely(tmp_path):
    event = manual(tmp_path, name="Night\x1b[2J\x1b]52;c;cGFzdGU=\x07Shift\u202e", flag_format="a\x1b[31m")
    text = "\n".join(describe(event, policies(), environ={}))
    assert "\x1b" not in text and "\x07" not in text and "\u202e" not in text
    assert "Night^[[2J^[]52;c;cGFzdGU=^GShift\ufffd" in text


def test_describe_and_check_draw_a_hostile_board_path_safely(tmp_path):
    # A teammate's profile whose board path carries OSC 52 (write to the clipboard) and a bidi
    # override. The folder does not exist, so check() names the path in its refusal too.
    event = manual(tmp_path, board=tmp_path / "Night\x1b]52;c;cGFzdGU=\x07Shift\N{RIGHT-TO-LEFT OVERRIDE}")
    lines = describe(event, policies(), environ={})
    messages = [problem.message for problem in check(event, policies(), max_lanes=4, environ={})]
    shown = f"{tmp_path}/Night^[]52;c;cGFzdGU=^GShift\N{REPLACEMENT CHARACTER}"
    assert f"board     {shown}" in lines
    assert messages == [f"event.board: {shown}: no such directory"]
    text = "\n".join(lines + messages)
    assert "\x1b" not in text and "\x07" not in text and "\N{RIGHT-TO-LEFT OVERRIDE}" not in text


# ---------------------------------------------------------------------- the command line

runner = CliRunner()
CONFIG = '[api]\nkey_env = "TEST_MODEL_KEY"\n[models]\nladder = ["fake/small"]\n[lanes]\nmax_lanes = {lanes}\nruntime = "{runtime}"\n'


@pytest.fixture
def env(monkeypatch, tmp_path):
    """The token and the API key set to known fakes; no config from the player's shell."""
    monkeypatch.setenv(TOKEN_ENV, FAKE_TOKEN)
    monkeypatch.setenv("TEST_MODEL_KEY", FAKE_KEY)
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "no-config-here.toml"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def config_file(tmp_path: Path, *, lanes: int = 4, runtime: str = "docker") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(CONFIG.format(lanes=lanes, runtime=runtime), encoding="utf-8")
    return path


def invoke(*args: str):
    return runner.invoke(preflight_cli.app, list(args))


def flat(output: str) -> str:
    """CLI output without Rich's box lines, whitespace collapsed: a wrapped message reads as one line."""
    return " ".join(re.sub(r"[│╭╮╰╯─]", " ", output).split())


def test_preflight_prints_the_event_and_every_stage_and_exits_0(tmp_path, env):
    path = write(tmp_path, toml(EVENT_CTFD, {**RULES_OPEN, "max_lanes": "8"}))
    result = invoke(str(path), "--config", str(config_file(tmp_path)))
    assert result.exit_code == 0, result.output
    out = result.stdout.splitlines()
    assert out[0] == f"profile   {path}"
    assert "event     Harbour Lights CTF · ctfd at https://ctf.example.org · team" in out
    for stage, policy in [("pull", "auto"), ("l1", "auto"), ("agents", "auto"), ("submit", "confirm"), ("instance", "auto")]:
        assert any(line.startswith(f"{stage:<10}{policy:<9}") for line in out), stage
    assert f"lanes     4 at a time · runtime docker · config {tmp_path / 'config.toml'}" in out
    assert out[-1] == "preflight: ok"
    assert result.stderr == ""


def test_preflight_says_whether_your_l1_pack_runs_from_the_config_it_checks(tmp_path, env):
    path = write(tmp_path, toml(EVENT_CTFD, RULES_OPEN))
    result = invoke(str(path), "--config", str(config_file(tmp_path)))  # no [l1] in it
    assert result.exit_code == 0, result.output
    assert f"l1        auto     {NO_PACK_SAID}" in result.stdout.splitlines()
    packed = tmp_path / "packed.toml"
    packed.write_text(config_file(tmp_path).read_text() + f'[l1]\npack = "{tmp_path / "pack"}"\n')
    result = invoke(str(path), "--config", str(packed))
    assert "l1        auto     your no-model solvers run on each challenge" in result.stdout.splitlines()


def test_preflight_prints_warnings_and_still_exits_0(tmp_path, env, monkeypatch):
    monkeypatch.delenv(TOKEN_ENV)
    path = write(tmp_path, toml(EVENT_CTFD, RULES_OPEN))
    result = invoke(str(path), "--config", str(config_file(tmp_path)))
    assert result.exit_code == 0
    assert f"warn: the CTFd token variable {TOKEN_ENV} (event.token_env) is not set or is empty" in result.stdout
    assert result.stdout.splitlines()[-1] == "preflight: ok (1 warning)"


def test_preflight_exits_2_when_a_policy_breaks_a_rule(tmp_path, env):
    path = write(tmp_path, toml(EVENT_CTFD, {**RULES_OPEN, "ai_allowed": "false"}, {"agents": '"auto"'}))
    result = invoke(str(path), "--config", str(config_file(tmp_path)))
    assert result.exit_code == 2
    assert 'refuse: the agents policy "auto" is looser than the rules allow (rules.ai_allowed = false)' in result.stdout
    assert result.stdout.splitlines()[-1] == "preflight: refused (1 refusal): a run with this profile must not start"


def test_preflight_checks_lanes_and_runtime_from_the_config_and_the_options(tmp_path, env):
    path = write(tmp_path, toml(EVENT_CTFD, {**RULES_OPEN, "live_targets": '"off"', "max_lanes": "8"}))
    config = str(config_file(tmp_path, lanes=12, runtime="host"))
    result = invoke(str(path), "--config", config)
    assert result.exit_code == 2
    assert "refuse: 12 lanes at once is more than the rules allow (rules.max_lanes = 8)" in result.stdout
    assert 'refuse: rules.live_targets = "off", but lanes would run on this machine (runtime host)' in result.stdout
    assert "preflight: refused (2 refusals)" in result.stdout
    result = invoke(str(path), "--config", config, "--max-lanes", "8", "--docker")
    assert result.exit_code == 0, result.stdout
    assert "lanes     8 at a time · runtime docker" in result.stdout


def test_preflight_warns_when_agents_are_on_and_no_config_can_be_loaded(tmp_path, env):
    path = write(tmp_path, toml(EVENT_CTFD, RULES_OPEN))
    result = invoke(str(path))  # FLIGHTDECK_CONFIG names a file that does not exist
    assert result.exit_code == 0
    assert f'warn: the agents policy is "auto", but no model config could be loaded: {tmp_path / "no-config-here.toml"}: no config file' in result.stdout
    assert "lanes     how many at a time is not known (no config, no --max-lanes)" in result.stdout
    no_ai = write(tmp_path, toml(EVENT_CTFD, {**RULES_OPEN, "ai_allowed": "false"}), "no-ai.toml")
    result = invoke(str(no_ai))
    assert result.exit_code == 0 and "warn:" not in result.stdout
    assert "lanes     none (agents off)" in result.stdout


def test_preflight_never_prints_the_token_or_the_api_key(tmp_path, env):
    for text in (toml(EVENT_CTFD, RULES_OPEN), toml(EVENT_CTFD, {**RULES_OPEN, "ai_allowed": "false"}, {"agents": '"auto"'})):
        path = write(tmp_path, text)
        result = invoke(str(path), "--config", str(config_file(tmp_path)))
        assert FAKE_TOKEN not in result.output and FAKE_KEY not in result.output
        assert f"${TOKEN_ENV} (set)" in result.stdout


def test_preflight_with_a_profile_it_cannot_read_exits_2_with_the_reason(tmp_path, env):
    path = write(tmp_path, toml(EVENT_CTFD, {**RULES_OPEN, "live_targets": '"sometimes"'}))
    result = invoke(str(path))
    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.startswith(f'flightdeck: {path}: rules.live_targets must be "allowed", "confirm" or "off"')


def test_preflight_with_a_profile_under_a_home_that_does_not_exist_exits_2_with_the_reason(env):
    result = invoke("~no-such-player-6631/event.toml")  # quoted, so the shell leaves the ~ alone
    assert result.exit_code == 2, result.exception
    assert result.stdout == ""
    assert result.stderr == "flightdeck: ~no-such-player-6631/event.toml: starts with ~ for a home directory that cannot be found\n"


@pytest.mark.parametrize("how", ["--config", "FLIGHTDECK_CONFIG"])
def test_preflight_with_a_config_under_a_home_that_does_not_exist_warns_with_the_reason(tmp_path, env, monkeypatch, how):
    path = write(tmp_path, toml(EVENT_CTFD, RULES_OPEN))
    named = "~no-such-player-6631/config.toml"
    if how == "--config":
        result = invoke(str(path), "--config", named)
        reason = f"{named}: starts with ~ for a home directory that cannot be found"
    else:
        monkeypatch.setenv("FLIGHTDECK_CONFIG", named)
        result = invoke(str(path))
        reason = "the config file ($FLIGHTDECK_CONFIG, else ~/.config/ctf-flightdeck/config.toml) is under a home directory that cannot be found"
    assert result.exit_code == 0, result.exception
    assert f'warn: the agents policy is "auto", but no model config could be loaded: {reason}' in result.stdout.splitlines()
    assert "lanes     how many at a time is not known (no config, no --max-lanes)" in result.stdout


def test_preflight_without_a_profile_is_a_usage_error(env):
    result = invoke()
    assert result.exit_code == 2
    assert "name the event profile to check, or use --example to print one" in flat(result.output)


def test_the_example_profile_loads_and_passes_warning_only_of_the_unset_token(tmp_path, env, monkeypatch):
    result = invoke("--example")
    assert result.exit_code == 0 and result.stdout == example_profile()
    loaded, chosen = load_profile(write(tmp_path, result.stdout))
    assert (loaded.name, loaded.platform, loaded.token_env) == ("Example CTF", "ctfd", "CTFD_TOKEN")
    assert re.fullmatch(loaded.flag_format, "example{x}")
    assert as_tuple(chosen) == ("auto", "auto", "auto", "confirm", "confirm")
    assert check(loaded, chosen, max_lanes=4, environ={"CTFD_TOKEN": FAKE_TOKEN}) == []
    unset = check(loaded, chosen, max_lanes=4, environ={})
    assert refusals(unset) == [] and len(warnings(unset)) == 1  # the unset token
    assert warnings(unset)[0].startswith("the CTFd token variable CTFD_TOKEN (event.token_env) is not set")


def test_preflight_mounts_as_one_command_with_options_after_the_profile(tmp_path, env):
    root = typer.Typer()

    @root.callback()
    def main() -> None:
        """flightdeck"""

    root.add_typer(preflight_cli.app, name="preflight")  # the integrator's one line
    path = write(tmp_path, toml(EVENT_CTFD, RULES_OPEN))
    result = runner.invoke(root, ["preflight", str(path), "--config", str(config_file(tmp_path)), "--max-lanes", "2"])
    assert result.exit_code == 0, result.output
    assert "lanes     2 at a time · runtime docker" in result.stdout
    usage = runner.invoke(root, ["preflight", "--help"])
    assert "Usage: root preflight [OPTIONS] [EVENT.toml]" in " ".join(usage.stdout.split())
    assert "COMMAND" not in usage.stdout
