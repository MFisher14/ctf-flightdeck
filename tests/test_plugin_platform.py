"""An event on a plugin's platform: what pre-flight says of its profile, the link between a
plugin and the deck (platform/plugin_run.py), and whole runs through `prepare_run`.

Plugins here are synthetic, in tmp_path: plugin_kit's adapter answers from a file, and
fake_platform's talks HTTP to a stand-in platform on 127.0.0.1. Nothing real is contacted.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from ctf_flightdeck import config as configs
from ctf_flightdeck import preflight, preflight_cli
from ctf_flightdeck.config import ConfigError, load_config
from ctf_flightdeck.core import interventions as iv
from ctf_flightdeck.core.driver import TurnReport
from ctf_flightdeck.core.model import ChallengeStatus, EventKind, LaneState, PendingKind
from ctf_flightdeck.platform.gamemaster import GameMasterClient
from ctf_flightdeck.platform.gamemaster_run import GameMasterLink
from ctf_flightdeck.platform.link import PlatformLink
from ctf_flightdeck.platform.plugin_run import PluginLink
from ctf_flightdeck.plugins.call import CallFailed, Verdict
from ctf_flightdeck.preflight import PLUGIN_BOARD, Policies, ProfileError, check, describe, load_profile

from ctf_flightdeck.addchallenge import NewChallenge
from ctf_flightdeck.platform.manual import cannot_check
from ctf_flightdeck.plugins import board as boards
from ctf_flightdeck.plugins import manifest
from ctf_flightdeck.plugins.call import Caller
from ctf_flightdeck.run import RunError, RunOptions, prepare_run

import plugin_kit
from fake_ctfd import Reply
from fake_model import FakeModelServer
from fake_platform import FLAG_FORMAT, FakePlatform, FakeTask, make_adapter, sample
from fake_platform import TOKEN as PLATFORM_TOKEN
from plugin_kit import make_plugin
from test_console import OSC, open_focus, osc, screen_text, terminal_frame
from test_deck import events, lane_on
from test_event_run import Model, config, log, model_api, play, platform_solves, submit, wait_for  # noqa: F401
from test_platform_submit import asked, chall, notes, platform_deck

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
    assert "token     $ACME_TOKEN (set), given only to the acme plugin, for https://ctf.example.test" in lines
    assert f"pull      confirm  {PLUGIN_BOARD['confirm']} (the rules allow auto)" in lines
    assert ("token     $ACME_TOKEN (NOT set), given only to the acme plugin, for https://ctf.example.test"
            in describe(loaded, chosen, environ={}, config=config))
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
                          "(a name that starts with ACME_ is fine), not a token for this platform: flightdeck would hand its value to "
                          "the acme plugin. Name the variable that holds your token for it, like ACME_TOKEN"),
])
def test_a_token_variable_that_holds_another_services_key_is_refused(tmp_path, variable, key_env, said):
    config = player_config(tmp_path, "acme", key_env=key_env)
    refusals, _ = checked(tmp_path, config, token_env=variable, environ={variable: "set"})
    assert refusals == [said]
    assert checked(tmp_path, config, token_env="ACME_API_KEY", environ={"ACME_API_KEY": "set"})[0] == []  # the platform's own


NOT_ITS_OWN = ("event.token_env names {name}, a variable that is not named for this platform (its name does not start with "
               "{own}_), so it may hold another service's or another event's secret, not a token for this platform: flightdeck "
               "would hand its value to the {plugin} plugin. Name the variable that holds your token for it, like {own}_TOKEN")


@pytest.mark.parametrize("variable", ["NPM_TOKEN", "CTFD_TOKEN", "CTFD_TOKEN_OTHER_EVENT", "DISCORD_WEBHOOK_URL", "GM_TOKEN", "TOKEN",
                                      "ACMETOKEN", "MY_ACME_TOKEN", "ACME"])
def test_a_plugins_token_variable_is_one_named_for_the_plugin(tmp_path, variable):
    """The profile may be a teammate's: the one variable it can have handed to the plugin is one
    whose name starts with the plugin's own, never another event's token or a secret no list knows."""
    config = player_config(tmp_path, "acme")
    refusals, _ = checked(tmp_path, config, token_env=variable, environ={variable: "set"})
    assert refusals == [NOT_ITS_OWN.format(name=variable, own="ACME", plugin="acme")]
    for own in ("ACME_TOKEN", "ACME_TOKEN_QUALS", "ACME_KEY"):
        assert checked(tmp_path, config, token_env=own, environ={own: "set"}) == ([], [])


def test_a_short_plugin_name_does_not_let_a_variable_through_that_only_has_its_letters(tmp_path):
    config = player_config(tmp_path, "ai")  # "AI" is in MAILGUN and in OPENAI
    refusals, _ = checked(tmp_path, config, platform="ai", token_env="MAILGUN_API_KEY", environ={"MAILGUN_API_KEY": "set"})
    assert refusals == ["event.token_env names MAILGUN_API_KEY, a name ending in _API_KEY like other services' key variables "
                        "(a name that starts with AI_ is fine), not a token for this platform: flightdeck would hand its value to "
                        "the ai plugin. Name the variable that holds your token for it, like AI_TOKEN"]
    refusals, _ = checked(tmp_path, config, platform="ai", token_env="RAIL_TOKEN", environ={"RAIL_TOKEN": "set"})
    assert refusals == [NOT_ITS_OWN.format(name="RAIL_TOKEN", own="AI", plugin="ai")]
    assert checked(tmp_path, config, platform="ai", token_env="AI_TOKEN", environ={"AI_TOKEN": "set"}) == ([], [])


@pytest.mark.parametrize("table, where, what", [
    ('[fallback]\nbase_url = "http://127.0.0.1:11435/v1"\nkey_env = "{v}"\nladder = ["local-model"]\n', "fallback.key_env",
     "a variable for another service's key"),
    ('[light]\nengine = "openai"\nmodel = "small"\nbase_url = "http://127.0.0.1:11436/v1"\nkey_env = "{v}"\n', "light.key_env",
     "a variable for another service's key"),
    ('[notify]\nwebhook_env = "{v}"\n', "notify.webhook_env", "the variable that holds your notification webhook's URL"),
])
def test_no_secret_the_config_names_is_a_plugins_token_whatever_its_name(tmp_path, table, where, what):
    """A variable the player's config uses for a key of its own is that key, named for the plugin or not."""
    variable = "ACME_SECRET"
    config_file = tmp_path / "config.toml"
    player_config(tmp_path, "acme")
    config_file.write_text(config_file.read_text() + "\n" + table.replace("{v}", variable))
    refusals, _ = checked(tmp_path, load_config(config_file), token_env=variable, environ={variable: "set"})
    assert refusals == [f"event.token_env names {variable} ({where} in your config), {what}, not a token for this platform: "
                        "flightdeck would hand its value to the acme plugin. Name the variable that holds your token for it, "
                        "like ACME_TOKEN"]


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


def test_flightdeck_preflight_checks_a_plugin_profile_against_the_config_it_is_given(tmp_path, monkeypatch):
    """The command passes the player's config to the check, so it says what a run would: the
    plugin by the config's name, or a refusal that does not show the profile's word."""
    monkeypatch.setenv("ACME_TOKEN", "set")
    monkeypatch.setenv("FLIGHTDECK_CONFIG", str(tmp_path / "no-config-here.toml"))
    config = player_config(tmp_path, "acme")
    runner = CliRunner()
    good = runner.invoke(preflight_cli.app, [str(profile_file(tmp_path)), "--config", str(config.source), "--docker"])
    assert good.exit_code == 0, good.output
    out = good.stdout.splitlines()
    assert "event     Quals · acme (a plugin) at https://ctf.example.test · solo" in out
    assert "token     $ACME_TOKEN (set), given only to the acme plugin, for https://ctf.example.test" in out and out[-1].startswith("preflight: ok")
    other = runner.invoke(preflight_cli.app, [str(profile_file(tmp_path, platform="harbourctf")), "--config", str(config.source), "--docker"])
    assert other.exit_code == 2 and "harbourctf" not in other.output
    assert "refuse: " + NO_TABLE.format(has="your config has: acme") in other.stdout.splitlines()
    absent = runner.invoke(preflight_cli.app, [str(profile_file(tmp_path)), "--docker"])  # no config at all
    assert absent.exit_code == 2
    assert ("refuse: event.platform names a plugin's platform, and your config could not be read, so flightdeck cannot tell "
            "whether you added it") in absent.stdout.splitlines()


# ---------------------------------------------------------------------- the link, at the deck


class FakeCaller:
    """Stands in for plugins.call.Caller: answers each submit with the next scripted outcome (a
    Verdict, or an exception to raise) and each solved() with the next scripted list."""

    url = "https://ctf.example.test"
    token = ""

    def __init__(self, *outcomes, solved=()) -> None:
        self.outcomes = list(outcomes)
        self.solved_replies = list(solved)
        self.submits: list[tuple[str, str]] = []
        self.gate: asyncio.Event | None = None  # set: each submit waits for it before it answers

    async def submit(self, ref: str, flag: str) -> Verdict:
        self.submits.append((ref, flag))
        if self.gate is not None:
            await self.gate.wait()
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def solved(self) -> set[str]:
        reply = self.solved_replies.pop(0) if len(self.solved_replies) > 1 else self.solved_replies[0]
        if isinstance(reply, BaseException):
            raise reply
        return set(reply)


def linked(tmp_path: Path, *outcomes, challenges=(), submit: str = "auto", refs=None, solved=(), **options):
    """A real deck whose submitter is a PluginLink on a FakeCaller. c0 has the ref 17, c1 the ref 23."""
    caller = FakeCaller(*outcomes, solved=options.pop("listed", ()))
    link = PluginLink(caller, "acme", tmp_path / "board", {"c0": "17", "c1": "23"} if refs is None else refs,
                      solved=solved, pulls=False, **options)
    deck, driver, _ = platform_deck(*challenges, submit=submit, submitter=link)
    link.deck = deck
    link.told = []
    link.needs_human = link.told.append
    link.waits = []

    async def nap(seconds: float) -> None:
        link.waits.append(seconds)

    link.sleep = nap
    return deck, link, caller


def drive(link: PluginLink, body) -> None:
    """Run `body()` with the link's submit worker going, then stop the worker."""

    async def main():
        worker = asyncio.create_task(link.work())
        try:
            await body()
        finally:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

    asyncio.run(main())


async def settled(link: PluginLink, deck, cid: str = "c0") -> None:
    """Wait until nothing of the challenge is on its way to the platform."""
    for _ in range(2000):
        if link.queue.empty() and link.sending is None and not deck.submitting(cid):
            return
        await asyncio.sleep(0.001)
    raise AssertionError("the link did not answer in time")


def warnings(deck) -> list[str]:
    """The link's own warnings (the deck's, of a challenge whose tries are counted, are not its)."""
    return [e.text for e in events(deck, EventKind.WARNING) if e.data.get("source") == "plugin"]


def test_both_links_are_what_a_run_asks_of_a_platform(tmp_path):
    """Run.links treats the Game Master's link and a plugin's alike: each has all of PlatformLink."""
    _, link, _ = linked(tmp_path)
    assert isinstance(link, PlatformLink)

    async def gm() -> bool:
        async with GameMasterClient("http://127.0.0.1:9/", "fake-gm-token-for-this-test") as client:  # never called
            return isinstance(GameMasterLink(client, {}), PlatformLink)

    assert asyncio.run(gm())
    assert not isinstance(object(), PlatformLink)


def test_a_correct_flag_goes_out_with_the_challenges_ref_and_solves_it(tmp_path):
    deck, link, caller = linked(tmp_path, Verdict("correct", "ok"))
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        assert lane.state is LaneState.RUNNING  # the lane carries on until the answer is in
        await settled(link, deck)

    drive(link, body)
    assert caller.submits == [("17", "t{c0}")]  # the platform's own id, once
    assert lane.state is LaneState.SOLVED and deck.challenges["c0"].status is ChallengeStatus.SOLVED
    assert link.held() == {"c0"} and warnings(deck) == [] and link.told == []
    (event,) = events(deck, EventKind.SUBMIT)
    assert (event.data["correct"], event.data["by"], event.data["detail"]) == (True, "platform", "ok")


def test_an_incorrect_flag_is_recorded_wrong_with_the_tries_the_platform_says_are_left(tmp_path):
    deck, link, caller = linked(tmp_path, Verdict("incorrect", "nope", tries_left=2))
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{bad}"))
        await settled(link, deck)

    drive(link, body)
    ch = deck.challenges["c0"]
    assert deck.not_flag("c0", "t{bad}") is not None and deck.wrong_flags("c0") == 1
    assert ch.tries_left == 2 and ch.limited and not ch.closed and lane.state is LaneState.RUNNING
    assert warnings(deck) == [] and link.told == []
    assert [e.text for e in events(deck, EventKind.WARNING)] == [  # the deck's own word: its flags wait for the player now
        "the platform counts the tries at the flag of Chall 0 (2 tries left): from now on its flags wait for you, under submit auto too"]
    (event,) = events(deck, EventKind.SUBMIT)
    assert (event.data["correct"], event.data["tries_left"]) == (False, 2)


NO_VERDICT = [
    (Verdict("unjudged", "frozen"), "the platform gave no verdict on it (frozen)"),
    (Verdict("unjudged"), "the platform gave no verdict on it"),
    (CallFailed("it gave no answer within 30 s", timed_out=True),
     "it gave no answer within 30 s; it may have reached the platform: check the challenge there before you submit it again"),
    (CallFailed("its answer is not one JSON object"), "its answer is not one JSON object"),
    (CallFailed("verdict must be one of correct, incorrect, already_solved, rate_limited, unjudged"),
     "verdict must be one of correct, incorrect, already_solved, rate_limited, unjudged"),
    (CallFailed("it exited with status 1: HTTP 500"), "it exited with status 1: HTTP 500"),
    (RuntimeError("a bug in the caller"),
     "flightdeck could not submit it (RuntimeError: a bug in the caller); it may have reached the platform: check the challenge "
     "there before you submit it again"),
]


@pytest.mark.parametrize("outcome, why", NO_VERDICT)
def test_no_verdict_gives_the_flag_back_to_the_player_and_never_records_it_wrong(tmp_path, outcome, why):
    """An answer that is not correct, incorrect or already_solved, and a call that failed, is
    no verdict: the player submits the flag by hand and says how it went, a warning says
    why, and autopilot is told."""
    deck, link, caller = linked(tmp_path, outcome)
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        await settled(link, deck)

    drive(link, body)
    assert caller.submits == [("17", "t{c0}")]  # sent once, never again by itself
    assert asked(lane) == [(PendingKind.CONFIRM, "t{c0}")]  # with the player: submit it by hand, then say how it went
    assert deck.not_flag("c0", "t{c0}") is None and deck.wrong_flags("c0") == 0 and not deck.challenges["c0"].closed
    assert warnings(deck) == [f"the acme plugin did not judge t{{c0}} for Chall 0: {why}"]
    assert link.told == [f"the acme plugin did not judge a flag: {why}"]
    assert [e.challenge for e in events(deck, EventKind.WARNING)] == ["c0"]
    assert deck.apply(iv.Approve(lane.id)).ok and deck.challenges["c0"].status is ChallengeStatus.SOLVED  # the player's word


def state_file(board: Path, refs: dict[str, str]) -> None:
    """The board's plugin.json, as a pull through the acme plugin from the FakeCaller's address writes it."""
    board.mkdir(exist_ok=True)
    (board / "plugin.json").write_text(json.dumps({"format": 1, "plugin": "acme", "url": FakeCaller.url, "refs": refs}))


def test_a_challenge_with_no_ref_is_never_sent_and_goes_back_to_the_player(tmp_path):
    deck, link, caller = linked(tmp_path, refs={"c1": "23"})
    state_file(tmp_path / "board", {"c1": "23"})
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        await settled(link, deck)

    drive(link, body)
    why = "c0 was not pulled through the plugin, so flightdeck has nowhere to send its flag: submit it by hand, then say whether it was accepted"
    assert caller.submits == [] and asked(lane) == [(PendingKind.CONFIRM, "t{c0}")]
    assert warnings(deck) == [f"the acme plugin did not judge t{{c0}} for Chall 0: {why}"] and len(link.told) == 1


def test_a_ref_a_pull_wrote_since_is_found_when_its_flag_goes_out_and_a_board_file_that_is_gone_is_said_once(tmp_path):
    deck, link, caller = linked(tmp_path, Verdict("correct"), refs={})
    first, second = lane_on(deck, "c0"), lane_on(deck, "c1")

    async def body():
        deck.report(first.id, TurnReport(action="solve.py", flag="t{c0}"))  # no plugin.json in the board folder at all
        await settled(link, deck, "c0")
        state_file(tmp_path / "board", {"c1": "23"})  # a pull in another terminal
        deck.report(second.id, TurnReport(action="solve.py", flag="t{c1}"))
        await settled(link, deck, "c1")

    drive(link, body)
    assert caller.submits == [("23", "t{c1}")] and second.state is LaneState.SOLVED and link.refs == {"c1": "23"}
    assert asked(first) == [(PendingKind.CONFIRM, "t{c0}")]
    assert warnings(deck)[0] == (
        f"{tmp_path / 'board'} was not pulled by the acme plugin, so flightdeck has nowhere to send its flags: `flightdeck "
        "plugin pull EVENT.toml` first, or set policies.pull to auto or confirm; flags of challenges added since the last read "
        "are not sent")
    assert len(warnings(deck)) == 2 and warnings(deck)[1].startswith("the acme plugin did not judge t{c0} for Chall 0: ")


def test_a_rate_limited_flag_is_sent_again_after_the_wait_the_plugin_gives(tmp_path):
    limited = Verdict("rate_limited", "slow down", retry_after=7)
    deck, link, caller = linked(tmp_path, limited, Verdict("rate_limited"), Verdict("rate_limited", retry_after=9000), Verdict("correct"))
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        await settled(link, deck)

    drive(link, body)
    assert caller.submits == [("17", "t{c0}")] * 4
    assert link.waits == [8.0, 65.0, 300.0]  # what the plugin asked and a second; none named; never longer than RESEND_MAX
    assert lane.state is LaneState.SOLVED and warnings(deck) == [] and link.told == []
    assert ("the platform rate-limited the submission of t{c0} and did not check it; flightdeck sends it again in 8s "
            "(send 2 of 4)") in notes(lane)


def test_a_flag_rate_limited_every_time_goes_back_to_the_player_after_three_more_sends(tmp_path):
    deck, link, caller = linked(tmp_path, *[Verdict("rate_limited", "slow down", retry_after=1)] * 4)
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        await settled(link, deck)

    drive(link, body)
    assert len(caller.submits) == 4 and link.waits == [2.0, 2.0, 2.0]  # the first send and RESENDS more
    assert asked(lane) == [(PendingKind.CONFIRM, "t{c0}")] and deck.not_flag("c0", "t{c0}") is None
    why = "the platform rate-limited it and did not check it (slow down)"
    assert warnings(deck) == [f"the acme plugin did not judge t{{c0}} for Chall 0: {why}"]
    assert link.told == [f"the acme plugin did not judge a flag: {why}"]


@pytest.mark.parametrize("challenge, verdict", [
    (chall("c0", max_attempts=3), Verdict("rate_limited", retry_after=1)),  # the board says its tries are counted
    (chall("c0"), Verdict("rate_limited", retry_after=1, tries_left=2)),  # the platform says so with the answer
])
def test_a_rate_limited_flag_is_never_sent_again_where_tries_are_counted(tmp_path, challenge, verdict):
    deck, link, caller = linked(tmp_path, verdict, challenges=(challenge, chall("c1")), submit="confirm")
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        assert deck.apply(iv.Approve(lane.id)).ok  # the player's yes: it goes out
        await settled(link, deck)

    drive(link, body)
    assert len(caller.submits) == 1 and link.waits == []
    assert asked(lane) == [(PendingKind.CONFIRM, "t{c0}")] and deck.not_flag("c0", "t{c0}") is None


def test_no_tries_left_with_no_verdict_closes_the_challenge_and_asks_nobody(tmp_path):
    deck, link, caller = linked(tmp_path, Verdict("unjudged", "no attempts left", tries_left=0))
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        await settled(link, deck)

    drive(link, body)
    assert deck.challenges["c0"].tries_left == 0 and asked(lane) == [] and deck.not_flag("c0", "t{c0}") is None
    assert warnings(deck) == [] and link.told == []  # no hand submit to ask for: the deck says the rest
    (said,) = [e.text for e in events(deck, EventKind.WARNING)]
    assert said.startswith("Chall 0 is out of tries: the platform checks no more flags for it") and "t{c0} is not known to be wrong" in said


def test_already_solved_closes_the_challenge_as_the_platforms_solve(tmp_path):
    deck, link, caller = linked(tmp_path, Verdict("already_solved", "dup"))
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        await settled(link, deck)

    drive(link, body)
    ch = deck.challenges["c0"]
    assert ch.status is ChallengeStatus.TEAMMATE and ch.solved_by == "your account" and lane.state is LaneState.STOPPED
    assert deck.not_flag("c0", "t{c0}") is None and warnings(deck) == [] and link.told == []
    assert link.held() == {"c0"}


def test_the_solved_list_closes_what_the_platform_lists_but_not_a_flag_on_its_way(tmp_path):
    deck, link, caller = linked(tmp_path, Verdict("correct"), solved={"23"})
    assert link.held() == {"c1"}
    link.apply_solved(before_run=True)
    assert deck.challenges["c1"].status is ChallengeStatus.TEAMMATE and not deck.challenges["c0"].closed
    (event,) = events(deck, EventKind.TEAMMATE)
    assert (event.data["who"], event.data["before_run"]) == ("your account", True)
    lane = lane_on(deck, "c0")
    caller.gate = asyncio.Event()

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        for _ in range(1000):
            if caller.submits:
                break
            await asyncio.sleep(0.001)
        link.solved.add("17")  # listed as solved while our flag is at the platform: the solve may be that flag's
        link.apply_solved()
        assert not deck.challenges["c0"].closed
        caller.gate.set()
        await settled(link, deck)

    drive(link, body)
    assert deck.challenges["c0"].status is ChallengeStatus.SOLVED and lane.state is LaneState.SOLVED  # ours, not the platform's


def test_a_solved_list_that_cannot_be_read_warns_once_while_it_lasts_and_tells_autopilot_after_three(tmp_path):
    failure = CallFailed("it exited with status 1: HTTP 502")
    deck, link, caller = linked(tmp_path, listed=[failure, failure, failure, failure, {"23"}, CallFailed("it gave no answer within 30 s")],
                                solves_seconds=0.005)

    async def main():
        watching = asyncio.create_task(link.watch())
        for _ in range(2000):
            if len(warnings(deck)) == 2:
                break
            await asyncio.sleep(0.001)
        watching.cancel()
        await asyncio.gather(watching, return_exceptions=True)

    asyncio.run(main())
    assert warnings(deck) == [
        "could not read the solved list from the acme plugin: it exited with status 1: HTTP 502; flightdeck reads it again in 0.005 s",
        "could not read the solved list from the acme plugin: it gave no answer within 30 s; flightdeck reads it again in 0.005 s",
    ]
    assert link.told[0] == "reading the solved list from the acme plugin has failed 3 times in a row: it exited with status 1: HTTP 502"
    assert link.told.count(link.told[0]) == 1  # once, at the third failure in a row
    assert deck.challenges["c1"].status is ChallengeStatus.TEAMMATE  # the read that worked in between was applied


def test_flags_on_their_way_when_the_run_ends_are_named(tmp_path):
    deck, link, caller = linked(tmp_path, Verdict("correct"))
    first, second = lane_on(deck, "c0"), lane_on(deck, "c1")
    caller.gate = asyncio.Event()

    async def body():
        deck.report(first.id, TurnReport(action="solve.py", flag="t{c0}"))
        deck.report(first.id, TurnReport(action="solve.py", flag="t{again}"))
        deck.report(second.id, TurnReport(action="solve.py", flag="t{c1}"))
        for _ in range(1000):
            if caller.submits:
                break
            await asyncio.sleep(0.001)

    drive(link, body)  # the worker is cancelled with the first flag at the platform
    assert caller.submits == [("17", "t{c0}")]
    assert link.unsent() == [
        f"acme plugin: t{{c0}} ({first.id}, Chall 0) was on its way to the platform when the run ended, so it is not known to "
        "have been submitted: check the challenge there before you submit it again",
        f"acme plugin: t{{c1}} ({second.id}, Chall 1) was not submitted: it was waiting to go to the platform when the run ended",
        f"acme plugin: t{{again}} ({first.id}, Chall 0) was not submitted: it was waiting for the answer to another flag of that "
        "challenge when the run ended",
    ]


# ---------------------------------------------------------------------- a whole run


TOKEN_VAR = "ACME_TOKEN"


@pytest.fixture
def token(monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, PLATFORM_TOKEN)


def yes(question: str) -> bool:
    return True


def event_file(tmp_path: Path, url: str, *, board: Path | None = None, **policies: str) -> Path:
    lines = ["[event]", 'name = "Fake Quals"', 'platform = "acme"', f'url = "{url}"', f'token_env = "{TOKEN_VAR}"',
             f"board = '{board or tmp_path / 'board'}'", f"flag_format = '{FLAG_FORMAT}'",
             "[rules]", "ai_allowed = true", "platform_automation = true", 'live_targets = "allowed"']
    if policies:
        lines += ["[policies]", *[f'{stage} = "{policy}"' for stage, policy in policies.items()]]
    path = tmp_path / "event.toml"
    path.write_text("\n".join(lines) + "\n")
    return path


def run_options(tmp_path: Path, url: str, plugin: Path, server=None, *, max_lanes: int = 1, pull: str = "auto",
                submit_policy: str = "auto", **options) -> RunOptions:
    """Options for a run of the acme event: the plugin in `plugin` is the one the config allows."""
    path = config(tmp_path, server.base_url if server is not None else None, max_lanes=max_lanes)
    path.write_text(path.read_text() + f'\n[plugins.acme]\npath = "{plugin}"\n')
    return RunOptions(event=event_file(tmp_path, url, pull=pull, submit=submit_policy), config=path, **options)


def acme_run(tmp_path: Path, fake: FakePlatform, server=None, **options):
    """A run of the acme event against the fake platform, through the synthetic adapter."""
    return prepare_run(run_options(tmp_path, fake.url, make_adapter(tmp_path / "acme"), server, **options))


def kinds(fake: FakePlatform) -> list[str]:
    return [kind for r in list(fake.requests) for kind in ("challenges", "file", "solved", "attempt") if r in fake.sent(kind)]


def plugin_warnings(run) -> list[str]:
    return [e["text"] for e in log(run) if e["kind"] == "warning" and e["data"].get("source") == "plugin"]


def lane_for(run, challenge_id: str):
    return next(lane for lane in run.deck.lanes.values() if lane.challenge_id == challenge_id)


def test_a_run_pulls_the_board_through_the_plugin_and_a_correct_flag_is_accepted_once(tmp_path, token):
    with FakePlatform(sample()) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{nope}"), submit("t{warm}")]})) as server:
        run = acme_run(tmp_path, fake, server)
        assert kinds(fake) == ["challenges", "file", "solved"]  # one pull with its file, one solved list: before anything starts
        board = tmp_path / "board"
        assert (board / "warm-up" / "note.txt").read_bytes() == b"a synthetic handout\n"
        assert run.plug is not None and run.plug.pulls and run.deck.submitter is run.plug and run.links == [run.plug]
        assert run.plug.refs == {"warm-up": "17", "web-thing": "23", "done-before": "31"}

        async def body(run):
            assert run.deck.challenges["done-before"].status is ChallengeStatus.TEAMMATE  # listed as solved: no lane
            assert [lane.challenge_id for lane in run.deck.lanes.values()] == ["warm-up"]
            await wait_for(lambda: run.deck.challenges["warm-up"].status is ChallengeStatus.SOLVED, "the solve")

        play(run, body)
        assert fake.attempts() == [(17, "t{nope}"), (17, "t{warm}")]  # each flag went out once
        assert all(r.headers["authorization"] == f"Bearer {PLATFORM_TOKEN}" for r in fake.requests)
    submitted = [(e["data"]["flag"], e["data"]["correct"], e["data"]["by"]) for e in log(run) if e["kind"] == "submit"]
    assert submitted == [("t{nope}", False, "platform"), ("t{warm}", True, "platform")]
    assert platform_solves(run) == [("done-before", "your account", True)]
    assert lane_for(run, "warm-up").state is LaneState.SOLVED and plugin_warnings(run) == [] and run.errors == []
    said = run.notes()
    assert f"flags go to {fake.url} through the acme plugin" in said
    assert f"board: 3 challenges from {fake.url} through the acme plugin in {board} (3 new); flightdeck pulls again every 300 s" in said
    everything = run.log.path.read_text() + "\n".join(said) + (run.dir / "status.json").read_text()
    assert PLATFORM_TOKEN not in everything


def test_a_flag_the_platform_rate_limits_is_sent_again_after_its_wait_and_then_judged(tmp_path, token):
    with FakePlatform(sample()[:1]) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        run = acme_run(tmp_path, fake, server)
        fake.limited, fake.retry_after = 2, 4
        waits: list[float] = []

        async def nap(seconds: float) -> None:
            waits.append(seconds)

        run.plug.sleep = nap

        async def body(run):
            await wait_for(lambda: run.deck.challenges["warm-up"].status is ChallengeStatus.SOLVED, "the solve")

        play(run, body)
        assert fake.attempts() == [(17, "t{warm}")] * 3 and waits == [5.0, 5.0]  # what the platform asked, and a second
    assert plugin_warnings(run) == []
    assert ("the platform rate-limited the submission of t{warm} and did not check it; flightdeck sends it again in 5s "
            "(send 2 of 4)") in [action.text for action in lane_for(run, "warm-up").actions]


@pytest.mark.parametrize("pull, appears", [("auto", True), ("confirm", False)])
def test_a_challenge_the_platform_releases_later_starts_a_lane_under_pull_auto_and_not_under_confirm(tmp_path, token, pull, appears):
    with FakePlatform(sample()[:1]) as fake, FakeModelServer(responder=Model({})) as server:
        run = acme_run(tmp_path, fake, server, pull=pull, max_lanes=4, solves_seconds=0.1, confirm=yes)
        run.plug.pull_seconds = 0.2
        assert run.plug.pulls is appears

        async def body(run):
            run.plug.solved.add("41")  # as a read of the solved list would: the platform lists the late one as solved
            fake.add(FakeTask(40, "Second Wave", points=75, files={"wave.txt": b"later\n"}), FakeTask(41, "Late And Done", solved=True))
            if appears:
                await wait_for(lambda: any(lane.challenge_id == "second-wave" for lane in run.deck.lanes.values()), "its lane")
                await wait_for(lambda: run.deck.challenges["late-and-done"].closed, "the late solved one closed")
            else:
                await wait_for(lambda: len(fake.sent("solved")) >= 6, "time enough for several pulls")

        play(run, body)
        pulls = len(fake.sent("challenges"))
    if appears:
        assert pulls > 1 and (tmp_path / "board" / "second-wave" / "wave.txt").read_bytes() == b"later\n"
        assert run.plug.refs["second-wave"] == "40" and run.deck.challenges["late-and-done"].status is ChallengeStatus.TEAMMATE
        assert sorted(lane.challenge_id for lane in run.deck.lanes.values()) == ["second-wave", "warm-up"]  # none on the solved one
        assert any("pulls again every 300 s" in note for note in run.notes())
    else:
        assert pulls == 1 and sorted(run.deck.challenges) == ["warm-up"] and not (tmp_path / "board" / "second-wave").exists()
        assert any('pull is "confirm" in the event profile: flightdeck pulled the board once, after you said yes' in n for n in run.notes())
    assert plugin_warnings(run) == []


def test_pull_confirm_asks_first_and_a_no_or_nobody_to_ask_pulls_nothing(tmp_path, token):
    with FakePlatform(sample()) as fake:
        options = run_options(tmp_path, fake.url, make_adapter(tmp_path / "acme"), pull="confirm")
        asked_for: list[str] = []
        with pytest.raises(RunError, match="you said no to the pull, so nothing was pulled and the run did not start"):
            prepare_run(RunOptions(**{**options.__dict__, "confirm": lambda question: bool(asked_for.append(question))}))
        assert asked_for == [f"Pull the board from {fake.url} through the acme plugin into {tmp_path / 'board'}?"]
        with pytest.raises(RunError, match='the event\'s pull policy is "confirm", so flightdeck asks before it pulls the board'):
            prepare_run(options)  # nobody to ask
        assert fake.requests == [] and not (tmp_path / "board").exists()


@pytest.mark.parametrize("kind, said", [
    ("challenges", "the acme plugin could not pull the board: it exited with status 1: the platform answered HTTP 500; nothing was started"),
    ("solved", "could not read the solved list from the acme plugin: it exited with status 1: the platform answered HTTP 500; "
               "nothing was started"),
])
def test_a_pull_or_a_solved_list_that_fails_at_the_start_stops_the_run_before_anything_starts(tmp_path, token, kind, said):
    with FakePlatform(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        fake.script("GET", kind, Reply(500, {"error": "internal"}))
        with pytest.raises(RunError) as refused:
            acme_run(tmp_path, fake, server)
        assert str(refused.value) == said
        assert server.chats() == [] and fake.attempts() == []  # no lane ran, nothing was submitted
    assert not (tmp_path / "runs").exists() or list((tmp_path / "runs").iterdir()) == []  # no run folder


def test_a_solved_list_that_keeps_failing_in_a_run_warns_once_and_tells_autopilot_once(tmp_path, token):
    with FakePlatform(sample()[:1]) as fake, FakeModelServer(responder=Model({})) as server:
        run = acme_run(tmp_path, fake, server, pull="confirm", solves_seconds=0.05, confirm=yes)
        assert run.plug.needs_human == run.autopilot.platform  # autopilot is told the platform needs a human
        told: list[str] = []
        run.plug.needs_human = told.append
        fake.script("GET", "solved", *[Reply(500, {"error": "internal"})] * 5)

        async def body(run):
            await wait_for(lambda: len(fake.sent("solved")) >= 8, "the reads")  # one at the start, five failing, two that work

        play(run, body)
    why = "it exited with status 1: the platform answered HTTP 500"
    assert plugin_warnings(run) == [f"could not read the solved list from the acme plugin: {why}; flightdeck reads it again in 0.05 s"]
    assert told == [f"reading the solved list from the acme plugin has failed 3 times in a row: {why}"]


def test_new_and_attach_are_refused_on_a_board_a_plugin_fills(tmp_path, token):
    with FakePlatform(sample()) as fake, FakeModelServer(responder=Model({})) as server:
        run = acme_run(tmp_path, fake, server)
        try:
            assert run.watches_folder and not run.by_hand  # its folders are watched for later pulls, but the player adds none
            app = run.app(refresh_seconds=None)
            assert app.adder is None and app.attacher is None and app.paster is None
            before = sorted(entry.name for entry in (tmp_path / "board").iterdir())
            assert asyncio.run(run.add_challenge(NewChallenge(name="Mine"))) == (
                False, "this board comes from the platform: challenges are added there, not here")
            handout = tmp_path / "extra.txt"
            handout.write_text("x")
            assert asyncio.run(run.attach_files("warm-up", [handout])) == (
                False, "files are attached to a challenge on a board you fill yourself")
            assert sorted(entry.name for entry in (tmp_path / "board").iterdir()) == before
        finally:
            run.close()


def pulled_before(tmp_path: Path, fake: FakePlatform, *, url: str | None = None) -> Path:
    """The board as `flightdeck plugin pull` writes it, before the run; the fake's requests are forgotten."""
    plugin = manifest.read(make_adapter(tmp_path / "acme"))
    caller = Caller(plugin, fake.url, "Fake Quals", PLATFORM_TOKEN)
    asyncio.run(boards.pull_into(caller, tmp_path / "board", plugin="acme", url=url or fake.url))
    fake.requests.clear()
    return tmp_path / "board"


def test_under_pull_manual_the_run_pulls_nothing_and_plays_the_board_plugin_pull_wrote(tmp_path, token):
    with FakePlatform(sample()) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        board = pulled_before(tmp_path, fake)
        run = acme_run(tmp_path, fake, server, pull="manual")
        assert kinds(fake) == ["solved"] and not run.plug.pulls  # the solved list only: no pull

        async def body(run):
            await wait_for(lambda: run.deck.challenges["warm-up"].status is ChallengeStatus.SOLVED, "the solve")

        play(run, body)
        assert fake.sent("challenges") == [] and fake.attempts() == [(17, "t{warm}")]
    assert any(note.startswith(f'board: 3 challenges in {board}, as `flightdeck plugin pull` wrote it; pull is "manual"')
               for note in run.notes())


def test_a_challenge_plugin_pull_adds_from_another_terminal_during_the_run_is_played_and_its_flag_finds_its_ref(tmp_path, token):
    script = {"Second Wave": [submit("t{second}")]}
    with FakePlatform(sample()[:1]) as fake, FakeModelServer(responder=Model(script)) as server:
        board = pulled_before(tmp_path, fake)
        run = acme_run(tmp_path, fake, server, pull="manual", max_lanes=4, folder_seconds=0.05)

        async def body(run):
            fake.add(FakeTask(40, "Second Wave", flag="t{second}"), FakeTask(41, "Late And Done", solved=True))
            run.plug.solved.add("41")  # as a read of the solved list would
            other = Caller(manifest.read(tmp_path / "acme"), fake.url, "Fake Quals", PLATFORM_TOKEN)
            await boards.pull_into(other, board, plugin="acme", url=fake.url)  # what `flightdeck plugin pull` does
            await wait_for(lambda: run.deck.challenges.get("second-wave") is not None
                           and run.deck.challenges["second-wave"].status is ChallengeStatus.SOLVED, "the late one solved")

        play(run, body)
        assert fake.attempts() == [(40, "t{second}")]
    assert run.plug.refs == {"warm-up": "17", "second-wave": "40", "late-and-done": "41"}
    assert sorted(lane.challenge_id for lane in run.deck.lanes.values()) == ["second-wave", "warm-up"]  # none on the solved one
    assert plugin_warnings(run) == []


def test_a_board_the_plugin_did_not_pull_has_nowhere_to_send_flags_so_the_run_does_not_start(tmp_path, token):
    with FakePlatform(sample()) as fake:
        board = tmp_path / "board"
        (board / "by-hand").mkdir(parents=True)
        (board / "by-hand" / "challenge.json").write_text(json.dumps({"name": "By Hand", "category": "misc", "points": 10}))
        options = run_options(tmp_path, fake.url, make_adapter(tmp_path / "acme"), pull="manual")
        with pytest.raises(RunError) as refused:
            prepare_run(options)
        assert str(refused.value) == (
            f"{board} was not pulled by the acme plugin, so flightdeck has nowhere to send its flags: `flightdeck plugin pull "
            "EVENT.toml` first, or set policies.pull to auto or confirm")
        with pytest.raises(RunError, match="is not empty and holds no plugin.json, so it is not a board the acme plugin pulled"):
            prepare_run(RunOptions(**{**options.__dict__, "event": event_file(tmp_path, fake.url, pull="auto", submit="auto")}))
        assert fake.requests == []  # refused before the plugin was asked anything


def test_a_board_pulled_from_another_address_is_refused(tmp_path, token):
    with FakePlatform(sample()) as fake:
        board = pulled_before(tmp_path, fake, url="https://other.example.test")
        for pull in ("manual", "auto"):
            with pytest.raises(RunError) as refused:
                prepare_run(run_options(tmp_path, fake.url, tmp_path / "acme", pull=pull))
            assert str(refused.value) == f"{board} holds a board pulled by another plugin or from another address: use a new folder"
        assert fake.requests == []


def test_a_profile_that_uses_the_plugin_for_nothing_plays_as_a_by_hand_board_and_never_runs_it(tmp_path):
    """pull and submit both by hand: no token is read, the plugin's program is never started,
    and the player fills the board themself."""
    root = make_plugin(tmp_path / "acme", {})
    (tmp_path / "board").mkdir()
    with FakeModelServer(responder=Model({})) as server:
        run = prepare_run(run_options(tmp_path, "https://ctf.example.test", root, server, pull="manual", submit_policy="manual"))
        try:
            assert run.plug is None and run.links == [] and run.by_hand and run.watches_folder
            assert run.deck.verify is cannot_check and run.deck.submitter is None and run.app(refresh_seconds=None).adder is not None
            assert any(note == "event profile: this run does not use the acme plugin: pull and submit are both by hand"
                       for note in run.notes())
        finally:
            run.close()
    assert plugin_kit.calls(root) == []


def test_under_submit_manual_the_plugin_pulls_and_lists_but_no_flag_goes_through_it(tmp_path, token):
    with FakePlatform(sample()[:1]) as fake, FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        run = acme_run(tmp_path, fake, server, submit_policy="manual")
        assert run.plug is not None and run.deck.submitter is None and run.deck.verify is cannot_check

        async def body(run):
            await wait_for(lambda: run.deck.lanes and lane_for(run, "warm-up").pending is not None, "the flag, with the player")
            assert lane_for(run, "warm-up").pending.kind is PendingKind.CONFIRM  # the player submits it and says how it went

        play(run, body)
        assert fake.attempts() == [] and kinds(fake)[:3] == ["challenges", "file", "solved"]
    assert f"the acme plugin reads the solved list from {fake.url}; no flag goes through it" in run.notes()
    assert not any(note.startswith("flags go to") for note in run.notes())


def test_answers_cannot_be_checked_against_a_file_when_flags_go_through_a_plugin(tmp_path, token):
    with FakePlatform(sample()) as fake:
        options = run_options(tmp_path, fake.url, make_adapter(tmp_path / "acme"))
        answers = tmp_path / "answers.sha256.json"
        answers.write_text("{}")
        with pytest.raises(RunError, match="--answers checks flags against a file, and this event checks them on its platform, "
                                           "through the acme plugin: drop --answers"):
            prepare_run(RunOptions(**{**options.__dict__, "answers": answers}))
        assert fake.requests == []


def test_a_plugin_event_needs_a_board_folder(tmp_path, token):
    with FakePlatform(sample()) as fake:
        options = run_options(tmp_path, fake.url, make_adapter(tmp_path / "acme"))
        profile = tmp_path / "event.toml"
        profile.write_text("\n".join(line for line in profile.read_text().splitlines() if not line.startswith("board")) + "\n")
        with pytest.raises(RunError, match="an event on a plugin's platform needs the board folder its challenges are pulled into"):
            prepare_run(options)
        named = prepare_run(RunOptions(**{**options.__dict__, "board": tmp_path / "elsewhere"}))  # FOLDER on the command line
        named.close()
        assert (tmp_path / "elsewhere" / "warm-up").is_dir() and named.plug.board == tmp_path / "elsewhere"


def test_a_flag_on_its_way_through_the_plugin_when_the_run_ends_is_named_and_its_program_is_stopped(tmp_path, monkeypatch):
    monkeypatch.setenv(TOKEN_VAR, plugin_kit.TOKEN)
    root = make_plugin(tmp_path / "acme", {
        "pull": {"answer": {"challenges": [plugin_kit.challenge("17", "Warm Up")]}}, "solved": {"answer": {"solved": []}},
        "submit": {"sleep": 30, "answer": {"verdict": "correct"}},  # a platform slow to answer
    })

    def submits() -> list[dict]:
        return [call for call in plugin_kit.calls(root) if call["request"]["op"] == "submit"]

    with FakeModelServer(responder=Model({"Warm Up": [submit("t{warm}")]})) as server:
        run = prepare_run(run_options(tmp_path, "https://ctf.example.test", root, server, pull="confirm", confirm=yes))

        async def main():
            run.release()
            try:
                await wait_for(lambda: len(submits()) == 1, "the flag with the plugin")
            finally:
                await run.shutdown()

        asyncio.run(main())
        run.close()
    (sent,) = submits()
    assert (sent["request"]["ref"], sent["request"]["flag"]) == ("17", "t{warm}")
    with pytest.raises(ProcessLookupError):  # the program did not outlive the run
        os.kill(sent["pid"], 0)
    assert [e for e in run.errors if e.startswith("acme plugin: ")] == [
        "acme plugin: t{warm} (L01, Warm Up) was on its way to the platform when the run ended, so it is not known to have been "
        "submitted: check the challenge there before you submit it again"]


def test_a_later_pull_that_fails_warns_once_and_what_a_pull_leaves_out_is_said_once(tmp_path, monkeypatch):
    """What the first pull left out or noted is in the run's notes; a later pull says only what
    is new. A pull that fails is one warning while the same failure lasts, and the next still runs."""
    monkeypatch.setenv(TOKEN_VAR, plugin_kit.TOKEN)
    warm, odd, odder = (plugin_kit.challenge("17", "Warm Up"), plugin_kit.challenge("18", "Odd", points=-1),
                        plugin_kit.challenge("19", "Odder", points=-2))
    first = {"answer": {"challenges": [warm, odd], "notes": ["2 challenges are locked"]}}
    down = {"stderr": "the platform is down\n", "exit": 1}
    later = {"answer": {"challenges": [warm, odd, odder, plugin_kit.challenge("20", "Late")], "notes": ["2 challenges are locked"]}}
    root = make_plugin(tmp_path / "acme", {"pull": [first, down, down, later], "solved": {"answer": {"solved": []}}})
    with FakeModelServer(responder=Model({})) as server:
        run = prepare_run(run_options(tmp_path, "https://ctf.example.test", root, server, max_lanes=4))
        run.plug.pull_seconds = 0.05
        left_out = 'acme: not added: Odd: "points" must be a whole number, 0 or more'
        assert left_out in run.notes() and "acme: 2 challenges are locked" in run.notes()

        async def body(run):
            await wait_for(lambda: any(lane.challenge_id == "late" for lane in run.deck.lanes.values()), "the late one's lane")
            pulls = len([call for call in plugin_kit.calls(root) if call["request"]["op"] == "pull"])
            await wait_for(lambda: len([c for c in plugin_kit.calls(root) if c["request"]["op"] == "pull"]) >= pulls + 2, "two more pulls")

        play(run, body)
    assert plugin_warnings(run) == [
        "the acme plugin could not pull new challenges: it exited with status 1: the platform is down; flightdeck pulls again in 0.05 s",
        'acme: not added: Odder: "points" must be a whole number, 0 or more',
    ]
    known = [call["request"]["known"] for call in plugin_kit.calls(root) if call["request"]["op"] == "pull"]
    assert known[0] == [] and known[1] == ["17"] and known[-1] == ["17", "20"]  # the refs on the board already, each time


# ---------------------------------------------------------------------- what a plugin says is never trusted


def test_a_run_gives_the_plugin_the_events_token_and_none_of_the_players_other_keys(tmp_path, monkeypatch):
    """The token comes from the keys file here, where a model key sits beside it: the plugin's
    program gets the first as FLIGHTDECK_PLUGIN_TOKEN and nothing of the second."""
    root = make_plugin(tmp_path / "acme", {
        "pull": {"answer": {"challenges": [plugin_kit.challenge("17", "Warm Up")]}}, "solved": {"answer": {"solved": []}}})
    keys = tmp_path / "keys.env"
    keys.write_text(f"{TOKEN_VAR}={plugin_kit.TOKEN}\nOPENROUTER_API_KEY=sk-or-fake-for-this-test\n")
    keys.chmod(0o600)
    monkeypatch.setenv("FLIGHTDECK_KEYS", str(keys))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-fake-for-this-test")
    with FakeModelServer(responder=Model({})) as server:
        prepare_run(run_options(tmp_path, "https://ctf.example.test", root, server)).close()
    seen = plugin_kit.calls(root)
    assert [call["request"]["op"] for call in seen] == ["pull", "solved"]
    for call in seen:
        assert call["env"]["FLIGHTDECK_PLUGIN_TOKEN"] == plugin_kit.TOKEN
        assert not {"OPENROUTER_API_KEY", "ANTHROPIC_API_KEY", TOKEN_VAR} & set(call["env"])
        assert plugin_kit.TOKEN not in json.dumps(call["request"]) and plugin_kit.TOKEN not in " ".join(call["argv"])
        assert (call["request"]["url"], call["request"]["event"]) == ("https://ctf.example.test", "Fake Quals")


def seen(tag: str) -> str:
    """osc(tag) as text.untrusted() shows it: the whole sequence, made visible."""
    return f"^[]0;{tag}^[" + chr(92)


def test_a_token_the_plugin_prints_and_an_escape_sequence_it_passes_on_never_reach_the_console_or_the_runs_files(tmp_path, monkeypatch):
    """The plugin answers a flag with the platform's words, which carry an escape sequence and
    the token; then its submit fails with the token on stderr, and so does its solved list.
    Nothing of the token is drawn or written, and the sequence is shown made visible."""
    secret = plugin_kit.TOKEN
    monkeypatch.setenv(TOKEN_VAR, secret)
    root = make_plugin(tmp_path / "acme", {
        "pull": {"answer": {"challenges": [plugin_kit.challenge("17", "Warm Up")]}},
        "solved": [{"answer": {"solved": []}}, {"stderr": "cannot list for {token} " + osc("sv") + "\n", "exit": 1}],
        "submit": [{"answer": {"verdict": "incorrect", "detail": f"wrong {osc('dt')} for {secret}"}},
                   {"stderr": "refused for {token} " + osc("er") + "\n", "exit": 3}],
    })
    model = Model({"Warm Up": [submit("t{one}"), submit("t{two}")]})

    async def main():
        with FakeModelServer(responder=model) as server:
            run = prepare_run(run_options(tmp_path, "https://ctf.example.test", root, server, pull="confirm", confirm=yes,
                                          solves_seconds=0.05))
            app = run.app(refresh_seconds=None)
            frames, texts = [], []
            async with app.run_test(size=(160, 46)) as pilot:
                await pilot.pause()
                for _ in range(2000):
                    lanes = list(run.deck.lanes.values())
                    if lanes and lanes[0].pending is not None and len(plugin_warnings(run)) >= 2:
                        break
                    await pilot.pause(0.01)
                (lane,) = run.deck.lanes.values()
                assert lane.pending.kind is PendingKind.CONFIRM and lane.pending.flag == "t{two}"
                app.refresh_view()
                await pilot.pause()
                frames.append(terminal_frame(app))
                texts.append(screen_text(app))
                await open_focus(pilot, app, lane.id)
                frames.append(terminal_frame(app))
                texts.append(screen_text(app))
            await run.shutdown()
            run.close()
            return run, lane, frames, texts

    run, lane, frames, texts = asyncio.run(main())
    said = sorted(plugin_warnings(run))
    assert said == [
        f"could not read the solved list from the acme plugin: it exited with status 1: cannot list for <token> {seen('sv')}; "
        "flightdeck reads it again in 0.05 s",
        f"the acme plugin did not judge t{{two}} for Warm Up: it exited with status 3: refused for <token> {seen('er')}",
    ]
    assert f"the platform's answer to t{{one}}: wrong {seen('dt')} for <token>" in [action.text for action in lane.actions]
    assert all(secret not in frame and OSC not in frame for frame in frames)
    assert "^[]0;dt" in texts[1] and "<token>" in "".join(texts)  # shown, made visible, with the token cut out
    written = [path for path in run.dir.rglob("*") if path.is_file()]
    assert {"events.jsonl", "status.json"} <= {path.name for path in written}
    for path in written:
        data = path.read_bytes()
        assert secret.encode() not in data and OSC.encode() not in data, path
    assert secret not in "\n".join(run.notes() + run.errors)
