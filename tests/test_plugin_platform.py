"""An event on a plugin's platform: what pre-flight says of its profile, the link between a
plugin and the deck (platform/plugin_run.py), and whole runs through `prepare_run`.

Plugins here are synthetic, in tmp_path: plugin_kit's adapter answers from a file, and
fake_platform's talks HTTP to a stand-in platform on 127.0.0.1. Nothing real is contacted.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from ctf_flightdeck import config as configs
from ctf_flightdeck import preflight
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

from plugin_kit import make_plugin
from test_deck import events, lane_on
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


def test_a_challenge_with_no_ref_is_never_sent_and_goes_back_to_the_player(tmp_path):
    deck, link, caller = linked(tmp_path, refs={"c1": "23"})
    lane = lane_on(deck, "c0")

    async def body():
        deck.report(lane.id, TurnReport(action="solve.py", flag="t{c0}"))
        await settled(link, deck)

    drive(link, body)
    why = "c0 was not pulled through the plugin, so flightdeck has nowhere to send its flag: submit it by hand, then say whether it was accepted"
    assert caller.submits == [] and asked(lane) == [(PendingKind.CONFIRM, "t{c0}")]
    assert warnings(deck) == [f"the acme plugin did not judge t{{c0}} for Chall 0: {why}"] and len(link.told) == 1


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
