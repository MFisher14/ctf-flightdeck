"""Pre-flight: the event profile (what an event's rules allow) and the stage policies.

The player writes an event profile, event.toml, from the event's rules (print a commented one
with `flightdeck preflight --example`):

- [event]: the event's name, its platform ("ctfd": flightdeck uses CTFd's API; "manual": a
  folder board; "gamemaster": a board `flightdeck gm pull` wrote, whose answers go to the Game
  Master; "http": a platform with a JSON API, asked by the routes its [http] table writes),
  where the board comes from, the flag format and team mode;
- [rules]: what the rules allow: AI help (ai_allowed), scripts using the platform's API
  (platform_automation), lanes touching challenge instances (live_targets: allowed, confirm or
  off) and, optionally, how many lanes may run at once (max_lanes), whether a challenge's text
  and files may be given to a model (material_to_models) and the label the team declared to
  the event for its AI use (declared_label);
- [policies], optional: how far flightdeck goes on its own at each stage. A policy may be
  stricter than the rules allow, never looser.

Every stage has a policy. From loosest to strictest:

    auto     flightdeck does it
    confirm  flightdeck prepares it and the player says yes first
    manual   the player does it; flightdeck says what to do
    off      nobody does it through flightdeck

    pull      getting the board (and later waves) from the platform
    l1        running the player's no-model (L1) solvers
    agents    starting model-driven lanes
    submit    submitting flags to the platform
    instance  lanes reaching a challenge's live instance

The rules set the loosest policy each stage may have (allowed()): rules.ai_allowed = false
makes agents off, and so does rules.material_to_models = false (a lane gives its model the
challenge's text and files, so no lane can keep that rule; its refusal names it:
NO_MATERIAL_TO_MODELS); rules.platform_automation = false makes pull and submit manual;
rules.live_targets makes instance auto (allowed), confirm (confirm) or off (off); everything
else may be auto. A stage the profile leaves out gets that loosest policy, except submit, which
gets confirm (a flag is submitted only after the player approves it) unless auto is asked for.

rules.declared_label is the team's own word to the event ("Human-Led AI", "Low AI": each event
has its words). flightdeck does not know what a label means and checks nothing by it: it shows
it before a run (describe(), the start of `play`) and records it with the run, for the flight
card and the solve records. What a label commits the team to goes in the other keys.

A "gamemaster" profile names the Game Master's url and token_env. A run with it pulls nothing
and starts no attempt (`flightdeck gm pull` does both, before the run: its pull line says so,
whatever the pull policy), so only its submit policy uses the platform: auto or confirm send
answers to the Game Master and read its solved list.

An "http" profile carries an [http] table (platform/http.py): the routes of the platform's
API, or a preset that ships with flightdeck (rctf, rctf2, noctf, gzctf). The table is data, not code, so the
profile may carry it, a teammate's too: every route is a path under event.url, the token goes
nowhere else, and describe() prints each request and where the token goes before anything
runs. The token variable must be named for the platform (HTTP_TOKEN, HTTP_TOKEN_..., or the
preset's name: RCTF_TOKEN), so a profile cannot name another event's or another service's
secret, nor a proxy's address (HTTP_PROXY). It plays as a plugin's platform does: flightdeck
pulls the board, submits and reads the solved list.

Any other platform name selects a plugin (plugins/): a program the player added with
`flightdeck plugin add`, which pulls, submits and reads the solved list for a platform
flightdeck does not know. The profile only selects it: check() refuses the run unless the
player's own config has a [plugins] table of that name, and never plays such a profile as a
folder board. Nothing shows event.platform until the config has made it a plugin's name.

check() lists the problems: refusals (a run must not start: a policy looser than the rules
allow, a platform setting missing, more lanes than the rules allow...) and warnings (worth
knowing before the event: a token variable that is not set...).

The profile holds no secret. token_env names the environment variable that holds the platform's
API token (an upper-case name: a token pasted there is refused without being shown), and nothing
here reads that variable except to see whether it is set. A profile can come from a teammate, so
everything in it is untrusted: error messages never show its string values (only TOML's own
message may quote a key, and the regular expression engine's part of the flag format), and
whatever is shown is made safe with text.untrusted().

Instance "confirm": a lane whose challenge has a live instance asks the player before its
first model call. Until the player allows it, its http tool is off and a docker lane has no
network; once allowed, the container joins a fenced network that reaches the instance and
nothing else (agent/egress.py). On the host runtime only the http tool waits (a lane's shell has this machine's
network), so check() warns there.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import NamedTuple
from urllib.parse import SplitResult, urlsplit

from .config import PLUGIN_NAME, Config, ConfigError
from .flagformat import problem as flag_format_problem
from .platform import http as http_platform
from .platform.http import HttpConfig
from .platform.instances import InstancesConfig
from .platform.instances import parse_config as parse_instances
from .plugins import manifest as plugin_manifest
from .text import untrusted


class Policy(StrEnum):
    AUTO = "auto"
    CONFIRM = "confirm"
    MANUAL = "manual"
    OFF = "off"


STRICTNESS = (Policy.AUTO, Policy.CONFIRM, Policy.MANUAL, Policy.OFF)
"""The policies from loosest (flightdeck does the most on its own) to strictest."""

STAGES = ("pull", "l1", "agents", "submit", "instance")
PLATFORMS = ("ctfd", "manual", "gamemaster", "http")
INSTANCE_PLATFORMS = ("ctfd", "http")  # where flightdeck starts a challenge's instance ([instances])
LIVE_TARGETS = ("allowed", "confirm", "off")
RUNTIMES = ("docker", "host")
MAX_PROFILE_BYTES = 1_000_000  # an event profile bigger than this is refused

USES_PLATFORM = frozenset({Policy.AUTO, Policy.CONFIRM})
"""Policies under which flightdeck itself uses the platform (pulls or submits)."""

OTHER_SERVICE_KEYS = frozenset({
    # model providers and agent command lines
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "AZURE_OPENAI_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
    "CODEX_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GROQ_API_KEY",
    "HF_TOKEN",
    "HUGGING_FACE_HUB_TOKEN",
    "MISTRAL_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "XAI_API_KEY",
    # code hosts and clouds
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
})
"""Variables that hold other services' keys, never a CTF platform's token. A profile whose
token_env names one would have flightdeck send that key to the platform's URL."""

OTHER_SERVICE_SUFFIXES = ("_API_KEY", "_AUTH_TOKEN", "_OAUTH_TOKEN", "_ACCESS_KEY", "_SECRET_KEY", "_PRIVATE_KEY", "_SESSION_TOKEN")
"""How other services' key variables are usually named, so OTHER_SERVICE_KEYS need not list
them all. A name with CTFD in it is taken for a CTFd token's variable even so (CTFD_API_KEY)."""

_PROXY_VARIABLE = re.compile(r"(?:HTTPS?|ALL|FTP|NO)_PROXY(?:_[A-Z0-9_]*)?")
"""The proxy settings many programs read (HTTP_PROXY, and names made from it): a proxy's
address, often with its user name and password. HTTP_PROXY starts with HTTP_ as the http
platform's own token variables do, so it is told apart by name (http_token_env)."""

_TABLES = ("event", "rules", "policies", "instances", "http")
_EVENT_KEYS = ("name", "platform", "url", "token_env", "board", "flag_format", "team", "start", "end")
_RULE_KEYS = ("ai_allowed", "platform_automation", "live_targets", "max_lanes", "material_to_models", "declared_label")
MAX_LABEL = 40  # a declared label longer than this is not a label
LABEL_SHAPE = f"a few words as the event writes them (letters, digits, spaces and hyphens, at most {MAX_LABEL} characters)"
_PLATFORM_ONLY = {"url": ("ctfd", "gamemaster", "http"), "token_env": ("ctfd", "gamemaster", "http"),
                  "board": ("manual", "gamemaster", "http")}
# token_env: an upper-case name, as config.py asks of api.key_env. A token is letters, digits and
# _ often enough (CTFd's is ctfd_ and 64 hex digits), but almost never all upper case, so one
# pasted into token_env is refused before anything could show it.
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_MAX_ENV_NAME = 64
_TOKEN_SHAPE = re.compile(r"\s*(?:ctfd_[0-9a-f]{16,}|[0-9a-f]{32,})\s*", re.IGNORECASE)
_NOT_A_NAME = (
    "must be the name of an environment variable, like CTFD_TOKEN (upper-case letters, digits and _, "
    f"not starting with a digit, at most {_MAX_ENV_NAME} characters), not the token itself"
)
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


def looser(a: Policy | str, b: Policy | str) -> bool:
    """Whether policy `a` lets flightdeck do more on its own than `b` (auto is the loosest)."""
    return STRICTNESS.index(Policy(a)) < STRICTNESS.index(Policy(b))


def strictest(*policies: Policy | str) -> Policy:
    """The strictest of the policies given."""
    return max((Policy(p) for p in policies), key=STRICTNESS.index)


@dataclass(frozen=True)
class Policies:
    """One policy per stage. Plain strings are accepted and stored as Policy members."""

    pull: Policy
    l1: Policy
    agents: Policy
    submit: Policy
    instance: Policy

    def __post_init__(self) -> None:
        for stage in STAGES:
            value = getattr(self, stage)
            try:
                policy = Policy(value)
            except ValueError:
                raise ValueError(f"the {stage} policy must be {_or(STRICTNESS)}") from None
            object.__setattr__(self, stage, policy)

    def items(self) -> list[tuple[str, Policy]]:
        """(stage, policy) in stage order."""
        return [(stage, getattr(self, stage)) for stage in STAGES]


@dataclass(frozen=True, kw_only=True)
class EventProfile:
    """The [event] and [rules] tables of an event profile, typed and checked."""

    # [event]
    name: str
    platform: str  # "ctfd" | "manual" | "gamemaster" | "http", or the name of a plugin's platform (`plugin`)
    url: str | None = None  # ctfd, gamemaster, http, a plugin's: the site's address, without a trailing /
    token_env: str | None = None  # ctfd, gamemaster, http, a plugin's: the NAME of the variable that holds the API token
    board: Path | None = None  # manual, gamemaster, http, a plugin's: the folder board (absolute: ~ expanded, else from the profile's folder)
    flag_format: str | None = None  # a regular expression; None: the board's, else the deck's default
    team: bool = False
    start: datetime | None = None  # when the event starts, with its zone: autopilot waits for it (autopilot.py)
    end: datetime | None = None  # when it ends, with its zone: autopilot stops the run then, as quitting does
    # [rules]
    ai_allowed: bool
    platform_automation: bool
    live_targets: str  # "allowed" | "confirm" | "off"
    max_lanes: int | None = None  # the rules' upper bound on lanes at once, if they set one
    material_to_models: bool = True  # may a challenge's text and files be given to a model; False: agents off, as no AI
    declared_label: str | None = None  # the label the team declared to the event for its AI use, in the event's words
    # [instances]: how a challenge's own container is started on the platform (platform/instances.py); None: no table
    instances: InstancesConfig | None = None
    # [http]: the routes of a platform with a JSON API (platform/http.py), for platform "http"; None: no table
    http: HttpConfig | None = None
    # where it came from
    explicit: frozenset[str] = frozenset()  # the stages whose policy the [policies] table sets; the rest are derived
    source: Path | None = None  # the file it was read from

    def __post_init__(self) -> None:
        if self.platform not in PLATFORMS and not _plugin_name(self.platform):
            raise ValueError(f"platform must be {_or(PLATFORMS)} or the name of a plugin")
        if self.live_targets not in LIVE_TARGETS:
            raise ValueError(f"live_targets must be {_or(LIVE_TARGETS)}")
        if self.declared_label is not None and not is_label(self.declared_label):
            raise ValueError(f"declared_label must be {LABEL_SHAPE}")
        if self.token_env is not None and not _is_env_name(self.token_env):
            # describe() and check() show token_env, so a profile built in code gets the same
            # check as load_profile's, and the value is never shown here either.
            raise ValueError(f"token_env {_NOT_A_NAME}")
        for name in ("start", "end"):
            when = getattr(self, name)
            if when is not None and (not isinstance(when, datetime) or when.utcoffset() is None):
                raise ValueError(f"{name} must be a time with its zone (a datetime that knows its UTC offset)")
        if self.start is not None and self.end is not None and self.end <= self.start:
            raise ValueError("end must be after start")
        unknown = set(self.explicit) - set(STAGES)
        if unknown:
            raise ValueError(f"explicit names stages that do not exist: {', '.join(sorted(unknown))}")
        object.__setattr__(self, "explicit", frozenset(self.explicit))

    @property
    def plugin(self) -> bool:
        """Whether the platform is a plugin's (plugins/), not one flightdeck has built in. The
        profile only selects it: the player's config must allow the plugin by that name."""
        return self.platform not in PLATFORMS

    @property
    def adapter(self) -> bool:
        """Whether flightdeck fills the board and submits through an adapter that makes the three
        calls (plugins.call.PlatformCaller): a plugin's program, or the built-in http platform."""
        return self.plugin or self.platform == "http"


@dataclass(frozen=True)
class Problem:
    refuse: bool  # True: the run must not start
    message: str


class ProfileError(Exception):
    """The event profile cannot be used. The message names the file and the key, never a
    string value from the file but a bad flag format, escaped and cut short."""


# ---------------------------------------------------------------------- policies from the rules


def allowed(profile: EventProfile) -> Policies:
    """The loosest policies the event's rules allow."""
    platform = Policy.AUTO if profile.platform_automation else Policy.MANUAL
    return Policies(
        pull=platform,
        l1=Policy.AUTO,
        agents=Policy.AUTO if profile.ai_allowed and profile.material_to_models else Policy.OFF,
        submit=platform,
        instance={"allowed": Policy.AUTO, "confirm": Policy.CONFIRM, "off": Policy.OFF}[profile.live_targets],
    )


def defaults(profile: EventProfile) -> Policies:
    """The policies of a profile whose [policies] table sets none: the loosest the rules allow,
    except that a flag is submitted only after the player approves it (submit confirm, or
    manual when the rules forbid platform automation)."""
    loosest = allowed(profile)
    return replace(loosest, submit=strictest(loosest.submit, Policy.CONFIRM))


def lane_network(policies: Policies, urls: Sequence[str]) -> str:
    """The network a docker lane starts with: "fenced" only when its challenge has a live
    instance and lanes may reach it at once (instance auto); "none" otherwise, so the lane
    cannot reach the instance or anything else. Under confirm the run gives the container
    the fenced network when the player allows it; under manual the player works the
    instance, not the lane. A fenced network reaches the instance and nothing else
    (agent/egress.py); no lane is put on Docker's open bridge network."""
    if policies.instance is not Policy.AUTO or not urls:
        return "none"
    return "fenced"


class DeckSubmit(NamedTuple):
    policy: str  # DeckConfig.submit: "auto" or "confirm"
    platform: bool  # whether the deck's verify() may hand flags to the board's verifier (CTFd, answers file)


def deck_submit(policy: Policy | str) -> DeckSubmit:
    """How a run sets up the deck for a submit policy.

    auto and confirm hand flags to the board's verifier: at once, or after the player approves.
    manual and off never do: with platform False the run gives the deck a verifier that cannot
    check (platform.manual.cannot_check), and the deck's "auto" then turns each candidate flag
    straight into "submit it yourself, then say if it was accepted". The deck has no mode that
    only notes a flag, so off is shown like manual: nothing reaches the platform either way.
    """
    policy = Policy(policy)
    if policy is Policy.AUTO:
        return DeckSubmit("auto", True)
    if policy is Policy.CONFIRM:
        return DeckSubmit("confirm", True)
    return DeckSubmit("auto", False)


# ---------------------------------------------------------------------- checks


def check(
    profile: EventProfile,
    requested: Policies,
    *,
    max_lanes: int | None,
    environ: Mapping[str, str] | None = None,
    model_config: Config | ConfigError | None = None,
    runtime: str | None = None,
) -> list[Problem]:
    """What stands in the way of a run with these policies: refusals first, then warnings.

    An agents policy of manual or off is a refusal (no_agents()): `flightdeck play` plays with
    agent lanes and starts no run without them, so no refusal here means play will start.

    max_lanes is how many lanes the run would start at once (None: not known yet, not checked).
    environ (default os.environ) is only asked whether the token and API key variables are set.
    model_config is the player's config, or the ConfigError that loading it raised, or None to
    leave the model check to the caller. runtime is "docker", "host" or None (not known).
    """
    if runtime is not None and runtime not in RUNTIMES:
        raise ValueError(f"runtime must be {_or(RUNTIMES)} or None")
    env = os.environ if environ is None else environ
    refuse: list[str] = []
    warn: list[str] = []
    loosest = allowed(profile)
    for stage, policy in requested.items():
        limit = getattr(loosest, stage)
        if looser(policy, limit):
            refuse.append(
                f'the {stage} policy "{policy}" is looser than the rules allow ({_rule(profile, stage)}): '
                f"it must be {_or(STRICTNESS[STRICTNESS.index(limit):])}"
            )
    if profile.platform == "ctfd":
        _check_ctfd(profile, requested, env, model_config, refuse, warn)
    elif profile.platform == "gamemaster":
        _check_gamemaster(profile, requested, env, model_config, refuse, warn)
    elif profile.platform == "manual":
        _check_manual(profile, refuse)
    elif profile.platform == "http":
        _check_http(profile, requested, env, model_config, refuse, warn)
    else:  # a plugin's platform is never played as a folder board
        _check_plugin(profile, requested, env, model_config, refuse, warn)
    if profile.http is not None and profile.platform != "http":
        warn.append('the [http] table does nothing in this run: it is read only for platform = "http"')
    if profile.instances is not None:
        why = instances_off(profile, requested)
        if why:
            warn.append(f"the [instances] table does nothing in this run: {why}, so flightdeck starts no instance "
                        "(start one on the site yourself; a lane then works from the files)")
    for key, platforms in _PLATFORM_ONLY.items():
        if getattr(profile, key) is not None and profile.platform not in platforms and not profile.plugin:
            warn.append(f'event.{key} is only for platform {_or(platforms)}, so this {profile.platform} profile does not use it')
    agents_on = requested.agents in (Policy.AUTO, Policy.CONFIRM)  # the policies under which play starts lanes
    if not agents_on:
        refuse.append(no_agents(profile, requested))
    if agents_on and profile.max_lanes is not None and max_lanes is not None and max_lanes > profile.max_lanes:
        refuse.append(
            f"{max_lanes} lanes at once is more than the rules allow (rules.max_lanes = {profile.max_lanes}): "
            f"run with --max-lanes {profile.max_lanes} or fewer, or lower [lanes] max_lanes in your config"
        )
    if agents_on:
        _check_models(requested.agents, env, model_config, warn)
    if agents_on and runtime == "host":
        if profile.live_targets == "off":
            refuse.append(
                'rules.live_targets = "off", but lanes would run on this machine (runtime host), where a '
                "lane's shell has this machine's network and flightdeck cannot keep it off a challenge's "
                "instance. Use the docker runtime: a lane there gets no network"
            )
        elif requested.instance in (Policy.MANUAL, Policy.OFF):
            warn.append(
                f'the instance policy is "{requested.instance}", but lanes run on this machine (runtime host), '
                "where a lane's shell can still reach an instance. The docker runtime enforces it (no network)"
            )
    if agents_on and requested.instance is Policy.CONFIRM and runtime == "host":
        warn.append(
            'the instance policy is "confirm", but lanes run on this machine (runtime host): a lane asks you '
            "before its http tool may reach the instance, but its shell has this machine's network and can "
            "reach it before you answer. The docker runtime enforces it (no network until you allow it)"
        )
    if profile.flag_format is None:
        warn.append(
            "event.flag_format is not set: lanes take the board's flag format if it has one, else anything "
            "shaped like word{...}. Set it from the event's rules, so flags in its format are caught"
        )
    return [Problem(True, m) for m in refuse] + [Problem(False, m) for m in warn]


NO_MATERIAL_TO_MODELS = (
    "the event's rules do not allow challenge material to be given to a model (rules.material_to_models = false), and "
    "every lane gives its model the challenge's text and files, so agents are off"
)
"""The refusal of a profile whose rules allow AI help but no challenge material to a model."""


def no_agents(profile: EventProfile, policies: Policies) -> str:
    """Why a profile whose agents policy is manual or off starts no run: `flightdeck play` plays
    with agent lanes. play says the same, before it calls check(). Each rule that turns agents
    off has its own words: no AI help at all, or (AI help allowed) no challenge material to a
    model, which a lane cannot keep."""
    if not profile.ai_allowed:
        why = "the event's rules do not allow AI help (rules.ai_allowed = false), so agents are off"
    elif not profile.material_to_models:
        why = NO_MATERIAL_TO_MODELS
    else:
        why = f'the event profile sets agents = "{policies.agents}"'
    return (
        f"{why}: `flightdeck play` plays with agent lanes, so it does not start. Play by hand; `flightdeck l1 run` "
        "runs your no-model solvers"
    )


def _check_ctfd(
    profile: EventProfile,
    requested: Policies,
    env: Mapping[str, str],
    model_config: Config | ConfigError | None,
    refuse: list[str],
    warn: list[str],
) -> None:
    if profile.url is None:
        refuse.append('event.url is required for platform "ctfd": the CTFd site\'s address, like https://ctf.example.org')
    if profile.token_env is None:
        refuse.append(
            'event.token_env is required for platform "ctfd": the name of the environment variable that '
            "holds your CTFd API token (the token itself never goes in the profile)"
        )
    if requested.pull not in USES_PLATFORM:
        refuse.append(
            f'platform "ctfd" with the pull policy "{requested.pull}": flightdeck will not pull the board from '
            "CTFd, so it has nothing to play. Download the challenges into a folder of challenge folders and "
            'use platform = "manual" with board = that folder'
        )
    name = profile.token_env
    if name is not None:
        api_env = isinstance(model_config, Config) and model_config.api.key_env == name
        fallback_env = (isinstance(model_config, Config) and model_config.fallback is not None
                        and model_config.fallback.key_env == name)
        model_key = api_env or fallback_env
        what = "a variable for another service's key" if model_key else _other_service(name)
        if what is not None:
            where = (" (api.key_env in your config)" if api_env else " (fallback.key_env in your config)") if model_key else ""
            refuse.append(
                f"event.token_env names {name}{where}, {what}, not a CTFd token: flightdeck would send its value "
                f"to {_shown_url(profile)}. Name the variable that holds your CTFd token, like CTFD_TOKEN"
            )
        elif (requested.pull in USES_PLATFORM or requested.submit in USES_PLATFORM) and not _is_set(env, name):
            warn.append(f"the CTFd token variable {name} (event.token_env) is not set or is empty: export your CTFd API token in it")
    url = _split_url(profile.url) if profile.url else None
    if url is not None and url.scheme == "http" and not _loopback(url.hostname or ""):
        warn.append("event.url is http, not https: the CTFd token would cross the network unencrypted")


def _check_gamemaster(
    profile: EventProfile,
    requested: Policies,
    env: Mapping[str, str],
    model_config: Config | ConfigError | None,
    refuse: list[str],
    warn: list[str],
) -> None:
    """A Game Master profile: its url and token_env are required (a submit policy that never
    uses the platform included, so the profile says where its board came from), and the token
    variable must not be another service's. The board is the folder `flightdeck gm pull` wrote:
    the run's BOARD argument, or event.board."""
    if profile.url is None:
        refuse.append('event.url is required for platform "gamemaster": the Game Master\'s address, the one URL its API answers at')
    if profile.token_env is None:
        refuse.append(
            'event.token_env is required for platform "gamemaster": the name of the environment variable that '
            "holds your Game Master token (the token itself never goes in the profile)"
        )
    name = profile.token_env
    if name is not None:
        api_env = isinstance(model_config, Config) and model_config.api.key_env == name
        fallback_env = (isinstance(model_config, Config) and model_config.fallback is not None
                        and model_config.fallback.key_env == name)
        model_key = api_env or fallback_env
        what = "a variable for another service's key" if model_key else _other_service(name, own="GM")
        if what is not None:
            where = (" (api.key_env in your config)" if api_env else " (fallback.key_env in your config)") if model_key else ""
            refuse.append(
                f"event.token_env names {name}{where}, {what}, not a Game Master token: flightdeck would send its value "
                f"to {_shown_url(profile)}. Name the variable that holds your Game Master token, like GM_TOKEN"
            )
        elif requested.submit in USES_PLATFORM and not _is_set(env, name):
            warn.append(f"the Game Master token variable {name} (event.token_env) is not set or is empty: export your token in it")
    url = _split_url(profile.url) if profile.url else None
    if url is not None and url.scheme == "http" and not _loopback(url.hostname or ""):
        warn.append("event.url is http, not https: the Game Master token would cross the network unencrypted")
    if profile.board is not None:
        _check_manual(profile, refuse)


NO_CONFIG_FOR_PLUGIN = ("event.platform names a plugin's platform, and your config could not be read, so flightdeck cannot "
                        "tell whether you added it")


def no_such_plugin(config: Config) -> str:
    """Why a profile whose platform is not built in and not a plugin of the player's config is
    refused. event.platform is not shown: it is the profile's word, which may be a teammate's
    or a value pasted by mistake, and only the player's own config makes it a plugin's name."""
    has = f"your config has: {', '.join(config.plugins)}" if config.plugins else "your config has no [plugins] table"
    return (f'event.platform is not {_or(PLATFORMS)}, and names no plugin in your config ({has}). '
            "`flightdeck plugin add FOLDER` adds one, after showing you what it runs")


def config_secrets(config: Config) -> dict[str, str]:
    """Every variable the player's config names for a secret of its own, and the setting that
    names it: the model keys ([api], [fallback], [light] and its job tables) and the
    notification webhook's URL. None of them is ever an event's token."""
    named = [(config.api.key_env, "api.key_env")]
    if config.fallback is not None:
        named.append((config.fallback.key_env, "fallback.key_env"))
    named.append((config.light.key_env, "light.key_env"))
    named += [(light.key_env, f"light.{job}.key_env") for job, light in config.light_tables.items()]
    named.append((config.notify.webhook_env, "notify.webhook_env"))
    secrets: dict[str, str] = {}
    for variable, setting in named:
        if variable:
            secrets.setdefault(variable, setting)
    return secrets


def plugin_token_env(name: str, plugin: str, config: Config) -> str | None:
    """Why event.token_env = `name` cannot be the token variable of an event on the `plugin`
    plugin's platform, or None when it can. Its value is handed to the plugin, and the profile
    that names it may be a teammate's, so the only variable a profile can name is one named
    for the plugin: its name starts with the plugin's own and a _ (ACME_TOKEN for acme; a
    name that merely has the letters in it does not count). Never a variable the config
    names for a secret of its own (config_secrets), nor one of OTHER_SERVICE_KEYS, whatever
    their names. Never a proxy setting either (a plugin called https names HTTPS_PROXY), nor
    one named for another plugin of the config whose name starts with this one's (MY_CTF_TOKEN
    is the my-ctf plugin's, not the my plugin's). So another event's token, another service's
    key, a proxy's password and a secret no list knows stay where they are."""
    own = _variable_prefix(plugin)
    setting = config_secrets(config).get(name)
    where = f" ({setting} in your config)" if setting else ""
    longer = sorted((other for other in getattr(config, "plugins", {}) if other != plugin
                     and len(_variable_prefix(other)) > len(own) and name.startswith(f"{_variable_prefix(other)}_")), key=len)
    if setting == "notify.webhook_env":
        what = "the variable that holds your notification webhook's URL"
    elif setting or name in OTHER_SERVICE_KEYS:
        what = "a variable for another service's key"
    elif _PROXY_VARIABLE.fullmatch(name) and not _PROXY_VARIABLE.fullmatch(own):  # a plugin the player called http_proxy keeps HTTP_PROXY_TOKEN
        what = "a proxy setting, whose value is a proxy's address and often the password for it"
    elif longer:
        what = f"a variable named for the {longer[-1]} plugin of your config"
    elif name.startswith(f"{own}_"):
        return None
    else:
        suffix = next((suffix for suffix in OTHER_SERVICE_SUFFIXES if name.endswith(suffix)), None)
        what = (f"a name ending in {suffix} like other services' key variables (a name that starts with {own}_ is fine)" if suffix
                else f"a variable that is not named for this platform (its name does not start with {own}_), so it may hold "
                     "another service's or another event's secret")
    return (f"event.token_env names {name}{where}, {what}, not a token for this platform: flightdeck would hand its value "
            f"to the {plugin} plugin. Name the variable that holds your token for it, like {own}_TOKEN")


def _variable_prefix(plugin: str) -> str:
    """The start of the names of a plugin's own variables: ACME for acme, MY_CTF for my-ctf."""
    return plugin.upper().replace("-", "_")


def http_token_env(name: str, http: HttpConfig, config: Config | None, url: str) -> str | None:
    """Why event.token_env = `name` cannot be the token variable of an event on the http
    platform, or None when it can. The profile names the variable and the address its value
    is sent to, and the profile may be a teammate's, so the only variable it can name is one
    named for this kind of platform (HttpConfig.names_token): HTTP_TOKEN, a name that starts
    with HTTP_TOKEN_ or, with a preset, with the preset's name and a _ (RCTF_TOKEN,
    RCTF_TOKEN_QUALS). A name that only starts with HTTP_ is not one: HTTP_PROXY holds a
    proxy's address and often its password. Never a variable the player's config names for a
    secret of its own, nor one of OTHER_SERVICE_KEYS, whatever their names. So a CTFd token,
    another service's key, a proxy's password and a secret no list knows stay where they
    are. `config`: the player's config when it could be read."""
    prefix = http.variable_prefix
    setting = config_secrets(config).get(name) if config is not None else None
    where = f" ({setting} in your config)" if setting else ""
    starts = f"{http_platform.TOKEN_VARIABLE}_" + (f" or {prefix}" if prefix else "")
    if setting == "notify.webhook_env":
        what = "the variable that holds your notification webhook's URL"
    elif setting or name in OTHER_SERVICE_KEYS:
        what = "a variable for another service's key"
    elif http.names_token(name):
        return None
    elif _PROXY_VARIABLE.fullmatch(name):
        what = "a proxy setting, whose value is a proxy's address and often the password for it"
    else:
        suffix = next((suffix for suffix in OTHER_SERVICE_SUFFIXES if name.endswith(suffix)), None)
        what = (f"a name ending in {suffix} like other services' key variables ({http_platform.TOKEN_VARIABLE}, or a name that "
                f"starts with {starts}, is fine)" if suffix
                else f"a variable that is not named for this platform (its name is not {http_platform.TOKEN_VARIABLE} and does not "
                     f"start with {starts}), so it may hold another service's or another event's secret")
    return (f"event.token_env names {name}{where}, {what}, not a token for this platform: flightdeck would send its value "
            f"to {untrusted(url, one_line=True)}. Name the variable that holds your token for it, like {http.variable_example}")


def _check_http(
    profile: EventProfile,
    requested: Policies,
    env: Mapping[str, str],
    model_config: Config | ConfigError | None,
    refuse: list[str],
    warn: list[str],
) -> None:
    """A profile on the http platform: its [http] table, the url every route is under, and a
    token variable named for the platform. The table needs no leave from the player's config:
    it is data, and what it can make flightdeck send is bounded by platform/http.py and shown
    by describe(). A board folder may be absent (a pull makes it), but not a file, and it must
    be inside the profile's own folder, as a plugin's."""
    http = profile.http
    if http is None:
        refuse.append(f'platform "http" needs an [http] table: {http_platform.PRESET_CHOICE}, or the platform\'s own routes (docs/BOARDS.md)')
        return
    uses = requested.pull in USES_PLATFORM or requested.submit in USES_PLATFORM
    if profile.url is None:
        refuse.append('event.url is required for platform "http": the platform\'s address, which every route of the [http] table is under')
    variable = profile.token_env
    if variable is None:
        refuse.append('event.token_env is required for platform "http": the name of the environment variable that holds your '
                      f"token (the token itself never goes in the profile), like {http.variable_example}")
    elif (wrong := http_token_env(variable, http, model_config if isinstance(model_config, Config) else None,
                                  profile.url or "(no url)")) is not None:
        refuse.append(wrong)
    elif uses and not _is_set(env, variable):
        warn.append(f"the token variable {variable} (event.token_env) is not set or is empty: export your token in it")
    url = _split_url(profile.url) if profile.url else None
    if url is not None and url.scheme == "http" and not _loopback(url.hostname or ""):
        warn.append("event.url is http, not https: your token would cross the network unencrypted")
    if requested.submit in USES_PLATFORM and http.submit is None:
        refuse.append(f'the submit policy "{requested.submit}" sends flags to the platform, and the [http] table has no '
                      '[http.submit] to send them by: add it, or set submit = "manual" under [policies]')
    board = profile.board
    if board is not None:
        elsewhere = plugin_board_problem(profile)
        if elsewhere is not None:
            refuse.append(elsewhere)
        else:
            try:
                if board.exists() and not board.is_dir():
                    refuse.append(f"event.board: {_show(board)}: is not a directory")
            except OSError as exc:
                refuse.append(f"event.board: {_show(board)}: cannot be read ({exc.strerror or type(exc).__name__})")
    if not uses:
        warn.append("this run does not use the platform's API: pull and submit are both by hand")


def plugin_http_warning(profile: EventProfile, plugin: str) -> str | None:
    """The warning for a profile whose address would carry the token the plugin is given over
    plain http (a loopback address apart), or None."""
    url = _split_url(profile.url) if profile.url else None
    if url is not None and url.scheme == "http" and not _loopback(url.hostname or ""):
        return f"event.url is http, not https: the token the {plugin} plugin is given would cross the network unencrypted"
    return None


def _check_plugin(
    profile: EventProfile,
    requested: Policies,
    env: Mapping[str, str],
    model_config: Config | ConfigError | None,
    refuse: list[str],
    warn: list[str],
) -> None:
    """A profile on a plugin's platform. Only the player's config allows a plugin: without a
    config that was read (`model_config` a ConfigError, or None) or without a [plugins] table
    of the platform's name the run is refused, and event.platform is not shown. With one, the
    plugin's plugin.toml must be usable (nothing of the plugin is run here), the profile must
    name the url, and the token variable when the plugin takes a token, which must not be
    another service's. A board folder may be absent (a pull makes it), but not a file."""
    if not isinstance(model_config, Config):
        refuse.append(NO_CONFIG_FOR_PLUGIN)
        return
    ref = model_config.plugins.get(profile.platform)
    if ref is None:
        refuse.append(no_such_plugin(model_config))
        return
    try:
        plugin = plugin_manifest.load(ref)
    except plugin_manifest.PluginError as exc:
        refuse.append(str(exc))
        return
    name = plugin.name  # the config's own word from here on
    uses = requested.pull in USES_PLATFORM or requested.submit in USES_PLATFORM
    if profile.url is None:
        refuse.append("event.url is required for a plugin's platform: the address its adapter talks to")
    variable = profile.token_env
    if plugin.token:
        if variable is None:
            refuse.append(f'event.token_env is required for platform "{name}": the name of the environment variable that '
                          "holds your token")
        elif (wrong := plugin_token_env(variable, name, model_config)) is not None:
            refuse.append(wrong)
        elif uses and not _is_set(env, variable):
            warn.append(f"the {name} token variable {variable} (event.token_env) is not set or is empty: export your token in it")
        if (unencrypted := plugin_http_warning(profile, name)) is not None:
            warn.append(unencrypted)
    elif variable is not None:
        warn.append(f"event.token_env does nothing in this run: the {name} plugin takes no token (token = false in its plugin.toml)")
    board = profile.board
    if board is not None:
        elsewhere = plugin_board_problem(profile)
        if elsewhere is not None:
            refuse.append(elsewhere)
        else:
            try:
                if board.exists() and not board.is_dir():
                    refuse.append(f"event.board: {_show(board)}: is not a directory")
            except OSError as exc:
                refuse.append(f"event.board: {_show(board)}: cannot be read ({exc.strerror or type(exc).__name__})")
    if not uses:
        warn.append(f"this run does not use the {name} plugin: pull and submit are both by hand")


def plugin_board_problem(profile: EventProfile) -> str | None:
    """Why the event.board of a profile on a plugin's platform cannot be its board, or None.

    A pull through a plugin (or the http platform's own) writes what the platform lists (folders, and files under the names
    the platform gives them) into the board folder, makes that folder when it is not there,
    and under the pull policy auto asks nothing. The profile may be someone else's, so the
    folder it names must be inside the profile's own folder, links followed: never another
    folder of the machine that loads what is put in it (an editor's plugin folder).
    A folder the player names on the command line is the player's own word, and may be
    anywhere; the profile then names none."""
    board, source = profile.board, profile.source
    if board is None or source is None:
        return None
    try:
        folder = source.absolute().parent.resolve()
        inside = board.resolve().is_relative_to(folder) and board.resolve() != folder
    except (OSError, RuntimeError):  # a loop of links, a name too long
        inside = False
    if inside:
        return None
    whose, pull = ("the http platform", http_platform.PULL_COMMAND) if profile.platform == "http" else ("a plugin's platform", "flightdeck plugin pull")
    return (f"event.board: for {whose} the board is a folder inside the profile's own folder "
            f"({_show(source.absolute().parent)}): a pull writes what the platform lists into it, and a profile may be someone "
            "else's. For a board elsewhere, take event.board out of the profile and name the folder yourself: "
            f"`flightdeck play FOLDER --event EVENT.toml`, `{pull} EVENT.toml FOLDER`")


def _check_manual(profile: EventProfile, refuse: list[str]) -> None:
    board = profile.board
    if board is None:
        refuse.append('event.board is required for platform "manual": the folder of challenge folders')
        return
    try:
        if board.is_dir():
            return
        what = "is not a directory" if board.exists() else "no such directory"
    except OSError as exc:  # pathlib passes on all but "no such file" and the like: a name too long, no permission
        what = f"cannot be read ({exc.strerror or type(exc).__name__})"
    refuse.append(f"event.board: {_show(board)}: {what}")


def _check_models(agents: Policy, env: Mapping[str, str], model_config: Config | ConfigError | None, warn: list[str]) -> None:
    if isinstance(model_config, ConfigError):
        warn.append(f'the agents policy is "{agents}", but no model config could be loaded: {model_config}')
    elif isinstance(model_config, Config):
        keys = [("API key", model_config.api.key_env, "api.key_env")]
        if model_config.fallback is not None:
            keys.append(("fallback API key", model_config.fallback.key_env, "fallback.key_env"))
        for what, key, setting in keys:
            if key and not _is_set(env, key):
                warn.append(
                    f'the agents policy is "{agents}", but the {what} variable {key} ({setting} in '
                    f"{_show(model_config.source)}) is not set or is empty"
                )


def _rule(profile: EventProfile, stage: str) -> str:
    """The rule that limits a stage."""
    if stage == "agents":
        return "rules.ai_allowed = false" if not profile.ai_allowed else "rules.material_to_models = false"
    if stage in ("pull", "submit"):
        return "rules.platform_automation = false"
    if stage == "instance":
        return f'rules.live_targets = "{profile.live_targets}"'
    return "no rule limits it"  # l1: allowed() never limits it


def _other_service(name: str, own: str = "CTFD") -> str | None:
    """Why a token_env of `name` looks like another service's key variable; None when it does
    not. `own`: what a name of the platform's own token variable holds (CTFD; GM for a Game
    Master's)."""
    if name in OTHER_SERVICE_KEYS:
        return "a variable for another service's key"
    if own not in name:
        for suffix in OTHER_SERVICE_SUFFIXES:
            if name.endswith(suffix):
                return f"a name ending in {suffix} like other services' key variables (a name with {own} in it is fine)"
    return None


def _is_set(environ: Mapping[str, str], name: str) -> bool:
    """Whether the variable holds something. That is all that is learned: the value is never
    kept, shown, logged or compared with anything."""
    return bool(environ.get(name, "").strip())


# ---------------------------------------------------------------------- what a run will do


COUNTED_WAIT = ", and so does every flag of a challenge whose tries the platform counts"
COUNTED_GO = (  # the player's config opts in ([lanes] submit_limited "auto")
    '; submit_limited = "auto" in your config: a challenge whose tries the platform counts gets a claimed flag at once too, '
    "the last try included"
)

_MEANING = {
    "pull": {
        Policy.AUTO: "flightdeck gets the board itself",
        Policy.CONFIRM: "flightdeck pulls the board once, after you say yes (no new waves)",
        Policy.MANUAL: "you put the challenges in the board folder",
        Policy.OFF: "the board is not fetched or updated",
    },
    "l1": {
        Policy.AUTO: "your no-model solvers run on each challenge",
        Policy.CONFIRM: "your no-model solvers run first on each challenge (starting play is your yes)",
        Policy.MANUAL: "your solvers do not run in lanes; `flightdeck l1 route` lists those that match a challenge",
        Policy.OFF: "no L1 solvers",
    },
    "agents": {
        Policy.AUTO: "model-driven lanes start on their own, up to the lane limit",
        Policy.CONFIRM: "lanes start on their own, up to the lane limit (starting play is your yes)",
        Policy.MANUAL: "`flightdeck play` does not start: it plays with agent lanes",
        Policy.OFF: "no model-driven lanes: `flightdeck play` does not start",
    },
    "submit": {
        Policy.AUTO: (
            "a flag a lane claims goes to the platform at once (a model's submit_flag, a coding agent's FLAG: line, "
            "a flag an L1 engine returns as its result); any other match waits for your approval" + COUNTED_WAIT
        ),
        Policy.CONFIRM: "each flag is submitted after you approve it",
        Policy.MANUAL: "you submit flags yourself and tell flightdeck how it went",
        Policy.OFF: "flightdeck never submits flags",
    },
    "instance": {
        Policy.AUTO: "lanes may reach their challenge's live instance",
        Policy.CONFIRM: "each lane asks you before it reaches its challenge's live instance",
        Policy.MANUAL: "lanes stay off live instances; you work them yourself",
        Policy.OFF: "no lane touches a live instance",
    },
}


FOLDER_BOARD = "a folder board: nothing to fetch"  # the pull line of a manual profile, whatever its policy
# the pull line of a Game Master profile, whatever its policy: a run never pulls or starts an attempt
GM_BOARD = "the board `flightdeck gm pull` wrote: a run pulls nothing and starts no attempt"
# the pull line of a profile on a plugin's platform, by its policy
PLUGIN_BOARD = {
    Policy.AUTO: "flightdeck pulls the board through the plugin, at the start and again every 5 minutes",
    Policy.CONFIRM: "flightdeck pulls the board through the plugin once, after you say yes (no later pulls)",
    Policy.MANUAL: "the run pulls nothing: it plays the board `flightdeck plugin pull` wrote",
    Policy.OFF: "the run pulls nothing: it plays the board `flightdeck plugin pull` wrote",
}
# the pull line of a profile on the http platform, by its policy
HTTP_BOARD = {
    Policy.AUTO: "flightdeck pulls the board by the [http] table's routes, at the start and again every 5 minutes",
    Policy.CONFIRM: "flightdeck pulls the board by the [http] table's routes once, after you say yes (no later pulls)",
    Policy.MANUAL: "the run pulls nothing: it plays the board `flightdeck http pull` wrote",
    Policy.OFF: "the run pulls nothing: it plays the board `flightdeck http pull` wrote",
}
# A coding-agent lane's container reaches its CLI's own API whatever the instance policy
# (run.lane_reach gives every such lane agent.egress.CLI_API), and nothing else but its instance.
AGENT_NETWORK = "; a coding-agent lane (--agent) reaches its CLI's API in every case"

NO_PACK = (
    "there is no [l1] pack in your config, so nothing runs at this stage: set pack = \"FOLDER\" under [l1] in it "
    "(a folder of engines; `flightdeck l1 import` makes their manifests), or give play --pack FOLDER"
)


def describe(
    profile: EventProfile,
    policies: Policies,
    *,
    environ: Mapping[str, str] | None = None,
    config: Config | ConfigError | None = None,
) -> list[str]:
    """What a run with this profile and these policies will do, one line each, made safe to show.
    `config` is the player's config, or the ConfigError loading it raised, or None: with a
    config that names no L1 pack, the l1 stage says nothing runs there and how to set one.
    A plugin's platform is named only when that config has it under [plugins]."""
    env = os.environ if environ is None else environ
    no_pack = isinstance(config, Config) and config.l1.pack is None
    plugin = profile.platform if profile.plugin and isinstance(config, Config) and profile.platform in config.plugins else None
    mode = "team" if profile.team else "solo"
    if profile.platform == "ctfd":
        where = f"ctfd at {_shown_url(profile)}"
    elif profile.platform == "gamemaster":
        where = f"a Game Master at {_shown_url(profile)}"
    elif profile.platform == "manual":
        where = "manual (a folder board)"
    elif profile.platform == "http":
        preset = profile.http.preset if profile.http is not None else None
        where = f"http ({preset + ' preset' if preset else 'the routes of its [http] table'}) at {_shown_url(profile)}"
    elif plugin is not None:
        where = f"{plugin} (a plugin) at {_shown_url(profile)}"
    else:
        where = "a plugin's platform (not in your config)"
    lines = [f"event     {untrusted(profile.name, one_line=True)} · {where} · {mode}"]
    rules = [
        "AI allowed" if profile.ai_allowed else "no AI",
        "platform automation allowed" if profile.platform_automation else "no platform automation",
        f"live targets {profile.live_targets}",
    ]
    if profile.max_lanes is not None:
        rules.append(f"at most {profile.max_lanes} lanes")
    if not profile.material_to_models:
        rules.append("no challenge material to a model")
    lines.append("rules     " + " · ".join(rules))
    if profile.declared_label is not None:
        lines.append(f"label     {label_line(profile.declared_label)}")
    if profile.platform in ("ctfd", "gamemaster", "http") and profile.token_env is not None:
        state = "set" if _is_set(env, profile.token_env) else "NOT set"
        lines.append(f"token     ${profile.token_env} ({state}), sent only to {_shown_url(profile)}")
    if plugin is not None and profile.token_env is not None:
        state = "set" if _is_set(env, profile.token_env) else "NOT set"
        # where it goes is the address above: the profile's word, which the player reads here before the plugin has the token
        lines.append(f"token     ${profile.token_env} ({state}), given only to the {plugin} plugin, for {_shown_url(profile)}")
    if profile.platform == "http" and profile.http is not None:
        # every request the table can make, and where the token goes: read before anything runs, as `plugin add` shows a plugin
        lines += [f"http      {line}" for line in http_platform.plan(profile.http, profile.instances)]
    if profile.board is not None:
        lines.append(f"board     {_show(profile.board)}")
    if profile.start is not None or profile.end is not None:
        when = [f"{name} {value.isoformat()}" for name, value in (("starts", profile.start), ("ends", profile.end)) if value is not None]
        lines.append("schedule  " + " · ".join(when) + " (autopilot waits for the start and stops at the end)")
    if profile.flag_format is not None:
        lines.append(f"flags     {untrusted(profile.flag_format, one_line=True)}")
    else:
        lines.append("flags     (not set: the board's flag format, else word{...})")
    loosest = allowed(profile)
    for stage, policy in policies.items():
        limit = getattr(loosest, stage)
        note = ""
        if looser(policy, limit):
            note = f" (looser than the rules allow: at most {limit})"
        elif policy is not limit:
            note = f" (the rules allow {limit})"
        meaning = _MEANING[stage][policy]
        if stage == "pull" and profile.platform == "manual":
            meaning = FOLDER_BOARD
        if stage == "pull" and profile.platform == "gamemaster":
            meaning = GM_BOARD
        if stage == "pull" and profile.plugin:
            meaning = PLUGIN_BOARD[policy]
        if stage == "pull" and profile.platform == "http":
            meaning = HTTP_BOARD[policy]
        if stage == "submit" and policy is Policy.AUTO and isinstance(config, Config) and config.lanes.submit_limited == "auto":
            meaning = meaning.removesuffix(COUNTED_WAIT) + COUNTED_GO
        if stage == "l1" and policy is not Policy.OFF and no_pack:
            meaning = NO_PACK
        lines.append(f"{stage:<10}{policy.value:<9}{meaning}{note}")
    if policies.instance is Policy.AUTO:
        network = "a docker lane's network reaches its challenge's live instance and nothing else; without one it has none"
    elif policies.instance is Policy.CONFIRM:
        network = "a docker lane has no network until you allow it its instance, then one that reaches the instance and nothing else"
    else:
        network = f'docker lanes get no network (instance "{policies.instance}")'
    lines.append(f"network   {network}{AGENT_NETWORK}")
    return lines


def label_line(label: str) -> str:
    """The declared label as a run shows it before it starts: the team's word to the event,
    which flightdeck shows and records and never checks."""
    return (f"{untrusted(label, one_line=True)} (what your team declared to the event: rules.declared_label; "
            "flightdeck shows it and records it with the run, and checks nothing by it)")


def instances_off(profile: EventProfile, policies: Policies) -> str:
    """Why flightdeck starts no instance on the platform under this profile and these policies,
    or "" when it does: it needs the [instances] table, CTFd or the http platform (and a named
    plugin of that platform's), the rules' leave to use the platform's API, and an instance
    policy of auto (starting one is reaching it). A plugin's platform is not named:
    event.platform is the profile's word, and nothing shows it."""
    if profile.instances is None:
        return "the profile has no [instances] table"
    if profile.plugin:
        return "the event is on a plugin's platform, and flightdeck starts instances only on CTFd and the http platform"
    if profile.platform not in INSTANCE_PLATFORMS:
        return f'the platform is "{profile.platform}", and flightdeck starts instances only on CTFd and the http platform'
    shape = profile.instances.platform
    if shape is not None and shape != profile.platform:
        return (f'instances.plugin {profile.instances.plugin} is for platform "{shape}", and this event\'s is '
                f'"{profile.platform}"' + (' (rCTF v2\'s instancer: plugin = "rctf"; GZCTF\'s: plugin = "gzctf")' if profile.platform == "http" else ""))
    if not profile.platform_automation:
        return "the rules do not allow flightdeck to use the platform's API (rules.platform_automation is false)"
    if policies.instance is not Policy.AUTO:
        return f'the instance policy is "{policies.instance}", and flightdeck starts an instance only under "auto"'
    return ""


def example_profile() -> str:
    """A commented event profile that loads; the player edits it to the event's rules."""
    return EXAMPLE


EXAMPLE = """\
# ctf-flightdeck event profile: what this event's rules allow. Write it from the rules, then
# check it with `flightdeck preflight event.toml`. It holds no secret: the CTFd token stays in
# the environment variable that token_env names.

[event]
name = "Example CTF"
platform = "ctfd"                   # "ctfd": flightdeck uses CTFd's API; "manual": a folder board
url = "https://ctf.example.org"     # ctfd: the site's address
token_env = "CTFD_TOKEN"            # ctfd: the NAME of the variable that holds your API token
# board = "board"                   # manual: the folder of challenge folders (relative to this file, or ~/...)
flag_format = "example\\\\{[^}]+\\\\}"  # a regular expression for the event's flags
team = false                        # true: claims, teammates' solves and live-box holds (team mode)
# start = "2026-11-14T09:00:00+00:00"  # when the event starts, with its zone: autopilot waits for it
# end = "2026-11-15T09:00:00+00:00"    # when it ends: autopilot stops the run then

[rules]
ai_allowed = true                   # may model-driven lanes work challenges
platform_automation = true          # may flightdeck pull and submit through the platform's API
live_targets = "confirm"            # "allowed", "confirm" or "off": may lanes touch challenge instances
# max_lanes = 8                     # if the rules limit how many agents run at once
# material_to_models = false        # if the rules forbid giving a challenge's text or files to a model: no lane then starts
# declared_label = "Human-Led AI"   # if the event has teams declare a label for their AI use: yours, in the event's words

# Optional. Each stage: "auto", "confirm", "manual" or "off"; stricter than the rules allow if you
# like, never looser. A stage left out gets the loosest the rules allow, and submit gets "confirm".
[policies]
# pull = "auto"                     # get the board from the platform
# l1 = "auto"                       # run your no-model solvers
# agents = "auto"                   # start model-driven lanes
# submit = "confirm"                # submit flags to the platform
# instance = "confirm"              # let lanes reach challenge instances

# Optional, on CTFd (or on rCTF v2, platform "http", with plugin = "rctf"): challenges whose
# instance the platform starts when asked (a container per team, a few at a time). With this table and the instance policy "auto", flightdeck starts
# one before a lane works its challenge, keeps at most max_running going, and stops it when the
# challenge is solved or nobody works it. See BOARDS.md for a plugin that is not listed.
# [instances]
# plugin = "docker_per_team"        # the site's container plugin: docker_per_team, ctfd_owl or chall_manager (BOARDS.md)
# types = ["container"]             # CTFd challenge types that have such an instance (a pull records each challenge's type)
# max_running = 3                   # the most kept running at once: the site's cap for a team, or less
"""


# ---------------------------------------------------------------------- reading


def load_profile(path: Path) -> tuple[EventProfile, Policies]:
    """Read and check an event profile. The policies are those its [policies] table sets, and
    defaults() for the rest. A policy looser than the rules allow is kept: check() refuses it."""
    try:
        path = Path(path).expanduser()
    except RuntimeError:  # ~user for a user that does not exist
        raise ProfileError(f"{_show(path)}: starts with ~ for a home directory that cannot be found") from None
    doc = _parse(path)
    _known(path, (), doc, _TABLES)
    event = _table(path, doc, "event")
    rules = _table(path, doc, "rules")
    _known(path, ("event",), event, _EVENT_KEYS)
    _known(path, ("rules",), rules, _RULE_KEYS)
    stages = _requested(path, _table(path, doc, "policies", required=False))
    profile = EventProfile(
        name=_string(path, event, ("event", "name"), required="the event's name, as the console shows it"),
        platform=_platform(path, event),
        url=_url(path, event),
        token_env=_token_env(path, event),
        board=_board(path, event),
        flag_format=_flag_format(path, event),
        team=_bool(path, event, ("event", "team"), default=False),
        **_schedule(path, event),
        ai_allowed=_bool(path, rules, ("rules", "ai_allowed"), required="true if the event's rules allow AI (model-driven) help, false if not"),
        platform_automation=_bool(
            path, rules, ("rules", "platform_automation"),
            required="true if the rules allow scripts to use the platform's API (pulling challenges, submitting flags), false if not",
        ),
        live_targets=_choice(
            path, rules, ("rules", "live_targets"), LIVE_TARGETS,
            required='"allowed", "confirm" or "off": may lanes touch challenge instances, only after you say yes, or never',
        ),
        max_lanes=_max_lanes(path, rules),
        material_to_models=_bool(path, rules, ("rules", "material_to_models"), default=True),
        declared_label=_label(path, rules),
        instances=_instances(path, doc),
        http=_http(path, doc, event),
        explicit=frozenset(stages),
        source=path,
    )
    return profile, replace(defaults(profile), **stages)


def _instances(path: Path, doc: dict) -> InstancesConfig | None:
    if "instances" not in doc:
        return None
    try:
        return parse_instances(doc["instances"])
    except ValueError as exc:
        raise ProfileError(f"{_show(path)}: {exc}") from None


def _http(path: Path, doc: dict, event: dict) -> HttpConfig | None:
    """The [http] table, checked (platform/http.py). A profile whose platform is "http" must have one."""
    if "http" not in doc:
        if event.get("platform") == "http":
            raise ProfileError(f'{_show(path)}: the [http] table is missing: platform = "http" asks the platform by the routes it '
                               f'writes ({http_platform.PRESET_CHOICE}, or the platform\'s own: `flightdeck http example` prints one to edit)')
        return None
    try:
        return http_platform.parse_config(doc["http"])
    except ValueError as exc:
        raise ProfileError(f"{_show(path)}: {exc}") from None


def _parse(path: Path) -> dict:
    try:
        with path.open("rb") as handle:
            raw = handle.read(MAX_PROFILE_BYTES + 1)
    except FileNotFoundError:
        how = f"flightdeck preflight --example > {shlex.quote(str(path))}"
        raise ProfileError(f"{_show(path)}: no such file. Write one from the event's rules, starting from `{how}`") from None
    except IsADirectoryError:
        raise ProfileError(f"{_show(path)}: is a directory, not an event profile") from None
    except OSError as exc:
        raise ProfileError(f"{_show(path)}: cannot read it ({exc.strerror})") from None
    if len(raw) > MAX_PROFILE_BYTES:
        raise ProfileError(f"{_show(path)}: is over {MAX_PROFILE_BYTES // 1000} KB, too big for an event profile")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError(f"{_show(path)}: is not UTF-8 text") from None
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:  # its message may quote a key from the file
        raise ProfileError(f"{_show(path)}: is not valid TOML: {_show(exc)}") from None
    except ValueError:  # the one tomllib leaves unwrapped: int() refuses a number of thousands of digits
        raise ProfileError(f"{_show(path)}: is not valid TOML: it holds a number too long to read") from None
    except RecursionError:
        raise ProfileError(f"{_show(path)}: is not valid TOML: its arrays or tables are nested too deeply to read") from None


def _table(path: Path, doc: dict, name: str, *, required: bool = True) -> dict:
    if name not in doc:
        if required:
            raise ProfileError(f"{_show(path)}: the [{name}] table is missing (see `flightdeck preflight --example`)")
        return {}
    value = doc[name]
    if not isinstance(value, dict):
        raise ProfileError(f"{_show(path)}: {name} must be a table ([{name}]){_got(value)}")
    return value


def _known(path: Path, where: tuple[str, ...], table: dict, known: tuple[str, ...]) -> None:
    """Unknown keys are errors: a typo must not leave a rule or policy silently at its default."""
    unknown = [key for key in table if key not in known]
    if not unknown:
        return
    if where:
        names = ", ".join(_key(*where, key) for key in unknown)
        raise ProfileError(f"{_show(path)}: unknown key {names} (known in {_key(*where)}: {', '.join(known)})")
    names = ", ".join(f"table [{_key(key)}]" if isinstance(table[key], dict) else f"key {_key(key)}" for key in unknown)
    raise ProfileError(f"{_show(path)}: unknown {names} (the known tables are {', '.join(f'[{t}]' for t in known)})")


def _requested(path: Path, table: dict) -> dict[str, Policy]:
    _known(path, ("policies",), table, STAGES)
    return {
        stage: Policy(_choice(path, table, ("policies", stage), tuple(STRICTNESS)))
        for stage in STAGES
        if stage in table
    }


def _string(path: Path, table: dict, key: tuple[str, str], *, required: str = "") -> str | None:
    """A non-empty string; None when absent and not required."""
    if key[1] not in table:
        if required:
            raise _error(path, key, f"is required: {required}")
        return None
    value = table[key[1]]
    if not isinstance(value, str):
        raise _error(path, key, f"must be a string{_got(value)}")
    if not value.strip():
        raise _error(path, key, "must not be empty")
    return value


def _choice(path: Path, table: dict, key: tuple[str, str], choices: tuple[str, ...], *, required: str = "") -> str | None:
    if key[1] not in table:
        if required:
            raise _error(path, key, f"is required: {required}")
        return None
    value = table[key[1]]
    if not isinstance(value, str) or value not in choices:
        raise _error(path, key, f"must be {_or(choices)}{_got(value)}")
    return value


def _plugin_name(value: object) -> bool:
    """Whether `value` could be the name of a plugin's platform: a name as the config's
    [plugins] table takes one, and not shaped like a token pasted where the name belongs."""
    return isinstance(value, str) and PLUGIN_NAME.fullmatch(value) is not None and _TOKEN_SHAPE.fullmatch(value) is None


def _platform(path: Path, event: dict) -> str:
    """event.platform: one flightdeck has built in, or a name that a plugin could have. The
    value is never shown: only the player's config makes it a plugin's name (check())."""
    key = ("event", "platform")
    if "platform" not in event:
        raise _error(path, key, 'is required: "ctfd" (flightdeck uses CTFd\'s API), "manual" (a folder of challenge folders), '
                                '"gamemaster" (a board `flightdeck gm pull` wrote), "http" (a platform with a JSON API, by '
                                'the routes of an [http] table) or the name of a plugin you added')
    value = event["platform"]
    if value not in PLATFORMS and not _plugin_name(value):
        names = ", ".join(json.dumps(name) for name in PLATFORMS)
        raise _error(path, key, f"must be {names} or the name of a plugin you added (lower-case letters, digits, - and _)"
                                + ("" if isinstance(value, str) else _got(value)))
    return value


def _bool(path: Path, table: dict, key: tuple[str, str], *, required: str = "", default: bool = False) -> bool:
    if key[1] not in table:
        if required:
            raise _error(path, key, f"is required: {required}")
        return default
    value = table[key[1]]
    if not isinstance(value, bool):
        raise _error(path, key, f"must be true or false{_got(value)}")
    return value


def _url(path: Path, table: dict) -> str | None:
    raw = _string(path, table, ("event", "url"))
    if raw is None:
        return None
    key = ("event", "url")
    if not _plain(raw):
        raise _error(path, key, "must not contain spaces or control characters")
    url = _split_url(raw)
    if url is None or url.scheme not in ("http", "https") or not url.hostname:
        raise _error(path, key, "must start with https:// (or http://) and name a host, like https://ctf.example.org")
    if url.username is not None or url.password is not None:
        raise _error(path, key, "must not carry a user name or password; the token goes in the variable event.token_env names")
    if url.query or url.fragment or raw.endswith(("?", "#")):
        raise _error(path, key, "must be the site's address, with no query (?...) or fragment (#...)")
    return raw.rstrip("/")


def _token_env(path: Path, table: dict) -> str | None:
    """The token variable's name. A value that is not one is never shown: it may be the token."""
    name = _string(path, table, ("event", "token_env"))
    if name is None or _is_env_name(name):
        return name
    if _TOKEN_SHAPE.fullmatch(name):
        raise _error(
            path,
            ("event", "token_env"),
            "looks like a CTFd API token itself, not the name of the variable that holds it: export the token "
            '(export CTFD_TOKEN=...) and name that variable here, like token_env = "CTFD_TOKEN"',
        )
    raise _error(path, ("event", "token_env"), _NOT_A_NAME)


def _board(path: Path, table: dict) -> Path | None:
    raw = _string(path, table, ("event", "board"))
    if raw is None:
        return None
    try:
        board = Path(raw).expanduser()
    except RuntimeError:  # ~user for a user that does not exist
        raise _error(path, ("event", "board"), "starts with ~ for a home directory that cannot be found") from None
    return board if board.is_absolute() else path.absolute().parent / board


def _flag_format(path: Path, table: dict) -> str | None:
    """One line, nothing hidden, short, and a regular expression that compiles (flagformat.py).
    The error shows the format only escaped and cut short."""
    pattern = _string(path, table, ("event", "flag_format"))
    if pattern is None:
        return None
    broken = flag_format_problem(pattern)
    if broken is not None:
        raise _error(path, ("event", "flag_format"), broken)
    return pattern


TIME_SHAPE = 'an ISO 8601 time with its zone, like "2026-11-14T09:00:00+01:00" or "2026-11-14T08:00:00Z"'


def _time(path: Path, table: dict, name: str) -> datetime | None:
    """event.start or event.end: an ISO 8601 date and time with its zone (a string, or TOML's
    own date-time), so it means one instant wherever flightdeck runs. None when absent."""
    key = ("event", name)
    if name not in table:
        return None
    value = table[name]
    if isinstance(value, datetime):
        when = value
    elif isinstance(value, str):
        try:
            when = datetime.fromisoformat(value.strip())
        except ValueError:
            raise _error(path, key, f"must be {TIME_SHAPE}{_got(value)}") from None
    else:
        raise _error(path, key, f"must be {TIME_SHAPE}{_got(value)}")
    if when.utcoffset() is None:
        raise _error(path, key, f"must say its zone: {TIME_SHAPE}{_got(value)}")
    return when


def _schedule(path: Path, table: dict) -> dict[str, datetime | None]:
    start, end = _time(path, table, "start"), _time(path, table, "end")
    if start is not None and end is not None and end <= start:
        raise _error(path, ("event", "end"), f"must be after event.start ({start.isoformat()}), but it is {end.isoformat()}")
    return {"start": start, "end": end}


def _max_lanes(path: Path, table: dict) -> int | None:
    if "max_lanes" not in table:
        return None
    value = table["max_lanes"]
    if not _is_int(value) or value < 1:
        raise _error(path, ("rules", "max_lanes"), f"must be a whole number, at least 1{_got(value)}")
    return value


def is_label(value: object) -> bool:
    """Whether `value` can be a declared label: one line of a few words, in letters, digits,
    spaces and hyphens (a flight card shows it, so nothing that could be an address, a path
    or markup), at most MAX_LABEL characters, with a letter or a digit in it."""
    return (isinstance(value, str) and 0 < len(value) <= MAX_LABEL and value == value.strip()
            and all(ch.isalnum() or ch in " -" for ch in value) and any(ch.isalnum() for ch in value))


def _label(path: Path, table: dict) -> str | None:
    """rules.declared_label, with the space around it dropped. A value that is not a label is
    never shown: it is the profile's text, which may be a teammate's."""
    raw = _string(path, table, ("rules", "declared_label"))
    if raw is None:
        return None
    label = raw.strip(" ")
    if not is_label(label):
        raise _error(path, ("rules", "declared_label"), f"must be {LABEL_SHAPE}")
    return label


# ---------------------------------------------------------------------- small helpers


def _split_url(value: str) -> SplitResult | None:
    """The URL's parts, or None when it cannot be parsed or its port is not a number in range."""
    try:
        url = urlsplit(value)
        _ = url.port  # parsing the port is what raises
    except ValueError:
        return None
    return url


def _loopback(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _plain(value: str) -> bool:
    """No whitespace and no control or other unprintable characters."""
    return all(ch.isprintable() and not ch.isspace() for ch in value)


def _is_env_name(value: str) -> bool:
    """An upper-case environment variable name of at most 64 characters (see _ENV_NAME)."""
    return len(value) <= _MAX_ENV_NAME and _ENV_NAME.fullmatch(value) is not None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _got(value: object) -> str:
    """What was found, for an error message: a number or a boolean as written, any other value
    only by its type (a string could be a token pasted into the wrong place)."""
    if isinstance(value, bool):
        return f" (got {'true' if value else 'false'})"
    if isinstance(value, (int, float)):
        return f" (got {value!r})"
    kinds = {str: "a string", list: "a list", dict: "a table"}
    return f" (got {kinds.get(type(value), type(value).__name__)})"


def _or(choices: Sequence[str]) -> str:
    """'"a"', '"a" or "b"', '"a", "b" or "c"'."""
    quoted = [f'"{choice}"' for choice in choices]
    return quoted[0] if len(quoted) == 1 else f"{', '.join(quoted[:-1])} or {quoted[-1]}"


def _key(*parts: str) -> str:
    """A dotted TOML key, with the parts that are not bare keys quoted (escapes included)."""
    return ".".join(part if _BARE_KEY.fullmatch(part) else json.dumps(part) for part in parts)


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _shown_url(profile: EventProfile) -> str:
    return untrusted(profile.url or "(no url)", one_line=True)


def _error(path: Path, key: tuple[str, ...], problem: str) -> ProfileError:
    return ProfileError(f"{_show(path)}: {_key(*key)} {problem}")
