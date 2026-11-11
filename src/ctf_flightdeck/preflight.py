"""Pre-flight: the event profile (what an event's rules allow) and the stage policies.

The player writes an event profile, event.toml, from the event's rules (print a commented one
with `flightdeck preflight --example`):

- [event]: the event's name, its platform ("ctfd": flightdeck uses CTFd's API; "manual": a
  folder board), where the board comes from, the flag format and team mode;
- [rules]: what the rules allow: AI help (ai_allowed), scripts using the platform's API
  (platform_automation), lanes touching challenge instances (live_targets: allowed, confirm or
  off) and, optionally, how many lanes may run at once (max_lanes);
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
makes agents off; rules.platform_automation = false makes pull and submit manual;
rules.live_targets makes instance auto (allowed), confirm (confirm) or off (off); everything
else may be auto. A stage the profile leaves out gets that loosest policy, except submit, which
gets confirm (a flag is submitted only after the player approves it) unless auto is asked for.

check() lists the problems: refusals (a run must not start: a policy looser than the rules
allow, a platform setting missing, more lanes than the rules allow...) and warnings (worth
knowing before the event: a token variable that is not set...).

The profile holds no secret. token_env names the environment variable that holds the platform's
API token, and nothing here reads that variable except to see whether it is set. A profile can
come from a teammate, so everything in it is untrusted: error messages never show its string
values, and what is shown is made safe with text.untrusted().
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
from enum import StrEnum
from pathlib import Path
from typing import NamedTuple
from urllib.parse import SplitResult, urlsplit

from .config import Config, ConfigError
from .text import untrusted


class Policy(StrEnum):
    AUTO = "auto"
    CONFIRM = "confirm"
    MANUAL = "manual"
    OFF = "off"


STRICTNESS = (Policy.AUTO, Policy.CONFIRM, Policy.MANUAL, Policy.OFF)
"""The policies from loosest (flightdeck does the most on its own) to strictest."""

STAGES = ("pull", "l1", "agents", "submit", "instance")
PLATFORMS = ("ctfd", "manual")
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

_TABLES = ("event", "rules", "policies")
_EVENT_KEYS = ("name", "platform", "url", "token_env", "board", "flag_format", "team")
_RULE_KEYS = ("ai_allowed", "platform_automation", "live_targets", "max_lanes")
_PLATFORM_ONLY = {"url": "ctfd", "token_env": "ctfd", "board": "manual"}
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
    platform: str  # "ctfd" | "manual"
    url: str | None = None  # ctfd: the site's address, without a trailing /
    token_env: str | None = None  # ctfd: the NAME of the variable that holds the API token
    board: Path | None = None  # manual: the folder board (absolute: ~ expanded, else from the profile's folder)
    flag_format: str | None = None  # a regular expression; None: the board's, else the deck's default
    team: bool = False
    # [rules]
    ai_allowed: bool
    platform_automation: bool
    live_targets: str  # "allowed" | "confirm" | "off"
    max_lanes: int | None = None  # the rules' upper bound on lanes at once, if they set one
    # where it came from
    explicit: frozenset[str] = frozenset()  # the stages whose policy the [policies] table sets; the rest are derived
    source: Path | None = None  # the file it was read from

    def __post_init__(self) -> None:
        if self.platform not in PLATFORMS:
            raise ValueError(f"platform must be {_or(PLATFORMS)}")
        if self.live_targets not in LIVE_TARGETS:
            raise ValueError(f"live_targets must be {_or(LIVE_TARGETS)}")
        if self.token_env is not None and not _is_env_name(self.token_env):
            # describe() and check() show token_env, so a profile built in code gets the same
            # check as load_profile's, and the value is never shown here either.
            raise ValueError(f"token_env {_NOT_A_NAME}")
        unknown = set(self.explicit) - set(STAGES)
        if unknown:
            raise ValueError(f"explicit names stages that do not exist: {', '.join(sorted(unknown))}")
        object.__setattr__(self, "explicit", frozenset(self.explicit))


@dataclass(frozen=True)
class Problem:
    refuse: bool  # True: the run must not start
    message: str


class ProfileError(Exception):
    """The event profile cannot be used. The message names the file and the key, never a
    string value from the file."""


# ---------------------------------------------------------------------- policies from the rules


def allowed(profile: EventProfile) -> Policies:
    """The loosest policies the event's rules allow."""
    platform = Policy.AUTO if profile.platform_automation else Policy.MANUAL
    return Policies(
        pull=platform,
        l1=Policy.AUTO,
        agents=Policy.AUTO if profile.ai_allowed else Policy.OFF,
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
    """The docker network for a lane: "bridge" only when its challenge has a live instance and
    lanes may reach one (instance auto or confirm); "none" otherwise, so the lane cannot reach
    the instance or anything else. Under manual the player works the instance, not the lane, so
    that is "none" too. Bridge is open egress, not only the instance, and a lane gets it when
    it starts: under confirm nothing holds it back until the player says yes (check() warns)."""
    if policies.instance in (Policy.OFF, Policy.MANUAL) or not urls:
        return "none"
    return "bridge"


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
    else:
        _check_manual(profile, refuse)
    for key, platform in _PLATFORM_ONLY.items():
        if getattr(profile, key) is not None and profile.platform != platform:
            warn.append(f'event.{key} is only for platform "{platform}", so this {profile.platform} profile does not use it')
    agents_on = requested.agents is not Policy.OFF
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
    if agents_on and requested.instance is Policy.CONFIRM:
        # lane_network() gives a docker lane its network when the lane starts, and nothing in a run
        # asks the player before a lane's first use of an instance, so confirm is not enforced yet.
        warn.append(
            'the instance policy is "confirm", but flightdeck does not yet ask you before a lane first reaches '
            "a live instance: a lane can reach it from its first turn, and a docker lane gets an open network "
            "(bridge: any host, not only the instance). Watch the lanes, or set [policies] instance = "
            '"manual" to keep docker lanes off instances'
        )
    if profile.flag_format is None:
        warn.append(
            "event.flag_format is not set: lanes take the board's flag format if it has one, else anything "
            "shaped like word{...}. Set it from the event's rules, so flags in its format are caught"
        )
    return [Problem(True, m) for m in refuse] + [Problem(False, m) for m in warn]


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
        model_key = isinstance(model_config, Config) and model_config.api.key_env == name
        what = "a variable for another service's key" if model_key else _other_service(name)
        if what is not None:
            where = " (api.key_env in your config)" if model_key else ""
            refuse.append(
                f"event.token_env names {name}{where}, {what}, not a CTFd token: flightdeck would send its value "
                f"to {_shown_url(profile)}. Name the variable that holds your CTFd token, like CTFD_TOKEN"
            )
        elif (requested.pull in USES_PLATFORM or requested.submit in USES_PLATFORM) and not _is_set(env, name):
            warn.append(f"the CTFd token variable {name} (event.token_env) is not set or is empty: export your CTFd API token in it")
    url = _split_url(profile.url) if profile.url else None
    if url is not None and url.scheme == "http" and not _loopback(url.hostname or ""):
        warn.append("event.url is http, not https: the CTFd token would cross the network unencrypted")


def _check_manual(profile: EventProfile, refuse: list[str]) -> None:
    board = profile.board
    if board is None:
        refuse.append('event.board is required for platform "manual": the folder of challenge folders')
    elif not board.is_dir():
        what = "is not a directory" if board.exists() else "no such directory"
        refuse.append(f"event.board: {_show(board)}: {what}")


def _check_models(agents: Policy, env: Mapping[str, str], model_config: Config | ConfigError | None, warn: list[str]) -> None:
    if isinstance(model_config, ConfigError):
        warn.append(f'the agents policy is "{agents}", but no model config could be loaded: {model_config}')
    elif isinstance(model_config, Config):
        key = model_config.api.key_env
        if key and not _is_set(env, key):
            warn.append(
                f'the agents policy is "{agents}", but the API key variable {key} (api.key_env in '
                f"{_show(model_config.source)}) is not set or is empty"
            )


def _rule(profile: EventProfile, stage: str) -> str:
    """The rule that limits a stage."""
    if stage == "agents":
        return "rules.ai_allowed = false"
    if stage in ("pull", "submit"):
        return "rules.platform_automation = false"
    if stage == "instance":
        return f'rules.live_targets = "{profile.live_targets}"'
    return "no rule limits it"  # l1: allowed() never limits it


def _other_service(name: str) -> str | None:
    """Why a token_env of `name` looks like another service's key variable; None when it does not."""
    if name in OTHER_SERVICE_KEYS:
        return "a variable for another service's key"
    if "CTFD" not in name:
        for suffix in OTHER_SERVICE_SUFFIXES:
            if name.endswith(suffix):
                return f"a name ending in {suffix} like other services' key variables (a name with CTFD in it is fine)"
    return None


def _is_set(environ: Mapping[str, str], name: str) -> bool:
    """Whether the variable holds something. That is all that is learned: the value is never
    kept, shown, logged or compared with anything."""
    return bool(environ.get(name, "").strip())


# ---------------------------------------------------------------------- what a run will do


_MEANING = {
    "pull": {
        Policy.AUTO: "flightdeck gets the board itself",
        Policy.CONFIRM: "flightdeck gets the board after you say yes",
        Policy.MANUAL: "you put the challenges in the board folder",
        Policy.OFF: "the board is not fetched or updated",
    },
    "l1": {
        Policy.AUTO: "your no-model solvers run on each challenge",
        Policy.CONFIRM: "your no-model solvers run after you say yes",
        Policy.MANUAL: "flightdeck lists the solvers that match; you run them",
        Policy.OFF: "no L1 solvers",
    },
    "agents": {
        Policy.AUTO: "model-driven lanes start on their own, up to the lane limit",
        Policy.CONFIRM: "each model-driven lane starts after you say yes",
        Policy.MANUAL: "a lane starts only when you queue it",
        Policy.OFF: "no model-driven lanes",
    },
    "submit": {
        Policy.AUTO: "flags are submitted to the platform at once",
        Policy.CONFIRM: "each flag is submitted after you approve it",
        Policy.MANUAL: "you submit flags yourself and tell flightdeck how it went",
        Policy.OFF: "flightdeck never submits flags",
    },
    "instance": {
        Policy.AUTO: "lanes may reach their challenge's live instance",
        Policy.CONFIRM: "lanes can reach their challenge's live instance: asking you first is not enforced yet",
        Policy.MANUAL: "lanes stay off live instances; you work them yourself",
        Policy.OFF: "no lane touches a live instance",
    },
}


def describe(profile: EventProfile, policies: Policies, *, environ: Mapping[str, str] | None = None) -> list[str]:
    """What a run with this profile and these policies will do, one line each, made safe to show."""
    env = os.environ if environ is None else environ
    mode = "team" if profile.team else "solo"
    if profile.platform == "ctfd":
        where = f"ctfd at {_shown_url(profile)}"
    else:
        where = "manual (a folder board)"
    lines = [f"event     {untrusted(profile.name, one_line=True)} · {where} · {mode}"]
    rules = [
        "AI allowed" if profile.ai_allowed else "no AI",
        "platform automation allowed" if profile.platform_automation else "no platform automation",
        f"live targets {profile.live_targets}",
    ]
    if profile.max_lanes is not None:
        rules.append(f"at most {profile.max_lanes} lanes")
    lines.append("rules     " + " · ".join(rules))
    if profile.platform == "ctfd" and profile.token_env is not None:
        state = "set" if _is_set(env, profile.token_env) else "NOT set"
        lines.append(f"token     ${profile.token_env} ({state}), sent only to {_shown_url(profile)}")
    if profile.board is not None:
        lines.append(f"board     {_show(profile.board)}")
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
        lines.append(f"{stage:<10}{policy.value:<9}{_MEANING[stage][policy]}{note}")
    if policies.instance in (Policy.AUTO, Policy.CONFIRM):
        lines.append("network   a docker lane gets an open network (bridge: any host) if its challenge has a live instance, else none")
    else:
        lines.append(f'network   docker lanes get no network (instance "{policies.instance}")')
    return lines


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

[rules]
ai_allowed = true                   # may model-driven lanes work challenges
platform_automation = true          # may flightdeck pull and submit through the platform's API
live_targets = "confirm"            # "allowed", "confirm" or "off": may lanes touch challenge instances
# max_lanes = 8                     # if the rules limit how many agents run at once

# Optional. Each stage: "auto", "confirm", "manual" or "off"; stricter than the rules allow if you
# like, never looser. A stage left out gets the loosest the rules allow, and submit gets "confirm".
[policies]
# pull = "auto"                     # get the board from the platform
# l1 = "auto"                       # run your no-model solvers
# agents = "auto"                   # start model-driven lanes
# submit = "confirm"                # submit flags to the platform
# instance = "confirm"              # let lanes reach challenge instances
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
        platform=_choice(
            path, event, ("event", "platform"), PLATFORMS,
            required='"ctfd" (flightdeck uses CTFd\'s API) or "manual" (a folder of challenge folders)',
        ),
        url=_url(path, event),
        token_env=_token_env(path, event),
        board=_board(path, event),
        flag_format=_flag_format(path, event),
        team=_bool(path, event, ("event", "team"), default=False),
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
        explicit=frozenset(stages),
        source=path,
    )
    return profile, replace(defaults(profile), **stages)


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
    except tomllib.TOMLDecodeError as exc:
        raise ProfileError(f"{_show(path)}: is not valid TOML: {exc}") from None


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
    pattern = _string(path, table, ("event", "flag_format"))
    if pattern is None:
        return None
    try:
        re.compile(pattern)
    except re.error as exc:
        where = f" at position {exc.pos}" if exc.pos is not None else ""
        raise _error(path, ("event", "flag_format"), f"is not a valid regular expression ({exc.msg}{where})") from None
    return pattern


def _max_lanes(path: Path, table: dict) -> int | None:
    if "max_lanes" not in table:
        return None
    value = table["max_lanes"]
    if not _is_int(value) or value < 1:
        raise _error(path, ("rules", "max_lanes"), f"must be a whole number, at least 1{_got(value)}")
    return value


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
