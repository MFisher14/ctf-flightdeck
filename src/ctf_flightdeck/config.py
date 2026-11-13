"""The player's config: the model API (and its fallback), the model ladder, prices, lane
settings and the run folder.

It lives outside the repository (~/.config/ctf-flightdeck/config.toml, or the file
$FLIGHTDECK_CONFIG names) and holds no secret: it names the environment variable that
holds the API key, and api_key() reads the key from there only when it is needed
(fallback_key() for the [fallback] API's).

The API speaks one of two dialects, [api] provider: "openai" (an OpenAI-compatible chat
completions endpoint: OpenRouter, OpenAI, a local server; the default) or "anthropic" (the
Anthropic Messages API, through its SDK). The optional [fallback] table names a second API
that a lane moves to when the first keeps failing (agent/fallback.py), with a ladder of the
same length as [models] ladder: position i is used for a lane on ladder[i]. With the
Anthropic API, [api] fast lists the ladder models a lane calls in fast mode; only a model
agent/fastmode.py lists for fast mode is accepted. [api] effort, with the Anthropic API too, is
a table of ladder model -> output_config.effort level for a lane's calls to that model.

[api] and [fallback] also take timeout (seconds one try of a lane's call may take) and
max_tokens (the most tokens a lane's reply may hold). Unset, max_tokens is LOCAL_MAX_TOKENS
for an OpenAI-compatible server on this machine and is not sent to any other: see
lane_max_tokens(). And context: the tokens of context the API's server gives a lane's model,
when that is less than a lane grows to (Ollama gives 4,096 or 32,768 unless told otherwise, and
drops the oldest messages past it without saying so). A lane is then refreshed before it
outgrows that server: lane_refresh_at().

The optional [light] table names the light model for flightdeck's small jobs (light.py):
engine "rules" (the default: no model), "openai" (an OpenAI-compatible server; recommended:
an open-weight model on this machine), "anthropic", "cactus" or "decider" (a Strands Decider
server: a decision model, with a confidence threshold and no key). Its key, like the API's, is
read from the variable its key_env names, by light_key(). With the openai engine, thinking
says whether the model may reason before it answers: see light_thinking().

[light] jobs lists the jobs a run gives the light model (RUN_JOBS: judge, route, recon,
flagcheck); without it, the hint judge alone, as before jobs existed. A job may have an engine
of its own, [light.<job>] (any of LIGHT_JOBS: hint and summary are for eval-local only): a
whole engine spec that must name its engine and inherits nothing from [light], so a key for
one API never meets another's server. light_for() gives the spec a job uses, light_key() its
key. A job whose engine cannot do it (JOB_ENGINES), a table for a run job that jobs leaves out
(it would look on and be off), and recon or flagcheck with no model for them are errors, each
naming its key.

The optional [notify] table turns on the notification webhook (notify.py): webhook_env names
the variable that holds its URL (a secret, read by webhook_url() as a key is; never the URL
itself), and `on` lists which of NOTIFY_KINDS are sent (all of them when it is left out).

Nothing that matters has a silent default. A missing file says how to create one, the
model ladder must be filled in, and an unknown table or key is an error, so a typo
fails loudly instead of quietly leaving the default in place. Every error names the file
and the key. Error messages show numbers but never a string value: a string could be
the API key pasted into the wrong place. The one name they show, the variable api.key_env
names, must be upper case like OPENROUTER_API_KEY: many keys are made only of letters,
digits and _ too, but almost none are all upper case.
"""

from __future__ import annotations

import json
import math
import os
import re
import shlex
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from .core.model import SUBMIT_POLICIES
from .pricing import RATES, Price
from .text import untrusted

CONFIG_ENV = "FLIGHTDECK_CONFIG"
RUNTIMES = ("docker", "host")
DEFAULT_RUN_DIR = "~/.local/share/ctf-flightdeck/runs"

_TABLES = ("api", "models", "prices", "lanes", "run", "l1", "agents", "fallback", "light", "notify", "autopilot", "governor")
NOTIFY_KINDS = ("flag", "needs-you", "disengaged")  # what [notify] on may list, and its default: all three
_API_KEYS = ("provider", "base_url", "key_env", "fast", "effort", "timeout", "max_tokens", "context")
_FALLBACK_KEYS = ("provider", "base_url", "key_env", "ladder", "timeout", "max_tokens", "context")
API_PROVIDERS = ("openai", "anthropic")
ANTHROPIC_BASE_URL = "https://api.anthropic.com"  # the Anthropic SDK's default (it adds /v1/messages itself)
PROVIDER_DEFAULTS = {  # provider -> (base_url, key_env) when the table leaves them out
    "openai": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "anthropic": (ANTHROPIC_BASE_URL, "ANTHROPIC_API_KEY"),
}
_LANE_KEYS = ("max_lanes", "runtime", "image", "token_cap", "dollar_cap", "submit", "submit_limited", "wrong_stop")
LIGHT_ENGINES = ("rules", "openai", "anthropic", "cactus", "decider")
MODEL_ENGINES = ("openai", "anthropic")  # the light engines that take a model, a base_url and a key_env
_LIGHT_KEYS = ("engine", "model", "base_url", "key_env", "timeout", "price", "threshold", "thinking")
LIGHT_JOBS = ("hint", "judge", "summary", "route", "recon", "flagcheck")  # each may have a [light.<job>] table
RUN_JOBS = ("judge", "route", "recon", "flagcheck")  # what [light] jobs may list: the jobs a run gives the light model
EVAL_JOBS = ("hint", "summary")  # measured by eval-local, never used in a run
DEFAULT_JOBS = ("judge",)  # [light] jobs when the table does not set it: the hint judge alone
# The engines that can do each job, from the function eval of 2026-11-11: the rules answer the judge
# and route's category and instance questions, but write no brief and check no flag; Cactus Needle
# called no tool on half the route questions; the decider was near chance on flags.
JOB_ENGINES = {
    "hint": LIGHT_ENGINES,
    "judge": LIGHT_ENGINES,
    "summary": MODEL_ENGINES,
    "route": ("rules", "decider", "openai", "anthropic"),
    "recon": MODEL_ENGINES,
    "flagcheck": MODEL_ENGINES,
}
_CANNOT = {  # why an engine cannot do a job, after "<engine> cannot do <job>: "
    "summary": "a summary is text, which only a model writes (openai or anthropic)",
    "route": "Cactus Needle called no tool on half the route questions when measured (route takes rules, decider, "
             "openai or anthropic)",
    "recon": "a brief is text, which only a model writes (openai or anthropic)",
    "flagcheck": "the rules check no flag (the planted-flag hold is on whatever the light model), and Cactus Needle and "
                 "the decider were near chance on flags when measured (flagcheck takes openai or anthropic)",
}
LIGHT_TIMEOUT = 30.0  # seconds a light job may take, all its tries; then the rules' answer stands
DECIDER_URL = "http://127.0.0.1:8000"  # `strands-decider serve MODEL --port 8000`, its README's example
# The decider's confidence below which its answer is "unsure" and the rules' answer stands. 0.9 is
# the Strands Decider README's calibration claim: on short classification tasks it has never seen,
# answers at a confidence of 0.9 or more are right about 95% of the time (its evaluation/results.md,
# Summary), and its routing convention acts without a check at 0.9 or above (docs/architecture.md).
DECIDER_THRESHOLD = 0.9
OLLAMA_URL = "http://127.0.0.1:11434/v1"  # Ollama's OpenAI-compatible endpoint on this machine
MLX_URL = "http://127.0.0.1:8080/v1"  # an MLX server's (mlx_lm.server's default port)
# A lane's reply cap for an OpenAI-compatible server on this machine when [api] max_tokens is not
# set: mlx_lm.server's own default is 512, and a model that reasons first runs out mid-thought.
LOCAL_MAX_TOKENS = 8192
MAX_REPLY_TOKENS = 1_000_000  # the largest max_tokens accepted: more than any model writes in one reply
MAX_CONTEXT = 10_000_000  # the largest [api] context accepted, in tokens: more than any model reads
# The fewest prompt tokens a lane may reach before a stated context refreshes it: a fresh context
# (the system prompt, the tools, the brief and the summary) takes a few thousand on its own, and a
# lane refreshed every turn or two would do little else.
MIN_REFRESH = 8192
MAX_TRY_SECONDS = 3600.0  # the longest [api] timeout accepted: an hour for one try
LOCAL_TIMEOUT = 600  # the [api] timeout `flightdeck init` writes for a server on this machine
_PRICE_KEYS = RATES  # input, output, cached_input, cache_write
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_MAX_ENV_NAME = 64
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class ApiConfig:
    base_url: str = "https://openrouter.ai/api/v1"
    key_env: str = "OPENROUTER_API_KEY"  # "" for a local server that needs no key (openai provider only)
    provider: str = "openai"  # openai | anthropic: the API's dialect
    fast: tuple[str, ...] = ()  # ladder models a lane calls in fast mode (anthropic only; agent/fastmode.py)
    effort: tuple[tuple[str, str], ...] = ()  # (ladder model, output_config.effort level) pairs (anthropic only)
    timeout: float | None = None  # seconds per try of a lane's call; None: the client's own (180, Anthropic 600)
    max_tokens: int | None = None  # a lane's reply cap as set; None: lane_max_tokens() decides
    context: int | None = None  # tokens of context its server gives a lane's model; None: not stated


@dataclass(frozen=True)
class FallbackConfig:
    """[fallback]: the API a lane moves to when the [api] one keeps failing."""

    provider: str  # openai | anthropic
    base_url: str
    key_env: str  # "" for a local server that needs no key (openai provider only)
    ladder: tuple[str, ...]  # ladder[i] is the fallback for models.ladder[i]
    timeout: float | None = None  # as ApiConfig's
    max_tokens: int | None = None  # as ApiConfig's
    context: int | None = None  # as ApiConfig's


@dataclass(frozen=True)
class LightConfig:
    """[light]: the light model for flightdeck's small jobs (light.py). Absent: rules only."""

    engine: str = "rules"  # rules | openai | anthropic | cactus | decider
    model: str = ""  # openai and anthropic: the model id; decider (optional): the model its server serves
    base_url: str = ""  # openai, anthropic and decider
    key_env: str = ""  # openai and anthropic; "" for a server that needs no key (openai only)
    timeout: float = LIGHT_TIMEOUT  # seconds a job may take, all its tries
    price: Price | None = None  # dollars per million tokens, for an API that reports no cost
    threshold: float = DECIDER_THRESHOLD  # decider: the confidence below which an answer is unsure
    thinking: bool | None = None  # openai only, as set; None: light_thinking() decides


@dataclass(frozen=True)
class LaneConfig:
    max_lanes: int = 4
    runtime: str = "docker"  # docker | host
    image: str = "ctf-flightdeck-lane:1"  # lane.IMAGE: built by `flightdeck image build`
    token_cap: int | None = 400_000  # None: no cap
    dollar_cap: float | None = 2.0  # None: no cap
    submit: str = "confirm"  # confirm | auto
    submit_limited: str = "confirm"  # confirm | auto: under submit auto, spend a challenge's counted tries without the player
    wrong_stop: int = 3  # under submit auto: after this many wrong flags at a challenge its next ones wait for the player; 0: never


@dataclass(frozen=True)
class L1Config:
    pack: Path | None = None  # a folder of L1 engines (manifests); None: no L1 stage
    concurrency: int = 4  # engines run at once on one challenge
    image: str | None = None  # the docker image engines run in when lanes run in Docker; None: the lane image
    lane_tools: bool = False  # lanes' models may call the pack's engines: the pack mounted read-only, its note in the brief


@dataclass(frozen=True)
class NotifyConfig:
    """[notify]: the opt-in notification webhook (notify.py). The URL is a secret (it often
    holds a token), so the config names the variable that holds it, as it does for a key."""

    webhook_env: str = ""  # the environment variable (or keys-file entry) holding the webhook URL; "": no notifications
    on: tuple[str, ...] = NOTIFY_KINDS  # which of NOTIFY_KINDS are sent


@dataclass(frozen=True)
class AutopilotConfig:
    """[autopilot] (autopilot.py, D20): whether a run engages it, and the run budget it needs."""

    engage: bool = False  # true: every play engages autopilot (as --autopilot does for one run)
    budget_dollars: float | None = None  # the whole run's budget in dollars; None: none in dollars
    budget_tokens: int | None = None  # and in tokens; engaging needs at least one of the two


MAX_GOVERNOR_LOAD = 1000.0  # the largest [governor] max_load_per_cpu accepted
MAX_GOVERNOR_MB = 1024 * 1024 * 1024  # the largest [governor] min_free_ram_mb or min_free_disk_mb accepted (1 PiB)


@dataclass(frozen=True)
class GovernorConfig:
    """[governor] (governor.py): the host limits past which no new lane starts. The defaults
    are the solver pack's governor's (packs/solvers/ctf/governor.py): its hard load limit, the
    RAM it wants for one more heavy agent, and its disk floor of 10 GiB."""

    enabled: bool = True  # false: the machine is not read and no start is held for it
    max_load_per_cpu: float = 3.0  # the 1-minute load average per CPU above which no new lane starts; 0: no limit
    min_free_ram_mb: int = 2048  # the RAM available, in MiB, below which no new lane starts; 0: no limit
    min_free_disk_mb: int = 10240  # the free disk at the run folder, in MiB, below which no new lane starts; 0: no limit


@dataclass(frozen=True)
class Config:
    api: ApiConfig
    models: tuple[str, ...]  # the ladder, weakest to strongest
    prices: dict[str, Price]  # dollars per million tokens, for models in the ladder or in an [agents] ladder (and the refusal fallback's: _prices)
    lanes: LaneConfig
    run_dir: Path  # expanded (~)
    source: Path | None  # the file it was read from
    l1: L1Config = L1Config()
    agents: dict[str, tuple[str, ...]] = field(default_factory=dict)  # coding-agent CLI -> its model ladder, weakest first
    fallback: FallbackConfig | None = None  # [fallback], when the config has one
    light: LightConfig = LightConfig()  # [light]; rules only when the config has none
    light_jobs: tuple[str, ...] = DEFAULT_JOBS  # [light] jobs: the jobs a run gives the light model
    light_tables: dict[str, LightConfig] = field(default_factory=dict)  # [light.<job>]: a job's own engine
    notify: NotifyConfig = NotifyConfig()  # [notify]; no webhook when the config has none
    autopilot: AutopilotConfig = AutopilotConfig()  # [autopilot]; off, with no budget, when the config has none
    governor: GovernorConfig = GovernorConfig()  # [governor]; on, with its defaults, when the config has none


@dataclass(frozen=True)
class LightSpec:
    """One distinct light engine spec of a config, and where it is used: `jobs`, the jobs that
    use it (a run's, from [light] jobs, and hint or summary for eval-local), and `tables`, the
    tables that set it ("light", "light.flagcheck", ...)."""

    config: LightConfig
    jobs: tuple[str, ...]
    tables: tuple[str, ...]


class ConfigError(Exception):
    """The config cannot be used. The message names the file and the key, never a secret."""


def default_config_path() -> Path:
    """$FLIGHTDECK_CONFIG if it is set, else ~/.config/ctf-flightdeck/config.toml. ConfigError
    when a ~ in it names a user that does not exist, or there is no home directory."""
    named = os.environ.get(CONFIG_ENV)
    try:
        if named:
            return Path(named).expanduser()
        return Path.home() / ".config" / "ctf-flightdeck" / "config.toml"
    except RuntimeError:
        where = f"${CONFIG_ENV} starts with ~ for a user that does not exist" if named else "there is no home directory"
        raise ConfigError(f"cannot find the config: {where}; name the file with an absolute path in ${CONFIG_ENV}") from None


def load_config(path: Path | None = None) -> Config:
    """Read and check the config file (default: default_config_path())."""
    path = default_config_path() if path is None else expand(Path(path))
    return _config(path, _parse(path))


def parse_config(text: str, source: Path) -> Config:
    """Check a config given as text, as load_config() checks a file, without writing it
    anywhere: `source` is the file it is for, which every error names (flightdeck init
    checks what it is about to write)."""
    return _config(source, _toml(text, source))


def _config(path: Path, doc: dict) -> Config:
    _known(path, (), doc, _TABLES)
    ladder = _ladder(path, _table(path, doc, "models"))
    agents = _agents(path, _table(path, doc, "agents"))  # before [prices], which may name their models
    light, jobs, tables = _light_tables(path, _table(path, doc, "light"))
    api = _api(path, _table(path, doc, "api"), ladder)
    return Config(
        api=api,
        models=ladder,
        prices=_prices(path, _table(path, doc, "prices"), ladder, agents, api.provider),
        lanes=_lanes(path, _table(path, doc, "lanes")),
        run_dir=_run_dir(path, _table(path, doc, "run")),
        source=path,
        l1=_l1(path, _table(path, doc, "l1")),
        autopilot=_autopilot(path, _table(path, doc, "autopilot")),
        governor=_governor(path, _table(path, doc, "governor")),
        agents=agents,
        fallback=_fallback(path, _table(path, doc, "fallback"), ladder) if "fallback" in doc else None,
        light=light,
        light_jobs=jobs,
        light_tables=tables,
        notify=_notify(path, _table(path, doc, "notify")),
    )


def api_key(config: Config) -> str | None:
    """The API key, read from the environment variable api.key_env names (or the keys file);
    None when key_env is "".

    An unset or empty variable is a ConfigError that names the variable and never shows a
    value. A key_env that is not an upper-case variable name may be the key itself, so it is
    refused without being shown, here too (a Config built in code skips load_config's check).
    """
    if config.api.provider == "anthropic":
        otherwise = "or point [api] at another API"
    else:
        otherwise = 'or set api.key_env = "" for a local server that needs no key'
    return _read_key(config, "api", config.api.key_env, otherwise)


def fallback_key(config: Config) -> str | None:
    """The [fallback] API's key, read as api_key() reads the [api] one; None when the config
    has no [fallback] or its key_env is ""."""
    if config.fallback is None:
        return None
    return _read_key(config, "fallback", config.fallback.key_env, "or remove [fallback] from the config")


def light_for(config: Config, job: str) -> LightConfig:
    """The engine spec `job` uses: its own [light.<job>] table, else [light]. (Whether a run
    gives the job the light model at all is [light] jobs: config.light_jobs.)"""
    if job not in LIGHT_JOBS:
        raise ValueError(f"unknown light job {job!r}: one of {', '.join(LIGHT_JOBS)}")
    return config.light_tables.get(job, config.light)


def light_key(config: Config, job: str | None = None) -> str | None:
    """The key of the engine `job` uses (light_for), or of [light]'s when `job` is None, read
    as api_key() reads the [api] one; None for an engine that takes no key (rules, cactus,
    decider) or a key_env of "". An error names the table the key_env is in."""
    light = config.light if job is None else light_for(config, job)
    if light.engine not in MODEL_ENGINES:
        return None
    if job is not None and job in config.light_tables:
        # Removing the table is the always-valid escape: a run job taken out of [light] jobs while
        # its [light.<job>] table stays is itself an error (_check_jobs), so name the table too.
        otherwise = f"or remove [light.{job}]" if job in EVAL_JOBS else f'or take "{job}" out of [light] jobs and remove [light.{job}]'
        return _read_key(config, f"light.{job}", light.key_env, otherwise)
    return _read_key(config, "light", light.key_env, 'or set [light] engine = "rules"')


def light_specs(config: Config) -> list[LightSpec]:
    """Each distinct engine spec of [light] and its job tables, [light]'s first, with the jobs
    that use it: [light]'s by each job in [light] jobs with no table of its own, a table's by
    its job. A spec set the same way in two tables is one spec, used by both their jobs."""
    found: dict[LightConfig, tuple[list[str], list[str]]] = {}
    found[config.light] = ([job for job in config.light_jobs if job not in config.light_tables], ["light"])
    for job, spec in config.light_tables.items():
        jobs, tables = found.setdefault(spec, ([], []))
        jobs.append(job)
        tables.append(f"light.{job}")
    return [LightSpec(spec, tuple(jobs), tuple(tables)) for spec, (jobs, tables) in found.items()]


def lane_max_tokens(provider: str, base_url: str, max_tokens: int | None) -> int | None:
    """What a lane's calls to one API ([api] or [fallback]) send as max_tokens: the table's
    max_tokens when it sets one; else LOCAL_MAX_TOKENS to an OpenAI-compatible server on this
    machine, and None to any other API: nothing is sent to another OpenAI-compatible one
    (OpenAI's own refuses max_tokens on its reasoning models), and the Anthropic client sends
    its own default."""
    if max_tokens is not None:
        return max_tokens
    from .light import on_this_machine

    return LOCAL_MAX_TOKENS if provider == "openai" and on_this_machine(base_url) else None


def reply_room(provider: str, base_url: str, max_tokens: int | None) -> int | None:
    """The most tokens one reply of a lane's call to this API may hold: lane_max_tokens(), or the
    Anthropic client's own default when nothing is set; None when nothing caps it (an
    OpenAI-compatible API elsewhere, sent no max_tokens: its server decides)."""
    tokens = lane_max_tokens(provider, base_url, max_tokens)
    if tokens is None and provider == "anthropic":
        from .agent.anthropic_client import DEFAULT_MAX_TOKENS

        return DEFAULT_MAX_TOKENS
    return tokens


def refresh_point(context: int, reply: int) -> int:
    """The prompt tokens at which a lane on a server that gives its model `context` tokens is
    refreshed: the context less room for two replies of up to `reply` tokens, the next one and
    as much again for what a turn adds before it (the reply the turn got, its tools' output). An
    allowance, not a bound: a turn whose tools print more can still reach past it."""
    return context - 2 * reply


def lane_refresh_at(config: Config, default: int) -> int:
    """The prompt tokens at which a lane continues in a fresh context with a summary (the driver's
    compact_at): `default` (agent/driver.COMPACT_AT), or sooner where [api] or [fallback] states a
    context it would outgrow. A lane can move to the fallback for the rest of a context, so the
    smaller of the two wins."""
    points = [default]
    for table in (config.api, config.fallback):
        if table is not None and table.context is not None:
            reply = reply_room(table.provider, table.base_url, table.max_tokens)
            assert reply is not None  # _context refuses a context with no reply cap to leave room for
            points.append(refresh_point(table.context, reply))
    return min(points)


def light_thinking(light: LightConfig) -> bool:
    """Whether the light model may reason before it answers: [light] thinking when the table
    sets it; else False for the openai engine on a server on this machine (each request then
    asks for thinking off: light.THINKING_OFF), and True for any other (a remote API may refuse
    fields it does not know, so nothing is added unless the player sets thinking = false)."""
    if light.thinking is not None:
        return light.thinking
    from .light import on_this_machine

    return not (light.engine == "openai" and on_this_machine(light.base_url))


def webhook_url(config: Config) -> str | None:
    """The notification webhook's URL, read from the variable notify.webhook_env names (the
    environment, then the keys file); None when the config names none (no notifications).

    The URL is a secret, as a key is: an unset variable, or one that does not hold an
    http:// or https:// URL, is a ConfigError that names the variable and never shows what it
    holds. A webhook_env that is not a variable name may be the URL itself, so it is refused
    without being shown, here too (a Config built in code skips load_config's check)."""
    name = config.notify.webhook_env
    where = f"{config.source}: " if config.source is not None else ""
    if not name:
        return None
    if not _is_env_name(name):
        raise ConfigError(f"{where}notify.webhook_env {_NOT_A_WEBHOOK_NAME}")
    from .keys import KeysError, environment, keys_path

    try:
        value = environment().get(name, "").strip()
    except KeysError as exc:
        raise ConfigError(str(exc)) from None
    if not value:
        raise ConfigError(
            f"{where}notify.webhook_env names the variable {name}, which is not set: put {name}=<the webhook's URL> in "
            f"{keys_path()} (chmod 600), or export it, or remove webhook_env from [notify] to play without notifications."
        )
    url = _split_url(value)
    if url is None or url.scheme not in ("http", "https") or not url.hostname or not _plain(value):
        raise ConfigError(
            f"{where}the variable {name} (notify.webhook_env) does not hold an http:// or https:// URL (it is not shown: "
            "a webhook's URL is a secret)."
        )
    return value


def _read_key(config: Config, table: str, name: str, otherwise: str) -> str | None:
    where = f"{config.source}: " if config.source is not None else ""
    if not name:
        return None
    if not _is_env_name(name):
        raise ConfigError(f"{where}{table}.key_env {_NOT_A_NAME}")
    from .keys import KeysError, environment, keys_path

    try:
        value = environment().get(name, "").strip()
    except KeysError as exc:
        raise ConfigError(str(exc)) from None
    if not value:
        raise ConfigError(
            f"{where}{table}.key_env names the variable {name}, which is not set: put {name}=<your key> in "
            f"{keys_path()} (chmod 600), or export it, {otherwise}."
        )
    return value


def example_config() -> str:
    """A commented config with every default. It loads once the model ladder is filled in."""
    return EXAMPLE


EXAMPLE = """\
# ctf-flightdeck config: ~/.config/ctf-flightdeck/config.toml, or the file $FLIGHTDECK_CONFIG names.
# Every key has the default shown except the model ladder, which you fill in.

[api]
# "openai": an OpenAI-compatible chat completions endpoint (OpenRouter by default).
# "anthropic": the Anthropic Messages API; base_url and key_env then default to
# "https://api.anthropic.com" and "ANTHROPIC_API_KEY" (`flightdeck init --provider anthropic`).
provider = "openai"
base_url = "https://openrouter.ai/api/v1"
# The name, in upper case, of the environment variable that holds your API key; the key
# itself never goes in this file. "" for a local server that needs no key.
key_env = "OPENROUTER_API_KEY"
# With provider "anthropic" only: the ladder models a lane calls in fast mode (up to 2.5x the
# output speed at a premium price: $8 / $40 per million tokens on claude-opus-5-5, twice the
# standard price). Fast mode has its own rate limit; on a 429 the lane goes on at standard
# speed for the rest of its session (until an escalation) and says so.
# fast = ["claude-opus-5-5"]
# With provider "anthropic" only: the effort (output_config.effort: how much a model thinks, and
# so spends) of each ladder model named here, one of low, medium, high, xhigh, max. A model with
# no entry is sent none and runs at Anthropic's default for it (medium for Claude Haiku 5.5 and
# Opus 5.5, high for Sonnet 5.5). It is not sent to the [fallback] API.
# effort = { "claude-opus-5-5" = "high" }
# Seconds one try of a lane's model call may take; a reply not complete by then is given up and
# tried again (the retries and their waits stay as they are). Default 180, or 600 with provider
# "anthropic". A model on this machine can need minutes for one reply: `flightdeck init` writes
# 600 for a server on this machine.
# timeout = 180
# The most tokens a lane's reply may hold, sent as max_tokens. Default: 8192 for a server on this
# machine (127.0.0.1, localhost or ::1; mlx_lm.server's own default is 512, too few for a model
# that reasons first), and none sent to any other OpenAI-compatible API: OpenAI's own API
# refuses max_tokens on its reasoning models, so leave it unset there. The Anthropic API always
# gets one: 16000 unless set here.
# max_tokens = 8192
# The tokens of context the server gives a lane's model, when that is less than a lane grows to: a
# lane is then refreshed (a summary replaces its history) before it outgrows the server, leaving
# room for two replies of up to max_tokens; unset, a lane is refreshed at 50,000 prompt tokens.
# Ollama gives a model 4,096 tokens on a machine with under 23 GiB of GPU memory (or none) and
# 32,768 from 23 GiB, unless OLLAMA_CONTEXT_LENGTH says otherwise, and drops the oldest messages
# past it without saying so: set OLLAMA_CONTEXT_LENGTH=65536 where Ollama runs, restart it, and set
# context = 65536 here. `flightdeck doctor` checks what the server gives.
# context = 65536

# [fallback]
# Optional: a second API a lane moves to when [api] keeps failing (rate limits, overload,
# outages: still failing after every retry). The lane stays there for the rest of its context;
# escalating, or the long-context refresh, tries [api] again. A refusal or a bad request never
# moves a lane. provider, base_url, key_env, timeout, max_tokens and context as in [api], and a
# ladder: one model id per [models] ladder entry, in the same order, in the fallback API's own
# naming. A lane is refreshed before it outgrows the smaller context of the two.
# provider = "openai"
# base_url = "https://openrouter.ai/api/v1"
# key_env = "OPENROUTER_API_KEY"
# ladder = ["vendor/small-model", "vendor/big-model"]

[models]
# Model ids, weakest to strongest: lanes start on the first, and escalating moves one step right.
# Required, for example: ladder = ["vendor/small-model", "vendor/big-model"]
ladder = []

# Dollars per million tokens, for an API that does not report what a call cost (OpenRouter
# does). Optional, per model in the ladder; with neither, the console shows dollars as "-".
# A model in an [agents] ladder below (the CLI's own name for it) can have one too: codex
# reports its tokens but no cost, so its price is how its lanes get dollars. A CLI that
# reports its own cost (claude) keeps its number. cached_input prices the prompt tokens read
# from the API's cache and cache_write those written to it (the Anthropic API charges 1.25
# times input for a write); either left out is the input rate. With provider = "anthropic", a
# model its refusal fallback answers with for a ladder model (claude-sonnet-5 for
# claude-sonnet-5-5; claude-opus-5 and claude-opus-4-8 for claude-opus-5-5) can have a price
# too: a declined call runs again on it, and that attempt is priced as it.
# [prices."vendor/small-model"]
# input = 0.10
# output = 0.40
# cached_input = 0.02

[lanes]
max_lanes = 4                   # lanes at once; the rest wait in the queue
runtime = "docker"              # "docker": a container per lane; "host": on this machine
image = "ctf-flightdeck-lane:1" # the lanes' docker image: `flightdeck image build` makes it (never pulled)
token_cap = 400000              # per lane; false for no cap
dollar_cap = 2.0                # per lane; false for no cap
submit = "confirm"              # "confirm": you approve each flag; "auto": a flag a lane claims goes at once; the rest wait for you
submit_limited = "confirm"      # a challenge whose tries the platform counts (CTFd's max attempts). "confirm": its flags
                                # wait for you, under submit "auto" too. "auto": under submit "auto" they go without you,
                                # the last try included: a wrong flag can use up the tries, for your whole team
wrong_stop = 3                  # under submit "auto": once the platform called this many flags wrong at one challenge,
                                # its next flags wait for you (a lane that guesses does not spray the platform). 0: never

[run]
dir = "~/.local/share/ctf-flightdeck/runs"  # a folder per run: the event log and the lanes' work

[agents]
# Coding-agent CLIs as lanes (`flightdeck play --agent claude`): each CLI's own model ladder,
# weakest first. They use the CLI's own key or token (claude: ANTHROPIC_API_KEY or
# CLAUDE_CODE_OAUTH_TOKEN; codex: CODEX_API_KEY, or a saved login on the host), never the [api]
# above.
# claude = ["sonnet", "opus"]
# codex = ["your-codex-model"]

[light]
# The light model: a small model for a run's small jobs (jobs, below). "rules" (the default) uses
# no model at all. Recommended: an open-weight model served on this machine through an
# OpenAI-compatible server (Ollama: http://127.0.0.1:11434/v1, an MLX server:
# http://127.0.0.1:8080/v1, key_env = ""), so no provider's safety classifier declines security
# work. Which models: docs/MODELS.md and `flightdeck models` give what each measured, job by job.
# Measured (docs/MODELS.md, `flightdeck models`): Qwen3.5 9B or Gemma 4 12B with thinking off;
# measure any other with eval-local first:
#   flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 --model <model> --compare rules
# The light model never holds up a lane or an alert: when it refuses, fails, times out or answers
# outside the options, the rules' answer stands and the run says so once. "cactus" is Cactus
# Needle (the [cactus] extra).
engine = "rules"   # rules | openai | anthropic | cactus | decider
# With engine = "openai" (an open-weight model on this machine, say), also set:
#   model = "<model>"                         # the name your server gives the model
#   base_url = "http://127.0.0.1:11434/v1"    # required (no default)
#   key_env = ""                              # required: "" for a server on this machine
#   thinking = false                          # see below
# thinking (openai only): false asks the model to answer without reasoning first, with each
# request ("reasoning_effort": "none", which Ollama reads, and "chat_template_kwargs":
# {"enable_thinking": false}, which mlx_lm.server reads); true sends neither. Default: false for a
# server on this machine, where a model that reasons first otherwise spends a job's few hundred
# tokens reasoning and answers nothing; true for any other, which may refuse fields it does not
# know. eval-local measures with the same setting (--thinking on|off overrides it).
# With engine = "anthropic": model = "claude-haiku-5-5", say; base_url and key_env default to
# "https://api.anthropic.com" and "ANTHROPIC_API_KEY". For either:
#   price = { input = 0.10, output = 0.50 }   # optional: dollars per million tokens, for an API that reports no cost
# With engine = "decider" (Strands Decider, a decision model: it picks one of the options with a
# calibrated confidence and writes no text; `flightdeck init --light decider` says how to start its
# server): base_url = "http://127.0.0.1:8000" (required), model = "<the model it serves>" (optional:
# checked against what the server reports) and threshold = 0.9 (the default: below this confidence
# an answer is unsure and the rules' answer stands). No key: the server is your own process.
# For any engine:
#   timeout = 30                              # seconds a job may take; then the rules' answer stands
# jobs: the jobs a run gives the light model. Default ["judge"], the hint judge alone. The others:
# "route" (a challenge's category where the board names none, and the specialist it suits), "recon"
# (a first look at the handout for the lane's opening brief) and "flagcheck" (a check of a flag
# before it is submitted without you, under submit "auto": it can only hold a flag for you, never
# submit one). The rules come first in every job and the light model only advises. recon and
# flagcheck need a model (openai or anthropic); route takes rules, decider, openai or anthropic.
#   jobs = ["judge", "flagcheck"]
# A job can have an engine of its own, [light.<job>]: a whole engine spec, as above, that inherits
# nothing from [light] (so the key for one API never goes to another's server). Its job must be in
# jobs. For example, Claude for flagcheck with an open-weight model on this machine for the rest:
#   [light.flagcheck]
#     engine = "anthropic"
#     model = "claude-haiku-5-5"
#     key_env = "ANTHROPIC_API_KEY"

[autopilot]
# Autopilot runs an event end to end while you are away (`flightdeck play --autopilot`, or
# engage = true here): every stage as automatic as the event's rules and this config allow,
# never looser, and its own interventions by rule. It approves nothing and submits nothing
# itself, never spends a challenge's last try, and reroutes no request a model declined. It
# needs the Docker runtime and a run budget: at the budget it holds the queue, pauses the lanes
# and disengages. `/autopilot off` in the console takes the controls back.
# engage = false                # true: every play engages it
# budget_dollars = 20.0         # the whole run's budget in dollars
# budget_tokens = 20000000      # and, or instead, in tokens (needed when a model has no price)

[governor]
# The host governor: while this machine is past one of these limits no NEW lane starts. The lanes
# at work carry on (it never stops or pauses one), the queue keeps its order, and starts resume by
# themselves when the reading recovers; with no lane at work one lane always starts. A warning
# says when it begins to hold starts, and which limit, and another when it stops. A reading
# flightdeck cannot take holds nothing. `flightdeck doctor` shows the readings.
# enabled = true                # false: the machine is not read
# max_load_per_cpu = 3.0        # the 1-minute load average divided by the CPUs; 0: no limit
# min_free_ram_mb = 2048        # the RAM available without swapping, in MiB; 0: no limit
# min_free_disk_mb = 10240      # the free disk where the run folder is, in MiB; 0: no limit

[l1]
# Your no-model solvers (L1): a folder of engines, each a script with a .manifest.toml beside it
# (`flightdeck l1 import` makes the manifests for a folder of scripts). A lane runs the engines
# routed to its challenge before its first model call; a flag an engine returns as its result
# waits for your approval, or goes at once under submit = "auto"; a match in what a text engine
# printed always waits.
# Each works in a copy of the handout. When lanes run in Docker, so do they: each in a container
# of the lane image, your pack mounted read-only, with no network unless lanes may reach the
# challenge's live instance at once. On the host runtime they run on this machine, as you.
# `flightdeck pack install` fetches flightdeck's own solver pack, sets it up and writes both lines.
# pack = "~/ctf/solvers"        # no pack: no L1 stage
# image = "ctf-flightdeck-pack:1"  # Docker lanes: the image engines run in (a pack's own, with what its engines need); unset: the lane image
# lane_tools = true             # the lanes' models may call the pack's engines too (a pack that says how: flightdeck's own does).
#                               # Docker lanes then run in the image above, with the pack mounted read-only
concurrency = 4                 # engines run at once on one challenge

[notify]
# Opt-in: a webhook flightdeck POSTs a small JSON message to during a run (docs/GUIDE.md, "Headless
# runs and notifications", lists every field; it never holds a flag). webhook_env names the
# environment variable (or keys.env entry) that holds the URL: a webhook's URL is a secret, so it
# never goes in this file. No webhook_env: nothing is sent.
# webhook_env = "FLIGHTDECK_WEBHOOK"
# on: what is sent. "flag": a flag was accepted; "needs-you": a lane waits for your approval or
# raised an alert (at most one a minute for each lane and need); "disengaged": no more lanes start
# (the queue is held, or autopilot disengaged).
# on = ["flag", "needs-you", "disengaged"]
"""

_NOT_A_NAME = (
    "must be the name of an environment variable, like OPENROUTER_API_KEY (upper-case letters, "
    f"digits and _, not starting with a digit, at most {_MAX_ENV_NAME} characters), not the key itself; "
    '"" for a local server that needs no key'
)

_NOT_A_WEBHOOK_NAME = (
    "must be the name of an environment variable, like FLIGHTDECK_WEBHOOK (upper-case letters, "
    f"digits and _, not starting with a digit, at most {_MAX_ENV_NAME} characters), not the webhook's URL itself: "
    "the URL is a secret, so it goes in that variable (or in the keys file), never in the config"
)


# ---------------------------------------------------------------------- reading


def _parse(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        how = f"flightdeck config --example > {shlex.quote(str(path))}"
        if not path.parent.is_dir():
            how = f"mkdir -p {shlex.quote(str(path.parent))} && {how}"
        try:
            usual = path == default_config_path()
        except ConfigError:  # no home directory to compare with
            usual = False
        init = "flightdeck init" if usual else f"flightdeck init --path {shlex.quote(str(path))}"
        raise ConfigError(
            f"{path}: no config file yet. Run `{init}`: it asks a few questions and writes one. Or "
            f"`{how}` for a commented one to fill in, or name another file with ${CONFIG_ENV}."
        ) from None
    except IsADirectoryError:
        raise ConfigError(f"{path}: is a directory, not a config file") from None
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read it ({exc.strerror})") from None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: is not UTF-8 text") from None
    return _toml(text, path)


def _toml(text: str, path: Path) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: is not valid TOML: {untrusted(str(exc), one_line=True)}") from None
    except (ValueError, RecursionError) as exc:  # a number too long to read, tables nested too deep
        raise ConfigError(f"{path}: cannot be read as TOML ({type(exc).__name__}: {untrusted(str(exc)[:200], one_line=True)})") from None


def expand(path: Path) -> Path:
    """`path` with ~ expanded. ConfigError when it names a user that does not exist."""
    try:
        return path.expanduser()
    except RuntimeError:
        raise ConfigError(f"{path}: starts with ~ for a user that does not exist (or there is no home directory)") from None


def _api(path: Path, table: dict, ladder: tuple[str, ...]) -> ApiConfig:
    _known(path, ("api",), table, _API_KEYS)
    provider, base_url, key_env = _endpoint(path, "api", table)
    max_tokens = _max_tokens(path, "api", table)
    return ApiConfig(base_url=base_url, key_env=key_env, provider=provider, fast=_fast(path, table, provider, ladder),
                     effort=_effort(path, table, provider, ladder),
                     timeout=_try_timeout(path, "api", table), max_tokens=max_tokens,
                     context=_context(path, "api", table, provider, base_url, max_tokens))


def _context(path: Path, name: str, table: dict, provider: str, base_url: str, max_tokens: int | None) -> int | None:
    """[api] or [fallback] context: the tokens of context the API's server gives a lane's model;
    None when absent. It must leave a lane room before its refresh (refresh_point()) of at least
    MIN_REFRESH tokens, so a value a lane cannot work in is refused, with what would do."""
    if "context" not in table:
        return None
    value = table["context"]
    if not _is_int(value) or not 1 <= value <= MAX_CONTEXT:
        raise _error(path, (name, "context"), f"must be a whole number of tokens from 1 to {MAX_CONTEXT}: the context "
                                              f"the server gives a lane's model{_got(value)}")
    reply = reply_room(provider, base_url, max_tokens)
    if reply is None:
        raise _error(path, (name, "context"), f"needs {name}.max_tokens too: flightdeck sends no reply cap to an "
                                              "OpenAI-compatible API elsewhere, so it cannot leave room for a reply in "
                                              f"the context{_got(value)}")
    if refresh_point(value, reply) < MIN_REFRESH:
        cap = f"{name}.max_tokens" if max_tokens is not None else "the default reply cap"
        raise _error(path, (name, "context"), f"leaves a lane too little room: it is refreshed {2 * reply} tokens before "
                                              f"the context ends, room for two replies of up to {reply} ({cap}), and a "
                                              f"context under {MIN_REFRESH + 2 * reply} tokens leaves it less than "
                                              f"{MIN_REFRESH}. Give the server a longer context (Ollama: "
                                              "OLLAMA_CONTEXT_LENGTH=65536, then restart it) and set this to it"
                                              f"{_got(value)}")
    return value


def _try_timeout(path: Path, name: str, table: dict) -> float | None:
    """[api] or [fallback] timeout: seconds one try of a lane's call may take; None when absent.
    The bounds also refuse nan and infinity (neither compares in range)."""
    if "timeout" not in table:
        return None
    value = table["timeout"]
    if not _is_number(value) or not 0 < value <= MAX_TRY_SECONDS:
        raise _error(path, (name, "timeout"), f"must be a number of seconds above 0 and at most {MAX_TRY_SECONDS:g}: how "
                                              f"long one try of a lane's model call may take{_got(value)}")
    return float(value)


def _max_tokens(path: Path, name: str, table: dict) -> int | None:
    """[api] or [fallback] max_tokens: the most tokens a lane's reply may hold; None when absent."""
    if "max_tokens" not in table:
        return None
    value = table["max_tokens"]
    if not _is_int(value) or not 1 <= value <= MAX_REPLY_TOKENS:
        raise _error(path, (name, "max_tokens"), f"must be a whole number of tokens from 1 to {MAX_REPLY_TOKENS}: the "
                                                 f"most a lane's reply may hold{_got(value)}")
    return value


def _fast(path: Path, table: dict, provider: str, ladder: tuple[str, ...]) -> tuple[str, ...]:
    """[api] fast: the ladder models a lane calls in fast mode. Only with the Anthropic API,
    and only models agent/fastmode.py lists (from Anthropic's documentation). A model id is shown
    only when it is one of those: any other string could be a key pasted into the wrong place."""
    if "fast" not in table:
        return ()
    from .agent.fastmode import FAST_MODES, fast_problem, listed

    value = table["fast"]
    if not isinstance(value, list):
        raise _error(path, ("api", "fast"), f"must be a list of model ids from models.ladder{_got(value)}")
    if value and provider != "anthropic":
        raise _error(
            path, ("api", "fast"),
            'is fast mode, a feature of the Anthropic Messages API: it needs [api] provider = "anthropic"',
        )
    seen: dict[str, int] = {}
    for i, model in enumerate(value):
        key = f"api.fast[{i}]"
        if not isinstance(model, str) or not model.strip():
            raise ConfigError(f"{path}: {key} must be a model id from models.ladder{_got(model)}")
        if model in seen:
            raise ConfigError(f"{path}: {key} repeats api.fast[{seen[model]}]; each model is listed once")
        seen[model] = i
        if model not in ladder:
            raise ConfigError(f"{path}: {key} is not a model in models.ladder: fast mode is chosen per ladder model")
        if model not in FAST_MODES:
            raise ConfigError(f"{path}: {key} names a model with no fast mode; fast mode is for {listed()}")
        problem = fast_problem(model)
        if problem is not None:
            raise ConfigError(f"{path}: {key}: {problem}")
    return tuple(value)


def _effort(path: Path, table: dict, provider: str, ladder: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """[api] effort: a table of ladder model -> output_config.effort level. Only with the
    Anthropic API, only models that take an effort and only a level that model takes
    (agent/anthropic_client.py EFFORT_LEVELS, from Anthropic's documentation): the API refuses
    any other, on every call of the lane. A model with no entry is sent none and runs at its
    own default. An entry is named by its place in the table, and a model id is shown only
    when it is one Anthropic documents: any other string could be a key pasted into the
    wrong place."""
    if "effort" not in table:
        return ()
    from .agent.anthropic_client import EFFORT_LEVELS, effort_problem

    value = table["effort"]
    if not isinstance(value, dict):
        raise _error(path, ("api", "effort"), "must be a table of a model id from models.ladder and its effort level, "
                                              f'as in effort = {{ "claude-opus-5-5" = "high" }}{_got(value)}')
    if value and provider != "anthropic":
        raise _error(
            path, ("api", "effort"),
            'is output_config.effort, a feature of the Anthropic Messages API: it needs [api] provider = "anthropic"',
        )
    out: list[tuple[str, str]] = []
    for i, (model, level) in enumerate(value.items()):
        key = _key("api", "effort", model) if model in EFFORT_LEVELS else f"api.effort (entry {i + 1})"
        if model not in ladder:
            raise ConfigError(f"{path}: {key} is not for a model in models.ladder: effort is set per ladder model")
        if not isinstance(level, str):
            raise ConfigError(f"{path}: {key} must be an effort level, a string{_got(level)}")
        problem = effort_problem(model, level)
        if problem is not None:
            raise ConfigError(f"{path}: {key} {problem}")
        out.append((model, level))
    return tuple(out)


def _light_tables(path: Path, table: dict) -> tuple[LightConfig, tuple[str, ...], dict[str, LightConfig]]:
    """[light], its jobs and its job tables ([light.<job>]), checked against each other."""
    known = (*_LIGHT_KEYS, "jobs", *LIGHT_JOBS)
    for key, value in table.items():
        if key not in known and isinstance(value, dict):
            raise ConfigError(f"{path}: unknown table [{_key('light', key)}]: a job's own engine goes in [light.<job>], "
                              f"for one of the jobs {', '.join(LIGHT_JOBS)}")
    _known(path, ("light",), table, known)
    light = _light(path, {key: value for key, value in table.items() if key in _LIGHT_KEYS}, ("light",))
    jobs = _jobs(path, table)
    tables: dict[str, LightConfig] = {}
    for job in LIGHT_JOBS:
        if job not in table:
            continue
        where = ("light", job)
        sub = table[job]
        if not isinstance(sub, dict):
            raise _error(path, where, f"must be a table ([light.{job}]): {job}'s own engine{_got(sub)}")
        if "jobs" in sub:
            raise _error(path, (*where, "jobs"), "is set in [light] only: it lists the jobs of every engine")
        for key, value in sub.items():
            if key not in _LIGHT_KEYS and isinstance(value, dict):
                raise ConfigError(f"{path}: unknown table [{_key(*where, key)}]: a job's table holds one engine spec, "
                                  f"with the keys {', '.join(_LIGHT_KEYS)}")
        _known(path, where, sub, _LIGHT_KEYS)
        if "engine" not in sub:
            raise _error(path, (*where, "engine"), f"is required: [light.{job}] is a whole engine spec of its own and "
                                                   "inherits nothing from [light]")
        tables[job] = _light(path, sub, where)
    _check_jobs(path, light, jobs, tables)
    return light, jobs, tables


def _jobs(path: Path, table: dict) -> tuple[str, ...]:
    """[light] jobs: the jobs a run gives the light model, each once; DEFAULT_JOBS when absent."""
    if "jobs" not in table:
        return DEFAULT_JOBS
    listed = ", ".join(RUN_JOBS)
    value = table["jobs"]
    if not isinstance(value, list):
        raise _error(path, ("light", "jobs"), f"must be a list of the jobs a run gives the light model, from {listed}"
                                              f"{_got(value)}")
    seen: dict[str, int] = {}
    for i, job in enumerate(value):
        key = f"light.jobs[{i}]"
        if not isinstance(job, str):
            raise ConfigError(f"{path}: {key} must be the name of a job, one of {listed}{_got(job)}")
        if job in EVAL_JOBS:
            raise ConfigError(f"{path}: {key} is {job}: measured by eval-local, not used in a run (a run's jobs are "
                              f"{listed})")
        if job not in RUN_JOBS:
            raise ConfigError(f"{path}: {key} is not a job a run gives the light model: one of {listed}")
        if job in seen:
            raise ConfigError(f"{path}: {key} repeats light.jobs[{seen[job]}]; each job is listed once")
        seen[job] = i
    return tuple(value)


def _check_jobs(path: Path, light: LightConfig, jobs: tuple[str, ...], tables: dict[str, LightConfig]) -> None:
    """Every job table is for a job that is on (a run job must be in jobs), and every job's
    engine can do it: a job without a table of its own uses [light]'s."""
    for job, spec in tables.items():
        if job in RUN_JOBS and job not in jobs:
            raise _error(path, ("light", job), f'is {job}\'s engine, but light.jobs does not list "{job}", so it would look '
                                               f'on and be off: add "{job}" to light.jobs, or remove [light.{job}]')
        if spec.engine not in JOB_ENGINES[job]:
            raise _error(path, ("light", job, "engine"), f'is "{spec.engine}", which cannot do {job}: {_CANNOT[job]}')
    for i, job in enumerate(jobs):
        if job in tables or light.engine in JOB_ENGINES[job]:
            continue
        if light.engine == "rules":
            raise ConfigError(f"{path}: light.jobs[{i}] is {job}, which needs a model: {_CANNOT[job]}. Name one in "
                              f"[light], or give {job} its own [light.{job}] table")
        raise ConfigError(f'{path}: light.jobs[{i}] is {job}, but [light]\'s engine "{light.engine}" cannot do it: '
                          f"{_CANNOT[job]}. Give {job} its own [light.{job}] table")


def _light(path: Path, table: dict, where: tuple[str, ...] = ("light",)) -> LightConfig:
    """One engine spec, [light]'s or a job table's (`where` is its key path, which every error
    names): the engine, and for a model engine its model, endpoint, key variable and price."""
    engine = _choice(path, table, (*where, "engine"), "rules", LIGHT_ENGINES)
    timeout = table.get("timeout", LIGHT_TIMEOUT)
    if not _is_number(timeout) or not math.isfinite(timeout) or timeout <= 0:
        raise _error(path, (*where, "timeout"), f"must be a positive number of seconds{_got(timeout)}")
    thinking = table.get("thinking")
    if "thinking" in table and engine != "openai":
        raise _error(path, (*where, "thinking"), f'is for the openai engine (a model on an OpenAI-compatible server), not "{engine}"')
    if "thinking" in table and not isinstance(thinking, bool):
        raise _error(path, (*where, "thinking"), f"must be true or false: whether the model may reason before it answers{_got(thinking)}")
    if "threshold" in table and engine != "decider":
        raise _error(path, (*where, "threshold"), f'is for the decider engine, not "{engine}"')
    if engine == "decider":
        return _decider(path, table, float(timeout), where)
    if engine not in MODEL_ENGINES:
        for key in ("model", "base_url", "key_env", "price"):
            if key in table:
                which = "openai, anthropic and decider" if key in ("model", "base_url") else "openai and anthropic"
                raise _error(path, (*where, key), f'is for the {which} engines, not "{engine}"')
        return LightConfig(engine=engine, timeout=float(timeout))
    example = "for example claude-haiku-5-5" if engine == "anthropic" else "the name your server gives the model"
    if "model" not in table:
        raise _error(path, (*where, "model"), f"is required for the {engine} engine: the model id ({example})")
    model = _string(path, table, (*where, "model"), "")
    if model != model.strip() or not _plain(model):
        raise _error(path, (*where, "model"), "must be a model id: no spaces or control characters")
    if engine == "openai":
        for key in ("base_url", "key_env"):
            if key not in table:
                raise _error(
                    path, (*where, key),
                    f'is required for the openai engine (it has no default): for a server on this machine, base_url = '
                    f'"{OLLAMA_URL}" (Ollama) or "{MLX_URL}" (an MLX server), and key_env = ""',
                )
    endpoint = {key: table[key] for key in ("base_url", "key_env") if key in table}
    _, base_url, key_env = _endpoint(path, where, {"provider": engine, **endpoint})
    price = None
    if "price" in table:
        entry = table["price"]
        if not isinstance(entry, dict):
            raise _error(path, (*where, "price"), f"must be a table of dollars per million tokens (input, output){_got(entry)}")
        price = _price(path, (*where, "price"), entry)
    return LightConfig(engine=engine, model=model, base_url=base_url, key_env=key_env, timeout=float(timeout), price=price,
                       thinking=thinking)


def _decider(path: Path, table: dict, timeout: float, where: tuple[str, ...] = ("light",)) -> LightConfig:
    """engine = "decider": a Strands Decider server's address (required), the model it serves
    (optional, checked against what the server reports) and the confidence threshold. No key
    and no price: the server is the player's own process, with no authentication."""
    from .light import DECIDER_PATH

    for key in ("key_env", "price"):
        if key in table:
            raise _error(path, (*where, key), "is not for the decider engine: a decision model server is your own "
                                              "process, with no key and no bill per call")
    if "base_url" not in table:
        raise _error(path, (*where, "base_url"), f'is required for the decider engine: the address its server listens '
                                                 f'on, for one on this machine base_url = "{DECIDER_URL}"')
    base_url = _string(path, table, (*where, "base_url"), "")
    if not _plain(base_url):
        raise _error(path, (*where, "base_url"), "must not contain spaces or control characters")
    url = _split_url(base_url)
    if url is None or url.scheme not in ("http", "https") or not url.hostname:
        raise _error(path, (*where, "base_url"), f'must start with http:// or https:// and name a host, like "{DECIDER_URL}"')
    if url.username is not None or url.password is not None:
        raise _error(path, (*where, "base_url"), "must not carry a user name or password: a decision model server takes none")
    if url.path.rstrip("/").endswith(("/v1", DECIDER_PATH)):
        raise _error(path, (*where, "base_url"), f'is the server\'s address without {DECIDER_PATH}, which flightdeck '
                                                 f'adds itself: like "{DECIDER_URL}"')
    model = ""
    if "model" in table:
        model = _string(path, table, (*where, "model"), "")
        if model != model.strip() or not _plain(model):
            raise _error(path, (*where, "model"), "must be a model id: no spaces or control characters")
    threshold = table.get("threshold", DECIDER_THRESHOLD)
    if not _is_number(threshold) or not math.isfinite(threshold) or not 0 < threshold <= 1:
        raise _error(path, (*where, "threshold"), "must be a number above 0 and at most 1: the confidence below which "
                                                  f"the decider's answer is unsure (default {DECIDER_THRESHOLD:g})"
                                                  f"{_got(threshold)}")
    return LightConfig(engine="decider", model=model, base_url=base_url, timeout=timeout, threshold=float(threshold))


def _fallback(path: Path, table: dict, ladder: tuple[str, ...]) -> FallbackConfig:
    """[fallback]: provider, base_url, key_env, timeout, max_tokens and context as in [api], and
    a ladder like [models]'s."""
    _known(path, ("fallback",), table, _FALLBACK_KEYS)
    provider, base_url, key_env = _endpoint(path, "fallback", table)
    one_each = "one for each model in models.ladder, in the same order"
    if "ladder" not in table:
        raise _error(path, ("fallback", "ladder"), f"is required: the fallback API's model ids, {one_each}")
    models = table["ladder"]
    if not isinstance(models, list):
        raise _error(path, ("fallback", "ladder"), f"must be a list of model ids, {one_each}{_got(models)}")
    for i, name in enumerate(models):
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{path}: fallback.ladder[{i}] must be a model id (a non-empty string){_got(name)}")
        if name != name.strip():
            raise ConfigError(f"{path}: fallback.ladder[{i}] has spaces around the model id")
    if len(models) != len(ladder):
        raise _error(
            path, ("fallback", "ladder"),
            f"has {len(models)} model(s) but models.ladder has {len(ladder)}: "
            "fallback.ladder[i] is the fallback for models.ladder[i]",
        )
    max_tokens = _max_tokens(path, "fallback", table)
    return FallbackConfig(provider=provider, base_url=base_url, key_env=key_env, ladder=tuple(models),
                          timeout=_try_timeout(path, "fallback", table), max_tokens=max_tokens,
                          context=_context(path, "fallback", table, provider, base_url, max_tokens))


def _endpoint(path: Path, where: str | tuple[str, ...], table: dict) -> tuple[str, str, str]:
    """(provider, base_url, key_env) of [api], [fallback] or a light engine spec (`where`: the
    table's name, or its key path), with the provider's defaults."""
    where = (where,) if isinstance(where, str) else where
    name = _key(*where)
    provider = _choice(path, table, (*where, "provider"), "openai", API_PROVIDERS)
    default_url, default_env = PROVIDER_DEFAULTS[provider]
    base_url = _string(path, table, (*where, "base_url"), default_url)
    if not _plain(base_url):  # urlsplit would quietly drop them, and the client would not
        raise _error(path, (*where, "base_url"), "must not contain spaces or control characters")
    url = _split_url(base_url)
    if url is None or url.scheme not in ("http", "https") or not url.hostname:
        raise _error(path, (*where, "base_url"), "must start with http:// or https:// and name a host")
    if url.username is not None or url.password is not None:
        raise _error(
            path,
            (*where, "base_url"),
            f"must not carry a user name or password; the key goes in the environment variable {name}.key_env names",
        )
    if provider == "anthropic" and url.path.rstrip("/").endswith("/v1"):
        raise _error(path, (*where, "base_url"), "ends in /v1, but the Anthropic SDK adds /v1/messages itself: drop the /v1")
    key_env = _string(path, table, (*where, "key_env"), default_env, empty=True)
    if key_env and not _is_env_name(key_env):
        raise _error(path, (*where, "key_env"), _NOT_A_NAME)
    if provider == "anthropic" and not key_env:
        raise _error(
            path, (*where, "key_env"),
            "is empty, but the Anthropic API needs a key: name the variable that holds it, like ANTHROPIC_API_KEY",
        )
    return provider, base_url, key_env


def _ladder(path: Path, table: dict) -> tuple[str, ...]:
    _known(path, ("models",), table, ("ladder",))
    example = 'for example ladder = ["vendor/small-model", "vendor/big-model"]'
    if "ladder" not in table:
        raise _error(path, ("models", "ladder"), f"is required: the model ids lanes use, weakest to strongest, {example}")
    ladder = table["ladder"]
    if not isinstance(ladder, list):
        raise _error(path, ("models", "ladder"), f"must be a list of model ids, weakest to strongest{_got(ladder)}")
    if not ladder:
        raise _error(path, ("models", "ladder"), f"is empty: list the model ids lanes use, weakest to strongest, {example}")
    first: dict[str, int] = {}
    for i, name in enumerate(ladder):
        key = f"models.ladder[{i}]"
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"{path}: {key} must be a model id (a non-empty string){_got(name)}")
        if name != name.strip():
            raise ConfigError(f"{path}: {key} has spaces around the model id")
        if name in first:
            raise ConfigError(f"{path}: {key} repeats models.ladder[{first[name]}]; each model is listed once")
        first[name] = i
    return tuple(ladder)


def _prices(path: Path, table: dict, ladder: tuple[str, ...], agents: dict[str, tuple[str, ...]],
            provider: str) -> dict[str, Price]:
    """[prices]: dollars per million tokens, per model in models.ladder or in an [agents] ladder
    (the CLI's own model names). For a CLI it prices what the CLI reports as tokens with no cost
    (codex), or a turn the CLI never reported; a cost the CLI reports itself (claude) wins. With
    the Anthropic API, also per model its server-side refusal fallback answers with for a model
    of the ladder (agent/refusal.py): that attempt is priced as the model that ran it."""
    named = set(ladder).union(*agents.values())
    answering: tuple[str, ...] = ()
    if provider == "anthropic":
        from .agent.refusal import answering as fallback_models

        answering = tuple(m for m in fallback_models(ladder) if m not in named)
    prices = {}
    for model, entry in table.items():
        where = ("prices", model)
        if not isinstance(entry, dict):
            raise _error(path, where, f"must be a table of dollars per million tokens (input, output){_got(entry)}")
        if model not in named and model not in answering:
            also = f", nor one Anthropic's refusal fallback answers with for the ladder ({', '.join(answering)})" if answering else ""
            raise _error(path, where, f"is for a model that is not in models.ladder or in an [agents] ladder{also}")
        prices[model] = _price(path, where, entry)
    return prices


def _price(path: Path, where: tuple[str, ...], entry: dict) -> Price:
    """One price table: input and output (required) and cached_input, dollars per million tokens."""
    _known(path, where, entry, _PRICE_KEYS)
    for name in ("input", "output"):
        if name not in entry:
            raise _error(path, (*where, name), "is required: dollars per million tokens")
    values = {}
    for name, value in entry.items():
        if not _is_number(value) or not math.isfinite(value) or value < 0:
            raise _error(path, (*where, name), f"must be a number of dollars per million tokens, 0 or more{_got(value)}")
        values[name] = float(value)
    try:
        return Price(**values)
    except ValueError as exc:
        raise _error(path, where, f"is not a valid price ({exc})") from None


def _lanes(path: Path, table: dict) -> LaneConfig:
    _known(path, ("lanes",), table, _LANE_KEYS)
    defaults = LaneConfig()
    max_lanes = table.get("max_lanes", defaults.max_lanes)
    if not _is_int(max_lanes) or max_lanes < 1:
        raise _error(path, ("lanes", "max_lanes"), f"must be a whole number, at least 1{_got(max_lanes)}")
    image = _string(path, table, ("lanes", "image"), defaults.image)
    if image.startswith("-") or not _plain(image):
        # docker would read "-..." as one of its own options
        raise _error(
            path, ("lanes", "image"), "must be a docker image name: no spaces or control characters, and not starting with -"
        )
    return LaneConfig(
        max_lanes=max_lanes,
        runtime=_choice(path, table, ("lanes", "runtime"), defaults.runtime, RUNTIMES),
        image=image,
        token_cap=_cap(path, table, "token_cap", defaults.token_cap, whole=True),
        dollar_cap=_cap(path, table, "dollar_cap", defaults.dollar_cap, whole=False),
        submit=_choice(path, table, ("lanes", "submit"), defaults.submit, SUBMIT_POLICIES),
        submit_limited=_choice(path, table, ("lanes", "submit_limited"), defaults.submit_limited, SUBMIT_POLICIES),
        wrong_stop=_wrong_stop(path, table, defaults.wrong_stop),
    )


def _wrong_stop(path: Path, table: dict, default: int) -> int:
    value = table.get("wrong_stop", default)
    if not _is_int(value) or value < 0:
        raise _error(path, ("lanes", "wrong_stop"), f"must be a whole number, 0 or more (0: never stop){_got(value)}")
    return value


AGENT_KINDS = ("claude", "codex")


def _agents(path: Path, table: dict) -> dict[str, tuple[str, ...]]:
    """[agents]: a model ladder per coding-agent CLI (`play --agent`), weakest first."""
    _known(path, ("agents",), table, AGENT_KINDS)
    out = {}
    for kind, value in table.items():
        if not isinstance(value, list) or not value or not all(isinstance(m, str) and _plain(m) for m in value):
            raise _error(path, ("agents", kind), f"must be a non-empty list of model names, weakest first{_got(value)}")
        if len(set(value)) != len(value):
            raise _error(path, ("agents", kind), "names a model twice")
        out[kind] = tuple(value)
    return out


def _l1(path: Path, table: dict) -> L1Config:
    _known(path, ("l1",), table, ("pack", "concurrency", "image", "lane_tools"))
    defaults = L1Config()
    concurrency = table.get("concurrency", defaults.concurrency)
    if not _is_int(concurrency) or concurrency < 1:
        raise _error(path, ("l1", "concurrency"), f"must be a whole number, at least 1{_got(concurrency)}")
    image = None
    if "image" in table:
        image = _string(path, table, ("l1", "image"), "")
        if not image or image.startswith("-") or not _plain(image):
            raise _error(path, ("l1", "image"), "must be a docker image name: no spaces or control characters, and not starting with -")
    lane_tools = table.get("lane_tools", False)
    if not isinstance(lane_tools, bool):
        raise _error(path, ("l1", "lane_tools"), f"must be true or false{_got(lane_tools)}")
    if "pack" not in table:
        if lane_tools:
            raise _error(path, ("l1", "lane_tools"), "needs a pack: set [l1] pack too")
        return L1Config(concurrency=concurrency, image=image)
    raw = _string(path, table, ("l1", "pack"), "")
    try:
        pack = Path(raw).expanduser()
    except RuntimeError:
        raise _error(path, ("l1", "pack"), "starts with ~ for a home directory that cannot be found") from None
    if not raw or not pack.is_absolute():
        raise _error(path, ("l1", "pack"), "must be an absolute path or start with ~")
    return L1Config(pack=pack, concurrency=concurrency, image=image, lane_tools=lane_tools)


def _notify(path: Path, table: dict) -> NotifyConfig:
    _known(path, ("notify",), table, ("webhook_env", "on"))
    name = table.get("webhook_env", "")
    if not isinstance(name, str) or (name and not _is_env_name(name)):  # never shown: it may be the URL itself
        raise _error(path, ("notify", "webhook_env"), _NOT_A_WEBHOOK_NAME)
    on = table.get("on", list(NOTIFY_KINDS))
    known = ", ".join(f'"{kind}"' for kind in NOTIFY_KINDS)
    if not isinstance(on, list) or not on:
        raise _error(path, ("notify", "on"), f"must be a list of one or more of {known}{_got(on)}")
    for item in on:
        if not isinstance(item, str) or item not in NOTIFY_KINDS:
            raise _error(path, ("notify", "on"), f"lists something that is not one of {known}")
    if len(set(on)) != len(on):
        raise _error(path, ("notify", "on"), "lists a kind twice")
    return NotifyConfig(webhook_env=name, on=tuple(kind for kind in NOTIFY_KINDS if kind in on))


def _autopilot(path: Path, table: dict) -> AutopilotConfig:
    _known(path, ("autopilot",), table, ("engage", "budget_dollars", "budget_tokens"))
    engage = table.get("engage", False)
    if not isinstance(engage, bool):
        raise _error(path, ("autopilot", "engage"), f"must be true or false{_got(engage)}")
    dollars = table.get("budget_dollars")
    if dollars is not None and (not _is_number(dollars) or not 0 < dollars < float("inf")):
        raise _error(path, ("autopilot", "budget_dollars"), f"must be a number above 0: the whole run's budget in dollars{_got(dollars)}")
    tokens = table.get("budget_tokens")
    if tokens is not None and (not _is_int(tokens) or tokens < 1):
        raise _error(path, ("autopilot", "budget_tokens"), f"must be a whole number above 0: the whole run's budget in tokens{_got(tokens)}")
    if engage and dollars is None and tokens is None:
        raise _error(path, ("autopilot", "engage"), "is true, and autopilot needs a run budget: set budget_dollars or "
                                                    "budget_tokens beside it")
    return AutopilotConfig(engage=engage, budget_dollars=float(dollars) if dollars is not None else None, budget_tokens=tokens)


def _governor(path: Path, table: dict) -> GovernorConfig:
    _known(path, ("governor",), table, ("enabled", "max_load_per_cpu", "min_free_ram_mb", "min_free_disk_mb"))
    defaults = GovernorConfig()
    enabled = table.get("enabled", defaults.enabled)
    if not isinstance(enabled, bool):
        raise _error(path, ("governor", "enabled"), f"must be true or false{_got(enabled)}")
    load = table.get("max_load_per_cpu", defaults.max_load_per_cpu)
    if not _is_number(load) or not 0 <= load <= MAX_GOVERNOR_LOAD:
        raise _error(path, ("governor", "max_load_per_cpu"),
                     f"must be a number from 0 to {MAX_GOVERNOR_LOAD:g}: the load average per CPU above which no new lane "
                     f"starts (0: no limit){_got(load)}")
    floors = {}
    for name, what in (("min_free_ram_mb", "the RAM available"), ("min_free_disk_mb", "the free disk at the run folder")):
        value = table.get(name, getattr(defaults, name))
        if not _is_int(value) or not 0 <= value <= MAX_GOVERNOR_MB:
            raise _error(path, ("governor", name),
                         f"must be a whole number of MiB from 0 to {MAX_GOVERNOR_MB}: {what} below which no new lane "
                         f"starts (0: no limit){_got(value)}")
        floors[name] = value
    return GovernorConfig(enabled=enabled, max_load_per_cpu=float(load), **floors)


def _run_dir(path: Path, table: dict) -> Path:
    _known(path, ("run",), table, ("dir",))
    raw = _string(path, table, ("run", "dir"), DEFAULT_RUN_DIR)
    try:
        run_dir = Path(raw).expanduser()
    except RuntimeError:  # ~user for a user that does not exist
        raise _error(path, ("run", "dir"), "starts with ~ for a home directory that cannot be found") from None
    if not run_dir.is_absolute():
        # relative to what: the config file or wherever flightdeck starts? Neither is obvious.
        raise _error(path, ("run", "dir"), "must be an absolute path or start with ~")
    return run_dir


# ---------------------------------------------------------------------- checks


def _table(path: Path, doc: dict, name: str) -> dict:
    value = doc.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: {name} must be a table ([{name}]){_got(value)}")
    return value


def _known(path: Path, where: tuple[str, ...], table: dict, known: tuple[str, ...]) -> None:
    """Unknown keys are errors: a typo must not leave a default silently in place."""
    unknown = [key for key in table if key not in known]
    if not unknown:
        return
    if where:
        names = ", ".join(_key(*where, key) for key in unknown)
        raise ConfigError(f"{path}: unknown key {names} (known in {_key(*where)}: {', '.join(known)})")
    names = ", ".join(f"table [{_key(key)}]" if isinstance(table[key], dict) else f"key {_key(key)}" for key in unknown)
    raise ConfigError(f"{path}: unknown {names} (the known tables are {', '.join(f'[{t}]' for t in known)})")


def _string(path: Path, table: dict, key: tuple[str, ...], default: str, *, empty: bool = False) -> str:
    value = table.get(key[-1], default)
    if not isinstance(value, str):
        raise _error(path, key, f"must be a string{_got(value)}")
    if not empty and not value.strip():
        raise _error(path, key, "must not be empty")
    return value


def _choice(path: Path, table: dict, key: tuple[str, ...], default: str, choices: tuple[str, ...]) -> str:
    value = table.get(key[-1], default)
    if not isinstance(value, str) or value not in choices:
        options = " or ".join(f'"{choice}"' for choice in choices)
        raise _error(path, key, f"must be {options}{_got(value)}")
    return value


def _cap(path: Path, table: dict, name: str, default: float | None, *, whole: bool) -> float | None:
    """A per-lane cap: a positive number, or false for none. An absent key keeps the default."""
    if name not in table:
        return default
    value = table[name]
    if value is False:
        return None
    if whole:
        ok = _is_int(value) and value > 0
        what = "a positive whole number of tokens"
    else:
        ok = _is_number(value) and math.isfinite(value) and value > 0
        what = "a positive number of dollars"
    if not ok:
        raise _error(path, ("lanes", name), f"must be {what}, or false for no cap{_got(value)}")
    return int(value) if whole else float(value)


def _split_url(value: str) -> SplitResult | None:
    """The URL's parts, or None when it cannot be parsed or its port is not a number in range."""
    try:
        url = urlsplit(value)
        _ = url.port  # parsing the port is what raises
    except ValueError:
        return None
    return url


def _plain(value: str) -> bool:
    """No whitespace and no control or other unprintable characters."""
    return all(ch.isprintable() and not ch.isspace() for ch in value)


def _is_env_name(value: str) -> bool:
    """An environment variable name in the usual form: upper-case letters, digits and _, not
    starting with a digit, at most 64 characters. Errors show api.key_env only in this form.
    Many API keys are letters, digits and _ only (gsk_..., hf_..., or 32 bare letters and
    digits), so a looser rule would let a key pasted into key_env through, to be shown in
    the error that says the variable is not set; almost no key is all upper case."""
    return len(value) <= _MAX_ENV_NAME and _ENV_NAME.fullmatch(value) is not None


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _got(value: object) -> str:
    """What was found, for an error message: a number or a boolean as written, any other
    value only by its type (a string could be a secret pasted into the wrong place)."""
    if isinstance(value, bool):
        return f" (got {'true' if value else 'false'})"
    if isinstance(value, (int, float)):
        return f" (got {value!r})"
    kinds = {str: "a string", list: "a list", dict: "a table"}
    return f" (got {kinds.get(type(value), type(value).__name__)})"


def _key(*parts: str) -> str:
    """A dotted TOML key, with the parts that are not bare keys quoted: prices."vendor/model".input."""
    return ".".join(part if _BARE_KEY.fullmatch(part) else json.dumps(part) for part in parts)


def _error(path: Path, key: tuple[str, ...], problem: str) -> ConfigError:
    return ConfigError(f"{path}: {_key(*key)} {problem}")
