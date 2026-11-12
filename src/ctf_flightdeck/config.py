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
agent/fastmode.py lists for fast mode is accepted.

[api] and [fallback] also take timeout (seconds one try of a lane's call may take) and
max_tokens (the most tokens a lane's reply may hold). Unset, max_tokens is LOCAL_MAX_TOKENS
for an OpenAI-compatible server on this machine and is not sent to any other: see
lane_max_tokens().

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
from .pricing import Price
from .text import untrusted

CONFIG_ENV = "FLIGHTDECK_CONFIG"
RUNTIMES = ("docker", "host")
DEFAULT_RUN_DIR = "~/.local/share/ctf-flightdeck/runs"

_TABLES = ("api", "models", "prices", "lanes", "run", "l1", "agents", "fallback", "light")
_API_KEYS = ("provider", "base_url", "key_env", "fast", "timeout", "max_tokens")
_FALLBACK_KEYS = ("provider", "base_url", "key_env", "ladder", "timeout", "max_tokens")
API_PROVIDERS = ("openai", "anthropic")
ANTHROPIC_BASE_URL = "https://api.anthropic.com"  # the Anthropic SDK's default (it adds /v1/messages itself)
PROVIDER_DEFAULTS = {  # provider -> (base_url, key_env) when the table leaves them out
    "openai": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "anthropic": (ANTHROPIC_BASE_URL, "ANTHROPIC_API_KEY"),
}
_LANE_KEYS = ("max_lanes", "runtime", "image", "token_cap", "dollar_cap", "submit")
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
MAX_TRY_SECONDS = 3600.0  # the longest [api] timeout accepted: an hour for one try
LOCAL_TIMEOUT = 600  # the [api] timeout `flightdeck init` writes for a server on this machine
_PRICE_KEYS = ("input", "output", "cached_input")
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_MAX_ENV_NAME = 64
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class ApiConfig:
    base_url: str = "https://openrouter.ai/api/v1"
    key_env: str = "OPENROUTER_API_KEY"  # "" for a local server that needs no key (openai provider only)
    provider: str = "openai"  # openai | anthropic: the API's dialect
    fast: tuple[str, ...] = ()  # ladder models a lane calls in fast mode (anthropic only; agent/fastmode.py)
    timeout: float | None = None  # seconds per try of a lane's call; None: the client's own (180, Anthropic 600)
    max_tokens: int | None = None  # a lane's reply cap as set; None: lane_max_tokens() decides


@dataclass(frozen=True)
class FallbackConfig:
    """[fallback]: the API a lane moves to when the [api] one keeps failing."""

    provider: str  # openai | anthropic
    base_url: str
    key_env: str  # "" for a local server that needs no key (openai provider only)
    ladder: tuple[str, ...]  # ladder[i] is the fallback for models.ladder[i]
    timeout: float | None = None  # as ApiConfig's
    max_tokens: int | None = None  # as ApiConfig's


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


@dataclass(frozen=True)
class L1Config:
    pack: Path | None = None  # a folder of L1 engines (manifests); None: no L1 stage
    concurrency: int = 4  # engines run at once on one challenge


@dataclass(frozen=True)
class Config:
    api: ApiConfig
    models: tuple[str, ...]  # the ladder, weakest to strongest
    prices: dict[str, Price]  # dollars per million tokens, for models in the ladder or in an [agents] ladder
    lanes: LaneConfig
    run_dir: Path  # expanded (~)
    source: Path | None  # the file it was read from
    l1: L1Config = L1Config()
    agents: dict[str, tuple[str, ...]] = field(default_factory=dict)  # coding-agent CLI -> its model ladder, weakest first
    fallback: FallbackConfig | None = None  # [fallback], when the config has one
    light: LightConfig = LightConfig()  # [light]; rules only when the config has none
    light_jobs: tuple[str, ...] = DEFAULT_JOBS  # [light] jobs: the jobs a run gives the light model
    light_tables: dict[str, LightConfig] = field(default_factory=dict)  # [light.<job>]: a job's own engine


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
    return Config(
        api=_api(path, _table(path, doc, "api"), ladder),
        models=ladder,
        prices=_prices(path, _table(path, doc, "prices"), ladder, agents),
        lanes=_lanes(path, _table(path, doc, "lanes")),
        run_dir=_run_dir(path, _table(path, doc, "run")),
        source=path,
        l1=_l1(path, _table(path, doc, "l1")),
        agents=agents,
        fallback=_fallback(path, _table(path, doc, "fallback"), ladder) if "fallback" in doc else None,
        light=light,
        light_jobs=jobs,
        light_tables=tables,
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


def light_thinking(light: LightConfig) -> bool:
    """Whether the light model may reason before it answers: [light] thinking when the table
    sets it; else False for the openai engine on a server on this machine (each request then
    asks for thinking off: light.THINKING_OFF), and True for any other (a remote API may refuse
    fields it does not know, so nothing is added unless the player sets thinking = false)."""
    if light.thinking is not None:
        return light.thinking
    from .light import on_this_machine

    return not (light.engine == "openai" and on_this_machine(light.base_url))


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
# speed for the rest of its context and says so.
# fast = ["claude-opus-5-5"]
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

# [fallback]
# Optional: a second API a lane moves to when [api] keeps failing (rate limits, overload,
# outages: still failing after every retry). The lane stays there for the rest of its context;
# escalating, or the long-context refresh, tries [api] again. A refusal or a bad request never
# moves a lane. provider, base_url, key_env, timeout and max_tokens as in [api], and a ladder:
# one model id per [models] ladder entry, in the same order, in the fallback API's own naming.
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
# reports its own cost (claude) keeps its number.
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
submit = "confirm"              # "confirm": you approve each flag; "auto": submitted at once

[run]
dir = "~/.local/share/ctf-flightdeck/runs"  # a folder per run: the event log and the lanes' work

[agents]
# Coding-agent CLIs as lanes (`flightdeck play --agent claude`): each CLI's own model ladder,
# weakest first. They use the CLI's own login or key, never the [api] above.
# claude = ["sonnet", "opus"]
# codex = ["your-codex-model"]

[light]
# The light model: a small model for flightdeck's small jobs (today the hint judge, which checks
# an "ignores the hint" alert). "rules" (the default) uses no model at all.
# Recommended: an open-weight model served on this machine through an OpenAI-compatible server
# (Ollama: http://127.0.0.1:11434/v1, an MLX server: http://127.0.0.1:8080/v1, key_env = ""), so
# no provider's safety classifier declines security work. Measure one before you switch it on:
#   flightdeck eval-local --engine openai --base-url http://127.0.0.1:11434/v1 --model <model> --compare rules
# Models to measure, for example (examples, not endorsements: eval-local decides): Qwen3.5 9B,
# Gemma 4 12B, gpt-oss-20b, Ministral 3 14B, Phi-4-mini. "anthropic" (a Claude model, e.g.
# claude-haiku-5-5) and "cactus" (Cactus Needle, the [cactus] extra) are there too. The light
# model never holds up a lane or an alert: when it refuses, fails, times out or answers outside
# the options, the rules' answer stands and the run says so once.
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

[l1]
# Your no-model solvers (L1): a folder of engines, each a script with a .manifest.toml beside it
# (`flightdeck l1 import` makes the manifests for a folder of scripts). A lane runs the engines
# routed to its challenge before its first model call; a flag one finds waits for your approval.
# Each works in a copy of the handout. When lanes run in Docker, so do they: each in a container
# of the lane image, your pack mounted read-only, with no network unless lanes may reach the
# challenge's live instance at once. On the host runtime they run on this machine, as you.
# pack = "~/ctf/solvers"        # no pack: no L1 stage
concurrency = 4                 # engines run at once on one challenge
"""

_NOT_A_NAME = (
    "must be the name of an environment variable, like OPENROUTER_API_KEY (upper-case letters, "
    f"digits and _, not starting with a digit, at most {_MAX_ENV_NAME} characters), not the key itself; "
    '"" for a local server that needs no key'
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
    return ApiConfig(base_url=base_url, key_env=key_env, provider=provider, fast=_fast(path, table, provider, ladder),
                     timeout=_try_timeout(path, "api", table), max_tokens=_max_tokens(path, "api", table))


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
    """[fallback]: provider, base_url, key_env, timeout and max_tokens as in [api], and a
    ladder like [models]'s."""
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
    return FallbackConfig(provider=provider, base_url=base_url, key_env=key_env, ladder=tuple(models),
                          timeout=_try_timeout(path, "fallback", table), max_tokens=_max_tokens(path, "fallback", table))


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


def _prices(path: Path, table: dict, ladder: tuple[str, ...], agents: dict[str, tuple[str, ...]]) -> dict[str, Price]:
    """[prices]: dollars per million tokens, per model in models.ladder or in an [agents] ladder
    (the CLI's own model names). For a CLI it prices what the CLI reports as tokens with no cost
    (codex), or a turn the CLI never reported; a cost the CLI reports itself (claude) wins."""
    named = set(ladder).union(*agents.values())
    prices = {}
    for model, entry in table.items():
        where = ("prices", model)
        if not isinstance(entry, dict):
            raise _error(path, where, f"must be a table of dollars per million tokens (input, output){_got(entry)}")
        if model not in named:
            raise _error(path, where, "is for a model that is not in models.ladder or in an [agents] ladder")
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
    )


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
    _known(path, ("l1",), table, ("pack", "concurrency"))
    defaults = L1Config()
    concurrency = table.get("concurrency", defaults.concurrency)
    if not _is_int(concurrency) or concurrency < 1:
        raise _error(path, ("l1", "concurrency"), f"must be a whole number, at least 1{_got(concurrency)}")
    if "pack" not in table:
        return L1Config(concurrency=concurrency)
    raw = _string(path, table, ("l1", "pack"), "")
    try:
        pack = Path(raw).expanduser()
    except RuntimeError:
        raise _error(path, ("l1", "pack"), "starts with ~ for a home directory that cannot be found") from None
    if not raw or not pack.is_absolute():
        raise _error(path, ("l1", "pack"), "must be an absolute path or start with ~")
    return L1Config(pack=pack, concurrency=concurrency)


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
