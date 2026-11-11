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
same length as [models] ladder: position i is used for a lane on ladder[i].

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

_TABLES = ("api", "models", "prices", "lanes", "run", "l1", "agents", "fallback")
_API_KEYS = ("provider", "base_url", "key_env")
_FALLBACK_KEYS = ("provider", "base_url", "key_env", "ladder")
API_PROVIDERS = ("openai", "anthropic")
ANTHROPIC_BASE_URL = "https://api.anthropic.com"  # the Anthropic SDK's default (it adds /v1/messages itself)
PROVIDER_DEFAULTS = {  # provider -> (base_url, key_env) when the table leaves them out
    "openai": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "anthropic": (ANTHROPIC_BASE_URL, "ANTHROPIC_API_KEY"),
}
_LANE_KEYS = ("max_lanes", "runtime", "image", "token_cap", "dollar_cap", "submit")
_PRICE_KEYS = ("input", "output", "cached_input")
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]*")
_MAX_ENV_NAME = 64
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class ApiConfig:
    base_url: str = "https://openrouter.ai/api/v1"
    key_env: str = "OPENROUTER_API_KEY"  # "" for a local server that needs no key (openai provider only)
    provider: str = "openai"  # openai | anthropic: the API's dialect


@dataclass(frozen=True)
class FallbackConfig:
    """[fallback]: the API a lane moves to when the [api] one keeps failing."""

    provider: str  # openai | anthropic
    base_url: str
    key_env: str  # "" for a local server that needs no key (openai provider only)
    ladder: tuple[str, ...]  # ladder[i] is the fallback for models.ladder[i]


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
    prices: dict[str, Price]  # dollars per million tokens, for models in the ladder
    lanes: LaneConfig
    run_dir: Path  # expanded (~)
    source: Path | None  # the file it was read from
    l1: L1Config = L1Config()
    agents: dict[str, tuple[str, ...]] = field(default_factory=dict)  # coding-agent CLI -> its model ladder, weakest first
    fallback: FallbackConfig | None = None  # [fallback], when the config has one


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
    return Config(
        api=_api(path, _table(path, doc, "api")),
        models=ladder,
        prices=_prices(path, _table(path, doc, "prices"), ladder),
        lanes=_lanes(path, _table(path, doc, "lanes")),
        run_dir=_run_dir(path, _table(path, doc, "run")),
        source=path,
        l1=_l1(path, _table(path, doc, "l1")),
        agents=_agents(path, _table(path, doc, "agents")),
        fallback=_fallback(path, _table(path, doc, "fallback"), ladder) if "fallback" in doc else None,
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

# [fallback]
# Optional: a second API a lane moves to when [api] keeps failing (rate limits, overload,
# outages: still failing after every retry). The lane stays there for the rest of its context;
# escalating, or the long-context refresh, tries [api] again. A refusal or a bad request never
# moves a lane. Same keys as [api], and a ladder: one model id per [models] ladder entry, in
# the same order, in the fallback API's own naming.
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


def _api(path: Path, table: dict) -> ApiConfig:
    _known(path, ("api",), table, _API_KEYS)
    provider, base_url, key_env = _endpoint(path, "api", table)
    return ApiConfig(base_url=base_url, key_env=key_env, provider=provider)


def _fallback(path: Path, table: dict, ladder: tuple[str, ...]) -> FallbackConfig:
    """[fallback]: provider, base_url and key_env as in [api], and a ladder like [models]'s."""
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
    return FallbackConfig(provider=provider, base_url=base_url, key_env=key_env, ladder=tuple(models))


def _endpoint(path: Path, name: str, table: dict) -> tuple[str, str, str]:
    """(provider, base_url, key_env) of [api] or [fallback], with the provider's defaults."""
    provider = _choice(path, table, (name, "provider"), "openai", API_PROVIDERS)
    default_url, default_env = PROVIDER_DEFAULTS[provider]
    base_url = _string(path, table, (name, "base_url"), default_url)
    if not _plain(base_url):  # urlsplit would quietly drop them, and the client would not
        raise _error(path, (name, "base_url"), "must not contain spaces or control characters")
    url = _split_url(base_url)
    if url is None or url.scheme not in ("http", "https") or not url.hostname:
        raise _error(path, (name, "base_url"), "must start with http:// or https:// and name a host")
    if url.username is not None or url.password is not None:
        raise _error(
            path,
            (name, "base_url"),
            f"must not carry a user name or password; the key goes in the environment variable {name}.key_env names",
        )
    if provider == "anthropic" and url.path.rstrip("/").endswith("/v1"):
        raise _error(path, (name, "base_url"), "ends in /v1, but the Anthropic SDK adds /v1/messages itself: drop the /v1")
    key_env = _string(path, table, (name, "key_env"), default_env, empty=True)
    if key_env and not _is_env_name(key_env):
        raise _error(path, (name, "key_env"), _NOT_A_NAME)
    if provider == "anthropic" and not key_env:
        raise _error(
            path, (name, "key_env"),
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


def _prices(path: Path, table: dict, ladder: tuple[str, ...]) -> dict[str, Price]:
    prices = {}
    for model, entry in table.items():
        where = ("prices", model)
        if not isinstance(entry, dict):
            raise _error(path, where, f"must be a table of dollars per million tokens (input, output){_got(entry)}")
        if model not in ladder:
            raise _error(path, where, "is for a model that is not in models.ladder")
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
            prices[model] = Price(**values)
        except ValueError as exc:
            raise _error(path, where, f"is not a valid price ({exc})") from None
    return prices


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


def _string(path: Path, table: dict, key: tuple[str, str], default: str, *, empty: bool = False) -> str:
    value = table.get(key[1], default)
    if not isinstance(value, str):
        raise _error(path, key, f"must be a string{_got(value)}")
    if not empty and not value.strip():
        raise _error(path, key, "must not be empty")
    return value


def _choice(path: Path, table: dict, key: tuple[str, str], default: str, choices: tuple[str, ...]) -> str:
    value = table.get(key[1], default)
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
