"""The player's config: the model API, the model ladder, prices, lane settings and the run folder.

It lives outside the repository (~/.config/ctf-flightdeck/config.toml, or the file
$FLIGHTDECK_CONFIG names) and holds no secret: it names the environment variable that
holds the API key, and api_key() reads the key from there only when it is needed.

Nothing that matters has a silent default. A missing file says how to create one, the
model ladder must be filled in, and an unknown table or key is an error, so a typo
fails loudly instead of quietly leaving the default in place. Every error names the file
and the key. Error messages show numbers but never a string value: a string could be
the API key pasted into the wrong place.
"""

from __future__ import annotations

import json
import math
import os
import re
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import SplitResult, urlsplit

from .core.model import SUBMIT_POLICIES
from .pricing import Price

CONFIG_ENV = "FLIGHTDECK_CONFIG"
RUNTIMES = ("docker", "host")
DEFAULT_RUN_DIR = "~/.local/share/ctf-flightdeck/runs"

_TABLES = ("api", "models", "prices", "lanes", "run")
_API_KEYS = ("base_url", "key_env")
_LANE_KEYS = ("max_lanes", "runtime", "image", "token_cap", "dollar_cap", "submit")
_PRICE_KEYS = ("input", "output", "cached_input")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


@dataclass(frozen=True)
class ApiConfig:
    base_url: str = "https://openrouter.ai/api/v1"
    key_env: str = "OPENROUTER_API_KEY"  # "" for a local server that needs no key


@dataclass(frozen=True)
class LaneConfig:
    max_lanes: int = 4
    runtime: str = "docker"  # docker | host
    image: str = "debian:bookworm-slim"
    token_cap: int | None = 400_000  # None: no cap
    dollar_cap: float | None = 2.0  # None: no cap
    submit: str = "confirm"  # confirm | auto


@dataclass(frozen=True)
class Config:
    api: ApiConfig
    models: tuple[str, ...]  # the ladder, weakest to strongest
    prices: dict[str, Price]  # dollars per million tokens, for models in the ladder
    lanes: LaneConfig
    run_dir: Path  # expanded (~)
    source: Path | None  # the file it was read from


class ConfigError(Exception):
    """The config cannot be used. The message names the file and the key, never a secret."""


def default_config_path() -> Path:
    """$FLIGHTDECK_CONFIG if it is set, else ~/.config/ctf-flightdeck/config.toml."""
    named = os.environ.get(CONFIG_ENV)
    if named:
        return Path(named).expanduser()
    return Path.home() / ".config" / "ctf-flightdeck" / "config.toml"


def load_config(path: Path | None = None) -> Config:
    """Read and check the config file (default: default_config_path())."""
    path = default_config_path() if path is None else Path(path).expanduser()
    doc = _parse(path)
    _known(path, (), doc, _TABLES)
    ladder = _ladder(path, _table(path, doc, "models"))
    return Config(
        api=_api(path, _table(path, doc, "api")),
        models=ladder,
        prices=_prices(path, _table(path, doc, "prices"), ladder),
        lanes=_lanes(path, _table(path, doc, "lanes")),
        run_dir=_run_dir(path, _table(path, doc, "run")),
        source=path,
    )


def api_key(config: Config) -> str | None:
    """The API key, read from the environment variable api.key_env names; None when key_env is "".

    An unset or empty variable is a ConfigError that names the variable and never shows a
    value (the variable's, or a key_env that is not a variable name and may be the key itself).
    """
    where = f"{config.source}: " if config.source is not None else ""
    name = config.api.key_env
    if not name:
        return None
    if not _ENV_NAME.fullmatch(name):
        raise ConfigError(f"{where}api.key_env {_NOT_A_NAME}")
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(
            f"{where}api.key_env names the environment variable {name}, which is not set or is empty. "
            f'Export your API key in it, or set api.key_env = "" for a local server that needs no key.'
        )
    return value


def example_config() -> str:
    """A commented config with every default. It loads once the model ladder is filled in."""
    return EXAMPLE


EXAMPLE = """\
# ctf-flightdeck config: ~/.config/ctf-flightdeck/config.toml, or the file $FLIGHTDECK_CONFIG names.
# Every key has the default shown except the model ladder, which you fill in.

[api]
# An OpenAI-compatible chat completions endpoint (OpenRouter by default).
base_url = "https://openrouter.ai/api/v1"
# The environment variable that holds your API key; the key itself never goes in this file.
# "" for a local server that needs no key.
key_env = "OPENROUTER_API_KEY"

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
image = "debian:bookworm-slim"  # the lanes' docker image; never pulled, so pull it yourself first
token_cap = 400000              # per lane; false for no cap
dollar_cap = 2.0                # per lane; false for no cap
submit = "confirm"              # "confirm": you approve each flag; "auto": submitted at once

[run]
dir = "~/.local/share/ctf-flightdeck/runs"  # a folder per run: the event log and the lanes' work
"""

_NOT_A_NAME = (
    "must be the name of an environment variable (letters, digits and _, not starting with a "
    'digit), not the key itself; "" for a local server that needs no key'
)


# ---------------------------------------------------------------------- reading


def _parse(path: Path) -> dict:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        how = f"flightdeck config --example > {shlex.quote(str(path))}"
        if not path.parent.is_dir():
            how = f"mkdir -p {shlex.quote(str(path.parent))} && {how}"
        raise ConfigError(
            f"{path}: no config file. Create one with `{how}`, then fill in the model ladder "
            f"([models] ladder), or name another file with ${CONFIG_ENV}."
        ) from None
    except IsADirectoryError:
        raise ConfigError(f"{path}: is a directory, not a config file") from None
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read it ({exc.strerror})") from None
    try:
        return tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        raise ConfigError(f"{path}: is not UTF-8 text") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: is not valid TOML: {exc}") from None


def _api(path: Path, table: dict) -> ApiConfig:
    _known(path, ("api",), table, _API_KEYS)
    defaults = ApiConfig()
    base_url = _string(path, table, ("api", "base_url"), defaults.base_url)
    if not _plain(base_url):  # urlsplit would quietly drop them, and the client would not
        raise _error(path, ("api", "base_url"), "must not contain spaces or control characters")
    url = _split_url(base_url)
    if url is None or url.scheme not in ("http", "https") or not url.hostname:
        raise _error(path, ("api", "base_url"), "must start with http:// or https:// and name a host")
    if url.username is not None or url.password is not None:
        raise _error(
            path,
            ("api", "base_url"),
            "must not carry a user name or password; the key goes in the environment variable api.key_env names",
        )
    key_env = _string(path, table, ("api", "key_env"), defaults.key_env, empty=True)
    if key_env and not _ENV_NAME.fullmatch(key_env):
        raise _error(path, ("api", "key_env"), _NOT_A_NAME)
    return ApiConfig(base_url=base_url, key_env=key_env)


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
