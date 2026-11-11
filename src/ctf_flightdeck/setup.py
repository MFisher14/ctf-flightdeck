"""First-run help: `flightdeck init` writes a config, `flightdeck doctor` checks a setup.

Both exist so a new player gets from install to a running console without reading the
architecture (the v0.1.0 requirement). Neither ever asks for, reads out or stores the API
key itself: the config names the environment variable that holds it.

init checks each answer as it is given (the *_answer functions: a bad one is asked again
at a terminal, and named by its option away from one), then checks the whole config in
memory before writing it, so an error names the file asked for and nothing half-made is
ever written. No message shows an answer: one may be a key typed in the wrong place.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import __version__
from .apicheck import LOCAL_HOSTS
from .pricing import Price

PROVIDERS = {
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "local": ("http://127.0.0.1:11434/v1", ""),  # Ollama's OpenAI-compatible endpoint; no key
    "mlx": ("http://127.0.0.1:8080/v1", ""),  # an MLX server on this Mac (mlx_lm.server's default port); no key
}
PROVIDER_CHOICES = ("openrouter", "anthropic", "openai", "local", "mlx", "custom")
PROVIDER_ALIASES = {"ollama": "local"}  # the local provider is Ollama's endpoint
LOCAL_PROVIDERS = ("local", "mlx")  # nothing to spend: no dollar cap
RUNTIMES = ("docker", "host")

# `init --provider anthropic`: the Anthropic Messages API (config [api] provider = "anthropic").
ANTHROPIC = ("https://api.anthropic.com", "ANTHROPIC_API_KEY")
ANTHROPIC_LADDER = ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")
ANTHROPIC_PRICES = {
    # Anthropic's list prices, dollars per million tokens (Anthropic's pricing as of 2026-11-03):
    # input, output, and cache reads; cache writes are counted as input. Claude Haiku 5.5's are
    # for prompts of 100K tokens or fewer (the long-context refresh keeps a lane's well under).
    "claude-haiku-5-5": Price(input=0.10, output=0.50, cached_input=0.01),
    "claude-sonnet-5-5": Price(input=2.0, output=10.0, cached_input=0.10),
    "claude-opus-5-5": Price(input=4.0, output=20.0, cached_input=0.20),
}
OPENROUTER_NAMES = {
    # OpenRouter's names for the same models (as openrouter.ai/anthropic lists them), for the
    # OpenRouter fallback that `init --provider anthropic` offers
    "claude-haiku-5-5": "anthropic/claude-haiku-5.5",
    "claude-sonnet-5-5": "anthropic/claude-sonnet-5.5",
    "claude-opus-5-5": "anthropic/claude-opus-5.5",
}


LIGHT_CHOICES = ("rules", "ollama", "mlx", "anthropic", "cactus", "decider")  # `init --light`
LIGHT_EXAMPLES = "Qwen3.5 9B, Gemma 4 12B, gpt-oss-20b, Ministral 3 14B or Phi-4-mini"  # to measure, not endorsements
LIGHT_ANTHROPIC = "claude-haiku-5-5"  # `init --light anthropic` without --light-model


@dataclass(frozen=True)
class LightAnswers:
    """[light] as `init` writes it (None in Answers: the rules alone)."""

    engine: str  # openai | anthropic | cactus | decider
    model: str = ""
    base_url: str = ""
    key_env: str = ""
    price: Price | None = None


def light_answers(choice: str, model: str | None) -> LightAnswers | None:
    """[light] for `init --light CHOICE [--light-model MODEL]`: None for rules. ValueError says
    what is missing. ollama and mlx are an open-weight model served on this machine: the
    recommended light model, measured first with eval-local. decider is a Strands Decider server
    on this machine; its --light-model (optional) is the model the server must report serving."""
    if choice == "rules":
        if model:
            raise ValueError("--light-model needs --light ollama, mlx, anthropic or decider")
        return None
    if choice in ("ollama", "mlx"):
        url = PROVIDERS["local" if choice == "ollama" else "mlx"][0]
        if not model:
            raise ValueError(
                f"--light {choice} needs --light-model, the name your server gives the model (examples to measure: "
                f"{LIGHT_EXAMPLES}); measure it first: flightdeck eval-local --engine openai --base-url {url} --model <model>"
            )
        return LightAnswers("openai", model, url, "")
    if choice == "anthropic":
        model = model or LIGHT_ANTHROPIC
        return LightAnswers("anthropic", model, ANTHROPIC[0], ANTHROPIC[1], ANTHROPIC_PRICES.get(model))
    if choice == "cactus":
        if model:
            raise ValueError("--light-model is not for cactus: Cactus Needle is its one model")
        return LightAnswers("cactus")
    if choice == "decider":
        from .config import DECIDER_URL

        return LightAnswers("decider", model or "", DECIDER_URL, "")
    raise ValueError(f"--light must be one of {', '.join(LIGHT_CHOICES)}, not {choice!r}")


def light_line(light: LightAnswers | None) -> str:
    """What `init` says about the light model it wrote."""
    if light is None:
        return ("light model: none, the rules alone. Recommended when you want one: an open-weight model on this "
                "machine (`flightdeck init --light ollama --light-model <model>`), measured first with `flightdeck eval-local`")
    if light.engine == "openai":
        return (f"light model: {light.model} on this machine; measure it against the rules: flightdeck eval-local "
                f"--engine openai --base-url {light.base_url} --model {light.model}")
    if light.engine == "anthropic":
        return (f"light model: {light.model} (Anthropic): a refusal leaves the rules' answer; an open-weight model on "
                "this machine has no provider classifier in front of it. Measure it: flightdeck eval-local --engine "
                f"anthropic --model {light.model}")
    if light.engine == "decider":
        from .config import DECIDER_THRESHOLD
        from .light import DECIDER_INSTALL, DECIDER_MLX, DECIDER_SERVE

        serves = f", serving {light.model}" if light.model else ""
        return (f"light model: Strands Decider, a decision model, at {light.base_url}{serves}; below confidence "
                f"{DECIDER_THRESHOLD:g} its answer is unsure and the rules' answer stands. Start its server: "
                f"{DECIDER_INSTALL}, then {DECIDER_SERVE} ({DECIDER_MLX}). Measure it: flightdeck eval-local "
                f"--engine decider --base-url {light.base_url}")
    return f'light model: Cactus Needle ({EXTRA_CACTUS}); measure it: flightdeck eval-local --engine cactus'


EXTRA_CACTUS = 'pip install "ctf-flightdeck[cactus]"'


@dataclass(frozen=True)
class FallbackAnswers:
    """[fallback] as `init` writes it."""

    base_url: str
    key_env: str
    ladder: tuple[str, ...]  # one per model in Answers.models, in order
    provider: str = "openai"
    comment: str = ""  # a line above the table, without the "# "


@dataclass(frozen=True)
class Answers:
    """What `init` needs; asked interactively or given as options."""

    base_url: str
    key_env: str  # "" for a local server with no key
    models: tuple[str, ...]  # weakest first
    runtime: str  # docker | host
    max_lanes: int = 4
    token_cap: int | None = 400_000
    dollar_cap: float | None = 2.0
    provider: str = "openai"  # [api] provider: openai | anthropic
    prices: Mapping[str, Price] = field(default_factory=dict)  # [prices], per model in the ladder
    fallback: FallbackAnswers | None = None
    light: LightAnswers | None = None  # [light]; None: the rules alone


def render(answers: Answers) -> str:
    """The config file for `answers`, with comments a player can follow."""
    models = ", ".join(_toml(m) for m in answers.models)
    token_cap = str(answers.token_cap) if answers.token_cap else "false"
    dollar_cap = f"{answers.dollar_cap:g}" if answers.dollar_cap else "false"
    provider = (
        f'provider = "{answers.provider}"   # the Anthropic Messages API\n' if answers.provider == "anthropic" else ""
    )
    return (
        "# flightdeck config, written by `flightdeck init`. Check it with `flightdeck doctor`.\n"
        "\n"
        "[api]\n"
        + provider
        + f"base_url = {_toml(answers.base_url)}\n"
        f"key_env = {_toml(answers.key_env)}   # the environment variable holding your key (never the key)\n"
        "\n"
        "[models]\n"
        f"ladder = [{models}]   # weakest first; escalation moves right\n"
        "\n"
        + _prices(answers.prices)
        + _fallback(answers.fallback)
        + _light(answers.light)
        + "[lanes]\n"
        f"max_lanes = {answers.max_lanes}\n"
        f"runtime = {_toml(answers.runtime)}\n"
        + (f'image = "{_lane_image()}"   # build it with `flightdeck image build`\n' if answers.runtime == "docker" else "")
        +
        f"token_cap = {token_cap}\n"
        f"dollar_cap = {dollar_cap}\n"
        'submit = "confirm"   # you approve every flag before it is submitted\n'
    )


def _toml(text: str) -> str:
    """`text` as a TOML basic string: a quote or backslash in it cannot end the string early."""
    return json.dumps(text, ensure_ascii=False)


def _prices(prices: Mapping[str, Price]) -> str:
    if not prices:
        return ""
    out = "# Dollars per million tokens: input, output, and cached_input for cache reads (a cache write counts as input).\n"
    for model, price in prices.items():
        out += f"[prices.{_toml(model)}]\ninput = {price.input:g}\noutput = {price.output:g}\n"
        if price.cached_input is not None:
            out += f"cached_input = {price.cached_input:g}\n"
        out += "\n"
    return out


def _fallback(spare: FallbackAnswers | None) -> str:
    if spare is None:
        return ""
    ladder = ", ".join(_toml(m) for m in spare.ladder)
    return (
        "[fallback]\n"
        + (f"# {spare.comment}\n" if spare.comment else "")
        + f"provider = {_toml(spare.provider)}\n"
        f"base_url = {_toml(spare.base_url)}\n"
        f"key_env = {_toml(spare.key_env)}\n"
        f"ladder = [{ladder}]   # one per [models] ladder entry, in order\n"
        "\n"
    )


# ---------------------------------------------------------------------- init's answers, one at a time


class AnswerError(ValueError):
    """An answer init cannot use. The message says what is wanted and never shows the answer."""


def provider_answer(text: str) -> str:
    """The provider asked for: one of PROVIDER_CHOICES ("ollama" is the local provider)."""
    name = text.strip().lower()
    name = PROVIDER_ALIASES.get(name, name)
    if name not in PROVIDER_CHOICES:
        raise AnswerError("choose one of openrouter, anthropic, openai, local (Ollama), mlx or custom")
    return name


def models_answer(text: str) -> tuple[str, ...]:
    """Model ids, weakest first, comma-separated: at least one, each once, none with spaces."""
    from .config import _plain

    ladder = tuple(part.strip() for part in text.split(",") if part.strip())
    if not ladder:
        raise AnswerError("give at least one model id, weakest first, comma-separated (like vendor/small,vendor/big)")
    for n, model in enumerate(ladder, 1):
        if not _plain(model):
            raise AnswerError(f"model id {n} has a space or a control character in it; a model id has none")
        if model in ladder[: n - 1]:
            raise AnswerError(f"model id {n} repeats model id {ladder.index(model) + 1}; give each model once")
    return ladder


def runtime_answer(text: str) -> str:
    """Where lanes run: docker or host."""
    runtime = text.strip().lower()
    if runtime not in RUNTIMES:
        raise AnswerError("give docker (a container per lane) or host (lanes on this machine)")
    return runtime


def key_env_answer(text: str, *, empty: bool = True) -> str:
    """The name of the variable that will hold the key ("" for none, when `empty`), never the key."""
    from .config import _is_env_name

    name = text.strip()
    if not name and empty:
        return ""
    if not _is_env_name(name):
        raise AnswerError(
            "give the name of an environment variable, like OPENROUTER_API_KEY (upper-case letters, digits and _), "
            "not the key itself" + (", or leave it empty for a server that needs no key" if empty else "")
        )
    return name


def base_url_answer(text: str, *, anthropic: bool = False) -> str:
    """An API's base URL: http(s), a host, no user name or password, no spaces."""
    from .config import _plain, _split_url

    url = text.strip()
    parts = _split_url(url) if url and _plain(url) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname:
        raise AnswerError("give the API's address: http:// or https://, a host, and its path (often ending in /v1)")
    if parts.username is not None or parts.password is not None:
        raise AnswerError("give the address without a user name or password: the key goes in its environment variable")
    if anthropic and parts.path.rstrip("/").endswith("/v1"):
        raise AnswerError("leave /v1 off: the Anthropic SDK adds /v1/messages itself")
    return url


def _light(light: LightAnswers | None) -> str:
    head = "[light]\n"
    if light is None:
        return (
            head + "# The light model for small jobs (the hint judge); \"rules\" uses none. Recommended: an open-weight\n"
            "# model on this machine (Ollama: http://127.0.0.1:11434/v1, an MLX server: http://127.0.0.1:8080/v1),\n"
            "# measured first with `flightdeck eval-local`. `flightdeck config --example` shows every key.\n"
            'engine = "rules"\n\n'
        )
    if light.engine == "decider":
        from .config import DECIDER_THRESHOLD
        from .light import DECIDER_INSTALL, DECIDER_SERVE

        out = head + 'engine = "decider"   # Strands Decider, a decision model: no key\n'
        out += f"# Start its server first: {DECIDER_INSTALL}; {DECIDER_SERVE}\n"
        out += f"base_url = {json.dumps(light.base_url)}\n"
        if light.model:
            out += f"model = {json.dumps(light.model)}   # checked against the model the server reports\n"
        out += f"threshold = {DECIDER_THRESHOLD:g}   # below this confidence its answer is unsure: the rules' answer stands\n"
        return out + "\n"
    out = head + f"engine = {json.dumps(light.engine)}\n"
    if light.engine == "cactus":
        return out + "\n"
    out += f"model = {json.dumps(light.model)}\nbase_url = {json.dumps(light.base_url)}\n"
    out += f"key_env = {json.dumps(light.key_env)}" + ("   # a server on this machine needs no key\n" if not light.key_env else "\n")
    if light.price is not None:
        parts = [f"input = {light.price.input:g}", f"output = {light.price.output:g}"]
        if light.price.cached_input is not None:
            parts.append(f"cached_input = {light.price.cached_input:g}")
        out += "price = { " + ", ".join(parts) + " }   # dollars per million tokens\n"
    return out + "\n"


def anthropic_fallback(models: Sequence[str]) -> FallbackAnswers | None:
    """The OpenRouter fallback for an Anthropic ladder, or None when OpenRouter's name for one
    of its models is not known here."""
    names = [OPENROUTER_NAMES.get(model) for model in models]
    if not models or not all(names):
        return None
    url, env = PROVIDERS["openrouter"]
    return FallbackAnswers(
        url, env, tuple(n for n in names if n),
        comment="OpenRouter, for a lane whose calls to Anthropic keep failing; these are OpenRouter's names for the same models",
    )


def _lane_image() -> str:
    from .lane import IMAGE

    return IMAGE


def write_config(answers: Answers, path: Path, *, force: bool = False) -> Path:
    """Check the config in memory, then write it. Refuses to overwrite unless force.

    A ConfigError names `path` and what is wrong; nothing is written before the check, so
    a key typed in the wrong place never reaches a file."""
    from .config import parse_config

    text = render(answers)
    parse_config(text, path)
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists; use --force to replace it")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str  # what was found
    fix: str = ""  # what to do when not ok
    essential: bool = True  # a failing essential check makes doctor exit 1


API_CHECKS = ("api key", "fallback key", "model server", "fallback server")  # what only flightdeck's own lanes use


def doctor(config_path: Path | None = None, *, environ: Mapping[str, str] = os.environ,
           agent: str | None = None, clean: bool = False) -> list[Check]:
    """Every check, in order. Never prints or returns the API key. `agent` ("claude" or
    "codex") also checks that coding-agent CLI and its credential, and in the docker runtime
    that the lane image has it, as play --agent does; the [api] checks are then warnings,
    since that CLI's lanes never use the [api] key or server. The last checks are what runs
    left running because flightdeck itself was killed (_leftover_checks): reported, and
    removed only with `clean`."""
    from dataclasses import replace

    checks = _checks(config_path, environ, agent)
    checks += _leftover_checks(config_path, docker=any(c.name == "docker" and c.ok for c in checks), clean=clean)
    if agent is None:
        return checks
    why = f" (only flightdeck's own lanes use it; {agent} lanes use {agent}'s own credential and models)"
    return [replace(c, essential=False, detail=c.detail + ("" if c.ok else why)) if c.name in API_CHECKS else c for c in checks]


def _checks(config_path: Path | None, environ: Mapping[str, str], agent: str | None) -> list[Check]:
    from .config import ConfigError, default_config_path, load_config

    checks: list[Check] = []
    version_ok = sys.version_info >= (3, 12)
    checks.append(Check("python", version_ok, f"Python {sys.version.split()[0]}, flightdeck {__version__}",
                        "flightdeck needs Python 3.12 or newer"))
    from .hardware import doctor_line
    checks.append(Check("machine", True, doctor_line(environ), essential=False))
    path = (config_path or default_config_path()).expanduser()
    config = None
    if not path.exists():
        checks.append(Check("config", False, f"no config at {path}", "run `flightdeck init` to write one"))
    else:
        try:
            config = load_config(path)
        except ConfigError as exc:
            checks.append(Check("config", False, str(exc), "fix it, or run `flightdeck init --force` to write a new one"))
        else:
            checks.append(Check("config", True, f"{path}: {len(config.models)} model(s), runtime {config.lanes.runtime}"))
    if config is not None:
        checks += _key_check("api key", config.api.key_env, environ, "the config's API needs no key")
        if config.fallback is not None:
            # the fallback's key is checked like the primary's: a run refuses to start without it
            checks += _key_check("fallback key", config.fallback.key_env, environ, "the [fallback] API needs no key",
                                 keys_file_checked=bool(config.api.key_env))
    if config is not None:
        if config.api.provider == "openai":
            checks += _local_server_check(config.api.base_url, config.models, source=config.source)
        spare = config.fallback
        if spare is not None and spare.provider == "openai":
            checks += _local_server_check(spare.base_url, spare.ladder, name="fallback server", source=config.source)
        checks += _light_checks(config, environ)
    if config is not None and config.l1.pack is not None:
        checks.append(_l1_check(config.l1.pack))
    found = False
    if agent is not None:
        agent_checks = _agent_checks(agent, config, environ)
        found = any(c.name == "agent" and c.ok for c in agent_checks)
        checks += agent_checks
    docker = _docker_checks(config)
    checks += docker
    image_there = any(c.name == "lane image" and c.ok for c in docker)
    if agent is not None and found and image_there and config is not None and config.lanes.runtime == "docker":
        checks.append(_agent_image_check(agent, config))  # play --agent runs the CLI inside that image
    try:
        columns, lines = os.get_terminal_size()
    except OSError:
        columns = lines = 0
    if columns:
        checks.append(_terminal_check(columns, lines, config))
    return checks


def _terminal_check(columns: int, lines: int, config) -> Check:
    """What a terminal this size leaves out of the console on a busy run with your lanes and
    runtime, and from which size none of it (console/room.py measures it with the console's
    own code: the header's pieces drop in the order CONSOLE-SPEC "Header" and D16 set)."""
    from .config import LaneConfig
    from .console.room import room

    lanes = config.lanes if config is not None else LaneConfig()
    fit = room(columns, lines, max_lanes=lanes.max_lanes, containerized=lanes.runtime == "docker")
    size = f"{columns}x{lines}"
    team = f"; team mode's key line, with c claim, needs {fit.team_columns} columns" if fit.team_columns > fit.columns else ""
    missing = fit.left_out()
    if not missing:
        rows = f"each of your {lanes.max_lanes} lanes" if lanes.max_lanes > 1 else "your lane"
        return Check("terminal", True, f"{size}: on a busy run the console shows the whole header, the board, every key "
                                       f"and a row for {rows}" + (team if columns < fit.team_columns else ""))
    return Check(
        "terminal", False, f"{size}: on a busy run the console leaves out " + "; ".join(missing),
        f"from {fit.columns}x{fit.lines} it leaves none of this out, with an event name of up to {fit.event} characters "
        f"(a column more for each character more){team}; the console still works smaller", essential=False,
    )


def _leftover_checks(config_path: Path | None, *, docker: bool, clean: bool) -> list[Check]:
    """What runs whose flightdeck was killed (SIGKILL, a power loss) left running: their
    containers and their process groups on this machine (leftovers.sweep), for the runs in
    the config's runs folder and those elsewhere that flightdeck's notes name (play
    --run-dir), and, when Docker runs, in Docker: every container of such a run for a
    config whose lanes run in Docker, else those of the runs whose record says they used it.

    doctor only reports them unless `clean`: it is what a player runs to look at a setup,
    often just after something went wrong, so it changes nothing unasked; a container a
    killed run left may be what the player wants to look into (docker logs, docker exec).
    play and practice remove them at their start, since their lanes would compete with them.
    Only what --clean removes gets the fix that says so; a line for what it leaves alone
    says why, and what to do when the player can."""
    from .config import DEFAULT_RUN_DIR, ConfigError, load_config
    from .leftovers import open_runs, sweep

    runtime = None
    try:
        config = load_config(config_path)
        runs: Path | None = config.run_dir
        runtime = config.lanes.runtime
    except ConfigError:  # the config check says what is wrong with it; runs go to the default folder then
        try:
            runs = Path(DEFAULT_RUN_DIR).expanduser()
        except RuntimeError:  # no home folder to expand ~ with
            runs = None
    look = (True if runtime == "docker" else None) if docker else False
    swept = sweep(runs, docker=look, clean=clean)
    if not swept.lines:  # the notes' folder could be found, or the sweep would have said why not
        return [Check("leftovers", True, f"no run left anything running (runs in {runs}, and those noted in {open_runs()})")]
    fix = "`flightdeck doctor --clean` removes them (play and practice also do when they start)"
    return ([Check("leftovers", True, line) for line in swept.done]
            + [Check("leftovers", False, line, fix, essential=False) for line in swept.found]
            + [Check("leftovers", False, line, essential=False) for line in swept.alone])


def _agent_checks(kind: str, config, environ: Mapping[str, str]) -> list[Check]:
    """The coding-agent CLI is on PATH with a credential; its warnings as non-essential checks.
    Nothing is run: finding it costs nothing."""
    from .agent.external import AgentError, find_agent
    from .run import DEFAULT_AGENT_LADDERS

    ladder = (config.agents.get(kind) if config is not None else None) or DEFAULT_AGENT_LADDERS.get(kind)
    if not ladder:
        return [Check("agent", False, f"no model ladder for {kind} lanes", f'add [agents] {kind} = ["<model>", ...] to your config')]
    try:
        from .keys import KeysError, environment

        try:
            merged = environment(environ)
        except KeysError as exc:
            return [Check("agent", False, str(exc), "fix the keys file")]
        found = find_agent(kind, ladder[0], environ=merged)
    except AgentError as exc:
        return [Check("agent", False, str(exc), f"install {kind}, then log in or set its key variable")]
    checks = [Check("agent", True, f"{kind} at {found.executable}" + (f": {found.auth}" if found.auth else ""))]
    checks += [Check("agent note", False, warning, essential=False) for warning in found.warnings]
    return checks


def _agent_image_check(kind: str, config) -> Check:
    """A docker lane runs the agent's CLI inside the lane image: the probe play runs (it starts
    a throwaway container of the image, with no network)."""
    from .run import image_lacks

    image = config.lanes.image
    problem = image_lacks(image, kind)
    if problem is None:
        return Check("agent image", True, f"{image} has {kind}")
    return Check(
        "agent image", False, problem,
        f"play with --host (lanes on this machine), or build an image FROM {image} that installs {kind}, and set "
        f"[lanes] image in {config.source} to it",
    )


def _light_checks(config, environ: Mapping[str, str]) -> list[Check]:
    """[light], checked like the API: the key is there, the server on this machine answers,
    Cactus is installed. None of it is essential: a light model that cannot be used leaves the
    rules alone, and the run says so."""
    import importlib.util

    light = config.light
    if light.engine == "rules":
        return [Check("light model", True, "none, the rules alone (optional: an open-weight model on this machine, "
                      "e.g. served by Ollama at http://127.0.0.1:11434/v1; see [light] in `flightdeck config --example`, "
                      "and measure one first with `flightdeck eval-local`)", essential=False)]
    if light.engine == "cactus":
        found = importlib.util.find_spec("cactus") is not None
        detail = "Cactus Needle, " + ("installed" if found else "not installed")
        return [Check("light model", found, detail + "; measure it: flightdeck eval-local --engine cactus",
                      f'{EXTRA_CACTUS}, or set [light] engine = "rules"', essential=False)]
    if light.engine == "decider":
        return _decider_checks(light, config.source)
    shown = _shown(light.base_url)
    measure = f"flightdeck eval-local --engine {light.engine} --model {light.model}"
    if light.engine == "openai":
        measure += f" --base-url {shown}"
    detail = f"{light.engine} {light.model} at {shown}; measure it against the rules: {measure}"
    if light.engine == "anthropic":
        detail += (" (a provider's classifier can decline security work: a refusal leaves the rules' answer, and an "
                   "open-weight model on this machine is recommended)")
    checks = [Check("light model", True, detail, essential=False)]
    if light.key_env:
        reported = bool(config.api.key_env) or bool(config.fallback is not None and config.fallback.key_env)
        checks += [replace(c, essential=False) for c in
                   _key_check("light key", light.key_env, environ, "", keys_file_checked=reported)]
    if light.engine == "openai":
        checks += [replace(c, essential=False) for c in
                   _local_server_check(light.base_url, (light.model,), name="light server", source=config.source)]
    return checks


def _decider_checks(light, source: Path | None) -> list[Check]:
    """[light] engine = "decider": what it is (and where its requests go, when its server is not
    on this machine), and whether that server answers GET /health as a Strands Decider server
    does, serving the model [light] names. Nothing is essential."""
    from urllib.parse import urlsplit

    from .light import on_this_machine

    shown = _shown(light.base_url)
    measure = f"flightdeck eval-local --engine decider --base-url {shown}" + (f" --model {light.model}" if light.model else "")
    detail = (f"Strands Decider (a decision model) at {shown}; below confidence {light.threshold:g} its answer is unsure "
              f"and the rules' answer stands; measure it against the rules: {measure}")
    if not on_this_machine(light.base_url):
        detail += (f"; its requests (challenge descriptions and lane steps) go to {urlsplit(light.base_url).hostname}, "
                   "not this machine")
    return [Check("light model", True, detail, essential=False), _decider_server_check(light, source)]


def _decider_server_check(light, source: Path | None) -> Check:
    """GET /health on the decider's server (its docs: answered once it is warmed up, with the
    model it serves and its window). Never essential: without it the rules' answer stands."""
    import httpx

    from .light import DECIDER_HEALTH, DECIDER_INSTALL, DECIDER_SERVE, WINDOW, same_model
    from .light import shown as folded

    root = httpx.URL(light.base_url)
    url = root.copy_with(path=root.path.rstrip("/") + DECIDER_HEALTH)
    shown = _shown(light.base_url)
    try:
        answer = httpx.get(url, timeout=2.0, follow_redirects=False)
    except httpx.HTTPError as exc:
        return Check("light server", False, f"nothing answers at {shown} ({type(exc).__name__})",
                     f"start it ({DECIDER_INSTALL}; {DECIDER_SERVE}; it answers once warmed up), or check [light] "
                     "base_url", essential=False)
    data = None
    if answer.is_success:
        try:
            data = answer.json()
        except (ValueError, RecursionError):
            data = None
    if not isinstance(data, dict) or data.get("status") != "ok":
        return Check("light server", False, f"{shown} answered {DECIDER_HEALTH} with HTTP {answer.status_code}, not as a "
                                            "Strands Decider server does",
                     "check [light] base_url: the address `strands-decider serve` listens on", essential=False)
    reported = data.get("model") if isinstance(data.get("model"), str) else ""
    if light.model and reported and not same_model(light.model, reported):
        where = f" in {source}" if source is not None else ""
        return Check("light server", False, f"{shown} serves {folded(reported)}, not {light.model}",
                     f"serve {light.model} there, or set [light] model{where} to the model it serves", essential=False)
    window = data.get("max_length")
    window = window if isinstance(window, int) and not isinstance(window, bool) else None
    if window is not None and window < WINDOW:
        return Check("light server", False, f"{shown} has a window of {window} tokens; flightdeck sizes its requests for "
                                            f"{WINDOW}, so a long one would be refused",
                     "serve a published Strands Decider model (their window is 4,096 tokens)", essential=False)
    serves = f"serves {folded(reported)}" if reported else "answers"
    return Check("light server", True, f"{shown} {serves}" + (f" (window {window} tokens)" if window else ""),
                 essential=False)


def _l1_check(pack: Path) -> Check:
    """The [l1] pack loads and holds engines (a run refuses to start otherwise)."""
    from .l1.manifest import ManifestError, discover

    try:
        engines = discover(pack)
    except ManifestError as exc:
        return Check("l1 pack", False, str(exc), "fix the manifest it names, or remove [l1] pack from the config")
    if not engines:
        return Check("l1 pack", False, f"{pack} has no engines (no .manifest.toml files)",
                     "`flightdeck l1 import` writes manifests for a folder of scripts")
    return Check("l1 pack", True, f"{pack}: {len(engines)} engine(s)")


def _key_check(name: str, variable: str, environ: Mapping[str, str], none_needed: str, *,
               keys_file_checked: bool = False) -> list[Check]:
    """Whether the key variable is set, in the environment or the keys file (never its value).
    A keys file flightdeck refuses is reported once: `keys_file_checked` when an earlier check did."""
    if not variable:
        return [Check(name, True, none_needed)]
    from .keys import KeysError, keys_path, source

    checks = []
    try:
        where = source(variable, environ)
    except KeysError as exc:  # a run refuses to start on such a file, wherever the key is
        if not keys_file_checked:
            checks.append(Check("keys file", False, str(exc), "fix the keys file, or remove it and export the key"))
        where = None
    detail = f"{variable} is set (in your {where})" if where else f"{variable} is not set"
    checks.append(Check(name, where is not None, detail, f"put {variable}=<your key> in {keys_path()} (chmod 600), or export it"))
    return checks


def _local_server_check(base_url: str, ladder: Sequence[str], *, name: str = "model server",
                        source: Path | None = None) -> list[Check]:
    """For an OpenAI-compatible API on this machine (Ollama, an MLX server), check that it
    answers and, when it lists its models, that it serves the ladder's. A remote API is never
    contacted here: `flightdeck play` asks it, with the key, before the console starts."""
    from urllib.parse import urlsplit

    import httpx

    from .apicheck import listed_models, missing, not_listed

    host = urlsplit(base_url).hostname or ""
    if host not in LOCAL_HOSTS:
        return []
    url = base_url.rstrip("/") + "/models"
    shown = _shown(url)  # never a credential the URL might carry (user:password@, ?api_key=)
    table = {"fallback server": "[fallback]", "light server": "[light]"}.get(name, "[api]")
    try:
        answer = httpx.get(url, timeout=2.0, follow_redirects=False)
    except httpx.HTTPError as exc:
        return [Check(name, False, f"nothing answers at {_shown(base_url)} ({type(exc).__name__})",
                      f"start your local model server (it must speak the OpenAI API with tool calling), "
                      f"or check {table} base_url")]
    ok = answer.status_code < 400
    listed = None
    if answer.is_success:
        try:
            listed = listed_models(answer.json())
        except (ValueError, RecursionError):
            listed = None
    if listed is None:
        return [Check(name, ok, f"{shown} answered {answer.status_code}",
                      f"check the server's address and port in {table} base_url")]
    gone = missing(ladder, listed)
    if gone:
        key = "models.ladder" if table == "[api]" else "fallback.ladder"
        where = f" in {source}" if source is not None else ""
        return [Check(name, False, f"{_shown(base_url)} does not serve {not_listed(gone, listed)}",
                      f"pull the model into the server (for Ollama: ollama pull NAME), or change {key}{where} to ids it serves")]
    return [Check(name, True, f"{shown} serves {', '.join(ladder)}")]


def _shown(url: str) -> str:
    """The URL without user info, query or fragment, safe to print."""
    import httpx

    try:
        return str(httpx.URL(url).copy_with(userinfo=b"", query=None, fragment=None))
    except (httpx.InvalidURL, ValueError, TypeError):
        return "(the [api] base_url)"


def _docker_checks(config) -> list[Check]:
    """Docker and the lane image, for a config whose lanes run in Docker. For one whose lanes
    run on this machine, Docker is only a warning and the image is not looked at: only
    `play --docker` would need them."""
    from .agent.workspace import docker_unavailable
    from .lane import IMAGE

    where = f"in {config.source}" if config is not None and config.source is not None else "in your config"
    reason = docker_unavailable()
    if config is not None and config.lanes.runtime == "host":
        if reason:
            return [Check("docker", False, f"{reason}; your config runs lanes on this machine, so only `play --docker` "
                                           "needs Docker", essential=False)]
        return [Check("docker", True, "running (your config runs lanes on this machine; `play --docker` would use it)")]
    if reason:
        return [Check("docker", False, reason, f'install or start Docker, or run lanes on this machine: set runtime = "host" '
                                               f"under [lanes] {where}, or pass --host to play or practice")]
    out = [Check("docker", True, "running")]
    if config is not None:
        image = config.lanes.image
        docker = shutil.which("docker") or "docker"
        found = subprocess.run([docker, "image", "inspect", image], capture_output=True).returncode == 0
        how = "flightdeck image build" if image == IMAGE else f"docker pull {image}"
        out.append(Check("lane image", found, f"{image} is {'present' if found else 'not on this machine'}", f"run `{how}`"))
    return out


def report(checks: Sequence[Check], *, agent: str | None = None) -> tuple[str, int]:
    """The checks as lines for the terminal, and the exit status (1 if an essential check
    failed). `agent`: what was checked was for that coding-agent CLI's lanes, so the next
    step is practice with it."""
    lines = []
    for check in checks:
        mark = "ok  " if check.ok else ("FAIL" if check.essential else "warn")
        lines.append(f"{mark} {check.name}: {check.detail}")
        if not check.ok and check.fix:
            lines.append(f"     fix: {check.fix}")
    failed = any(not c.ok and c.essential for c in checks)
    practice = "flightdeck practice" + (f" --agent {agent}" if agent else "")
    lines.append("" if failed else f"Ready. Try `{practice}`.")
    return "\n".join(lines).rstrip() + "\n", 1 if failed else 0
