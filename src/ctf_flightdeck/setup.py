"""First-run help: `flightdeck init` writes a config, `flightdeck doctor` checks a setup.

Both exist so a new player gets from install to a running console without reading the
architecture (the v0.1.0 requirement). Neither ever asks for, reads out or stores the API
key itself: the config names the environment variable that holds it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

from . import __version__
from .pricing import Price

PROVIDERS = {
    "openrouter": ("https://openrouter.ai/api/v1", "OPENROUTER_API_KEY"),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY"),
    "local": ("http://127.0.0.1:11434/v1", ""),  # Ollama's OpenAI-compatible endpoint; no key
    "mlx": ("http://127.0.0.1:8080/v1", ""),  # an MLX server on this Mac (mlx_lm.server's default port); no key
}
LOCAL_PROVIDERS = ("local", "mlx")  # nothing to spend: no dollar cap
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")

# `init --provider anthropic`: the Anthropic Messages API (config [api] provider = "anthropic").
ANTHROPIC = ("https://api.anthropic.com", "ANTHROPIC_API_KEY")
ANTHROPIC_LADDER = ("claude-haiku-5-5", "claude-sonnet-5-5", "claude-opus-5-5")
ANTHROPIC_PRICES = {
    # Anthropic's list prices, dollars per million tokens (claude-api skill, cached 2026-11-03):
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


LIGHT_CHOICES = ("rules", "ollama", "mlx", "anthropic", "cactus")  # `init --light`
LIGHT_EXAMPLES = "Qwen3.5 9B, Gemma 4 12B, gpt-oss-20b, Ministral 3 14B or Phi-4-mini"  # to measure, not endorsements
LIGHT_ANTHROPIC = "claude-haiku-5-5"  # `init --light anthropic` without --light-model


@dataclass(frozen=True)
class LightAnswers:
    """[light] as `init` writes it (None in Answers: the rules alone)."""

    engine: str  # openai | anthropic | cactus
    model: str = ""
    base_url: str = ""
    key_env: str = ""
    price: Price | None = None


def light_answers(choice: str, model: str | None) -> LightAnswers | None:
    """[light] for `init --light CHOICE [--light-model MODEL]`: None for rules. ValueError says
    what is missing. ollama and mlx are an open-weight model served on this machine: the
    recommended light model, measured first with eval-local."""
    if choice == "rules":
        if model:
            raise ValueError("--light-model needs --light ollama, mlx or anthropic")
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
    models = ", ".join(f'"{m}"' for m in answers.models)
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
        + f'base_url = "{answers.base_url}"\n'
        f'key_env = "{answers.key_env}"   # the environment variable holding your key (never the key)\n'
        "\n"
        "[models]\n"
        f"ladder = [{models}]   # weakest first; escalation moves right\n"
        "\n"
        + _prices(answers.prices)
        + _fallback(answers.fallback)
        + _light(answers.light)
        + "[lanes]\n"
        f"max_lanes = {answers.max_lanes}\n"
        f'runtime = "{answers.runtime}"\n'
        + (f'image = "{_lane_image()}"   # build it with `flightdeck image build`\n' if answers.runtime == "docker" else "")
        +
        f"token_cap = {token_cap}\n"
        f"dollar_cap = {dollar_cap}\n"
        'submit = "confirm"   # you approve every flag before it is submitted\n'
    )


def _prices(prices: Mapping[str, Price]) -> str:
    if not prices:
        return ""
    out = "# Dollars per million tokens: input, output, and cached_input for cache reads (a cache write counts as input).\n"
    for model, price in prices.items():
        out += f'[prices."{model}"]\ninput = {price.input:g}\noutput = {price.output:g}\n'
        if price.cached_input is not None:
            out += f"cached_input = {price.cached_input:g}\n"
        out += "\n"
    return out


def _fallback(spare: FallbackAnswers | None) -> str:
    if spare is None:
        return ""
    ladder = ", ".join(f'"{m}"' for m in spare.ladder)
    return (
        "[fallback]\n"
        + (f"# {spare.comment}\n" if spare.comment else "")
        + f'provider = "{spare.provider}"\n'
        f'base_url = "{spare.base_url}"\n'
        f'key_env = "{spare.key_env}"\n'
        f"ladder = [{ladder}]   # one per [models] ladder entry, in order\n"
        "\n"
    )


def _light(light: LightAnswers | None) -> str:
    head = "[light]\n"
    if light is None:
        return (
            head + "# The light model for small jobs (the hint judge); \"rules\" uses none. Recommended: an open-weight\n"
            "# model on this machine (Ollama: http://127.0.0.1:11434/v1, an MLX server: http://127.0.0.1:8080/v1),\n"
            "# measured first with `flightdeck eval-local`. `flightdeck config --example` shows every key.\n"
            'engine = "rules"\n\n'
        )
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
    """Validate the config by loading it, then write it. Refuses to overwrite unless force."""
    from .config import load_config

    text = render(answers)
    with tempfile.TemporaryDirectory() as tmp:
        trial = Path(tmp) / "config.toml"
        trial.write_text(text, encoding="utf-8")
        load_config(trial)  # ConfigError says what is wrong before anything is written
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


def doctor(config_path: Path | None = None, *, environ: Mapping[str, str] = os.environ,
           agent: str | None = None) -> list[Check]:
    """Every check, in order. Never prints or returns the API key. `agent` ("claude" or
    "codex") also checks that coding-agent CLI and its credential (play --agent)."""
    from .config import ConfigError, default_config_path, load_config

    checks: list[Check] = []
    version_ok = sys.version_info >= (3, 12)
    checks.append(Check("python", version_ok, f"Python {sys.version.split()[0]}, flightdeck {__version__}",
                        "flightdeck needs Python 3.12 or newer"))
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
            checks += _local_server_check(config.api.base_url)
        spare = config.fallback
        if spare is not None and spare.provider == "openai":
            checks += _local_server_check(spare.base_url, name="fallback server")
        checks += _light_checks(config, environ)
    if config is not None and config.l1.pack is not None:
        checks.append(_l1_check(config.l1.pack))
    if agent is not None:
        checks += _agent_checks(agent, config, environ)
    runtime = config.lanes.runtime if config is not None else "docker"
    checks += _docker_checks(config.lanes.image if config is not None else None, essential=runtime == "docker")
    try:
        columns, lines = os.get_terminal_size()
    except OSError:
        columns = lines = 0
    if columns:
        big = columns >= 100 and lines >= 30
        checks.append(Check("terminal", big, f"{columns}x{lines}",
                            "the console is easiest at 100x30 or more (it works smaller)", essential=False))
    return checks


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
        checks += [replace(c, essential=False) for c in _local_server_check(light.base_url, name="light server")]
    return checks


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


def _local_server_check(base_url: str, *, name: str = "model server") -> list[Check]:
    """For an OpenAI-compatible API on this machine (Ollama, an MLX server), check that it
    answers. A remote API is never contacted here."""
    from urllib.parse import urlsplit

    import httpx

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
    return [Check(name, ok, f"{shown} answered {answer.status_code}",
                  f"check the server's address and port in {table} base_url")]


def _shown(url: str) -> str:
    """The URL without user info, query or fragment, safe to print."""
    import httpx

    try:
        return str(httpx.URL(url).copy_with(userinfo=b"", query=None, fragment=None))
    except (httpx.InvalidURL, ValueError, TypeError):
        return "(the [api] base_url)"


def _docker_checks(image: str | None, *, essential: bool) -> list[Check]:
    from .agent.workspace import docker_unavailable
    from .lane import IMAGE

    reason = docker_unavailable()
    if reason:
        return [Check("docker", False, reason, "start Docker, or use the host runtime (--host)", essential)]
    out = [Check("docker", True, "running")]
    if image is not None:
        docker = shutil.which("docker") or "docker"
        found = subprocess.run([docker, "image", "inspect", image], capture_output=True).returncode == 0
        how = "flightdeck image build" if image == IMAGE else f"docker pull {image}"
        out.append(Check("lane image", found, f"{image} is {'present' if found else 'not on this machine'}", f"run `{how}`", essential))
    return out


def report(checks: Sequence[Check]) -> tuple[str, int]:
    """The checks as lines for the terminal, and the exit status (1 if an essential check failed)."""
    lines = []
    for check in checks:
        mark = "ok  " if check.ok else ("FAIL" if check.essential else "warn")
        lines.append(f"{mark} {check.name}: {check.detail}")
        if not check.ok and check.fix:
            lines.append(f"     fix: {check.fix}")
    failed = any(not c.ok and c.essential for c in checks)
    lines.append("" if failed else "Ready. Try `flightdeck practice`.")
    return "\n".join(lines).rstrip() + "\n", 1 if failed else 0
