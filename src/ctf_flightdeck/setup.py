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
    # Anthropic's list prices, dollars per million tokens: input, output, cache reads
    # (cached_input) and writes to the 5-minute cache (cache_write), the cache flightdeck's
    # requests use. From Anthropic's documentation as the claude-api skill (Claude Code 2.1.322)
    # carries it: shared/model-migration.md unless said, each with the line it relies on.
    # Anthropic's pricing page is the source of truth.
    #
    # "Claude Haiku 5.5 ... $0.10 / $0.50 per MTok input / output when the prompt is 100K tokens
    # or fewer, and $0.50 / $2.50 when it is longer; cache reads are 0.1x the input rate, 5-minute
    # cache writes 1.25x". These are the rates for 100K tokens or fewer: the long-context refresh
    # (agent/driver.py COMPACT_AT) keeps a lane's prompt well under.
    "claude-haiku-5-5": Price(input=0.10, output=0.50, cached_input=0.01, cache_write=0.125),
    # "Claude Sonnet 5.5 succeeds Claude Sonnet 5 in the Sonnet line at the same prices - $2 / $10
    # per MTok input / output, 5-minute cache writes $2.50, 1-hour cache writes $4, and Claude
    # Sonnet 5's batch rates - except cache reads, at $0.10, half Claude Sonnet 5's rate." (The
    # skill's copy in Claude Code 2.1.319 gave $0.20 for those cache reads; this one corrects it.)
    "claude-sonnet-5-5": Price(input=2.0, output=10.0, cached_input=0.10, cache_write=2.5),
    # Claude Opus 5.5: "$4 / $20 per MTok; 5-minute cache writes $5 and 1-hour cache writes $8;
    # cache reads $0.20 per MTok (0.05x base input)".
    "claude-opus-5-5": Price(input=4.0, output=20.0, cached_input=0.20, cache_write=5.0),
    # The models Anthropic's refusal fallback answers with for those (agent/refusal.py), priced
    # so that an attempt of theirs is too. Claude Sonnet 5: Claude Sonnet 5.5's prices above ("at
    # the same prices"), but cache reads at twice $0.10 ("half Claude Sonnet 5's rate").
    "claude-sonnet-5": Price(input=2.0, output=10.0, cached_input=0.20, cache_write=2.5),
    # Claude Opus 5 "is a drop-in upgrade at Opus 4.8's pricing - $5 per million input tokens, $25
    # per million output"; cache reads at 0.1x ("0.05x on Claude Opus 5.5 and Claude Sonnet 5.5,
    # and 0.1x on every other model") and writes at 1.25x (shared/prompt-caching.md: "Cache writes
    # cost 1.25× for 5-minute TTL, 2× for 1-hour TTL"). Claude Opus 4.8 the same.
    "claude-opus-5": Price(input=5.0, output=25.0, cached_input=0.50, cache_write=6.25),
    "claude-opus-4-8": Price(input=5.0, output=25.0, cached_input=0.50, cache_write=6.25),
}


def anthropic_prices(ladder: Sequence[str]) -> dict[str, Price]:
    """[prices] as `init --provider anthropic` writes it for `ladder`: each of its models whose
    price is known here, then each model Anthropic's refusal fallback answers with for one of
    them (agent/refusal.py), so that its attempts are priced as the model that ran them."""
    from .agent.refusal import answering

    prices = {m: ANTHROPIC_PRICES[m] for m in ladder if m in ANTHROPIC_PRICES}
    prices.update({m: ANTHROPIC_PRICES[m] for m in answering(tuple(ladder)) if m in ANTHROPIC_PRICES and m not in prices})
    return prices


OPENROUTER_NAMES = {
    # OpenRouter's names for the same models (as openrouter.ai/anthropic lists them), for the
    # OpenRouter fallback that `init --provider anthropic` offers
    "claude-haiku-5-5": "anthropic/claude-haiku-5.5",
    "claude-sonnet-5-5": "anthropic/claude-sonnet-5.5",
    "claude-opus-5-5": "anthropic/claude-opus-5.5",
}


LIGHT_CHOICES = ("rules", "ollama", "mlx", "anthropic", "cactus", "decider")  # `init --light`
# The light models the benchmark measured at or above the rules; the catalog (`flightdeck models`)
# gives each one's results. Not Phi-4-mini, which scored below the rules, nor any model nothing measured.
LIGHT_MEASURED = "measured (`flightdeck models` gives each result): Qwen3.5 9B or Gemma 4 12B with thinking off"
LIGHT_ANTHROPIC = "claude-haiku-5-5"  # `init --light anthropic` without --light-model

# What init suggests for a server on this machine: the default at its prompt, named in its
# message away from a terminal, never written without the player choosing it. From a benchmark
# of open-weight models on one Mac (Apple M4 Max, 36 GB, 2026-11-11: docs/MODELS.md), not a guarantee.
BENCHMARK = "in flightdeck's benchmark (docs/MODELS.md)"
SUGGESTED_LADDERS = {
    "local": ("gpt-oss:20b", f"the local model that solved the most practice challenges as served (2 of 4), {BENCHMARK}"),
    "mlx": ("mlx-community/Qwen3.5-9B-MLX-4bit",
            f"it solved 2 of 4 practice challenges with thinking off and replies of up to 8192 tokens, {BENCHMARK}"),
}
SUGGESTED_LIGHT = {  # `init --light ollama|mlx`, with thinking off
    "ollama": ("qwen3.5:9b", f"with thinking off it scored 42 of the 44 hint and judge cases in eval-local against the rules' 38, {BENCHMARK}"),
    "mlx": ("mlx-community/Qwen3.5-9B-MLX-4bit",
            f"with thinking off it scored 41 of the 44 hint and judge cases in eval-local against the rules' 38, {BENCHMARK}"),
}
MLX_MAX_TOKENS = 8192  # the --max-tokens init suggests for mlx_lm.server (its own default is 512)


def mlx_server_command(model: str, base_url: str = PROVIDERS["mlx"][0]) -> str:
    """How to start mlx_lm.server for `model` as init suggests: replies of up to 8192 tokens and
    thinking off (--chat-template-args, for every request it serves), on 127.0.0.1 (its default
    host) at the port `base_url` names (8080, its default, unless another is given). The model
    id is quoted for the shell."""
    import shlex
    from urllib.parse import urlsplit

    port = urlsplit(base_url).port
    command = (f"mlx_lm.server --model {shlex.quote(model)} --max-tokens {MLX_MAX_TOKENS} "
               """--chat-template-args '{"enable_thinking":false}'""")
    return command + (f" --port {port}" if port is not None and port != 8080 else "")


@dataclass(frozen=True)
class LightAnswers:
    """[light] as `init` writes it (None in Answers: the rules alone)."""

    engine: str  # openai | anthropic | cactus | decider
    model: str = ""
    base_url: str = ""
    key_env: str = ""
    price: Price | None = None
    thinking: bool | None = None  # openai only: written as [light] thinking when set


def light_answers(choice: str, model: str | None) -> LightAnswers | None:
    """[light] for `init --light CHOICE [--light-model MODEL]`: None for rules. ValueError says
    what is missing. ollama and mlx are an open-weight model served on this machine: the
    recommended light model, measured first with eval-local, and written with thinking off.
    decider is a Strands Decider server on this machine; its --light-model (optional) is the
    model the server must report serving."""
    if choice == "rules":
        if model:
            raise ValueError("--light-model needs --light ollama, mlx, anthropic or decider")
        return None
    if choice in ("ollama", "mlx"):
        url = PROVIDERS["local" if choice == "ollama" else "mlx"][0]
        if not model:
            suggested, why = SUGGESTED_LIGHT[choice]
            raise ValueError(
                f"--light {choice} needs --light-model, the name your server gives the model (suggested: --light-model "
                f"{suggested}: {why}; {LIGHT_MEASURED}); measure any other first: flightdeck eval-local "
                f"--engine openai --base-url {url} --model <model>"
            )
        return LightAnswers("openai", model, url, "", thinking=False)
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
        thinking = ", thinking off (asked for with each request)" if light.thinking is False else ""
        return (f"light model: {light.model} on this machine{thinking}; measure it against the rules: flightdeck "
                f"eval-local --engine openai --base-url {light.base_url} --model {light.model}")
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
    prices: Mapping[str, Price] = field(default_factory=dict)  # [prices], per model in the ladder (and the refusal fallback's)
    fallback: FallbackAnswers | None = None
    light: LightAnswers | None = None  # [light]; None: the rules alone
    timeout: float | None = None  # [api] timeout, written when set (init: a server on this machine)
    max_tokens: int | None = None  # [api] max_tokens, written when set (init: a server on this machine)


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
        + _api_limits(answers)
        + "\n"
        "[models]\n"
        f"ladder = [{models}]   # weakest first; escalation moves right\n"
        "\n"
        + _prices(answers.prices, answers.models)
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


def is_ollama(base_url: str) -> bool:
    """Whether `base_url` is Ollama on this machine, at its default port (what `init --provider
    local` writes, or a custom URL to it)."""
    from .light import on_this_machine
    from .ollama_context import default_port

    return on_this_machine(base_url) and default_port(base_url)


OLLAMA_CONTEXT_NOTE = (
    "Ollama gives a model 4,096 tokens of context on a machine with under 23 GiB of GPU memory (or none) and 32,768 "
    "from 23 GiB, and drops a lane's oldest messages past it without saying so; a lane needs about 65,536. Set "
    "OLLAMA_CONTEXT_LENGTH=65536 where Ollama runs, restart Ollama, then uncomment context = 65536 under [api] so lanes "
    "are refreshed before they outgrow it (`flightdeck doctor` checks what Ollama gives). The light model's short "
    "prompts fit 4,096."
)


def _ollama_context(answers: Answers) -> str:
    """For lanes on Ollama: the context note, and [api] context to uncomment once Ollama has it."""
    if answers.provider != "openai" or not is_ollama(answers.base_url):
        return ""
    import textwrap

    note = "".join(f"# {line}\n" for line in textwrap.wrap(OLLAMA_CONTEXT_NOTE, 96))
    return note + "# context = 65536\n"


def _api_limits(answers: Answers) -> str:
    """[api] timeout and max_tokens, each with why, when the answers set them, and for lanes on
    Ollama the context note (_ollama_context)."""
    out = ""
    if answers.timeout is not None:
        out += ("# Seconds a lane waits for one reply before it tries again (180 when unset). A model on this machine\n"
                "# can take minutes for one: Gemma 4 12B on Ollama, at about 22 tokens a second, ran past 180 s\n"
                f"# {BENCHMARK}.\n"
                f"timeout = {answers.timeout:g}\n")
    if answers.max_tokens is not None:
        out += ("# The most tokens a lane's reply may hold (mlx_lm.server's own default is 512, too few for a model\n"
                "# that reasons first). Leave it out for OpenAI's own API: its reasoning models refuse max_tokens.\n"
                f"max_tokens = {answers.max_tokens}\n")
    return out + _ollama_context(answers)


def _prices(prices: Mapping[str, Price], ladder: Sequence[str] = ()) -> str:
    """[prices]: the ladder's models first, then the others (the refusal fallback's), said so."""
    if not prices:
        return ""
    out = ("# Dollars per million tokens: input, output, cached_input for the prompt tokens read from the cache,\n"
           "# and cache_write for those written to it (left out: the input rate).\n")
    others = False
    for model, price in sorted(prices.items(), key=lambda item: item[0] not in ladder):
        if model not in ladder and not others:
            others = True
            out += ("# The models Anthropic's refusal fallback answers with for the ladder's: a call they decline runs\n"
                    "# again on one of them, and that attempt is priced as it.\n")
        out += f"[prices.{_toml(model)}]\n" + price_lines(price) + "\n"
    return out


def price_lines(price: Price) -> str:
    """A price's rates as the lines of its [prices] table."""
    return "".join(f"{name} = {value:g}\n" for name, value in price.rates())


def price_table(price: Price) -> str:
    """A price as an inline table: [light] price = { ... }."""
    return "{ " + ", ".join(f"{name} = {value:g}" for name, value in price.rates()) + " }"


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


def light_model_answer(text: str) -> str:
    """The light model's id, as its server names it: one id, no spaces or control characters."""
    from .config import _plain

    model = text.strip()
    if not model or not _plain(model):
        raise AnswerError("give the model's id as your server names it (one id, no spaces)")
    return model


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
            head + "# The light model for a run's small jobs (the hint judge by default); \"rules\" uses none. Recommended:\n"
            "# an open-weight model on this machine (Ollama: http://127.0.0.1:11434/v1, an MLX server:\n"
            "# http://127.0.0.1:8080/v1): `flightdeck models` and docs/MODELS.md say which were measured, and\n"
            "# `flightdeck eval-local` measures any other. `flightdeck config --example` shows every key.\n"
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
    if light.thinking is not None:
        if not light.thinking:
            out += ("# Thinking off: each request asks the model to answer without reasoning first. As served, a model\n"
                    "# that reasons first spent eval-local's few hundred tokens a job reasoning and answered nothing;\n"
                    "# with thinking off, Qwen3.5 9B and Gemma 4 12B beat the rules (41 or 42 of the 44 hint and judge cases\n"
                    "# against 38)\n"
                    f"# {BENCHMARK}.\n")
        out += f"thinking = {'true' if light.thinking else 'false'}\n"
    if light.price is not None:
        out += f"price = {price_table(light.price)}   # dollars per million tokens\n"
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
    from . import hardware

    machine = hardware.probe(hardware.RealHost(environ), runtimes=False)  # no runtime or server asked
    checks.append(Check("machine", True, hardware.doctor_line(environ, machine=machine), essential=False))
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
            checks += _lane_calls(config.api, "api")
            checks += _lane_context(config, "api", machine, environ)
        spare = config.fallback
        if spare is not None and spare.provider == "openai":
            checks += _local_server_check(spare.base_url, spare.ladder, name="fallback server", source=config.source)
            checks += _lane_calls(spare, "fallback")
            checks += _lane_context(config, "fallback", machine, environ)
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
    """[light] and its job tables, checked like the API: each distinct engine spec once (jobs
    or tables that share a spec share its checks), naming the jobs that use it: the key is
    there, the server on this machine answers, Cactus is installed. None of it is essential: a
    light model that cannot be used leaves the rules alone, and the run says so. A config with
    no jobs and no job tables is checked as it always was."""
    from .config import DEFAULT_JOBS, RUN_JOBS, light_specs

    if config.light_jobs == DEFAULT_JOBS and not config.light_tables:
        return _light_spec_checks(config, config.light, environ)
    checks: list[Check] = []
    for spec in light_specs(config):
        if not spec.jobs and spec.config.engine == "rules":
            continue  # [light] left as the rules, with every job on a table of its own
        suffix = "" if "light" in spec.tables else " [" + ", ".join(spec.tables) + "]"
        named = [job if job in RUN_JOBS else f"{job} (in eval-local)" for job in spec.jobs]
        if named:
            used = "for " + (named[0] if len(named) == 1 else ", ".join(named[:-1]) + " and " + named[-1])
        elif config.light_jobs:
            used = "used by no job (each job in [light] jobs has a table of its own)"
        else:
            used = "used by no job ([light] jobs lists none)"
        for check in _light_spec_checks(config, spec.config, environ, suffix=suffix):
            if check.name.startswith("light model"):
                check = replace(check, detail=f"{used}: {check.detail}")
            checks.append(check)
    return checks or [replace(check, detail=f"no job uses a light model ([light] jobs lists none): {check.detail}")
                      for check in _light_spec_checks(config, config.light, environ)]


def _light_spec_checks(config, light, environ: Mapping[str, str], *, suffix: str = "") -> list[Check]:
    """One light engine spec, checked; every check's name ends in `suffix` (the job tables that
    set the spec, or "" for [light]'s own)."""
    import importlib.util

    if light.engine == "rules":
        return [Check("light model" + suffix, True, "none, the rules alone (optional: an open-weight model on this "
                      "machine, e.g. served by Ollama at http://127.0.0.1:11434/v1; see [light] in `flightdeck config "
                      "--example`, and measure one first with `flightdeck eval-local`)", essential=False)]
    if light.engine == "cactus":
        found = importlib.util.find_spec("cactus") is not None
        detail = "Cactus Needle, " + ("installed" if found else "not installed")
        return [Check("light model" + suffix, found, detail + "; measure it: flightdeck eval-local --engine cactus",
                      f'{EXTRA_CACTUS}, or set [light] engine = "rules"', essential=False)]
    if light.engine == "decider":
        return [replace(check, name=check.name + suffix) for check in _decider_checks(light, config.source)]
    shown = _shown(light.base_url)
    measure = f"flightdeck eval-local --engine {light.engine} --model {light.model}"
    thinking = ""
    if light.engine == "openai":
        from .config import light_thinking

        measure += f" --base-url {shown}"
        thinking = ", thinking off (asked for with each request)" if not light_thinking(light) else ", thinking on"
    detail = f"{light.engine} {light.model} at {shown}{thinking}; measure it against the rules: {measure}"
    if light.engine == "anthropic":
        detail += (" (a provider's classifier can decline security work: a refusal leaves the rules' answer, and an "
                   "open-weight model on this machine is recommended)")
    checks = [Check("light model" + suffix, True, detail, essential=False)]
    if light.key_env:
        reported = bool(config.api.key_env) or bool(config.fallback is not None and config.fallback.key_env)
        checks += [replace(c, essential=False) for c in
                   _key_check("light key" + suffix, light.key_env, environ, "", keys_file_checked=reported)]
    if light.engine == "openai":
        checks += [replace(c, essential=False) for c in
                   _local_server_check(light.base_url, (light.model,), name="light server" + suffix, source=config.source)]
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


def _lane_calls(table, name: str) -> list[Check]:
    """For an OpenAI-compatible server on this machine ([api] or [fallback]): the max_tokens a
    lane's calls send and how long one try may take, each with where it comes from. A slow
    local model needs both: a 512-token cap ends its reply mid-thought, and a try that runs out
    of time is given up and made again."""
    from .agent.client import DEFAULT_TIMEOUT
    from .config import LOCAL_TIMEOUT, lane_max_tokens
    from .light import on_this_machine

    if table.provider != "openai" or not on_this_machine(table.base_url):
        return []
    tokens = lane_max_tokens(table.provider, table.base_url, table.max_tokens)
    said = f"[{name}] max_tokens" if table.max_tokens is not None else "the default for a server on this machine"
    if table.timeout is not None:
        wait = f"{table.timeout:g} s per try ([{name}] timeout)"
    else:
        wait = (f"{DEFAULT_TIMEOUT:g} s per try (the default; a model on this machine can take longer for one reply: "
                f"timeout = {LOCAL_TIMEOUT} under [{name}] gives it {LOCAL_TIMEOUT // 60} minutes, as init writes)")
    detail = f"to {_shown(table.base_url)}: replies of up to {tokens} tokens (max_tokens, {said}), {wait}"
    return [Check("lane calls" if name == "api" else "fallback calls", True, detail)]


NOT_OLLAMA = object()  # what _ollama_loaded() returns for a server that is not Ollama


def _ollama_loaded(base_url: str):
    """What the Ollama at `base_url` (on this machine) has loaded, with the context it gives each
    ({model: tokens}, from GET /api/ps), and a note when it could not say: (None, why) for an
    Ollama that does not answer at its default port, (NOT_OLLAMA, "") for a server that answers
    as something else, or that does not answer at another port (the model server check says so)."""
    import httpx

    from .ollama_context import PS_PATH, default_port, ollama_root, parse_ps

    root = ollama_root(base_url)
    try:
        answer = httpx.get(root + PS_PATH, timeout=2.0, follow_redirects=False)
    except httpx.HTTPError as exc:
        if default_port(base_url):
            return None, f" (nothing answered {PS_PATH} there: {type(exc).__name__})"
        return NOT_OLLAMA, ""
    loaded = parse_ps(answer.content) if answer.status_code == 200 else None
    if loaded is None:
        return NOT_OLLAMA, ""
    return loaded, ""


def _lane_context(config, name: str, machine, environ: Mapping[str, str]) -> list[Check]:
    """For [api] or [fallback] on an Ollama on this machine: whether a lane fits the context
    Ollama gives the ladder's models (ollama_context.py: what Ollama says of a loaded model, else
    an estimate from OLLAMA_CONTEXT_LENGTH here or this machine's GPU memory). Past it Ollama drops
    a lane's oldest messages without saying so; a warning, never essential: a lane still runs.
    Nothing for another server, and nothing for the light role, whose prompts fit any context
    Ollama gives (4,096 tokens at the least)."""
    from .agent.driver import COMPACT_AT
    from .config import lane_refresh_at, reply_room
    from .light import on_this_machine
    from .ollama_context import default_contexts, lane_finding

    table = config.api if name == "api" else config.fallback
    if table is None or not on_this_machine(table.base_url):
        return []
    loaded, note = _ollama_loaded(table.base_url)
    if loaded is NOT_OLLAMA:
        return []
    ladder = config.models if name == "api" else table.ladder
    check = "lane context" if name == "api" else "fallback context"
    finding = lane_finding(_shown(table.base_url).removesuffix("/v1").split("://", 1)[-1], ladder, loaded,
                           default_contexts(machine, environ), lane_refresh_at(config, COMPACT_AT),
                           reply_room(table.provider, table.base_url, table.max_tokens), table=f"[{name}]",
                           stated_context=table.context, source=str(config.source or ""))
    if finding is None:
        return [Check(check, False, "flightdeck cannot tell the context Ollama gives a lane's model: none is loaded to "
                                    f"ask, and this machine's GPU memory is unknown{note}",
                      "`ollama ps` shows a loaded model's CONTEXT; a lane needs about 65,536 tokens", essential=False)]
    return [Check(check, finding.ok, finding.detail + note, finding.fix, essential=False)]


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
