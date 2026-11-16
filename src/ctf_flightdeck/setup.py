"""First-run help: `flightdeck init` writes a config, `flightdeck doctor` checks a setup.

Both exist so a new player gets from install to a running console without reading the
architecture (the v0.1.0 requirement). The config names the environment variable that holds
the API key, never the key. At a terminal init asks for a key that is not set yet at a hidden
prompt and puts it in the player's keys file (keys.save); neither init nor doctor ever reads
a key out, and no message or config holds one. The home screen's setup form (console/home.py)
asks the same questions and writes the same config: both go through the *_answer functions,
answers_for and write_setup here.

init checks each answer as it is given (the *_answer functions: a bad one is asked again
at a terminal, and named by its option away from one), then checks the whole config in
memory before writing it, so an error names the file asked for and nothing half-made is
ever written. No message shows an answer: one may be a key typed in the wrong place.
"""

from __future__ import annotations

import json
import os
import re
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

# What init suggests where it has no ladder of its own to write: the default at its prompt and in
# the home screen's setup form, named in its message away from a terminal, never written without
# the player choosing it. For a model API: OpenRouter's names for the Claude ladder ("Lanes on an
# API" in docs/MODELS.md), and for OpenAI's own API two models its documentation lists with
# function calling on Chat Completions (the API flightdeck speaks) and no reasoning to switch off
# first; flightdeck has measured neither, and docs/MODELS.md says so. For a server on this
# machine: from a benchmark of open-weight models on one Mac (Apple M4 Max, 36 GB, 2026-11-11:
# docs/MODELS.md), not a guarantee.
BENCHMARK = "in flightdeck's benchmark (docs/MODELS.md)"
SUGGESTED_LADDERS = {
    "openrouter": (",".join(OPENROUTER_NAMES[model] for model in ANTHROPIC_LADDER),
                   "OpenRouter's names for Claude Haiku, Sonnet and Opus 5.5, the ladder flightdeck would start with on an "
                   "API (docs/MODELS.md)"),
    "openai": ("gpt-5.4-mini,gpt-5.4",
               "a small model and a larger one that take tool calls on OpenAI's Chat Completions API; flightdeck has not "
               "measured them (docs/MODELS.md)"),
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
        raise AnswerError("choose one of openrouter, anthropic, openai, ollama (or local), mlx or custom")
    return name


# The provider menu, in parts: init prints it whole at its prompt (PROVIDER_MENU), and the home
# screen's setup form lists the same choices in the same words (provider_menu()).
PROVIDER_QUESTION = "Which model API do the lanes use?"
PROVIDER_LINES = (  # in PROVIDER_CHOICES' order; the local provider is shown as ollama
    ("openrouter", "one key for many vendors' models (OPENROUTER_API_KEY)"),
    ("anthropic", "Claude models on Anthropic's API (ANTHROPIC_API_KEY)"),
    ("openai", "OpenAI's API (OPENAI_API_KEY)"),
    ("ollama", "open-weight models on this machine, free"),
    ("mlx", "an MLX server on this Mac, free"),
    ("custom", "any other OpenAI-compatible server"),
)
AGENT_NOTE = ("A coding-agent CLI (Claude Code, Codex) is not chosen here: it needs no setup, `flightdeck play --agent "
              "claude` uses it.")
PROVIDER_MENU = (
    PROVIDER_QUESTION + "\n"
    + "".join(f"  {number}  {name:<13}{what}\n" for number, (name, what) in enumerate(PROVIDER_LINES, 1))
    + "Choose one, by number or name. " + AGENT_NOTE.replace("it needs no setup", "it needs\nno setup") + " Your choice"
)
_AGENT_WORDS = ("agent", "codex", "cli", "claudecode", "claude-code")
_CHOOSE = "choose a number from 1 to 6, or one of openrouter, anthropic, openai, ollama (or local), mlx or custom"


def providers_answer(text: str) -> tuple[str, ...]:
    """What a player typed at init's provider menu: a number or a name, or several of them
    (commas or spaces). The first is the lanes' API; the rest are returned for init to say
    what becomes of them. Words for a coding-agent CLI are dropped (the menu says why)."""
    chosen: list[str] = []
    for word in re.split(r"[,\s]+", text.strip().lower()):
        if not word:
            continue
        if word.isdigit() and 1 <= int(word) <= len(PROVIDER_CHOICES):
            word = PROVIDER_CHOICES[int(word) - 1]
        try:
            name = provider_answer(word)
        except AnswerError:
            if any(part in word for part in _AGENT_WORDS):
                continue
            raise AnswerError(_CHOOSE) from None
        if name not in chosen:
            chosen.append(name)
    if not chosen:
        raise AnswerError(_CHOOSE)
    return tuple(chosen)


def provider_menu() -> tuple[tuple[str, str], ...]:
    """The menu's choices as (provider, "name: what it is"), in its order: what the home
    screen's setup form lists."""
    return tuple((provider_answer(name), f"{name}: {what}") for name, what in PROVIDER_LINES)


def default_models(provider: str) -> tuple[str, str]:
    """The models offered for `provider` before the player types any, as the models question
    takes them (weakest first, comma-separated), and why those: Anthropic's ladder, else what
    SUGGESTED_LADDERS holds. ("", "") for custom, whose models only its server can name."""
    if provider == "anthropic":
        return ",".join(ANTHROPIC_LADDER), "Claude Haiku, Sonnet and Opus 5.5, written with Anthropic's list prices"
    return SUGGESTED_LADDERS.get(provider, ("", ""))


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


# What init asks where the runtime is chosen: what host means is said there, not only when play starts.
RUNTIME_QUESTION = "Runtime: docker (a container per lane) or host (lanes run as you, and can read your files and keys)"


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


def provider_api(provider: str) -> tuple[str | None, str | None]:
    """A provider's address and the variable that holds its key ("" for a server that needs
    none); (None, None) for custom, which has neither of its own."""
    if provider == "anthropic":
        return ANTHROPIC
    return PROVIDERS.get(provider, (None, None))


def answers_for(provider: str, ladder: Sequence[str], runtime: str, *, base_url: str | None = None,
                key_env: str | None = None, max_lanes: int = 4, fallback: FallbackAnswers | None = None,
                light: LightAnswers | None = None) -> Answers:
    """The config for a provider (one of PROVIDER_CHOICES), a ladder and a runtime, as
    `flightdeck init` and the home screen's setup form both write it: the provider's address
    and key variable unless others are given (custom has neither of its own, so both must
    be: ValueError), Anthropic's prices for an Anthropic ladder, no dollar cap for a server
    that costs nothing (a cap would only stop every lane once to ask about a cost nobody
    reports): Ollama, an MLX server, and a custom server on this machine (P92; the token cap
    stays, and server_lines says what a local proxy to a paid API should set), and for an
    OpenAI-compatible server on this machine the longer timeout and the reply cap, since a
    local model can take minutes for one reply."""
    from .config import LOCAL_MAX_TOKENS, LOCAL_TIMEOUT
    from .light import on_this_machine

    dialect = "anthropic" if provider == "anthropic" else "openai"
    url, env = provider_api(provider)
    base_url = base_url or url
    key_env = env if key_env is None else key_env
    if base_url is None or key_env is None:
        raise ValueError(f"the {provider} provider has no address or key variable of its own: give both ('' for no key)")
    here = dialect == "openai" and on_this_machine(base_url)
    return Answers(
        base_url, key_env, tuple(ladder), runtime, max_lanes,
        dollar_cap=None if provider in LOCAL_PROVIDERS or (provider == "custom" and here) else 2.0,
        provider=dialect, prices=anthropic_prices(ladder) if dialect == "anthropic" else {},  # the refusal fallback's models too
        fallback=fallback, light=light,
        timeout=LOCAL_TIMEOUT if here else None, max_tokens=LOCAL_MAX_TOKENS if here else None,
    )


LOCAL_PROXY_NOTE = (
    "dollar cap: none, for a server on this machine (the token cap still holds); if it passes calls on to a paid API, "
    "set dollar_cap under [lanes] and the models' prices under [prices]"
)


def server_lines(answers: Answers, provider: str) -> list[str]:
    """What a player is told about a model server on this machine once its config is written:
    for a custom one, that it has no dollar cap and what a proxy to a paid API should set; how long a lane's call may take and how long its reply may be, what Ollama does with a
    lane's context, and the command that starts the MLX server. Nothing for a remote API."""
    from .config import LOCAL_MAX_TOKENS, LOCAL_TIMEOUT

    lines = []
    if provider == "custom" and answers.dollar_cap is None:
        lines.append(LOCAL_PROXY_NOTE)
    if answers.timeout is not None:
        lines.append(f"lane calls: {LOCAL_TIMEOUT} s per try and replies of up to {LOCAL_MAX_TOKENS} tokens, for a server "
                     "on this machine: a local model can take minutes for one reply (the default 180 s gave up on Gemma 4 "
                     f"12B's replies {BENCHMARK}); change timeout and max_tokens under [api]")
    if answers.provider == "openai" and is_ollama(answers.base_url):
        lines.append(f"context: {OLLAMA_CONTEXT_NOTE}")
    if provider == "mlx":
        lines.append(f"next: start the MLX server: {mlx_server_command(answers.models[0], answers.base_url)}   (thinking off, "
                     "and a reply cap of 8192 tokens instead of its 512: with these, Qwen3.5 9B solved 2 of 4 practice "
                     f"challenges on MLX {BENCHMARK})")
    return lines


def lane_image_missing(answers: Answers) -> bool:
    """Whether the config's lanes need the lane image built first: Docker lanes, and the image
    init names (flightdeck's own) is not on this machine."""
    return answers.runtime == "docker" and not image_present(_lane_image())


def check_config(answers: Answers, path: Path, *, force: bool = False) -> str:
    """The config's text for `answers`, checked in memory as load_config() would check the
    file: a ConfigError names `path` and what is wrong. FileExistsError when `path` is there
    and `force` is not given. Nothing is written."""
    from .config import parse_config

    text = render(answers)
    parse_config(text, path)
    if path.exists() and not force:
        raise FileExistsError(f"{path} exists; use --force to replace it")
    return text


def write_config(answers: Answers, path: Path, *, force: bool = False) -> Path:
    """Check the config in memory, then write it. Refuses to overwrite unless force.

    A ConfigError names `path` and what is wrong; nothing is written before the check, so
    a key typed in the wrong place never reaches a file.

    The file is never written over in place: the text goes into a new file beside it, which
    is renamed over the path (config_edit.replace_file: the mode of the config it replaces
    is kept, a link stays a link). A write that fails half way leaves the config that was
    there as it was, and a new config that cannot be written is not left half made. A new
    config gets the mode any new file of the player's gets (their umask), and a file that
    appears at the path while this runs is not written over (FileExistsError)."""
    from .config_edit import replace_file

    text = check_config(answers, path, force=force)
    path.parent.mkdir(parents=True, exist_ok=True)
    target = Path(os.path.realpath(path))  # what a link at the path points at, there or not yet
    made = False
    if not target.exists():
        # an empty file, made with the mode the umask gives, which replace_file then keeps
        os.close(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666))
        made = True
    try:
        replace_file(path, text.encode("utf-8"))
    except BaseException:
        if made:
            target.unlink(missing_ok=True)
        raise
    return path


def write_setup(answers: Answers, path: Path, *, keys: Mapping[str, str] | None = None, force: bool = False) -> Path:
    """Write the config and keep the keys the player gave for it: each of `keys` ({variable:
    key}) goes to the keys file (keys.save: the owner's only, never shown, never in the
    config). Only a variable the config names is taken (its API's, its fallback's:
    ValueError otherwise). The config is checked first (check_config) and written before the
    keys are kept, so a config that would be refused, or cannot be written (OSError), keeps no
    key; and a key that cannot be kept (keys.KeysError) takes the config back out (the one it
    replaced, with `force`, goes back), so none is left that names a key nobody has."""
    from . import keys as keys_file

    check_config(answers, path, force=force)
    named = {answers.key_env, answers.fallback.key_env if answers.fallback is not None else ""} - {""}
    if any(variable not in named for variable in keys or {}):
        raise ValueError("a key was given for a variable the config does not name")
    from .config_edit import replace_file

    try:
        before: bytes | None = path.read_bytes()  # only with force: check_config refuses one that is there
    except FileNotFoundError:
        before = None
    except OSError as exc:  # said by the callers as "cannot write <path>: <strerror>"
        raise OSError(exc.errno, f"the config there cannot be read ({exc.strerror or type(exc).__name__}), so it is not "
                                 "replaced: it could not be put back if the key cannot be kept") from None
    write_config(answers, path, force=force)
    try:
        for variable, value in (keys or {}).items():
            keys_file.save(variable, value)
    except BaseException:
        if before is None:
            path.unlink(missing_ok=True)
        else:
            replace_file(path, before)  # byte for byte, in one step, with the file's mode
        raise
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
           agent: str | None = None, clean: bool = False,
           terminal: tuple[int, int] | None = None) -> list[Check]:
    """Every check, in order. Never prints or returns the API key. `terminal`: the size the
    terminal check measures (columns, lines), for a caller whose output is not the player's
    terminal (the home screen's checks run in a child process: health.py); None asks the
    terminal on standard output, and there is no terminal check without one. `agent` ("claude" or
    "codex") also checks that coding-agent CLI and its credential, and in the docker runtime
    that the lane image has it, as play --agent does; the [api] checks are then warnings,
    since that CLI's lanes never use the [api] key or server. The last checks are what runs
    left running because flightdeck itself was killed (_leftover_checks): reported, and
    removed only with `clean`."""
    from dataclasses import replace

    checks = _checks(config_path, environ, agent, terminal)
    checks += _leftover_checks(config_path, docker=any(c.name == "docker" and c.ok for c in checks), clean=clean)
    if agent is None:
        return checks
    why = f" (only flightdeck's own lanes use it; {agent} lanes use {agent}'s own credential and models)"
    return [replace(c, essential=False, detail=c.detail + ("" if c.ok else why)) if c.name in API_CHECKS else c for c in checks]


def _checks(config_path: Path | None, environ: Mapping[str, str], agent: str | None,
            terminal: tuple[int, int] | None = None) -> list[Check]:
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
    host_at = len(checks)  # where the host line goes: after the machine, once the config says where runs go
    if not path.exists():
        checks.append(Check("config", False, f"no config at {path}", "run `flightdeck init` to write one"))
    else:
        try:
            config = load_config(path)
        except ConfigError as exc:
            checks.append(Check("config", False, str(exc), "fix it, or run `flightdeck init --force` to write a new one"))
        else:
            checks.append(Check("config", True, f"{path}: {len(config.models)} model(s), runtime {config.lanes.runtime}"))
    checks += _config_home_check(environ, config_named=config_path is not None or None)
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
    elif config is not None:
        checks.append(Check("l1 pack", True, "none, so each lane starts on its model (optional: `flightdeck pack install` adds "
                            "flightdeck's solver pack, some 800 no-model solvers that run first)"))
    if config is not None and config.plugins:
        from .plugins import manifest as plugins

        for name, ref in config.plugins.items():  # read, never run: a plugin that cannot be used stops only its own events
            try:
                checks.append(Check(f"plugin {name}", True, plugins.doctor_line(plugins.load(ref)), essential=False))
            except plugins.PluginError as exc:
                said = str(exc).removeprefix(f"plugin {name}: ")  # the line is named "plugin NAME" already
                if not (ref.path / plugins.MANIFEST).exists():  # the folder moved or is gone: no plugin.toml to fix
                    fix = (f"put the plugin's folder back at {ref.path}, or change [plugins.{name}] path in {path} to where "
                           f"it is now, or take [plugins.{name}] out")
                else:
                    fix = f"fix the plugin's plugin.toml, or take [plugins.{name}] out of {path}"
                checks.append(Check(f"plugin {name}", False, said, fix, essential=False))
    found = False
    if agent is not None:
        agent_checks = _agent_checks(agent, config, environ)
        found = any(c.name == "agent" and c.ok for c in agent_checks)
        checks += agent_checks
    docker = _docker_checks(config)
    checks += docker
    if config is not None and config.l1.pack is not None:
        checks += _pack_tools_checks(config, environ, docker_runs=any(c.name == "docker" and c.ok for c in docker))
    checks.insert(host_at, _host_check(config, environ))
    image_there = any(c.name == "lane image" and c.ok for c in docker)
    if agent is not None and found and image_there and config is not None and config.lanes.runtime == "docker":
        checks.append(_agent_image_check(agent, config))  # play --agent runs the CLI inside that image
    if terminal is not None:
        columns, lines = terminal
    else:
        try:
            columns, lines = os.get_terminal_size()
        except OSError:
            columns = lines = 0
    if columns:
        checks.append(_terminal_check(columns, lines, config))
    return checks


def _host_check(config, environ: Mapping[str, str], reading=None) -> Check:
    """The host governor's readings now (governor.py): the load per CPU, the RAM available and
    the free disk where runs go (the config's runs folder, else the default one), and any
    `[governor]` limit that binds, which would hold a run's new lanes back. Never essential:
    a busy machine is no broken setup. `reading`: as probed, else probed here."""
    from . import governor, hardware
    from .config import DEFAULT_RUN_DIR, GovernorConfig

    policy = config.governor if config is not None else GovernorConfig()
    if reading is None:
        try:
            runs = config.run_dir if config is not None else Path(DEFAULT_RUN_DIR).expanduser()
        except RuntimeError:  # no home folder to expand ~ with
            runs = Path.cwd()
        reading = governor.probe(runs, hardware.RealHost(environ))
    said = governor.summary(reading)
    if not policy.enabled:
        return Check("host", True, f"{said}; the governor is off ([governor] enabled = false): no lane is held back for these",
                     essential=False)
    binding = governor.decide(reading, policy, 0).limits
    if binding:
        return Check(
            "host", False, f"{said}; over a limit now: {binding}",
            "a run would start one lane at a time until this clears (the lanes at work carry on); free the machine up, "
            "or change the limit under [governor] in your config", essential=False,
        )
    return Check("host", True, f"{said}; within the [governor] limits, so a run holds no lane back", essential=False)


def _pack_tools_checks(config, environ: Mapping[str, str], *, docker_runs: bool) -> list[Check]:
    """The programs the config's pack says its engines call (`tools` in its pack.toml) that
    are missing where the engines run: on this machine's PATH for the host runtime; for
    Docker, in the image they run in (`[l1] image`, else the lane image), asked of one
    throwaway container with no network (pack.missing_in_image). Never essential: an engine
    whose program is missing says so when it runs, and the rest still work. When the image
    cannot be asked (no Docker, not on this machine), the line says that, and nothing about
    what is missing. A pack that lists no tools gets no line."""
    from . import pack as packs

    name = "pack tools"
    try:
        info = packs.read(config.l1.pack)
    except packs.PackError as exc:
        return [Check(name, False, str(exc), "fix the pack's pack.toml", essential=False)]
    tools = info.tools
    if not tools:
        return []
    count = f"{len(tools)} program{'' if len(tools) == 1 else 's'}"
    unrun = "an engine that needs a missing one says so and does not run; the rest work"
    if config.lanes.runtime == "host":
        absent = packs.missing_on_host(tools, environ.get("PATH", ""))
        if not absent:
            return [Check(name, True, f"all {count} the pack's engines call are on PATH", essential=False)]
        return [Check(name, False, f"not on PATH: {' '.join(absent)} ({len(absent)} of the {count} the pack's engines call)",
                      f"install them ({unrun})", essential=False)]
    own = config.l1.image
    image = own or config.lanes.image
    what = f"the pack image {image}" if own else f"the lane image {image} (no [l1] image: engines run in it)"
    build = "`flightdeck pack image` builds it" if own else "`flightdeck image build` builds flightdeck's own"
    if not docker_runs:
        return [Check(name, False, f"not looked up: Docker is not running, so {what} cannot be asked which of the "
                                   f"{count} the pack's engines call it has", essential=False)]
    if not image_present(image):
        return [Check(name, False, f"not looked up: {what} is not on this machine, so which of the {count} the pack's "
                                   "engines call it has is not known", build, essential=False)]
    try:
        absent = packs.missing_in_image(image, tools)
    except packs.PackError as exc:
        return [Check(name, False, f"not looked up: {exc}", essential=False)]
    if not absent:
        return [Check(name, True, f"all {count} the pack's engines call are in {what}", essential=False)]
    return [Check(name, False, f"not in {what}: {' '.join(absent)} ({len(absent)} of the {count} the pack's engines call)",
                  f"add them to the image ({unrun})", essential=False)]


ROOM_LANES = 16  # the terminal check looks at room for at most this many lanes (D8: the lane list scrolls past it)


def _terminal_check(columns: int, lines: int, config) -> Check:
    """What a terminal this size leaves out of the console on a busy run with your lanes and
    runtime, in the layout your config opens it in, and from which size none of it
    (console/room.py measures it with the console's own code: the header's pieces drop in the
    order CONSOLE-SPEC "Narrow terminals" and D16 set)."""
    from .config import ConsoleConfig, LaneConfig
    from .console.room import room

    lanes = config.lanes if config is not None else LaneConfig()
    layout = (config.console if config is not None else ConsoleConfig()).layout  # the layout the console opens in
    fit = room(columns, lines, max_lanes=min(lanes.max_lanes, ROOM_LANES), containerized=lanes.runtime == "docker", layout=layout)
    size = f"{columns}x{lines}"
    team = f"; team mode's key line, with c claim, needs {fit.team_columns} columns" if fit.team_columns > fit.columns else ""
    missing = fit.left_out()
    if not missing:
        rows = f"each of your {lanes.max_lanes} lanes" if lanes.max_lanes > 1 else "your lane"
        # the simple layout has no board, and its key line shows the keys that apply to the selected lane
        shows = "the whole header, its key line" if layout == "simple" else "the whole header, the board, every key"
        return Check("terminal", True, f"{size}: on a busy run the console shows {shows} "
                                       f"and a row for {rows}" + (team if columns < fit.team_columns else ""))
    layout = ""
    if fit.compact:
        from .console.views import COMPACT_MAX_WIDTH

        layout = (f"the compact layout, for {COMPACT_MAX_WIDTH} columns or fewer (what needs you and why, the one-key "
                  "answers, each lane's state and cost); ")
    return Check(
        "terminal", False, f"{size}: {layout}on a busy run the console leaves out " + "; ".join(missing),
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
        return [Check("agent", False, str(exc), _agent_fix(kind, str(exc)))]
    checks = [Check("agent", True, f"{kind} at {found.executable}" + (f": {found.auth}" if found.auth else ""))]
    checks += [Check("agent note", False, warning, essential=False) for warning in found.warnings]
    return checks


AGENT_CREDENTIALS = {  # how each CLI gets its credential, as find_agent reads it
    "claude": "set ANTHROPIC_API_KEY, or CLAUDE_CODE_OAUTH_TOKEN (`claude setup-token` makes one), in the keys file or "
              "the environment",
    "codex": "set CODEX_API_KEY in the keys file or the environment, or run `codex login` (host runtime only)",
}


def _agent_fix(kind: str, problem: str) -> str:
    """What to do about find_agent's `problem`: install the CLI only when it is the CLI that is
    missing, fix the ladder when its model name is refused, else how that CLI gets its credential."""
    if "not found on PATH" in problem:
        return f"install {kind}, or put the folder that has it on PATH"
    if "is not a model name" in problem:
        return f"give {kind} a model name its CLI takes: [agents] {kind} in your config"
    return AGENT_CREDENTIALS.get(kind, f"give {kind} its credential")


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


def _config_home_check(environ: Mapping[str, str], *, config_named: bool | None) -> list[Check]:
    """The `config folder` check, only when $XDG_CONFIG_HOME moved flightdeck's config folder
    and a file of it is still at ~/.config/ctf-flightdeck: where each was found, and whether it
    is read (confighome.notes). Not essential: a run reads the file that line names."""
    from . import confighome

    try:
        lines = confighome.notes(environ, config_named=config_named)
    except (OSError, RuntimeError):
        return []
    if not lines:
        return []
    return [Check("config folder", False, "; ".join(lines),
                  f"keep flightdeck's files in {confighome.show(confighome.folder(environ))}", essential=False)]


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

    from .run import host_warning

    where = f"in {config.source}" if config is not None and config.source is not None else "in your config"
    reason = docker_unavailable()
    if config is not None and config.lanes.runtime == "host":
        risk = Check("host runtime", False, host_warning(), essential=False)  # what host means, wherever it is the runtime
        if reason:
            return [Check("docker", False, f"{reason}; your config runs lanes on this machine, so only `play --docker` "
                                           "needs Docker", essential=False), risk]
        return [Check("docker", True, "running (your config runs lanes on this machine; `play --docker` would use it)"), risk]
    if reason:
        return [Check("docker", False, reason, "install or start Docker, or run lanes on this machine (lanes then run as you "
                                               'and can read your files and keys): set runtime = "host" '
                                               f"under [lanes] {where}, or pass --host to play or practice")]
    out = [Check("docker", True, "running")]
    if config is not None:
        image = config.lanes.image
        found = image_present(image)
        how = "flightdeck image build" if image == IMAGE else f"docker pull {image}"
        out.append(Check("lane image", found, f"{image} is {'present' if found else 'not on this machine'}", f"run `{how}`"))
        if found:
            out += _lane_image_build_checks(image)
        if config.l1.pack is not None and config.l1.image:
            there = image_present(config.l1.image)
            out.append(Check("l1 image", there, f"{config.l1.image} is {'present' if there else 'not on this machine'}",
                             "run `flightdeck pack image`, or remove [l1] image to run engines in the lane image"))
    return out


def _lane_image_build_checks(image: str) -> list[Check]:
    """A lane image that is on this machine but was not built from the Dockerfile this
    flightdeck ships: nothing else asks for a rebuild, and what its lanes' shells have may
    differ (the image of flightdeck 0.4.0 has no debugger and no decompiler: P59). Told by the
    label `image build` writes (lane.built_from), so no container is started. A warning:
    lanes run in the old image all the same, and each lane's brief names only what its own
    container has. No line for an image built from today's Dockerfile, for one that cannot be
    asked, or for a player's own image that carries no such label: what that holds is theirs."""
    from . import lane

    label = lane.built_from(image)
    if label is None or label == lane.fingerprint() or (not label and image != lane.IMAGE):
        return []
    return [Check(
        "lane image build", False,
        f"{image} was not built from the Dockerfile this flightdeck ships (another flightdeck built it, or it was built by "
        "hand), so its lanes' shells may lack programs this one's have",
        "run `flightdeck image build` to build it again (lanes run in the old one all the same)", essential=False,
    )]


def image_present(image: str) -> bool:
    """Whether Docker on this machine has `image` (false when it has not, or when there is no
    Docker to ask). Nothing is pulled."""
    docker = shutil.which("docker")
    if docker is None:
        return False
    try:
        return subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def report(checks: Sequence[Check], *, agent: str | None = None) -> tuple[str, int]:
    """The checks as lines for the terminal, and the exit status (1 if an essential check
    failed). `agent`: what was checked was for that coding-agent CLI's lanes, so the next
    step is practice with it.

    The last line is the one a player acts on: how many things there are to fix (the FAIL
    lines, which stop a run) and what to run then, or that the setup is ready and the next
    command. Warnings are counted on it too, as what they are: nothing a run waits for."""
    lines = []
    for check in checks:
        mark = "ok  " if check.ok else ("FAIL" if check.essential else "warn")
        lines.append(f"{mark} {check.name}: {check.detail}")
        if not check.ok and check.fix:
            lines.append(f"     fix: {check.fix}")
    failed = sum(1 for c in checks if not c.ok and c.essential)
    warned = sum(1 for c in checks if not c.ok and not c.essential)
    warnings = f"{warned} warning{'' if warned == 1 else 's'}"
    again = "flightdeck doctor" + (f" --agent {agent}" if agent else "")
    practice = "flightdeck practice" + (f" --agent {agent}" if agent else "")
    if failed:
        last = (f"{failed} thing{'' if failed == 1 else 's'} to fix before a run: the FAIL line{'' if failed == 1 else 's'} above. "
                f"Then run `{again}` again.")
        if warned:
            last += f" ({warnings} besides: a run does not wait for {'it' if warned == 1 else 'them'}.)"
    elif warned:
        last = f"Ready, with {warnings} above that a run does not wait for. Try `{practice}`."
    else:
        last = f"Ready. Try `{practice}`."
    lines.append(last)
    return "\n".join(lines) + "\n", 1 if failed else 0
