"""`flightdeck eval-local`: measure light models against the rules before switching one on.

The integrator mounts this module's `app` onto the root CLI, so `flightdeck eval-local` runs it.

Engines (light.py), each a column of the scorecard, the rules always the first (they are what
the light role falls back to):

- `--engine openai --base-url URL --model M`: an OpenAI-compatible server. Recommended: an
  open-weight model on this machine (Ollama: http://127.0.0.1:11434/v1, an MLX server:
  http://127.0.0.1:8080/v1), no key. `--key-env` names a key's variable for a server that
  needs one.
- `--engine anthropic --model M`: a Claude model (claude-haiku-5-5, say), key from
  `--key-env` (default ANTHROPIC_API_KEY), base URL the SDK's unless `--base-url`.
- `--engine cactus`: Cactus Needle on this machine (the [cactus] extra).
- `--engine decider --base-url URL`: a Strands Decider server (a decision model; e.g.
  http://127.0.0.1:8000 for `strands-decider serve MODEL --port 8000`), `--model` optional (the
  model it should report serving). An answer below `--threshold` (default 0.9) is unsure: a row
  of its own, and neither right nor wrong, so its accuracy is how often an answer it was sure of
  is right. Summary cases are n/a (a decision model writes no text). It is always announced
  first: the server it calls and at most how many times (one call per hint and judge case).
- `--engine rules`: the rules alone.
- `--from-config`: the engines your config gives the jobs, as a run builds them: each job's
  [light.<job>] table, else [light] (a run job [light] jobs leaves out gets none, so only the
  rules score it), one column per distinct engine, doing only its jobs.
- `--compare SPEC`, as often as you like: another column, `rules`, `cactus`,
  `anthropic:MODEL`, `openai:MODEL@BASE_URL` (a server with no key) or `decider@BASE_URL`.
- `--jobs JOB,...`: only these jobs' cases (hint, judge, summary, route, recon, flagcheck).
- `--cases FILE|bundled`: the case set. `bundled` (the default) is flightdeck's own set of
  all six jobs; FILE a JSONL file of the player's, in the same format (a second, independently
  written set, say: the same model on both shows how much a figure owes to the wording of
  one set). Every set is
  checked before anything is scored or sent (localmodel.check_synthetic): hosts under .test
  only, no key material; a bad case stops the command with the file and the line. The
  scorecard's second line names the set its figures come from, and how many runs.
- `--repeat N`: each engine runs N times over the cases, one run after another. The scorecard
  then leads with a runs table: each run's score in each job, the mean and the range, so the
  spread between runs shows; the rest is the first run in full. The rules answer the same
  every run, so they run once. A paid engine's announcement says calls x N.
- `--show-misses`: after the scorecard, every job each column got wrong, with what it said
  (keyword verdicts on briefs and summaries under-credit: read them).
- `--thinking on|off`: whether an openai column's model may reason before it answers, as
  [light] thinking says in a run (off sends light.THINKING_OFF with each request). Default:
  for a column on [light]'s own server, [light] thinking as your config sets it; for any
  other, off for a server on this machine and on elsewhere (config.light_thinking()), so
  nothing is added for an API elsewhere unless asked. Each openai column's label says which.

Before any call the cases are checked and the rules scored (no network): a missing lexicon, or
a case that names an id it lacks, stops the command before anything is spent. A paid API
(Claude, or an OpenAI-compatible server not on this machine) is said first: how many calls it
makes (one per job it does, a route case being three, never a retry, so never more than the
case set) and how they are priced (`--price`, or the config's [light] price with
--from-config, else for Claude its list price as flightdeck knows it, else unknown).

--base-url may carry credentials (a user name and password, or a token in the query string,
for a server behind a proxy). They are sent, never shown: messages name the endpoint without
them, and any of them MIN_SECRET characters or longer is cut out of text a server sends back.
A key is read from its variable (or the keys file) and never shown either.

Exit codes: 0 with the scorecard; 2 when the evaluation cannot run (options, cases, the
lexicon, an engine that fails on its first jobs); 1 after the scorecard when most of an
engine's jobs held no answer (declined, failed, cut off, empty, not an option), since that
score does not measure the model.
"""

from __future__ import annotations

import asyncio
import math
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, NoReturn
from urllib.parse import urlsplit

import httpx
import typer

from . import light as L
from . import localmodel

if TYPE_CHECKING:
    from .config import Config, LightConfig

app = typer.Typer(no_args_is_help=True, help="Measure a light model against the rules on small jobs (D15).")

EXAMPLE_URL = "http://127.0.0.1:11434/v1"
MIN_SECRET = 4  # shorter parts of --base-url are not cut out of server text: that would garble it
MAX_REPEAT = 50  # --repeat's most runs: more is a mistyped number, and a paid engine's bill
DEFAULT_TIMEOUT = 30.0  # seconds a job may take, unless --timeout (or, with --from-config, the config) says
ANTHROPIC_KEY_ENV = "ANTHROPIC_API_KEY"
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")


@dataclass(frozen=True)
class Spec:
    """One engine to evaluate, as the options give it. From the config (--from-config):
    `light` is its engine spec, built as a run builds it, and `jobs` the jobs it does there."""

    engine: str
    model: str = ""
    base_url: str = ""
    key_env: str = ""
    light: LightConfig | None = None
    jobs: tuple[str, ...] | None = None  # None: every job its engine does


class _Only:
    """An engine asked only some jobs (a column from the config: the jobs it has there)."""

    def __init__(self, engine: L.Light, jobs: tuple[str, ...]) -> None:
        self._engine = engine
        self._jobs = jobs

    def does(self, job: str) -> bool:
        return job in self._jobs and self._engine.does(job)

    def __getattr__(self, name: str):
        return getattr(self._engine, name)


@app.command("eval-local")
def eval_local(
    engine: Annotated[
        str | None, typer.Option("--engine", help="openai (an OpenAI-compatible server; recommended: an open-weight model "
                                                  "on this machine), anthropic, cactus, decider (a Strands Decider server) "
                                                  "or rules. Default openai.")
    ] = None,
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help=f"The OpenAI-compatible base URL, e.g. {EXAMPLE_URL} (Ollama) or "
                                        "http://127.0.0.1:8080/v1 (an MLX server); for anthropic, another API URL; for "
                                        f"decider, its server's address, e.g. {L.DECIDER_URL}."),
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model id to evaluate (decider: optional, the model "
                                                               "its server must report serving).")] = None,
    key_env: Annotated[
        str | None, typer.Option("--key-env", help="The variable holding the key (anthropic: ANTHROPIC_API_KEY by "
                                                   "default; openai: none unless given). Never the key itself.")
    ] = None,
    price: Annotated[
        str | None, typer.Option("--price", metavar="IN,OUT[,CACHED]",
                                 help="Dollars per million tokens, for an API that reports no cost.")
    ] = None,
    timeout: Annotated[
        float | None, typer.Option("--timeout", help="Seconds one job may take (default 30; with --from-config, each "
                                                     "engine's [light] timeout).")
    ] = None,
    threshold: Annotated[
        float | None, typer.Option("--threshold", help=f"Decider columns: the confidence below which an answer is "
                                                       f"unsure (default {L.DECIDER_THRESHOLD:g}).")
    ] = None,
    compare: Annotated[
        list[str] | None,
        typer.Option("--compare", metavar="SPEC",
                     help="Another engine to score beside it: rules, cactus, anthropic:MODEL, openai:MODEL@BASE_URL or "
                          "decider@BASE_URL."),
    ] = None,
    cases: Annotated[
        str | None,
        typer.Option("--cases", metavar="FILE",
                     help="The case set: a JSONL file of your own in the bundled set's format (synthetic only: hosts "
                          "under .test, no key material), or `bundled` (the default: the set bundled with flightdeck)."),
    ] = None,
    repeat: Annotated[
        int, typer.Option("--repeat", metavar="N",
                          help="Run each engine N times over the cases and show each run's score, the mean and the "
                               "range. A paid engine then makes N times the calls, and is announced so.")
    ] = 1,
    thinking: Annotated[
        str | None,
        typer.Option("--thinking", metavar="on|off",
                     help="Whether an openai model may reason before it answers; off asks for thinking off with each "
                          "request. Default: [light] thinking from your config for [light]'s own server, else off for a "
                          "server on this machine and on elsewhere.")
    ] = None,
    jobs: Annotated[
        str | None, typer.Option("--jobs", metavar="JOB,...",
                                 help="Only these jobs' cases: hint, judge, summary, route, recon, flagcheck.")
    ] = None,
    from_config: Annotated[
        bool, typer.Option("--from-config", metavar="", help="Score each job with the engine your config gives it ([light.<job>], "
                                                 "else [light]), beside the rules.")
    ] = False,
    show_misses: Annotated[
        bool, typer.Option("--show-misses", metavar="", help="Also list every job each column got wrong, with what it said.")
    ] = False,
) -> None:
    """Score light models and the rules side by side on the light jobs: hints, hint judging, lane
    summaries, routing, first-pass briefs and flag checks, alone and as a run uses each."""
    if timeout is not None and (not math.isfinite(timeout) or timeout <= 0):
        _fail("--timeout must be a positive number of seconds")
    if not 1 <= repeat <= MAX_REPEAT:
        _fail(f"--repeat must be a number of runs from 1 to {MAX_REPEAT}")
    think = _thinking_option(thinking) if thinking is not None else None
    wanted = _jobs_option(jobs) if jobs is not None else None
    config = None
    if from_config:
        given = [name for name, value in (("--engine", engine), ("--base-url", base_url), ("--model", model),
                                          ("--key-env", key_env), ("--price", price)) if value is not None]
        if given:
            _fail(f"--from-config takes each engine from your config: drop {', '.join(given)} (--compare adds columns)")
        config = _config_for_columns()
        specs = [Spec("rules")]
    else:
        specs = [_main_spec(engine or "openai", base_url, model, key_env)]
    specs += [_compare_spec(text) for text in compare or ()]
    if threshold is not None and not any(spec.engine == "decider" for spec in specs) and config is None:
        _fail("--threshold is for a decider column (--engine decider or --compare decider@BASE_URL)")
    if threshold is not None and not (math.isfinite(threshold) and 0 < threshold <= 1):
        _fail("--threshold must be a number above 0 and at most 1: the confidence below which an answer is unsure")
    if price is not None and specs[0].engine == "decider":
        _fail("--price is not for --engine decider: a decision model server is your own, with no bill per call")
    priced = _price(price) if price is not None else None

    loaded, source = _case_set(cases)
    if wanted is not None:
        loaded = [case for case in loaded if case.kind in wanted]
        if not loaded:
            _fail(f"the case set has no {' or '.join(wanted)} cases")

    # The baseline is cheap and needs no network, so compute it first: if the lexicon is
    # missing, or a case names an id it does not have, we stop before any model call.
    try:
        rules = localmodel.rules_baseline(loaded)
    except localmodel.LocalModelError as exc:
        _fail(str(exc))

    columns: list[Spec] = _config_columns(config, loaded) if config is not None else []
    for spec in specs:
        if spec.engine != "rules" and spec not in columns:
            columns.append(spec)
    if threshold is not None and not any(spec.engine == "decider" for spec in columns):
        _fail("--threshold is for a decider column (--engine decider or --compare decider@BASE_URL)")
    if think is not None and not any(spec.engine == "openai" for spec in columns):
        _fail("--thinking is for an openai engine (a model on an OpenAI-compatible server); give --engine openai or "
              "--compare openai:MODEL@BASE_URL")
    thinks = _thinks(columns, think)
    keys = {spec: _config_key(config, spec) if spec.light is not None else _key(spec) for spec in columns}
    main = specs[0] if specs[0].engine != "rules" else None
    if repeat > 1 and not columns:
        _fail("--repeat is for a light model: the rules answer the same every run, so they run once")
    for spec in columns:
        sure = threshold if threshold is not None else (spec.light.threshold if spec.light else L.DECIDER_THRESHOLD)
        price_of = priced if spec == main else (spec.light.price if spec.light else None)
        notice = _spend_notice(spec, loaded, price_of, repeat) or _decider_notice(spec, loaded, sure, repeat)
        if notice:
            typer.echo(f"flightdeck: {notice}", err=True)

    runs = asyncio.run(_run(columns, keys, loaded, priced if main in columns else None, main, timeout, threshold,
                            thinks, repeat))
    reports = [column[0] for column in runs]
    typer.echo(localmodel.format_scorecard([rules, *reports], show_misses=show_misses, source=source,
                                           runs=[(rules,), *runs]), nl=False)
    worst = []
    for spec, column in zip(columns, runs):
        for number, report in enumerate(column, start=1):
            message = _unmeasured(report, thinks.get(spec))
            if message:  # one line an engine: its first run that does not measure it
                worst.append(message if repeat == 1 else f"run {number} of {repeat}: {message}")
                break
    for message in worst:
        typer.echo(f"flightdeck: {message}", err=True)
    if worst:
        raise typer.Exit(1)


def _fail(message: str) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(2) from None


def _case_set(named: str | None) -> tuple[list[localmodel.Case], str]:
    """The cases --cases names and how the scorecard names their set: `bundled` (or no
    --cases) is flightdeck's own, anything else a file of the player's (a file called
    `bundled` is ./bundled). Every set is checked before anything is scored or sent: a
    malformed case, or one that is not synthetic (a host outside .test, key material), stops
    the command with the file and the line."""
    from .text import untrusted

    try:
        if named is None or named in localmodel.CASE_SETS:
            name = named or localmodel.BUNDLED
            path = localmodel.bundled_cases_path(name)
            source = f"{name} (flightdeck's own, {path.name})"
        else:
            from .config import ConfigError, expand

            try:
                path = expand(Path(named))
            except ConfigError as exc:
                _fail(f"--cases: {exc}")
            if not path.is_file():
                _fail(f"--cases: {'not a file' if path.exists() else 'no such file'}: {untrusted(named, one_line=True)} "
                      f"(a case file of your own, or one of flightdeck's sets: {', '.join(localmodel.CASE_SETS)})")
            source = f"{untrusted(path.name, one_line=True)} (your file)"
        loaded = localmodel.load_cases(path)
        localmodel.check_synthetic(loaded, path)
    except (localmodel.LocalModelError, FileNotFoundError) as exc:
        _fail(str(exc))
    return loaded, source


# ---------------------------------------------------------------------- the engines


def _main_spec(engine: str, base_url: str | None, model: str | None, key_env: str | None) -> Spec:
    if engine == "rules":
        return Spec("rules")
    if engine == "cactus":
        return Spec("cactus")
    if engine == "openai":
        if not base_url or not model:
            _fail("--engine openai needs --base-url and --model, e.g. --base-url http://127.0.0.1:11434/v1 for an "
                  "open-weight model served by Ollama on this machine")
        _check_url(base_url)
        return Spec("openai", model, base_url, _key_env(key_env) if key_env else "")
    if engine == "anthropic":
        if not model:
            _fail("--engine anthropic needs --model, e.g. claude-haiku-5-5")
        if base_url:
            _check_url(base_url)
        return Spec("anthropic", model, base_url or "https://api.anthropic.com", _key_env(key_env or ANTHROPIC_KEY_ENV))
    if engine == "decider":
        if not base_url:
            _fail(f"--engine decider needs --base-url, its server's address, e.g. {L.DECIDER_URL} for one on this "
                  f"machine (start it: {L.DECIDER_SERVE})")
        if key_env:
            _fail("--key-env is not for --engine decider: a decision model server takes no key")
        _check_decider_url(base_url)
        return Spec("decider", model or "", base_url, "")
    _fail(f"unknown engine {engine!r}; use openai, anthropic, cactus, decider or rules")


def _compare_spec(text: str) -> Spec:
    if text in ("rules", "cactus"):
        return Spec(text)
    kind, sep, rest = text.partition(":")
    if kind == "anthropic" and sep and rest:
        return Spec("anthropic", rest, "https://api.anthropic.com", ANTHROPIC_KEY_ENV)
    if kind == "openai" and sep:
        at = rest.rfind("@http")
        if at > 0:
            url = rest[at + 1:]
            _check_url(url, option="--compare")
            return Spec("openai", rest[:at], url, "")
    if text.startswith("decider@http"):
        url = text[len("decider@"):]
        _check_decider_url(url, option="--compare")
        return Spec("decider", "", url, "")
    _fail("--compare takes rules, cactus, anthropic:MODEL, openai:MODEL@BASE_URL or decider@BASE_URL "
          f"(e.g. openai:some-model@{EXAMPLE_URL} or decider@{L.DECIDER_URL})")


def _thinking_option(text: str) -> bool:
    """--thinking: True for on, False for off."""
    value = text.strip().lower()
    if value not in ("on", "off"):
        _fail("--thinking must be on or off")
    return value == "on"


def _jobs_option(text: str) -> tuple[str, ...]:
    """--jobs: the job names, each once, in KINDS order."""
    named = [part.strip() for part in text.split(",") if part.strip()]
    unknown = [name for name in named if name not in localmodel.KINDS]
    if not named or unknown:
        _fail(f"--jobs takes job names separated by commas: {', '.join(localmodel.KINDS)}")
    return tuple(kind for kind in localmodel.KINDS if kind in named)


def _config_for_columns() -> Config:
    """The player's config, for --from-config; one that cannot be read stops here, named."""
    from .config import ConfigError, default_config_path, load_config

    try:
        return load_config(default_config_path())
    except ConfigError as exc:
        _fail(f"--from-config: {exc}")


def _config_columns(config: Config, cases: list[localmodel.Case]) -> list[Spec]:
    """A column for each distinct engine the config gives the cases' jobs ([light.<job>], else
    [light]), doing only those jobs. A run job [light] jobs leaves out has no engine (only the
    rules score it), nor has a job whose engine is the rules; hint and summary, which no run
    uses, take [light.hint] or [light.summary], else [light]."""
    from .config import EVAL_JOBS, light_for

    grouped: dict[LightConfig, list[str]] = {}
    for kind in localmodel.KINDS:
        if not any(case.kind == kind for case in cases):
            continue
        if kind not in EVAL_JOBS and kind not in config.light_jobs:
            continue
        light = light_for(config, kind)
        if light.engine != "rules" and kind in L.DOES[light.engine]:
            grouped.setdefault(light, []).append(kind)
    columns = [Spec(light.engine, light.model, light.base_url, light.key_env, light=light, jobs=tuple(kinds))
               for light, kinds in grouped.items()]
    for spec in columns:
        typer.echo(f"flightdeck: from {config.source}: {spec.engine} {spec.model or _shown(spec.base_url)} does "
                   f"{_and(list(spec.jobs or ()))}", err=True)
    if not columns:
        typer.echo(f"flightdeck: {config.source} gives these jobs no light model: the rules alone", err=True)
    return columns


def _config_key(config: Config | None, spec: Spec) -> str | None:
    """The key of a column from the config, read as a run reads it; a missing one stops here."""
    from .config import ConfigError, light_key

    assert config is not None and spec.jobs
    try:
        return light_key(config, spec.jobs[0])
    except ConfigError as exc:
        _fail(str(exc))


def _thinks(columns: list[Spec], think: bool | None) -> dict[Spec, bool]:
    """Whether each openai column's model may reason before it answers: --thinking when given;
    for a column from the config, its own thinking as a run reads it (config.light_thinking());
    else, for a column on [light]'s own server, [light] thinking as the player's config sets it
    (their word for that server, said on stderr); else the default for the column's server
    (config.light_thinking(): off on this machine, on elsewhere). So [light] thinking = false,
    which init writes for a light model on this machine, never sends a field to an API
    elsewhere, which may refuse fields it does not know."""
    openai = [spec for spec in columns if spec.engine == "openai"]
    if think is not None:
        return {spec: think for spec in openai}
    if not openai:
        return {}
    from .config import LightConfig, light_thinking

    thinks = {spec: light_thinking(spec.light) for spec in openai if spec.light is not None}
    openai = [spec for spec in openai if spec.light is None]
    if not openai:
        return thinks
    light, where = _configured_light()
    said = set()
    for spec in openai:
        mine = light is not None and light.thinking is not None and _same_server(spec.base_url, light.base_url)
        thinks[spec] = light_thinking(LightConfig("openai", spec.model, spec.base_url, spec.key_env,
                                                  thinking=light.thinking if mine else None))
        if mine and _shown(spec.base_url) not in said:
            said.add(_shown(spec.base_url))
            typer.echo(f"flightdeck: thinking {'on' if light.thinking else 'off'} for {_shown(spec.base_url)}, [light]'s "
                       f"server, as [light] thinking in {where} says (--thinking on|off overrides it)", err=True)
    return thinks


def _configured_light() -> tuple[LightConfig | None, Path | None]:
    """The player's [light] table when its engine is openai (None for another engine, or when
    there is no config file), and the file. A config that cannot be read stops here, named:
    its thinking is not guessed."""
    from .config import ConfigError, default_config_path, load_config

    try:
        path = default_config_path()
        if not path.exists():
            return None, None
        light = load_config(path).light
    except (ConfigError, OSError) as exc:
        _fail(f"--thinking takes its default from [light] thinking in your config, which cannot be read: {exc}. "
              "Fix it, or give --thinking on or off")
    return (light if light.engine == "openai" else None), path


def _same_server(one: str, other: str) -> bool:
    """Whether two base URLs name the same server: the same scheme, port and path (a trailing
    slash aside) and the same host, 127.0.0.1, localhost and ::1 being one machine. User info,
    query and fragment do not count."""
    from urllib.parse import urlsplit

    def server(url: str) -> tuple | None:
        try:
            parts = urlsplit(url.strip())
            port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
        except ValueError:
            return None
        host = "this machine" if L.on_this_machine(url) else parts.hostname
        return parts.scheme, host, port, parts.path.rstrip("/")

    here = server(one)
    return here is not None and here == server(other)


def _key_env(name: str) -> str:
    if not _ENV_NAME.fullmatch(name):
        _fail("--key-env must name an environment variable in upper case, like ANTHROPIC_API_KEY, not hold the key")
    return name


def _key(spec: Spec) -> str | None:
    """The key for `spec` from its variable or the keys file; a missing one stops here, named."""
    if not spec.key_env:
        return None
    from .keys import KeysError, environment, keys_path

    try:
        value = environment().get(spec.key_env, "").strip()
    except KeysError as exc:
        _fail(str(exc))
    if not value:
        _fail(f"{spec.key_env} is not set: put {spec.key_env}=<your key> in {keys_path()} (chmod 600), or export it")
    return value


def _price(text: str) -> L.Price:
    try:
        values = [float(part) for part in text.split(",")]
    except ValueError:
        _fail("--price must be IN,OUT or IN,OUT,CACHED: dollars per million tokens")
    if len(values) not in (2, 3) or not all(math.isfinite(v) and v >= 0 for v in values):
        _fail("--price must be IN,OUT or IN,OUT,CACHED: dollars per million tokens, 0 or more")
    return L.Price(*values)


def _list_price(model: str) -> L.Price | None:
    from .setup import ANTHROPIC_PRICES

    return ANTHROPIC_PRICES.get(model)


def _paid(spec: Spec) -> bool:
    if spec.engine == "anthropic":
        return True
    if spec.engine == "openai":
        return not L.on_this_machine(spec.base_url)
    return False


def _does(spec: Spec, kind: str) -> bool:
    """Whether a column's engine does `kind`'s jobs (from the config: only its own jobs there)."""
    return kind in L.DOES[spec.engine] and (spec.jobs is None or kind in spec.jobs)


def _and(words: list[str]) -> str:
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def _calls(calls: int, repeat: int) -> str:
    """How many calls an engine makes at most: "4 calls", or over --repeat's runs "4 calls x 3 runs = 12 calls"."""
    return f"{calls} calls" if repeat == 1 else f"{calls} calls x {repeat} runs = {calls * repeat} calls"


def _spend_notice(spec: Spec, cases: list[localmodel.Case], price: L.Price | None, repeat: int = 1) -> str:
    """What a paid engine is about to spend, said before any call; "" for a free one."""
    if not _paid(spec):
        return ""
    calls = localmodel.count_jobs(cases, lambda kind: _does(spec, kind))
    routed = any(case.kind == L.ROUTE and _does(spec, case.kind) for case in cases)
    tokens = L.ANTHROPIC_TOKENS if spec.engine == "anthropic" else L.OPENAI_TOKENS
    most = max([tokens[kind] for kind in {case.kind for case in cases} if _does(spec, kind)] or [0])
    label = f"{spec.engine} {spec.model}"
    if price is not None:
        given = "your config's [light] price" if spec.light is not None else "--price"
        how = f"priced at {given} (${price.input:g} / ${price.output:g} per million tokens)"
    elif spec.engine == "anthropic" and _list_price(spec.model) is not None:
        listed = _list_price(spec.model)
        how = (f"priced at Anthropic's list price for {spec.model} as flightdeck knows it "
               f"(${listed.input:g} / ${listed.output:g} per million tokens; --price overrides)")
    elif spec.engine == "anthropic":
        how = "its cost unknown: give --price to see it"
    else:
        how = "priced as the API reports, else unknown (--price sets one)"
    where = "" if spec.engine == "anthropic" else f" at {_shown(spec.base_url)}"
    per = "one per job, three for a route case" if routed else "one per case"
    return (f"{label}{where} is a paid API: at most {_calls(calls, repeat)}, {per} (no retries), each with at most "
            f"{most} output tokens; {how}")


def _decider_notice(spec: Spec, cases: list[localmodel.Case], threshold: float, repeat: int = 1) -> str:
    """What a decider column will do, said before any call; "" for another engine."""
    if spec.engine != "decider":
        return ""
    calls = localmodel.count_jobs(cases, lambda kind: _does(spec, kind))
    asked = [kind for kind in localmodel.KINDS if kind != L.ROUTE and _does(spec, kind) and any(c.kind == kind for c in cases)]
    per = f"one per {_and(asked)} case" if asked else ""
    if any(case.kind == L.ROUTE and _does(spec, case.kind) for case in cases):
        per += (", " if per else "") + "three per route case"
    skipped = {kind: sum(1 for case in cases if case.kind == kind) for kind in (L.SUMMARY, L.RECON)
               if not _does(spec, kind) and any(case.kind == kind for case in cases)}
    where = urlsplit(spec.base_url).hostname
    elsewhere = "" if L.on_this_machine(spec.base_url) else f"; its requests (descriptions, lane steps) go to {where}"
    na = ""
    if skipped:
        many = sum(skipped.values()) != 1
        listed = _and([f"{n} {kind}" for kind, n in skipped.items()])
        na = f"; its {listed} case{'s are' if many else ' is'} n/a: a decision model writes no text"
    return (f"decider at {_shown(spec.base_url)}: at most {_calls(calls, repeat)} to the decision model server, {per} "
            f"(no retries){na}; an answer below confidence {threshold:g} counts as unsure{elsewhere}")


def _engine(spec: Spec, key: str | None, price: L.Price | None, timeout: float | None,
            threshold: float | None = None, thinks: bool = True) -> L.Light:
    """The engine of a column: from the options, or from the config as a run builds it (with
    --timeout, --threshold and --thinking over the config's when given), asked only its jobs."""
    if spec.light is not None:
        return _Only(_config_engine(spec, key, timeout, threshold, thinks), spec.jobs or ())
    timeout = DEFAULT_TIMEOUT if timeout is None else timeout
    threshold = L.DECIDER_THRESHOLD if threshold is None else threshold
    if spec.engine == "cactus":
        return L.CactusLight(timeout)
    if spec.engine == "decider":
        try:
            return L.DeciderLight(spec.base_url, spec.model, timeout=timeout, threshold=threshold)
        except ValueError:  # _check_decider_url checks the same; never quote the URL: it may carry a credential
            raise localmodel.LocalModelError(f"--base-url cannot be used as a decider server's address, e.g. "
                                             f"{L.DECIDER_URL}") from None
    if spec.engine == "openai":
        from .agent.client import ModelClient

        try:
            client = ModelClient(spec.base_url, key, timeout=timeout, max_retries=0,
                                 extra_body=None if thinks else L.THINKING_OFF)
        except ValueError:  # _check_url checks the same; the client's words may quote parts of the URL
            raise localmodel.LocalModelError(f"--base-url cannot be used as a model endpoint, e.g. {EXAMPLE_URL}") from None
        light = L.ModelLight("openai", client, spec.model, price=price, timeout=timeout, tokens=L.OPENAI_TOKENS,
                             temperature=0.0, free=L.on_this_machine(spec.base_url))
        light.label = f"{light.label} (thinking {'on' if thinks else 'off'})"  # the column says how it was asked
        return light
    from .agent.anthropic_client import AnthropicClient

    try:
        client = AnthropicClient(spec.base_url, key, timeout=timeout, max_retries=0, effort="low", server_fallback=False)
    except ValueError as exc:  # a key no header can carry: never shown
        raise localmodel.LocalModelError(f"the Anthropic API cannot be used: {exc}") from None
    return L.ModelLight("anthropic", client, spec.model, price=price or _list_price(spec.model), timeout=timeout,
                        tokens=L.ANTHROPIC_TOKENS)


def _config_engine(spec: Spec, key: str | None, timeout: float | None, threshold: float | None,
                   thinks: bool) -> L.Light:
    """A column from the config, built as a run builds it (light.build), with the options
    that measure it another way applied; Claude with no [light] price is priced at its list
    price, as every Claude column here is."""
    from .config import light_thinking

    light = spec.light
    assert light is not None
    if timeout is not None:
        light = replace(light, timeout=timeout)
    if threshold is not None and light.engine == "decider":
        light = replace(light, threshold=threshold)
    if light.engine == "openai":
        light = replace(light, thinking=thinks)
    engine = L.build(light, key)
    if isinstance(engine, L.ModelLight):
        if light.engine == "openai":
            engine.label = f"{engine.label} (thinking {'on' if light_thinking(light) else 'off'})"
        elif engine.price is None:
            engine.price = _list_price(light.model)
    return engine


async def _run(columns: list[Spec], keys: dict, cases: list[localmodel.Case], price: L.Price | None, main: Spec | None,
               timeout: float | None, threshold: float | None = None,
               thinks: dict[Spec, bool] | None = None, repeat: int = 1) -> list[tuple[localmodel.EvalReport, ...]]:
    """Each column's runs (`repeat` of them, one after another on the one engine), in column order."""
    reports = []
    for spec in columns:
        try:
            engine = _engine(spec, keys[spec], price if spec == main else None, timeout, threshold,
                             (thinks or {}).get(spec, True))
        except (L.LightError, localmodel.LocalModelError) as exc:
            _fail(str(exc))
        try:
            reports.append(await localmodel.evaluate_runs(engine, cases, repeat))
        except localmodel.EngineFailed as exc:
            _fail(_failed(spec, str(exc)))
        except localmodel.LocalModelError as exc:
            _fail(str(exc))
        finally:
            await engine.aclose()
    return reports


def _failed(spec: Spec, why: str) -> str:
    if spec.engine == "openai":
        return f"the local model at {_shown(spec.base_url)} failed: {_redact(why, spec.base_url)}"
    if spec.engine == "anthropic":
        return f"the Anthropic API failed for {spec.model}: {why}"
    if spec.engine == "decider":
        return f"the decision model at {_shown(spec.base_url)} failed: {_redact(why, spec.base_url)}"
    return f"Cactus Needle failed: {why}"


def _unmeasured(report: localmodel.EvalReport, thinks: bool | None = None) -> str:
    """Why this engine's score does not measure it (most of its jobs held no answer), or "".
    `thinks`: an openai column's thinking setting (None for another engine)."""
    if not report.total or 2 * report.unanswered <= report.total:
        return ""
    refused = report.count(L.REFUSED)
    failed = report.count(L.ERROR, L.TIMEOUT)
    blank = report.count(L.NO_ANSWER, L.OUTSIDE)
    of = f"of {report.total}"
    if refused >= max(failed, blank):
        return (f"{report.label} declined {refused} {of} jobs, so this score does not measure what it knows. A "
                "provider's safety classifier can decline security work; an open-weight model on your own machine has "
                "no such classifier in front of it. In a run, each refusal leaves the rules' answer.")
    if failed >= blank:
        return (f"{report.label} failed or timed out on {failed} {of} jobs, so this score does not measure the "
                "model: check the server, or give it a longer --timeout.")
    text = (f"{report.label}: {blank} {of} replies were cut off at the token cap, empty, or not exactly one of the "
            "options, so this score does not measure the model. Check that it answers with the option alone: a "
            "model that reasons at length before it answers needs that switched off for this evaluation")
    if thinks is True:
        return text + " (--thinking off asks for it)."
    if thinks is False:
        return text + (" (it was asked to: check that its server reads reasoning_effort, as Ollama does, or "
                       "chat_template_kwargs, as mlx_lm.server does)."
                       )
    return text + "."


# ---------------------------------------------------------------------- URLs and the secrets they may carry


def _check_url(base_url: str, *, option: str = "--base-url") -> None:
    problem = _url_problem(base_url, option)
    if problem:
        _fail(problem)


def _check_decider_url(base_url: str, *, option: str = "--base-url") -> None:
    _check_url(base_url, option=option)
    problem = L.decider_url_problem(base_url)
    if problem:
        _fail(f"{option} {problem}")


def _url_problem(base_url: str, option: str = "--base-url") -> str:
    """Why the URL cannot be used, or "". Never quotes the URL: it may hold credentials."""
    if not base_url.startswith(("http://", "https://")):
        return f"{option} must start with http:// or https://, e.g. {EXAMPLE_URL}"
    try:
        url = httpx.URL(base_url)
    except httpx.InvalidURL:
        return f"{option} is not a valid URL (check its host and port), e.g. {EXAMPLE_URL}"
    if not url.host:
        return f"{option} names no host, e.g. {EXAMPLE_URL}"
    return ""


def _shown(base_url: str) -> str:
    """The endpoint as it may be shown: no user name, password, query or fragment."""
    return str(httpx.URL(base_url).copy_with(userinfo=b"", query=None, fragment=None))


def _redact(text: str, base_url: str) -> str:
    """`text` with every credential --base-url may carry cut out (a server may echo one back):
    the user name and password, raw and decoded, and every query value."""
    url = httpx.URL(base_url)
    user, _, password = url.userinfo.decode("ascii", "replace").partition(":")
    secrets = {url.username, url.password, user, password}
    secrets.update(part.partition("=")[2] for part in url.query.decode("ascii", "replace").split("&"))
    secrets.update(value for _, value in url.params.multi_items())
    for secret in sorted((s for s in secrets if len(s) >= MIN_SECRET), key=len, reverse=True):
        text = text.replace(secret, "[redacted]")
    return text
