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
- `--engine rules`: the rules alone.
- `--compare SPEC`, as often as you like: another column, `rules`, `cactus`,
  `anthropic:MODEL` or `openai:MODEL@BASE_URL` (a server with no key).

Before any call the cases are checked and the rules scored (no network): a missing lexicon, or
a case that names an id it lacks, stops the command before anything is spent. A paid API
(Claude, or an OpenAI-compatible server not on this machine) is said first: how many calls it
makes (one per case it does, never a retry, so never more than the case set) and how they are
priced (`--price`, else for Claude its list price as flightdeck knows it, else unknown).

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
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, NoReturn

import httpx
import typer

from . import light as L
from . import localmodel

app = typer.Typer(no_args_is_help=True, help="Measure a light model against the rules on small jobs (D15).")

EXAMPLE_URL = "http://127.0.0.1:11434/v1"
MIN_SECRET = 4  # shorter parts of --base-url are not cut out of server text: that would garble it
ANTHROPIC_KEY_ENV = "ANTHROPIC_API_KEY"
_ENV_NAME = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")


@dataclass(frozen=True)
class Spec:
    """One engine to evaluate, as the options give it."""

    engine: str
    model: str = ""
    base_url: str = ""
    key_env: str = ""


@app.command("eval-local")
def eval_local(
    engine: Annotated[
        str, typer.Option("--engine", help="openai (an OpenAI-compatible server; recommended: an open-weight model on "
                                            "this machine), anthropic, cactus or rules.")
    ] = "openai",
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help=f"The OpenAI-compatible base URL, e.g. {EXAMPLE_URL} (Ollama) or "
                                        "http://127.0.0.1:8080/v1 (an MLX server); for anthropic, another API URL."),
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model id to evaluate.")] = None,
    key_env: Annotated[
        str | None, typer.Option("--key-env", help="The variable holding the key (anthropic: ANTHROPIC_API_KEY by "
                                                   "default; openai: none unless given). Never the key itself.")
    ] = None,
    price: Annotated[
        str | None, typer.Option("--price", metavar="IN,OUT[,CACHED]",
                                 help="Dollars per million tokens, for an API that reports no cost.")
    ] = None,
    timeout: Annotated[float, typer.Option("--timeout", help="Seconds one job may take.")] = 30.0,
    compare: Annotated[
        list[str] | None,
        typer.Option("--compare", metavar="SPEC",
                     help="Another engine to score beside it: rules, cactus, anthropic:MODEL or openai:MODEL@BASE_URL."),
    ] = None,
    cases: Annotated[
        Path | None,
        typer.Option("--cases", exists=True, dir_okay=False, help="Case file (default: the set bundled with flightdeck)."),
    ] = None,
) -> None:
    """Score light models and the rules side by side on hints, hint judging and lane summaries."""
    if not math.isfinite(timeout) or timeout <= 0:
        _fail("--timeout must be a positive number of seconds")
    specs = [_main_spec(engine, base_url, model, key_env)] + [_compare_spec(text) for text in compare or ()]
    priced = _price(price) if price is not None else None

    try:
        loaded = localmodel.load_cases(cases or localmodel.default_cases_path())
    except (localmodel.CaseError, FileNotFoundError) as exc:
        _fail(str(exc))

    # The baseline is cheap and needs no network, so compute it first: if the lexicon is
    # missing, or a case names an id it does not have, we stop before any model call.
    try:
        rules = localmodel.rules_baseline(loaded)
    except localmodel.LocalModelError as exc:
        _fail(str(exc))

    columns: list[Spec] = []
    for spec in specs:
        if spec.engine != "rules" and spec not in columns:
            columns.append(spec)
    keys = {spec: _key(spec) for spec in columns}
    for spec in columns:
        notice = _spend_notice(spec, loaded, priced if spec == specs[0] else None)
        if notice:
            typer.echo(f"flightdeck: {notice}", err=True)

    reports = asyncio.run(_run(columns, keys, loaded, priced if specs[0] in columns else None, specs[0], timeout))
    reports = [rules, *reports]
    typer.echo(localmodel.format_scorecard(reports), nl=False)
    worst = [message for report in reports[1:] if (message := _unmeasured(report))]
    for message in worst:
        typer.echo(f"flightdeck: {message}", err=True)
    if worst:
        raise typer.Exit(1)


def _fail(message: str) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(2) from None


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
    _fail(f"unknown engine {engine!r}; use openai, anthropic, cactus or rules")


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
    _fail("--compare takes rules, cactus, anthropic:MODEL or openai:MODEL@BASE_URL "
          f"(e.g. openai:some-model@{EXAMPLE_URL})")


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


def _spend_notice(spec: Spec, cases: list[localmodel.Case], price: L.Price | None) -> str:
    """What a paid engine is about to spend, said before any call; "" for a free one."""
    if not _paid(spec):
        return ""
    calls = sum(1 for case in cases if case.kind in L.JOBS)
    tokens = L.ANTHROPIC_TOKENS if spec.engine == "anthropic" else L.OPENAI_TOKENS
    label = f"{spec.engine} {spec.model}"
    if price is not None:
        how = f"priced at --price (${price.input:g} / ${price.output:g} per million tokens)"
    elif spec.engine == "anthropic" and _list_price(spec.model) is not None:
        listed = _list_price(spec.model)
        how = (f"priced at Anthropic's list price for {spec.model} as flightdeck knows it "
               f"(${listed.input:g} / ${listed.output:g} per million tokens; --price overrides)")
    elif spec.engine == "anthropic":
        how = "its cost unknown: give --price to see it"
    else:
        how = "priced as the API reports, else unknown (--price sets one)"
    where = "" if spec.engine == "anthropic" else f" at {_shown(spec.base_url)}"
    return (f"{label}{where} is a paid API: at most {calls} calls, one per case (no retries), each with at most "
            f"{max(tokens.values())} output tokens; {how}")


def _engine(spec: Spec, key: str | None, price: L.Price | None, timeout: float) -> L.Light:
    if spec.engine == "cactus":
        return L.CactusLight(timeout)
    if spec.engine == "openai":
        from .agent.client import ModelClient

        try:
            client = ModelClient(spec.base_url, key, timeout=timeout, max_retries=0)
        except ValueError:  # _check_url checks the same; the client's words may quote parts of the URL
            raise localmodel.LocalModelError(f"--base-url cannot be used as a model endpoint, e.g. {EXAMPLE_URL}") from None
        return L.ModelLight("openai", client, spec.model, price=price, timeout=timeout, tokens=L.OPENAI_TOKENS,
                            temperature=0.0, free=L.on_this_machine(spec.base_url))
    from .agent.anthropic_client import AnthropicClient

    try:
        client = AnthropicClient(spec.base_url, key, timeout=timeout, max_retries=0, effort="low", server_fallback=False)
    except ValueError as exc:  # a key no header can carry: never shown
        raise localmodel.LocalModelError(f"the Anthropic API cannot be used: {exc}") from None
    return L.ModelLight("anthropic", client, spec.model, price=price or _list_price(spec.model), timeout=timeout,
                        tokens=L.ANTHROPIC_TOKENS)


async def _run(columns: list[Spec], keys: dict, cases: list[localmodel.Case], price: L.Price | None, main: Spec,
               timeout: float) -> list[localmodel.EvalReport]:
    reports = []
    for spec in columns:
        try:
            engine = _engine(spec, keys[spec], price if spec == main else None, timeout)
        except (L.LightError, localmodel.LocalModelError) as exc:
            _fail(str(exc))
        try:
            reports.append(await localmodel.evaluate_engine(engine, cases))
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
    return f"Cactus Needle failed: {why}"


def _unmeasured(report: localmodel.EvalReport) -> str:
    """Why this engine's score does not measure it (most of its jobs held no answer), or ""."""
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
    return (f"{report.label}: {blank} {of} replies were cut off at the token cap, empty, or not exactly one of the "
            "options, so this score does not measure the model. Check that it answers with the option alone: a "
            "model that reasons at length before it answers needs that switched off for this evaluation.")


# ---------------------------------------------------------------------- URLs and the secrets they may carry


def _check_url(base_url: str, *, option: str = "--base-url") -> None:
    problem = _url_problem(base_url, option)
    if problem:
        _fail(problem)


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
