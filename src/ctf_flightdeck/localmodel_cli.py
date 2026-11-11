"""`flightdeck eval-local`: measure a local model against the rules baseline.

The integrator mounts this module's `app` onto the root CLI (`app.add_typer(localmodel_cli.app)`),
so `flightdeck eval-local` runs it. It is its own module and never edits cli.py.

It talks to an OpenAI-compatible local server (Ollama, llama.cpp, MLX) with no API key, runs
the bundled synthetic case set through the model and through the rules baseline, and prints
accuracy for each side by side. The baseline runs first: it needs no network, so a missing
lexicon or a case it cannot score stops the command before a single model call. Cactus ships
no OpenAI-compatible server (D15), so there is no adapter for it here: `--engine cactus`
says so and stops.

--base-url may carry credentials (a user name and password, or a token in the query string,
for a server behind a proxy). They are sent, never shown: messages name the endpoint
without them, and they are cut out of any text the server sends back.

Exit codes: 0 with the scorecard; 2 when the evaluation cannot run (options, cases, the
lexicon, the server); 1 after the scorecard when most replies held no answer, since that
score does not measure the model.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, NoReturn

import httpx
import typer

from . import localmodel

app = typer.Typer(no_args_is_help=True, help="Evaluate an optional local model on small jobs (D15).")

EXAMPLE_URL = "http://127.0.0.1:11434/v1"
MIN_SECRET = 4  # shorter parts of --base-url are not cut out of server text: that would garble it


@app.command("eval-local")
def eval_local(
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help=f"The local server's OpenAI-compatible base URL, e.g. {EXAMPLE_URL}."),
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model id to evaluate.")] = None,
    cases: Annotated[
        Path | None,
        typer.Option("--cases", exists=True, dir_okay=False, help="Case file (default: the set bundled with flightdeck)."),
    ] = None,
    engine: Annotated[
        str, typer.Option("--engine", help="openai (OpenAI-compatible local server) or cactus (not supported).")
    ] = "openai",
) -> None:
    """Score a local model and the rules baseline on triage hints and lane summaries."""
    if engine == "cactus":
        _fail(
            "Cactus is not supported by eval-local: it ships no OpenAI-compatible server (D15), so "
            "there is no endpoint to evaluate. Use Ollama, llama.cpp or MLX (--engine openai) instead."
        )
    if engine != "openai":
        _fail(f"unknown engine {engine!r}; use openai or cactus")
    if not base_url or not model:
        _fail("eval-local needs --base-url and --model for an OpenAI-compatible server")
    problem = _url_problem(base_url)
    if problem:
        _fail(problem)

    try:
        loaded = localmodel.load_cases(cases or localmodel.default_cases_path())
    except (localmodel.CaseError, FileNotFoundError) as exc:
        _fail(str(exc))

    # The baseline is cheap and needs no network, so compute it first: if the lexicon is
    # missing, or a case expects an id it does not have, we stop before any model call.
    try:
        rules = localmodel.rules_baseline(loaded)
    except localmodel.LocalModelError as exc:
        _fail(str(exc))

    try:
        report = asyncio.run(_run(base_url, model, loaded))
    except localmodel.LocalModelError as exc:
        _fail(_redact(str(exc), base_url))

    typer.echo(localmodel.format_comparison(report, rules))
    if 2 * report.unanswered > len(report.results):
        typer.echo(
            f"flightdeck: {report.unanswered} of {len(report.results)} replies were cut off at the token "
            "cap or empty, so this score does not measure the model. Check that it answers directly: a "
            "model that reasons before it answers needs that switched off for this evaluation.",
            err=True,
        )
        raise typer.Exit(1)


def _fail(message: str) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(2) from None


async def _run(base_url: str, model: str, cases: list[localmodel.Case]) -> localmodel.EvalReport:
    from .agent.client import ModelClient, ModelError

    try:
        client = ModelClient(base_url, None)
    except ValueError:  # _url_problem checks the same; the client's words may quote parts of the URL
        raise localmodel.LocalModelError(f"--base-url cannot be used as a model endpoint, e.g. {EXAMPLE_URL}") from None
    async with client:
        try:
            return await localmodel.evaluate(client, model, cases)
        except ModelError as exc:
            raise localmodel.LocalModelError(f"the local model at {_shown(base_url)} failed: {exc}") from None


def _url_problem(base_url: str) -> str:
    """Why --base-url cannot be used, or "". Never quotes the URL: it may hold credentials."""
    if not base_url.startswith(("http://", "https://")):
        return f"--base-url must start with http:// or https://, e.g. {EXAMPLE_URL}"
    try:
        url = httpx.URL(base_url)
    except httpx.InvalidURL:
        return f"--base-url is not a valid URL (check its host and port), e.g. {EXAMPLE_URL}"
    if not url.host:
        return f"--base-url names no host, e.g. {EXAMPLE_URL}"
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
