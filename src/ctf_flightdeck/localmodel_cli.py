"""`flightdeck eval-local`: measure a local model against the rules baseline.

The integrator mounts this module's `app` onto the root CLI (`app.add_typer(localmodel_cli.app)`),
so `flightdeck eval-local` runs it. It is its own module and never edits cli.py.

It talks to an OpenAI-compatible local server (Ollama, llama.cpp, MLX) with no API key, runs
the bundled synthetic case set through the model and through the rules baseline, and prints
accuracy for each side by side. Cactus ships no OpenAI-compatible server (D15), so there is
no adapter for it here: `--engine cactus` says so and stops.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated

import typer

from . import localmodel

app = typer.Typer(no_args_is_help=True, help="Evaluate an optional local model on small jobs (D15).")


@app.command("eval-local")
def eval_local(
    base_url: Annotated[
        str | None,
        typer.Option("--base-url", help="The local server's OpenAI-compatible base URL, e.g. http://127.0.0.1:11434/v1."),
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
        typer.echo(
            "flightdeck: Cactus is not supported by eval-local: it ships no OpenAI-compatible "
            "server (D15), so there is no endpoint to evaluate. Use Ollama, llama.cpp or MLX "
            "(--engine openai) instead.",
            err=True,
        )
        raise typer.Exit(2)
    if engine != "openai":
        typer.echo(f"flightdeck: unknown engine {engine!r}; use openai or cactus", err=True)
        raise typer.Exit(2)
    if not base_url or not model:
        typer.echo("flightdeck: eval-local needs --base-url and --model for an OpenAI-compatible server", err=True)
        raise typer.Exit(2)

    try:
        case_path = cases or localmodel.default_cases_path()
        loaded = localmodel.load_cases(case_path)
    except (localmodel.CaseError, FileNotFoundError) as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None

    # The baseline is cheap and needs no network, so compute it first: if the lexicon is
    # missing we stop before spending a single model call.
    try:
        rules = localmodel.rules_baseline(loaded)
    except localmodel.LocalModelError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None

    try:
        model_report = asyncio.run(_run(base_url, model, loaded))
    except localmodel.LocalModelError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None

    typer.echo(localmodel.format_comparison(model_report, rules))


async def _run(base_url: str, model: str, cases: list[localmodel.Case]) -> localmodel.EvalReport:
    from .agent.client import ModelClient, ModelError

    try:
        async with ModelClient(base_url, None) as client:
            return await localmodel.evaluate(client, model, cases)
    except ModelError as exc:
        raise localmodel.LocalModelError(f"the local model at {base_url} could not be reached: {exc}") from None
