"""Command line: `flightdeck` (also installed as `ctfdeck`)."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from . import __version__
from .mock import scenarios

ScenarioName = StrEnum("ScenarioName", {name: name for name in scenarios.SCENARIOS})
SCENARIO_LIST = "Scenarios:\n\n" + "\n".join(
    f"- **{name}**: {build().summary}." for name, build in scenarios.SCENARIOS.items()
)

app = typer.Typer(
    name="flightdeck",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="markdown",
    help="A terminal harness for playing CTFs with AI agents, where you run the loop.",
)


def _version(ctx: typer.Context, value: bool) -> None:
    if value:
        typer.echo(f"{ctx.find_root().info_name} {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version and exit.")
    ] = False,
) -> None:
    """A terminal harness for playing CTFs with AI agents, where you run the loop."""


@app.command(epilog=SCENARIO_LIST)
def mock(
    scenario: Annotated[
        ScenarioName,
        typer.Option("--scenario", "-s", metavar="NAME", help="Scenario to play (listed below)."),
    ] = ScenarioName.default,
    max_lanes: Annotated[
        int | None, typer.Option("--max-lanes", min=1, help="Concurrent lanes (default: the scenario's, 16 for most).")
    ] = None,
    team: Annotated[
        bool | None, typer.Option("--team/--solo", help="Team or solo mode (default: the scenario's; default is team).")
    ] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", help="Show lanes running on the host instead of in Docker.")
    ] = None,
    screenshot: Annotated[
        Path | None,
        typer.Option(
            "--screenshot", metavar="DIR", file_okay=False, dir_okay=True,
            help="Run headless and save SVG screenshots of the key moments to DIR, then exit.",
        ),
    ] = None,
    speed: Annotated[
        float, typer.Option("--speed", min=0.25, max=20.0, help="Mock clock ticks per second (live console).")
    ] = 2.0,
) -> None:
    """Open the console on fake, scripted data (M0 mock). No models, no network."""
    containerized = None if host is None else not host
    if screenshot is not None:
        from .mock.screenshots import capture

        try:
            screenshot.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise typer.BadParameter(f"cannot create {screenshot}: {exc.strerror}", param_hint="--screenshot") from exc
        result = capture(scenario.value, screenshot, max_lanes=max_lanes, team=team, containerized=containerized)
        for path in result.saved:
            typer.echo(str(path))
        for note in result.skipped:
            typer.echo(f"skipped {note}", err=True)
        return

    from .console.app import FlightdeckApp
    from .mock.world import FakeWorld

    world = FakeWorld(scenarios.get(scenario.value), max_lanes=max_lanes, team=team, containerized=containerized)
    FlightdeckApp(world.deck, ticker=world.tick, tick_seconds=1.0 / speed, mock=f"MOCK · {scenario.value}").run()


def main() -> None:
    app()
