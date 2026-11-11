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
    ] = 1.0,
) -> None:
    """Open the console on fake, scripted data (M0 mock). No models, no network."""
    containerized = None if host is None else not host
    if screenshot is not None:
        from .mock.screenshots import capture

        screenshot = screenshot.expanduser()  # the shell leaves ~ alone in --screenshot=~/x

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


class Submit(StrEnum):
    confirm = "confirm"
    auto = "auto"


@app.command()
def play(
    board: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, dir_okay=True, help="A folder of challenge folders (each with a challenge.json)."),
    ],
    answers: Annotated[
        Path | None,
        typer.Option("--answers", exists=True, dir_okay=False, help="sha256 answers file (default: answers.sha256.json in the board, if any)."),
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", dir_okay=False, help="Config file (default: $FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml).")
    ] = None,
    max_lanes: Annotated[int | None, typer.Option("--max-lanes", min=1, help="Concurrent lanes (default: the config's).")] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", help="Run lanes on this machine, or in Docker (default: the config's runtime).")
    ] = None,
    team: Annotated[bool, typer.Option("--team/--solo", help="Team or solo mode.")] = False,
    submit: Annotated[
        Submit | None, typer.Option("--submit", help="confirm: you approve each flag; auto: submit at once (default: the config's).")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model lanes start on (default: the weakest in the ladder).")] = None,
    run_dir: Annotated[Path | None, typer.Option("--run-dir", file_okay=False, help="Where run folders go (default: the config's).")] = None,
) -> None:
    """Play a board with agent lanes (M1). Spends tokens on the API in your config."""
    from .run import RunError, RunOptions, host_warning, prepare_run

    options = RunOptions(
        board=board.expanduser(),
        answers=answers.expanduser() if answers else None,
        config=config.expanduser() if config else None,
        max_lanes=max_lanes,
        runtime=None if host is None else ("host" if host else "docker"),
        team=team,
        submit=submit.value if submit else None,
        model=model,
        run_dir=run_dir.expanduser() if run_dir else None,
    )
    try:
        run = prepare_run(options)
    except RunError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    if run.runtime == "host":
        typer.echo(f"flightdeck: {host_warning()}", err=True)
    for note in run.notes():
        typer.echo(f"flightdeck: {note}", err=True)
    try:
        run.app().run()
    finally:
        run.close()
        typer.echo(f"run log: {run.log.path}")
        for problem in run.driver.errors:
            typer.echo(f"flightdeck: {problem}", err=True)


@app.command()
def practice(
    config: Annotated[
        Path | None, typer.Option("--config", dir_okay=False, help="Config file (default: $FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml).")
    ] = None,
    max_lanes: Annotated[int | None, typer.Option("--max-lanes", min=1, help="Concurrent lanes (default: the config's).")] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", help="Run lanes on this machine, or in Docker (default: the config's runtime).")
    ] = None,
    model: Annotated[str | None, typer.Option("--model", help="The model lanes start on (default: the weakest in the ladder).")] = None,
    run_dir: Annotated[Path | None, typer.Option("--run-dir", file_okay=False, help="Where run folders go (default: the config's).")] = None,
) -> None:
    """Play the practice set that ships with flightdeck (14 small synthetic challenges, answers
    checked by hash). Spends tokens like `play`."""
    from .practice_set import practice_dir

    try:
        board = practice_dir()
    except FileNotFoundError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    play(
        board=board, answers=None, config=config, max_lanes=max_lanes, host=host,
        team=False, submit=None, model=model, run_dir=run_dir,
    )


image_app = typer.Typer(no_args_is_help=True, help="The lane image: what a lane's shell has inside its container.")
app.add_typer(image_app, name="image")


@image_app.command("build")
def image_build(
    tag: Annotated[str, typer.Option("--tag", help="Image name and tag.")] = "",
) -> None:
    """Build the lane image with Docker (pulls the Debian base image and packages)."""
    import subprocess

    from .agent.workspace import docker_unavailable
    from .lane import IMAGE, build_command, context_dir

    reason = docker_unavailable()
    if reason:
        typer.echo(f"flightdeck: building the lane image needs Docker: {reason}", err=True)
        raise typer.Exit(2)
    argv = build_command(tag or IMAGE)
    typer.echo(f"flightdeck: {' '.join(argv)}", err=True)
    result = subprocess.run(argv, cwd=context_dir())
    if result.returncode != 0:
        typer.echo(f"flightdeck: docker build failed (exit {result.returncode})", err=True)
        raise typer.Exit(result.returncode)
    typer.echo(f"built {tag or IMAGE}")


@image_app.command("dockerfile")
def image_dockerfile() -> None:
    """Print the lane image's Dockerfile."""
    from .lane import dockerfile

    typer.echo(dockerfile(), nl=False)


@app.command("config")
def config_command(
    example: Annotated[bool, typer.Option("--example", help="Print a commented example config and exit.")] = False,
    path: Annotated[Path | None, typer.Option("--path", dir_okay=False, help="The config file to check.")] = None,
) -> None:
    """Check your config (or print an example). Never prints the API key."""
    from .config import ConfigError, default_config_path, example_config, load_config
    from .run import environment_has_key

    if example:
        typer.echo(example_config(), nl=False)
        return
    target = (path or default_config_path()).expanduser()
    try:
        loaded = load_config(target)
    except ConfigError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    lanes = loaded.lanes
    key = loaded.api.key_env
    typer.echo(f"config: {target}")
    typer.echo(f"api: {loaded.api.base_url}")
    typer.echo(f"key: {key or '(none needed)'}" + (f" is {'set' if environment_has_key(loaded) else 'NOT set'}" if key else ""))
    typer.echo(f"models (weakest first): {', '.join(loaded.models)}")
    priced = [m for m in loaded.models if m in loaded.prices]
    typer.echo(f"prices from config: {', '.join(priced) or 'none (the API reports cost, or it shows as unknown)'}")
    typer.echo(f"lanes: {lanes.max_lanes} at a time, runtime {lanes.runtime}" + (f" ({lanes.image})" if lanes.runtime == "docker" else ""))
    typer.echo(f"caps per lane: {lanes.token_cap or 'no'} tokens, ${lanes.dollar_cap if lanes.dollar_cap else 'no cap'}; submit {lanes.submit}")
    typer.echo(f"runs go to: {loaded.run_dir}")


def main() -> None:
    app()
