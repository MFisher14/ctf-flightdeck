"""`flightdeck preflight EVENT.toml`: check an event profile and show what a run would do.

The command line mounts `app` with one line:

    app.add_typer(preflight_cli.app, name="preflight")

It is a single command (a callback with no subcommands), so it reads `flightdeck preflight
EVENT.toml`. It prints the event, its rules, the policy of every stage and the problems check()
finds. Exit status: 0 when nothing refuses (warnings are printed), 2 when something refuses or
the profile cannot be read. It never prints a token or a key, only whether its variable is set.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Annotated

import typer

if TYPE_CHECKING:
    from .config import Config, ConfigError

app = typer.Typer(
    name="preflight",
    add_completion=False,
    rich_markup_mode="markdown",
    subcommand_metavar="",  # a single command: no COMMAND in the usage line
    context_settings={"allow_interspersed_args": True},  # options may follow EVENT.toml
)


@app.callback(invoke_without_command=True)
def preflight(
    event: Annotated[
        Path | None,
        typer.Argument(
            metavar="EVENT.toml", show_default=False,
            help="The event profile: what the event's rules allow (print one with --example).",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", dir_okay=False, help="Config file (default: $FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml)."),
    ] = None,
    max_lanes: Annotated[
        int | None, typer.Option("--max-lanes", min=1, help="Lanes at once, checked against the rules (default: the config's).")
    ] = None,
    host: Annotated[
        bool | None, typer.Option("--host/--docker", help="Check for lanes on this machine, or in Docker (default: the config's runtime).")
    ] = None,
    example: Annotated[bool, typer.Option("--example", help="Print a commented example event profile and exit.")] = False,
) -> None:
    """Check an event profile against the event's rules and show the policy a run would use at
    each stage (pull, l1, agents, submit, instance: auto, confirm, manual or off). Exits 2 if
    anything refuses. Never prints a token or a key, only whether its variable is set."""
    from .config import Config
    from .preflight import Policy, ProfileError, check, describe, example_profile, load_profile
    from .text import untrusted

    if example:
        typer.echo(example_profile(), nl=False)
        return
    if event is None:
        raise typer.BadParameter("name the event profile to check, or use --example to print one", param_hint="EVENT.toml")
    try:
        profile, policies = load_profile(event)  # it expands ~ itself, and says so when it cannot
    except ProfileError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    loaded = _load_config(config)
    found = loaded if isinstance(loaded, Config) else None
    runtime = ("host" if host else "docker") if host is not None else (found.lanes.runtime if found else None)
    lanes = max_lanes or (found.lanes.max_lanes if found else None)
    from .keys import KeysError, environment

    try:
        environ = environment()
    except KeysError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    problems = check(profile, policies, max_lanes=lanes, model_config=loaded, runtime=runtime, environ=environ)

    typer.echo(f"profile   {untrusted(str(profile.source), one_line=True)}")
    for line in describe(profile, policies, config=loaded):
        typer.echo(line)
    if policies.agents is Policy.OFF:
        typer.echo("lanes     none (agents off)")
    else:
        parts = [f"{lanes} at a time" if lanes is not None else "how many at a time is not known (no config, no --max-lanes)"]
        if runtime is not None:
            parts.append(f"runtime {runtime}")
        if found is not None:
            parts.append(f"config {untrusted(str(found.source), one_line=True)}")
        typer.echo("lanes     " + " · ".join(parts))
    for problem in problems:
        typer.echo(f"{'refuse' if problem.refuse else 'warn'}: {problem.message}")
    refusals = sum(1 for problem in problems if problem.refuse)
    warnings = len(problems) - refusals
    if refusals:
        counts = _count(refusals, "refusal") + (f", {_count(warnings, 'warning')}" if warnings else "")
        typer.echo(f"preflight: refused ({counts}): a run with this profile must not start")
        raise typer.Exit(2)
    typer.echo("preflight: ok" + (f" ({_count(warnings, 'warning')})" if warnings else ""))


def _load_config(config: Path | None) -> Config | ConfigError:
    """The player's config, or the ConfigError that says why there is none (check() shows it).

    The path is found here, not in load_config, because expanding a ~user that does not exist
    (in --config or $FLIGHTDECK_CONFIG) raises RuntimeError, which load_config passes on.
    """
    from .config import CONFIG_ENV, ConfigError, default_config_path, load_config
    from .text import untrusted

    try:
        path = config.expanduser() if config is not None else default_config_path()
    except (RuntimeError, ConfigError):  # ~user for a user that does not exist, or no home directory at all
        if config is not None:
            return ConfigError(f"{untrusted(str(config), one_line=True)}: starts with ~ for a home directory that cannot be found")
        return ConfigError(
            f"the config file (${CONFIG_ENV}, else ~/.config/ctf-flightdeck/config.toml) is under a home "
            "directory that cannot be found"
        )
    try:
        return load_config(path)
    except ConfigError as exc:
        return exc


def _count(n: int, what: str) -> str:
    return f"{n} {what}{'' if n == 1 else 's'}"
