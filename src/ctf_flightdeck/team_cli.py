"""`flightdeck team`: set up and look at the shared folder of team mode (team.py)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(
    no_args_is_help=True,
    help="Team mode: the shared folder teammates' flightdecks use for claims, live-box holds and solves.",
)

FolderArg = Annotated[
    Path, typer.Argument(metavar="FOLDER", help="The shared folder: on a network drive, a Syncthing folder or a shared mount.")
]


@app.command("init")
def init(folder: FolderArg) -> None:
    """Make FOLDER a team folder. One teammate does this once; the others' flightdecks
    find it once it has synced."""
    from .team import TeamError, init_folder, printable

    try:
        path = init_folder(folder)
    except TeamError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    typer.echo(f"team folder: {printable(path)}")


@app.command("status")
def status(
    folder: FolderArg,
    stale_hours: Annotated[
        float, typer.Option("--stale-hours", min=0.01, help="A claim or box hold older than this counts as released.")
    ] = 6.0,
) -> None:
    """Show the claims, live-box holds and solves in FOLDER, and every file flightdeck
    ignores there (and why). Reads only."""
    import time

    from .team import TeamError, printable, read_state

    try:
        state = read_state(folder, stale_after=stale_hours * 3600)
    except TeamError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        raise typer.Exit(2) from None
    now = time.time()
    for title, marks in (("claims", state.claims), ("live boxes", state.boxes), ("solves", state.solves)):
        typer.echo(f"{title}: {len(marks) or 'none'}")
        for cid, mark in marks.items():
            note = f"  {printable(mark.note)}" if mark.note else ""
            typer.echo(f"  {cid}  {mark.who}  {_age(now - mark.at)}{note}")
    for problem in state.problems:
        typer.echo(f"ignored: {problem}")


def _age(seconds: float) -> str:
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds / 60:.0f} min ago"
    if seconds < 48 * 3600:
        return f"{seconds / 3600:.1f} h ago"
    return f"{seconds / 86400:.0f} days ago"
