"""`flightdeck report RUN_DIR [--board PATH]`: the post-flight report for a run folder.

The integrator mounts this app on the main one with `app.add_typer(postflight_cli.app)`
(no name), which adds the `report` command as it is.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

REPORT = "report.md"

app = typer.Typer(add_completion=False, help="Post-flight: what happened in a run.")


@app.command("report")
def report_command(
    run_dir: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, dir_okay=True, help="A run folder (it holds events.jsonl)."),
    ],
    board: Annotated[
        Path | None,
        typer.Option(
            "--board", exists=True, file_okay=False, dir_okay=True,
            help="The board folder the run played: the event's name, and names and points the run log lacks.",
        ),
    ] = None,
) -> None:
    """Write the post-flight report to RUN_DIR/report.md and print a short summary."""
    from .platform.manual import BoardError, load_board
    from .postflight import report, summary
    from .runrecord import RunFolderError, load_run
    from .text import untrusted

    run_dir = run_dir.expanduser()
    try:
        record = load_run(run_dir)
    except RunFolderError as exc:
        typer.echo(f"flightdeck: {untrusted(str(exc), one_line=True)}", err=True)
        raise typer.Exit(2) from None
    loaded = None
    if board is not None:
        try:
            loaded = load_board(board.expanduser())
        except BoardError as exc:
            typer.echo(f"flightdeck: --board: {exc}", err=True)  # BoardError messages are already made safe
            raise typer.Exit(2) from None
    try:
        written = write_report(run_dir, report(record, board=loaded))
    except OSError as exc:
        where = untrusted(str(run_dir / REPORT), one_line=True)
        typer.echo(f"flightdeck: cannot write {where}: {exc.strerror or exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(summary(record, board=loaded), nl=False)
    typer.echo(f"report: {untrusted(str(written), one_line=True)}")


def write_report(run_dir: Path, text: str) -> Path:
    """Write RUN_DIR/report.md whole or not at all: a new temporary file in the run folder
    (created exclusively, so never through a symlink; its mode follows the umask like the
    run's other files), then renamed over the old report. A symlink named report.md is
    replaced, never followed, so a run folder from elsewhere cannot make this write
    outside it."""
    target = run_dir / REPORT
    temp = run_dir / f".report.{os.urandom(6).hex()}.md.tmp"
    handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o666)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(text)
        os.replace(temp, target)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise
    return target
