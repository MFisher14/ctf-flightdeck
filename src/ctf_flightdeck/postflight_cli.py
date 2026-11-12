"""`flightdeck report RUN_DIR [--board PATH]`: the post-flight report for a run folder.

RUN_DIR is the run folder or its events.jsonl (the path a run prints when it ends). The run
log names the event and every challenge it released (a format 2 log), so --board only fills
in what an older log lacks.

cli.py mounts `report_command` as `flightdeck report`; `app` holds it too, for a mount of
its own. A run folder or board that cannot be read fails with the reason (exit 2), never a
traceback.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated, NoReturn

import typer

REPORT = "report.md"

app = typer.Typer(add_completion=False, help="Post-flight: what happened in a run.")


@app.command("report")
def report_command(
    run_dir: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=True, dir_okay=True, help="A run folder (it holds events.jsonl), or its events.jsonl."),
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
    from .config import ConfigError, expand
    from .platform.manual import BoardError, load_board
    from .postflight import report, summary
    from .runrecord import RunFolderError, load_run, run_folder
    from .text import untrusted

    try:
        run_dir = run_folder(expand(run_dir))
        record = load_run(run_dir)
    except (RunFolderError, ConfigError) as exc:
        _fail(str(exc))
    except OSError as exc:  # a file in it that cannot be read (permissions, say)
        _fail(f"cannot read {exc.filename or run_dir}: {exc.strerror or exc}")
    except (ValueError, OverflowError) as exc:  # a transcript's count is NaN, Infinity or 1e400: runrecord's int() refuses it
        _fail(f"cannot read the run in {run_dir}: a number in it is not finite ({exc})")
    loaded = None
    if board is not None:
        try:
            loaded = load_board(expand(board))
        except (BoardError, ConfigError) as exc:
            typer.echo(f"flightdeck: --board: {exc}", err=True)  # BoardError messages are already made safe
            raise typer.Exit(2) from None
        except OSError as exc:  # one load_board does not turn into a BoardError (a folder it cannot search)
            _fail(f"--board: cannot read {exc.filename or board}: {exc.strerror or exc}")
    try:
        written = write_report(run_dir, report(record, board=loaded))
    except OSError as exc:
        where = untrusted(str(run_dir / REPORT), one_line=True)
        typer.echo(f"flightdeck: cannot write {where}: {exc.strerror or exc}", err=True)
        raise typer.Exit(1) from None
    typer.echo(summary(record, board=loaded), nl=False)
    typer.echo(f"report: {untrusted(str(written), one_line=True)}")


def _fail(message: str) -> NoReturn:
    """Say why on stderr, folded onto one line (paths and messages come from the run), and exit 2."""
    from .text import untrusted

    typer.echo(f"flightdeck: {untrusted(message, one_line=True)}", err=True)
    raise typer.Exit(2) from None


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
