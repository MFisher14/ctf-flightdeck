"""`flightdeck score`: score a past run from its event log (practice mode, M3).

Mounted on the main command line by cli.py with `app.add_typer(practice_cli.app)`; with no
name of its own, the command joins the top level as `flightdeck score`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from .text import untrusted

EVENTS_FILE = "events.jsonl"

app = typer.Typer(add_completion=False, rich_markup_mode="markdown")


@app.command("score")
def score_command(
    run_dir: Annotated[
        Path,
        typer.Argument(metavar="RUN_DIR", help="A run folder (it holds events.jsonl), or an events.jsonl file.", show_default=False),
    ],
    board: Annotated[
        Path | None,
        typer.Option("--board", help="The board the run played (default: the practice set that ships with flightdeck)."),
    ] = None,
    answers: Annotated[
        Path | None,
        typer.Option("--answers", help="sha256 answers file to check the flags against (default: answers.sha256.json in the board, if any)."),
    ] = None,
) -> None:
    """Score a past run from its event log: solves, points, first solve, cost per solve,
    interventions and wrong submissions. Reads only the run folder (the log, and the lane
    transcripts for what was spent outside a turn) and the board; spends nothing."""
    from .platform.manual import BoardError, load_board
    from .practice_mode import ScoreError, score, scorecard

    log = _events_file(run_dir.expanduser())
    folder = board.expanduser() if board is not None else _practice_board()
    try:
        played = load_board(folder, answers=answers.expanduser() if answers is not None else None)
        result = score(log, played)
    except (BoardError, ScoreError) as exc:
        _fail(str(exc))
    typer.echo(scorecard(result), nl=False)


def _events_file(path: Path) -> Path:
    """The run's event log: RUN_DIR/events.jsonl, or the file itself when given one."""
    if path.is_dir():
        log = path / EVENTS_FILE
        if not log.is_file():
            _fail(f"{path}: no {EVENTS_FILE} here, so it is not a run folder (runs go to the run_dir in your config)")
        return log
    if path.is_file():
        return path
    _fail(f"{path}: no such run folder or event log")


def _practice_board() -> Path:
    from .practice_set import practice_dir

    try:
        return practice_dir()
    except FileNotFoundError as exc:
        _fail(f"{exc}; name the board the run played with --board")


def _fail(message: str) -> NoReturn:
    """The reason on stderr as one safe line, whoever made the message, and exit 2."""
    typer.echo(f"flightdeck: {untrusted(message, one_line=True)}", err=True)
    raise typer.Exit(2)

