"""`flightdeck score`: score a past run from its event log (practice mode, M3).

The board is --board; else the one the run recorded when it started (RUN_DIR/run.json), said
on stderr, with the answers file it was given; else, for a run older than run.json, the
practice set. A recorded board that is gone is an error naming it, never another board.

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
        typer.Option(
            "--board",
            help="The board the run played (default: the board recorded in the run's run.json; a run folder without "
            "one: the practice set).",
        ),
    ] = None,
    answers: Annotated[
        Path | None,
        typer.Option(
            "--answers",
            help="sha256 answers file to check the flags against (default: the one the run was given, else "
            "answers.sha256.json in the board, if any).",
        ),
    ] = None,
) -> None:
    """Score a past run from its event log: solves, points, first solve, cost per solve,
    interventions and wrong submissions. Reads only the run folder (the log, and the lane
    transcripts for what was spent outside a turn) and the board; spends nothing."""
    from .config import ConfigError, expand
    from .platform.manual import BoardError, load_board
    from .practice_mode import ScoreError, score, scorecard

    try:
        log = _events_file(expand(run_dir))
    except ConfigError as exc:
        _fail(str(exc))
    if board is not None:
        folder = expand(board)
    else:
        folder, recorded_answers = _recorded_board(log.parent)
        answers = answers if answers is not None else recorded_answers
    try:
        played = load_board(folder, answers=expand(answers) if answers is not None else None)
        result = score(log, played)
    except (BoardError, ConfigError, ScoreError) as exc:
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


def _recorded_board(run_dir: Path) -> tuple[Path, Path | None]:
    """The board and answers file the run recorded when it started (RUN_DIR/run.json), said on
    stderr; the practice set for a run older than run.json. A recorded board or answers file
    that is gone fails, naming it: scoring another board would be a silent guess."""
    from .runrecord import RUN_INFO, RunFolderError, read_run_info

    try:
        info = read_run_info(run_dir)
    except RunFolderError as exc:
        _fail(f"{exc}; name the board the run played with --board")
    if info is None or info.board is None:
        return _practice_board(), None
    where = run_dir / RUN_INFO
    if not info.board.is_dir():
        _fail(f"the board this run played, {info.board} (recorded in {where}), is not there any more: name it with --board")
    if info.answers is not None and not info.answers.is_file():
        _fail(f"the answers file this run was given, {info.answers} (recorded in {where}), is not there any more: "
              "name one with --answers, or the board with --board")
    typer.echo(f"flightdeck: board: {untrusted(str(info.board), one_line=True)} (recorded by the run)", err=True)
    return info.board, info.answers


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

