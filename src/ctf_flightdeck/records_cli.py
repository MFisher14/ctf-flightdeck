"""`flightdeck records RUN_DIR`: a solve record for every challenge a run solved.

RUN_DIR is a run folder, its events.jsonl, or `latest` for the newest run in the config's [run]
dir, named on stderr (runrecord.resolve_run). The records go to RUN_DIR/records/<challenge
id>.md (solverecord.py says what is in one): the lanes' whole transcripts, every intervention,
and how each flag went to the platform, for a player whose event asks how a challenge was
solved. `--challenge ID` writes only that challenge's (give it again for more).

A record is what the log says and nothing else, so one that exists is written again, never
kept: it is not a draft to edit. Nothing is written through a symlink (a lane on the host
runtime can write into the run folder), and nothing is sent anywhere. No model is called.

cli.py mounts `records_command` as `flightdeck records`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

FOLDER = "records"


def records_command(
    run_dir: Annotated[
        Path,
        typer.Argument(metavar="RUN_DIR", help="A run folder (it holds events.jsonl), its events.jsonl, or `latest`: the newest run in your config's [run] dir."),
    ],
    challenge: Annotated[
        list[str] | None,
        typer.Option("--challenge", metavar="ID", help="Write the record of this challenge only (its id, as the run folder names it); give it again for more."),
    ] = None,
    board: Annotated[
        Path | None, typer.Option("--board", file_okay=False, help="The board folder, for names and points the run log lacks.")
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", dir_okay=False, help="Config file whose [run] dir `latest` looks in (default: "
                     "$FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml)."),
    ] = None,
) -> None:
    """Write a solve record for every challenge the run solved, in RUN_DIR/records/: each
    lane's whole transcript, your interventions and who let each flag go. For an event's
    organisers when they ask how you solved it; it holds challenge text and flags, so it is not
    for posting. Nothing is sent anywhere."""
    from . import solverecord
    from .config import ConfigError, expand
    from .postflight import analyse
    from .runrecord import RunFolderError, load_run, read_run_setup, resolve_run
    from .writeup import file_name
    from .writeup_cli import _board, _fail, _folder, _Refused, _show, _write

    try:
        run_dir = resolve_run(expand(run_dir), say=lambda line: typer.echo(f"flightdeck: {line}", err=True), config=config)
        run = load_run(run_dir)
        setup = read_run_setup(run_dir)
    except (RunFolderError, ConfigError) as exc:
        _fail(str(exc))
    except OSError as exc:  # a file in it that cannot be read (permissions, say)
        _fail(f"cannot read {exc.filename or run_dir}: {exc.strerror or exc}")
    except (ValueError, OverflowError) as exc:  # a count in a transcript that is not finite
        _fail(f"cannot read the run in {run_dir}: a number in it is not finite ({exc})")
    loaded_board = _board(board) if board is not None else None
    for problem in run.problems:
        typer.echo(f"flightdeck: {_show(run_dir)}: {_show(problem)}", err=True)
    solved = solverecord.solved(run)
    wanted = list(dict.fromkeys(challenge or ()))
    for cid in wanted:
        if cid not in solved:  # asked for by name: said before anything is written
            known = any(event.challenge == cid for event in run.events) or any(lane.challenge == cid for lane in run.lanes.values())
            why = solverecord.NOT_SOLVED if known else "is not in this run"
            _fail(f"--challenge: {cid!r} {why}: there is no solve to record"
                  + (f" (solved in it: {', '.join(solved)})" if solved else ""))
    if not solved:
        typer.echo("no challenge was solved with a flag of this run: no records to write")
        return
    folder = run_dir / FOLDER
    trouble: list[str] = []
    todo: list[tuple[str, Path]] = []
    for cid in wanted or solved:
        name = file_name(cid)
        if name is None:
            trouble.append(f"{_show(cid)!r}: this challenge id cannot name a file, so no record was written")
            continue
        todo.append((cid, folder / name))
    if todo:
        try:
            _folder(folder, "records")
        except _Refused as exc:
            _fail(str(exc))
    flight = analyse(run, board=loaded_board)
    for cid, target in todo:
        try:
            _write(target, solverecord.record(run, cid, setup=setup, flight=flight), "record")
        except _Refused as exc:
            trouble.append(str(exc))
            continue
        typer.echo(f"wrote {_show(target)}")
    if todo:
        typer.echo("A record holds the challenge's text, the lanes' commands and outputs and the flag: read it, then hand it to "
                   "the event's organisers only.", err=True)
    for line in trouble:
        typer.echo(f"flightdeck: {line}", err=True)
    if trouble:
        raise typer.Exit(1)
