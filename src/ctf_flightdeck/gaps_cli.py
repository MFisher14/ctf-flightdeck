"""`flightdeck gaps RUN_DIR [--pack PACK] [--board PATH]`: the gap report for a run folder.

Writes RUN_DIR/gaps.md (for you) and RUN_DIR/gaps.json (for build mode) and prints a short
summary. With --pack, each gap is routed again offline against your pack, which needs the
board the run played (--board) for the handouts; routing never runs an engine.

Nothing is written through a symlink: each file is written new in the run folder and renamed
over the old one, so a symlink planted where a report goes (a lane on the host runtime can
write into the run folder) is replaced, never followed.

The integrator mounts this app on the main one with `app.add_typer(gaps_cli.app)` (no name),
which adds the `gaps` command as it is.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from .text import untrusted

app = typer.Typer(add_completion=False, help="The gap report: the challenges no L1 engine solved, and why.")


@app.command("gaps")
def gaps_command(
    run_dir: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, dir_okay=True, help="A run folder (it holds events.jsonl)."),
    ],
    pack: Annotated[
        Path | None,
        typer.Option(
            "--pack", exists=True, file_okay=False, dir_okay=True,
            help="Your L1 pack: route each gap again offline and say which engines would reach it now "
            "(nothing is run). Needs --board.",
        ),
    ] = None,
    board: Annotated[
        Path | None,
        typer.Option(
            "--board", exists=True, file_okay=False, dir_okay=True,
            help="The board folder the run played: the event's name, names and points the run log lacks, "
            "and the handouts --pack routes.",
        ),
    ] = None,
) -> None:
    """The challenges no L1 engine solved, and why: written to RUN_DIR/gaps.md (for you) and
    RUN_DIR/gaps.json (for build mode), with a short summary printed."""
    from .gaps import JSON_FILE, MARKDOWN_FILE, GapError, gap_report, gaps_json, gaps_markdown, summary
    from .l1.manifest import ManifestError
    from .platform.manual import BoardError, load_board
    from .runrecord import RunFolderError, load_run

    if pack is not None and board is None:
        _fail("--pack needs --board: routing reads each challenge's handout from the board the run played")
    run_dir = run_dir.expanduser()
    try:
        record = load_run(run_dir)
    except RunFolderError as exc:
        _fail(str(exc))
    loaded = None
    if board is not None:
        try:
            loaded = load_board(board.expanduser())
        except BoardError as exc:
            _fail(f"--board: {exc}")
    try:
        rep = gap_report(record, pack=pack.expanduser() if pack is not None else None, board=loaded)
    except ManifestError as exc:
        _fail(f"--pack: {exc}")
    except GapError as exc:
        _fail(str(exc))
    try:
        written = write_files(run_dir, {MARKDOWN_FILE: gaps_markdown(rep), JSON_FILE: gaps_json(rep)})
    except OSError as exc:
        _fail(f"cannot write the gap report in {run_dir}: {exc.strerror or exc}", code=1)
    typer.echo(summary(rep), nl=False)
    for path in written:
        typer.echo(f"wrote {_show(path)}")


def write_files(folder: Path, files: Mapping[str, str]) -> list[Path]:
    """Write each file into `folder` whole or not at all: first every one as a new temporary
    file there (created exclusively, never through a symlink; its mode follows the umask),
    then each renamed over its target, so a symlink at a target is replaced, never followed.
    On an error no temporary file is left behind."""
    staged: list[tuple[Path, Path]] = []
    try:
        for name, text in files.items():
            temp = folder / f".{name}.{os.urandom(6).hex()}.tmp"
            handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o666)
            staged.append((temp, folder / name))
            with os.fdopen(handle, "w", encoding="utf-8") as out:
                out.write(text)
        for temp, target in staged:
            os.replace(temp, target)
    except BaseException:
        for temp, _ in staged:
            temp.unlink(missing_ok=True)
        raise
    return [target for _, target in staged]


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _fail(message: str, code: int = 2) -> NoReturn:
    typer.echo(f"flightdeck: {_show(message)}", err=True)
    raise typer.Exit(code)
