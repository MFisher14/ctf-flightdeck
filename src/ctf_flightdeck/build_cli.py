"""`flightdeck build`: build mode, turning a gap into a new L1 engine with a test that proves
a raw handout reaches it (see build.py).

    flightdeck build gap CHALLENGE_DIR --pack PACK [--name ID] [--answers FILE]
    flightdeck build check PACK [--timeout SECONDS]

CHALLENGE_DIR is a folder-board challenge (a folder with a challenge.json); its parent is
read as the board, so the board's flag format and answers file apply. `check` runs the
pack's case tests, each with pytest in a subprocess of its own, and lists the engines
passing and failing; it exits 1 when one fails. Heavy modules are imported inside the
commands.

The integrator mounts this app with `app.add_typer(build_cli.app, name="build")`, next to
`flightdeck image build`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from .text import untrusted

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Build mode: turn a gap into a new L1 engine, with a test that proves a raw handout reaches it.",
)


@app.command("gap")
def gap_command(
    challenge_dir: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, dir_okay=True,
                       help="The challenge folder of a folder board (it has a challenge.json) that no engine solved."),
    ],
    pack: Annotated[
        Path,
        typer.Option("--pack", file_okay=False,
                     help="Your L1 pack: the engine, its manifest and its test go there (made if missing)."),
    ],
    name: Annotated[
        str | None,
        typer.Option("--name", metavar="ID", help="The new engine's id (default: <category>.<challenge id>)."),
    ] = None,
    answers: Annotated[
        Path | None,
        typer.Option("--answers", exists=True, file_okay=True, dir_okay=False,
                     help="An answers file: challenge id to the sha256 of its flag (default: the board's "
                          "answers.sha256.json, if it has one). Only the sha256 is kept, never a flag."),
    ] = None,
) -> None:
    """Write a new engine for a challenge: a solver stub, its manifest, and a test on a copy of
    the challenge that passes once the engine solves it. Nothing is overwritten."""
    from .build import BOARD, BuildError, case_ids, case_size, scaffold
    from .config import ConfigError, expand
    from .l1.manifest import ManifestError, load
    from .platform.manual import ANSWERS_FILE

    try:
        solver, manifest, test, case = scaffold(pack, challenge_dir, engine_id=name, answers=answers)
    except BuildError as exc:
        _fail(str(exc))
    try:
        root = expand(pack).absolute()
    except ConfigError as exc:  # scaffold already ran on the literal path; say so before printing it
        _fail(str(exc))
    try:
        routes = load(manifest).routes
    except ManifestError as exc:  # scaffold checked it loads; only a change since could do this
        _fail(str(exc))
    files, size = case_size(case)
    typer.echo(f"wrote {_rel(solver, root)}: the engine, a stub until you write solve()")
    for rule in routes:
        parts = [f"category {' | '.join(rule.category)}"] if rule.category else []
        parts += [f"keywords {' | '.join(rule.keywords)}"] if rule.keywords else []
        parts += [f"files {' | '.join(rule.files)}"] if rule.files else []
        typer.echo(f"wrote {_rel(manifest, root)}: routes {', and '.join(parts)} (priority {rule.priority})")
    typer.echo(f"wrote {_rel(test, root)}: its test, test_routed and test_solved")
    has_answer = (case / ANSWERS_FILE).is_file()
    _, challenge = case_ids(case)
    typer.echo(
        f"wrote {_rel(case, root)}/: the challenge as it was handed out, in {BOARD}/{challenge}/ ({files} file"
        f"{'' if files == 1 else 's'}, {_size(size)})" + (", and the sha256 of its flag" if has_answer else "")
    )
    if not has_answer:
        typer.echo(
            f"flightdeck: the board has no answer for {challenge}, so test_solved fails until you write "
            f'{{"{challenge}": "<the sha256 of the flag>"}} to {_show(case / ANSWERS_FILE)}',
            err=True,
        )
    typer.echo(f"next: write solve() in {_rel(solver, root)}, then run `flightdeck build check {_show(pack)}`; "
               "the engine is done when its test passes")


@app.command("check")
def check_command(
    pack: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, dir_okay=True, help="Your L1 pack, with case tests from `flightdeck build gap`."),
    ],
    timeout: Annotated[
        float | None,
        typer.Option("--timeout", metavar="SECONDS", min=1,
                     help="Seconds each case test may take (default: its engine's timeout plus two minutes)."),
    ] = None,
) -> None:
    """Run the pack's case tests, with pytest, and list the engines passing and failing.
    The tests get no API keys or tokens from flightdeck's environment."""
    from .build import BuildError, check

    try:
        results = check(pack, timeout=timeout)
    except BuildError as exc:
        _fail(str(exc))
    if not results:
        typer.echo(f"flightdeck: no case tests in {_show(pack)} (`flightdeck build gap` writes them)", err=True)
        return
    for result in results:
        if result.passed:
            typer.echo(f"pass  {_show(result.engine)}")
        else:
            typer.echo(f"FAIL  {_show(result.engine)}: {_show(result.detail)}")
    failing = sum(1 for result in results if not result.passed)
    passing = len(results) - failing
    typer.echo(f"{passing} engine{'' if passing == 1 else 's'} passing, {failing} failing")
    if failing:
        raise typer.Exit(1)


# ---------------------------------------------------------------- helpers


def _rel(path: Path, root: Path) -> str:
    try:
        return _show(path.relative_to(root).as_posix())
    except ValueError:
        return _show(path)


def _size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _fail(message: str) -> NoReturn:
    typer.echo(f"flightdeck: {_show(message)}", err=True)
    raise typer.Exit(2)
