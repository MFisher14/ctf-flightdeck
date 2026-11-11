"""`flightdeck l1`: the player's L1 solver pack from the command line.

    flightdeck l1 list PACK
    flightdeck l1 route PACK CHALLENGE_DIR
    flightdeck l1 run PACK CHALLENGE_DIR [--flag-format RE] [--workdir DIR]
    flightdeck l1 import FOLDER

CHALLENGE_DIR is a folder-board challenge (a folder with a challenge.json); its parent is
read as the board, so the board's flag format and id rules apply. `run` prints each
engine's SolverResult as one line of JSON on stdout, best engine first; everything meant
for the player goes to stderr. Heavy modules are imported inside the commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from ..text import untrusted

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="L1 solver packs: your no-model solvers, routed to a challenge and run in copies of it.",
)

PackArg = Annotated[
    Path, typer.Argument(exists=True, file_okay=False, dir_okay=True, help="A folder of engines, each described by a *.manifest.toml.")
]
ChallengeArg = Annotated[
    Path, typer.Argument(exists=True, file_okay=False, dir_okay=True, help="A challenge folder of a folder board (it has a challenge.json).")
]


@app.command("list")
def list_engines(pack: PackArg) -> None:
    """List the engines in a pack, with their routes."""
    manifests = _discover(pack)
    if not manifests:
        typer.echo(
            f"flightdeck: no engines in {_show(pack)} (an engine is described by a *.manifest.toml; "
            "`flightdeck l1 import` writes them for a folder of plain scripts)",
            err=True,
        )
        return
    for manifest in manifests:
        entry = manifest.entry
        how = f"{entry.path}:{entry.function}" if entry.kind == "python" else "cli: " + " ".join(entry.argv)
        extra = f", needs {', '.join(manifest.needs_tools)}" if manifest.needs_tools else ""
        tags = f" [{', '.join(manifest.tags)}]" if manifest.tags else ""
        typer.echo(_show(f"{manifest.id}{tags}: {how} (output {manifest.output}, timeout {manifest.timeout_seconds}s{extra})"))
        for rule in manifest.routes:
            parts = [f"category {' | '.join(rule.category)}"] if rule.category else []
            parts += [f"keywords {' | '.join(rule.keywords)}"] if rule.keywords else []
            parts += [f"files {' | '.join(rule.files)}"] if rule.files else []
            typer.echo(_show(f"    priority {rule.priority}: {', and '.join(parts)}"))


@app.command("route")
def route_command(pack: PackArg, challenge_dir: ChallengeArg) -> None:
    """Show which engines a challenge reaches, best first, and why."""
    from .router import route

    manifests = _discover(pack)
    item, _ = _challenge(challenge_dir)
    hits = route(manifests, item.challenge, item.handout)
    if not hits:
        typer.echo(f"flightdeck: no engine in {_show(pack)} routes {item.challenge.id}", err=True)
        return
    for hit in hits:
        typer.echo(f"{hit.priority:3d}  {hit.manifest.id}  {hit.reason}")


@app.command("run")
def run_command(
    pack: PackArg,
    challenge_dir: ChallengeArg,
    flag_format: Annotated[
        str | None,
        typer.Option("--flag-format", metavar="RE", help="The flag format, a regular expression (default: the board's, else flightdeck's generic one)."),
    ] = None,
    workdir: Annotated[
        Path | None,
        typer.Option("--workdir", file_okay=False, help="Where engine workspaces go: a new folder per run inside it (default: a new temporary folder)."),
    ] = None,
) -> None:
    """Run every engine the challenge reaches, each in its own copy of the challenge, and
    print each result as one line of JSON."""
    import asyncio
    import re
    import tempfile

    from ..core.model import DeckConfig
    from ..eventlog import new_run_dir
    from .router import route
    from .runner import run_routed

    manifests = _discover(pack)
    item, board = _challenge(challenge_dir)
    if flag_format is not None:
        try:
            re.compile(flag_format)
        except re.error as exc:
            raise typer.BadParameter(f"does not compile as a regular expression ({exc})", param_hint="--flag-format") from None
        pattern = flag_format
    elif board.flag_format:
        pattern = board.flag_format
    else:
        pattern = DeckConfig(event=board.event).flag_format
        typer.echo(f"flightdeck: the board sets no flag format; using {pattern} (pass --flag-format to set one)", err=True)
    hits = route(manifests, item.challenge, item.handout)
    if not hits:
        typer.echo(f"flightdeck: no engine in {_show(pack)} routes {item.challenge.id}; nothing ran", err=True)
        return
    try:
        runs_dir = new_run_dir(workdir.expanduser()) if workdir else Path(tempfile.mkdtemp(prefix="flightdeck-l1-"))
    except OSError as exc:
        raise typer.BadParameter(f"cannot create a folder there ({exc.strerror})", param_hint="--workdir") from None
    typer.echo(
        f"flightdeck: running {len(hits)} engine{'s' if len(hits) != 1 else ''} on this machine as you, each in a copy "
        f"of the challenge under {_show(runs_dir)}; they get no API keys or tokens from flightdeck's environment",
        err=True,
    )
    runs = asyncio.run(run_routed(hits, item.handout, workdir=runs_dir, flag_format=pattern, challenge_id=item.challenge.id))
    for run in runs:
        typer.echo(run.result.to_json())


@app.command("import")
def import_command(
    folder: Annotated[Path, typer.Argument(exists=True, file_okay=False, dir_okay=True, help="A folder of your scripts.")],
) -> None:
    """Wrap a folder of plain scripts as engines: write a manifest for each script that has
    none, into FOLDER/.flightdeck/generated/. The scripts are never changed."""
    from .importer import ImporterError, import_scripts
    from .manifest import ManifestError

    try:
        report = import_scripts(folder)
    except (ImporterError, ManifestError) as exc:
        _fail(str(exc))
    root = folder.expanduser().absolute()
    for path in report.written:
        typer.echo(f"wrote {_show(_relative(path, root))}")
    for path, why in report.skipped:
        typer.echo(f"skipped {_show(_relative(path, root))}: {_show(why)}")
    typer.echo(
        f"flightdeck: {len(report.written)} generated manifest{'s' if len(report.written) != 1 else ''}, "
        f"{len(report.skipped)} skipped",
        err=True,
    )


# ---------------------------------------------------------------- helpers


def _discover(pack: Path):
    from .manifest import ManifestError, discover

    try:
        return discover(pack)
    except ManifestError as exc:
        _fail(str(exc))


def _challenge(challenge_dir: Path):
    """(BoardChallenge, Board) for a challenge folder, read through its parent's board."""
    from ..platform.manual import CHALLENGE_FILE, BoardError, load_board

    directory = challenge_dir.expanduser()
    if not (directory / CHALLENGE_FILE).is_file():
        _fail(f"{_show(directory)} is not a challenge folder (it has no {CHALLENGE_FILE})")
    target = directory.resolve()
    try:
        board = load_board(target.parent)
    except BoardError as exc:
        _fail(str(exc))
    for item in board.challenges:
        if item.handout.resolve() == target:
            return item, board
    _fail(f"{_show(directory)} is not one of the challenges of the board in {_show(target.parent)}")


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _fail(message: str):
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(2)
