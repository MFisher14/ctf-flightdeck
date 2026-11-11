"""`flightdeck l1`: the player's L1 solver pack from the command line.

    flightdeck l1 list PACK
    flightdeck l1 route PACK CHALLENGE_DIR
    flightdeck l1 run PACK CHALLENGE_DIR [--flag-format RE] [--workdir DIR]
    flightdeck l1 import FOLDER

CHALLENGE_DIR is a folder-board challenge (a folder with a challenge.json); its parent is
read as the board, so the board's flag format and id rules apply. `run` prints each
engine's SolverResult as one line of JSON on stdout, best engine first; everything meant
for the player goes to stderr. Heavy modules are imported inside the commands.

A pack is the player's own code and a challenge is untrusted, so the two never overlap:
`route` and `run` refuse a challenge inside the pack (or a pack inside the challenge), and
`run` refuses a --workdir inside either (engine workspaces are copies of the challenge).
Folders of the pack that hold a challenge's files are never searched for engines; the
commands say which ones they left out.
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
    _apart(pack, item.handout)
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
    keep: Annotated[
        bool,
        typer.Option("--keep", help="Keep each engine's copy of the challenge after the run (default: each is removed once its result is read)."),
    ] = False,
) -> None:
    """Run every engine the challenge reaches, each in its own copy of the challenge, and
    print each result as one line of JSON."""
    import asyncio
    import re
    import tempfile

    from ..core.model import DeckConfig
    from ..eventlog import new_run_dir
    from .router import route
    from .runner import remove_tree, run_routed

    manifests = _discover(pack)
    item, board = _challenge(challenge_dir)
    _apart(pack, item.handout)
    if workdir is not None:
        _not_inside(workdir.expanduser(), pack, item.handout, "--workdir")
    else:
        _not_inside(Path(tempfile.gettempdir()), pack, item.handout, "--workdir", default=True)
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
    after = "kept there (--keep)" if keep else "each removed once its result is read (--keep keeps them)"
    typer.echo(
        f"flightdeck: running {len(hits)} engine{'s' if len(hits) != 1 else ''} on this machine as you, each in a copy "
        f"of the challenge under {_show(runs_dir)}, {after}; they get no API keys or tokens from flightdeck's environment",
        err=True,
    )
    try:
        runs = asyncio.run(run_routed(hits, item.handout, workdir=runs_dir, flag_format=pattern, challenge_id=item.challenge.id, keep=keep))
    finally:
        if not keep:  # the run's own folder: a temporary one goes whole, one in --workdir once it is empty
            left = remove_tree(runs_dir) if workdir is None else _remove_if_empty(runs_dir)
            if left:
                typer.echo(f"flightdeck: could not remove {_show(runs_dir)}: {left}", err=True)
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
    """The pack's engines; the folders it left out (they hold a challenge's files) said on stderr."""
    from .manifest import ManifestError, read_pack

    try:
        found = read_pack(pack)
    except ManifestError as exc:
        _fail(str(exc))
    root = pack.expanduser().absolute()
    for folder, why in found.skipped:
        typer.echo(f"flightdeck: skipped {_show(_relative(folder, root))} in the pack: {_show(why)}; nothing in it is an engine", err=True)
    return found.manifests


def _apart(pack: Path, handout: Path) -> None:
    """Fail unless the pack and the challenge are apart: neither inside the other."""
    pack_dir, challenge = pack.expanduser().resolve(), handout.resolve()
    if _within(challenge, pack_dir) or _within(pack_dir, challenge):
        _fail(
            f"the challenge {_show(challenge)} and the pack {_show(pack_dir)} overlap: a pack holds your own engines "
            "and must never hold a challenge's files (or sit inside one). Keep the board and the pack in separate folders"
        )


def _not_inside(folder: Path, pack: Path, handout: Path, option: str, *, default: bool = False) -> None:
    """Fail when the folder engine workspaces go in is inside the pack or the challenge."""
    where = folder.resolve()
    for owner, what in ((pack.expanduser().resolve(), "the pack"), (handout.resolve(), "the challenge")):
        if _within(where, owner):
            which = f"the default temporary folder {_show(where)}" if default else f"{_show(where)}"
            raise typer.BadParameter(
                f"{which} is inside {what} {_show(owner)}: engine workspaces are copies of the challenge, and "
                f"neither the pack nor the challenge may hold one. Pass {option} with a folder outside both",
                param_hint=option,
            )


def _within(path: Path, folder: Path) -> bool:
    return path == folder or path.is_relative_to(folder)


def _remove_if_empty(folder: Path) -> str:
    """Remove a run's folder in --workdir when every engine's copy in it is gone: "" when it
    was removed or holds something (an engine's copy that could not be removed, which that
    engine's result already says), else why not."""
    import errno

    try:
        folder.rmdir()
    except OSError as exc:
        if exc.errno in (errno.ENOTEMPTY, errno.EEXIST):
            return ""
        return _show(exc.strerror or str(exc))
    return ""


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
