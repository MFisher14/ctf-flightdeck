"""`flightdeck writeups RUN_DIR`: a Markdown draft for every challenge a run solved.

The drafts go to RUN_DIR/writeups/<challenge id>.md (see writeup.py for what is in one). A
draft that exists already is kept, since the player may have edited it, unless --force is
given. Nothing is written through a symlink: a lane on the host runtime can write into the
run folder, so it could have planted one.

--polish MODEL has a model tidy the prose through the API in the player's config. It spends
tokens, and the model never sees anything from the run (writeup.polish). A refused or failed
polish keeps the plain draft and says why.

Mounted by the main CLI with `app.add_typer(writeup_cli.app)` (no name: the command is
`writeups` at the top level).
"""

from __future__ import annotations

import os
import re
import secrets
import stat
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from .text import MARK, untrusted

app = typer.Typer(add_completion=False, rich_markup_mode="markdown")

FOLDER = "writeups"
_SURROGATE = re.compile("[\ud800-\udfff]")


class _Refused(Exception):
    """The drafts cannot be written where they belong; the message says why."""


@app.command("writeups")
def writeups(
    run_dir: Annotated[Path, typer.Argument(metavar="RUN_DIR", help="A run folder (the one holding events.jsonl), or its events.jsonl.")],
    redact: Annotated[
        bool,
        typer.Option(
            "--redact", metavar="",
            help="Write `<flag>` in place of the flag wherever the run's text holds it: whole, cut short, "
            "folded, or the part inside its braces.",
        ),
    ] = False,
    board: Annotated[
        Path | None, typer.Option("--board", file_okay=False, help="The board folder, for names and points the run log lacks.")
    ] = None,
    polish: Annotated[
        str | None,
        typer.Option(
            "--polish", metavar="MODEL",
            help="Have MODEL tidy the prose, through the API in your config (spends tokens). It never sees "
            "the run's flags, commands or outputs.",
        ),
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", dir_okay=False, help="Config file for --polish (default: $FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml).")
    ] = None,
    force: Annotated[bool, typer.Option("--force", metavar="", help="Replace drafts that already exist.")] = False,
) -> None:
    """Draft a writeup for every challenge the run solved, in RUN_DIR/writeups/."""
    from . import writeup
    from .runrecord import RunFolderError, load_run, run_folder

    try:
        run_dir = run_folder(run_dir.expanduser())
        record = load_run(run_dir)
    except RunFolderError as exc:
        _fail(str(exc))
    loaded_board = _board(board) if board is not None else None
    for problem in record.problems:
        typer.echo(f"flightdeck: {_show(run_dir)}: {_show(problem)}", err=True)
    solved = writeup.solves(record)
    for lane in record.lanes.values():
        if lane.state == "solved" and lane.challenge not in solved:
            typer.echo(
                f"flightdeck: {_show(lane.lane)}'s transcript says it solved {_show(lane.challenge)}, but events.jsonl "
                "has no accepted flag for it, so it gets no draft",
                err=True,
            )
    if not solved:
        typer.echo("no challenge was solved in this run: no writeups to draft")
        return
    folder = run_dir / FOLDER
    todo: list[tuple[str, Path]] = []
    trouble: list[str] = []
    for cid in solved:
        name = writeup.file_name(cid)
        if name is None:
            trouble.append(f"{_show(cid)!r}: this challenge id cannot name a file, so no draft was written")
            continue
        target = folder / name
        if not force and (target.is_symlink() or target.exists()):
            trouble.append(f"{_show(target)} exists; kept it (pass --force to replace it)")
            continue
        todo.append((cid, target))
    client_config = _polish_config(config) if polish is not None and todo else None
    if todo:
        try:
            _folder(folder)
        except _Refused as exc:
            _fail(str(exc))
    if client_config is not None:
        import asyncio

        assert polish is not None
        try:
            drafts, spent = asyncio.run(_polished(record, [cid for cid, _ in todo], polish, client_config, loaded_board, redact))
        except _Refused as exc:
            _fail(str(exc))
    else:
        drafts = {cid: (writeup.draft(record, cid, board=loaded_board, redact=redact), "") for cid, _ in todo}
        spent = ""
    for cid, target in todo:
        markdown, refused = drafts[cid]
        try:
            _write(target, markdown)
        except _Refused as exc:
            trouble.append(str(exc))
            continue
        typer.echo(f"wrote {_show(target)}" + (" (not polished)" if refused else ""))
        if refused:
            trouble.append(f"{_show(target)}: not polished: {_show(refused)}")
    if spent:
        typer.echo(spent)
    for line in trouble:
        typer.echo(f"flightdeck: {line}", err=True)
    if trouble:
        raise typer.Exit(1)


# ---------------------------------------------------------------------- inputs


def _board(path: Path):
    from .platform.manual import BoardError, load_board

    try:
        return load_board(path.expanduser())
    except BoardError as exc:
        _fail(str(exc))


def _polish_config(path: Path | None):
    """The config and API key --polish needs, checked before anything is written."""
    from .config import ConfigError, api_key, load_config

    try:
        loaded = load_config(path.expanduser() if path is not None else None)
        return loaded, api_key(loaded)
    except ConfigError as exc:
        _fail(f"--polish needs the model API from your config: {exc}")


async def _polished(record, ids, model, client_config, board, redact) -> tuple[dict[str, tuple[str, str]], str]:
    """Each draft polished, or plain with the reason it is not; and a line on what it cost."""
    from . import writeup
    from .agent.client import ModelError, call_dollars
    from .agent.fallback import client_for

    loaded, key = client_config
    drafts: dict[str, tuple[str, str]] = {}
    tokens, dollars, unknown = 0, 0.0, False

    def spend(usage) -> None:
        """Every part of the call (a refusal fallback's attempts too), each at its model's price."""
        nonlocal tokens, dollars, unknown
        tokens += sum(part.total for part in usage.parts())
        cost = call_dollars(usage, model, loaded.prices.get)
        if cost is None:
            unknown = True
        else:
            dollars += cost

    try:
        client = client_for(loaded.api.provider, loaded.api.base_url, key)  # the [api] one: polishing is not a lane
    except ValueError as exc:  # the key from the environment cannot go in a header; never shown
        raise _Refused(f"--polish cannot use the model API: {exc}") from None
    async with client:
        for cid in ids:
            try:
                done = await writeup.polish(record, cid, client=client, model=model, board=board, redact=redact)
            except (writeup.PolishError, ModelError) as exc:
                if exc.usage is not None:  # refused, or the model declined: the call was made and paid for
                    spend(exc.usage)
                drafts[cid] = (writeup.draft(record, cid, board=board, redact=redact), str(exc))
                continue
            drafts[cid] = (done.markdown, "")
            spend(done.usage)
    from . import fmt

    polished = sum(1 for _, refused in drafts.values() if not refused)
    cost_text = "cost unknown" if unknown else f"${fmt.dollars(dollars)}"
    return drafts, f"polish: {polished} of {len(ids)} drafts with {_show(model)}, {fmt.tokens(tokens)} tokens, {cost_text}"


# ---------------------------------------------------------------------- writing


def _folder(folder: Path) -> None:
    """RUN_DIR/writeups as a real directory: made if missing, never a symlink."""
    try:
        info = os.lstat(folder)
    except FileNotFoundError:
        try:
            folder.mkdir()
        except OSError as exc:
            raise _Refused(f"cannot create {_show(folder)}: {exc.strerror or exc}") from None
        return
    except OSError as exc:
        raise _Refused(f"cannot look at {_show(folder)}: {exc.strerror or exc}") from None
    if stat.S_ISLNK(info.st_mode):
        raise _Refused(f"{_show(folder)} is a symlink; flightdeck does not write drafts through symlinks")
    if not stat.S_ISDIR(info.st_mode):
        raise _Refused(f"{_show(folder)} is not a directory")


def _write(target: Path, markdown: str) -> None:
    """Write a new file in the same folder (O_EXCL: never one that is there, a symlink
    included), then rename it over the target, so a symlink at the target is replaced, never
    followed, and a crash leaves no half-written draft. Text UTF-8 cannot hold (a lone
    surrogate) is refused like a full disk: the temporary file goes, the other drafts are
    still written."""
    temp = target.parent / f".draft-{secrets.token_hex(8)}.md"
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o666)
    except OSError as exc:
        raise _Refused(f"cannot write in {_show(target.parent)}: {exc.strerror or exc}") from None
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(markdown)
        os.replace(temp, target)
    except (OSError, UnicodeError) as exc:
        temp.unlink(missing_ok=True)
        why = (exc.strerror or exc) if isinstance(exc, OSError) else "the draft holds text that is not valid Unicode"
        raise _Refused(f"cannot write {_show(target)}: {why}") from None
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def _show(value: object) -> str:
    """Untrusted text for the terminal: folded, and a lone surrogate (which a UTF-8 terminal
    cannot take) shown as U+FFFD."""
    return _SURROGATE.sub(MARK, untrusted(str(value), one_line=True))


def _fail(message: str) -> NoReturn:
    typer.echo(f"flightdeck: {_show(message)}", err=True)
    raise typer.Exit(2)
