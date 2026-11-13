"""`flightdeck gm ...`: list a Game Master's challenges, and pull its started attempts into a
folder board (platform/gamemaster.py).

The integrator mounts `app` as `flightdeck gm`. The token is read from the environment
variable --token-env names (its name is all flightdeck is ever told) and is never printed.
A pull starts no attempt unless --start is given, and never one whose start runs a clock.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, NoReturn

import typer

app = typer.Typer(
    name="gm",
    no_args_is_help=True,
    add_completion=False,
    help="Work with a Game Master: list its challenges, pull its started attempts into a folder that `flightdeck play` opens.",
)

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MAX_SHOWN_NAME = 32  # a variable name longer than this is not echoed: it may be a token pasted in its place

_URL = Annotated[str, typer.Argument(metavar="URL", help="The Game Master's address: the one URL its API answers at.")]
_TOKEN_ENV = Annotated[
    str, typer.Option("--token-env", help="The environment variable that holds your Game Master token (its name, not the token).")
]


@app.callback()
def gm() -> None:
    """Work with a Game Master: list its challenges, pull its started attempts into a folder that `flightdeck play` opens."""


@app.command("list")
def list_command(url: _URL, token_env: _TOKEN_ENV = "GM_TOKEN") -> None:
    """List the Game Master's challenges: id, lane, mode, solved or not, name. One read; nothing is started.

    A challenge whose start runs a clock is marked "clocked": flightdeck never starts one.
    """
    import asyncio

    from ..text import untrusted
    from .gamemaster import GameMasterClient, GameMasterError

    token = _token(token_env)

    async def run():
        async with GameMasterClient(url, token) as client:
            return await client.challenges()

    problem = None
    try:
        rows = asyncio.run(run())
    except (GameMasterError, ValueError) as exc:
        problem = str(exc)
    if problem is not None:
        _fail(problem)
    for row in rows:
        mode = (untrusted(row.mode, one_line=True) or "-") + (" (clocked)" if row.clocked else "")
        typer.echo("  ".join([
            untrusted(row.id, one_line=True),
            untrusted(row.lane, one_line=True) or "-",
            mode,
            "solved" if row.solved else "open",
            untrusted(row.name, one_line=True),
        ]))
    solved = sum(1 for row in rows if row.solved)
    typer.echo(f"{len(rows)} challenge{'' if len(rows) == 1 else 's'}, {solved} solved")


@app.command()
def pull(
    url: _URL,
    dest: Annotated[
        Path,
        typer.Argument(metavar="DEST", file_okay=False, help="The board folder: new or empty, or one pulled from this Game Master before (a re-pull adds what is new)."),
    ],
    token_env: _TOKEN_ENV = "GM_TOKEN",
    start: Annotated[
        bool,
        typer.Option(
            "--start", metavar="",
            help="Start each attempt that is not started and runs no clock, then pull it. Without it nothing is started.",
        ),
    ] = False,
    event: Annotated[
        str | None,
        typer.Option("--event", help="The event's name for board.json (default: the board's own; the folder's name for a new board)."),
    ] = None,
    flag_format: Annotated[
        str | None,
        typer.Option(
            "--flag-format",
            help='What an answer looks like, a regular expression, for board.json: what its group named "answer" matches is '
                 "sent (default for a new board: answer{...}; a re-pull keeps the board's, and refuses another).",
        ),
    ] = None,
) -> None:
    """Pull the Game Master's started attempts: a folder per answer with its challenge.json and files.

    A challenge there is an attempt that must be started before it can be read. A pull starts
    none unless --start is given, and never one whose start runs a clock (start that one on
    the Game Master yourself, then pull again). Every attempt left unstarted is named, with
    the reason.

    Exit status 1 when some challenges could not be pulled (each is named, with the reason;
    pull again to retry them). 2 when the pull could not start or finish (a refused token,
    the Game Master not answering, nothing started to pull, a flag format other than the
    board's): what was written stays.
    """
    import asyncio

    from ..flagformat import problem as flag_format_problem
    from ..text import untrusted
    from .gamemaster import GameMasterClient, GameMasterError, PullStopped
    from .gamemaster import pull as pull_board
    from .manual import BoardError

    if flag_format is not None and (broken := flag_format_problem(flag_format)) is not None:
        _fail(f"--flag-format {broken}")
    token = _token(token_env)
    dest = dest.expanduser()

    async def run():
        async with GameMasterClient(url, token) as client:
            return await pull_board(client, dest, event=event, flag_format=flag_format, start=start, progress=typer.echo)

    problem = None
    try:
        result = asyncio.run(run())
    except PullStopped as exc:
        for line in exc.unstarted:
            typer.echo(f"not started: {line}", err=True)
        for line in exc.problems:
            typer.echo(f"not pulled: {line}", err=True)
        problem = exc.reason
    except (GameMasterError, BoardError, ValueError) as exc:
        problem = str(exc)
    except OSError as exc:
        problem = f"{untrusted(str(dest), one_line=True)}: cannot write the board ({exc.strerror or type(exc).__name__})"
    if problem is not None:
        _fail(problem)
    total = len(result.board.challenges)
    summary = f"{untrusted(str(dest), one_line=True)}: {total} challenge{'' if total == 1 else 's'}, {len(result.added)} new"
    if result.started:
        summary += f", {len(result.started)} attempt{'' if len(result.started) == 1 else 's'} started"
    if result.unstarted:
        summary += f", {len(result.unstarted)} left unstarted"
    typer.echo(summary)
    typer.echo(f"answers are submitted as {untrusted(result.board.flag_format or '', one_line=True)} (board.json's flag_format)")
    for line in result.unstarted:
        typer.echo(f"not started: {line}", err=True)
    for line in result.problems:
        typer.echo(f"not pulled: {line}", err=True)
    if result.problems:
        raise typer.Exit(1)


def _token(token_env: str) -> str:
    """The token, from the variable `token_env` names; exit 2 when it names none or holds nothing."""
    if not _ENV_NAME.fullmatch(token_env):
        _fail("--token-env must be the NAME of an environment variable (letters, digits and _), never the token itself")
    token = os.environ.get(token_env, "").strip()
    if not token:
        named = token_env if len(token_env) <= MAX_SHOWN_NAME else "that --token-env names"
        _fail(
            f"the environment variable {named} is not set or is empty: put your Game Master token in it, or name "
            "another variable with --token-env"
        )
    return token


def _fail(message: str) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(2)
