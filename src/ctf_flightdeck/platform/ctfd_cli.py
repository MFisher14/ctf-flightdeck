"""`flightdeck ctfd ...`: pull a CTFd board into a folder board (M2).

The integrator mounts `app` as `flightdeck ctfd`. The token is read from the environment
variable --token-env names (its name is all flightdeck is ever told) and is never printed.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Annotated, NoReturn

import typer

app = typer.Typer(
    name="ctfd",
    no_args_is_help=True,
    add_completion=False,
    help="Work with a CTFd: pull its board into a folder that `flightdeck play` opens.",
)

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
MAX_SHOWN_NAME = 32  # a variable name longer than this is not echoed: it may be a token pasted in its place


@app.callback()
def ctfd() -> None:
    """Work with a CTFd: pull its board into a folder that `flightdeck play` opens."""


@app.command()
def pull(
    url: Annotated[str, typer.Argument(metavar="URL", help="The CTFd's address, as in the browser: https://ctf.example.org")],
    dest: Annotated[
        Path,
        typer.Argument(metavar="DEST", file_okay=False, help="The board folder: new or empty, or one pulled from this CTFd before (a re-pull adds what is new)."),
    ],
    token_env: Annotated[
        str, typer.Option("--token-env", help="The environment variable that holds your CTFd API token (its name, not the token).")
    ] = "CTFD_TOKEN",
    event: Annotated[
        str | None,
        typer.Option("--event", help="The event's name for board.json (default: the board's own; the folder's name for a new board)."),
    ] = None,
    flag_format: Annotated[
        str | None,
        typer.Option(
            "--flag-format",
            help="The event's flag format, a regular expression, for board.json (a re-pull keeps the board's, and refuses another).",
        ),
    ] = None,
) -> None:
    """Pull the board from CTFd: a folder per challenge with its challenge.json and files.

    Exit status 1 when some challenges could not be pulled (each is named, with the reason;
    pull again to retry them). 2 when the pull could not start or finish (a refused token,
    CTFd not answering, nothing to pull, a flag format other than the board's): what was
    written stays, each challenge left out so far is named, and pulling again goes on from
    there.
    """
    import asyncio

    from ..flagformat import problem as flag_format_problem
    from ..text import untrusted
    from .ctfd import CTFdClient, CTFdError, PullStopped
    from .ctfd import pull as pull_board
    from .manual import BoardError

    if flag_format is not None and (broken := flag_format_problem(flag_format)) is not None:
        _fail(f"--flag-format {broken}")
    if not _ENV_NAME.fullmatch(token_env):
        _fail("--token-env must be the NAME of an environment variable (letters, digits and _), never the token itself")
    token = os.environ.get(token_env, "").strip()
    if not token:
        # a CTFd token (ctfd_<hex>) is also a valid variable name: a long one may be the token, so it is not shown
        named = token_env if len(token_env) <= MAX_SHOWN_NAME else "that --token-env names"
        _fail(
            f"the environment variable {named} is not set or is empty: put your CTFd API token in it "
            "(CTFd: Settings, Access Tokens), or name another variable with --token-env"
        )
    dest = dest.expanduser()

    async def run():
        async with CTFdClient(url, token) as client:
            return await pull_board(client, dest, event=event, flag_format=flag_format, progress=typer.echo)

    problem = None
    try:
        result = asyncio.run(run())
    except PullStopped as exc:
        for line in exc.problems:
            typer.echo(f"not pulled: {line}", err=True)
        problem = exc.reason
    except (CTFdError, BoardError, ValueError) as exc:
        problem = str(exc)
    except OSError as exc:
        problem = f"{untrusted(str(dest), one_line=True)}: cannot write the board ({exc.strerror or type(exc).__name__})"
    if problem is not None:
        _fail(problem)
    total = len(result.board.challenges)
    summary = f"{untrusted(str(dest), one_line=True)}: {total} challenge{'' if total == 1 else 's'}, {len(result.added)} new"
    if result.hidden:
        summary += f", {result.hidden} locked until a prerequisite is solved"
    typer.echo(summary)
    for line in result.problems:
        typer.echo(f"not pulled: {line}", err=True)
    if result.problems:
        raise typer.Exit(1)


def _fail(message: str) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(2)
