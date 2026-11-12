"""`flightdeck share RUN_DIR [--name TEXT]`: print a run's flight card.

RUN_DIR is the run folder, its events.jsonl (the path a run prints when it ends), or the word
`latest` for the newest run under the config's [run] dir (runrecord.resolve_run). The card
(share.py) goes to standard output and nowhere else: the player pastes it where they choose.
A run folder that cannot be read fails with the reason (exit 2), never a traceback.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

POST = "https://github.com/MFisher14/ctf-flightdeck/issues/new?template=flight-card.yml"


def share_command(
    run_dir: Annotated[
        Path,
        typer.Argument(metavar="RUN_DIR", help="A run folder (it holds events.jsonl), its events.jsonl, or `latest` for your newest run."),
    ],
    name: Annotated[
        str,
        typer.Option("--name", metavar="TEXT", help="Your own name for the run on the card, such as the event's."),
    ] = "",
    config: Annotated[
        Path | None,
        typer.Option("--config", dir_okay=False, help="Config file whose [run] dir `latest` looks in (default: "
                     "$FLIGHTDECK_CONFIG or ~/.config/ctf-flightdeck/config.toml)."),
    ] = None,
) -> None:
    """Print the run's flight card: what you ran and how it went, with no flags and no
    challenge names or text. Nothing is sent anywhere."""
    from .config import ConfigError, expand
    from .runrecord import RunFolderError, load_run, read_run_setup, resolve_run
    from .share import card

    try:
        folder = resolve_run(expand(run_dir), say=lambda line: typer.echo(f"flightdeck: {line}", err=True), config=config)
        record = load_run(folder)
        setup = read_run_setup(folder)
    except (RunFolderError, ConfigError) as exc:
        _fail(str(exc))
    except OSError as exc:
        _fail(f"cannot read {exc.filename or run_dir}: {exc.strerror or exc}")
    except (ValueError, OverflowError) as exc:  # a count in a transcript that is not finite
        _fail(f"cannot read the run in {run_dir}: a number in it is not finite ({exc})")
    start = next((e for e in record.events if e.kind == "run-start"), None)
    version = start.data.get("version") if start is not None else None
    typer.echo(card(record, setup, version=version if isinstance(version, str) else "", label=name), nl=False)
    typer.echo(f"\nThis card holds no flag and no challenge name. Read it, then post it if you like: {POST}", err=True)


def _fail(message: str) -> NoReturn:
    from .text import untrusted

    typer.echo(f"flightdeck: {untrusted(message, one_line=True)}", err=True)
    raise typer.Exit(2) from None
