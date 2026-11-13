"""`flightdeck vpn`: keep an event's VPN file, connect it, and say whether it is up.

    flightdeck vpn add FOLDER FILE     # copy the event's .conf or .ovpn into its folder (owner-only)
    flightdeck vpn up FOLDER           # connect: shows the sudo command, then runs it
    flightdeck vpn status FOLDER       # whether it looks connected
    flightdeck vpn down FOLDER         # disconnect

FOLDER is the event's folder (`flightdeck start` makes it); `up`, `status` and `down` also
take a VPN file itself. Connecting needs root: sudo asks for your password in this terminal.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Annotated, NoReturn

import typer

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="An event's VPN (WireGuard or OpenVPN): keep its file, connect it, see whether it is up.")

Target = Annotated[Path, typer.Argument(metavar="FOLDER", show_default=False, help="The event's folder, or a VPN file (.conf or .ovpn).")]


def _vpn(target: Path):
    from . import vpn
    from .config import ConfigError, expand

    try:
        return vpn.named(expand(target))
    except (vpn.VPNError, ConfigError) as exc:
        _fail(str(exc))


@app.command("add")
def add(folder: Annotated[Path, typer.Argument(metavar="FOLDER", show_default=False, file_okay=False, help="The event's folder.")],
        file: Annotated[Path, typer.Argument(metavar="FILE", show_default=False, dir_okay=False, help="The VPN file the event gave you (.conf or .ovpn).")]) -> None:
    """Copy the event's VPN file into its folder, readable by you only."""
    from . import vpn
    from .config import ConfigError, expand

    try:
        kept = vpn.keep(expand(folder), expand(file))
    except (vpn.VPNError, ConfigError) as exc:
        _fail(str(exc))
    typer.echo(f"vpn: kept as {kept.file} ({'WireGuard' if kept.kind == 'wireguard' else 'OpenVPN'}); "
               f"`flightdeck vpn up {kept.folder}` connects it")


@app.command("up")
def up(target: Target, yes: Annotated[bool, typer.Option("--yes", "-y", metavar="", help="Run the command without asking.")] = False) -> None:
    """Connect the event's VPN on this machine (sudo asks for your password)."""
    code = connect(_vpn(target), yes=yes)
    if code:
        raise typer.Exit(code)


def connect(found, *, yes: bool = False) -> int:
    """Show the command that connects `found`, run it on a yes, and say how it stands. 0 when
    it is connected (or was already)."""
    from . import vpn

    if vpn.connected(found) is True:
        typer.echo(vpn.status_line(found, True))
        return 0
    try:
        argv = vpn.up_command(found)
    except vpn.VPNError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        return 2
    typer.echo("vpn: connecting needs root on this machine. The command (sudo asks for your password; flightdeck never sees it):")
    typer.echo("  " + " ".join(argv))
    if not yes:
        if not sys.stdin.isatty():
            typer.echo("flightdeck: there is no terminal to ask at: run the command above yourself, or pass --yes", err=True)
            return 2
        if not typer.confirm("Run it?", default=True):
            typer.echo("vpn: not connected")
            return 1
    done = subprocess.run(argv)
    if done.returncode != 0:
        typer.echo(f"flightdeck: the VPN did not come up (exit {done.returncode}); what its tool said is above", err=True)
        return done.returncode
    state = vpn.connected(found)
    typer.echo(vpn.status_line(found, state) if state is not None else "vpn: started; reach a target to see that it works")
    return 0 if state is not False else 1


@app.command("status")
def status(target: Target) -> None:
    """Whether the event's VPN looks connected."""
    from . import vpn

    found = _vpn(target)
    state = vpn.connected(found)
    typer.echo(vpn.status_line(found, state))
    if state is False:
        raise typer.Exit(1)


@app.command("down")
def down(target: Target) -> None:
    """Disconnect the event's VPN."""
    from . import vpn

    found = _vpn(target)
    try:
        argv = vpn.down_command(found)
    except vpn.VPNError as exc:
        _fail(str(exc))
    typer.echo("  " + " ".join(argv))
    done = subprocess.run(argv)
    if done.returncode != 0:
        _fail(f"the VPN was not disconnected (exit {done.returncode})", status=done.returncode)
    typer.echo("vpn: disconnected")


def _fail(message: str, *, status: int = 2) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(status)
