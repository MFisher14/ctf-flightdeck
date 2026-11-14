"""`flightdeck vpn`: keep an event's VPN file, connect it, and say whether it is up.

    flightdeck vpn add FOLDER FILE     # copy the event's .conf or .ovpn into its folder (owner-only)
    flightdeck vpn up FOLDER           # connect: shows the sudo command, then runs it
    flightdeck vpn status FOLDER       # whether it looks connected
    flightdeck vpn down FOLDER         # disconnect

FOLDER is the event's folder (`flightdeck start` makes it); `up`, `status` and `down` also
take a VPN file itself. Connecting needs root: sudo asks for your password in this terminal.

A VPN file can run programs as root, so nothing is run through sudo for a file the player did
not add (`vpn add`, or the VPN answer of `flightdeck start`) or that changed since: it is
said to be unverified. The lines of an added file that run a program as root are shown as
written and asked about with no as the default; --yes does not answer for them, and with no
terminal to ask at the command is refused (vpn.py says what is checked).
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
    typer.echo(f"vpn: kept as {kept.file} ({'WireGuard' if kept.kind == 'wireguard' else 'OpenVPN'})")
    try:
        lines = vpn.root_programs(kept.kind, vpn.read(kept))
    except vpn.VPNError as exc:
        _fail(str(exc))
    if lines:
        _show_root_lines(kept, lines)
        typer.echo(f"vpn: `flightdeck vpn up {kept.folder}` and `flightdeck play` show these again and ask before anything runs")
    if ensure_tool(kept):
        typer.echo(f"vpn: ready; `flightdeck vpn up {kept.folder}` connects it, and `flightdeck play` offers to")


@app.command("up")
def up(target: Target, yes: Annotated[bool, typer.Option("--yes", "-y", metavar="", help="Run the command without asking (a file's lines that run a program as root are still asked about).")] = False) -> None:
    """Connect the event's VPN on this machine (sudo asks for your password)."""
    code = connect(_vpn(target), yes=yes)
    if code:
        raise typer.Exit(code)


def ensure_tool(found, *, yes: bool = False) -> bool:
    """The VPN's tool is on this machine, installing it when it is not: the package manager's
    command is shown and run on a yes. False, with the reason said, when it still is not."""
    from . import vpn

    if vpn.has_tool(found):
        return True
    argv = vpn.install_command(found)
    what = "WireGuard" if found.kind == "wireguard" else "OpenVPN"
    if argv is None:
        typer.echo(f"flightdeck: this event's VPN is {what}, and {found.tool} is not on this machine; flightdeck found no package "
                   f"manager to install it with (Homebrew, apt, dnf or pacman): install {found.tool}, then run this again", err=True)
        return False
    typer.echo(f"vpn: this event's VPN is {what}, and {found.tool} is not on this machine. To install it:")
    typer.echo("  " + " ".join(argv))
    if not yes:
        if not sys.stdin.isatty():
            typer.echo("flightdeck: there is no terminal to ask at: run the command above yourself, or pass --yes", err=True)
            return False
        if not typer.confirm("Install it now?", default=True):
            typer.echo(f"vpn: {found.tool} was not installed, so the VPN cannot be connected")
            return False
    done = subprocess.run(argv)
    if done.returncode != 0 or not vpn.has_tool(found):
        typer.echo(f"flightdeck: {found.tool} was not installed (exit {done.returncode}); what the package manager said is above", err=True)
        return False
    typer.echo(f"vpn: installed {found.tool}")
    return True


def _at_terminal() -> bool:
    """Whether there is somebody to ask (stdin is a terminal)."""
    return sys.stdin.isatty()


def _show_root_lines(found, lines) -> None:
    from . import vpn

    typer.echo(f"vpn: {found.file.name} runs programs as root when it is connected or disconnected. From the file, as written:")
    for line in lines:
        typer.echo(f"  line {line.number}{f' ({line.note})' if line.note else ''}: {vpn.shown(line.text)}")


def _nobody_to_ask(found, lines) -> bool:
    """True, with the lines shown and the refusal said, when the file runs programs as root
    (`lines`) and there is no terminal to ask at."""
    if not lines or _at_terminal():
        return False
    _show_root_lines(found, lines)
    typer.echo(f"flightdeck: refused: {found.file.name} runs programs as root (the lines above) and there is no terminal to ask "
               "at; --yes does not answer for them. Run this at a terminal, or take the lines out and `flightdeck vpn add` "
               "the file again", err=True)
    return True


def _go_ahead(found, lines, *, yes: bool, declined: str) -> int:
    """Whether to run the sudo command just shown: 0 to run it, else the exit code. A file
    whose lines run programs as root (`lines`) is asked about with no as the default, whatever
    --yes says, and refused when there is nobody to ask."""
    if _nobody_to_ask(found, lines):
        return 2
    if lines:
        _show_root_lines(found, lines)
        if not typer.confirm("Run the command, and with it these lines as root?", default=False):
            typer.echo(declined)
            return 1
        return 0
    if not yes:
        if not _at_terminal():
            typer.echo("flightdeck: there is no terminal to ask at: run the command above yourself, or pass --yes", err=True)
            return 2
        if not typer.confirm("Run it?", default=True):
            typer.echo(declined)
            return 1
    return 0


def connect(found, *, yes: bool = False) -> int:
    """Show the command that connects `found`, run it on a yes, and say how it stands. 0 when
    it is connected (or was already). A file the player did not add, or that changed since, is
    never connected; one that runs programs as root is asked about first (_go_ahead)."""
    from . import vpn

    try:
        data = vpn.read(found)
        if not vpn.added(found, data):
            typer.echo(f"flightdeck: {vpn.unverified(found)}", err=True)
            return 2
        lines = vpn.root_programs(found.kind, data)
        if vpn.connected(found) is True:
            typer.echo(vpn.status_line(found, True))
            return 0
    except vpn.VPNError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        return 2
    if _nobody_to_ask(found, lines):  # before anything is installed for a file that will not be connected
        return 2
    if not ensure_tool(found, yes=yes):
        return 2
    try:
        argv = vpn.up_command(found)
    except vpn.VPNError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        return 2
    typer.echo("vpn: connecting needs root on this machine. The command (sudo asks for your password; flightdeck never sees it):")
    typer.echo("  " + " ".join(argv))
    code = _go_ahead(found, lines, yes=yes, declined="vpn: not connected")
    if code:
        return code
    done = subprocess.run(argv)
    if done.returncode != 0:
        typer.echo(f"flightdeck: the VPN did not come up (exit {done.returncode}); what its tool said is above", err=True)
        return done.returncode
    try:
        state = vpn.connected(found)
    except vpn.VPNError as exc:
        typer.echo(f"flightdeck: {exc}", err=True)
        return 1
    typer.echo(vpn.status_line(found, state) if state is not None else "vpn: started; reach a target to see that it works")
    return 0 if state is not False else 1


@app.command("status")
def status(target: Target) -> None:
    """Whether the event's VPN looks connected."""
    from . import vpn

    found = _vpn(target)
    try:
        state = vpn.connected(found)
    except vpn.VPNError as exc:
        _fail(str(exc))
    typer.echo(vpn.status_line(found, state))
    if state is False:
        raise typer.Exit(1)


@app.command("down")
def down(target: Target) -> None:
    """Disconnect the event's VPN. An OpenVPN is stopped only when it is the one flightdeck
    started for this file; WireGuard's file is read again by wg-quick, so it is checked as
    `vpn up` checks it."""
    from . import vpn

    found = _vpn(target)
    lines = []
    try:
        if found.kind == "wireguard":  # `wg-quick down FILE` runs the file's PreDown and PostDown as root
            data = vpn.read(found)
            if not vpn.added(found, data):
                _fail(vpn.unverified(found))
            lines = vpn.root_programs(found.kind, data, down=True)
        argv = vpn.down_command(found)
    except vpn.VPNError as exc:
        _fail(str(exc))
    typer.echo("  " + " ".join(argv))
    code = _go_ahead(found, lines, yes=True, declined="vpn: nothing was run")
    if code:
        raise typer.Exit(code)
    done = subprocess.run(argv)
    if done.returncode != 0:
        _fail(f"the VPN was not disconnected (exit {done.returncode})", status=done.returncode)
    if found.kind == "openvpn":
        try:
            vpn.forget_started(found)  # OpenVPN leaves its pid file behind: the next status is not misled by it
        except OSError as exc:
            typer.echo(f"flightdeck: stopped, but {found.folder / vpn.PID_FILE} could not be removed ({exc.strerror}); "
                       "the next `vpn status` clears it", err=True)
    typer.echo("vpn: disconnected")


def _fail(message: str, *, status: int = 2) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(status)
