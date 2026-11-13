"""`flightdeck pack`: fetch a solver pack, set it up and point your config at it.

    flightdeck pack install [SOURCE]     # flightdeck's own solver pack when SOURCE is left out
    flightdeck pack image                # build the image your config's pack runs its engines in
    flightdeck pack info [PACK]          # what a pack is, whether it is ready, and the programs it calls that are missing

SOURCE is a git address or a folder on this machine. A pack is code you choose to run: its
setup command runs on this machine as you, so `install` shows the command and asks before
running it (`--yes` answers yes; with no terminal to ask at, it stops and says so).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Annotated

import typer

from .text import untrusted

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Solver packs: fetch one, set it up, and point your config at it.",
)

ConfigOpt = Annotated[Path | None, typer.Option("--config", dir_okay=False, help="The config file to write the pack into (default: your config).")]


@app.command("install")
def install(
    source: Annotated[str | None, typer.Argument(metavar="SOURCE", show_default=False, help="A git address (https://, ssh://, git@host:path) or a folder on this machine. Left out: flightdeck's own solver pack.")] = None,
    ref: Annotated[str | None, typer.Option("--ref", help="A branch or tag of the pack to fetch (flightdeck's own pack: this release's tag).")] = None,
    subdir: Annotated[str | None, typer.Option("--subdir", help="The pack is this folder of the repository at SOURCE.")] = None,
    name: Annotated[str | None, typer.Option("--name", help="The folder name the fetched pack gets (default: from its address).")] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", metavar="", help="Run the pack's setup command and build its image without asking.")] = False,
    no_setup: Annotated[bool, typer.Option("--no-setup", metavar="", help="Do not run the pack's setup command.")] = False,
    image: Annotated[bool | None, typer.Option("--image/--no-image", show_default=False, metavar="", help="Build the pack's Docker image (default: when your config runs lanes in Docker).")] = None,
    lane_tools: Annotated[bool | None, typer.Option("--lane-tools/--no-lane-tools", show_default=False, metavar="", help="Let the lanes' models call the pack's engines (default: yes, when the pack says how).")] = None,
    config: ConfigOpt = None,
    no_config: Annotated[bool, typer.Option("--no-config", metavar="", help="Do not write the pack into your config; print the lines instead.")] = False,
) -> None:
    """Fetch a solver pack, set it up, and write it into your config's [l1] table."""
    from . import pack as packs
    from .config import ConfigError, default_config_path, load_config
    from .l1.manifest import ManifestError, discover

    try:
        own = packs.own_pack() if source is None else None
        if own is not None:  # a checkout of flightdeck has its pack beside it
            root, how = own, "this checkout's own"
        elif source is None:
            wanted = ref or packs.default_ref()
            typer.echo(f"flightdeck: fetching flightdeck's solver pack ({packs.DEFAULT_SOURCE}, {packs.DEFAULT_SUBDIR}, {wanted})", err=True)
            try:
                root, how = packs.fetch(packs.DEFAULT_SOURCE, ref=wanted, name=name or packs.DEFAULT_NAME, subdir=packs.DEFAULT_SUBDIR)
            except packs.PackError as exc:
                hint = "" if ref else f" (this flightdeck looks for the tag {wanted}; `--ref main` fetches the newest pack instead)"
                _fail(f"{exc}{hint}")
        elif not packs.is_url(source) and Path(source).expanduser().is_dir():
            root, how = Path(source).expanduser().resolve(), "used where it is"
        else:
            typer.echo(f"flightdeck: fetching {_show(source)}", err=True)
            root, how = packs.fetch(source, ref=ref, name=name, subdir=subdir)
        info = packs.read(root)
    except packs.PackError as exc:
        _fail(str(exc))
    typer.echo(f"pack: {_show(info.name)}" + (f" {_show(info.version)}" if info.version else "") + f" at {root} ({how})")
    if info.description:
        typer.echo(f"  {_show(info.description)}")

    config_path = None
    loaded = None
    if not no_config:
        try:
            config_path = (config or default_config_path()).expanduser()
            loaded = load_config(config_path) if config_path.exists() else None
        except ConfigError as exc:
            _fail(str(exc))
        if loaded is None:
            _fail(f"there is no config at {config_path}: run `flightdeck init` first, or pass --no-config")

    if info.setup and not no_setup:
        command = " ".join(_show(word) for word in info.setup)
        typer.echo(f"setup: the pack's setup command runs on this machine, as you: {command}")
        if not _agreed(yes, "Run it?"):
            _fail("the setup command was not run, so the pack is not ready: run this again with --yes, or with --no-setup to skip it", status=1)
        done = subprocess.run(packs.setup_command(info), cwd=root)
        if done.returncode != 0:
            _fail(f"the pack's setup command failed (exit {done.returncode}); the config was not changed", status=done.returncode)
    elif info.setup:
        typer.echo("setup: skipped (--no-setup); the pack's engines may report blocked until it is run")

    docker_lanes = loaded is not None and loaded.lanes.runtime == "docker"
    build = image if image is not None else (info.image is not None and docker_lanes)
    built = None
    if build:
        built = _build_image(info, loaded.lanes.image if loaded is not None else None, yes=yes)
    elif info.image is not None:
        typer.echo(f"image: not built ({'--no-image' if image is False else 'your config runs lanes on this machine'}); "
                   "`flightdeck pack image` builds it for Docker lanes")

    try:
        engines = discover(root)
    except ManifestError as exc:
        _fail(f"the pack does not load: {exc}")
    if not engines:
        _fail(f"{root} has no engines (no .manifest.toml files), so it is not a pack flightdeck can run")
    typer.echo(f"engines: {len(engines)}")

    tag = info.image.tag if info.image is not None and (built or _image_present(info.image.tag)) else None
    if lane_tools and info.lane_note is None:
        _fail(f"--lane-tools: the pack {_show(info.name)} does not say how a lane calls it (no [lanes] note in its pack.toml)")
    tools = info.lane_note is not None if lane_tools is None else lane_tools
    if no_config:
        typer.echo("add to your config:\n\n[l1]\n" + f'pack = "{root}"' + (f'\nimage = "{tag}"' if tag else "")
                   + ("\nlane_tools = true" if tools else ""))
        return
    try:
        packs.write_config(config_path, root, tag, tools)
    except packs.PackError as exc:
        _fail(str(exc))
    typer.echo(f"config: {config_path} now has [l1] pack = {root}" + (f" and image = {tag}" if tag else ""))
    if tools:
        typer.echo("lanes: their models may call the pack's engines too (lane_tools = true)"
                   + (f"; Docker lanes then run in {tag}" if tag else "") + ". `--no-lane-tools` turns that off")
    typer.echo("next: `flightdeck doctor` checks the setup; `flightdeck practice` plays the practice board with the pack running first")


@app.command("image")
def image_command(
    pack: Annotated[Path | None, typer.Argument(metavar="PACK", show_default=False, exists=True, file_okay=False, help="The pack's folder (default: your config's [l1] pack).")] = None,
    config: ConfigOpt = None,
) -> None:
    """Build the Docker image a pack's engines run in, and write it into your config."""
    from . import pack as packs
    from .config import ConfigError, default_config_path, load_config

    try:
        config_path = (config or default_config_path()).expanduser()
        loaded = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))
    root = pack.resolve() if pack is not None else loaded.l1.pack
    if root is None:
        _fail("your config names no pack ([l1] pack): `flightdeck pack install` sets one up")
    try:
        info = packs.read(root)
        if info.image is None:
            _fail(f"the pack {_show(info.name)} brings no image of its own; its engines run in the lane image")
        _build_image(info, loaded.lanes.image, yes=True)
        if loaded.l1.pack is not None and loaded.l1.pack.resolve() == info.root:
            packs.write_config(config_path, loaded.l1.pack, info.image.tag)
            typer.echo(f"config: {config_path} now has [l1] image = {info.image.tag}")
    except packs.PackError as exc:
        _fail(str(exc))


@app.command("info")
def info_command(
    pack: Annotated[Path | None, typer.Argument(metavar="PACK", show_default=False, exists=True, file_okay=False, help="The pack's folder (default: your config's [l1] pack).")] = None,
    config: ConfigOpt = None,
) -> None:
    """Show what a pack is: its name, engines, setup command and image, and the programs it calls that are missing."""
    from . import pack as packs
    from .config import ConfigError, default_config_path, load_config
    from .l1.manifest import ManifestError, discover

    root = pack.resolve() if pack is not None else None
    if root is None:
        try:
            root = load_config((config or default_config_path()).expanduser()).l1.pack
        except ConfigError as exc:
            _fail(str(exc))
        if root is None:
            _fail("your config names no pack ([l1] pack): `flightdeck pack install` sets one up")
    try:
        info = packs.read(root)
        engines = discover(info.root)
    except (packs.PackError, ManifestError) as exc:
        _fail(str(exc))
    typer.echo(f"pack: {_show(info.name)}" + (f" {_show(info.version)}" if info.version else "") + f" at {info.root}")
    if info.description:
        typer.echo(f"  {_show(info.description)}")
    typer.echo(f"engines: {len(engines)}")
    typer.echo("setup: " + (" ".join(_show(word) for word in info.setup) if info.setup else "none needed"))
    if info.image is None:
        typer.echo("image: none of its own (engines run in the lane image under Docker)")
    else:
        there = _image_present(info.image.tag)
        typer.echo(f"image: {info.image.tag} ({'built' if there else 'not built: `flightdeck pack image`'})")
    if not info.tools:
        typer.echo("tools: none listed (its pack.toml has no `tools`)")
        return
    typer.echo(f"tools: {len(info.tools)} programs its engines call: {' '.join(info.tools)}")
    absent = packs.missing_on_host(info.tools)
    typer.echo("  on this machine: " + (f"missing {' '.join(absent)}" if absent else "all on PATH"))
    if info.image is not None:
        if not there:
            typer.echo(f"  in the image {info.image.tag}: not looked up, since it is not built")
            return
        try:
            absent = packs.missing_in_image(info.image.tag, info.tools)
        except packs.PackError as exc:
            typer.echo(f"  in the image {info.image.tag}: not looked up: {exc}")
        else:
            typer.echo(f"  in the image {info.image.tag}: " + (f"missing {' '.join(absent)}" if absent else "all there"))


def _build_image(info, lane_image: str | None, *, yes: bool) -> bool:
    """Build the pack's image; True when it was built. Stops the command when it cannot be."""
    from . import pack as packs
    from .agent.workspace import docker_unavailable
    from .lane import IMAGE

    if info.image is None:
        _fail(f"the pack {_show(info.name)} brings no image of its own; its engines run in the lane image")
    reason = docker_unavailable()
    if reason:
        _fail(f"building the pack's image needs Docker: {reason}")
    argv = packs.image_command(info, lane_image or IMAGE)
    typer.echo(f"image: building {info.image.tag} from the pack's Dockerfile (docker runs what it says): {' '.join(_show(a) for a in argv)}")
    if not _agreed(yes, "Build it?"):
        typer.echo("image: not built; `flightdeck pack image` builds it later")
        return False
    done = subprocess.run(argv)
    if done.returncode != 0:
        _fail(f"docker build failed (exit {done.returncode})", status=done.returncode)
    typer.echo(f"image: built {info.image.tag}")
    return True


def _image_present(tag: str) -> bool:
    from .setup import image_present

    return image_present(tag)


def _agreed(yes: bool, question: str) -> bool:
    if yes:
        return True
    if not sys.stdin.isatty():
        _fail("there is no terminal to ask at: pass --yes to run the pack's setup and build its image, or --no-setup and --no-image to skip them")
    return typer.confirm(question, default=False)


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _fail(message: str, *, status: int = 2):
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(status)
