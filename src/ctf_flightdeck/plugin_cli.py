"""`flightdeck plugin`: play an event on a platform flightdeck does not know, through an adapter of your own.

    flightdeck plugin new NAME [--dir DIR]       # write a skeleton to fill in: DIR/NAME/
    flightdeck plugin add FOLDER [--yes]         # show what the plugin runs and gets, ask, and allow it in your config
    flightdeck plugin pull EVENT.toml [FOLDER]   # pull the event's board through its plugin; submits nothing

A plugin is code you choose to run: its program runs on this machine as you, so `add` shows
what it is and asks before your config allows it (`--yes` answers yes; with no terminal to
ask at, it stops and says so). flightdeck never downloads, installs or updates a plugin, and
only `[plugins.NAME]` in your own config allows one: an event profile, which may be a
teammate's, only selects it by name.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, NoReturn

import typer

from .text import untrusted

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Plugins: play an event on a platform flightdeck does not know, through an adapter of your own.",
)


@app.command("new")
def new(
    name: Annotated[str, typer.Argument(metavar="NAME", help="The platform's name: lower-case letters, digits, - and _, starting with a letter.")],
    directory: Annotated[Path | None, typer.Option("--dir", file_okay=False, help="Where the plugin's folder goes (default: this folder).")] = None,
) -> None:
    """Write a plugin to fill in: NAME/ with plugin.toml, adapter.py (the three calls, with placeholder routes) and event.example.toml."""
    from .plugins import manifest

    try:
        files = manifest.skeleton(name)
    except manifest.PluginError as exc:
        _fail(str(exc))
    folder = (directory.expanduser() if directory is not None else Path.cwd()) / name
    if folder.is_symlink() or folder.exists():
        _fail(f"{_show(folder)} is already there: flightdeck does not write over it. Choose another name, or another --dir")
    try:
        folder.mkdir(parents=True)
        for file_name, text in files.items():
            (folder / file_name).write_text(text, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write {_show(folder)}: {exc.strerror or exc}")
    typer.echo(f"wrote {_show(folder)}: {', '.join(files)}")
    typer.echo(f"next: put the platform's own routes in {_show(folder / 'adapter.py')}, then `flightdeck plugin add {_show(folder)}`")


@app.command("add")
def add(
    folder: Annotated[Path, typer.Argument(metavar="FOLDER", file_okay=False, help="The plugin's folder: the one that holds its plugin.toml.")],
    yes: Annotated[bool, typer.Option("--yes", "-y", metavar="", help="Enable the plugin without asking.")] = False,
) -> None:
    """Show what a plugin is, what it runs and what it gets, ask, and write it into your config's [plugins] table."""
    from .config import ConfigError, default_config_path, load_config
    from .plugins import manifest

    try:
        plugin = manifest.read(folder)
    except manifest.PluginError as exc:
        _fail(str(exc))
    try:
        config_path = default_config_path().expanduser()
        if not config_path.exists():
            _fail(f"there is no config at {config_path}: run `flightdeck init` first")
        loaded = load_config(config_path)
    except ConfigError as exc:
        _fail(str(exc))
    if plugin.name in loaded.plugins:
        _fail(f"plugins.{plugin.name} is already in {config_path}: change its path there")
    for line in manifest.card(plugin):
        typer.echo(f"  {line}")
    if not yes:
        if not _at_terminal():
            _fail("there is no terminal to ask at: read the plugin's files, then pass --yes to enable it")
        if not typer.confirm("  Enable it?", default=False):
            _fail("the plugin was not enabled: your config is as it was", status=1)
    try:
        manifest.enable(config_path, plugin.name, plugin.root)
    except manifest.PluginError as exc:
        _fail(str(exc))
    typer.echo(f"config: {config_path} now has [plugins.{plugin.name}] path = {_show(plugin.root)}")
    typer.echo(f'next: an event profile with platform = "{plugin.name}" uses it; `flightdeck plugin pull EVENT.toml` '
               "tries its pull and submits nothing")


@app.command("pull")
def pull(
    event: Annotated[Path, typer.Argument(metavar="EVENT.toml", dir_okay=False, help="The event profile: its platform names a plugin you added.")],
    folder: Annotated[Path | None, typer.Argument(metavar="FOLDER", file_okay=False, show_default=False, help="The board folder (default: the profile's event.board).")] = None,
) -> None:
    """Pull an event's board through its plugin and read the solved list back; nothing is submitted.

    The plugin lists the challenges and downloads their files; flightdeck writes the board
    folders and checks each as any folder board. A second pull adds what is new.

    Exit status 1 when some challenges were left out (each is named, with the reason), 2 when
    the pull could not start or the plugin's call failed.
    """
    import asyncio

    from .config import ConfigError, load_config
    from .platform.manual import BoardError, load_board
    from .plugins import manifest
    from .plugins.board import load_refs, pull_into
    from .plugins.call import CallFailed, Caller
    from .preflight import (
        NO_CONFIG_FOR_PLUGIN,
        PLATFORMS,
        ProfileError,
        load_profile,
        no_such_plugin,
        plugin_board_problem,
        plugin_http_warning,
    )

    try:
        profile, _ = load_profile(event)  # it expands ~ itself, and says so when it cannot
    except ProfileError as exc:
        _fail(str(exc))
    if profile.platform in PLATFORMS:
        _fail(f'event.platform is "{profile.platform}", which flightdeck has built in: `flightdeck plugin pull` is for an '
              "event on a plugin's platform")
    try:
        config = load_config()
    except ConfigError as exc:
        _fail(f"{NO_CONFIG_FOR_PLUGIN}: {exc}")
    ref = config.plugins.get(profile.platform)
    if ref is None:  # the value is not shown: it is the profile's word, and only the player's config makes it a name
        _fail(no_such_plugin(config))
    try:
        plugin = manifest.load(ref)
    except manifest.PluginError as exc:
        _fail(str(exc))
    if not profile.platform_automation:
        _fail(f"rules.platform_automation = false in {_show(event)}: the event's rules do not allow scripts on the platform, "
              f"so flightdeck does not run the {plugin.name} plugin for it")
    if profile.url is None:
        _fail("event.url is required for a plugin's platform: the address its adapter talks to")
    elsewhere = plugin_board_problem(profile)  # the profile's word for where a pull writes: inside its own folder, or none
    if elsewhere is not None:
        _fail(elsewhere)
    token = _token(profile.token_env, plugin, config) if plugin.token else None
    if token is not None and (unencrypted := plugin_http_warning(profile, plugin.name)) is not None:
        typer.echo(f"flightdeck: warning: {unencrypted}", err=True)  # as a run's pre-flight warns: said before the plugin has it
    board = folder.expanduser() if folder is not None else profile.board
    if board is None:
        _fail("name the board folder: `flightdeck plugin pull EVENT.toml FOLDER`, or set event.board in the profile")
    caller = Caller(plugin, profile.url, profile.name, token)

    async def run():
        written = await pull_into(caller, board, plugin=plugin.name, url=profile.url)
        try:
            solved = await caller.solved()
        except CallFailed as exc:
            return written, None, str(exc)
        return written, solved, None

    try:
        written, solved, why = asyncio.run(run())
    except manifest.PluginError as exc:
        _fail(str(exc))
    except CallFailed as exc:
        _fail(f"the {plugin.name} plugin could not pull the board: {exc}")
    for note in written.notes:
        typer.echo(f"{plugin.name}: {note}", err=True)
    for problem in written.problems:
        typer.echo(f"{plugin.name}: not added: {problem}", err=True)
    try:
        loaded = load_board(board, empty_ok=True)
    except BoardError as exc:
        _fail(str(exc))
    count = len(loaded.challenges)
    by_category: dict[str, int] = {}
    for item in loaded.challenges:
        by_category[item.challenge.category] = by_category.get(item.challenge.category, 0) + 1
    line = f"pulled into {_show(board)}: {count} challenge{'' if count == 1 else 's'}"
    if by_category:
        line += " (" + ", ".join(f"{_show(category) or '-'} {n}" for category, n in by_category.items()) + ")"
    if written.added and len(written.added) != count:
        line += f", {len(written.added)} new"
    if solved is None:
        typer.echo(line + "; nothing was submitted")
        _fail(f"could not read the solved list from the {plugin.name} plugin: {why}; what was pulled stays in {_show(board)}")
    on_board = set(load_refs(board, plugin=plugin.name, url=profile.url).values())
    typer.echo(f"{line}, {len(solved & on_board)} listed as solved; nothing was submitted")
    if written.problems:
        raise typer.Exit(1)


def _token(name: str | None, plugin, config) -> str:
    """The event's token, from the variable event.token_env names (the environment, else the
    keys file). Never shown. A variable that holds another service's key is refused, as a run
    refuses it (preflight): its value would be handed to the plugin."""
    from .keys import KeysError, environment
    from .preflight import plugin_token_env

    if name is None:
        _fail(f'event.token_env is required for platform "{plugin.name}": the name of the environment variable that holds your token')
    wrong = plugin_token_env(name, plugin.name, config)
    if wrong is not None:
        _fail(wrong)
    try:
        value = environment().get(name, "").strip()
    except KeysError as exc:
        _fail(str(exc))
    if not value:
        _fail(f"the token variable {name} (event.token_env) is not set or is empty: put {name}=<token> in your keys file or "
              "export it, then pull again")
    return value


def _at_terminal() -> bool:
    """Whether `add` may ask its question (stdin is a terminal)."""
    return sys.stdin.isatty()


def _show(value: object) -> str:
    return untrusted(str(value), one_line=True)


def _fail(message: str, *, status: int = 2) -> NoReturn:
    typer.echo(f"flightdeck: {message}", err=True)
    raise typer.Exit(status)
