"""Where the player's config folder is: config.toml, keys.env and the themes folder (P94).

The folder is $XDG_CONFIG_HOME/ctf-flightdeck when that is an absolute path (the XDG rule:
anything else is ignored), else ~/.config/ctf-flightdeck, as the state folder
(leftovers.state_folder) and the packs folder (pack.packs_folder) follow $XDG_STATE_HOME and
$XDG_DATA_HOME. $FLIGHTDECK_CONFIG and $FLIGHTDECK_KEYS still name a file of their own, and
then nothing here is looked at for that file.

A player who set $XDG_CONFIG_HOME after flightdeck had written ~/.config/ctf-flightdeck has
their files at the old place. Each is found, never ignored without a word:

- the file is only at the old place: it is read there (and written there, so init and the
  keys form keep to the one file that is read), and notes() says so;
- it is at both places: the one under $XDG_CONFIG_HOME is read, and notes() says the old one
  is not.

notes() is said once per command, on stderr (cli.root), and doctor has it as a check of its
own (setup.doctor); the home screen's Settings and health shows doctor's checks.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

CONFIG_HOME_ENV = "XDG_CONFIG_HOME"
FOLDER = "ctf-flightdeck"
CONFIG_FILE = "config.toml"
KEYS_FILE = "keys.env"
THEMES = "themes"  # beside the config file that is read (config._console)


@dataclass(frozen=True)
class Found:
    """One of flightdeck's files, found where it was looked for: `path` is the one read."""

    name: str  # CONFIG_FILE or KEYS_FILE
    path: Path
    old: Path | None  # ~/.config/ctf-flightdeck/NAME when $XDG_CONFIG_HOME moved the folder and it is there; else None


def folder(environ: Mapping[str, str] = os.environ) -> Path:
    """$XDG_CONFIG_HOME/ctf-flightdeck when that is an absolute path, else
    ~/.config/ctf-flightdeck. RuntimeError when there is no home folder and no such variable."""
    base = environ.get(CONFIG_HOME_ENV, "")
    if os.path.isabs(base):
        return Path(base) / FOLDER
    return old_folder()


def old_folder() -> Path:
    """~/.config/ctf-flightdeck, where flightdeck kept its config before P94 whatever
    $XDG_CONFIG_HOME said. RuntimeError when there is no home folder."""
    return Path.home() / ".config" / FOLDER


def moved(environ: Mapping[str, str] = os.environ) -> bool:
    """Whether $XDG_CONFIG_HOME puts the folder somewhere other than ~/.config/ctf-flightdeck
    (False when it is unset, relative, or ~/.config itself)."""
    base = environ.get(CONFIG_HOME_ENV, "")
    if not os.path.isabs(base):
        return False
    try:
        old = old_folder()
    except RuntimeError:  # no home folder: there is no old place to have files in
        return False
    return not _same(Path(base) / FOLDER, old)


def find(name: str, environ: Mapping[str, str] = os.environ) -> Found:
    """Where `name` (CONFIG_FILE or KEYS_FILE) is read from: in folder(), unless
    $XDG_CONFIG_HOME moved the folder and the file is only at the old place, which is then
    the one read. RuntimeError as folder()."""
    new = folder(environ) / name
    if not moved(environ):
        return Found(name, new, None)
    old = old_folder() / name
    if not _there(old):
        return Found(name, new, None)
    if _there(new):
        return Found(name, new, old)  # both: the new one is read, the old one is not
    return Found(name, old, old)  # only at the old place: read there


def notes(environ: Mapping[str, str] = os.environ, *, config_named: bool | None = None,
          keys_named: bool | None = None) -> list[str]:
    """One line for each file of flightdeck's at ~/.config/ctf-flightdeck that $XDG_CONFIG_HOME
    moved the folder away from: whether it is read there or not. [] when nothing is there, the
    folder was not moved, or the file is one $FLIGHTDECK_CONFIG / $FLIGHTDECK_KEYS names
    (`config_named` / `keys_named`: None reads those variables from `environ`). No line holds
    a file's content."""
    if not moved(environ):
        return []
    from .config import CONFIG_ENV
    from .keys import KEYS_ENV

    config_named = bool(environ.get(CONFIG_ENV)) if config_named is None else config_named
    keys_named = bool(environ.get(KEYS_ENV)) if keys_named is None else keys_named
    base = folder(environ)
    lines = []
    config_at = None
    for name, named in ((CONFIG_FILE, config_named), (KEYS_FILE, keys_named)):
        if named:
            continue
        found = find(name, environ)
        if name == CONFIG_FILE:
            config_at = found.path.parent
        if found.old is None:
            continue
        if found.path == found.old:
            lines.append(f"{show(found.old)} is read from the old place: ${CONFIG_HOME_ENV} puts flightdeck's config in "
                         f"{show(base)}, which has no {name}; move it there to keep your files together")
        else:
            lines.append(f"{show(found.old)} is not read: ${CONFIG_HOME_ENV} puts flightdeck's config in {show(base)}, "
                         f"which has its own {name}; remove the old one, or move what you need into the new one")
    if config_at is not None:  # the themes folder is beside the config that is read: one left at the other place is not
        other = old_folder() if _same(config_at, base) else base
        if _there(other / THEMES) and not _same(other, config_at):
            lines.append(f"{show(other / THEMES)} is not read: your themes are read from {show(config_at / THEMES)}, "
                         f"beside the config that is read; move the theme files there")
    return lines


def show(path: Path) -> str:
    """The path with the home folder as ~, for a line the player reads."""
    with suppress(RuntimeError, ValueError):
        return f"~/{path.relative_to(Path.home())}"
    return str(path)


def _there(path: Path) -> bool:
    return os.path.lexists(path)  # a link to nowhere is a file that is there and broken: the reader says so


def _same(one: Path, other: Path) -> bool:
    try:
        return os.path.realpath(one) == os.path.realpath(other)
    except OSError:
        return one == other
