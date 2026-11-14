"""Changing the player's config file in place: one edit that is checked, or the file as it was.

`flightdeck init` writes a whole config (setup.py). Afterwards flightdeck changes the file only
through rewrite(), here: `pack install` sets `[l1] pack` (pack.write_config), `plugin add`
appends `[plugins.NAME]` (plugins.manifest.enable), and the console keeps the theme and the
layout the player picked (save_console). The shape is the same for all three:

1. read the file as it is, byte for byte (its line endings too);
2. make the new text, and write it over the old one in place, so a config that is a link
   (a dotfiles folder) stays a link and keeps its mode;
3. load the file again and check that it holds the change;
4. when it does not load, or does not hold the change, write the old text back.

Every failure is an EditError that names the file, says why, and says how the file was left.
Nothing here prints a value from the file: a string in a player's config could be a key pasted
into the wrong place (as config.py).
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable, Mapping
from pathlib import Path

from . import themes
from .config import LAYOUTS, ConfigError, load_console

HEADER = re.compile(r"^\s*(\[\[?)\s*([^\[\]]+?)\s*\]\]?\s*(#.*)?$")  # [table] or [[table]], alone on its line


class EditError(Exception):
    """The config was not changed. The message names the file, why, and how the file was left."""


def set_keys(text: str, table: str, lines: Mapping[str, str | None]) -> str:
    """`text` (a config file) with each key of `lines` set in `[table]`: its value is the whole
    line that sets it (`theme = "nord"`), or None to comment out a line that is there.
    Everything else stays as it is, comments and line endings included. A key that is set goes
    where its line was; else under a commented example of it (`# theme = ...`), which stays;
    else at the table's end, above a block of comments that a blank line sets apart and the
    next table follows (they are that table's). A table that is not there is added at the end
    of the file.

    It works on lines, not on TOML: a key set on a line of a multi-line string, or a table
    written another way (`console.theme = ...`, `["console"]`), is not seen. A caller that must
    know checks what the result parses to (save_console), and every caller loads the file."""
    cr = "\r" if "\r\n" in text else ""
    rows = text.split("\n")
    if rows[-1] == "":
        rows.pop()  # the text ended with a newline (or is empty): no last row
    start = next((i for i, row in enumerate(rows) if (m := HEADER.match(row)) and m.group(1) == "[" and m.group(2) == table), None)
    if start is None:
        if all(line is None for line in lines.values()):
            return text  # nothing to set, and no table to comment a line out of
        if rows and rows[-1].strip():
            rows.append(cr)
        rows.append(f"[{table}]{cr}")
        start = len(rows) - 1
    end = next((i for i in range(start + 1, len(rows)) if HEADER.match(rows[i])), len(rows))
    body = rows[start + 1:end]
    for key, line in lines.items():
        body = _set_key(body, key, line, cr, followed=end < len(rows))
    return "\n".join(rows[:start + 1] + body + rows[end:]) + "\n"


def _set_key(body: list[str], key: str, line: str | None, cr: str, *, followed: bool) -> list[str]:
    live = re.compile(rf"^\s*{re.escape(key)}\s*=")
    dead = re.compile(rf"^\s*#\s*{re.escape(key)}\s*=")
    at = next((i for i, row in enumerate(body) if live.match(row)), None)
    if at is not None:
        if line is None:
            return body[:at] + ["# " + body[at].lstrip()] + body[at + 1:]
        return body[:at] + [line + cr] + body[at + 1:]
    if line is None:
        return body
    at = next((i for i, row in enumerate(body) if dead.match(row)), None)
    if at is not None:
        return body[:at + 1] + [line + cr] + body[at + 1:]  # under the example line, which stays
    last = _last(body, len(body) - 1)
    if followed and last == len(body) - 1 and body[last].lstrip().startswith("#"):
        top = last  # comments right above the next table: whose they are is what is over them
        while top >= 0 and body[top].lstrip().startswith("#"):
            top -= 1
        if top >= 0 and not body[top].strip():
            last = _last(body, top)
    return body[:last + 1] + [line + cr] + body[last + 1:]


def _last(body: list[str], until: int) -> int:
    """The last row of `body`, at `until` or before, that is not blank; -1 when there is none."""
    return next((i for i in range(until, -1, -1) if body[i].strip()), -1)


def rewrite(path: Path, change: Callable[[str], str], check: Callable[[], None], *, what: str,
            first: str = "run `flightdeck init` first") -> bool:
    """Write change(the config's text) over the config at `path`, then call `check`, which
    loads the file and raises ConfigError when it does not load or does not hold the change:
    the old text is then written back. False when the change leaves the text as it is (nothing
    is written, and nothing is checked). `what` is the change in a few words ("the pack"), for
    the message; `first` is what to do when there is no config. `change` may raise to refuse:
    nothing is written before it returns."""
    try:
        with path.open(encoding="utf-8", newline="") as handle:  # newline="": line endings as they are
            before = handle.read()
    except FileNotFoundError:
        raise EditError(f"there is no config at {path}: {first}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise EditError(f"cannot read the config {path}: {exc}") from None
    after = change(before)
    if after == before:
        return False
    try:
        _write(path, after)
    except OSError as exc:
        raise EditError(f"cannot write the config {path} ({exc.strerror or type(exc).__name__}): {_left(path, before)}") from None
    try:
        check()
    except ConfigError as exc:
        left = _left(path, before)
        if left != PUT_BACK:
            raise EditError(f"the config did not load with {what} in it ({exc}), and {left}") from None
        raise EditError(f"the config did not load with {what} in it, so it was put back as it was: {exc}") from None
    return True


AS_IT_WAS = "it is as it was"
PUT_BACK = "it was put back as it was"


def _write(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def _left(path: Path, before: str) -> str:
    """Make the file at `path` hold `before` again, and say how it was left."""
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            if handle.read() == before:
                return AS_IT_WAS  # the write never began (a file that cannot be written)
    except (OSError, UnicodeDecodeError):
        pass  # not readable now: writing the old text back is still the thing to try
    try:
        _write(path, before)
    except OSError as exc:
        return f"it could not be put back as it was ({exc.strerror or type(exc).__name__}): look at it before the next run"
    return PUT_BACK


# ---------------------------------------------------------------------- the config's [console] table

CONSOLE_KEYS = ("layout", "theme")  # what a console may keep, in the order they are written and said


def console_lines(*, theme: str | None = None, layout: str | None = None) -> dict[str, str]:
    """The config lines that keep a theme and a layout, by key (CONSOLE_KEYS; None: not that
    one). ValueError for a value that is not a layout or not a theme's name: nothing a player
    typed gets here unchecked."""
    if layout is not None and layout not in LAYOUTS:
        raise ValueError(f"layout must be one of {', '.join(LAYOUTS)}")
    if theme is not None and themes.NAME.fullmatch(theme) is None:
        raise ValueError("a theme's name is lower-case letters, digits, - and _, at most 32 characters")
    values = {"layout": layout, "theme": theme}
    return {key: f'{key} = "{values[key]}"' for key in CONSOLE_KEYS if values[key] is not None}


def save_console(path: Path, *, theme: str | None = None, layout: str | None = None) -> bool:
    """Keep a theme, a layout or both in the config at `path`: `theme = "NAME"` and
    `layout = "NAME"` under `[console]`, every other line as it was. False when the file says
    so already. EditError when it could not be done, with the file as it was.

    Before anything is written, the new text must parse to what the old text parses to with
    those keys set and nothing else changed: so a config flightdeck cannot edit by lines (see
    set_keys), or one that is not TOML, is refused and never touched. After the write the
    [console] table is loaded as a console loads it (config.load_console: the theme's file
    too), and the old text goes back when it does not load."""
    lines = console_lines(theme=theme, layout=layout)
    if not lines:
        raise ValueError("save_console needs a theme or a layout")
    wanted = {key: value for key, value in (("layout", layout), ("theme", theme)) if value is not None}
    by_hand = f"write {' and '.join(lines.values())} under [console] yourself"

    def change(before: str) -> str:
        try:
            doc = tomllib.loads(before)
        except (ValueError, RecursionError):  # TOMLDecodeError is a ValueError
            raise EditError(f"{path} is not valid TOML, so it was left as it is: mend it, or {by_hand}") from None
        after = set_keys(before, "console", lines)
        table = doc.get("console", {})
        try:
            got = tomllib.loads(after)
        except (ValueError, RecursionError):
            got = None
        if not isinstance(table, dict) or got != {**doc, "console": {**table, **wanted}}:
            raise EditError(f"flightdeck could not place the line in {path}, which was left as it is: {by_hand}")
        return after

    def check() -> None:
        console = load_console(path)
        for key, value in wanted.items():
            if getattr(console, key) != value:
                raise ConfigError(f"{path}: [console] did not take {key}")

    return rewrite(path, change, check, what=" and ".join(f"the {key}" for key in wanted))
