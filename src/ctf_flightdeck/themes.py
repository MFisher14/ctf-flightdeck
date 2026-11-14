"""The console's palettes: the built-in themes, and a player's own theme file.

A palette is 17 colours by role (ROLES: `page` behind everything, `ok` for running and solved,
`error` for what needs the player...), whether it is dark, and the Pygments style of the diff
view. The console draws every colour from the one in use (console/theme.py), so a theme changes
colours only, never a shape or a glyph.

`[console] theme` in the config names a built-in (BUILTIN), or NAME for the file NAME.toml in
the `themes` folder beside the config:

    base = "flightdeck"     # optional: a built-in the colours left out come from
    dark = true             # optional with base
    syntax = "monokai"      # optional with base: the Pygments style of the diff view

    [colors]                # "#rrggbb" only
    accent = "#ff5fd7"

Without `base`, every colour, `dark` and `syntax` are required. A file is read only for the name
it is asked for (load); nothing in the folder is read because it is there.

A theme the player could not read the console in is refused: each pair of CONTRAST (the text of
a chip on its chip, a state's colour on the page) must have a WCAG contrast of MIN_CONTRAST or
more. So are an unknown key, a colour that is not # and six hex digits, and a file with a
built-in's name. Every ThemeError names the file and the key and shows no value from the file:
a string in a file of the player's could be a key pasted into the wrong place (as config.py).

Pure: no rich and no textual here, so the config can load a palette without a console.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .text import untrusted

ROLES = (  # in the order a theme file's example gives them
    "page",  # behind everything
    "surface",  # dialogs, the command menu
    "border",
    "text",
    "muted",  # labels, hints, finished lanes
    "accent",  # keys, the focused border, the player's own messages
    "selected",
    "selected_focus",
    "brand",  # the flightdeck segment, "sending", flightdeck's own lines
    "segment",  # header segments
    "ok",  # running, solved, flag
    "error",  # killed, blocked, course alerts, "need you"
    "warn",  # paused, parked, held, problems
    "info",  # teammates, model names, take-over
    "pending",  # waiting for the player
    "ink",  # text on ok, warn, accent and info chips
    "ink_light",  # text on brand, error and pending chips
)
NAME = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")  # a theme's name: its file is NAME.toml
MAX_BYTES = 65536  # the largest theme file read: 64 KiB
MIN_CONTRAST = 3.0  # WCAG's floor for large text and for the parts of an interface

_KEYS = ("base", "dark", "syntax", "colors")
_COLOUR = re.compile(r"#[0-9a-fA-F]{6}")
_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")


class ThemeError(Exception):
    """A theme cannot be used. The message names the file and the key, never a value."""


class NoSuchTheme(ThemeError):
    """No built-in theme and no theme file has the name asked for. The message starts "names no
    theme: " and does not repeat the name, so a caller puts what named it in front."""


@dataclass(frozen=True)
class Palette:
    name: str
    dark: bool
    syntax: str  # a Pygments style's name
    page: str
    surface: str
    border: str
    text: str
    muted: str
    accent: str
    selected: str
    selected_focus: str
    brand: str
    segment: str
    ok: str
    error: str
    warn: str
    info: str
    pending: str
    ink: str
    ink_light: str


def _palette(name: str, dark: bool, syntax: str, *colours: str) -> Palette:
    return Palette(name, dark, syntax, **dict(zip(ROLES, colours, strict=True)))


BUILTIN: dict[str, Palette] = {
    palette.name: palette
    for palette in (
        #                                     page       surface    border     text       muted      accent
        #                                     selected   sel_focus  brand      segment    ok         error
        #                                     warn       info       pending    ink        ink_light
        _palette("flightdeck", True, "monokai", "#121212", "#1e1e1e", "#3c4146", "#e0e0e0", "#7d8590", "#ffa62b",
                 "#1b2633", "#22324a", "#0178d4", "#2f3437", "#4ebf71", "#e0475b",
                 "#e5c07b", "#3fb8e0", "#a66bff", "#0b0b0b", "#ffffff"),
        _palette("light", False, "default", "#fafafa", "#ececec", "#b4b9c0", "#1f2328", "#646c76", "#b35900",
                 "#dbe7f5", "#c5d9f0", "#0b63b0", "#e2e4e8", "#1a7f37", "#cf222e",
                 "#8a6100", "#0a6f94", "#8250df", "#ffffff", "#ffffff"),
        _palette("nord", True, "nord", "#2e3440", "#3b4252", "#4c566a", "#d8dee9", "#97a1b5", "#d08770",
                 "#3b4252", "#434c5e", "#5e81ac", "#434c5e", "#a3be8c", "#c5616c",
                 "#ebcb8b", "#88c0d0", "#a2739c", "#2e3440", "#eceff4"),
        _palette("gruvbox", True, "gruvbox-dark", "#282828", "#32302f", "#504945", "#ebdbb2", "#a89984", "#fe8019",
                 "#3c3836", "#504945", "#458588", "#3c3836", "#b8bb26", "#e5493b",
                 "#fabd2f", "#83a598", "#b16286", "#1d2021", "#fbf1c7"),
        _palette("dracula", True, "dracula", "#282a36", "#343746", "#44475a", "#f8f8f2", "#9aa4cc", "#ffb86c",
                 "#343746", "#44475a", "#6272a4", "#44475a", "#50fa7b", "#e0405f",
                 "#f1fa8c", "#8be9fd", "#9a67ea", "#21222c", "#f8f8f2"),
    )
}
DEFAULT = BUILTIN["flightdeck"]

CONTRAST: tuple[tuple[str, str, str], ...] = (  # (foreground role, background role, what the pair shows)
    ("ink", "ok", "the AUTOPILOT chip and a flag's alert"),
    ("ink", "warn", 'the "queue held" chip'),
    ("ink", "accent", "the key chips"),
    ("ink", "info", "a teammate's alert"),
    ("ink_light", "error", '"▲ N need you"'),
    ("ink_light", "pending", "the chip of a lane that waits for you"),
    ("ink_light", "brand", 'the flightdeck segment and the "sending" chip'),
    ("text", "page", "the console's text"),
    ("text", "surface", "the text of a dialog and of the command menu"),
    ("text", "segment", "the header"),
    ("text", "selected_focus", "the selected row"),
    ("muted", "page", "labels and hints"),
    ("ok", "page", "a running or solved lane"),
    ("error", "page", "a killed lane and a blocked challenge"),
    ("warn", "page", "a paused lane and a problem"),
    ("info", "page", "model names and a teammate's solves"),
    ("pending", "page", "what waits for you"),
    ("accent", "page", "the focused border and your own messages"),
    ("brand", "page", "flightdeck's own lines"),
)


def contrast(a: str, b: str) -> float:
    """The WCAG 2 contrast ratio of two "#rrggbb" colours: 1.0 (the same) to 21.0 (black on white)."""
    lighter, darker = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (lighter + 0.05) / (darker + 0.05)


def _luminance(colour: str) -> float:
    def linear(channel: int) -> float:
        value = channel / 255
        return value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4

    red, green, blue = (linear(int(colour[i:i + 2], 16)) for i in (1, 3, 5))
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def weak_pairs(palette: Palette) -> list[tuple[str, str, str, float]]:
    """The rows of CONTRAST the palette has under MIN_CONTRAST, each with its ratio."""
    out = []
    for fg, bg, what in CONTRAST:
        ratio = contrast(getattr(palette, fg), getattr(palette, bg))
        if ratio < MIN_CONTRAST:
            out.append((fg, bg, what, ratio))
    return out


def load(name: str, folder: Path | None) -> Palette:
    """The palette called `name`: the file NAME.toml in `folder` (the `themes` folder beside
    the config; None: there is none), else a built-in. NoSuchTheme when it is neither;
    ThemeError when the file cannot be used, or has a built-in's name."""
    if not isinstance(name, str) or NAME.fullmatch(name) is None:  # also: never a path out of the folder
        raise ThemeError("a theme's name is lower-case letters, digits, - and _, at most 32 characters")
    if folder is not None:
        file = folder / f"{name}.toml"
        try:
            there = file.exists() or file.is_symlink()
        except OSError as exc:  # a folder that cannot be searched: said, not a bare PermissionError
            raise ThemeError(f"{file}: cannot look for it ({exc.strerror})") from None
        if there:
            if name in BUILTIN:
                raise ThemeError(f"{file} has a built-in theme's name: rename the file")
            return parse(_read(file), file)
    if name in BUILTIN:
        return BUILTIN[name]
    own = f"; your own is NAME.toml in {folder}" if folder is not None else ""
    raise NoSuchTheme(f"names no theme: built in are {', '.join(BUILTIN)}{own}")


def names(folder: Path | None) -> tuple[list[str], list[str]]:
    """(the built-in themes, the player's own): the own ones are the stems of the .toml files
    in `folder` that are theme names, in order. No file is opened, so one listed may not load;
    one with a built-in's name is left out (load refuses it)."""
    own: list[str] = []
    if folder is not None:
        try:
            found = sorted(entry.name for entry in folder.iterdir())
        except OSError:  # no themes folder: no themes of the player's own
            found = []
        for entry in found:
            stem, dot, suffix = entry.rpartition(".")
            if dot and suffix == "toml" and NAME.fullmatch(stem) and stem not in BUILTIN:
                own.append(stem)
    return list(BUILTIN), own


def parse(text: str, source: Path) -> Palette:
    """The palette a theme file's `text` gives; `source` is the file, which every error names
    and whose stem is the theme's name."""
    if source.stem in BUILTIN:
        raise ThemeError(f"{source} has a built-in theme's name: rename the file")
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ThemeError(f"{source}: {untrusted(str(exc), one_line=True)}") from None
    except (ValueError, RecursionError) as exc:  # a number too long to read, tables nested too deep
        raise ThemeError(f"{source}: cannot be read as TOML ({type(exc).__name__})") from None
    _known(source, (), doc, _KEYS)
    base = None
    if "base" in doc:
        if not isinstance(doc["base"], str) or doc["base"] not in BUILTIN:
            raise ThemeError(f"{source}: base must be {_options(tuple(BUILTIN))}")
        base = BUILTIN[doc["base"]]
    colours = _colours(source, doc.get("colors", {}), base)
    dark = doc.get("dark", base.dark if base else None)
    if dark is None:
        raise ThemeError(f"{source}: dark is required without base: true for a dark theme, false for a light one")
    if not isinstance(dark, bool):
        raise ThemeError(f"{source}: dark must be true or false")
    syntax = doc.get("syntax", base.syntax if base else None)
    if syntax is None:
        raise ThemeError(f'{source}: syntax is required without base: the Pygments style of the diff view, like "monokai"')
    if not isinstance(syntax, str) or syntax not in _pygments_styles():
        raise ThemeError(f"{source}: syntax names no Pygments style")
    palette = Palette(name=source.stem, dark=dark, syntax=syntax, **colours)
    for fg, bg, what, ratio in weak_pairs(palette):
        shown = math.floor(ratio * 10) / 10  # never rounded up to the floor it is under
        raise ThemeError(f"{source}: colors.{fg} on colors.{bg} has contrast {shown:.1f}, under {MIN_CONTRAST:.1f}: "
                         f"{what} could not be read")
    return palette


def _colours(source: Path, table: object, base: Palette | None) -> dict[str, str]:
    if not isinstance(table, dict):
        raise ThemeError(f"{source}: colors must be a table ([colors])")
    _known(source, ("colors",), table, ROLES)
    for role in ROLES:
        if role in table and (not isinstance(table[role], str) or _COLOUR.fullmatch(table[role]) is None):
            raise ThemeError(f'{source}: colors.{role} must be a colour written as # and six hex digits, like "#ffa62b"')
    if base is None:
        missing = [role for role in ROLES if role not in table]
        if missing:
            raise ThemeError(f"{source}: missing colors: {', '.join(missing)} (give every colour, or set "
                             f'base = "flightdeck" to start from a built-in theme)')
        return {role: table[role].lower() for role in ROLES}
    return {role: table[role].lower() if role in table else getattr(base, role) for role in ROLES}


def _read(file: Path) -> str:
    """The file's text. It is opened without waiting (O_NONBLOCK) and read only when it is a
    regular file: a FIFO or a device would otherwise hold the console until something writes to it.
    The kind is checked on the bare descriptor, before it is wrapped (os.fdopen raises on a
    directory and leaves the descriptor open), and the descriptor is closed on every path."""
    try:
        descriptor = os.open(file, os.O_RDONLY | os.O_NONBLOCK)
        try:
            mode = os.fstat(descriptor).st_mode
            if stat.S_ISDIR(mode):
                raise IsADirectoryError
            if not stat.S_ISREG(mode):
                raise ThemeError(f"{file}: is not a regular file, so it is not read")
            handle = os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise
        with handle:  # the handle owns the descriptor now: closing it closes the descriptor
            raw = handle.read(MAX_BYTES + 1)
    except IsADirectoryError:
        raise ThemeError(f"{file}: is a directory, not a theme file") from None
    except OSError as exc:
        raise ThemeError(f"{file}: cannot read it ({exc.strerror})") from None
    if len(raw) > MAX_BYTES:
        raise ThemeError(f"{file}: larger than {MAX_BYTES // 1024} KiB")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ThemeError(f"{file}: is not UTF-8 text") from None


def _known(source: Path, where: tuple[str, ...], table: dict, known: tuple[str, ...]) -> None:
    """Unknown keys are errors: a typo must not leave the base's colour silently in place."""
    unknown = [key for key in table if key not in known]
    if not unknown:
        return
    shown = ", ".join(_key(*where, key) for key in unknown)
    inside = f"known in {_key(*where)}" if where else "known"
    raise ThemeError(f"{source}: unknown key {shown} ({inside}: {', '.join(known)})")


def _key(*parts: str) -> str:
    """A dotted TOML key, with the parts that are not bare keys quoted (as config._key)."""
    return ".".join(part if _BARE_KEY.fullmatch(part) else json.dumps(part) for part in parts)


def _options(choices: tuple[str, ...]) -> str:
    """`"a", "b" or "c"`."""
    quoted = [f'"{choice}"' for choice in choices]
    return quoted[0] if len(quoted) == 1 else f"{', '.join(quoted[:-1])} or {quoted[-1]}"


def _pygments_styles() -> frozenset[str]:
    """The names Pygments has a style for. Pygments comes with rich, which draws the diff view;
    the names are listed, never looked up by importing what the file names."""
    from pygments.styles import get_all_styles

    return frozenset(get_all_styles())

