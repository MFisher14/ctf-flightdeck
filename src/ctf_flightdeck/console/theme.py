"""The console's look: colors, chips and the header segments.

Only plain Unicode is used (╱ between header segments, ╭╮ rounded borders), so it works
in any terminal font; no Nerd Font is needed. Every colored shape is whole cells of
background color: no half-block caps or glyph edges whose size depends on the font, so
no color shows past a corner.

Every colour comes from one palette (themes.Palette): the one in use (use(), active()). The
console's modules read a colour by its old name, `theme.GREEN`, and get the palette's colour
for that name's role (NAMES) at the moment they draw, so a colour must be read when something
is drawn, never kept in a module-level table: one kept at import would stay the default's.
css_variables() and textual() give the same palette to the Textual styles, so one palette
colours the whole console.
"""

from __future__ import annotations

from rich.style import Style
from rich.text import Text
from textual.theme import Theme

from .. import themes
from ..core.model import AlertKind

NAMES = {  # a colour's name in the console's code: its role in the palette
    "ACCENT": "accent",
    "BLUE": "brand",
    "SEGMENT": "segment",
    "PAGE": "page",
    "GREEN": "ok",
    "RED": "error",
    "YELLOW": "warn",
    "CYAN": "info",
    "PURPLE": "pending",
    "MUTED": "muted",
    "BORDER": "border",
    "SELECTED": "selected",
    "INK": "ink",
    "WHITE": "ink_light",
    "TEXT": "text",
}

_active: themes.Palette = themes.DEFAULT


def use(palette: themes.Palette) -> None:
    """Draw with `palette` from now on. An app calls this before it is built (and set_palette
    when the player changes the theme); what is already on screen keeps its colours until it
    is drawn again."""
    global _active
    _active = palette


def active() -> themes.Palette:
    """The palette in use."""
    return _active


def __getattr__(name: str) -> str:
    """`theme.GREEN` and the other names of NAMES: that role's colour in the palette in use."""
    role = NAMES.get(name)
    if role is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return getattr(_active, role)


def alert_colors(kind: AlertKind) -> tuple[str, str]:
    """(text, background) for an alert's chip; course alerts are red."""
    palette = _active
    if kind is AlertKind.FLAG:
        return palette.ink, palette.ok
    if kind is AlertKind.BUDGET:
        return palette.ink, palette.accent
    if kind is AlertKind.TEAMMATE:
        return palette.ink, palette.info
    return palette.ink_light, palette.error


def pending_colors() -> tuple[str, str]:
    """(text, background) for the chip of a lane that waits for the player."""
    return _active.ink_light, _active.pending


def chip(text: str, fg: str, bg: str) -> Text:
    """A small solid label, one cell of padding each side: ` flag `."""
    return Text(f" {text} ", style=Style(color=fg, bgcolor=bg, bold=True), no_wrap=True)


def key_chip(key: str) -> Text:
    return chip(key, _active.ink, _active.accent)


def segments(parts: list[tuple[str, str, str, bool]]) -> Text:
    """Header pieces (text, fg, bg, bold) as solid segments with a ╱ between them.

    The ╱ sits on the page, not on either segment, so each segment is a clean block."""
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, (text, fg, bg, bold) in enumerate(parts):
        if i:
            out.append("╱", Style(color=_active.border))
        out.append(f" {text} ", Style(color=fg, bgcolor=bg, bold=bold))
    return out


def css_variables() -> dict[str, str]:
    """The palette in use as the variables the console's own styles are written in
    (`$fd-page`, `$fd-border`...)."""
    palette = _active
    return {
        "fd-page": palette.page,
        "fd-surface": palette.surface,
        "fd-border": palette.border,
        "fd-muted": palette.muted,
        "fd-accent": palette.accent,
        "fd-selected": palette.selected,
        "fd-selected-focus": palette.selected_focus,
    }


def textual() -> Theme:
    """The palette in use as a Textual theme, named fd-NAME: what Textual's own styles
    (`$background`, `$surface`, `$accent`, `$warning`...) are drawn from. `secondary` and `panel`
    are left for Textual to derive."""
    palette = _active
    return Theme(
        name=f"fd-{palette.name}",
        primary=palette.brand,
        accent=palette.accent,
        warning=palette.warn,
        error=palette.error,
        success=palette.ok,
        foreground=palette.text,
        background=palette.page,
        surface=palette.surface,
        dark=palette.dark,
        variables=css_variables(),
    )
