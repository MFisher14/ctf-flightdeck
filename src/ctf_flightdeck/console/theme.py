"""The console's look: colors, chips and the header segments.

Only plain Unicode is used (╱ between header segments, ╭╮ rounded borders), so it works
in any terminal font; no Nerd Font is needed. Every colored shape is whole cells of
background color: no half-block caps or glyph edges whose size depends on the font, so
no color shows past a corner.
"""

from __future__ import annotations

from rich.style import Style
from rich.text import Text

from ..core.model import AlertKind

ACCENT = "#ffa62b"
BLUE = "#0178d4"
SEGMENT = "#2f3437"
PAGE = "#121212"
GREEN = "#4ebf71"
RED = "#e0475b"
YELLOW = "#e5c07b"
CYAN = "#3fb8e0"
PURPLE = "#a66bff"
MAGENTA = "#ff5fd7"
MUTED = "#7d8590"
BORDER = "#3c4146"
SELECTED = "#1b2633"
INK = "#0b0b0b"
WHITE = "#ffffff"
TEXT = "#e0e0e0"

_ALERT_COLORS = {
    AlertKind.FLAG: (INK, GREEN),
    AlertKind.BUDGET: (INK, ACCENT),
    AlertKind.TEAMMATE: (INK, CYAN),
}
PENDING_COLORS = (WHITE, PURPLE)


def alert_colors(kind: AlertKind) -> tuple[str, str]:
    """(text, background) for an alert's chip; course alerts are red."""
    return _ALERT_COLORS.get(kind, (WHITE, RED))


def chip(text: str, fg: str, bg: str) -> Text:
    """A small solid label, one cell of padding each side: ` flag `."""
    return Text(f" {text} ", style=Style(color=fg, bgcolor=bg, bold=True), no_wrap=True)


def key_chip(key: str) -> Text:
    return chip(key, INK, ACCENT)


def segments(parts: list[tuple[str, str, str, bool]]) -> Text:
    """Header pieces (text, fg, bg, bold) as solid segments with a ╱ between them.

    The ╱ sits on the page, not on either segment, so each segment is a clean block."""
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, (text, fg, bg, bold) in enumerate(parts):
        if i:
            out.append("╱", Style(color=BORDER))
        out.append(f" {text} ", Style(color=fg, bgcolor=bg, bold=bold))
    return out
