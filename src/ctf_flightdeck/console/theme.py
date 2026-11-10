"""The console's look: colors, chips and the slanted header segments.

Only plain Unicode is used (╱ cuts, ▐▌ chip caps, ╭╮ rounded borders), so it works in
any terminal font; no Nerd Font is needed.
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
    """A small label with half-block caps: ▐flag▌."""
    out = Text(no_wrap=True)
    out.append("▐", Style(color=bg))
    out.append(text, Style(color=fg, bgcolor=bg, bold=True))
    out.append("▌", Style(color=bg))
    return out


def key_chip(key: str) -> Text:
    return chip(key, INK, ACCENT)


def segments(parts: list[tuple[str, str, str, bool]]) -> Text:
    """Header pieces (text, fg, bg, bold) as slanted segments cut apart by ╱."""
    out = Text(no_wrap=True, overflow="ellipsis")
    for i, (text, fg, bg, bold) in enumerate(parts):
        out.append(f" {text} ", Style(color=fg, bgcolor=bg, bold=bold))
        following = parts[i + 1][2] if i + 1 < len(parts) else None
        out.append("╱", Style(color=PAGE, bgcolor=following))
    return out
