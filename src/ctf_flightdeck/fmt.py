"""Compact number and time formats shared by the console and the deck."""

from __future__ import annotations


def tokens(n: int) -> str:
    """950, 210k, 4.1M. Rounds before choosing the unit, so 999,600 is 1.0M, not 1000k."""
    if n < 1_000:
        return str(n)
    if round(n / 1_000) < 1_000:
        return f"{round(n / 1_000)}k"
    return f"{n / 1_000_000:.1f}M"


def dollars(x: float | None, *, short: bool = False) -> str:
    """Dollar amount without the sign. short=True drops the leading zero: ".21"."""
    if x is None:
        return "-"
    if round(x, 2) >= 100:
        return f"{x:.0f}"
    if 0 < x < 0.005:  # a real spend that would round to 0.00: say so rather than show nothing
        return "<.01" if short else f"{x:.4f}"
    text = f"{x:.2f}"
    return text[1:] if short and text.startswith("0.") else text


def duration(seconds: float) -> str:
    """Idle-style duration: 45s, 6m, 2h05."""
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    return f"{s // 3600}h{(s % 3600) // 60:02d}"


def clock(seconds: float) -> str:
    """Event clock: T+01:42:10."""
    s = int(seconds)
    return f"T+{s // 3600:02d}:{(s % 3600) // 60:02d}:{s % 60:02d}"
