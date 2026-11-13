"""B-211: the clock line -- current Eastern time and the next-release countdown, for every agent turn.

Agents confused the time and date during events (Huntress Day 24-26: wrong day, a stale "now" from a
log line). The fix is to never let an agent work out the time from memory: a Claude Code hook injects
this line on every prompt, and any agent (Codex has no per-turn hook) runs `python -m ctf clock`.

    clock_line(now, profile)           -> one block of text: now in ET (with EST/EDT) and UTC, the next
                                          release of the event (ctf.quota.next_release: the event
                                          start, [allowance] releases and daily_release) with a
                                          countdown, and where the event stands (starts / ends / ended)
    clock_line(now, None, reason=...)  -> the clock alone, plus why there is no countdown (named)
    hook_response(text, event)         -> the Claude Code hook JSON (additionalContext)

`now` is always passed in (epoch seconds): the caller owns the clock, so tests drive it with an
injected time and nothing here reads the wall clock.
"""
from __future__ import annotations

import datetime as _dt
import zoneinfo

from . import quota as _quota
from .event import EventProfile

ET = zoneinfo.ZoneInfo("America/New_York")
UTC = _dt.timezone.utc
PREFIX = "CLOCK"
HOOK_EVENTS = ("UserPromptSubmit", "SessionStart")


def fmt_et(t: float) -> str:
    """`Thu 2026-11-12 14:03 EST`: the weekday and the date are spelled out, and the zone abbreviation
    says whether daylight time applies, so a reader never has to work either out."""
    return _dt.datetime.fromtimestamp(t, ET).strftime("%a %Y-%m-%d %H:%M %Z")


def fmt_utc(t: float) -> str:
    return _dt.datetime.fromtimestamp(t, UTC).strftime("%H:%M UTC")


def fmt_delta(seconds: float) -> str:
    """A countdown, floored: `2d 03h 04m`, `3h 04m`, `4m 05s`, `45s`. Negative input is an error:
    a countdown to a time already past is a bug in the caller."""
    if seconds < 0:
        raise ValueError(f"countdown to a past time ({seconds:.0f} s)")
    s = int(seconds)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    if d:
        return f"{d}d {h:02d}h {m:02d}m"
    if h:
        return f"{h}h {m:02d}m"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def event_lines(profile: EventProfile, now: float) -> list[str]:
    start, end = _quota.event_span(profile)   # the same reading next_release uses
    slug = profile.slug
    out = []
    rel = _quota.next_release(profile, now)
    if rel is None:
        out.append(f"Next release ({slug}): none ahead (no event start, [allowance] release or "
                   "daily_release is after now)")
    else:
        out.append(f"Next release ({slug}): {fmt_et(rel)}, in {fmt_delta(rel - now)}")
    if now < start:
        out.append(f"Event {slug}: not started; starts {fmt_et(start)}, in {fmt_delta(start - now)}")
    elif now < end:
        out.append(f"Event {slug}: running; ends {fmt_et(end)}, in {fmt_delta(end - now)}")
    else:
        out.append(f"Event {slug}: over; ended {fmt_et(end)}")
    return out


def clock_line(now: float, profile: EventProfile | None, *, reason: str | None = None) -> str:
    """The clock block for `now`. With no profile, `reason` (required) says why there is no countdown,
    so a missing event is named on every turn instead of the countdown silently disappearing."""
    lines = [f"{PREFIX}: now {fmt_et(now)} ({fmt_utc(now)}). Take the time from this line, not from memory."]
    if profile is None:
        if not reason:
            raise ValueError("clock_line without a profile needs the reason there is none")
        lines.append(f"Release countdown: unavailable ({reason})")
    else:
        lines.extend(event_lines(profile, now))
    return "\n".join(lines)


def hook_response(text: str, event: str = "UserPromptSubmit") -> dict:
    """The Claude Code hook answer that adds `text` to the turn's context."""
    if event not in HOOK_EVENTS:
        raise ValueError(f"unsupported hook event {event!r}; the clock hook handles {', '.join(HOOK_EVENTS)}")
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}
