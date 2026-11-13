"""ctf clock -- the current Eastern time and the next-release countdown (B-211).

    python -m ctf clock                       now in ET and UTC, the event's next release and countdown
    python -m ctf clock --event SLUG          ... for that event (default $CTF_EVENT, else the only one)
    python -m ctf clock --now WHEN            ... as of another time (epoch seconds or ISO-8601; an ISO
                                              time without a zone is Eastern time)
    python -m ctf clock --hook [--hook-event UserPromptSubmit|SessionStart]
                                              the same text as Claude Code hook JSON (additionalContext),
                                              for tools/clock_hook

Agents take the time from this, never from memory or a log line. The release times come from the
event profile: dates.start, [allowance] releases and daily_release (ctf.quota.next_release).

Exit codes: 0 printed; 2 a named error (a bad --now, or an event that was named by --event or
$CTF_EVENT and does not load). With no event named and none to pick, the clock still prints and says
why there is no countdown. --hook never fails a prompt: every error becomes a named line, exit 0.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import time

HELP = "current Eastern time and the event's next-release countdown (B-211); --hook for Claude Code"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: $CTF_EVENT, else the only profile)")
    p.add_argument("--now", help="as of this time: epoch seconds or ISO-8601 (no zone = Eastern)")
    p.add_argument("--hook", action="store_true", help="print Claude Code hook JSON; never fail")
    p.add_argument("--hook-event", default="UserPromptSubmit", choices=("UserPromptSubmit", "SessionStart"),
                   help="the hook event the JSON answers (default UserPromptSubmit)")


class ClockError(ValueError):
    pass


def parse_now(raw: str) -> float:
    from ..clockline import ET
    try:
        return float(raw)
    except ValueError:
        pass
    try:
        d = _dt.datetime.fromisoformat(raw)
    except ValueError:
        raise ClockError(f"--now {raw!r} is neither epoch seconds nor an ISO-8601 time") from None
    return (d if d.tzinfo else d.replace(tzinfo=ET)).timestamp()


def _profile(args):
    """(profile, reason, error): the profile, else why there is none. `error` is True when the event
    was named (--event or $CTF_EVENT) and did not load: that is a failure, not an absent event."""
    from .. import env, event
    named = args.event or env.get("CTF_EVENT")
    try:
        return (event.load(args.event) if args.event else event.current()), None, False
    except Exception as e:      # EventError, a broken TOML, a bad zone: named, never a traceback
        what = f"event {named!r} did not load" if named else "no event"
        return None, f"{what}: {type(e).__name__}: {e}", bool(named)


def run(args: argparse.Namespace) -> int:
    from .. import clockline
    try:
        now = parse_now(args.now) if args.now else time.time()
    except ClockError as e:
        if not args.hook:
            print(f"ctf clock: {e}", file=sys.stderr)
            return 2
        now, bad_now = time.time(), str(e)
    else:
        bad_now = None
    prof, reason, error = _profile(args)
    if error and not args.hook:
        print(f"ctf clock: {reason}", file=sys.stderr)
        return 2
    text = clockline.clock_line(now, prof, reason=reason)
    if bad_now:
        text += f"\nClock hook error: {bad_now}; the time above is the wall clock"
    if args.hook:
        print(json.dumps(clockline.hook_response(text, args.hook_event)))
    else:
        print(text)
    return 0
