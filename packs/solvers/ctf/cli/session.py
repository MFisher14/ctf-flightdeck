"""ctf session — the named launcher sessions (B-175).

    python -m ctf session list [--sessions-dir D] [--json]
        Every claimed session: live (its launcher or agent runs, by pid AND start time) or stale.

A launcher started with --session NAME (or $CTF_SESSION) claims NAME and refuses to start while the
previous holder is live. Ending a live session is the reaper's job: python -m ctf reap, then the
player confirms the session:<name>@<launcher pid>-<start ms> id it lists.
Exit: 0 ok, 2 no sessions folder resolves or a record is unreadable.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .. import sessions as _sessions

HELP = "list named launcher sessions (live or stale, by exact pid + start time)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="session_cmd", required=True)
    ls = sp.add_parser("list", help="list claimed sessions")
    ls.add_argument("--sessions-dir", dest="sessions_dir",
                    help="session records (default $CTF_SESSIONS_DIR, else <workdir>/sessions)")
    ls.add_argument("--json", action="store_true")


def run(args: argparse.Namespace) -> int:
    try:
        root = _sessions.sessions_root(args.sessions_dir)
        states = _sessions.list_sessions(root)
    except _sessions.SessionError as e:
        print(f"ctf session: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([{"name": s.name, "status": s.status, "launcher": s.launcher,
                           "agent": s.agent, "record": s.record} for s in states], indent=1))
        return 0
    if not states:
        print(f"no sessions in {root}")
    for s in states:
        r = s.record
        since = r.get("claimed_at")
        age = f"{time.time() - float(since):.0f}s" if isinstance(since, (int, float)) else "?"
        print(f"{s.name:16} {s.status:5}  {r.get('harness')} challenge {r.get('challenge')}  "
              f"launcher {r.get('launcher_pid')} {s.launcher}  agent {r.get('agent_pid')} {s.agent}  "
              f"claimed {age} ago")
    return 0
