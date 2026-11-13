"""ctf compaction show | check | audit -- the compaction thresholds (B-032; ctf/compaction.py).

    python -m ctf compaction show [--json]               thresholds and what each launcher passes
    python -m ctf compaction check LOG [--harness H] [--limit N]
                                                         latest context vs the threshold: exit 0 under,
                                                         3 at or over (stop the agent, restart it from
                                                         a briefing), 2 unusable input
    python -m ctf compaction audit LOG... [--harness H] [--limit N] [--tolerance F] [--json]
                                                         per session log: peak, responses over the
                                                         threshold, where it compacted; exit 0 every
                                                         log held, 1 one exceeded (or the threshold
                                                         is off), 2 unusable input

LOG is a Claude Code transcript JSONL or a Codex rollout JSONL (detected; --harness overrides).
Only usage and compaction records are read: log text is data.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import compaction as _c
from .. import env as _env

HELP = "compaction thresholds (Claude 200K, Codex 150K): show, check a live session, audit logs"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    sh = sp.add_parser("show", help="thresholds and the launch settings")
    sh.add_argument("--json", action="store_true")
    ck = sp.add_parser("check", help="latest context of one session against the threshold")
    ck.add_argument("log")
    ck.add_argument("--harness", choices=_c.HARNESSES)
    ck.add_argument("--limit", help="threshold to check against (default: the harness threshold)")
    au = sp.add_parser("audit", help="where each session's context went and where it compacted")
    au.add_argument("logs", nargs="+")
    au.add_argument("--harness", choices=_c.HARNESSES)
    au.add_argument("--limit", help="threshold to measure against (default: the harness threshold)")
    au.add_argument("--tolerance", type=float, default=_c.OVERSHOOT_TOLERANCE,
                    help="fraction over the threshold a response may reach and still count as held")
    au.add_argument("--json", action="store_true", help="one JSON object per log")


def _limit(raw: str | None) -> int | None:
    if raw is None:
        return None
    val = _c.parse_tokens(raw, name="--limit")
    if val is None:
        raise _c.CompactionError("--limit off: give a token count")
    return val


def _show(as_json: bool) -> int:
    th = {h: _c.threshold(h) for h in _c.HARNESSES}
    env = _c.claude_env()
    doc = {"thresholds": th, "claude_env": env, "claude_settings": _c.claude_settings(),
           "codex_args": _c.codex_config_args()}
    if as_json:
        print(json.dumps(doc))
        return 0
    for h in _c.HARNESSES:
        src = _c.ENV_VARS[h] if _env.get(_c.ENV_VARS[h]) else "default"
        print(f"{h:<7} {'off' if th[h] is None else f'{th[h]:,}'} tokens  ({src})")
    print("claude launch env:  " + (" ".join(f"{k}={v}" for k, v in env.items()) or "(none: off)"))
    print("codex launch args:  " + (" ".join(doc["codex_args"]) or "(none: off)"))
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "show":
            return _show(args.json)
        if args.action == "check":
            r = _c.check(args.log, args.harness, limit=_limit(args.limit))
            print(r.line())
            return _c.CHECK_EXIT_OVER if r.over else 0
        limit = _limit(args.limit)
        audits = [_c.audit(p, args.harness, limit=limit, tolerance=args.tolerance) for p in args.logs]
    except _c.CompactionError as e:
        print(f"ctf compaction: {e}", file=sys.stderr)
        return 2
    for a in audits:
        print(json.dumps(a.to_dict()) if args.json else a.line())
    return 0 if all(a.held for a in audits) else 1
