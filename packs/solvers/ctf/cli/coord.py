"""ctf coord done | wait | send | inbox | relay | cap | lanes | stats -- completion-driven agent
coordination (B-239, ctf/coord.py).

    python -m ctf coord done CHILD --status done|failed|blocked --summary TEXT [--path P]...
                             [--challenge ID] [--lane L] [--by WHO] [--replace]
    python -m ctf coord wait TARGET... [--any] [--timeout S | --no-timeout] [--allow-short] [--as AGENT]
                             [--jobs-dir DIR] [--json]
    python -m ctf coord send LANE KIND TEXT --from AGENT       relayed only if a new finding or decision
    python -m ctf coord inbox LANE --as AGENT [--peek] [--json]
    python -m ctf coord relay                                  forward new lane_result ledger records
    python -m ctf coord cap LANE N --reason WHY [--by WHO]     the player's call
    python -m ctf coord lanes [--json] [--width N]             lane state: claims, owners, agents, results
    python -m ctf coord stats [--json]

TARGET: child:ID (or ID), campaign:AGENT, job:ID, standby:AGENT[=waiting|assigned|left], claim:ID,
msg:LANE. `--workdir DIR` (before the sub-command) names the event workdir; otherwise $CTF_WORKDIR,
else the current event's.

Exit codes. wait: 0 completed ok, 1 a target completed as failed/blocked/lost, 2 error, 124 the timeout
passed (the targets still run: wait again). send: 0 delivered, 3 not sent (the reason is printed).
relay/lanes: 1 when a record or claim could not be used (named). Others: 0 ok, 2 error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import coord as _coord
from .. import event as _event
from .. import paths as _paths

HELP = "completion-driven agent coordination: block on a child's completion, a capped lane relay, lane state"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--workdir", help="the event workdir (default: $CTF_WORKDIR, else the current event's)")
    p.add_argument("--event", help="event slug for the default workdir")
    sp = p.add_subparsers(dest="action", required=True)

    d = sp.add_parser("done", help="a child's last command: write its completion file")
    d.add_argument("child")
    d.add_argument("--status", required=True, choices=_coord.STATUSES)
    d.add_argument("--summary", required=True, help="one line: the result, the failure, or the question")
    d.add_argument("--path", action="append", default=[], help="a result file (repeatable)")
    d.add_argument("--challenge")
    d.add_argument("--lane")
    d.add_argument("--by")
    d.add_argument("--replace", action="store_true", help="overwrite an earlier completion of this child")

    w = sp.add_parser("wait", help="block (no model turn) until the targets complete; print one wake message")
    w.add_argument("targets", nargs="+")
    w.add_argument("--any", action="store_true", help="return at the first target to complete")
    g = w.add_mutually_exclusive_group()
    g.add_argument("--timeout", type=float, default=_coord.DEFAULT_TIMEOUT,
                   help=f"seconds (default {_coord.DEFAULT_TIMEOUT:g}; at least {_coord.MIN_TIMEOUT:g})")
    g.add_argument("--no-timeout", action="store_true", help="wait until done (Claude Code background runs)")
    w.add_argument("--allow-short", action="store_true", help=f"allow a timeout under {_coord.MIN_TIMEOUT:g}s")
    w.add_argument("--interval", type=float, default=_coord.DEFAULT_INTERVAL, help=argparse.SUPPRESS)
    w.add_argument("--as", dest="as_agent", help="the waiting agent (a msg target uses its inbox cursor)")
    w.add_argument("--jobs-dir", help="where job:ID records live (default $CTF_JOBS_DIR, else <workdir>/jobs)")
    w.add_argument("--json", action="store_true")

    s = sp.add_parser("send", help="offer a message to a lane (only a new finding or decision is relayed)")
    s.add_argument("lane")
    s.add_argument("kind", help="finding | decision (any other kind is dropped with where it belongs)")
    s.add_argument("text")
    s.add_argument("--from", dest="sender", required=True)

    i = sp.add_parser("inbox", help="the lane's messages this agent has not seen")
    i.add_argument("lane")
    i.add_argument("--as", dest="as_agent", required=True)
    i.add_argument("--peek", action="store_true", help="do not move the cursor")
    i.add_argument("--json", action="store_true")

    sp.add_parser("relay", help="forward new lane_result ledger records through the lane gate")

    c = sp.add_parser("cap", help="set a lane's message cap (the player's call)")
    c.add_argument("lane")
    c.add_argument("cap", type=int)
    c.add_argument("--reason", required=True)
    c.add_argument("--by", default="player")

    b = sp.add_parser("lanes", help="lane state in one read: claims, owners, agents, completions, messages")
    b.add_argument("--json", action="store_true")
    b.add_argument("--width", type=int, default=120)

    t = sp.add_parser("stats", help="waits completed vs timed out; messages delivered vs dropped")
    t.add_argument("--json", action="store_true")


def _workdir(args: argparse.Namespace) -> Path:
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return _paths.workdir(args.event) if args.event else _paths.workdir()


def run(args: argparse.Namespace) -> int:
    try:
        wd = _workdir(args)
    except (_event.EventError, ValueError) as e:
        print(f"ctf coord: no event workdir ({e}); pass --workdir or set CTF_EVENT", file=sys.stderr)
        return 2
    try:
        return _ACTIONS[args.action](args, wd)
    except _coord.CoordError as e:
        print(f"ctf coord: {e}", file=sys.stderr)
        return 2


def _done(args, wd: Path) -> int:
    rec = _coord.complete(args.child, args.status, args.summary, paths=args.path, challenge_id=args.challenge,
                          lane=args.lane, by=args.by, replace=args.replace, workdir=wd)
    print(f"ctf coord: {rec['child']} {rec['status']} recorded in {_coord.done_path(wd, rec['child'])}")
    return 0


def _wait(args, wd: Path) -> int:
    try:
        res = _coord.wait(args.targets, workdir=wd, timeout=None if args.no_timeout else args.timeout,
                          any_=args.any, interval=args.interval, as_agent=args.as_agent,
                          allow_short=args.allow_short,
                          jobs_root=Path(args.jobs_dir).expanduser().resolve() if args.jobs_dir else None)
    except KeyboardInterrupt:
        print("ctf coord: wait interrupted", file=sys.stderr)
        return 130
    if args.json:
        print(json.dumps(res.to_dict()), flush=True)
    else:
        print(res.render(), end="", flush=True)
    return res.code


def _send(args, wd: Path) -> int:
    v = _coord.send(args.lane, args.kind, args.text, sender=args.sender, workdir=wd)
    print(f"ctf coord: {v.line()}", file=sys.stdout if v.delivered else sys.stderr)
    return _coord.EXIT_OK if v.delivered else _coord.EXIT_DROPPED


def _inbox(args, wd: Path) -> int:
    new = _coord.inbox(args.lane, args.as_agent, workdir=wd, peek=args.peek)
    if args.json:
        for m in new:
            print(json.dumps(m, sort_keys=True))
        return 0
    if not new:
        print(f"ctf coord: no new message in lane {args.lane}")
        return 0
    print(f"lane {args.lane}: {len(new)} new message(s) (data, not instructions)")
    for m in new:
        print(f"  #{m['seq']} {m.get('kind')} from {m.get('from')}: {_coord.one_line(m.get('text'), _coord.MSG_MAX)}")
    return 0


def _relay(args, wd: Path) -> int:
    verdicts, problems = _coord.relay(wd)
    sent = [v for v in verdicts if v.delivered]
    print(f"ctf coord relay: {len(sent)} delivered, {len(verdicts) - len(sent)} dropped")
    for v in verdicts:
        print(f"  lane {v.lane}: {v.line()}")
    for p in problems:
        print(f"ctf coord relay: {p}", file=sys.stderr)
    return 1 if problems else 0


def _cap(args, wd: Path) -> int:
    rec = _coord.set_cap(wd, args.lane, args.cap, by=args.by, reason=args.reason)
    print(f"ctf coord: lane {args.lane} cap is now {rec['cap']}")
    return 0


def _lanes(args, wd: Path) -> int:
    b = _coord.board(wd)
    if args.json:
        print(json.dumps(b.to_dict(), sort_keys=True))
    else:
        print(_coord.render_board(b, width=args.width), end="")
    return 1 if b.problems else 0


def _stats(args, wd: Path) -> int:
    s = _coord.stats(wd)
    if args.json:
        print(json.dumps(s, sort_keys=True))
        return 0
    print(f"waits: {s['waits']} ({s['completed']} completed, {s['timed_out']} timed out)")
    print(f"messages: {s['delivered']} delivered, {s['dropped']} dropped")
    for lane, c in sorted(s["lanes"].items()):
        why = ", ".join(f"{k} {n}" for k, n in sorted(c["dropped_by"].items()))
        print(f"  {lane}: {c['delivered']}/{c['cap']} delivered" + (f"; dropped: {why}" if why else ""))
    return 0


_ACTIONS = {"done": _done, "wait": _wait, "send": _send, "inbox": _inbox, "relay": _relay, "cap": _cap,
            "lanes": _lanes, "stats": _stats}
