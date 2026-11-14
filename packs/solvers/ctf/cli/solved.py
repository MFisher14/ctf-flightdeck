"""ctf solved run | once | list -- the solved watcher and the shared solved view (B-015, ctf/solved.py).

    python -m ctf solved run [--since SEQ] [--duration S] [--poll S]
    python -m ctf solved once [--since SEQ]
    python -m ctf solved list [--json]

`run` follows this event's watch stream (`ctf watch run` must be polling the board) and, for each team
solve it sees, stops every agent on that challenge (the B-033 budget hook) and marks its dispatch claim
solved; a challenge that leaves the board has its claim marked gone. `once` acts on the solves the stream
already shows and exits. `list` prints the ids the team has solved (the shared view the dispatcher gates
on). No model, no platform call, nothing submitted.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import event as _event
from .. import paths as _paths
from .. import solved as _solved
from .. import watch as _watch

HELP = "the solved watcher: stop agents on any team solve and never dispatch onto solved challenges"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)
    for name, helptext in (("run", "follow the stream and stop agents on each team solve"),
                           ("once", "act on the team solves the stream already shows")):
        s = sp.add_parser(name, help=helptext)
        s.add_argument("--since", type=int, default=0, help="only stream events with seq greater than this")
        if name == "run":
            s.add_argument("--duration", type=float, help="stop after this many seconds")
            s.add_argument("--poll", type=float, default=0.5, help="seconds between stream reads")
    sl = sp.add_parser("list", help="print the challenge ids the team has solved")
    sl.add_argument("--json", action="store_true", help="print the ids as one JSON array")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _on_solve(cid: str, new: bool) -> None:
    where = "stopped agents and marked claim solved" if new else "already recorded (no-op)"
    print(f"team solve: {cid} -> {where}", flush=True)


def _on_gone(cid: str, revoked: bool) -> None:
    if revoked:
        print(f"challenge gone: {cid} -> claim marked gone", flush=True)


def _on_return(cid: str, restored: bool) -> None:
    if restored:
        print(f"challenge back: {cid} -> gone claim restored to dispatched", flush=True)


def _on_problem(msg: str) -> None:
    print(f"ctf solved: {msg}", file=sys.stderr, flush=True)


def _watcher(wd) -> _solved.SolvedWatcher:
    return _solved.SolvedWatcher(workdir=wd, on_solve=_on_solve, on_gone=_on_gone, on_problem=_on_problem,
                                 on_return=_on_return)


def _once(args, wd) -> int:
    w = _watcher(wd)
    solved = w.once(since=args.since)
    if not solved:
        print("ctf solved: no team solves in the stream (is `ctf watch run` polling?)", file=sys.stderr)
    return 0


def _run(args, wd) -> int:
    w = _watcher(wd)
    until = None if args.duration is None else w.clock() + args.duration
    try:
        w.run(since=args.since, poll=args.poll, until=until)
    except KeyboardInterrupt:
        pass
    return 0


def _list(args, wd) -> int:
    ids = sorted(_solved.solved_ids(wd))
    if args.json:
        print(json.dumps(ids))
    else:
        for cid in ids:
            print(cid)
        if not ids:
            print("ctf solved: no team solves recorded yet", file=sys.stderr)
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
        wd = _paths.workdir(profile.slug)
        return {"run": _run, "once": _once, "list": _list}[args.action](args, wd)
    except (_event.EventError, _solved.SolvedError, _watch.WatchError) as e:
        print(f"ctf solved: {e}", file=sys.stderr)
        return 2
