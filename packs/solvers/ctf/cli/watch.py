"""ctf watch run | tail | diff -- the one no-model board poller and its stream (B-017, ctf/watch.py).

    python -m ctf watch run [--wave ISO ...] [--daily HH:MM ...] [--once | --duration S] [--json]
    python -m ctf watch tail [--since SEQ] [--follow] [--json]
    python -m ctf watch diff ID [--from N] [--to M] [--json]

`run` polls the event's board through ctf.platform.get_adapter (reads only) and writes every
detection to <workdir>/watch/events.jsonl: 1 s polls from 20 s before to 60 s after each anchor
(dates.start when it has a time, each --wave, each --daily release), 5 s otherwise. One per workdir:
a second `run` fails naming the first one's pid. `diff` re-checks a brief change offline from the
stored versions, never touching the platform.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .. import event as _event
from .. import paths as _paths
from .. import watch as _watch
from ..platform.base import PlatformError

HELP = "the one no-model board poller (new challenges, brief edits) and its event stream"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)
    r = sp.add_parser("run", help="poll the board and write the stream")
    r.add_argument("--wave", action="append", default=[],
                   help="a wave/release time (ISO-8601 with zone, or epoch); repeatable")
    r.add_argument("--daily", action="append", default=[],
                   help="a daily release time HH:MM[:SS] UTC, on every event day; repeatable")
    r.add_argument("--fast", type=float, default=_watch.FAST_S, help="seconds between polls near an anchor")
    r.add_argument("--slow", type=float, default=_watch.SLOW_S, help="seconds between polls otherwise")
    r.add_argument("--lead", type=float, default=_watch.LEAD_S, help="fast polling starts this long before an anchor")
    r.add_argument("--tail", type=float, default=_watch.TAIL_S, help="fast polling lasts this long after an anchor")
    r.add_argument("--details-per-poll", type=int, default=_watch.DETAILS_PER_POLL,
                   help="challenge details re-read per poll, round robin (0: listing only)")
    g = r.add_mutually_exclusive_group()
    g.add_argument("--once", action="store_true", help="poll once and exit")
    g.add_argument("--duration", type=float, help="stop after this many seconds")
    r.add_argument("--json", action="store_true", help="print each event as one JSON line")
    t = sp.add_parser("tail", help="print the stream")
    t.add_argument("--since", type=int, default=0, help="only events with seq greater than this")
    t.add_argument("--follow", action="store_true", help="keep printing new events")
    t.add_argument("--json", action="store_true")
    d = sp.add_parser("diff", help="verify and print a brief change offline")
    d.add_argument("id")
    d.add_argument("--from", dest="frm", type=int, help="older version (default: the one before --to)")
    d.add_argument("--to", type=int, help="newer version (default: the latest)")
    d.add_argument("--json", action="store_true")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _line(ev: dict) -> str:
    when = time.strftime("%H:%M:%S", time.gmtime(ev.get("ts", 0)))
    kind = ev.get("event")
    rest = {k: v for k, v in ev.items() if k not in ("seq", "ts", "event", "changes")}
    if kind == "brief_changed":
        rest.pop("alert", None)
    return f"[{ev.get('seq')}] {when}Z {kind} " + " ".join(f"{k}={json.dumps(v, ensure_ascii=False)}"
                                                         for k, v in rest.items())


def _printer(as_json: bool):
    def out(ev: dict) -> None:
        print(json.dumps(ev, ensure_ascii=False) if as_json else _line(ev), flush=True)
    return out


def _run(args, profile) -> int:
    from ..platform import get_adapter
    anchors, notes = _watch.anchors_for(profile, args.wave, args.daily)
    for n in notes:
        print(f"ctf watch: note: {n}", file=sys.stderr)
    sched = _watch.Schedule(tuple(a for a, _ in anchors), fast=args.fast, slow=args.slow,
                            lead=args.lead, tail=args.tail)
    for a, label in anchors:
        print(f"ctf watch: anchor {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(a))} ({label})",
              file=sys.stderr)
    if not anchors:
        print(f"ctf watch: no anchors: polling every {sched.slow:g} s", file=sys.stderr)
    adapter = get_adapter(profile)
    wd = _paths.workdir(profile.slug)
    from ..platform import wire as _wire     # B-140: the anchors are release windows for every lane
    if _wire.of(adapter) is not None:
        _wire.of(adapter).lane = "watch"
        if anchors:
            _wire.mark_releases(wd, [a for a, _ in anchors])
    w = _watch.Watcher(adapter, workdir=wd, schedule=sched, details_per_poll=args.details_per_poll,
                       on_event=_printer(args.json))
    with w:
        if args.once:
            evs = w.tick()
            failed = [e for e in evs if e["event"] == "poll_error"]
            return 1 if failed else 0
        else:
            until = None if args.duration is None else time.time() + args.duration
            try:
                w.run(until=until)
            except KeyboardInterrupt:
                pass
    return 0


def _tail(args, profile) -> int:
    wd = _paths.workdir(profile.slug)
    out = _printer(args.json)
    if args.follow:
        try:
            for ev in _watch.follow(wd, since=args.since):
                out(ev)
        except KeyboardInterrupt:
            pass
        return 0
    for ev in _watch.read_events(wd, since=args.since):
        out(ev)
    return 0


def _diff(args, profile) -> int:
    wd = _paths.workdir(profile.slug)
    res = _watch.verify(wd, args.id, args.frm, args.to)
    if args.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
        return 0
    print(f"challenge {res['challenge_id']}: versions {res['from']} -> {res['to']} verified "
          "(hashes and chain match)")
    if not res["changes"]:
        print("no field changed")
    for k, ch in sorted(res["changes"].items()):
        print(f"--- {k}")
        if "diff" in ch:
            print(ch["diff"])
        else:
            print(f"before: {json.dumps(ch['old'], ensure_ascii=False)}")
            print(f"after:  {json.dumps(ch['new'], ensure_ascii=False)}")
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
        return {"run": _run, "tail": _tail, "diff": _diff}[args.action](args, profile)
    except (_event.EventError, _watch.WatchError, PlatformError) as e:
        print(f"ctf watch: {e}", file=sys.stderr)
        return 2
