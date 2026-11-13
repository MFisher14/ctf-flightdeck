"""ctf wire status | journal | ratelimits | mark-release -- the platform request journal and budget (B-140).

    python -m ctf wire status [--json]                          counts now, pause, release windows, lanes
    python -m ctf wire journal [--since WHEN] [--lane L] [--op O] [--status N] [--json]
    python -m ctf wire ratelimits [--since WHEN] [--json]       each 429 with the 60 s mix before it
    python -m ctf wire mark-release [--at WHEN ...] [--clear]   record release anchors (default: now)

Reads <workdir>/wire/ of the event (--workdir, else $CTF_WORKDIR, else the event's; --event picks
the event). Never contacts the platform. WHEN is epoch seconds or ISO-8601 with a UTC offset; for
--since a bare number under 10^6 is "this many seconds ago".

Exit codes: 0 ok, 2 an error (no event profile, bad time, unusable wire dir).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import sys
import time
from pathlib import Path

HELP = "the platform request journal and release-minute budget: status, journal, ratelimits, mark-release"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir holding wire/ (default: the event's)")
    sp = p.add_subparsers(dest="action", required=True)
    st = sp.add_parser("status", help="requests in the last 60 s and this minute, pause, release windows")
    st.add_argument("--json", action="store_true")
    jo = sp.add_parser("journal", help="the per-request journal")
    jo.add_argument("--since", help="epoch seconds, ISO-8601 with offset, or N seconds ago (N < 10^6)")
    jo.add_argument("--lane")
    jo.add_argument("--op")
    jo.add_argument("--status", type=int, help="only rows with this HTTP status")
    jo.add_argument("--json", action="store_true", help="one JSON row per line")
    rl = sp.add_parser("ratelimits", help="each 429 with the request mix by op and lane of the 60 s before it")
    rl.add_argument("--since")
    rl.add_argument("--json", action="store_true")
    mk = sp.add_parser("mark-release", help="record release anchors for every process of the event")
    mk.add_argument("--at", action="append", default=[], help="anchor time (repeatable; default now)")
    mk.add_argument("--clear", action="store_true", help="drop every recorded anchor first")


def _when(text: str, *, relative: bool = False) -> float:
    from .ledger import parse_when
    t = text.strip()
    if relative:
        try:
            v = float(t)
        except ValueError:
            pass
        else:
            return time.time() - v if v < 1e6 else v
    return parse_when(t)


def _utc(ts: float | None) -> str:
    if ts is None:
        return "-"
    d = _dt.datetime.fromtimestamp(float(ts), tz=_dt.timezone.utc)
    return d.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _profile(args):
    from .. import event
    return event.load(args.event) if args.event else event.current()


def _workdir(args, prof) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(prof.slug)


def run(args: argparse.Namespace) -> int:
    from ..event import EventError
    from ..platform import wire
    try:
        prof = _profile(args)
        wd = _workdir(args, prof)
        if args.action == "status":
            return _status(args, prof, wd)
        if args.action == "journal":
            return _journal(args, wd)
        if args.action == "ratelimits":
            return _ratelimits(args, wd)
        if args.action == "mark-release":
            if args.clear:
                wire.clear_releases(wd)
            ats = [_when(a) for a in args.at] or ([] if args.clear else [time.time()])
            kept = wire.mark_releases(wd, ats) if ats else []
            for a in ats:
                print(f"release anchor {_utc(a)} recorded in {wire.wire_dir(wd)}")
            if not kept:
                print("no release anchors recorded")
            return 0
    except (EventError, ValueError, wire.WireError) as e:
        print(f"ctf wire {args.action}: {e}", file=sys.stderr)
        return 2
    raise AssertionError(f"unhandled action {args.action!r}")


def _status(args, prof, wd: Path) -> int:
    from ..platform import wire
    s = wire.Wire(prof, workdir=wd).status()
    pace = s.pop("pace")
    if args.json:
        print(json.dumps({**s, "pace": dataclasses.asdict(pace)}, indent=1))
        return 0
    caps = []
    if pace.per_minute:
        caps.append(f"per_minute {pace.per_minute}")
    if pace.release_budget:
        caps.append(f"release_budget {pace.release_budget}")
    if pace.reserve:
        caps.append(f"reserve {pace.reserve}")
    if pace.release_poll_gap_s:
        caps.append(f"poll gap {pace.release_poll_gap_s:g} s after +{pace.release_poll_free_s:g} s")
    if pace.release_lane_budget or pace.release_lanes:
        caps.append(f"lane budget {pace.release_lane_budget}"
                    + "".join(f", {k} {v}" for k, v in pace.release_lanes))
    print(f"wire {wire.wire_dir(wd)}  [{', '.join(caps) or 'no caps: journal only'}]")
    print(f"requests: {s['n60']} in the last 60 s, {s['nmin']} in this calendar minute")
    print(f"pause: {s['pause_left_s']:g} s left" if s["pause_left_s"] else "pause: none")
    print(f"last 429: {_utc(s['last_429'])}")
    for w in s["windows"]:
        lanes = ", ".join(f"{k} {v}" for k, v in sorted(w["by_lane"].items()))
        print(f"release window {_utc(w['anchor'])} +{w['elapsed_s']:.1f} s: {w['requests']} request(s)"
              + (f" ({lanes})" if lanes else ""))
    if not s["windows"]:
        print(f"release window: none open; next anchor {_utc(s['next_anchor'])}")
    return 0


def _journal(args, wd: Path) -> int:
    from ..platform import wire
    since = _when(args.since, relative=True) if args.since else None
    rows, bad = wire.read_journal(wd, since=since)
    rows = [r for r in rows if (args.lane is None or (r.get("lane") or "-") == args.lane)
            and (args.op is None or r.get("op") == args.op)
            and (args.status is None or r.get("status") == args.status)]
    for r in rows:
        if args.json:
            print(json.dumps(r, sort_keys=True))
            continue
        flags = " FORCED" if r.get("forced") else ""
        held = f" held {r['held_s']:g}s by {r['held_by']}" if r.get("held_by") else ""
        rel = f" +{r['rel_s']:.1f}s" if r.get("rel_s") is not None else ""
        print(f"{_utc(r['ts'])}{rel} {r.get('op', '?'):<10} {r.get('status') or r.get('error') or '-'} "
              f"{(r.get('dur_s') or 0) * 1000:.0f}ms lane={r.get('lane') or '-'} "
              f"challenge={r.get('challenge') or '-'} n60={r.get('n60')} nmin={r.get('nmin')}{held}{flags}")
    if bad:
        print(f"ctf wire journal: {bad} unreadable line(s) skipped", file=sys.stderr)
    if not rows and not args.json:
        print(f"no journal rows in {wire.journal_path(wd)}" + (" for that filter" if since or args.lane
                                                               or args.op or args.status else ""))
    return 0


def _ratelimits(args, wd: Path) -> int:
    from ..platform import wire
    since = _when(args.since, relative=True) if args.since else None
    rows, bad = wire.read_journal(wd)
    rep = [x for x in wire.ratelimit_report(rows) if since is None or x["ts"] >= since]
    if bad:
        print(f"ctf wire ratelimits: {bad} unreadable line(s) skipped", file=sys.stderr)
    if args.json:
        print(json.dumps(rep, indent=1))
        return 0
    if not rep:
        print(f"no 429 in {wire.journal_path(wd)}")
        return 0
    for x in rep:
        rel = f" (release +{x['rel_s']:.1f} s)" if x.get("rel_s") is not None else ""
        print(f"429 at {_utc(x['ts'])}{rel} on {x['op']} lane={x['lane'] or '-'}: "
              f"{x['n60']} in the last 60 s, {x['nmin']} in the calendar minute (second {x['second']:.1f}); "
              f"pause {x['pause_s']} s" + (f", Retry-After {x['retry_after']}" if x.get("retry_after") else ""))
        print("  by op:    " + ", ".join(f"{k} {v}" for k, v in x["by_op"].items()))
        print("  by lane:  " + ", ".join(f"{k} {v}" for k, v in x["by_lane"].items()))
        print("  by class: " + ", ".join(f"{k} {v}" for k, v in x["by_class"].items()))
        if x["limit_headers"]:
            print("  headers:  " + ", ".join(f"{k}: {v}" for k, v in sorted(x["limit_headers"].items())))
    return 0
