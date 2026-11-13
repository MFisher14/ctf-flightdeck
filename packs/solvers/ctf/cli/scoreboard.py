"""ctf scoreboard ingest | watch | record | show | bench | floors -- the public board and first bloods
(B-099).

    python -m ctf scoreboard ingest [--force] [--max-solves N] [--team T] [--json]
                                    one low-priority read of the board into <workdir>/scoreboard/
    python -m ctf scoreboard watch [--interval S] [--cycles N] [--force] [--max-solves N] [--team T]
                                    ingest every S seconds (default 60) until stopped or N cycles
    python -m ctf scoreboard record CID TEAM WHEN [--category C] [--name N] [--team T]
    python -m ctf scoreboard record CID TEAM --delete
                                    enter (or remove) one team's solve by hand: a Game Master board
                                    publishes none, so first-blood times are typed in (no request)
    python -m ctf scoreboard show [--top N] [--json]
                                    the stored standings and each challenge's first blood (no request)
    python -m ctf scoreboard bench [--team T] [--margin M] [--t0 WHEN] [--lane L] [--json] [--strict]
                                    per-lane gap vs rival first bloods from the store and the ledger
    python -m ctf scoreboard floors [--team T] [--t0 WHEN] [--since WHEN] [--json] [--write]
                                    latency.floor_table with the fastest rival first blood per mode
                                    as its known record

Every command takes --event SLUG (default: the current event) and --workdir DIR. Only ingest and
watch contact the platform, through the adapter and the wire (lane "board"); a Game Master event
answers NotSupported and a manual one NotAllowed, named, exit 2. The module docstring of
ctf/scoreboard.py is the contract.

Exit codes: 0 ok (ingest also when deferred: it says why); 1 a read failed (ingest, watch) or, with
bench --strict, a FAIL verdict; 2 an error (named).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

HELP = "the public scoreboard: ingest, watch, show, first-blood bench, floor records (B-099)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    from .. import scoreboard as sb
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir (default: the event's)")
    sp = p.add_subparsers(dest="action", required=True)
    for name, text in (("ingest", "one low-priority read of the board into the store"),
                       ("watch", "ingest every --interval seconds")):
        x = sp.add_parser(name, help=text)
        x.add_argument("--force", action="store_true",
                       help="read even in a release window, a pause or a busy minute (the wire still holds)")
        x.add_argument("--max-solves", type=int, default=sb.MAX_SOLVES,
                       help=f"per-challenge solves reads per cycle (default {sb.MAX_SOLVES})")
        x.add_argument("--team", help="our team's board name (default: the profile's platform.team)")
        if name == "ingest":
            x.add_argument("--json", action="store_true")
        else:
            x.add_argument("--interval", type=float, default=sb.DEFAULT_INTERVAL_S,
                           help=f"seconds between cycles (default {sb.DEFAULT_INTERVAL_S:g})")
            x.add_argument("--cycles", type=int, default=None, help="stop after N cycles (default: never)")
    rc = sp.add_parser("record", help="enter one team's solve by hand (a Game Master board; no request)")
    rc.add_argument("challenge", help="the challenge id (as the ledger names it)")
    rc.add_argument("account", metavar="TEAM", help="the team that solved it, as the board names it")
    rc.add_argument("when", nargs="?", help="the solve time (epoch or ISO-8601 with offset); not with --delete")
    rc.add_argument("--category", help="the challenge's lane (board category)")
    rc.add_argument("--name", help="the challenge's name")
    rc.add_argument("--team", help="our team's board name (default: the profile's platform.team)")
    rc.add_argument("--delete", action="store_true", help="remove this team's hand-entered solve")
    sh = sp.add_parser("show", help="the stored standings and first bloods (no request)")
    sh.add_argument("--top", type=int, default=20, help="standings rows to print (default 20)")
    sh.add_argument("--json", action="store_true")
    be = sp.add_parser("bench", help="per-lane gap vs rival first bloods (store + ledger, no request)")
    be.add_argument("--team", help="our team's board name (default: the profile's platform.team)")
    be.add_argument("--margin", type=float, default=sb.DEFAULT_MARGIN,
                    help=f"beat the rival first blood by this share (default {sb.DEFAULT_MARGIN:g})")
    be.add_argument("--t0", help="release time for challenges in no ledger wave (epoch or ISO-8601 with offset)")
    be.add_argument("--lane", help="only this lane (the board category)")
    be.add_argument("--json", action="store_true")
    be.add_argument("--strict", action="store_true", help="exit 1 when any verdict is FAIL")
    fl = sp.add_parser("floors", help="the wire-floor table with first-blood records per mode")
    fl.add_argument("--team", help="our team's board name (default: the profile's platform.team)")
    fl.add_argument("--t0", help="release time for challenges in no ledger wave")
    fl.add_argument("--since", help="timings since WHEN (epoch or ISO-8601 with offset)")
    fl.add_argument("--json", action="store_true")
    fl.add_argument("--write", action="store_true", help="also write <workdir>/wire/floors.json")


def _profile(args):
    from .. import event
    return event.load(args.event) if args.event else event.current()


def _workdir(args, prof) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(prof.slug)


def _when(text: str) -> float:
    from .ledger import parse_when
    return parse_when(text)


def _utc(ts) -> str:
    if ts is None:
        return "-"
    return _dt.datetime.fromtimestamp(float(ts), tz=_dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def _print_result(r, as_json: bool) -> None:
    if as_json:
        print(json.dumps(r.to_dict(), sort_keys=True))
        return
    if r.deferred and not r.fetched and not r.board_rows:
        print(f"deferred: {r.deferred}")
        return
    print(f"board: {r.board_rows} row(s), {r.challenges} challenge(s); solves read for {len(r.fetched)}"
          + (f", {len(r.pending)} pending" if r.pending else ""))
    if r.deferred:
        print(f"  {r.deferred}")
    for fb in r.first_bloods:
        who = " (ours)" if fb["ours"] else ""
        print(f"  first blood {fb['challenge_id']}: {fb['account']}{who} at {_utc(fb['at'])}")
    for e in r.errors:
        print(f"  ERROR {e}", file=sys.stderr)


def _ingest(args, prof, wd: Path) -> int:
    from .. import scoreboard as sb
    from ..platform import get_adapter
    r = sb.ingest(get_adapter(prof), workdir=wd, team=args.team, max_solves=args.max_solves, force=args.force)
    _print_result(r, args.json)
    return 0 if r.ok else 1


def _watch(args, prof, wd: Path) -> int:
    from .. import scoreboard as sb
    from ..platform import get_adapter
    failed = []

    def on_error(e):
        failed.append(e)
        print(f"ctf scoreboard watch: cycle failed: {e}", file=sys.stderr)

    try:
        out = sb.watch(get_adapter(prof), cycles=args.cycles, interval_s=args.interval, workdir=wd,
                       team=args.team, max_solves=args.max_solves, force=args.force,
                       on_result=lambda r: (_print_result(r, False), sys.stdout.flush()), on_error=on_error)
    except KeyboardInterrupt:
        return 0
    return 1 if failed or any(not r.ok for r in out) else 0


def _record(args, prof, wd: Path) -> int:
    from .. import scoreboard as sb
    if args.delete == bool(args.when):
        raise ValueError("record needs WHEN, or --delete without WHEN")
    at = None if args.delete else _when(args.when)
    e = sb.record_solve(wd, args.challenge, args.account, at, category=args.category, name=args.name,
                        team=args.team or prof.platform.team, delete=args.delete)
    fb = sb.first_blood(e)
    what = "removed" if args.delete else f"recorded at {_utc(at)}"
    print(f"challenge {args.challenge}: {args.account} {what} by hand; first blood now "
          + (f"{fb['account']} at {_utc(fb['at'])}" if fb else "-"))
    return 0


def _show(args, wd: Path) -> int:
    from .. import scoreboard as sb
    st = sb.load(wd)
    if args.json:
        print(json.dumps(st, sort_keys=True))
        return 0
    if st["board_at"] is None:
        print(f"no board ingested in {sb.store_dir(wd)}: run `ctf scoreboard ingest`")
        return 0
    print(f"standings at {_utc(st['board_at'])} ({len(st['board'])} teams)")
    for rank, team, score in st["board"][:args.top]:
        print(f"  {rank:>4} {score:>7}  {team}")
    print("first bloods:")
    for cid, e in sorted(st["challenges"].items(), key=lambda kv: (len(kv[0]), kv[0])):
        fb = sb.first_blood(e)
        n = len(e.get("solves") or ())
        print(f"  {cid:>6} {str(e.get('category') or '-')[:14]:<14} {str(e.get('name') or '')[:28]:<28} "
              + (f"{fb['account']} at {_utc(fb['at'])} ({n} solve(s))" if fb else "-"))
    return 0


def _bench(args, prof, wd: Path):
    from .. import ledger
    from .. import scoreboard as sb
    team = args.team or prof.platform.team
    t0 = _when(args.t0) if getattr(args, "t0", None) else None
    return sb.bench(sb.load(wd), list(ledger.read(wd)), team=team, margin=getattr(args, "margin", sb.DEFAULT_MARGIN),
                    t0=t0, lane=getattr(args, "lane", None))


def _bench_cmd(args, prof, wd: Path) -> int:
    from .. import scoreboard as sb
    b = _bench(args, prof, wd)
    if args.json:
        print(json.dumps(b.to_dict(), sort_keys=True))
    else:
        print(sb.render_bench(b))
    failed = any(r.verdict == sb.FAIL for r in b.rows)
    return 1 if (args.strict and failed) else 0


def _floors(args, prof, wd: Path) -> int:
    from .. import scoreboard as sb
    from ..platform import latency, wire
    b = _bench(args, prof, wd)
    records = sb.floor_records(b, kind=prof.platform.kind)
    since = _when(args.since) if args.since else None
    rows, bad = latency.read_phases(wd, since=since)
    jrows, jbad = wire.read_journal(wd, since=since)
    table = latency.floor_table(rows, jrows, kind=prof.platform.kind, records=records)
    if bad or jbad:
        print(f"ctf scoreboard floors: {bad} unreadable phases line(s), {jbad} unreadable journal line(s) "
              "skipped", file=sys.stderr)
    if args.write:
        print(f"floors written to {latency.write_floors(wd, table)}", file=sys.stderr)
    if args.json:
        print(json.dumps({"records": records, "table": table}, sort_keys=True))
        return 0
    if not records:
        print("no first-blood record: needs a rival solve on the board and a release time (a ledger "
              "wave or --t0)")
    for r in table:
        line = f"{r['mode']:<22} floor {r['floor_s'] if r['floor_s'] is not None else '-'}"
        if "record_s" in r:
            line += f"  first blood {r['record_s']:g} s: {r['verdict']}"
        print(line)
    return 0


def run(args: argparse.Namespace) -> int:
    from .. import scoreboard as sb
    from ..event import EventError
    from ..platform import NotSupported, PlatformError
    try:
        prof = _profile(args)
        wd = _workdir(args, prof)
        if args.action == "ingest":
            return _ingest(args, prof, wd)
        if args.action == "watch":
            return _watch(args, prof, wd)
        if args.action == "record":
            return _record(args, prof, wd)
        if args.action == "show":
            return _show(args, wd)
        if args.action == "bench":
            return _bench_cmd(args, prof, wd)
        return _floors(args, prof, wd)
    except NotSupported as e:            # NotAllowed too (a subclass): the kind or the rules say no
        print(f"ctf scoreboard {args.action}: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    except (EventError, PlatformError, sb.ScoreboardError, ValueError) as e:
        print(f"ctf scoreboard {args.action}: error: {e}", file=sys.stderr)
        return 2
