"""`ctf hof`: Hall of Fame eligibility of timed attempts (B-044, ctf/platform/halloffame.py).

    python -m ctf hof report [--json] [--strict]     every classified timed start and timed result
                                                     of the event (ledger), a WARN line for each
                                                     regular attempt, not-eligible attempt or
                                                     start read as a teammate's
    python -m ctf hof check FILE [FILE ...] --id CID  offline: the eligibility of saved start /
                                                     retry / result bodies (later files win)
    python -m ctf hof classify FILE --date DATE [--elapsed S] [--id CID] [--own ID ...]
                                                     offline: whose attempt a saved start reply is
                                                     (fresh, own, foreign, unknown); with --id, our
                                                     own starts recorded in the ledger count too

Nothing here contacts the platform. FILEs are read as JSON data only.

Exit codes: report 0 (1 with --strict when any WARN); check 0 eligible, 1 not eligible or a
regular attempt, 3 nothing said; classify 0 fresh or own, 1 foreign, 3 unknown; 2 an error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from ..platform import halloffame as hof

HELP = "Hall of Fame eligibility of timed attempts: report, check, classify (B-044)"
UNKNOWN_EXIT = 3


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    r = sub.add_parser("report", help="every timed start and result of the event, with WARN lines")
    r.add_argument("--json", action="store_true", help="one JSON object per record")
    r.add_argument("--strict", action="store_true", help="exit 1 when any record has a WARN")
    c = sub.add_parser("check", help="offline: eligibility of saved start/result bodies")
    c.add_argument("files", nargs="+", type=Path)
    c.add_argument("--id", dest="challenge_id", required=True, help="the timed challenge id")
    k = sub.add_parser("classify", help="offline: whose attempt a saved start reply is")
    k.add_argument("file", type=Path)
    k.add_argument("--date", required=True, help="the reply's Date header (HTTP-date or ISO)")
    k.add_argument("--elapsed", type=float, default=0.0, help="seconds the start request took")
    k.add_argument("--id", dest="challenge_id", help="the challenge id: our recorded starts count as own")
    k.add_argument("--own", action="append", default=[], help="an attempt id of our own (repeatable)")
    k.add_argument("--skew", type=float, default=hof.SKEW_TOLERANCE_S,
                   help=f"clock skew tolerance in seconds (default {hof.SKEW_TOLERANCE_S:g})")


def _load(path: Path) -> dict:
    try:
        body = json.loads(path.read_bytes())
    except OSError as e:
        raise ValueError(f"{path}: unreadable ({e.strerror or e})") from None
    except ValueError as e:
        raise ValueError(f"{path}: not JSON ({e})") from None
    if not isinstance(body, dict):
        raise ValueError(f"{path}: not a JSON object")
    return body


def _report(args) -> int:
    profile = _event.current()
    rows = hof.report(profile)
    warned = 0
    for r in rows:
        if r["warn"]:
            warned += 1
        if args.json:
            print(json.dumps(r, sort_keys=True))
            continue
        kind = "start " if r["event"] == hof.START_EVENT else "result"
        what = r.get("origin") if r["event"] == hof.START_EVENT else r.get("status")
        line = (f"{kind} {r.get('challenge_id')} attempt {r.get('attempt_id') or '?'}: {what}; "
                f"eligible={json.dumps(r.get('eligible'))} counts={json.dumps(r.get('counts') or {}, sort_keys=True)}")
        print(line)
        if r["warn"]:
            print(f"  WARN {r['warn']}")
    if not rows:
        print(f"event {profile.slug}: no timed start or result recorded")
    else:
        print(f"event {profile.slug}: {len(rows)} record(s), {warned} WARN")
    return 1 if (args.strict and warned) else 0


def _check(args) -> int:
    bodies = [_load(f) for f in args.files]
    el = hof.eligibility(args.challenge_id, *bodies)
    print(f"{el.challenge_id}: {el.verdict()}")
    if el.pool or el.counts:
        print(f"  said: {json.dumps({**el.pool, **el.counts}, sort_keys=True)}")
    if el.note:
        print(f"  NOTE {el.note}")
    if el.eligible is False or el.regular:
        return 1
    return 0 if el.eligible else UNKNOWN_EXIT


def _classify(args) -> int:
    body = _load(args.file)
    own = set(args.own)
    if args.challenge_id:
        own |= hof.own_attempt_ids(_event.current(), args.challenge_id)
    o = hof.classify_start(body, date=args.date, elapsed_s=args.elapsed, own_attempt_ids=own,
                           skew_tolerance_s=args.skew)
    print(f"{o.kind}: attempt {o.attempt_id or '?'}: {o.reason}")
    if o.kind == "foreign":
        return 1
    return UNKNOWN_EXIT if o.kind == "unknown" else 0


def run(args: argparse.Namespace) -> int:
    try:
        return {"report": _report, "check": _check, "classify": _classify}[args.action](args)
    except (_event.EventError, ValueError) as e:
        print(f"ctf hof {args.action}: error: {e}", file=sys.stderr)
        return 2
