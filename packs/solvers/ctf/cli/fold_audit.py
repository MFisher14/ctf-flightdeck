"""ctf fold-audit: fail when a live fix recorded for an event has not reached the master commit the
next event will start from (B-038).

    python -m ctf fold-audit SLUG [--target REF] [--fork DIR] [--workspace DIR] [--json]
    python -m ctf fold-audit --all [--target REF] [--exclude SLUG ...] [--json]

--target defaults to HEAD of the master (the commit `promote start` would tag for the next event).
With --fork / --workspace the event's tree is inventoried again and anything changed or added since
the record was made fails. --all audits every event with a promotion record or a start tag.
Exit 0 pass, 1 fail, 2 error (no record, no git checkout, unknown target).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import event as _event
from .. import foldaudit as _fa
from .. import paths
from ..promote import PromoteError

HELP = "gate: every live fix recorded for an event reached the master commit the next event starts from"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("slug", nargs="?", help="event slug (or --all)")
    p.add_argument("--all", action="store_true", help="every event with a record or a start tag")
    p.add_argument("--exclude", action="append", default=[], help="with --all: skip this event")
    p.add_argument("--target", default="HEAD", help="master ref the next event starts from (default HEAD)")
    p.add_argument("--master", type=Path, help="the master checkout (default: this checkout)")
    p.add_argument("--record", type=Path, help="the promotion record (default: <master>/events/SLUG/promotion.json)")
    p.add_argument("--fork", type=Path, help="re-inventory the event fork and fail on unrecorded changes")
    p.add_argument("--workspace", type=Path, help="re-inventory the event workspace too")
    p.add_argument("--json", action="store_true")


def run(args: argparse.Namespace) -> int:
    if bool(args.slug) == bool(args.all):
        print("ctf fold-audit: give one event slug or --all", file=sys.stderr)
        return 2
    if args.all and (args.record or args.fork or args.workspace):
        print("ctf fold-audit: --record/--fork/--workspace need one event slug", file=sys.stderr)
        return 2
    master = args.master or paths.repo_root()
    try:
        if args.all:
            results = _fa.audit_all(master=master, target=args.target, exclude=set(args.exclude))
        else:
            results = [_fa.audit(args.slug, master=master, target=args.target, record=args.record,
                                 fork=args.fork, workspace=args.workspace)]
    except (PromoteError, _event.EventError) as e:
        print(f"ctf fold-audit: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(_fa.to_json(results))
    else:
        for r in results:
            print(_fa.render(r))
        if not results:
            print("fold-audit: no event has a promotion record or a start tag")
    failed = [r for r in results if not r.passed]
    summary = (f"FOLD_AUDIT result={'fail' if failed else 'pass'} events={len(results)} "
               f"failed={len(failed)} unfolded={sum(len(r.failures()) for r in results)}")
    print(summary, file=sys.stderr if args.json else sys.stdout)
    return 1 if failed else 0
