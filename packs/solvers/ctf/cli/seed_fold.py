"""ctf seed-fold: fold event-learned label verdicts into the tracked master seeds (B-040).

    python -m ctf seed-fold [LANE ...] [--dry-run] [--workdir DIR] [--json]

With no lane it folds every lane that has a runtime label ledger under the event workdir; with lanes it
folds exactly those. This is the "fold step after each solve": the same promotion `labels.py promote`
runs by hand, over every lane at once, so it can be run after each accepted run. It promotes only what
the judge ledger already recorded, and an order-degenerate acceptance (one the input could not
distinguish) folds its evidence but never its name.

Exit 0 folded (even when nothing changed), 2 an error (no judge ledger, an unknown lane, no event
workdir, an unreadable seed).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import seedfold as _seedfold

HELP = "fold event-learned label verdicts into the tracked master seeds (B-040)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("lanes", nargs="*", help="lanes to fold (default: every lane with a ledger)")
    p.add_argument("--dry-run", action="store_true", help="report the keys that would change; write nothing")
    p.add_argument("--workdir", type=Path, metavar="DIR", help="the event workdir (default: ctf.paths.workdir())")
    p.add_argument("--json", action="store_true")


def run(args: argparse.Namespace) -> int:
    # The explicit --workdir is threaded straight into the fold (seedfold -> labels), never through the
    # process environment: $CTF_WORKDIR is read only by ctf.paths, and a CLI run leaves it untouched.
    workdir = args.workdir.expanduser().resolve() if args.workdir is not None else None
    try:
        result = _seedfold.fold_all(args.lanes or None, dry_run=args.dry_run,
                                    warn=_seedfold._note, workdir=workdir)
    except (_seedfold.SeedFoldError, _event.EventError) as e:
        print(f"ctf seed-fold: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({lane: changed for lane, changed in result.items()}, indent=2))
        return 0
    verb = "would update" if args.dry_run else "updated"
    total = 0
    lm = _seedfold.labels_module()
    for lane, changed in result.items():
        for line in changed:
            print(f"{lane}: {line}")
        total += len(changed)
        if changed:
            print(f"{verb} {len(changed)} key(s) in {_seedfold.seed_path(lm, lane)}")
    if not result:
        print("seed-fold: no lane has a runtime label ledger; nothing to fold")
    else:
        print(f"SEED_FOLD lanes={len(result)} keys={total} {'dry-run' if args.dry_run else 'written'}")
    return 0
