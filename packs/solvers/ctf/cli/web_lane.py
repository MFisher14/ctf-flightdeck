"""ctf web-lane -- start a web Layer-1 on every released web row and bank the proofs (B-007).

    python -m ctf web-lane list                  the released, unsolved web rows this event shows us
    python -m ctf web-lane run                    force each web row open, read it (GET-only), bank proofs
    python -m ctf web-lane run --dry-run          read every row but submit nothing (no bank; local only)
    python -m ctf web-lane run --only <id> ...    only these web rows (each must be a released web row)

``--event SLUG`` or ``--profile events/<slug>/event.toml`` selects the event (default: the current
event).  Every call goes through ``ctf.platform.get_adapter`` -- the SubmitGate is the one road to a
submission.  The lane drives the Game Master only and refuses any other platform kind before any
start.  It is GET-only -- it forces the proof reader into ``get_only`` mode so its clue-gated
state-changing siblings cannot reach the wire (Open O-2 keeps any state-changing web action out until
it is settled; the POST/SSRF/auth/header/WebSocket classes are B-233..B-237) -- and submits only a
value the event's ``[proof]`` format accepts.  It never runs a model and never guesses.  ``--dry-run``
is a local no-submit read, not the Game Master ``op=practice`` wire op (still unported).

Exit: 0 ok, 2 on an error (including a platform kind the lane does not drive, e.g. CTFd), 4 when the
event forbids automated submission/instances (a manual-mode event, instances not allowed).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import paths as _paths
from .. import web_lane as _lane
from ..platform import NotAllowed, NotSupported, PlatformError, get_adapter

HELP = "start a web Layer-1 on every released web row and bank its proof (B-007)"
REFUSED_EXIT = 4


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml under events/ (instead of --event)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sp = p.add_subparsers(dest="action", required=True)
    sp.add_parser("list", help="the released, unsolved web rows this event shows us")
    pr = sp.add_parser("run", help="force each web row open, read it GET-only, bank the proofs")
    pr.add_argument("--dry-run", action="store_true", dest="dry_run",
                    help="read every row but submit nothing (local; not the Game Master op=practice)")
    pr.add_argument("--include-solved", action="store_true",
                    help="also list AND run rows already solved by our team (re-reads them; "
                         "a re-submit of a solved row is judged already-solved)")
    pr.add_argument("--only", action="append", metavar="ID", dest="only",
                    help="only this web row id (repeatable); each must be a released web row")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        root = _paths.events_root().resolve()
        path = Path(args.profile).expanduser().resolve()
        if not path.is_relative_to(root):
            raise _event.EventError(
                f"--profile {args.profile} is outside the repo's events/ folder; the web lane only "
                "loads committed event profiles (use --event SLUG)")
        return _event.load_path(path)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def build_gate(profile):
    """The SubmitGate for `profile` (seam the tests replace with a fake Game Master)."""
    return get_adapter(profile)


def _row_line(r: _lane.RowResult) -> str:
    extra = ""
    if r.proofs:
        extra = f"  proofs={len(r.proofs)}"
    if r.reason:
        extra += f"  ({r.reason})"
    # B-237: one indented line per named class note (why an unread target was not read).
    return "\n".join([f"{r.state:<14} {r.challenge_id}{extra}"] + [f"    - {n}" for n in r.notes])


def run(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
        gate = build_gate(profile)
    except (_event.EventError, PlatformError) as e:
        print(f"ctf web-lane: {e}", file=sys.stderr)
        return 2

    try:
        if args.action == "list":
            rows = _lane.select_web_rows(gate)
            if args.json:
                print(json.dumps([{"id": c.id, "name": c.name, "tags": list(c.tags)} for c in rows]))
            else:
                for c in rows:
                    print(f"{c.id}  ({', '.join(c.tags) or 'web'})")
                print(f"# {len(rows)} released, unsolved web row(s)", file=sys.stderr)
            return 0

        # action == run
        _lane.require_gamemaster(gate)      # refuse a non-Game-Master event before any start_instance
        rows = _lane.select_web_rows(gate, include_solved=args.include_solved)
        if args.only:
            want = set(args.only)
            picked = [c for c in rows if c.id in want]
            missing = sorted(want - {c.id for c in picked})
            if missing:
                print(f"ctf web-lane: not a released web row: {', '.join(missing)}", file=sys.stderr)
                return 2
            rows = picked
        results = _lane.run_lane(gate, rows=rows, practice=args.dry_run,
                                 include_solved=args.include_solved)
    except NotAllowed as e:
        print(f"ctf web-lane: {e}", file=sys.stderr)
        return REFUSED_EXIT
    except (NotSupported, PlatformError, _lane.WebLaneError) as e:
        print(f"ctf web-lane: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([{"id": r.challenge_id, "state": r.state, "proofs": dict(r.proofs),
                           "reason": r.reason, "notes": list(r.notes)} for r in results]))
    else:
        for r in results:
            print(_row_line(r))
    banked = sum(1 for r in results if r.state == _lane.BANKED)
    found = sum(1 for r in results if r.state == _lane.FOUND)
    tag = "read" if args.dry_run else "banked"
    print(f"# {len(results)} web row(s); {found if args.dry_run else banked} {tag}", file=sys.stderr)
    return 0
