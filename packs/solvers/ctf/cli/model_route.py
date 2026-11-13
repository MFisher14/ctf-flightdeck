"""ctf model-route check | show | resolve -- the per-role, per-difficulty model router (B-201,
ctf/router.py).

    python -m ctf model-route check   [--event SLUG | --profile PATH]
    python -m ctf model-route show    [--harness claude|codex] [--json]
    python -m ctf model-route resolve ROLE [--difficulty D] [--harness H] [--category C] [--json]

`check` validates the profile's [routing] table (or, with none, the built-in defaults) against
tools/ledger/pricing.json: every model priced, each rule's harness and speed tier valid for its model;
exit 2 naming each problem. `show` prints every role x difficulty route; `resolve` one. Both read the
event ledger for the B-096 A/B gate (an approving `ab_verify` record moves verify to its model) and
write nothing. Without a [routing] table the launchers and `ctf escalate` do not route: `show` then
says so and prints the defaults an opted-in profile would start from.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import event as _event
from .. import paths as _paths
from .. import router as _router

HELP = "the per-role, per-difficulty model router (B-201): check, show and resolve routes"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)
    sp.add_parser("check", help="validate the routing table against the price table")
    sh = sp.add_parser("show", help="print every role x difficulty route")
    sh.add_argument("--harness", choices=_router.HARNESSES, help="routes as this launcher sees them")
    sh.add_argument("--json", action="store_true")
    rs = sp.add_parser("resolve", help="print the route for one role")
    rs.add_argument("role", choices=_router.ROLES)
    rs.add_argument("--difficulty", choices=_router.DIFFICULTIES)
    rs.add_argument("--harness", choices=_router.HARNESSES)
    rs.add_argument("--category")
    rs.add_argument("--json", action="store_true")


def _profile(args) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _line(r: _router.Route) -> str:
    model = r.model or "<CLI default>"
    tier = r.tier + (f" (budget ${r.budget_usd:g})" if r.budget_usd is not None else "")
    notes = "".join(f"\n    note: {n}" for n in r.notes)
    return f"{r.role:<12} {r.difficulty:<7} {model:<26} {r.effort:<8} {tier:<12} {r.source}{notes}"


def run(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
        rt = _router.Router.from_profile(profile, workdir=_paths.workdir(profile.slug))
        if args.action == "check":
            state = "opted in" if rt.opted_in else "no [routing] table: launches and escalation are not routed"
            print(f"routing ok: {profile.slug} ({state}; {len(rt.routing.rules)} rule(s))")
            return 0
        if args.action == "show":
            routes = rt.table(harness=args.harness)
            if args.json:
                print(json.dumps({"event": profile.slug, "opted_in": rt.opted_in,
                                  "routes": [r.to_dict() for r in routes]}, indent=2))
                return 0
            if not rt.opted_in:
                print(f"{profile.slug} has no [routing] table: nothing is routed; the defaults below are "
                      "what an opted-in profile starts from")
            for r in routes:
                print(_line(r))
            return 0
        r = rt.resolve(args.role, args.difficulty, harness=args.harness, category=args.category)
        print(json.dumps(r.to_dict(), indent=2) if args.json else _line(r))
        return 0
    except (_event.EventError, _router.RouterError) as e:
        print(f"ctf model-route: {e}", file=sys.stderr)
        return 2
