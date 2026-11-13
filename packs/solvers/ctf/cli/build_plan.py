"""ctf build-plan rank | check | pre-event — pay for the build once (B-008).

    python -m ctf build-plan rank --items to_build.json [--event SLUG] [--board board.json]
                                  [--effort-budget UNITS] [--top N] [--json] [--record]
    python -m ctf build-plan check ITEM_ID [--event SLUG] [--now ISO8601]   # exit 0 allowed, 1 refused
    python -m ctf build-plan pre-event [--event SLUG] [--run]

Payoffs and scores are modeled estimates, not measured savings; the output says so.
Effort units: S=1, M=3, L=8, XL=20. The default effort budget is 0: nothing but the doctor and the
rehearsal is approved until the player sets a budget.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import sys

from .. import buildplan as _bp
from .. import event as _event
from .. import preevent as _pre

HELP = "rank pre-event builds by modeled value per effort; gate builds on an approved ranking"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    r = sp.add_parser("rank", help="rank to_build-style items for an event (modeled estimates)")
    r.add_argument("--items", required=True, help="JSON list of item records (to_build.json shape)")
    r.add_argument("--event", help="event slug (default: the current event)")
    r.add_argument("--board", help="JSON list of visible challenges ({category, name, description})")
    r.add_argument("--effort-budget", type=float, default=0.0,
                   help="effort units to approve (S=1 M=3 L=8 XL=20; default 0 = approve nothing)")
    r.add_argument("--top", type=int, default=25, help="rows to print (0 = all; default 25)")
    r.add_argument("--json", action="store_true", help="print the ranking as JSON")
    r.add_argument("--record", action="store_true",
                   help="write <workdir>/build-plan/ranking.json for the gate (and a ledger event)")
    c = sp.add_parser("check", help="may this build run now? exit 0 approved, 1 refused")
    c.add_argument("item_id")
    c.add_argument("--event", help="event slug (default: the current event)")
    c.add_argument("--now", help="ISO 8601 time to judge the phase at (default: now)")
    pe = sp.add_parser("pre-event", help="the default pre-event plan: doctor, rehearsal, approved builds")
    pe.add_argument("--event", help="event slug (default: the current event)")
    pe.add_argument("--run", action="store_true", help="run the doctor and rehearsal hooks")


def _profile(slug: str | None) -> _event.EventProfile:
    return _event.load(slug) if slug else _event.current()


def _fmt_usd(v: float | None) -> str:
    return "-" if v is None else f"${v:,.0f}"


def _rank(args: argparse.Namespace) -> int:
    prof = _profile(args.event)
    items = _bp.load_items(args.items)
    board = _bp.load_board(args.board) if args.board else None
    rk = _bp.rank(items, prof, effort_budget=args.effort_budget, board=board,
                  items_source=args.items, board_source=args.board)
    if args.json:
        print(rk.to_json())
    else:
        print(f"build ranking for {prof.slug}: {len(rk.entries)} items, effort budget "
              f"{rk.effort_budget:g} units, board {'visible' if rk.board_visible else 'not visible'}")
        print(f"NOTE: payoff, value and score are MODELED ESTIMATES: {_bp.ESTIMATE_LABEL}.")
        counts = {d: sum(e.decision == d for e in rk.entries) for d in _bp.DECISIONS}
        print("  " + "  ".join(f"{d}={n}" for d, n in counts.items()))
        print(f"  {'#':>3} {'id':<8} {'decision':<11} {'score':>8} {'value':>8} {'eff':>4} "
              f"{'rows':>4} {'payoff*':>9}  lane / reason")
        shown = rk.entries if args.top == 0 else rk.entries[:args.top]
        for e in shown:
            print(f"  {e.rank:>3} {e.id:<8} {e.decision:<11} {e.score:>8.3f} {e.value:>8.2f} "
                  f"{e.effort:>4} {e.closes:>4} {_fmt_usd(e.payoff_usd):>9}  {e.lane}: {e.reason}")
        if len(shown) < len(rk.entries):
            print(f"  ... {len(rk.entries) - len(shown)} more (--top 0 for all)")
        print("  * payoff = the first $ figure in the item's payoff text: a modeled estimate.")
    if args.record:
        p = _bp.record(rk)
        print(f"recorded {p} ({len(rk.approved())} approved)", file=sys.stderr if args.json else sys.stdout)
    return 0


def _check(args: argparse.Namespace) -> int:
    prof = _profile(args.event)
    now = None
    if args.now:
        try:
            now = _dt.datetime.fromisoformat(args.now)
        except ValueError:
            print(f"ctf build-plan: --now {args.now!r} is not ISO 8601", file=sys.stderr)
            return 2
    dec = _bp.check_build(args.item_id, prof, now=now)
    print(f"{'ALLOW' if dec.allowed else 'REFUSE'}  {dec.item_id}  [{dec.phase}]  {dec.reason}")
    return 0 if dec.allowed else 1


def _pre_event(args: argparse.Namespace) -> int:
    prof = _profile(args.event)
    try:
        rk = _bp.load_ranking()
    except _bp.BuildPlanError as e:
        rk = None
        print(f"no ranking: {e}")
    if rk is not None and rk.event != prof.slug:
        print(f"ignoring the recorded ranking: it is for '{rk.event}', not '{prof.slug}'")
        rk = None
    print(f"pre-event plan for {prof.slug}:")
    for n, s in enumerate(_pre.plan(prof, rk), 1):
        print(f"  {n}. [{s.kind}] {s.name}: {s.detail}")
    if not any(s.kind == "build" for s in _pre.plan(prof, rk)):
        print("  (no builds approved: pre-event work is the doctor and the rehearsal)")
    if not args.run:
        return 0
    bad = 0
    for r in _pre.run_hooks(prof):
        bad += not r.passed
        print(f"  {r.status.upper():<5} {r.name}: {r.detail}")
    if bad:
        print(f"ctf build-plan: {bad} pre-event hook(s) did not pass (a stub is not a pass)", file=sys.stderr)
        return 3
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "rank":
            return _rank(args)
        if args.action == "check":
            return _check(args)
        return _pre_event(args)
    except (_event.EventError, _bp.BuildPlanError, ValueError) as e:
        print(f"ctf build-plan: {e}", file=sys.stderr)
        return 2
