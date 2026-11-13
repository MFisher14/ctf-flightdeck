"""ctf human -- human-only work, surfaced early (B-169): checklist, task cards, pins, confirm list.

    python -m ctf human checklist [--for YYYY-MM-DD] [--json] [--out FILE]
                                                   the evening checklist (default: for tomorrow)
    python -m ctf human add-card KIND --ask TEXT --need TEXT [--challenge ID] [--why T] [--source S]
                                                   a task card for one out-of-band step
    python -m ctf human add-pin CHALLENGE --ask TEXT [--decimals 4] [--candidate "lat,lon note"]...
                                                   queue the final map pin for the player
    python -m ctf human cards [--all] [--kind K] [--json]   open task cards (oldest first)
    python -m ctf human pins [--json]                        the OSINT final-pin queue
    python -m ctf human answer CARD VALUE [--by WHO]         record the player's answer
    python -m ctf human drop CARD --reason TEXT [--by WHO]   close a card nobody needs any more
    python -m ctf human confirm CHALLENGE (--flag F | --where FILE) [--points N] [--name N] [--note T]
                                                   add an item to the off-platform confirm list
    python -m ctf human confirm-list [--all] [--live] [--json]   the one-glance confirm list
    python -m ctf human confirmed CHALLENGE... [--by WHO]       tick items the player confirmed
    python -m ctf human reconcile TRUTH.csv [--live] [--json]   Game Master record vs the export

Exit codes: 0 ok, 1 reconcile found something to act on, 2 a bad request or missing configuration
(the message names it). Nothing here contacts the off-platform confirm system; --live asks the event
platform for the team's solves through the policy gate's read path (ctf.platform.get_adapter).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import sys
import time
from pathlib import Path

from .. import event as _event
from .. import humanops as _h
from ..platform import NotSupported, PlatformError

HELP = "human-only work: evening checklist, task cards, OSINT pin queue, confirm list, reconcile"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    sp = p.add_subparsers(dest="action", required=True)

    ck = sp.add_parser("checklist", help="the evening checklist of human-only items")
    ck.add_argument("--for", dest="for_date", help="the day it is for, YYYY-MM-DD (default: tomorrow)")
    ck.add_argument("--json", action="store_true")
    ck.add_argument("--out", help="also write the checklist to this file")

    ac = sp.add_parser("add-card", help="a task card for one out-of-band step")
    ac.add_argument("kind", choices=[k for k in _h.CARD_KINDS if k != "pin"],
                    help="; ".join(f"{k}: {v}" for k, v in _h.CARD_KIND_HELP.items() if k != "pin"))
    ac.add_argument("--ask", required=True, help="the exact question or step, self-contained")
    ac.add_argument("--need", required=True, help="the exact thing to hand back (a word, a label, a value)")
    ac.add_argument("--challenge")
    ac.add_argument("--why", default="", help="why an agent cannot do it")
    ac.add_argument("--source", default="", help="who asks (agent, lane)")

    ap = sp.add_parser("add-pin", help="queue the final map pin for the player")
    ap.add_argument("challenge")
    ap.add_argument("--ask", required=True, help="what the pin is (e.g. 'the bench in photo 2')")
    ap.add_argument("--decimals", type=int, default=_h.DEFAULT_PIN_DECIMALS,
                    help=f"decimals the answer must carry (default {_h.DEFAULT_PIN_DECIMALS})")
    ap.add_argument("--candidate", action="append", default=[],
                    help="'lat,lon' with an optional note after a space; repeatable")
    ap.add_argument("--why", default="")
    ap.add_argument("--source", default="")

    cs = sp.add_parser("cards", help="task cards, oldest first (open only unless --all)")
    cs.add_argument("--all", action="store_true")
    cs.add_argument("--kind", choices=_h.CARD_KINDS)
    cs.add_argument("--json", action="store_true")

    ps = sp.add_parser("pins", help="the OSINT final-pin queue")
    ps.add_argument("--json", action="store_true")

    an = sp.add_parser("answer", help="record the player's answer to a card")
    an.add_argument("card")
    an.add_argument("value")
    an.add_argument("--by", default="")

    dr = sp.add_parser("drop", help="close a card nobody needs any more")
    dr.add_argument("card")
    dr.add_argument("--reason", required=True)
    dr.add_argument("--by", default="")

    co = sp.add_parser("confirm", help="add an item to the off-platform confirm list")
    co.add_argument("challenge")
    co.add_argument("--flag")
    co.add_argument("--where", help="the file that holds the flag value")
    co.add_argument("--points", type=float)
    co.add_argument("--name")
    co.add_argument("--note", default="")

    cl = sp.add_parser("confirm-list", help="the one-glance confirm list")
    cl.add_argument("--all", action="store_true", help="include items already confirmed")
    cl.add_argument("--live", action="store_true", help="add the platform's team solves the ledger lacks")
    cl.add_argument("--json", action="store_true")

    cd = sp.add_parser("confirmed", help="tick items the player confirmed in the off-platform system")
    cd.add_argument("challenges", nargs="+")
    cd.add_argument("--by", default="")

    rc = sp.add_parser("reconcile", help="the Game Master record against the player's export")
    rc.add_argument("truth", help="CSV export: challenge[,points][,flag] with a header row")
    rc.add_argument("--live", action="store_true", help="add the platform's team solves the ledger lacks")
    rc.add_argument("--json", action="store_true")


def _jsonable(obj):
    if dataclasses.is_dataclass(obj):
        return {k: _jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, (list, tuple)):
        return [_jsonable(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, _dt.date):
        return obj.isoformat()
    return obj


def _live_solves(profile):
    from ..platform import get_adapter
    return get_adapter(profile).team_solves()


def run(args: argparse.Namespace) -> int:
    try:
        profile = _event.load(args.event) if args.event else _event.current()
        ops = _h.HumanOps(profile)
        return _ACTIONS[args.action](ops, args)
    except (_h.HumanOpsError, _event.EventError) as e:
        print(f"ctf human {args.action}: {e}", file=sys.stderr)
        return 2
    except PlatformError as e:
        if isinstance(e, NotSupported):
            raise                      # the ctf main prints "refused: <reason>" and exits 4
        print(f"ctf human {args.action}: platform: {e}", file=sys.stderr)
        return 2


def _checklist(ops: _h.HumanOps, args) -> int:
    day = None
    if args.for_date:
        try:
            day = _dt.date.fromisoformat(args.for_date)
        except ValueError:
            raise _h.HumanOpsError(f"--for {args.for_date!r} is not a date (YYYY-MM-DD)") from None
    cl = ops.checklist(day)
    text = json.dumps(_jsonable(cl), indent=1) if args.json else _h.render_checklist(cl)
    if args.out:
        Path(args.out).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    print(text, end="" if text.endswith("\n") else "\n")
    return 0


def _add_card(ops, args) -> int:
    c = ops.add_card(args.kind, ask=args.ask, need=args.need, challenge_id=args.challenge,
                     why=args.why, source=args.source)
    print(f"card {c.id} open: {args.kind}" + (f" / challenge {c.challenge_id}" if c.challenge_id else ""))
    return 0


def _add_pin(ops, args) -> int:
    c = ops.add_pin(args.challenge, ask=args.ask, decimals=args.decimals, candidates=args.candidate,
                    why=args.why, source=args.source)
    print(f"pin {c.id} queued for challenge {c.challenge_id} ({len(c.candidates)} candidate(s), "
          f"answer needs {c.decimals} decimals)")
    return 0


def _print_cards(cards, as_json: bool, empty: str) -> int:
    if as_json:
        for c in cards:
            print(json.dumps(_jsonable(c)))
        return 0
    if not cards:
        print(empty)
        return 0
    now = time.time()
    print("\n\n".join(_h.render_card(c, now) for c in cards))
    return 0


def _cards(ops, args) -> int:
    return _print_cards(ops.cards(status=None if args.all else "open", kind=args.kind), args.json,
                        "no task cards" if args.all else "no open task cards")


def _pins(ops, args) -> int:
    return _print_cards(ops.pin_queue(), args.json, "pin queue empty")


def _answer(ops, args) -> int:
    c = ops.answer(args.card, args.value, by=args.by)
    print(f"card {c.id} answered: {c.answer}")
    return 0


def _drop(ops, args) -> int:
    c = ops.drop(args.card, args.reason, by=args.by)
    print(f"card {c.id} dropped: {c.reason}")
    return 0


def _confirm(ops, args) -> int:
    it = ops.add_confirm(args.challenge, flag=args.flag, where=args.where, points=args.points,
                         name=args.name, note=args.note)
    print(f"{ops.confirm_system()} confirm list: {_h.confirm_line(it)}")
    return 0


def _confirm_list(ops, args) -> int:
    live = _live_solves(ops.profile) if args.live else None
    items = ops.confirm_list(include_done=args.all, live_solves=live)
    if args.json:
        for it in items:
            print(json.dumps(_jsonable(it)))
        return 0
    system = ops.confirm_system()
    pending = [i for i in items if not i.done]
    print(f"{system} confirm list: {len(pending)} pending" + (f", {len(items) - len(pending)} confirmed"
                                                            if args.all else ""))
    for it in items:
        print(f"  [{'x' if it.done else ' '}] {_h.confirm_line(it)}")
    return 0


def _confirmed(ops, args) -> int:
    for cid in args.challenges:
        it = ops.mark_confirmed(cid, by=args.by)
        print(f"confirmed in {ops.confirm_system()}: {it.challenge_id}")
    return 0


def _reconcile(ops, args) -> int:
    truth = _h.read_truth(args.truth)
    live = _live_solves(ops.profile) if args.live else None
    rep = ops.reconcile(truth, live_solves=live)
    if args.json:
        print(json.dumps(_jsonable(rep) | {"counts": rep.counts(), "clean": rep.clean}))
    else:
        print(_h.render_reconciliation(rep))
    return 0 if rep.clean else 1


_ACTIONS = {
    "checklist": _checklist, "add-card": _add_card, "add-pin": _add_pin, "cards": _cards, "pins": _pins,
    "answer": _answer, "drop": _drop, "confirm": _confirm, "confirm-list": _confirm_list,
    "confirmed": _confirmed, "reconcile": _reconcile,
}
