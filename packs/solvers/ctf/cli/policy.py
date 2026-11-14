"""`ctf policy`: the event's solve policy, one config every harness reads (B-173, ctf/eventpolicy.py).

    python -m ctf policy show [--json] [--event SLUG]       every policy value of the event
    python -m ctf policy authorize-sweep <id> --count N --reason R [--ttl S]
                                                            the PLAYER's one-run sweep authorization
    python -m ctf policy sweep <id> --auth A --candidates FILE --note N
                                                            one paced sweep run under that authorization
    python -m ctf policy point <id> <host[:port]> --reason R
                                                            a challenge service the player pointed at
    python -m ctf policy unpoint <host[:port]> --reason R   withdraw a point
    python -m ctf policy guesses [<id>]                     logged guesses and sweep sends, with notes

The event is CTF_EVENT (else the only profile); `show --event` reads another one. Exit codes: 0 ok
(sweep: a candidate was accepted), 1 sweep ran and nothing was accepted, 2 error, 4 refused by the
event's policy.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import eventpolicy as ep
from ..platform import NotAllowed, NotSupported, PlatformError, get_adapter
from ..platform import legacy as _legacy
from ..platform.queue import QueueError
from ..platform.rules import EventRules

HELP = "the event's solve policy: show, authorize-sweep, sweep, point, unpoint, guesses (B-173)"
REFUSED_EXIT = 4


def add_arguments(p: argparse.ArgumentParser) -> None:
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("show", help="every policy value of the event")
    s.add_argument("--json", action="store_true", help="one JSON object (for scripts and harnesses)")
    s.add_argument("--event", metavar="SLUG", help="default: the current event (CTF_EVENT)")
    a = sub.add_parser("authorize-sweep", help="the player's authorization for ONE sweep run on a challenge")
    a.add_argument("challenge_id")
    a.add_argument("--count", type=int, required=True, help="most sends the run may make")
    a.add_argument("--reason", required=True, help="who authorized it and why (goes into the write-up)")
    a.add_argument("--ttl", type=float, default=None, help="seconds until it expires (default sweep.ttl_s)")
    w = sub.add_parser("sweep", help="one paced sweep run under a player's authorization")
    w.add_argument("challenge_id")
    w.add_argument("--auth", required=True, help="the id authorize-sweep printed")
    w.add_argument("--candidates", type=Path, required=True, help="file with one candidate value per line")
    w.add_argument("--note", required=True, help="how the candidate list was built")
    pt = sub.add_parser("point", help="record a challenge service the player pointed at")
    pt.add_argument("challenge_id")
    pt.add_argument("address", help="host or host:port the player gave")
    pt.add_argument("--reason", required=True, help="the player's words naming the service")
    up = sub.add_parser("unpoint", help="withdraw a pointed service")
    up.add_argument("address")
    up.add_argument("--reason", required=True)
    g = sub.add_parser("guesses", help="logged guesses and sweep sends, with their provenance notes")
    g.add_argument("challenge_id", nargs="?")


def _err(action: str, msg: str, code: int = 2) -> int:
    word = "refused" if code == REFUSED_EXIT else "error"
    print(f"ctf policy {action}: {word}: {msg}", file=sys.stderr)
    return code


def _shown(profile, rec: dict) -> str:
    if "flag" in rec:
        return str(rec["flag"])
    return "sha256:" + str(rec.get("flag_sha256", ""))[:12]


def _sweep(args, profile) -> int:
    err = _legacy.refusal(profile, "ctf policy sweep", submit=True)   # R-02: manual refuses first
    if isinstance(err, NotAllowed):
        return _err("sweep", str(err), REFUSED_EXIT)
    try:
        text = args.candidates.read_text(encoding="utf-8")
    except OSError as e:
        return _err("sweep", f"cannot read the candidate file {args.candidates}: {e}")
    cands = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not cands:
        return _err("sweep", f"{args.candidates} holds no candidate values")
    try:
        gate = get_adapter(profile)
        rep = ep.run_sweep(gate, args.challenge_id, cands, auth_id=args.auth, note=args.note)
    except ep.SweepError as e:
        return _err("sweep", str(e), REFUSED_EXIT)
    except NotSupported:
        raise
    except (PlatformError, QueueError) as e:
        notes = "".join(f"; {n}" for n in getattr(e, "__notes__", ()))
        return _err("sweep", f"{e}{notes}")
    shown_flag = (rep.accepted if profile.rules.flag_sharing == "allowed" else "<flag>")
    print(f"sweep {rep.auth_id} on challenge {rep.challenge_id}: {rep.outcome}; {rep.sent} sent, "
          f"{len(rep.skipped)} skipped as already judged")
    if rep.accepted is not None:
        print(f"accepted: {shown_flag}")
    if rep.reason:
        print(f"why it ended: {rep.reason}")
    return 0 if rep.accepted is not None else 1


def run(args: argparse.Namespace) -> int:
    act = args.action
    try:
        profile = (_event.load(args.event) if act == "show" and args.event else _event.current())
    except _event.EventError as e:
        return _err(act, str(e))
    try:
        if act == "show":
            pol = ep.summary(profile)
            if args.json:
                print(json.dumps(pol.to_dict(), sort_keys=True))
            else:
                print("\n".join(ep.lines(pol)))
            return 0
        if act == "authorize-sweep":
            try:
                rec = EventRules(profile).authorize_sweep(args.challenge_id, args.count, args.reason,
                                                          ttl_s=args.ttl)
            except ValueError as e:
                return _err(act, str(e), REFUSED_EXIT)
            print(f"authorized one sweep run of up to {rec['count']} send(s) on challenge "
                  f"{rec['challenge_id']}; auth id {rec['auth_id']}")
            pen = profile.rules.wrong_penalty
            if pen:
                print(f"worst case: {rec['count'] * pen} point(s) lost ({pen} per wrong answer)")
            print(f"run it once: python -m ctf policy sweep {rec['challenge_id']} --auth {rec['auth_id']} "
                  "--candidates FILE --note \"...\"")
            return 0
        if act == "sweep":
            return _sweep(args, profile)
        if act == "point":
            rec = ep.point(profile, args.challenge_id, args.address, args.reason)
            port = f":{rec['port']}" if "port" in rec else " (any port)"
            print(f"pointed: {rec['host']}{port} for challenge {rec['challenge_id']}; the scope guard "
                  "now admits it")
            return 0
        if act == "unpoint":
            rec = ep.unpoint(profile, args.address, args.reason)
            print(f"unpointed: {rec['host']}" + (f":{rec['port']}" if "port" in rec else ""))
            return 0
        rows = ep.guess_log(profile, args.challenge_id)
        for r in rows:
            kind = f"sweep {r['sweep']}" if r.get("sweep") else "guess"
            print(f"challenge {r.get('challenge_id')}  {kind:<22} {r.get('status'):<14} {_shown(profile, r)}  "
                  f"({r.get('provenance')})")
        if not rows:
            print("no logged guesses or sweep sends")
        return 0
    except ep.PolicyError as e:
        return _err(act, str(e), REFUSED_EXIT)
    except ValueError as e:         # a corrupt ledger line
        return _err(act, str(e))
