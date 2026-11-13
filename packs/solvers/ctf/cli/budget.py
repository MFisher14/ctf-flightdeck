"""ctf budget status | extend | stop | resume | set -- per-challenge spend caps and stop signals (B-033).

    python -m ctf budget status [ID ...] [--json]      spend, cap, state and idle time per challenge
    python -m ctf budget extend ID --usd N --reason R  raise a cap (a person at a terminal only)
    python -m ctf budget stop ID --solved [--by WHO]   fire the team-solve stop by hand (B-015 hook)
    python -m ctf budget stop ID [--note TEXT]         a manual stop
    python -m ctf budget resume ID                     lift a manual or no-progress stop (terminal only)
    python -m ctf budget set ID [--points N] [--opened WHEN] [--tail] [--name NAME]
                                                       what the cap is computed from

`extend` and `resume` are the human decisions the budget gate waits for. They refuse to run without
an interactive terminal and ask you to type the challenge id back, so no agent can extend a cap.
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys

from .. import budget as _budget
from .. import event as _event

HELP = "per-challenge budget caps and stop signals: status, extend, stop, resume, set"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    sp = p.add_subparsers(dest="action", required=True)
    st = sp.add_parser("status", help="spend, cap and state per challenge")
    st.add_argument("ids", nargs="*", help="challenge ids (default: every challenge in the ledger)")
    st.add_argument("--json", action="store_true", help="one JSON object per line")
    ex = sp.add_parser("extend", help="raise a challenge's cap (interactive; a human decision)")
    ex.add_argument("id")
    ex.add_argument("--usd", type=float, required=True, help="amount to add to the cap")
    ex.add_argument("--reason", required=True)
    so = sp.add_parser("stop", help="stop work on a challenge")
    so.add_argument("id")
    so.add_argument("--solved", action="store_true", help="a teammate solved it (the solved-watcher hook)")
    so.add_argument("--by", help="who solved it / who stopped it")
    so.add_argument("--note")
    rs = sp.add_parser("resume", help="lift a manual or no-progress stop (interactive)")
    rs.add_argument("id")
    se = sp.add_parser("set", help="record points / opening time / tail flag for a challenge")
    se.add_argument("id")
    se.add_argument("--points", type=float)
    se.add_argument("--opened", help="when the challenge opened (epoch or ISO-8601; for per-day budgets)")
    se.add_argument("--tail", action=argparse.BooleanOptionalAction, default=None,
                    help="force the 20-minute no-progress timer on (or off)")
    se.add_argument("--name")


def _fmt(st: _budget.ChallengeStatus) -> str:
    pct = (100.0 * st.spent_usd / st.cap_usd) if st.cap_usd else 0.0
    cap = f"${st.cap_usd:.2f}"
    if st.extended_usd:
        cap += f" (base ${st.base_cap_usd:.2f} + extended ${st.extended_usd:.2f})"
    state = {"ok": "ok", "at_cap": "AT CAP: waiting for `ctf budget extend`"}.get(st.state, "")
    if st.state == "stopped":
        state = f"STOPPED ({st.stop_reason}{', by ' + st.stop_by if st.stop_by else ''})"
    pts = "-" if st.points is None else f"{st.points:g}"
    idle = "-" if st.idle_seconds is None else f"{st.idle_seconds / 60:.0f}m"
    timer = "on" if st.timer_applies else "off"
    return (f"{st.challenge_id:<12} spent ${st.spent_usd:.2f} of {cap}  {pct:.0f}%  {state}  "
            f"pts={pts} tokens={st.tokens:,} no-progress-timer={timer} idle={idle}")


def _require_human(action: str, cid: str) -> str:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise PermissionError(f"`ctf budget {action}` is a human decision: run it yourself in an "
                              "interactive terminal (no flag bypasses this)")
    typed = input(f"Type the challenge id ({cid}) to confirm {action}: ").strip()
    if typed != cid:
        raise PermissionError(f"confirmation did not match {cid!r}; nothing changed")
    return getpass.getuser() or "human"


def run(args: argparse.Namespace) -> int:
    try:
        prof = _event.load(args.event) if args.event else _event.current()
        meter = _budget.LedgerMeter(prof)
        if args.action == "status":
            ids = args.ids or meter.challenges()
            if not ids and not args.json:
                print("no challenges in the ledger yet")
            for cid in ids:
                st = meter.status(cid)
                print(json.dumps(st.to_dict()) if args.json else _fmt(st))
            return 0
        if args.action == "extend":
            st = meter.status(args.id)
            print(_fmt(st))
            if args.usd <= 0:
                raise ValueError("--usd must be positive")
            who = _require_human("extend", args.id)
            new = meter.extend(args.id, args.usd, by=who, reason=args.reason)
            print(f"extended {args.id} by ${args.usd:.2f}: cap now ${new:.2f}")
            return 0
        if args.action == "stop":
            if args.solved:
                fresh = _budget.on_team_solve(args.id, solver=args.by, workdir=meter.workdir)
                print(f"{args.id}: {'stopped (team solve)' if fresh else 'already stopped for a team solve'}")
            else:
                fresh = meter.stop(args.id, "manual", by=args.by or getpass.getuser(), note=args.note)
                print(f"{args.id}: {'stopped (manual)' if fresh else 'already stopped'}")
            return 0
        if args.action == "resume":
            st = meter.status(args.id)
            print(_fmt(st))
            if st.stop_reason is None:
                raise ValueError(f"challenge {args.id} is not stopped")
            if st.stop_reason not in _budget.RESUMABLE:
                raise ValueError(f"challenge {args.id} was stopped by {st.stop_reason}; that stop is final")
            who = _require_human("resume", args.id)
            meter.resume(args.id, by=who)
            print(f"{args.id}: resumed")
            return 0
        if args.points is None and args.opened is None and args.tail is None and not args.name:
            raise ValueError("set needs at least one of --points, --opened, --tail/--no-tail, --name")
        meter.register(args.id, points=args.points, opened_at=args.opened, tail=args.tail, name=args.name)
        print(_fmt(meter.status(args.id)))
        return 0
    except PermissionError as e:
        print(f"ctf budget: {e}", file=sys.stderr)
        return 1
    except (_event.EventError, ValueError, EOFError) as e:
        print(f"ctf budget: {e}", file=sys.stderr)
        return 2
