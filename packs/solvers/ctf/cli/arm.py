"""`python -m ctf arm` — the day-1 regression gate for the armed Layer-1 openers (B-014).

For each lane's opener it builds the synthetic first-days fixtures, runs the opener engine under the
intake network guard with no model, no token, no ledger and a fresh workdir, checks each frozen answer
key, and checks that no key also holds on the opener's neutral controls. The first release of any
event is meant to be played with this armed, so no model is on the critical path.

    python -m ctf arm                       arm every lane's opener
    python -m ctf arm --lane warmups        just one lane (repeatable)
    python -m ctf arm --event huntress      just the lanes that event's profile has (its slug is CTF_EVENT)
    python -m ctf arm --strict              a not-run opener also fails the gate
    python -m ctf arm --json                machine-readable results (with every case and control)
    python -m ctf arm --guard os            insist on the OS network sandbox (exit 2 where it is unavailable)
    python -m ctf arm --root DIR            read openers/layer1.toml and the engines from another checkout

Exit codes: 0 all selected openers armed (and, under --strict, none not-run), 1 an opener failed
(or, under --strict, one was not run), 2 a usage / declaration / guard error or nothing selected.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import openers as _openers
from ..intake import guard as _guard

HELP = "arm and regression-check the Layer-1 openers (no-model day-1 gate)"

_TAG = {_openers.ARMED: "ARMED  ", _openers.FAILED: "FAILED ", _openers.NOT_RUN: "not-run"}


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--lane", action="append", metavar="LANE",
                        help="only this lane's opener (repeatable)")
    parser.add_argument("--event", metavar="SLUG",
                        help="only the lanes this event profile has; the engines run with CTF_EVENT=SLUG")
    parser.add_argument("--strict", action="store_true",
                        help="a not-run opener (missing tool / not offline-armable) also fails the gate")
    parser.add_argument("--json", action="store_true", help="print results as JSON")
    parser.add_argument("--timeout", type=float, default=60.0,
                        help="per-run timeout in seconds (default 60)")
    parser.add_argument("--guard", choices=_guard.MODES, default="auto",
                        help="network guard for the engines (default auto: the OS sandbox when it works)")
    parser.add_argument("--root", metavar="DIR", type=Path,
                        help="the checkout to read openers/layer1.toml and the engines from (default: this one)")


def _case_json(c: _openers.CaseResult) -> dict:
    return {"fixture": c.fixture, "mode": c.mode, "status": c.status, "reason": c.reason,
            "found": list(c.found), "missing": list(c.missing), "exit_code": c.exit_code,
            "seconds": round(c.seconds, 3)}


def run(args: argparse.Namespace) -> int:
    try:
        openers = _openers.load(args.root)
    except _openers.OpenerError as e:
        print(f"ctf arm: {e}", file=sys.stderr)
        return 2

    profile = None
    if args.event:
        try:
            profile = _event.load(args.event)
        except _event.EventError as e:
            print(f"ctf arm: --event {args.event}: {e}", file=sys.stderr)
            return 2
    try:
        selected = _openers.select(openers, lanes=args.lane, profile=profile)
    except _openers.OpenerError as e:
        print(f"ctf arm: {e}", file=sys.stderr)
        return 2
    if not selected:
        scope = f" for event '{args.event}'" if args.event else ""
        print(f"ctf arm: no openers selected{scope} "
              f"(declared lanes: {', '.join(o.lane for o in openers)})", file=sys.stderr)
        return 2
    try:
        guard = _guard.resolve(args.guard)
    except _guard.GuardError as e:
        print(f"ctf arm: {e}", file=sys.stderr)
        return 2

    results = [_openers.arm(o, root=args.root, timeout=args.timeout, guard=guard, profile=profile)
               for o in selected]

    if args.json:
        print(json.dumps([{"lane": r.lane, "engine": r.engine, "status": r.status, "reason": r.reason,
                           "found": list(r.found), "missing": list(r.missing),
                           "exit_code": r.exit_code, "seconds": round(r.seconds, 3),
                           "cases": [_case_json(c) for c in r.cases]} for r in results],
                         indent=2))
    else:
        print(f"guard: {guard.reason}")
        for r in results:
            if r.status == _openers.ARMED:
                n_cases = sum(c.mode != "control" for c in r.cases)
                detail = f"{n_cases} case(s), {len(r.cases) - n_cases} control(s), {r.seconds:.2f}s"
            else:
                detail = r.reason
            print(f"  [{_TAG.get(r.status, r.status)}] {r.lane:<18} {r.engine:<34} {detail}")

    failed = [r for r in results if r.status == _openers.FAILED]
    not_run = [r for r in results if r.status == _openers.NOT_RUN]
    armed = [r for r in results if r.status == _openers.ARMED]
    if not args.json:
        line = f"\n{len(armed)} armed, {len(failed)} failed, {len(not_run)} not run"
        print(line + (" (strict: not-run fails)" if args.strict and not_run else ""))
    if failed or (args.strict and not_run):
        return 1
    return 0
