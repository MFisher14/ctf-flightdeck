"""ctf contract show | check | report | may-stop | solves | fact | fresh-eyes -- the solver contract
(B-172, ctf/solver_contract.py).

    python -m ctf contract show [--lane L]
    python -m ctf contract check [FILE|-] [--challenge ID]
    python -m ctf contract report ID --status S [--next N] [--evidence E] [--oracle O] [--solves S]
                                     [--stop-loss X] [--by WHO]
    python -m ctf contract may-stop ID [--json]
    python -m ctf contract solves ID [--record N --source S]
    python -m ctf contract fact ID TEXT --evidence E [--by WHO]
    python -m ctf contract fresh-eyes ID [--write]

`show` prints the contract every brief carries (with `--lane`, that lane's simplest-first ladder).
`check` lints a status report (a file, or stdin with `-` or no argument): exit 0 when it keeps the
contract, 1 with each violation on stderr. `report` builds the report from flags, checks it, and records
a `solver_status` ledger event only when it passes (exit 1, nothing recorded, otherwise): SOLVED before
the ledger shows an acceptance is refused. `may-stop` exits 0 and names the stop-loss when one has fired,
1 (keep working) when none has. `solves` prints the latest recorded solve count (exit 1 when none is on
record) or, with `--record`, records one. `fact` records one verified fact (evidence required).
`fresh-eyes` prints (or, with `--write`, writes `<challenge folder>/fresh-eyes.md`) the artifact plus the
verified facts. Exit 2 on a named error. No model, no network, no platform call.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import dispatch as _dispatch
from .. import event as _event
from .. import paths as _paths
from .. import solver_contract as _sc

HELP = "the solver contract: rules in every brief, report checks, stop-loss verdict, fresh-eyes brief"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)
    s = sp.add_parser("show", help="print the solver contract")
    s.add_argument("--lane", help="also print this lane's simplest-first ladder")
    c = sp.add_parser("check", help="lint a status report; exit 1 on a violation")
    c.add_argument("file", nargs="?", default="-", help="the report file, or - for stdin (default)")
    c.add_argument("--challenge", help="challenge id (else the report's CHALLENGE line)")
    r = sp.add_parser("report", help="check a status report and record it when it passes")
    r.add_argument("id")
    r.add_argument("--status", required=True, help=f"one of {', '.join(_sc.STATUSES)}")
    for flag in ("next", "evidence", "oracle", "solves", "stop-loss"):
        r.add_argument(f"--{flag}", default="")
    r.add_argument("--note", default="", help="free prose (checked for broken/stand-down/elsewhere claims)")
    r.add_argument("--by", help="who reports (agent name)")
    m = sp.add_parser("may-stop", help="has a stop-loss fired? exit 0 yes, 1 keep working")
    m.add_argument("id")
    m.add_argument("--json", action="store_true")
    so = sp.add_parser("solves", help="the recorded solve count; --record N --source S records one")
    so.add_argument("id")
    so.add_argument("--record", type=int, metavar="N")
    so.add_argument("--source", help="where the count was read (with --record)")
    f = sp.add_parser("fact", help="record one verified fact (evidence required)")
    f.add_argument("id")
    f.add_argument("text")
    f.add_argument("--evidence", required=True, help="file, offset, request or command output")
    f.add_argument("--by", help="who verified it")
    fe = sp.add_parser("fresh-eyes", help="the artifact plus verified facts only")
    fe.add_argument("id")
    fe.add_argument("--write", action="store_true", help="write <challenge folder>/fresh-eyes.md")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _print_violations(vs) -> None:
    for v in vs:
        print(f"contract violation [{v.rule}/{v.code}]: {v.message}", file=sys.stderr)


def _show(args, _profile_fn) -> int:
    if args.lane:
        print(f"## simplest-first ladder: {args.lane}\n")
        for i, rung in enumerate(_sc.ladder_for(args.lane), 1):
            print(f"{i}. {rung}")
        print()
    print(_sc.rules_md(), end="")
    return 0


def _check(args, profile_fn) -> int:
    if args.file == "-":
        text = sys.stdin.read()
    else:
        try:
            text = Path(args.file).read_text(encoding="utf-8")
        except OSError as e:
            raise _sc.ContractError(f"cannot read the report {args.file}: {e}") from None
    profile = profile_fn()
    vs = _sc.check_report(text, profile=profile, workdir=_paths.workdir(profile.slug),
                          challenge_id=args.challenge)
    if vs:
        _print_violations(vs)
        return 1
    print("report keeps the solver contract")
    return 0


def _report(args, profile_fn) -> int:
    profile = profile_fn()
    lines = [f"STATUS: {args.status}"]
    for key, val in (("NEXT", args.next), ("EVIDENCE", args.evidence), ("ORACLE", args.oracle),
                     ("SOLVES", args.solves), ("STOP_LOSS", args.stop_loss)):
        if val:
            lines.append(f"{key}: {val}")
    if args.note:
        lines.append(args.note)
    rep = _sc.parse_report("\n".join(lines))
    rec, vs = _sc.record_status(rep, profile=profile, challenge_id=args.id,
                                workdir=_paths.workdir(profile.slug), by=args.by)
    if vs:
        _print_violations(vs)
        print("nothing recorded", file=sys.stderr)
        return 1
    print(f"recorded {_sc.STATUS_EVENT}: {rec['challenge_id']} {rec['status']}")
    return 0


def _may_stop(args, profile_fn) -> int:
    profile = profile_fn()
    v = _sc.may_stop(profile, args.id, workdir=_paths.workdir(profile.slug))
    if args.json:
        print(json.dumps({"challenge_id": v.challenge_id, "allowed": v.allowed, "reasons": list(v.reasons)}))
    else:
        head = "may stop" if v.allowed else "KEEP WORKING"
        print(f"{v.challenge_id}: {head}")
        for r in v.reasons:
            print(f"- {r}")
    return 0 if v.allowed else 1


def _solves(args, profile_fn) -> int:
    profile = profile_fn()
    wd = _paths.workdir(profile.slug)
    if args.record is not None:
        if not args.source:
            raise _sc.ContractError("--record needs --source (where the count was read)")
        rec = _sc.record_solve_count(args.id, args.record, source=args.source, workdir=wd)
        print(f"recorded solve count: {rec['challenge_id']} {rec['count']} ({rec['source']})")
        return 0
    if args.source:
        raise _sc.ContractError("--source goes with --record")
    sc = _sc.solve_count(args.id, workdir=wd)
    if sc is None:
        print(f"{args.id}: no solve count on record; read it from the board and record it with "
              f"`python -m ctf contract solves {args.id} --record N --source board`", file=sys.stderr)
        return 1
    print(f"{sc.challenge_id}: {sc.count} solve(s) ({sc.source})")
    return 0


def _fact(args, profile_fn) -> int:
    profile = profile_fn()
    rec = _sc.record_fact(args.id, args.text, evidence=args.evidence,
                          workdir=_paths.workdir(profile.slug), by=args.by)
    print(f"recorded fact for {rec['challenge_id']}")
    return 0


def _fresh_eyes(args, profile_fn) -> int:
    profile = profile_fn()
    wd = _paths.workdir(profile.slug)
    if args.write:
        print(_sc.write_fresh_eyes(args.id, workdir=wd))
    else:
        print(_sc.fresh_eyes_md(args.id, workdir=wd), end="")
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        return {"show": _show, "check": _check, "report": _report, "may-stop": _may_stop,
                "solves": _solves, "fact": _fact, "fresh-eyes": _fresh_eyes}[args.action](
                    args, lambda: _profile(args))
    except (_event.EventError, _sc.ContractError, _dispatch.DispatchError, ValueError) as e:
        print(f"ctf contract: {e}", file=sys.stderr)
        return 2
