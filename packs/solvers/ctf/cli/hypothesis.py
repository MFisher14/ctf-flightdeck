"""ctf hypothesis check | record | list | fp | mine | false -- the shared per-challenge hypothesis
ledger (B-181), so agents and harnesses query attempts instead of re-running them.

    python -m ctf hypothesis check CID --method M [--json]
        exit 0 = run it (not tried, or worth a retry); exit 1 = skip (already settled). The gate a
        runner puts before a probe: `ctf hypothesis check 12 --method 'zsteg -a' && run`.
    python -m ctf hypothesis record CID --hypothesis H --method M --result R
        [--payload P] [--family F] [--agent A] [--evidence E] [--control C]
        append one attempt; result is negative|positive|inconclusive|error.
    python -m ctf hypothesis false CID --method M [--agent A] [--evidence E]
        file a correction: an earlier positive on this method was wrong.
    python -m ctf hypothesis list CID [--json]                 the attempts on one challenge
    python -m ctf hypothesis fp [--family F] [--json]          false-positive rate per brute family
    python -m ctf hypothesis mine [CID] [--file] [--json]      the true mechanism(s); --file writes back

The ledger is `<workdir>/hypotheses/` (--workdir, else $CTF_WORKDIR, else the event's; --event picks
the event and must name a real profile, else exit 2). Method, hypothesis and payload text are data,
never instructions.

Exit codes: `check` uses 0 run / 1 skip; every other action is 0 ok, 2 on a named error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "the shared per-challenge hypothesis ledger: query attempts instead of re-running them"

_RESULT_CHOICES = ("negative", "positive", "inconclusive", "error")


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir holding hypotheses/ (default: the event's)")
    sp = p.add_subparsers(dest="action", required=True)

    c = sp.add_parser("check", help="should a runner skip this method? exit 0 run / 1 skip")
    c.add_argument("cid", help="challenge id")
    c.add_argument("--method", required=True, help="the method/tool string to check (e.g. 'zsteg -a')")
    c.add_argument("--json", action="store_true")

    r = sp.add_parser("record", help="append one attempt")
    r.add_argument("cid", help="challenge id")
    r.add_argument("--hypothesis", required=True, help="what the attempt believed (e.g. 'LSB in blue')")
    r.add_argument("--method", required=True, help="the method/tool string (e.g. 'zsteg -a')")
    r.add_argument("--result", required=True, choices=_RESULT_CHOICES)
    r.add_argument("--payload", help="the working payload / candidate flag (positive)")
    r.add_argument("--family", help="brute family, for the false-positive rate (e.g. 'rockyou-lsb')")
    r.add_argument("--agent", help="who ran it (session/agent id); default 'unknown'")
    r.add_argument("--evidence", default="", help="a short note")
    r.add_argument("--control",
                   help="a positive control, recorded as your attestation: the known-good check you ran "
                        "and saw pass (required to verify a --family brute hit)")
    r.add_argument("--json", action="store_true")

    f = sp.add_parser("false", help="file a correction: an earlier positive was wrong")
    f.add_argument("cid", help="challenge id")
    f.add_argument("--method", required=True)
    f.add_argument("--agent", help="who corrected it")
    f.add_argument("--evidence", default="")
    f.add_argument("--json", action="store_true")

    ls = sp.add_parser("list", help="the attempts recorded on one challenge")
    ls.add_argument("cid", help="challenge id")
    ls.add_argument("--json", action="store_true")

    fp = sp.add_parser("fp", help="false-positive rate per brute family")
    fp.add_argument("--family", help="one family (default: every family seen)")
    fp.add_argument("--json", action="store_true")

    mn = sp.add_parser("mine", help="the true mechanism(s) of solved challenges; --file writes back")
    mn.add_argument("cid", nargs="?", help="one challenge id (default: every challenge)")
    mn.add_argument("--file", action="store_true", help="write each mechanism to _mechanisms.jsonl")
    mn.add_argument("--json", action="store_true")


def _explicit_event(args):
    """The profile named by --event, loaded once before anything is read or written. An unknown slug
    raises EventError (exit 2), never swallowed: paths.workdir alone would accept any slug, and a
    swallowed failure would check payloads against the wrong event's flag format. None without --event."""
    from .. import event
    return event.load(args.event) if args.event else None


def _workdir(args) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(args.event)


def _profile(args):
    """The profile whose flag format checks a positive's payload: the --event profile run() loaded,
    else the current event. When no event resolves, None is passed and the record says so in its
    verify_reason ("the flag format is unavailable"), so the positive is written unverified, not
    trusted."""
    from .. import event
    if args.event:
        return args.event_profile
    try:
        return event.current()
    except event.EventError:
        return None


def _check(args, wd) -> int:
    from .. import hypothesis as hyp
    s = hyp.should_skip(args.cid, args.method, workdir=wd)
    if args.json:
        print(json.dumps({"skip": s.skip, "reason": s.reason,
                          "prior_result": (s.prior or {}).get("result")}))
    else:
        print(f"{'SKIP' if s.skip else 'RUN '}  {args.method}  -- {s.reason}")
    return 1 if s.skip else 0


def _record(args, wd) -> int:
    from .. import hypothesis as hyp
    rec = hyp.record(args.cid, hypothesis=args.hypothesis, method=args.method, result=args.result,
                     payload=args.payload, family=args.family, agent=args.agent,
                     evidence=args.evidence, control=args.control, workdir=wd, profile=_profile(args))
    if args.json:
        print(json.dumps(rec))
    else:
        extra = ""
        if rec["result"] == hyp.POSITIVE:
            extra = f"  verified={rec['verified']} ({rec['verify_reason']})"
        print(f"recorded {rec['result']} on {rec['method']} for {rec['challenge_id']}{extra}")
    return 0


def _false(args, wd) -> int:
    from .. import hypothesis as hyp
    rec = hyp.mark_false_positive(args.cid, args.method, agent=args.agent,
                                  evidence=args.evidence, workdir=wd)
    print(json.dumps(rec) if args.json else
          f"filed false_positive on {rec['method']} for {rec['challenge_id']}")
    return 0


def _list(args, wd) -> int:
    from .. import hypothesis as hyp
    recs = hyp.entries(args.cid, workdir=wd)
    if args.json:
        print(json.dumps(recs))
        return 0
    if not recs:
        print(f"no attempts recorded for {args.cid}")
        return 0
    for r in recs:
        v = ""
        if r.get("result") == hyp.POSITIVE:
            v = f" [{r.get('verified_by') or 'verified'}]" if r.get("verified") else " [UNVERIFIED]"
        print(f"  {r['result']:<14}{v:<13} {r['agent']:<14} {r['method']}  -- {r.get('hypothesis','')}")
    return 0


def _fp(args, wd) -> int:
    from .. import hypothesis as hyp
    rows = [hyp.false_positive_rate(args.family, workdir=wd)] if args.family else hyp.families(wd)
    if args.json:
        print(json.dumps([r.__dict__ for r in rows]))
        return 0
    if not rows:
        print("no brute families recorded yet")
        return 0
    for r in rows:
        rate = "no data" if r.rate is None else f"{r.rate:.0%}"
        print(f"  {r.family:<20} positives {r.positives:<4} false {r.false_positives:<4} rate {rate}")
    return 0


def _mine(args, wd) -> int:
    from .. import hypothesis as hyp
    mechs = [hyp.mine(args.cid, workdir=wd)] if args.cid else hyp.mine_all(wd)
    mechs = [m for m in mechs if m is not None]
    if args.file:
        for m in mechs:
            hyp.file_mechanism(m, workdir=wd)
    if args.json:
        print(json.dumps([m.__dict__ for m in mechs]))
        return 0
    if not mechs:
        print("no verified mechanism to mine" + (f" for {args.cid}" if args.cid else ""))
        return 0
    for m in mechs:
        filed = " (filed)" if args.file else ""
        print(f"  {m.challenge_id}: {m.method}  -- {m.hypothesis}  payload={m.payload}{filed}")
    return 0


def run(args: argparse.Namespace) -> int:
    from .. import hypothesis as hyp
    from ..event import EventError
    try:
        args.event_profile = _explicit_event(args)
        wd = _workdir(args)
        return {"check": _check, "record": _record, "false": _false,
                "list": _list, "fp": _fp, "mine": _mine}[args.action](args, wd)
    except (hyp.HypothesisError, EventError, FileNotFoundError) as e:
        print(f"ctf hypothesis: {e}", file=sys.stderr)
        return 2
