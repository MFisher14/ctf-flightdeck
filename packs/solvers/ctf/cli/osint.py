"""ctf osint -- the time-boxed live-OSINT playbook: box status, the human handoff, the guess budget (B-115).

    python -m ctf osint status ID [--json] [--token-cap N] [--time-box S]
        spend, tokens left, time box left, box state, and how many queries/candidates are on record.
    python -m ctf osint handoff ID [--reason R] [--source S ...] [--note T] [--token-cap N] [--time-box S]
        write the human-handoff file (exact queries tried, candidates, sources, models tried) and record
        a stop so the dispatcher/escalator leave the challenge to the human. Never drives a browser.
    python -m ctf osint guess-budget --wrong-count N [--guess-budget M] [--approvals-left K] [--json]
        whether the threat-intel kit may run another candidate-feeding lookup, tied to the submit gate's
        wrong-answer accounting.

The live OSINT itself stays human: this command builds the rig around the human, it never searches a
platform or starts a model.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import event as _event
from .. import osint_playbook as _pb

HELP = "time-boxed live-OSINT playbook: box status, human handoff, guess budget"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    sp = p.add_subparsers(dest="action", required=True)

    st = sp.add_parser("status", help="OSINT box status for a challenge")
    st.add_argument("id")
    st.add_argument("--json", action="store_true")
    _box_args(st)

    ho = sp.add_parser("handoff", help="write the human-handoff file and record a stop")
    ho.add_argument("id")
    ho.add_argument("--reason", default=_pb.REASON_MANUAL,
                    help="why the handoff happened (default: manual)")
    ho.add_argument("--source", action="append", default=[], metavar="TEXT",
                    help="a source the human should consult / already consulted (repeatable)")
    ho.add_argument("--note", default="", help="a free note for the write-up")
    _box_args(ho)

    gb = sp.add_parser("guess-budget", help="whether another candidate-feeding lookup may run")
    gb.add_argument("--wrong-count", type=int, required=True,
                    help="wrong answers already on this challenge (Workspace.wrong_count)")
    gb.add_argument("--guess-budget", type=int, default=_pb.DEFAULT_GUESS_BUDGET)
    gb.add_argument("--approvals-left", type=int, default=0,
                    help="unused player post-guard approvals that still permit a lookup")
    gb.add_argument("--json", action="store_true")


def _box_args(sp: argparse.ArgumentParser) -> None:
    sp.add_argument("--token-cap", type=int, default=_pb.DEFAULT_TOKEN_CAP,
                    help=f"token cap for the live-OSINT run (default {_pb.DEFAULT_TOKEN_CAP})")
    sp.add_argument("--time-box", type=float, default=_pb.DEFAULT_TIME_BOX_SECONDS,
                    help=f"wall-clock time box in seconds (default {_pb.DEFAULT_TIME_BOX_SECONDS:.0f})")


def _profile(args) -> _pb.OsintProfile:
    return _pb.OsintProfile(time_box_seconds=args.time_box, token_cap=args.token_cap)


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "guess-budget":
            g = _pb.check_guess_budget(args.wrong_count, guess_budget=args.guess_budget,
                                       approvals_left=args.approvals_left)
            if args.json:
                print(json.dumps(g.to_dict()))
            else:
                print(f"{'ALLOWED' if g.allowed else 'BLOCKED'}: {g.reason}")
            return 0 if g.allowed else 3

        prof = _event.load(args.event) if args.event else _event.current()
        m = _pb.meter(prof, osint=_profile(args))
        cid = args.id

        if args.action == "status":
            st = m.status(cid)
            tried = _pb.tried_queries(cid, m.workdir)
            cands = _pb.candidates(cid, workdir=m.workdir)
            if args.json:
                print(json.dumps({**st.to_dict(), "queries_tried": len(tried),
                                  "candidates": len(cands)}))
            else:
                left = "-" if st.box_seconds_left is None else f"{st.box_seconds_left / 60:.0f}m"
                tleft = "-" if st.tokens_left is None else f"{st.tokens_left:,}"
                print(f"{cid}: box={st.box_state} spent=${st.spent_usd:.2f} tokens={st.tokens:,} "
                      f"tokens_left={tleft} time_box_left={left} "
                      f"queries_tried={len(tried)} candidates={len(cands)}")
            return 0

        # handoff
        h = _pb.build_handoff(m, cid, reason=args.reason, sources=args.source, notes=args.note)
        print(f"handoff written: {h.path}")
        print(f"  reason={h.reason} spent=${h.spent_usd:.2f} tokens={h.tokens:,} "
              f"queries_tried={len(h.queries_tried)} candidates={len(h.candidates)} "
              f"models_tried={len(h.models_tried)}")
        return 0
    except (_event.EventError, _pb.PlaybookError, ValueError) as e:
        print(f"ctf osint: {e}", file=sys.stderr)
        return 2
