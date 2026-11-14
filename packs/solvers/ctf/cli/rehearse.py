"""ctf rehearse — replay one wave end to end against a fake platform on 127.0.0.1 (B-039).

    python -m ctf rehearse [--event SLUG] [--submit-interval S] [--keep DIR] [--json]

A CTFd event runs against ctf.fakectfd through the carried client, `ctf wait`, triage, the router,
a Layer-1 flag scan, a Codex handoff brief (no model call) and guarded_submit; a manual event runs
through its drop folder and the submit gate. See ctf/rehearsal.py. Nothing reaches the real platform,
the real token is never read, and no model is called.

Exit 0 when the rehearsal passed, 1 when a step failed, 2 when it cannot run for this event.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .. import event as _event
from .. import rehearsal as _reh

HELP = "wave rehearsal: replay one wave against a fake CTFd (or the manual drop folder), offline"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--submit-interval", type=float, default=_reh.DEFAULT_SUBMIT_INTERVAL,
                   help=f"pacer interval in seconds (default {_reh.DEFAULT_SUBMIT_INTERVAL:g}; the fake "
                        "rate-limits anything faster)")
    p.add_argument("--keep", type=Path, metavar="DIR",
                   help="run in DIR (must be empty or absent) and keep it; default: a temp folder, removed")
    p.add_argument("--json", action="store_true", help="print the result as JSON")


def run(args: argparse.Namespace) -> int:
    try:
        prof = _event.load(args.event) if args.event else _event.current()
    except _event.EventError as e:
        print(f"ctf rehearse: {e}", file=sys.stderr)
        return 2
    try:
        if args.keep is not None:
            rep = _reh.rehearse(prof, workdir=args.keep, submit_interval=args.submit_interval)
        else:
            with tempfile.TemporaryDirectory(prefix="ctf-rehearsal-") as td:
                rep = _reh.rehearse(prof, workdir=Path(td) / "run", submit_interval=args.submit_interval)
    except _reh.RehearsalError as e:
        print(f"ctf rehearse: {e}", file=sys.stderr)
        return 2
    print(json.dumps(rep.to_dict(), indent=1) if args.json else rep.render())
    return 0 if rep.passed else 1
