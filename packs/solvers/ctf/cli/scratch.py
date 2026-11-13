"""ctf scratch -- per-challenge scratch passes with a manifest, instead of /tmp (B-178).

    python -m ctf scratch new CHALLENGE --purpose P [--agent A] [--goal G] [--shell]
    python -m ctf scratch close CHALLENGE PASS [--status closed|failed|interrupted] [--note N]
    python -m ctf scratch list CHALLENGE [--json]
    python -m ctf scratch prune CHALLENGE --keep N

CHALLENGE is a challenge folder path or an id / folder name under the workdir (`12` finds
`12-<name>`). `new` prints the pass folder; with --shell it prints `export TMPDIR=...` lines, so
`eval "$(python -m ctf scratch new 12 --purpose angr --shell)"` sends a shell's temp files there.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys

from .. import event as _event
from .. import scratch as _scratch

HELP = "per-challenge scratch passes under <challenge>/.scratch with a per-pass manifest"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    n = sp.add_parser("new", help="open the next scratch pass and print its folder")
    n.add_argument("challenge")
    n.add_argument("--purpose", required=True)
    n.add_argument("--agent")
    n.add_argument("--goal")
    n.add_argument("--shell", action="store_true", help="print export lines for TMPDIR and CTF_SCRATCH_DIR")
    c = sp.add_parser("close", help="record a pass's files and close it")
    c.add_argument("challenge")
    c.add_argument("pass_name", metavar="PASS")
    c.add_argument("--status", default="closed", choices=sorted(_scratch.CLOSED_STATUSES))
    c.add_argument("--note")
    ls = sp.add_parser("list", help="every pass, oldest first")
    ls.add_argument("challenge")
    ls.add_argument("--json", action="store_true")
    pr = sp.add_parser("prune", help="delete old closed passes, keeping the newest N")
    pr.add_argument("challenge")
    pr.add_argument("--keep", type=int, required=True)


def run(args: argparse.Namespace) -> int:
    try:
        chal = _scratch.challenge_dir(args.challenge)
        if args.action == "new":
            d = _scratch.open_pass(chal, args.purpose, agent=args.agent, goal=args.goal)
            if args.shell:
                for k, v in _scratch.env_for(d).items():
                    print(f"export {k}={shlex.quote(v)}")
            else:
                print(d)
            return 0
        if args.action == "close":
            root = _scratch.scratch_root(chal)
            if "/" in args.pass_name or args.pass_name.startswith("."):
                raise _scratch.ScratchError(f"bad pass name {args.pass_name!r}")
            m = _scratch.close_pass(root / args.pass_name, args.status, note=args.note)
            print(f"{m['pass']}: {m['status']}, {len(m['files'])} file(s) recorded")
            return 0
        if args.action == "list":
            ps = _scratch.passes(chal)
            if args.json:
                print(json.dumps(ps, sort_keys=True))
            else:
                for m in ps:
                    nf = "-" if m["files"] is None else str(len(m["files"]))
                    print(f"{m['pass']:<32} {m['status']:<12} files={nf:<4} {m['purpose']}")
            return 0
        removed = _scratch.prune(chal, args.keep)
        for r in removed:
            print(f"removed {r}")
        return 0
    except (_scratch.ScratchError, _event.EventError) as e:
        print(f"ctf scratch: {e}", file=sys.stderr)
        return 2
