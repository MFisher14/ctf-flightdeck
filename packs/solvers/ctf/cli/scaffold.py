"""ctf scaffold -- write a tested repro / probe / adversarial / bench scaffold, or a racer candidate (B-258).

    python -m ctf scaffold list
    python -m ctf scaffold repro DIR [--target FILE.py:FUNC] [--name N] [--force]
    python -m ctf scaffold probe DIR [--name N] [--force]
    python -m ctf scaffold adv   DIR [--target FILE.py:FUNC] [--name N] [--force]
    python -m ctf scaffold bench DIR [--target FILE.py:FUNC] [--name N] [--force]
    python -m ctf scaffold racer --day N [--role cx] [--lane-dir DIR] [--force]

DIR is a folder (the file is <name or kind>.py in it) or a .py path; a scratch pass folder from
`ctf scratch new` is the usual place. Prints the written path. Exit 0 written, 2 refused (an existing
file without --force, a bad option, a missing template). What each scaffold does: ctf/scaffold.py.
"""
from __future__ import annotations

import argparse
import sys

from .. import scaffold as _s

HELP = "write a repro/probe/adv/bench scratch scaffold, or a complex-racer day candidate"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="kind", required=True)
    sp.add_parser("list", help="the scaffolds and what each replaces")
    for kind in ("repro", "probe", "adv", "bench"):
        k = sp.add_parser(kind, help=_s.KINDS[kind])
        k.add_argument("dest", help="a folder, or the .py path to write")
        if kind != "probe":
            k.add_argument("--target", default="", help="FILE.py:FUNCTION or package.module:FUNCTION")
        k.add_argument("--name", default="", help="file name without .py (default: the kind)")
        k.add_argument("--force", action="store_true", help="overwrite an existing file")
    r = sp.add_parser("racer", help=_s.KINDS["racer"])
    r.add_argument("--day", type=int, required=True)
    r.add_argument("--role", default="cx", help="the candidate's role (default cx: dNN_cx_dev.py)")
    r.add_argument("--lane-dir", help="the lane folder (default: solvers/binary of this checkout)")
    r.add_argument("--force", action="store_true")


def run(args: argparse.Namespace) -> int:
    try:
        if args.kind == "list":
            for kind, what in _s.KINDS.items():
                print(f"{kind:<6} {what}")
            return 0
        if args.kind == "racer":
            path = _s.write_racer(args.day, role=args.role, lane_dir=args.lane_dir, force=args.force)
        else:
            path = _s.write_scaffold(args.kind, args.dest, target=getattr(args, "target", ""), name=args.name,
                                     force=args.force)
    except (_s.ScaffoldError, OSError) as e:
        print(f"ctf scaffold: {e}", file=sys.stderr)
        return 2
    print(path)
    return 0
