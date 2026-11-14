"""ctf primer — print the generated repo brief (B-199, ctf.primer): one read to orient a fresh agent.

    python -m ctf primer              docs/PRIMER.md: start here, reading rules, layout, large files
    python -m ctf primer --index      docs/FILE-INDEX.md (long: prefer `ctf read docs/FILE-INDEX.md --grep W`)
    python -m ctf primer --check      exit 1 when either file is missing or stale (prints which)
    python -m ctf primer --write      regenerate both (also done by `python -m ctf engines generate`)

Exit codes: 0 ok; 1 stale (--check); 2 the file is missing (run `python -m ctf engines generate`), or
--check / --write outside a git checkout (the primer lists the gate's file list).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import paths, primer
from ..gate import GateError

HELP = "print the generated repo primer (start here, reading rules, layout, large files) or check it (B-199)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    g = p.add_mutually_exclusive_group()
    g.add_argument("--index", action="store_true", help="print the file index instead of the brief")
    g.add_argument("--check", action="store_true", help="exit 1 when a primer file is stale")
    g.add_argument("--write", action="store_true", help="regenerate both primer files")
    p.add_argument("--root", type=Path, default=None, help="the checkout (default: this repo)")


def run(args: argparse.Namespace) -> int:
    try:
        return _run(args)
    except GateError as e:
        print(f"ctf primer: cannot list the tree: {e}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    root = args.root or paths.repo_root()
    if args.check:
        bad = primer.stale_files(root)
        for rel in bad:
            print(f"stale: {rel}")
        if bad:
            print("run `python -m ctf engines generate` (or `python -m ctf primer --write`)", file=sys.stderr)
        return 1 if bad else 0
    if args.write:
        for p in primer.write(root):
            print(f"wrote {p.relative_to(root).as_posix()}", file=sys.stderr)
        return 0
    rel = primer.INDEX_REL if args.index else primer.PRIMER_REL
    p = Path(root) / rel
    if not p.is_file():
        print(f"ctf primer: {rel} is missing; run `python -m ctf engines generate`", file=sys.stderr)
        return 2
    sys.stdout.write(p.read_text(encoding="utf-8"))
    return 0
