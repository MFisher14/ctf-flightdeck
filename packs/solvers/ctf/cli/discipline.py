"""ctf discipline [--plain] | ctf discipline check -- "<command>" — the brief command discipline (B-043).

With no subcommand it prints the discipline every agent brief carries (markdown; `--plain` for a
prompt that is not markdown: tools/codex_handoff.sh reads it this way). `check` lints one shell
command against it before it is run: each problem with the fix, exit 1; a clean command prints
"ok" and exits 0. One source: ctf/briefdiscipline.py.

Exit: 0 printed / clean, 1 the command breaks the discipline, 2 usage.
"""
from __future__ import annotations

import argparse
import sys

from .. import briefdiscipline as _bd

HELP = "print the brief command discipline, or check one command against it"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--plain", action="store_true", help="plain text instead of markdown")
    sp = p.add_subparsers(dest="action")
    c = sp.add_parser("check", help="lint one shell command (exit 1 when it breaks the discipline)")
    c.add_argument("command", nargs=argparse.REMAINDER,
                   help='the command, as one quoted argument after `--`')


def run(args: argparse.Namespace) -> int:
    if args.action != "check":
        sys.stdout.write(_bd.rules_plain() if args.plain else _bd.rules_md())
        return 0
    words = list(args.command)
    if words and words[0] == "--":
        words = words[1:]
    if not words:
        print('ctf discipline check: give the command as one quoted argument: '
              'ctf discipline check -- "<command>"', file=sys.stderr)
        return 2
    command = words[0] if len(words) == 1 else " ".join(words)
    vs = _bd.check(command)
    if not vs:
        print("ok: one command, literal program, absolute paths")
        return 0
    for v in vs:
        print(f"{v.rule}: {v.detail}\n  fix: {v.fix}")
    return 1
