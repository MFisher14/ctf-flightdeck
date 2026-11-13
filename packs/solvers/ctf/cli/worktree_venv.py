"""ctf worktree-venv [--venv DIR] [--worktree DIR] [--force] — link the shared master venv into a worktree.

A fresh git worktree has no ``.venv``, so ``.venv/bin/python`` fails there. This links the worktree's
``.venv`` to the master checkout's venv (found through git) — the same pinned interpreter and packages, no
editable install — so the worktree runs the engines and the suite like the master checkout. Before it
links, git is made to ignore the ``.venv`` symlink (the root .gitignore covers it; elsewhere ``.venv`` is
added to info/exclude), so the link is never committed. Only the first venv source given (--venv, then
$CTF_VENV, then the master's) is used; an unusable one exits 2. Without --worktree it links the top
level of the checkout holding the current directory; in the master checkout itself it reports that the
.venv is the master venv and exits 0 without touching it. See ctf/worktreevenv.py.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import worktreevenv as _wv

HELP = "link this git worktree's .venv to the shared master venv (B-187)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--worktree", type=Path, default=None,
                   help="the worktree to link (default: the top level of the git checkout holding "
                        "the current directory, else the current directory)")
    p.add_argument("--venv", type=Path, default=None,
                   help="the venv to link (default: $CTF_VENV, else the master checkout's .venv)")
    p.add_argument("--force", action="store_true",
                   help="replace an existing .venv symlink that points elsewhere")


def run(args: argparse.Namespace) -> int:
    worktree = args.worktree
    if worktree is None:
        # From a subdirectory, link the checkout root's .venv (where .venv/bin/python is spelled from).
        worktree = _wv.checkout_root(Path.cwd()) or Path.cwd()
    try:
        action, target = _wv.link(worktree, args.venv, force=args.force)
    except _wv.WorktreeVenvError as e:
        print(f"ctf worktree-venv: {e}", file=sys.stderr)
        return 2
    dest = Path(worktree).resolve() / ".venv"
    if action == "is-master":
        print(f"{dest} is the master venv itself (this is the master checkout): nothing to link")
        return 0
    verb = {"linked": "linked", "relinked": "re-linked", "exists": "already links"}[action]
    print(f"{dest} {verb} -> {target}")
    return 0
