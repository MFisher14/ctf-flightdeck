"""ctf worktree create|list — per-agent build worktrees (B-147).

    ctf worktree create <branch> <path> [--base REF] [--repo DIR]
                        [--harness claude|codex|human|other [--row ID]... [--file PATTERN]... [--fold F]...]
        Add a worktree at <path> on a new <branch> cut from REF (default HEAD). One branch and one
        directory per agent: refuses a branch that already exists or a non-empty path, so two agents
        can never share a working tree. <branch> may be given bare (e.g. "B-147"): it becomes
        "item/B-147" unless it already contains a "/".
        With --harness it also registers the agent in the B-213 work registry (ctf.workreg, the
        repo's ctf.paths.workreg_state()) under the branch name, with the worktree and the claims,
        before the worktree is made: all or nothing. A claim clash (exit 1, each clash named) or a
        bad claim (exit 2) creates nothing; a failed `git worktree add` unregisters it again. The
        record is held until `ctf work leave`, `ctf integrate run` merges the branch, or the worktree
        folder is removed.

    ctf worktree list [--repo DIR] [--json]
        List the repo's worktrees (path, branch, head), the way `git worktree list` does.

Runs git only in the given repo (default: the current checkout); --repo may be given before or after
the sub-command. Never pushes or touches a remote.
Exit: 0 ok, 1 a claim conflict (--harness), 2 refused/usage (branch or path taken, not a git work tree,
a bad claim or an unreadable work registry).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import paths as _paths
from .. import workreg as _wr
from .. import worktree as _wt

HELP = "create or list per-agent build worktrees (one named branch per agent)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", type=Path, default=None, help="run git here (default: current directory)")
    sp = p.add_subparsers(dest="action", required=True)

    def repo_too(q: argparse.ArgumentParser) -> None:
        # also accepted after the sub-command; SUPPRESS keeps a --repo given before it
        q.add_argument("--repo", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    c = sp.add_parser("create", help="add a worktree on a new per-agent branch")
    repo_too(c)
    c.add_argument("branch", help="the agent's branch; a bare id like 'B-147' becomes 'item/B-147'")
    c.add_argument("path", type=Path, help="where to put the new worktree (must not already exist)")
    c.add_argument("--base", default="HEAD", help="ref the branch is cut from (default HEAD)")
    c.add_argument("--harness", choices=_wr.HARNESSES, default=None,
                   help="also register the agent and its claims in the work registry (B-213) first")
    c.add_argument("--row", action="append", default=[], metavar="ID", help="claim a B-138 backlog row (repeatable)")
    c.add_argument("--file", action="append", default=[], metavar="PATTERN",
                   help="claim a repo-relative path or glob (* ? **; trailing / = directory) (repeatable)")
    c.add_argument("--fold", action="append", default=[], metavar="SLUG:SOURCE:PATH",
                   help="claim a promotion entry to fold (ctf.promote) (repeatable)")

    ls = sp.add_parser("list", help="list the repo's worktrees")
    repo_too(ls)
    ls.add_argument("--json", action="store_true", help="machine-readable output")


def _branch_name(raw: str) -> str:
    return raw if "/" in raw else _wt.agent_branch(raw)


def _create_registered(repo: Path, branch: str, args: argparse.Namespace) -> _wt.Worktree:
    """Register `branch` (B-213) with the worktree path and claims, then make the worktree; unregister
    when that fails. The folder is made (empty) first, so the record is never stale for want of it."""
    dest = Path(args.path).resolve()
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise _wt.WorktreeError(f"worktree path {dest} already exists and is not empty")
    reg = _wr.Registry(_paths.workreg_state(_wt._toplevel(repo)))
    made = not dest.exists()
    dest.mkdir(parents=True, exist_ok=True)
    try:
        reg.begin(branch, harness=args.harness, branch=branch, worktree=dest, rows=args.row,
                  files=args.file, folds=args.fold, note="ctf worktree create")
    except BaseException:
        if made:
            dest.rmdir()
        raise
    try:
        return _wt.create(repo, branch, dest, base=args.base)
    except BaseException:
        reg.leave(branch)
        if made and dest.is_dir() and not any(dest.iterdir()):
            dest.rmdir()
        raise


def run(args: argparse.Namespace) -> int:
    repo = args.repo or Path.cwd()
    try:
        if args.action == "create":
            branch = _branch_name(args.branch)
            # a Namespace built in code without the B-213 fields means: no registration
            for name, default in (("harness", None), ("row", []), ("file", []), ("fold", [])):
                if not hasattr(args, name):
                    setattr(args, name, default)
            if args.harness is None:
                if args.row or args.file or args.fold:
                    raise _wt.WorktreeError("--row, --file and --fold are claims: they need --harness "
                                            "(which registers the agent, B-213)")
                w = _wt.create(repo, branch, args.path, base=args.base)
            else:
                try:
                    w = _create_registered(repo, branch, args)
                except _wr.ClaimConflict as e:
                    for c in e.conflicts:
                        print(f"ctf worktree: conflict: {c.describe()}", file=sys.stderr)
                    print(f"ctf worktree: nothing created for {branch}", file=sys.stderr)
                    return 1
                print(f"registered {branch} ({args.harness}) in the work registry")
            print(f"created worktree {w.path} on {w.branch} (from {args.base})")
            return 0
        worktrees = _wt.list_worktrees(repo)
        if args.json:
            print(json.dumps([{"path": str(w.path), "branch": w.branch, "head": w.head,
                               "detached": w.detached, "bare": w.bare, "locked": w.locked}
                              for w in worktrees], indent=2))
        else:
            for w in worktrees:
                label = w.branch or ("(bare)" if w.bare else "(detached)")
                print(f"{w.head[:12]:12}  {label:24}  {w.path}")
        return 0
    except (_wt.WorktreeError, _wr.WorkRegError, FileNotFoundError) as e:
        print(f"ctf worktree: {e}", file=sys.stderr)
        return 2
