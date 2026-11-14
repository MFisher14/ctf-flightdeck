"""ctf integrate plan|run|guard — the integrator merge queue for build swarms (B-147).

One integrator merges the finished item branches back onto the integration branch in BUILD-PLAN
dependency order, regenerating the generated files and rerunning the gate after each merge. Direct
commits to the integration branch are refused (only the integrator's merges land there).

    ctf integrate plan --items FILE [--branches id=branch ...] [--prefix item] [--repo DIR]
        Print the merge order (dependency-sorted). Reads item dependencies from --items (a
        to_build-style JSON, as ctf.buildplan.load_items reads). Branches default to the repo's
        local <prefix>/<id> branches.

    ctf integrate run --items FILE [--branches id=branch ...] [--prefix item] [--repo DIR]
                      [--integration-branch NAME] [--no-regen] [--no-gate] [--keep-going]
        Merge each queued branch in order, one line per item:
          merged          merge commit made (--no-ff), generated files regenerated into it, gate green
          already-merged  the branch tip is already in the integration branch; nothing was done
          conflict | merge-failed | missing-branch | regen-failed | gate-failed
                          the item failed and the integration branch is back where it was before it
          skipped         not tried: the queue had halted, a dependency in the queue did not merge,
                          or a dependency that is not queued has a local <prefix>/<id> branch
                          that is not merged yet (queue it or merge it first)
        After the queue, every agent registered on a merged or already-merged branch in the B-213
        work registry (ctf.workreg, the repo's ctf.paths.workreg_state()) leaves it, one
        `left <agent>` line each; an unreadable registry is exit 2 (the merges stand).
        The first failure halts the queue. --keep-going goes on to the items that do not depend
        (directly or through other queued items) on a failed one. Nothing is pushed. Must run on
        the integration branch with a clean tree. The regenerate and gate steps run with
        $CTF_PYTHON, else the interpreter running this command. An interrupt (Ctrl-C) mid-step
        rolls that step back before it propagates; after a hard kill mid-step the next run exits 2
        naming the ungated merge and the commit to reset to.

    ctf integrate guard [--repo DIR] [--integration-branch NAME]
        Hook guard: exit 2 (refuse) when a commit is being made directly on the integration
        branch outside the integrator (a hand merge included); exit 0 otherwise. Opt-in: it
        protects a checkout once that checkout's pre-commit and pre-merge-commit hooks call it.
        git runs no hook for a fast-forward merge, reset or branch -f; the guard cannot see those.

An empty queue (no <prefix>/<id> branches and no --branches) is exit 2 for plan and run.

The integration branch is --integration-branch, else $CTF_INTEGRATION_BRANCH, else the repo's
`git config ctftools.integrationBranch`; there is no built-in name, and run and guard exit 2 without one.
--repo may be given before or after the sub-command.

Exit: 0 ok / allowed, 1 some item did not merge, 2 refused or a usage/config error.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .. import buildplan as _bp
from .. import paths as _paths
from .. import workreg as _wr
from .. import worktree as _wt

HELP = "integrator merge queue: merge item branches in dependency order, regen, rerun the gate"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--repo", type=Path, default=None, help="the integration checkout (default: cwd)")
    sp = p.add_subparsers(dest="action", required=True)

    def repo_too(q: argparse.ArgumentParser) -> None:
        # also accepted after the sub-command; SUPPRESS keeps a --repo given before it
        q.add_argument("--repo", type=Path, default=argparse.SUPPRESS, help=argparse.SUPPRESS)

    def common(q: argparse.ArgumentParser) -> None:
        repo_too(q)
        q.add_argument("--items", type=Path, help="to_build-style JSON for item dependencies")
        q.add_argument("--branches", nargs="+", default=[], metavar="ID=BRANCH",
                       help="explicit id=branch pairs (default: the repo's <prefix>/<id> branches)")
        q.add_argument("--prefix", default=_wt.DEFAULT_BRANCH_PREFIX, help="branch prefix (default 'item')")

    pl = sp.add_parser("plan", help="print the dependency-sorted merge order")
    common(pl)

    ru = sp.add_parser("run", help="merge the queued branches in dependency order")
    common(ru)
    ru.add_argument("--integration-branch", default=None, help="override the integration branch name")
    ru.add_argument("--no-regen", action="store_true", help="skip regenerating generated files")
    ru.add_argument("--no-gate", action="store_true", help="skip rerunning the gate")
    ru.add_argument("--keep-going", action="store_true",
                    help="after a failure, go on to the items that do not depend on it")

    gu = sp.add_parser("guard", help="pre-commit guard: refuse a direct commit on the integration branch")
    repo_too(gu)
    gu.add_argument("--integration-branch", default=None, help="override the integration branch name")


def _branches(args: argparse.Namespace, repo: Path) -> dict[str, str]:
    if args.branches:
        out: dict[str, str] = {}
        for pair in args.branches:
            if "=" not in pair:
                raise _wt.WorktreeError(f"--branches entry {pair!r} must be ID=BRANCH")
            iid, br = pair.split("=", 1)
            out[iid.strip()] = br.strip()
        return out
    return _wt.item_branches(repo, prefix=args.prefix)


def _items(args: argparse.Namespace):
    if not args.items:
        raise _wt.WorktreeError("no --items file given; the merge order needs BUILD-PLAN dependencies")
    return _bp.load_items(args.items)


def _leave_merged(repo: Path, res) -> None:
    """B-213: a merged branch's agents leave the work registry (their claims stop blocking)."""
    done = [s.branch for s in res.steps if s.status in _wt.OK_STATUSES]
    if not done:
        return
    reg = _wr.Registry(_paths.workreg_state(_wt._toplevel(repo)))
    for branch in done:
        for name in reg.leave_branch(branch, why="merged by ctf integrate run"):
            print(f"left            {name:10}  {branch:22}  work registry: claims released")


def run(args: argparse.Namespace) -> int:
    repo = args.repo or Path.cwd()
    try:
        if args.action == "guard":
            _wt.refuse_direct_commit(repo, integration_branch=args.integration_branch)
            return 0

        branches = _branches(args, repo)
        if not branches:
            print("ctf integrate: no item branches to merge", file=sys.stderr)
            return 2
        items = _items(args)

        if args.action == "plan":
            order = _wt.dependency_order(branches, items)
            for iid in order:
                print(f"{iid}\t{branches[iid]}")
            return 0

        res = _wt.integrate(
            repo, branches, items=items, integration_branch=args.integration_branch,
            regenerate=None if args.no_regen else _wt.default_regenerate,
            gate=None if args.no_gate else _wt.default_gate,
            stop_on_fail=not args.keep_going, prefix=args.prefix,
        )
        for s in res.steps:
            detail = " ".join(s.detail.split())     # git's conflict text is several lines; one per item
            print(f"{s.status:14}  {s.item:10}  {s.branch:22}  {detail}")
        print(f"INTEGRATE branch={res.integration_branch} merged={len(res.merged())} "
              f"failed={len(res.failures())} halted={res.halted} ok={res.ok}")
        try:
            _leave_merged(repo, res)
        except (_wr.WorkRegError, FileNotFoundError) as e:
            print(f"ctf integrate: work registry: {e} (the merges above stand)", file=sys.stderr)
            return 2
        return 0 if res.ok else 1
    except _wt.DirectCommitRefused as e:
        print(f"ctf integrate: {e}", file=sys.stderr)
        return 2
    except (_wt.WorktreeError, _bp.BuildPlanError) as e:
        print(f"ctf integrate: {e}", file=sys.stderr)
        return 2
