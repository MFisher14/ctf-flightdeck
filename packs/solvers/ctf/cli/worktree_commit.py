"""ctf worktree-commit -m "<message>" [--all] [--trailer K=V]... [--protect B]... — one-command commit.

The sanctioned way for a worktree agent to commit its own work without assembling multi-step
git that gets refused as "too complex". It stages the worktree's changes (tracked by default,
everything with --all) and commits them with the given message, after refusing a protected
branch so it can never land on main/master. The default protected branches (main, master) have no
override: --protect only adds branches, and there is no flag that removes one. Trailers (e.g. a Co-Authored-By line) are appended
if a --trailer is given and not already present. It runs git in the current directory only and
never pushes, switches branch, or rewrites history.

Exit: 0 committed, 1 git failed (e.g. nothing to commit), 2 refused (not a git work tree, detached
HEAD, protected branch) or usage (a malformed --trailer).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

HELP = "stage and commit the current git worktree with one command (refuses a protected branch)"

DEFAULT_PROTECTED = ("main", "master")


class WorktreeCommitError(RuntimeError):
    """The commit did not happen. ``exit_code`` is the CLI exit status for this class of failure."""

    exit_code = 2


class WorktreeRefused(WorktreeCommitError):
    """Refused before staging anything: not a git work tree, detached HEAD, protected branch, or a
    malformed --trailer. Exit 2."""

    exit_code = 2


class GitFailed(WorktreeCommitError):
    """git itself failed (e.g. nothing to commit, a failing hook). Exit 1."""

    exit_code = 1


@dataclass(frozen=True)
class GitInfo:
    toplevel: Path
    branch: str          # "HEAD" when detached
    detached: bool


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("-m", "--message", required=True, help="the commit message (subject, then body)")
    p.add_argument("--all", action="store_true", dest="all_files",
                   help="stage untracked files too (git add -A); default stages tracked changes only")
    p.add_argument("--trailer", action="append", default=[], metavar="KEY=VALUE",
                   help="append this trailer line if absent (repeatable), e.g. 'Co-Authored-By=Name <x@y>'")
    p.add_argument("--protect", action="append", default=[], metavar="BRANCH",
                   help=f"also refuse this branch (repeatable); defaults: {', '.join(DEFAULT_PROTECTED)}")
    p.add_argument("--cwd", type=Path, default=None, help="run git here instead of the process cwd")


def ensure_trailers(message: str, trailers: list[str]) -> str:
    """Return message with each 'Key: Value' trailer appended if not already present verbatim.

    A --trailer is given as KEY=VALUE; it renders as 'KEY: VALUE'. An entry without '=' is an error."""
    lines: list[str] = []
    for t in trailers:
        if "=" not in t:
            raise WorktreeRefused(f"--trailer {t!r} must be KEY=VALUE")
        k, v = t.split("=", 1)
        k, v = k.strip(), v.strip()
        if not k:
            raise WorktreeRefused(f"--trailer {t!r} has an empty key")
        lines.append(f"{k}: {v}")
    out = message.rstrip("\n")
    present = set(out.splitlines())
    to_add = [ln for ln in lines if ln not in present]
    if not to_add:
        return out
    return out + "\n\n" + "\n".join(to_add)


def protected_set(extra: list[str]) -> frozenset[str]:
    """The defaults plus any --protect branches. Nothing removes a default (no override exists)."""
    return frozenset(DEFAULT_PROTECTED).union(extra)


def _git(cwd: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *argv], cwd=str(cwd), capture_output=True, text=True)


def git_info(cwd: Path) -> GitInfo:
    inside = _git(cwd, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != "true":
        raise WorktreeRefused(f"{cwd} is not inside a git work tree")
    top = _git(cwd, "rev-parse", "--show-toplevel")
    branch = _git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
    if top.returncode != 0 or branch.returncode != 0:
        err = (top.stderr or branch.stderr).strip()
        raise GitFailed(f"git rev-parse failed in {cwd}: {err}")
    name = branch.stdout.strip()
    return GitInfo(toplevel=Path(top.stdout.strip()), branch=name, detached=(name == "HEAD"))


def commit(cwd: Path, message: str, *, all_files: bool, protected: frozenset[str],
           trailers: list[str] | None = None) -> GitInfo:
    """Stage and commit in cwd. Raises WorktreeRefused for a non-git dir, detached HEAD, a protected
    branch or a malformed trailer (all before staging anything), and GitFailed when git add/commit
    fails. Stages tracked changes only (git add -u) unless all_files (git add -A)."""
    info = git_info(cwd)
    if info.detached:
        raise WorktreeRefused("HEAD is detached; checkout a branch before committing")
    if info.branch in protected:
        raise WorktreeRefused(
            f"refusing to commit on protected branch {info.branch!r} "
            f"(this helper is for item/work branches only; it has no override)")
    msg = ensure_trailers(message, list(trailers or []))
    add = _git(cwd, "add", "-A") if all_files else _git(cwd, "add", "-u")
    if add.returncode != 0:
        raise GitFailed(f"git add failed: {add.stderr.strip() or add.stdout.strip()}")
    done = _git(cwd, "commit", "-m", msg)
    if done.returncode != 0:
        raise GitFailed(f"git commit failed: {done.stderr.strip() or done.stdout.strip()}")
    return info


def run(args: argparse.Namespace) -> int:
    cwd = args.cwd or Path.cwd()
    try:
        protected = protected_set(args.protect)
        info = commit(cwd, args.message, all_files=args.all_files, protected=protected,
                      trailers=args.trailer)
    except WorktreeCommitError as e:
        print(f"ctf worktree-commit: {e}", file=sys.stderr)
        return e.exit_code
    print(f"committed on {info.branch} ({info.toplevel})")
    return 0
