"""One git checkout per lane (B-179).

Each lane gets `git clone --shared --no-checkout <repo>` at <batch>/lanes/<id>/wt, then a branch
lane/<batch>/<id> at the backlog's base commit. A clone rather than `git worktree add`, on purpose:
a linked worktree writes its commits into the source repo's .git, which sits outside the lane's
fence, so a fenced `git commit` would fail; a clone keeps its own .git inside the lane folder
(objects are borrowed read-only from the source through alternates). The clone's `origin` remote is
removed, so a lane cannot push or fetch into the source; integration fetches from the clone.

Also done per lane: the source's `core.hooksPath` is copied (the pre-commit secret guard keeps
running), `.venv` is linked to the master venv and listed in the clone's own info/exclude.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .backlog import Backlog
from .layout import BatchDirs


class CheckoutError(RuntimeError):
    """A git step failed or the lane folder is in an unexpected state. Names the lane and step."""


def git_bin() -> str:
    g = shutil.which("git")
    if g is None:
        raise CheckoutError("git is not on PATH: lane checkouts need git")
    return g


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run([git_bin(), "-C", str(repo), *args], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    if check and p.returncode != 0:
        raise CheckoutError(f"git {' '.join(args)} in {repo} failed ({p.returncode}): "
                            f"{(p.stderr or p.stdout).strip()}")
    return p


def resolve_base(repo: Path, base: str) -> str:
    p = git(repo, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}", check=False)
    if p.returncode != 0 or not p.stdout.strip():
        raise CheckoutError(f"base ref {base!r} does not resolve to a commit in {repo}")
    return p.stdout.strip()


def find_venv(repo: Path) -> Path:
    """The master venv: <repo>/.venv, else the main checkout's .venv (a worktree has none)."""
    own = Path(repo) / ".venv"
    if (own / "bin" / "python").exists():
        return own.resolve()
    p = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir", check=False)
    if p.returncode == 0 and p.stdout.strip():
        main = Path(p.stdout.strip()).parent / ".venv"
        if (main / "bin" / "python").exists():
            return main.resolve()
    raise CheckoutError(f"no venv: {own}/bin/python is missing and the main checkout has none "
                        "(run setup.sh in the main checkout, or pass --venv)")


def missing_context(repo: Path, backlog: Backlog, sha: str) -> list[tuple[str, str]]:
    """(lane id or "*", path) for every context file the base commit lacks."""
    out = []
    wanted = [("*", p) for p in backlog.context] + [(ln.id, p) for ln in backlog.lanes for p in ln.context]
    for who, p in wanted:
        if git(repo, "cat-file", "-e", f"{sha}:{p}", check=False).returncode != 0:
            out.append((who, p))
    return out


def current_branch(co: Path) -> str | None:
    p = git(co, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)
    return p.stdout.strip() if p.returncode == 0 else None


def setup_lane(repo: Path, backlog: Backlog, lane_id: str, dirs: BatchDirs, base_sha: str,
               venv: Path | None) -> str:
    """Create the lane checkout. Returns "created" or "exists" (a checkout on the lane's branch is
    reused untouched). Anything else at the path is a CheckoutError, never overwritten."""
    co = dirs.checkout(lane_id)
    branch = backlog.branch(lane_id)
    if co.exists():
        if not (co / ".git").is_dir():
            raise CheckoutError(f"lane {lane_id}: {co} exists and is not a lane checkout; move it away")
        have = current_branch(co)
        if have != branch:
            raise CheckoutError(f"lane {lane_id}: {co} is on {have or 'a detached HEAD'}, expected {branch}")
        return "exists"
    co.parent.mkdir(parents=True, exist_ok=True)
    git(co.parent, "clone", "--quiet", "--shared", "--no-checkout", str(Path(repo).resolve()), str(co))
    try:
        git(co, "checkout", "--quiet", "-b", branch, base_sha)
        git(co, "remote", "remove", "origin")
        git(co, "config", "lane.base", base_sha)
        git(co, "config", "lane.start", base_sha)
        hp = git(repo, "config", "--get", "core.hooksPath", check=False).stdout.strip()
        if hp:
            git(co, "config", "core.hooksPath", hp)
        exclude = co / ".git" / "info" / "exclude"
        exclude.parent.mkdir(parents=True, exist_ok=True)
        with open(exclude, "a", encoding="utf-8") as fh:
            fh.write("\n# B-179 lane checkout\n.venv\n")
        if venv is not None:
            (co / ".venv").symlink_to(Path(venv).resolve(), target_is_directory=True)
    except Exception:
        shutil.rmtree(co, ignore_errors=True)
        raise
    return "created"


def setup(repo: Path, backlog: Backlog, dirs: BatchDirs, *, lane_ids: list[str] | None = None,
          venv: Path | None = None) -> dict[str, str]:
    repo = Path(repo)
    sha = resolve_base(repo, backlog.base)
    miss = missing_context(repo, backlog, sha)
    if miss:
        raise CheckoutError("context file(s) missing at base " + backlog.base + ": "
                            + ", ".join(f"{p} ({who})" for who, p in miss))
    out = {}
    for lid in lane_ids or backlog.order():
        out[lid] = setup_lane(repo, backlog, lid, dirs, sha, venv)
    return out


# ------------------------------------------------------------------------------- inspecting a lane

def _lane_config(co: Path, key: str) -> str:
    p = git(co, "config", "--get", f"lane.{key}", check=False)
    if p.returncode != 0 or not p.stdout.strip():
        raise CheckoutError(f"{co}: lane.{key} is not recorded (not a lane checkout?)")
    return p.stdout.strip()


def base_of(co: Path) -> str:
    """The backlog base commit the lane branch was created at."""
    return _lane_config(co, "base")


def start_of(co: Path) -> str:
    """Where the lane's own work starts: the base, or the merge of its dependencies' branches.
    The lane's changes and commits are counted from here."""
    return _lane_config(co, "start")


def merge_dependencies(co: Path, deps: list[tuple[str, Path]]) -> str:
    """Fetch each (branch, dependency checkout) into the lane checkout and merge it, then record
    lane.start at the result. Done once, before the lane first runs; a conflict aborts the merge and
    raises CheckoutError naming the branch."""
    if git(co, "config", "--get", "lane.deps-merged", check=False).stdout.strip() == "1":
        return start_of(co)
    for branch, dep_co in deps:
        git(co, "fetch", "--quiet", "--no-tags", str(dep_co), f"+refs/heads/{branch}:refs/heads/{branch}")
        p = git(co, "merge", "--no-ff", "--no-edit", "-m", f"Merge dependency {branch}", branch, check=False)
        if p.returncode != 0:
            git(co, "merge", "--abort", check=False)
            raise CheckoutError(f"{co}: merging dependency {branch} conflicts: "
                                f"{(p.stdout + p.stderr).strip()}")
    sha = head(co)
    git(co, "config", "lane.start", sha)
    git(co, "config", "lane.deps-merged", "1")
    return sha


def alternates(co: Path) -> list[Path]:
    """The object stores the clone borrows from (read-only), so a strict fence can re-open them."""
    f = Path(co) / ".git" / "objects" / "info" / "alternates"
    if not f.is_file():
        return []
    return [Path(x.strip()).resolve() for x in f.read_text().splitlines() if x.strip() and not x.startswith("#")]


def head(co: Path) -> str:
    return git(co, "rev-parse", "HEAD").stdout.strip()


def commits_since(co: Path, sha: str) -> int:
    return int(git(co, "rev-list", "--count", f"{sha}..HEAD").stdout.strip() or 0)


def changed_files(co: Path, sha: str) -> list[str]:
    out = git(co, "diff", "--name-only", "--no-renames", sha, "HEAD").stdout
    return sorted(x for x in out.splitlines() if x)


def uncommitted(co: Path) -> list[str]:
    out = git(co, "status", "--porcelain", "--untracked-files=all").stdout
    return sorted(line[3:] for line in out.splitlines() if line.strip())


def is_ancestor(co: Path, a: str, b: str) -> bool:
    return git(co, "merge-base", "--is-ancestor", a, b, check=False).returncode == 0


def show(co: Path, rev: str, rel: str) -> str | None:
    p = git(co, "show", f"{rev}:{rel}", check=False)
    return p.stdout if p.returncode == 0 else None
