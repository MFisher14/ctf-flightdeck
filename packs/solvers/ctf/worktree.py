"""Per-agent build worktrees and the integrator merge queue (B-147).

Build swarms used to share one checkout: agents clobbered each other's files and every green test
result was conditional on whatever else was mid-edit (37 apply_patch verification failures across 18
of 29 subagents in the Huntress logs). The fix is structural:

  * **one worktree per agent, on its own named branch**, created before the agent is spawned, so no
    two agents ever write the same working tree (`create`, `list_worktrees`, `agent_branch`);
  * **one integrator** that merges the finished item branches back in BUILD-PLAN *dependency order*
    (`dependency_order`), regenerating the generated files and rerunning the gate after each merge
    (`integrate`);
  * **the integration branch takes no direct commits** — only the integrator's merges land on it
    (`refuse_direct_commit`, the check behind ``ctf integrate guard``). The guard is opt-in: it
    protects a checkout only once that checkout's ``pre-commit`` and ``pre-merge-commit`` hooks call
    it. This repo's ``.githooks`` do not call it (wiring it is a human step, see the build log). A
    hook cannot see a fast-forward merge, ``git reset`` or ``git branch -f``: git runs no hook there.

The integration branch has no built-in name: it is the ``integration_branch`` argument, else
``$CTF_INTEGRATION_BRANCH``, else the repo's ``git config ctftools.integrationBranch``; with none
of them set the integrator and the guard refuse with a named reason
(:func:`integration_branch_name`).

Everything here drives ``git`` through :func:`git`; it never pushes, never touches a remote, and runs
only in the directory it is given. The regenerate and gate steps of :func:`integrate` are injected
callables so the orchestration is testable on throwaway repos; :func:`default_regenerate` and
:func:`default_gate` wire the production commands.

Relation to ``ctf lanes integrate`` (B-179, docs/lanes.md): that command audits Codex lane results
(ownership, collisions, CAPABILITIES bullets) and with ``--merge`` merges the clean lane branches,
but it neither regenerates the generated files nor runs a gate. This module is the merge queue proper: any item
branches, BUILD-PLAN order, regenerate + gate after every merge, rollback of a merge that fails.

    from ctf import worktree
    wt = worktree.create(repo, worktree.agent_branch("B-147"), repo.parent / "wt-B-147")
    for w in worktree.list_worktrees(repo): ...
    res = worktree.integrate(integ_repo, branches, items=items)   # items: buildplan.Item list
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Mapping, Sequence

from . import env

# The branch the integrator owns is configuration, never a built-in name (see integration_branch_name).
# Only the integrator's merges land on it; a direct commit (a hand merge included) is refused unless
# the sanctioned integrator is running (ALLOW_ENV true).
INTEGRATION_BRANCH_ENV = "CTF_INTEGRATION_BRANCH"
INTEGRATION_BRANCH_GIT_CONFIG = "ctftools.integrationBranch"
ALLOW_ENV = "CTF_INTEGRATION_ALLOW"
PYTHON_ENV = "CTF_PYTHON"
DEFAULT_BRANCH_PREFIX = "item"
# While a queue step is between "merge started" and "gated or rolled back", this file in the
# checkout's git dir names the step. A run that finds it with the branch off the recorded base knows
# the previous run died there (kill, power loss) and that HEAD never passed the gate.
STEP_JOURNAL = "ctf-integrate-step.json"

# git runs with a deterministic identity, so the library's own commits never depend on the caller's
# git config. Hooks are NOT disabled: the integrator's commits go through the repo's hooks like any
# other commit (the secret scan still applies) and carry ALLOW_ENV so a hook that calls
# refuse_direct_commit admits them.
_GIT_IDENT = (
    "-c", "user.email=integrator@ctf-tools.invalid",
    "-c", "user.name=ctf-integrator",
    "-c", "commit.gpgsign=false",
)


class WorktreeError(RuntimeError):
    """A worktree or merge-queue operation failed loudly with a named reason (no silent fallback)."""


class DirectCommitRefused(WorktreeError):
    """A commit was attempted directly on the integration branch outside the integrator."""


# --------------------------------------------------------------------------------- git plumbing

def git(repo: str | Path, *argv: str, check: bool = True,
        extra_env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess:
    """Run ``git <argv>`` in ``repo`` with a fixed identity. The repo's hooks run as usual.

    ``extra_env`` is added to the environment of this one command (the integrator passes ALLOW_ENV
    this way, so it never leaks into the regenerate or gate steps). ``check`` raises
    :class:`WorktreeError` naming the command and git's stderr on a non-zero exit; ``check=False``
    returns the completed process for the caller to inspect."""
    cp = subprocess.run(["git", *_GIT_IDENT, "-C", str(repo), *argv],
                        capture_output=True, text=True,
                        env={**os.environ, **(extra_env or {})})
    if check and cp.returncode != 0:
        raise WorktreeError(f"git {' '.join(argv)} failed in {repo}: "
                            f"{(cp.stderr or cp.stdout).strip()}")
    return cp


def _toplevel(repo: str | Path) -> Path:
    cp = git(repo, "rev-parse", "--show-toplevel", check=False)
    if cp.returncode != 0:
        raise WorktreeError(f"{repo} is not inside a git work tree")
    return Path(cp.stdout.strip())


def current_branch(repo: str | Path) -> str:
    """The checked-out branch name, or ``"HEAD"`` when detached.

    Uses ``symbolic-ref`` so an unborn branch (a fresh repo with no commit yet) still reports its
    name; a detached HEAD, where ``symbolic-ref`` fails, reports ``"HEAD"``."""
    cp = git(repo, "symbolic-ref", "--short", "HEAD", check=False)
    if cp.returncode == 0:
        return cp.stdout.strip()
    return "HEAD"


def _branch_exists(repo: str | Path, branch: str) -> bool:
    return git(repo, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}",
               check=False).returncode == 0


def is_clean(repo: str | Path) -> bool:
    """True when the work tree has no staged, unstaged or untracked changes."""
    return not _dirty_paths(repo)


# --------------------------------------------------------------------------------- worktrees

def item_branches(repo: str | Path, *, prefix: str = DEFAULT_BRANCH_PREFIX) -> dict[str, str]:
    """Map item id -> branch for every local ``<prefix>/<id>`` branch in ``repo``.

    This is how the integrator discovers the finished item branches to queue when none are named
    explicitly. Branch ids keep their order of discovery; the integrator re-sorts them by dependency."""
    out: dict[str, str] = {}
    pfx = f"{prefix}/" if prefix else ""
    lines = git(repo, "for-each-ref", "--format=%(refname:short)", f"refs/heads/{pfx}*").stdout
    for ref in lines.splitlines():
        ref = ref.strip()
        if not ref:
            continue
        iid = ref[len(pfx):] if pfx else ref
        if iid:
            out[iid] = ref
    return out


def agent_branch(agent: str, *, prefix: str = DEFAULT_BRANCH_PREFIX) -> str:
    """The branch name for an agent/item, e.g. ``agent_branch("B-147") == "item/B-147"``.

    One agent, one branch: the convention keeps names collision-free and lets the integrator map a
    branch back to its BUILD-PLAN item. ``agent`` must be non-empty, must not start with ``-`` (git
    would read it as an option) and must give a name ``git check-ref-format`` accepts (no whitespace,
    ``~^:?*[\\``, ``..``, ``@{``, a ``.lock`` suffix, a leading or trailing dot, a trailing slash)."""
    a = str(agent).strip()
    if not a:
        raise WorktreeError("agent id must be non-empty")
    name = f"{prefix}/{a}" if prefix else a
    if a.startswith("-") or any(c.isspace() for c in a) or not _legal_branch_name(name):
        raise WorktreeError(f"agent id {agent!r} is not a legal branch component")
    return name


def _legal_branch_name(name: str) -> bool:
    """git's own verdict on ``refs/heads/<name>`` (the one authority on ref syntax)."""
    cp = subprocess.run(["git", "check-ref-format", f"refs/heads/{name}"],
                        capture_output=True, text=True)
    return cp.returncode == 0


@dataclass(frozen=True)
class Worktree:
    """One entry of ``git worktree list``."""

    path: Path
    head: str                       # commit sha, "" for a bare entry
    branch: str | None              # short branch name, None when detached or bare
    detached: bool = False
    bare: bool = False
    locked: bool = False


def create(repo: str | Path, branch: str, path: str | Path, *, base: str = "HEAD") -> Worktree:
    """Add a worktree at ``path`` on a new ``branch`` cut from ``base``.

    Refuses loudly (``WorktreeError``) when ``branch`` already exists or ``path`` is a non-empty
    existing location, so two agents can never be handed the same branch or directory. The new
    worktree is returned."""
    _toplevel(repo)
    dest = Path(path)
    if _branch_exists(repo, branch):
        raise WorktreeError(f"branch {branch!r} already exists; one branch per agent "
                            f"(pick a fresh name, e.g. {agent_branch('B-123')!r})")
    if dest.exists() and (not dest.is_dir() or any(dest.iterdir())):
        raise WorktreeError(f"worktree path {dest} already exists and is not empty")
    git(repo, "worktree", "add", "-b", branch, str(dest), base)
    for w in list_worktrees(repo):
        if w.path == dest.resolve() or w.path == dest:
            return w
    # Should not happen: git reported success but the entry is absent.
    raise WorktreeError(f"git worktree add succeeded but {dest} is not listed")


def list_worktrees(repo: str | Path) -> list[Worktree]:
    """Parse ``git worktree list --porcelain`` into :class:`Worktree` entries (main first)."""
    out = git(repo, "worktree", "list", "--porcelain").stdout
    entries: list[Worktree] = []
    cur: dict[str, object] = {}

    def flush() -> None:
        if not cur:
            return
        branch = cur.get("branch")
        entries.append(Worktree(
            path=Path(str(cur["worktree"])),
            head=str(cur.get("HEAD", "")),
            branch=str(branch) if branch else None,
            detached=bool(cur.get("detached")),
            bare=bool(cur.get("bare")),
            locked=bool(cur.get("locked")),
        ))
        cur.clear()

    for line in out.splitlines():
        if line == "":
            flush()
            continue
        if line.startswith("worktree "):
            flush()
            cur["worktree"] = line[len("worktree "):]
        elif line.startswith("HEAD "):
            cur["HEAD"] = line[len("HEAD "):]
        elif line.startswith("branch "):
            ref = line[len("branch "):]
            cur["branch"] = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
        elif line == "detached":
            cur["detached"] = True
        elif line == "bare":
            cur["bare"] = True
        elif line == "locked" or line.startswith("locked "):
            cur["locked"] = True
    flush()
    return entries


# --------------------------------------------------------------------------- dependency order

def item_dependencies(branches: Mapping[str, str], items: Sequence[object]) -> dict[str, set[str]]:
    """Map each queued item id -> every id its record depends on, queued or not.

    ``branches`` maps item id -> branch name (the ids to merge). ``items`` are
    :class:`ctf.buildplan.Item`-shaped records (anything with ``.id`` and ``.dependencies``). An
    item that lists itself is not its own dependency (it would otherwise read as a cycle). A queued
    id with no item record raises :class:`WorktreeError`: the order cannot be trusted without it."""
    in_queue = set(branches)
    unknown = in_queue - {getattr(it, "id", None) for it in items}
    if unknown:
        raise WorktreeError(f"no BUILD-PLAN item record for queued branch id(s): {', '.join(sorted(unknown))}")
    deps: dict[str, set[str]] = {}
    for it in items:
        iid = getattr(it, "id")
        if iid not in in_queue:
            continue
        itdeps = tuple(getattr(it, "dependencies", ()) or ())
        deps[iid] = {d for d in itdeps if d != iid}
    return deps


def queue_dependencies(branches: Mapping[str, str], items: Sequence[object]) -> dict[str, set[str]]:
    """Map each queued item id -> the ids it depends on that are *also in the queue*
    (:func:`item_dependencies` narrowed to the queue). A dependency outside the queue does not
    constrain the *order*; whether it holds its dependent back is :func:`unmerged_dependency_branches`."""
    in_queue = set(branches)
    return {iid: {d for d in ds if d in in_queue}
            for iid, ds in item_dependencies(branches, items).items()}


def unmerged_dependency_branches(repo: str | Path, deps: Iterable[str], *,
                                 prefix: str = DEFAULT_BRANCH_PREFIX) -> list[tuple[str, str]]:
    """Of the dependency ids ``deps``, the ``(id, branch)`` pairs whose local ``<prefix>/<id>``
    branch exists and has a tip that is not in ``repo``'s HEAD: work that exists but has not been
    merged. A dependency with no local branch is not listed (already merged and its branch deleted,
    or never built: the two cannot be told apart here)."""
    out: list[tuple[str, str]] = []
    for dep in sorted(deps):
        branch = f"{prefix}/{dep}" if prefix else str(dep)
        if not _branch_exists(repo, branch):
            continue
        if git(repo, "merge-base", "--is-ancestor", f"refs/heads/{branch}", "HEAD",
               check=False).returncode != 0:
            out.append((dep, branch))
    return out


def dependency_order(branches: Mapping[str, str], items: Sequence[object]) -> list[str]:
    """Return the item ids of ``branches`` in BUILD-PLAN dependency order.

    An item comes after every dependency that is *also in the queue* (:func:`queue_dependencies`); a
    dependency outside the queue does not change the order. Ties break by id for a stable order. A
    cycle among the queued items raises :class:`WorktreeError` naming the members."""
    deps = queue_dependencies(branches, items)
    # Kahn's algorithm with a stable (sorted) frontier.
    order: list[str] = []
    satisfied: set[str] = set()
    remaining = set(deps)
    while remaining:
        ready = sorted(i for i in remaining if deps[i] <= satisfied)
        if not ready:
            cyc = ", ".join(sorted(remaining))
            raise WorktreeError(f"dependency cycle among queued items: {cyc}")
        for i in ready:
            order.append(i)
            satisfied.add(i)
            remaining.discard(i)
    return order


# --------------------------------------------------------------------- the integrator merge queue

# A step that put (or found) the item's work on the integration branch.
OK_STATUSES = ("merged", "already-merged")
# A step that tried and failed; the integration branch is back at the commit it had before the step.
FAILED_STATUSES = ("conflict", "merge-failed", "missing-branch", "regen-failed", "gate-failed")


@dataclass(frozen=True)
class MergeStep:
    """What happened for one item branch in the queue.

    ``status`` is one of OK_STATUSES, FAILED_STATUSES or ``skipped`` (not attempted: the queue had
    halted, a dependency in the queue did not merge, or a dependency outside the queue has a local
    branch that is not merged yet; ``detail`` names which). ``commit`` is the
    merge commit for ``merged``, the unchanged HEAD for ``already-merged``, the rolled-back merge
    commit for ``gate-failed`` (still reachable by sha for a post-mortem), the pre-merge HEAD for the
    other failures, and empty for ``skipped``."""

    item: str
    branch: str
    status: str
    detail: str = ""
    commit: str = ""


@dataclass(frozen=True)
class IntegrationResult:
    integration_branch: str
    order: tuple[str, ...]
    steps: tuple[MergeStep, ...]
    halted: bool = False            # the queue stopped before trying every item

    @property
    def ok(self) -> bool:
        return all(s.status in OK_STATUSES for s in self.steps)

    def merged(self) -> list[MergeStep]:
        return [s for s in self.steps if s.status == "merged"]

    def failures(self) -> list[MergeStep]:
        return [s for s in self.steps if s.status in FAILED_STATUSES]

    def failure(self) -> MergeStep | None:
        return next(iter(self.failures()), None)


# A regenerate step: given the repo, bring the generated files up to date (returns nothing; raises to
# signal it could not). A gate step: given (repo, base_before_this_merge), return (ok, detail). A gate
# must leave the checkout as it found it (write only ignored paths, or outside the checkout).
Regenerate = Callable[[Path], None]
Gate = Callable[[Path, str], "tuple[bool, str]"]


def _dirty_paths(repo: str | Path) -> list[str]:
    """Paths ``git status`` reports as staged, modified or untracked (ignored files excluded).

    ``--untracked-files=all`` is explicit so the answer does not depend on the user's
    ``status.showUntrackedFiles``: with ``no`` there, a stray or freshly generated file would be
    invisible to the clean-tree checks and to the fold of the regenerated files."""
    out = git(repo, "status", "--porcelain", "--untracked-files=all").stdout
    return [line[3:] for line in out.splitlines() if line.strip()]


def _head(repo: str | Path) -> str:
    return git(repo, "rev-parse", "HEAD").stdout.strip()


def _head_is_merge_of(repo: str | Path, base: str, tip: str) -> bool:
    """True when HEAD is a merge commit whose parents are exactly (``base``, ``tip``): the merge this
    queue just made, and nothing else. The only commit the integrator may amend."""
    parts = git(repo, "rev-list", "--parents", "-n", "1", "HEAD").stdout.split()
    return parts[1:] == [base, tip]


def _rollback(repo: str | Path, base: str) -> list[str]:
    """Put the integration branch and its tracked files back at ``base`` (also ends a merge in
    progress). Returns what is still dirty afterwards: untracked files a step created. They are never
    deleted here (the queue cannot know they are disposable); the caller halts the queue instead."""
    git(repo, "reset", "--hard", base)
    return _dirty_paths(repo)


def _names(paths: Sequence[str], limit: int = 5) -> str:
    more = f", +{len(paths) - limit} more" if len(paths) > limit else ""
    return ", ".join(paths[:limit]) + more


def _journal_path(repo: str | Path) -> Path:
    """STEP_JOURNAL in this checkout's own git dir (a linked worktree has its own)."""
    return Path(git(repo, "rev-parse", "--absolute-git-dir").stdout.strip()) / STEP_JOURNAL


def _refuse_interrupted_step(repo: str | Path, integ: str) -> None:
    """Refuse to run on top of a step a previous run never finished.

    A step that ends normally, fails, or is interrupted by an exception (Ctrl-C included) removes
    its journal after putting the branch where it belongs. A journal that is still there means the
    process died inside the step. If the branch is back at the recorded base nothing ungated landed
    and the stale journal is dropped. Otherwise HEAD holds a merge that never passed the gate (or
    something made on top of one): :class:`WorktreeError` names the item and the commit to reset
    to. Nothing is reset here: the queue cannot know what else happened since."""
    journal = _journal_path(repo)
    if not journal.exists():
        return
    try:
        rec = json.loads(journal.read_text())
        item, branch, base = str(rec["item"]), str(rec["branch"]), str(rec["base"])
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise WorktreeError(f"unreadable integrator step journal {journal} ({type(e).__name__}): a "
                            f"previous run was interrupted mid-step; check {integ!r} holds no "
                            f"ungated merge, delete the file and run again") from None
    head = _head(repo)
    if head == base:
        journal.unlink()
        return
    raise WorktreeError(
        f"a previous integrator run was interrupted while merging {branch!r} ({item}): {integ!r} is "
        f"at {head[:12]}, which never passed the gate (it was at {base[:12]} before that step). "
        f"Roll it back with `git reset --hard {base}` and run again (journal: {journal})")


def integrate(repo: str | Path, branches: Mapping[str, str], *, items: Sequence[object],
              integration_branch: str | None = None,
              regenerate: Regenerate | None = None, gate: Gate | None = None,
              stop_on_fail: bool = True, prefix: str = DEFAULT_BRANCH_PREFIX) -> IntegrationResult:
    """Merge the queued item branches onto the integration branch in dependency order.

    ``branches`` maps item id -> branch. Each item is one step (:class:`MergeStep`):

      * a branch that does not resolve is ``missing-branch``; a branch whose tip is already in the
        integration branch is ``already-merged`` and nothing is merged, regenerated, gated or amended;
      * otherwise ``git merge --no-ff`` makes a merge commit (parents: the previous HEAD, the branch
        tip); ``regenerate`` runs and what it changed is folded into *that* commit, which is the only
        commit ever amended (HEAD is checked to be it first); then ``gate`` runs;
      * a conflict, a merge git refuses for another reason, a regenerate failure, a red gate, a gate
        that raises and a gate that leaves the checkout changed (a file, or a commit of its own) all
        roll the branch back to the commit it had before the step, so a failed item never stays on
        the integration branch;
      * an interrupt (Ctrl-C, ``SystemExit``, any exception the step does not expect) between the
        merge and the end of the gate rolls the branch back the same way and is re-raised: an
        ungated merge is never left for the next run to report as ``already-merged``. A process
        killed outright cannot roll back; the next run finds its step journal (STEP_JOURNAL in the
        git dir) and refuses, naming the commit to reset to (:func:`_refuse_interrupted_step`);
      * an item with a dependency that is *not* queued but has a local ``<prefix>/<dep>`` branch
        whose tip is not in the integration branch is ``skipped`` naming it
        (:func:`unmerged_dependency_branches`): the dependency exists and is not merged, so the
        dependent must not go first. A dependency with no local branch does not hold it.

    After a failure the queue halts and the rest are ``skipped`` (``stop_on_fail``, the default).
    With ``stop_on_fail=False`` it goes on, but only to independent items: an item with a failed or
    skipped dependency in the queue is ``skipped`` naming that dependency. Whatever the mode, the
    queue halts when a failed step left untracked files behind that the rollback does not own (they
    are named, never deleted, never swept into a later merge).

    Nothing is pushed and no remote is touched. The integrator's own git commands carry ``ALLOW_ENV``
    so a pre-commit hook that calls :func:`refuse_direct_commit` admits them while still blocking
    stray hand commits on the branch.

    Raises :class:`WorktreeError` before doing anything if no integration branch is configured, the
    repo is not on it, a previous run died mid-step and left its merge on the branch, or its work
    tree is dirty (an uncommitted direct edit must not be swept into a merge); and mid-queue if git
    did not produce the merge commit the queue expects."""
    integ = integration_branch_name(integration_branch, repo=repo)
    top = _toplevel(repo)
    on = current_branch(repo)
    if on != integ:
        raise WorktreeError(f"integrator must run on the integration branch {integ!r}, not {on!r}")
    _refuse_interrupted_step(repo, integ)
    dirty = _dirty_paths(repo)
    if dirty:
        raise WorktreeError(f"integration work tree {top} has uncommitted changes ({_names(dirty)}); "
                            f"refusing to merge over a direct edit")
    for iid, branch in branches.items():
        if not str(branch) or str(branch).startswith("-"):
            raise WorktreeError(f"queued branch {branch!r} for {iid} is not a branch name")
    all_deps = item_dependencies(branches, items)
    deps = queue_dependencies(branches, items)
    order = dependency_order(branches, items)
    steps: list[MergeStep] = []
    not_merged: dict[str, str] = {}     # item -> its status, for every item that did not land
    halt = ""                           # why the queue stopped; "" while it is running
    for iid in order:
        branch = branches[iid]
        if halt:
            steps.append(MergeStep(iid, branch, "skipped", halt))
            not_merged[iid] = "skipped"
            continue
        held_by = sorted(d for d in deps[iid] if d in not_merged)
        if held_by:
            why = ", ".join(f"{d} ({not_merged[d]})" for d in held_by)
            steps.append(MergeStep(iid, branch, "skipped", f"dependency did not merge: {why}"))
            not_merged[iid] = "skipped"
            continue
        waiting = unmerged_dependency_branches(repo, all_deps[iid] - set(branches), prefix=prefix)
        if waiting:
            why = ", ".join(f"{d} ({b})" for d, b in waiting)
            steps.append(MergeStep(iid, branch, "skipped",
                                   f"dependency is not queued and its branch is not merged into "
                                   f"{integ}: {why}; queue it or merge it first"))
            not_merged[iid] = "skipped"
            continue
        step, leftovers = _merge_one(repo, top, iid, branch, integ, regenerate, gate)
        steps.append(step)
        if step.status in OK_STATUSES:
            continue
        not_merged[iid] = step.status
        if leftovers:
            halt = (f"queue halted: {iid} ({step.status}) left files in the work tree that are not "
                    f"tracked: {_names(leftovers)}; remove them and run again")
        elif stop_on_fail:
            halt = f"queue halted: {iid} {step.status}"
    return IntegrationResult(integration_branch=integ, order=tuple(order),
                             steps=tuple(steps), halted=bool(halt))


def _merge_one(repo: str | Path, top: Path, iid: str, branch: str, integ: str,
               regenerate: Regenerate | None, gate: Gate | None) -> tuple[MergeStep, list[str]]:
    """One queue step. Returns the step and, for a failed step, what the rollback left dirty."""
    base = _head(repo)
    tip_cp = git(repo, "rev-parse", "--verify", "--quiet", f"{branch}^{{commit}}", check=False)
    if tip_cp.returncode != 0:
        return MergeStep(iid, branch, "missing-branch",
                         f"{branch!r} does not name a commit in {top}", base), []
    tip = tip_cp.stdout.strip()
    if git(repo, "merge-base", "--is-ancestor", tip, base, check=False).returncode == 0:
        return MergeStep(iid, branch, "already-merged",
                         f"{tip[:12]} is already in {integ}; nothing merged", base), []

    journal = _journal_path(repo)
    journal.write_text(json.dumps({"item": iid, "branch": branch, "base": base, "tip": tip}) + "\n")
    try:
        out = _merge_regen_gate(repo, top, iid, branch, base, tip, regenerate, gate)
    except BaseException:
        # Ctrl-C in the gate, SystemExit, an error no branch below expects: the merge may be on the
        # branch ungated. Put the branch back, then let the interrupt through. If the rollback itself
        # fails the journal stays, and the next run refuses instead of accepting the merge.
        _rollback(repo, base)
        journal.unlink(missing_ok=True)
        raise
    journal.unlink(missing_ok=True)
    return out


def _merge_regen_gate(repo: str | Path, top: Path, iid: str, branch: str, base: str, tip: str,
                      regenerate: Regenerate | None, gate: Gate | None) -> tuple[MergeStep, list[str]]:
    """Merge ``branch`` (tip ``tip``) onto ``base``, regenerate, gate. Every failure it reports has
    been rolled back to ``base``; anything it raises is rolled back by :func:`_merge_one`."""
    allow = {ALLOW_ENV: "1"}
    merge = git(repo, "merge", "--no-ff", "--no-edit", branch, check=False, extra_env=allow)
    if merge.returncode != 0:
        conflicted = bool(git(repo, "ls-files", "--unmerged").stdout.strip())
        left = _rollback(repo, base)
        return MergeStep(iid, branch, "conflict" if conflicted else "merge-failed",
                         (merge.stdout + merge.stderr).strip()[:500], base), left
    if not _head_is_merge_of(repo, base, tip):
        got = _head(repo)
        _rollback(repo, base)
        raise WorktreeError(f"git merge of {branch!r} did not leave a merge commit of {base[:12]} and "
                            f"{tip[:12]} at HEAD (got {got[:12]}); rolled back, queue stopped")

    if regenerate is not None:
        try:
            regenerate(top)
        except Exception as e:  # a failed regen fails the step, never a silent skip
            left = _rollback(repo, base)
            return MergeStep(iid, branch, "regen-failed", f"{type(e).__name__}: {e}"[:500], base), left
        if not _head_is_merge_of(repo, base, tip):
            left = _rollback(repo, base)
            return MergeStep(iid, branch, "regen-failed",
                             "the regenerate step moved HEAD; it must only write files", base), left
        if _dirty_paths(repo):
            # Fold the regenerated files into the merge commit just made. HEAD was checked above to
            # be that commit, so this amend can never rewrite anything older.
            git(repo, "add", "-A", extra_env=allow)
            fold = git(repo, "commit", "--amend", "--no-edit", check=False, extra_env=allow)
            if fold.returncode != 0:
                left = _rollback(repo, base)
                return MergeStep(iid, branch, "regen-failed",
                                 ("could not commit the regenerated files: "
                                  + (fold.stderr or fold.stdout).strip())[:500], base), left

    merged = _head(repo)
    if gate is not None:
        try:
            ok, detail = gate(top, base)
        except Exception as e:  # a gate that cannot run is a red gate, never a pass
            ok, detail = False, f"gate could not run: {type(e).__name__}: {e}"
        if ok:
            changed = _dirty_paths(repo)
            if changed or _head(repo) != merged:
                what = _names(changed) if changed else "HEAD moved"
                ok, detail = False, (f"gate passed but changed the checkout ({what}); a gate must "
                                     f"write only ignored paths or outside the checkout")
        if not ok:
            left = _rollback(repo, base)
            return MergeStep(iid, branch, "gate-failed", str(detail)[:500], merged), left
    subject = git(repo, "log", "-1", "--pretty=%s", tip).stdout.strip()[:200]
    return MergeStep(iid, branch, "merged", subject, merged), []


# --------------------------------------------------------------------- refuse direct commits

def integration_branch_name(integration_branch: str | None = None, *, repo: str | Path | None = None,
                            environ: Mapping[str, str] | None = None) -> str:
    """The integration branch: the argument, else ``$CTF_INTEGRATION_BRANCH``, else ``repo``'s
    ``git config ctftools.integrationBranch`` (shared by every worktree of the repo, so one setting
    covers a hook that runs in all of them). There is no built-in name: with none of the three set this
    raises :class:`WorktreeError` saying how to set one."""
    if integration_branch:
        return integration_branch
    from_env = env.get(INTEGRATION_BRANCH_ENV, environ=environ)
    if from_env:
        return from_env
    if repo is not None:
        cp = git(repo, "config", "--get", INTEGRATION_BRANCH_GIT_CONFIG, check=False)
        if cp.returncode == 0 and cp.stdout.strip():
            return cp.stdout.strip()
    raise WorktreeError(
        f"no integration branch configured: pass --integration-branch, set ${INTEGRATION_BRANCH_ENV}, "
        f"or run `git config {INTEGRATION_BRANCH_GIT_CONFIG} <branch>` in the repo")


def refuse_direct_commit(repo: str | Path, *, integration_branch: str | None = None,
                         environ: Mapping[str, str] | None = None) -> None:
    """Guard for a pre-commit hook: refuse a direct commit on the integration branch.

    A commit is allowed when the current branch is *not* the integration branch, when the
    sanctioned integrator is running (``ALLOW_ENV`` true: 1/true/yes/on, see :func:`integrate`), or
    when the branch has no commit yet (the initial commit). Any other commit on the integration
    branch raises :class:`DirectCommitRefused`, which the hook turns into a non-zero exit so the
    commit does not land. ``ALLOW_ENV`` set to 0/false/no/off or empty does not admit, and a value
    that is not a boolean refuses too (the guard fails closed). ``environ`` (default ``os.environ``)
    is the one environment read, for the allow flag and for the branch name alike.

    A merge in progress (``MERGE_HEAD``) is *not* an exemption: the integrator never commits a
    merge by hand (its merges carry ``ALLOW_ENV``, and it rolls a conflict back), so the only
    commits such an exemption would admit are hand merges, with whatever else was staged alongside.

    What a hook can see: ``pre-commit`` runs for ``git commit`` (concluding a ``--no-commit`` or
    conflicted merge included); ``pre-merge-commit`` runs when ``git merge`` makes a merge commit
    itself. Wire the guard into both. git runs no hook for a fast-forward merge, ``git reset``,
    ``git branch -f`` or ``git update-ref``, so those are outside what this guard can refuse."""
    environ = os.environ if environ is None else environ
    integ = integration_branch_name(integration_branch, repo=repo, environ=environ)
    on = current_branch(repo)
    if on != integ:
        return
    try:
        allowed = env.get_bool(ALLOW_ENV, False, environ=environ)
    except env.EnvError as e:
        raise DirectCommitRefused(f"refusing a direct commit on the integration branch {integ!r}: "
                                  f"{e}") from None
    if allowed:
        return
    if git(repo, "rev-parse", "--verify", "--quiet", "HEAD", check=False).returncode != 0:
        return  # no HEAD yet: the branch's first commit
    raise DirectCommitRefused(
        f"refusing a direct commit on the integration branch {integ!r}: only the integrator may "
        f"commit here, and only by merging item branches (ctf integrate; a hand merge is a direct "
        f"commit too). Make your change on an item branch in your own worktree.")


# --------------------------------------------------------------------- production step wiring

GENERATED_FILE_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("tools/requirements_gen.py",),
    ("-m", "ctf", "engines", "generate"),
    ("-m", "ctf", "engines", "coverage", "--write"),
)


def resolve_python(python: str | Path | None = None, *,
                   environ: Mapping[str, str] | None = None) -> str:
    """The interpreter the regenerate and gate steps run: ``python`` if given, else ``$CTF_PYTHON`` if
    set, else the interpreter running the integrator (``sys.executable``). Not ``<repo>/.venv``: a
    fresh worktree has none. Only the first source given is used, and it must be an executable file;
    otherwise :class:`WorktreeError` names the source (no falling through to the next one)."""
    from_env = env.get(PYTHON_ENV, environ=environ)
    if python:
        why, cand = "the python argument", str(python)
    elif from_env:
        why, cand = f"${PYTHON_ENV}", from_env
    else:
        why, cand = "the running interpreter (sys.executable)", sys.executable or ""
    if not cand or not Path(cand).is_file() or not os.access(cand, os.X_OK):
        raise WorktreeError(f"no usable interpreter for the regenerate and gate steps: {why}: "
                            f"{cand!r} is not an executable file")
    return cand


def regenerate_commands(repo: str | Path) -> list[tuple[str, ...]]:
    """The generator commands for ``repo``, in run order: GENERATED_FILE_COMMANDS, then
    ``new-event <slug> --regen`` for every event profile under ``<repo>/events`` (its CLAUDE.md and
    AGENTS.md are generated from event.toml)."""
    from . import event as _event
    cmds = list(GENERATED_FILE_COMMANDS)
    for slug in _event.available(Path(repo) / "events"):
        cmds.append(("-m", "ctf", "new-event", slug, "--regen"))
    return cmds


def default_regenerate(repo: str | Path, *, python: str | Path | None = None) -> None:
    """Regenerate the tracked generated files after a merge (production wiring for :func:`integrate`).

    Runs :func:`regenerate_commands` in ``repo`` with :func:`resolve_python`. Any non-zero exit raises
    :class:`WorktreeError` naming the command, so a broken regeneration fails the step rather than
    committing a stale tree."""
    py = resolve_python(python)
    for cmd in regenerate_commands(repo):
        cp = subprocess.run([py, *cmd], cwd=str(repo), capture_output=True, text=True)
        if cp.returncode != 0:
            raise WorktreeError(f"regenerate `{' '.join(cmd)}` failed (exit {cp.returncode}): "
                                f"{(cp.stderr or cp.stdout).strip()[:300]}")


def default_gate(repo: str | Path, base: str, *, python: str | Path | None = None) -> tuple[bool, str]:
    """Rerun the impact-selected gate for the changes since ``base`` (production wiring).

    Runs ``ctf gate run --base <base>`` in ``repo`` with :func:`resolve_python`. Returns
    ``(ok, detail)``: ``ok`` is exit status 0, ``detail`` the gate's last output line. A red gate is a
    normal result, not an exception; an interpreter that cannot be found raises
    :class:`WorktreeError`, which :func:`integrate` records as a failed gate."""
    py = resolve_python(python)
    cp = subprocess.run([py, "-m", "ctf", "gate", "run", "--base", base],
                        cwd=str(repo), capture_output=True, text=True)
    tail = ((cp.stdout or cp.stderr).strip().splitlines() or [""])[-1]
    return cp.returncode == 0, tail if cp.returncode == 0 else f"exit {cp.returncode}: {tail}"
