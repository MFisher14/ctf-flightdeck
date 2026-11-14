"""Arm and release-morning safety (B-197): `python -m ctf release` (ctf/cli/release.py). Builds on
B-038's event tags and git helpers.

Release-morning faults this closes (Huntress retros / Day 29):
  - arming needed a human every night because `git tag -f` was blocked  -> write a *dated* tag
    every time, so a fresh arm never force-moves an existing one;
  - live fixes sat outside the armed tag                                 -> `lag` alerts when the
    latest armed tag is behind HEAD, and `ctf release check` diffs armed vs the release ref;
  - a hard code freeze with rollback to the last green commit            -> freeze/green tags and
    `rollback_target`;
  - the opener blocked itself on its own helpers for ~594 s on Day 29    -> `classify`, a
    process-identity fence by lineage, own group and an owned-process registry, so a wait never
    includes our own (even detached) helpers; `arm` runs its real-process regression first;
  - built work was unwired                                               -> `unwired`, an
    arm-report of modules nothing imports.

Tag namespaces (all annotated, all dated, none ever force-moved):

    event/<slug>/armed/<YYYY-MM-DD>           the tree declared release-ready that day
    event/<slug>/armed/<YYYY-MM-DD>.<n>       a later re-arm the same day (n >= 2)
    event/<slug>/green/<YYYY-MM-DDTHH-MM-SS>  a commit a green gate run marked (rollback target)
    event/<slug>/freeze/<YYYY-MM-DDTHH-MM-SS> a code freeze: arming past it is refused until thawed
    event/<slug>/thaw/<YYYY-MM-DDTHH-MM-SS>   lifts the freeze made before it

A second stamp in the same second gets a `.<n>` suffix (n >= 2), like a same-day re-arm; freeze and
thaw share one suffix sequence so their order is always decidable.

Errors: `ArmError` is a refusal (frozen, nothing to thaw or roll back, the fence regression failed);
`ArmInputError` is a bad input or a missing tool (a ref that is not a commit, no such package, no
psutil). The CLI exits 1 on the first and 2 on the second.

Git is reused from ctf.promote (B-038): the same `git` runner, `commit_of`, `is_ancestor`,
`require_repo` and slug check. This module adds no git behaviour of its own beyond listing and
annotating tags.
"""
from __future__ import annotations

import ast
import datetime as _dt
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import ledger, paths
from .promote import (
    PromoteError,
    TAG_PREFIX,
    _check_slug,
    commit_of,
    git,
    is_ancestor,
    require_repo,
)

ARMED = "armed"
GREEN = "green"
FREEZE = "freeze"
THAW = "thaw"

_LEAF_RE = re.compile(r"^([^.]+)(?:\.(\d+))?$")


class ArmError(PromoteError):
    """An arm/release step is refused; the message names what blocks it (CLI exit 1)."""


class ArmInputError(PromoteError):
    """A bad input or a missing tool: a ref that is not a commit, no such package, no psutil
    (CLI exit 2, so a script can tell it from a refusal or a lagging release ref)."""


# ------------------------------------------------------------------------------------------- tags

@dataclass(frozen=True)
class Tag:
    """One event tag: its short leaf (what follows the namespace), the full ref name, the commit it
    points at, and the sort key parsed from the leaf."""
    slug: str
    kind: str
    leaf: str
    name: str
    commit: str
    sort: tuple

    @property
    def date(self) -> str:
        """The date (armed) or timestamp (others) part of the leaf, without any `.<n>` suffix."""
        return self.sort[0]


def _ns(slug: str, kind: str) -> str:
    _check_slug(slug)
    return f"{TAG_PREFIX}{slug}/{kind}/"


def _leaf_sort(kind: str, leaf: str) -> tuple:
    """A total order within a namespace: (date-or-timestamp, suffix), the unsuffixed leaf being
    suffix 1. The date/timestamp parts sort chronologically as strings; the suffix numerically
    (so `.10` sorts after `.9`)."""
    m = _LEAF_RE.match(leaf)
    if not m:
        return (leaf, 0)
    return (m.group(1), int(m.group(2) or 1))


def _resolve(root: Path, ref: str) -> str:
    sha = commit_of(root, ref)
    if sha is None:
        raise ArmInputError(f"{ref} is not a commit in {root}")
    return sha


def list_tags(slug: str, kind: str, *, master: Path | None = None) -> list[Tag]:
    """Every tag in the namespace, oldest first. A tag whose target commit is gone (dangling) is
    skipped — it cannot anchor anything."""
    root = _master(master)
    ns = _ns(slug, kind)
    out: list[Tag] = []
    for name in git(root, "tag", "-l", f"{ns}*").splitlines():
        name = name.strip()
        if not name:
            continue
        leaf = name[len(ns):]
        sha = commit_of(root, f"refs/tags/{name}")
        if sha is None:
            continue
        out.append(Tag(slug, kind, leaf, name, sha, _leaf_sort(kind, leaf)))
    out.sort(key=lambda t: t.sort)
    return out


def latest(slug: str, kind: str, *, master: Path | None = None) -> Tag | None:
    tags = list_tags(slug, kind, master=master)
    return tags[-1] if tags else None


def _master(master: Path | None) -> Path:
    return require_repo(paths.repo_root() if master is None else Path(master), "master")


def _now(now: _dt.datetime | None) -> _dt.datetime:
    return now if now is not None else _dt.datetime.now()


def _write_tag(root: Path, name: str, sha: str, message: str) -> None:
    if commit_of(root, f"refs/tags/{name}"):
        raise ArmError(f"tag {name} already exists; a dated tag is written once (never force-moved)")
    git(root, "tag", "-a", name, "-m", message, sha)


# ------------------------------------------------------------------------------------------- arm

def arm(slug: str, *, master: Path | None = None, ref: str = "HEAD",
        now: _dt.datetime | None = None, message: str | None = None,
        allow_past_freeze: bool = False, log: bool = True, fence_check: bool = True) -> Tag:
    """Write a dated armed tag on the commit `ref` resolves to and return it.

    No `git tag -f`: the first arm of a day is `armed/<date>`, a re-arm the same day is
    `armed/<date>.2`, `.3`, ...  Arming is a no-op (returning the existing tag) only when the
    day's *latest* armed tag already points at the commit; re-arming an earlier commit (after a
    rollback, say) writes the next suffix so it becomes the latest. A hard freeze (see `freeze`)
    refuses an arm on any commit that is not the frozen commit unless `allow_past_freeze=True`,
    naming the freeze. Before any tag is written the process fence's real-process regression
    (`fence_selftest`) runs; a failure refuses the arm (`fence_check=False` skips it)."""
    root = _master(master)
    sha = _resolve(root, ref)

    fz = active_freeze(slug, master=root)
    if fz is not None and not allow_past_freeze and sha != fz.commit:
        raise ArmError(
            f"{slug} is frozen at {fz.commit[:12]} ({fz.name}); arming {sha[:12]} would ship code "
            f"past the freeze. Thaw it (`ctf release thaw {slug}`) or arm the frozen commit, or pass "
            f"--allow-past-freeze."
        )

    if fence_check:
        problems = fence_selftest()
        if problems:
            raise ArmError("the process fence failed its real-process regression, so arming is "
                           "refused (the opener could block on its own helpers): "
                           + "; ".join(problems))

    date = _now(now).strftime("%Y-%m-%d")
    same_day = [t for t in list_tags(slug, ARMED, master=root) if t.date == date]
    if same_day and same_day[-1].commit == sha:
        t = same_day[-1]
        if log:
            ledger.append("arm.noop", workdir=paths.workdir(slug), slug=slug,
                          commit=sha, tag=t.name)
        return t
    leaf = date if not same_day else f"{date}.{max(t.sort[1] for t in same_day) + 1}"
    name = f"{_ns(slug, ARMED)}{leaf}"
    _write_tag(root, name, sha, message or f"{slug}: armed for release on {leaf}")
    if log:
        ledger.append("arm.write", workdir=paths.workdir(slug), slug=slug, commit=sha, tag=name)
    return Tag(slug, ARMED, leaf, name, sha, _leaf_sort(ARMED, leaf))


def latest_armed(slug: str, *, master: Path | None = None) -> Tag | None:
    return latest(slug, ARMED, master=master)


# ----------------------------------------------------------------------------------------- lag

@dataclass(frozen=True)
class Lag:
    """How the latest armed tag stands against a release ref."""
    slug: str
    armed: Tag | None
    head_commit: str | None
    behind: int                 # commits the release ref is ahead of the armed commit
    files: tuple[str, ...]      # paths that differ (armed..head), sorted
    state: str                  # armed | lagging | ahead | diverged | not-armed
    detail: str

    @property
    def is_lagging(self) -> bool:
        """True whenever the armed tag does not already describe the release ref (so a release
        gate should stop and make the operator look)."""
        return self.state != "armed"


def lag(slug: str, *, master: Path | None = None, head: str = "HEAD") -> Lag:
    """Compare the latest armed tag with `head` (the commit that would ship)."""
    root = _master(master)
    arm_tag = latest_armed(slug, master=root)
    head_sha = _resolve(root, head)
    if arm_tag is None:
        return Lag(slug, None, head_sha, 0, (), "not-armed",
                   f"{slug} has no armed tag: run `ctf release {slug}` before release")
    if arm_tag.commit == head_sha:
        return Lag(slug, arm_tag, head_sha, 0, (), "armed",
                   f"armed tag {arm_tag.leaf} is {head}")
    files = tuple(sorted(_diff_names(root, arm_tag.commit, head_sha)))
    if is_ancestor(root, arm_tag.commit, head_sha):
        n = _count(root, arm_tag.commit, head_sha)
        return Lag(slug, arm_tag, head_sha, n, files, "lagging",
                   f"{head} is {n} commit(s) and {len(files)} file(s) ahead of armed tag "
                   f"{arm_tag.leaf}: re-arm before release")
    if is_ancestor(root, head_sha, arm_tag.commit):
        n = _count(root, head_sha, arm_tag.commit)
        return Lag(slug, arm_tag, head_sha, 0, files, "ahead",
                   f"armed tag {arm_tag.leaf} is {n} commit(s) AHEAD of {head}: "
                   f"the release ref is behind what was armed")
    return Lag(slug, arm_tag, head_sha, 0, files, "diverged",
               f"armed tag {arm_tag.leaf} and {head} have diverged "
               f"({len(files)} file(s) differ): re-arm the release ref")


def _diff_names(root: Path, a: str, b: str) -> list[str]:
    out = git(root, "diff", "--name-only", "--no-renames", a, b)
    return [p for p in out.splitlines() if p]


def _count(root: Path, a: str, b: str) -> int:
    out = git(root, "rev-list", "--count", f"{a}..{b}")
    return int(out.strip() or "0")


# --------------------------------------------------------------------------------- freeze / green

def worktree_dirty(root: Path) -> list[str]:
    """Paths with uncommitted changes in the checkout at `root` (tracked edits, staged changes and
    untracked files; ignored files excluded). Empty when the working tree is exactly HEAD."""
    out = git(_master(root), "status", "--porcelain=v1", "--untracked-files=all")
    return [ln[3:] for ln in out.splitlines() if ln.strip()]


def mark_green(slug: str, *, master: Path | None = None, ref: str = "HEAD",
               now: _dt.datetime | None = None, log: bool = True,
               require_clean: bool = False, note: str = "") -> Tag:
    """Record that `ref` is a green commit (a rollback target) and return the green tag.

    `ctf gate run --mark-green SLUG` calls this after a green run with `require_clean=True`: a green
    run on a dirty tree does not describe HEAD, so it is refused naming the dirty paths. Tags are
    never force-moved, so the history of green commits is kept; marking the commit the latest green
    tag already points at is a no-op returning that tag (two fast green runs on one commit do not
    collide), and a second green in the same second on another commit gets a `.<n>` suffix."""
    root = _master(master)
    sha = _resolve(root, ref)
    if require_clean:
        dirty = worktree_dirty(root)
        if dirty:
            shown = ", ".join(dirty[:5]) + (f" (+{len(dirty) - 5} more)" if len(dirty) > 5 else "")
            raise ArmError(f"cannot mark {sha[:12]} green for {slug}: the working tree has "
                           f"uncommitted changes ({shown}), so the green run does not describe it")
    cur = latest(slug, GREEN, master=root)
    if cur is not None and cur.commit == sha:
        if log:
            ledger.append("arm.green.noop", workdir=paths.workdir(slug), slug=slug, commit=sha,
                          tag=cur.name)
        return cur
    msg = f"{slug}: green gate at {ref}" + (f" ({note})" if note else "")
    return _stamp(slug, GREEN, root=root, sha=sha, now=now, log=log, message=msg,
                  event="arm.green")


def freeze(slug: str, *, master: Path | None = None, ref: str = "HEAD",
           now: _dt.datetime | None = None, log: bool = True) -> Tag:
    """Start a hard code freeze at `ref`. While it is active, `arm` refuses any other commit."""
    root = _master(master)
    return _stamp(slug, FREEZE, root=root, sha=_resolve(root, ref), now=now, log=log,
                  message=f"{slug}: code freeze at {ref}", event="arm.freeze", order_with=(THAW,))


def thaw(slug: str, *, master: Path | None = None, now: _dt.datetime | None = None,
         log: bool = True) -> Tag:
    """Lift the active freeze. Refuses when nothing is frozen."""
    root = _master(master)
    if active_freeze(slug, master=root) is None:
        raise ArmError(f"{slug} is not frozen (no freeze tag, or it is already thawed)")
    return _stamp(slug, THAW, root=root, sha=_resolve(root, "HEAD"), now=now, log=log,
                  message=f"{slug}: freeze lifted", event="arm.thaw", order_with=(FREEZE,))


def _stamp(slug: str, kind: str, *, root: Path, sha: str, now: _dt.datetime | None, log: bool,
           message: str, event: str, order_with: tuple[str, ...] = ()) -> Tag:
    """Write `<kind>/<timestamp>` on `sha`. A leaf already taken this second (in `kind` or in any
    namespace of `order_with`, which shares the suffix sequence) gets the next `.<n>`."""
    ts = _now(now).strftime("%Y-%m-%dT%H-%M-%S")
    taken = [t.sort[1] for k in (kind, *order_with) for t in list_tags(slug, k, master=root)
             if t.sort[0] == ts]
    leaf = ts if not taken else f"{ts}.{max(taken) + 1}"
    name = f"{_ns(slug, kind)}{leaf}"
    _write_tag(root, name, sha, message)
    if log:
        ledger.append(event, workdir=paths.workdir(slug), slug=slug, commit=sha, tag=name)
    return Tag(slug, kind, leaf, name, sha, _leaf_sort(kind, leaf))


def active_freeze(slug: str, *, master: Path | None = None) -> Tag | None:
    """The freeze in force: the latest freeze tag with no thaw tag made at or after it, else None."""
    root = _master(master)
    fz = latest(slug, FREEZE, master=root)
    if fz is None:
        return None
    th = latest(slug, THAW, master=root)
    if th is not None and th.sort >= fz.sort:
        return None
    return fz


def last_green(slug: str, *, master: Path | None = None) -> Tag | None:
    return latest(slug, GREEN, master=master)


def rollback_target(slug: str, *, master: Path | None = None) -> Tag:
    """The commit the operator should roll back to: the last green tag. Refuses (loudly, never a
    silent fallback) when no green commit was ever marked."""
    t = last_green(slug, master=master)
    if t is None:
        raise ArmError(f"{slug} has no green tag: nothing to roll back to "
                       f"(a green gate run marks one: `ctf gate run ... --mark-green {slug}`, "
                       f"or by hand `ctf release green {slug}`)")
    return t


# ------------------------------------------------------------------ process-identity fence
#
# The Day-29 fault: the release-host fence listed "other" processes and waited for them, but the
# opener's own *detached* helpers (new session leaders, as tools/process_group.spawn makes every
# owned helper) were counted as foreign, so the opener waited on itself; every rerun left another
# orphaned helper behind. Ownership is therefore decided by lineage and by an explicit owned-process
# registry, never by session: a detached helper is still our descendant while its spawner lives, and
# an orphaned one (spawner exited, reparented to init) is ours only if its spawner registered it.

def _psutil():
    try:
        import psutil
    except ImportError as e:
        raise ArmInputError("psutil is not installed in this Python: the process fence reads the "
                            "process table with it (pinned in requirements.in)") from e
    return psutil


_CT_TOLERANCE = 1e-3   # seconds; psutil create_time is stable for one process


@dataclass(frozen=True)
class OwnedRecord:
    """One registered owned process: its pid, its process group, and its create time (the
    identity that tells it from a later process that reused the pid)."""
    pid: int
    pgid: int
    create_time: float
    label: str = ""


class OwnedRegistry:
    """A folder of owned-process records, one `<pid>.json` each, written by whoever spawns a helper
    that may outlive it (`register(proc)` right after `tools.process_group.spawn`, with the
    OwnedProcess, a Popen or a pid). `classify(..., registry=)` then counts that helper, its process
    group and its descendants as ours even after the spawner has exited, for as long as the group
    has a member. A record whose pid now names another process (create time differs) is ignored; a
    record whose process and group are both gone is expired (deleted) by `classify`;
    `forget(pid)` drops a record."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def register(self, proc, label: str = "") -> OwnedRecord:
        pid = proc if isinstance(proc, int) else getattr(proc, "pid", None)
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise ArmInputError(f"cannot register {proc!r} as an owned process: no pid")
        ps = _psutil()
        try:
            ct = ps.Process(pid).create_time()
            pg = os.getpgid(pid)
        except (ps.NoSuchProcess, ProcessLookupError):
            raise ArmError(f"pid {pid} is not running: it cannot be registered as owned") from None
        rec = OwnedRecord(pid, pg, ct, label)
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / f".{pid}.json.tmp"
        tmp.write_text(json.dumps(rec.__dict__), encoding="utf-8")
        os.replace(tmp, self.root / f"{pid}.json")
        return rec

    def forget(self, pid: int) -> bool:
        p = self.root / f"{int(pid)}.json"
        if p.exists():
            p.unlink()
            return True
        return False

    def expire(self, rec: OwnedRecord) -> bool:
        """Drop `rec` because its process and its whole group are gone (classify calls this): its
        group id may now be reused by unrelated work. Only the exact record is dropped: a record
        rewritten since (another registration of a reused pid) is kept."""
        p = self.root / f"{rec.pid}.json"
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        if int(d.get("pgid", -1)) != rec.pgid or not _same(float(d.get("create_time", 0.0)),
                                                         rec.create_time):
            return False
        try:
            p.unlink()
        except FileNotFoundError:
            return False
        return True

    def records(self) -> list[OwnedRecord]:
        if not self.root.is_dir():
            return []
        out = []
        for p in sorted(self.root.glob("*.json")):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
                out.append(OwnedRecord(int(d["pid"]), int(d["pgid"]), float(d["create_time"]),
                                       str(d.get("label", ""))))
            except (OSError, ValueError, KeyError, TypeError) as e:
                raise ArmError(f"owned-process record {p} is unreadable ({type(e).__name__}): "
                               f"fix or remove it; the fence will not guess ownership") from None
        return out


@dataclass(frozen=True)
class FenceVerdict:
    """Which of a set of pids this process owns and which are foreign. A wait or a signal 'for all
    the other work on this host' must target only `foreign`: waiting on one of ours is the Day-29
    self-block. `why` gives each pid's reason: self, ancestor, descendant, own-group, registered,
    registered-group, foreign, gone or zombie."""
    own_pid: int
    own_pgid: int
    ours: tuple[int, ...]
    foreign: tuple[int, ...]
    missing: tuple[int, ...]
    why: dict = field(default_factory=dict, compare=False)

    def safe_to_wait(self) -> tuple[int, ...]:
        """The pids a 'wait for the other work' loop may block on: foreign and still alive."""
        return self.foreign


def _same(ct_a: float, ct_b: float) -> bool:
    return abs(ct_a - ct_b) < _CT_TOLERANCE


def group_alive(pgid: int) -> bool:
    """Does process group `pgid` still have a member (zombies included: their pid, and so the group
    id, is still allocated)? `killpg(pgid, 0)` sends nothing; EPERM means members exist that we may
    not signal."""
    if pgid <= 0:
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _owned_sets(registry: OwnedRegistry | None, ps) -> tuple[dict[int, float], set[int]]:
    """(registered live pids -> create time, registered process groups). A record whose pid now
    names a different process is stale and ignored entirely. A record whose leader has exited
    still owns its group while the group has a member (a process-group id is not reused while any
    member is alive); once the group is empty the record is expired, i.e. deleted from the
    registry, so a later, unrelated group that reuses the id is never counted as ours."""
    nodes: dict[int, float] = {}
    groups: set[int] = set()
    for rec in (registry.records() if registry is not None else []):
        try:
            ct = ps.Process(rec.pid).create_time()
        except ps.NoSuchProcess:
            if group_alive(rec.pgid):
                groups.add(rec.pgid)      # leader gone: its surviving group members are still ours
            else:
                registry.expire(rec)      # leader and group gone: the pgid is free for reuse
            continue
        if _same(ct, rec.create_time):
            nodes[rec.pid] = ct
            groups.add(rec.pgid)
    return nodes, groups


def classify(pids: Iterable[int], *, registry: OwnedRegistry | None = None) -> FenceVerdict:
    """Partition `pids` into ours, foreign and missing.

    A pid is ours when it is this process; one of its ancestors (waiting on a parent deadlocks);
    a descendant at any depth, detached or not (the ppid chain reaches us); in our process group;
    or, with `registry`, a registered owned process, a descendant of one, or in a registered
    process group. Shared *session* is deliberately not ownership: a terminal or harness session
    holds unrelated jobs, and an orphaned helper of ours must be registered to count. A pid that
    no longer runs, or is a zombie (exited, unreaped), is missing."""
    ps = _psutil()
    me = os.getpid()
    pg = os.getpgrp()
    try:
        ancestors = {a.pid for a in ps.Process(me).parents()}
    except ps.Error:
        ancestors = {os.getppid()}
    reg_nodes, reg_groups = _owned_sets(registry, ps)

    ours: list[int] = []
    foreign: list[int] = []
    missing: list[int] = []
    why: dict[int, str] = {}

    def put(pid: int, bucket: list, reason: str) -> None:
        bucket.append(pid)
        why[pid] = reason

    for pid in dict.fromkeys(int(p) for p in pids):   # de-dupe, keep order
        if pid == me:
            put(pid, ours, "self")
            continue
        if pid <= 0:
            put(pid, missing, "gone")
            continue
        try:
            proc = ps.Process(pid)
            if proc.status() == ps.STATUS_ZOMBIE:
                put(pid, missing, "zombie")
                continue
            chain = proc.parents()
            pgid = os.getpgid(pid)
        except (ps.NoSuchProcess, ProcessLookupError):
            put(pid, missing, "gone")
            continue
        except (ps.AccessDenied, PermissionError):
            put(pid, foreign, "foreign")       # cannot be read, so it cannot be shown to be ours
            continue
        if pid in ancestors:
            put(pid, ours, "ancestor")
        elif any(a.pid == me for a in chain):
            put(pid, ours, "descendant")
        elif pgid == pg:
            put(pid, ours, "own-group")
        elif _registered(proc, chain, reg_nodes, ps):
            put(pid, ours, "registered")
        elif pgid in reg_groups:
            put(pid, ours, "registered-group")
        else:
            put(pid, foreign, "foreign")
    return FenceVerdict(me, pg, tuple(ours), tuple(foreign), tuple(missing), why)


def _registered(proc, chain, reg_nodes: dict[int, float], ps) -> bool:
    """Is `proc`, or any ancestor of it, a registered owned process (pid and create time match)?"""
    for node in (proc, *chain):
        ct = reg_nodes.get(node.pid)
        if ct is None:
            continue
        try:
            if _same(node.create_time(), ct):
                return True
        except ps.Error:
            continue
    return False


def _tool(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise ArmInputError(f"{name} is not on PATH: the fence regression needs it to start its "
                            f"synthetic helper processes")
    return found


def fence_selftest() -> list[str]:
    """The real-process fence regression `arm` runs before every arm (the Day-29 retro asks for it).

    It starts, from this process: a detached child (a new session leader, as
    tools/process_group.spawn makes every helper), which must be ours; and, through a shell that
    then exits, an orphan in our session but in another process group, which must be foreign until
    it is registered, and ours once it is. Returns the problems found ([] when the fence is right);
    every helper it started is killed before it returns."""
    ps = _psutil()
    sh, sleep = _tool("sh"), _tool("sleep")
    problems: list[str] = []
    quiet = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    detached = subprocess.Popen([sleep, "30"], start_new_session=True, **quiet)
    orphan = None
    try:
        launcher = subprocess.Popen([sh, "-c", f"'{sleep}' 30 </dev/null >/dev/null 2>&1 & echo $!"],
                                    process_group=0, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        out, _ = launcher.communicate(timeout=10)
        orphan = ps.Process(int(out.strip()))   # anchors the orphan's identity for the kill below
        v = classify([detached.pid, orphan.pid])
        if detached.pid not in v.ours:
            problems.append(f"a detached (new-session) child was classified "
                            f"{v.why.get(detached.pid)}, not ours")
        if orphan.pid not in v.foreign:
            problems.append(f"an unregistered orphan in another process group was classified "
                            f"{v.why.get(orphan.pid)}, not foreign")
        with tempfile.TemporaryDirectory(prefix="ctf-fence-") as d:
            reg = OwnedRegistry(Path(d))
            reg.register(orphan.pid, label="fence-selftest")
            v2 = classify([orphan.pid], registry=reg)
            if orphan.pid not in v2.ours:
                problems.append(f"a registered orphaned helper was classified "
                                f"{v2.why.get(orphan.pid)}, not ours")
    except (subprocess.SubprocessError, ValueError, OSError, PromoteError, ps.Error) as e:
        problems.append(f"the fence regression could not run ({type(e).__name__}: {e})")
    finally:
        detached.kill()
        detached.wait()
        if orphan is not None:
            try:
                orphan.kill()                # psutil refuses if the pid was reused meanwhile
            except ps.Error:
                pass
    return problems


# ------------------------------------------------------------------- arm report: unwired modules

@dataclass(frozen=True)
class Unwired:
    module: str                 # dotted name, e.g. ctf.foo
    path: str                   # repo-relative posix path
    reason: str


# Modules that are reached by name or by the harness, not by an `import` we can see, so a zero
# import count is expected and not a defect.
_ENTRYPOINT_BASENAMES = frozenset({"__init__", "__main__", "conftest"})
_SKIP_DIRS = frozenset({"__pycache__", "node_modules"})
# A test tree is not a caller: every built item ships a test that imports it, so counting tests would
# make a module only its own test imports look wired, which is exactly the fault the report exists for.
_TEST_DIRS = frozenset({"tests", "test"})


def is_test_file(root: Path, pyfile: Path) -> bool:
    """A test file: under a `tests`/`test` folder (relative to `root`), a `conftest.py`, or named
    `test_*.py` / `*_test.py`."""
    rel = pyfile.relative_to(root)
    name = rel.name
    return (any(part in _TEST_DIRS for part in rel.parts[:-1]) or name == "conftest.py"
            or name.startswith("test_") or name.endswith("_test.py"))


def _module_name(root: Path, pyfile: Path) -> str:
    rel = pyfile.relative_to(root).with_suffix("")
    parts = list(rel.parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _is_entrypoint(module: str, package: str) -> bool:
    leaf = module.rsplit(".", 1)[-1]
    if leaf in _ENTRYPOINT_BASENAMES or leaf.startswith("_") or leaf.startswith("test_"):
        return True
    # CLI command modules (package.cli.<name>) are discovered by directory scan, not imported.
    return f"{package}.cli." in (module + ".")


def _walk_py(root: Path) -> list[Path]:
    """Every .py under `root`, skipping hidden folders (.git, .venv, .claude, ...), __pycache__
    and node_modules."""
    out: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith(".") and d not in _SKIP_DIRS)
        out.extend(Path(dirpath) / f for f in sorted(filenames) if f.endswith(".py"))
    return out


def _docstring_nodes(tree: ast.AST) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                ids.add(id(body[0].value))
    return ids


def imported_names(text: str, module: str, is_package: bool) -> tuple[set[str], list[str]] | None:
    """What a source file imports, resolved with `ast`: (dotted names it imports, its non-docstring
    string constants). `module` is the file's own dotted name, used to resolve relative imports
    (`from . import x`, `from .. import x`, `from ..pkg import x`). Every `from B import n` adds both
    `B` and `B.n` (n may be a submodule). None when the file does not parse."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    own = module.split(".") if module else []
    pkg = own if is_package else own[:-1]
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                up = node.level - 1
                if up > len(pkg):
                    continue                      # beyond the top package: not resolvable
                base_parts = pkg[:len(pkg) - up] + (node.module.split(".") if node.module else [])
            else:
                base_parts = node.module.split(".") if node.module else []
            base = ".".join(base_parts)
            if base:
                names.add(base)
            for a in node.names:
                if a.name != "*":
                    names.add(f"{base}.{a.name}" if base else a.name)
    docs = _docstring_nodes(tree)
    strings = [n.value for n in ast.walk(tree)
               if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]
    return names, strings


def pytest_plugins(text: str) -> set[str]:
    """The dotted names a conftest registers with a module-level `pytest_plugins = "x"` or
    `pytest_plugins = ("x", "y")` / `[...]`. Empty when the file does not parse."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return set()
    out: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "pytest_plugins"
                                                for t in node.targets):
            v = node.value
            items = v.elts if isinstance(v, (ast.Tuple, ast.List)) else [v]
            out.update(e.value for e in items
                       if isinstance(e, ast.Constant) and isinstance(e.value, str))
    return out


def unwired(root: Path | None = None, *, package: str = "ctf",
            include_tests: bool = False) -> list[Unwired]:
    """Modules of `package` that nothing else in the tree imports — the arm report of 'built work
    left unwired' (the spec's zero-caller check). Entry points (`__init__`, `__main__`,
    `_`-prefixed, `test_*`, and the CLI command modules, all reached without an import we can see)
    are never reported.

    Test files (`is_test_file`: under `tests/` or `test/`, `conftest.py`, `test_*.py`, `*_test.py`)
    are not callers by default: a module only its own test imports is still unwired, since nothing
    that runs at an event reaches it. `include_tests=True` counts them (the old, looser report).
    A module naming itself (its own dotted name in a string, e.g. `logging.getLogger("ctf.x")`) does
    not count as its own caller. A module a `conftest.py` registers as a pytest plugin
    (`pytest_plugins = ("ctf.x",)`) is wired: pytest loads it by name, the way the CLI loads its
    command modules.

    Imports are resolved with `ast`, absolute and relative (`import a.b`, `from a import b`,
    `from . import b`, `from .. import b`, `from ..a import b`), relative to each file's package. A
    module named in a non-docstring string constant (`importlib.import_module("ctf.x")`,
    `[python, "-m", "ctf.x"]`) also counts as wired; a comment or docstring mention does not. A file
    that does not parse is searched textually for the absolute dotted name instead. Hidden folders
    (.venv, .git, ...) are not part of the tree."""
    r = (paths.repo_root() if root is None else Path(root)).resolve()
    pkg_dir = r / package.replace(".", "/")
    if not pkg_dir.is_dir():
        raise ArmInputError(f"no package {package!r} under {r}")

    tree = _walk_py(r)
    modules = {p: _module_name(r, p) for p in tree if pkg_dir in p.parents}
    corpus = tree if include_tests else [p for p in tree if not is_test_file(r, p)]

    # Each file's imports, once: (names, strings), or the raw text of a file that does not parse.
    parsed: dict[Path, tuple[set[str], list[str]] | str] = {}
    for p in corpus:
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        got = imported_names(text, _module_name(r, p), p.name == "__init__.py")
        parsed[p] = got if got is not None else text
    plugins: set[str] = set()
    if not include_tests:
        for p in tree:
            if p.name == "conftest.py":
                try:
                    plugins |= pytest_plugins(p.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue

    out: list[Unwired] = []
    for pyfile, module in modules.items():
        # A package's __init__ runs whenever any module under it is imported: never reported.
        if pyfile.name == "__init__.py" or _is_entrypoint(module, package):
            continue
        token = re.compile(rf"(?<![\w.]){re.escape(module)}(?!\w)")
        wired = module in plugins
        for src, got in parsed.items():
            if src == pyfile:
                continue
            if isinstance(got, str):
                hit = bool(token.search(got))
            else:
                names, strings = got
                hit = module in names or any(token.search(s) for s in strings)
            if hit:
                wired = True
                break
        if not wired:
            out.append(Unwired(module, pyfile.relative_to(r).as_posix(),
                               "no other .py in the tree imports this module" if include_tests else
                               "no other non-test .py in the tree imports this module"))
    return out
