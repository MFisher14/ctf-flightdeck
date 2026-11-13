"""End-of-event reaper: exact PIDs and exact paths, dry run first, the player confirms each id (B-175).

After an event (or a build) the leftovers were cleaned by hand, late, or not at all: background
brutes still running, play-day sessions that never exited, dozens of finished worktrees and merged
branches. Blanket kills and bulk deletes were (rightly) refused mid-event. This reaper never acts in
bulk. It lists what it would do, each item under an exact id, and acts only on the ids the player
names with --confirm, re-checking each one right before acting:

    job:<job id>          a running job (stopped through its supervisor: TERM, then KILL, whole group)
                          or a lost one (its command stopped by exact pid + start time + pgid, or, when
                          the command is already gone, its record closed)
    session:<name>@<launcher pid>-<start ms>
                          a live launcher session (agent stopped by identity, then its launcher), or a
                          stale session record (removed, and only while it is still that stale claim).
                          The launcher identity is part of the id, so a name re-claimed after the dry
                          run is a different id and the old one is "not in the current plan"
    worktree:<path>       a linked git worktree that is clean (nothing staged, modified or untracked),
                          unlocked and whose HEAD is merged into the base; removed with
                          `git worktree remove` (never --force)
    branch:<name>         a local branch merged into the base, not protected and not checked out;
                          deleted with `git update-ref -d refs/heads/<name> <sha>`, which deletes it only
                          if it still points at the commit that was checked

Never touched: the main worktree, the worktree holding the current directory, a locked or dirty
worktree, an unmerged or protected branch (main, master, the base, the current branch, the
configured integration branch, every --protect), a remote, any process whose recorded identity no
longer matches (a reused pid), a lost job with no recorded identity.

    p = plan(jobs_root=..., sessions_root=..., repo=..., base="HEAD")
    print(render(p))
    results = execute(p, ["job:x", "branch:item/B-1"], log=workdir / "reaper.jsonl")

Each action is appended to the log (`reaper.jsonl`: ts, id, outcome, detail). Process kills and
deletions are privileged: the player runs --confirm; an agent shows the dry run.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from . import jobs as _jobs
from . import procid as _procid
from . import sessions as _sessions
from . import worktree as _wt

DEFAULT_PROTECTED = ("main", "master")
KIND_ORDER = ("session", "job", "worktree", "branch")


class ReapError(RuntimeError):
    """The reaper cannot proceed as asked (unknown id, unreadable state); nothing was changed."""


@dataclass
class Candidate:
    id: str
    kind: str
    action: str
    detail: str
    facts: dict = field(default_factory=dict)
    after: str | None = None          # another id that must succeed first (branch of a worktree)


@dataclass
class Kept:
    what: str
    reason: str


@dataclass
class Plan:
    candidates: list[Candidate] = field(default_factory=list)
    kept: list[Kept] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    jobs_root: Path | None = None
    sessions_root: Path | None = None
    repo: Path | None = None
    base: str | None = None
    base_sha: str | None = None
    protect: tuple[str, ...] = ()     # the --protect extras, re-applied when a branch is deleted

    def by_id(self) -> dict[str, Candidate]:
        return {c.id: c for c in self.candidates}


@dataclass
class Result:
    id: str
    outcome: str          # done | failed | skipped
    detail: str


# ------------------------------------------------------------------------------------ plan

def _owner_text(st: _jobs.JobState) -> str:
    owner = st.job.get("owner")
    if not owner:
        return "no owner"
    os_ = _jobs.owner_status(st)
    if os_ == "none":
        return f"owner {owner}"
    return f"owner {owner} ({'alive' if os_ == 'alive' else 'gone: orphan'})"


def _plan_jobs(p: Plan, root: Path) -> None:
    for st in _jobs.live_jobs(root):
        cmd = " ".join(st.job.get("argv", []))[:80]
        pid = st.job.get("pid")
        if st.state == "running":
            p.candidates.append(Candidate(
                f"job:{st.id}", "job",
                "stop the job: TERM to its supervisor, which stops the command's whole process group",
                f"running, pid {pid}, pgid {st.job.get('pgid', pid)}, {_owner_text(st)} :: {cmd}",
                {"pid": pid, "pid_start": st.job.get("pid_start"),
                 "supervisor_pid": st.job.get("supervisor_pid")}))
            continue
        cs = _jobs.command_status(st)
        if cs == "unknown":
            p.kept.append(Kept(f"job:{st.id}", f"lost, and no start time is recorded for pid {pid}: "
                                               "its identity cannot be proved, so it is not signalled"))
        elif cs == "alive":
            p.candidates.append(Candidate(
                f"job:{st.id}", "job",
                "stop the lost job's process group by exact identity (pid + start time + pgid)",
                f"lost (supervisor gone), command pid {pid} still running, {_owner_text(st)} :: {cmd}",
                {"pid": pid, "pid_start": st.job.get("pid_start"), "pgid": st.job.get("pgid")}))
        else:
            p.candidates.append(Candidate(
                f"job:{st.id}", "job", "close the lost job's record (its command is already gone)",
                f"lost, command pid {pid} {cs} :: {cmd}", {"pid": pid}))


def _plan_sessions(p: Plan, root: Path) -> None:
    for s in _sessions.list_sessions(root):
        r = s.record
        who = f"{r.get('harness')} challenge {r.get('challenge')}"
        # The id names this claim (launcher pid + start), not just the name: a confirm run plans
        # afresh, so a name re-claimed after the dry run must not match the id the player read.
        sid = _sessions.reap_id(s.name, r)
        facts = {"name": s.name, "status": s.status,
                 **{k: r.get(k) for k in ("launcher_pid", "launcher_start", "agent_pid", "agent_start")}}
        if s.status == "live":
            p.candidates.append(Candidate(
                sid, "session",
                "stop the session: TERM/KILL the agent by identity, then its launcher",
                f"live ({who}): launcher pid {r.get('launcher_pid')} {s.launcher}, agent pid "
                f"{r.get('agent_pid')} {s.agent}", facts))
        else:
            p.candidates.append(Candidate(
                sid, "session", "remove the stale session record (nothing in it runs)",
                f"stale ({who}): launcher pid {r.get('launcher_pid')} {s.launcher}, agent {s.agent}",
                facts))


def _git_ok(repo: Path, *argv: str) -> bool:
    return _wt.git(repo, *argv, check=False).returncode == 0


def _resolve(repo: Path, ref: str) -> str:
    cp = _wt.git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", check=False)
    if cp.returncode != 0:
        raise ReapError(f"base {ref!r} is not a commit in {repo}")
    return cp.stdout.strip()


def _merged(repo: Path, sha: str, base_sha: str) -> bool:
    return _git_ok(repo, "merge-base", "--is-ancestor", sha, base_sha)


def _dirty(path: Path) -> bool:
    cp = _wt.git(path, "status", "--porcelain", "--untracked-files=all", check=False)
    return cp.returncode != 0 or bool(cp.stdout.strip())


def _inside(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def protected_branches(repo: Path, base: str, extra: Iterable[str] = ()) -> set[str]:
    out = set(DEFAULT_PROTECTED) | set(extra)
    out.add(base)
    cur = _wt.current_branch(repo)
    if cur != "HEAD":
        out.add(cur)
    try:
        out.add(_wt.integration_branch_name(repo=repo))
    except _wt.WorktreeError:
        pass        # no integration branch configured: nothing extra to protect
    return out


def _plan_git(p: Plan, repo: Path, base: str, protect: Sequence[str], here: Path) -> None:
    top = _wt._toplevel(repo)
    p.repo = top
    p.base = base
    p.protect = tuple(protect)
    p.base_sha = _resolve(top, base)
    wts = _wt.list_worktrees(top)
    main = wts[0].path if wts else top
    wt_cand: dict[str, str] = {}            # branch -> worktree candidate id
    checked_out: dict[str, Path] = {}
    for w in wts:
        if w.branch:
            checked_out[w.branch] = w.path
        if w.path == main or w.bare:
            continue
        wid = f"worktree:{w.path}"
        if _inside(here, w.path):
            p.kept.append(Kept(wid, "the current directory is inside it"))
        elif w.locked:
            p.kept.append(Kept(wid, "locked (git worktree unlock first, if it is really done)"))
        elif not w.path.is_dir():
            p.kept.append(Kept(wid, "missing on disk (git worktree prune clears the entry)"))
        elif _dirty(w.path):
            p.kept.append(Kept(wid, "has staged, modified or untracked files"))
        elif not w.head or not _merged(top, w.head, p.base_sha):
            p.kept.append(Kept(wid, f"HEAD {w.head[:12]} is not merged into {base}"))
        else:
            p.candidates.append(Candidate(
                wid, "worktree", "git worktree remove (no --force)",
                f"clean, HEAD {w.head[:12]} merged into {base}, branch {w.branch or '(detached)'}",
                {"path": str(w.path), "head": w.head, "branch": w.branch}))
            if w.branch:
                wt_cand[w.branch] = wid

    prot = protected_branches(top, base, protect)
    refs = _wt.git(top, "for-each-ref", "--format=%(refname:short) %(objectname)", "refs/heads").stdout
    unmerged = 0
    for line in refs.splitlines():
        name, _, sha = line.strip().rpartition(" ")
        if not name:
            continue
        bid = f"branch:{name}"
        if name in prot:
            if _merged(top, sha, p.base_sha) and name != base:
                p.kept.append(Kept(bid, "protected"))
            continue
        if not _merged(top, sha, p.base_sha):
            unmerged += 1
            continue
        after = None
        if name in checked_out:
            after = wt_cand.get(name)
            if after is None:
                p.kept.append(Kept(bid, f"merged, but checked out at {checked_out[name]} (kept)"))
                continue
        p.candidates.append(Candidate(
            bid, "branch", f"delete the local branch only if it still points at {sha[:12]}",
            f"merged into {base}" + (f"; after {after}" if after else ""),
            {"name": name, "sha": sha}, after=after))
    if unmerged:
        p.notes.append(f"{unmerged} local branch(es) not merged into {base}: kept")
    p.notes.append("remote branches are never touched; delete merged ones on the remote by hand")


def plan(*, jobs_root: Path | None = None, sessions_root: Path | None = None, repo: Path | None = None,
         base: str = "HEAD", protect: Sequence[str] = (), here: Path | None = None) -> Plan:
    """What the reaper would do. Changes nothing."""
    p = Plan(jobs_root=jobs_root, sessions_root=sessions_root)
    if jobs_root is not None:
        _plan_jobs(p, Path(jobs_root))
    else:
        p.notes.append("jobs: not checked (no jobs folder given)")
    if sessions_root is not None:
        _plan_sessions(p, Path(sessions_root))
    else:
        p.notes.append("sessions: not checked (no sessions folder given)")
    if repo is not None:
        try:
            _plan_git(p, Path(repo), base, protect, Path(here or Path.cwd()))
        except _wt.WorktreeError as e:
            raise ReapError(str(e)) from None
    else:
        p.notes.append("worktrees and branches: not checked (no --repo given)")
    p.candidates.sort(key=lambda c: (KIND_ORDER.index(c.kind), c.id))
    return p


def render(p: Plan) -> str:
    out = []
    if p.repo is not None:
        out.append(f"repo {p.repo}, base {p.base} ({(p.base_sha or '')[:12]})")
    if p.candidates:
        out.append(f"{len(p.candidates)} item(s) the reaper can act on (each only with --confirm <id>):")
        for c in p.candidates:
            out.append(f"  {c.id}")
            out.append(f"      {c.detail}")
            out.append(f"      on confirm: {c.action}")
    else:
        out.append("nothing to reap")
    if p.kept:
        out.append(f"{len(p.kept)} item(s) kept:")
        out.extend(f"  {k.what}: {k.reason}" for k in p.kept)
    out.extend(f"note: {n}" for n in p.notes)
    return "\n".join(out) + "\n"


def to_json(p: Plan) -> dict:
    return {"repo": str(p.repo) if p.repo else None, "base": p.base, "base_sha": p.base_sha,
            "candidates": [asdict(c) for c in p.candidates], "kept": [asdict(k) for k in p.kept],
            "notes": list(p.notes)}


# ------------------------------------------------------------------------------------ execute

def _log(log: Path | None, r: Result) -> None:
    if log is None:
        return
    log.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": time.time(), "id": r.id, "outcome": r.outcome, "detail": r.detail},
                      separators=(",", ":")) + "\n"
    fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)


def _do_job(p: Plan, c: Candidate) -> str:
    d = _jobs.job_dir(p.jobs_root, c.id.split(":", 1)[1])
    st = _jobs.state(d)
    if st.state == "running":
        end = _jobs.kill(d)
    elif st.state == "lost":
        end = _jobs.kill_lost(d, by="reaper")
    else:
        return f"already ended ({_jobs.describe(st)})"
    return _jobs.describe(end)


def _do_session(p: Plan, c: Candidate, *, agent_grace: float, launcher_grace: float) -> str:
    """A stale candidate only ever removes the record, and only while it is still that same stale
    claim; a live candidate stops only the launcher identity that was planned."""
    name = c.facts["name"]
    planned = c.facts
    if planned["status"] == "stale":
        with _sessions._locked(p.sessions_root, name):
            again = _sessions.session_state(p.sessions_root, name)
            if not _sessions.same_stale_record(again.record, planned):
                raise ReapError(f"session {name!r} was re-claimed by launcher pid "
                                f"{again.record.get('launcher_pid')} since the plan; not touched")
            if again.status != "stale":
                raise ReapError(f"session {name!r} came back to life; not removed")
            again.path.unlink()
        return "stale record removed"
    s = _sessions.stop(p.sessions_root, name, agent_grace=agent_grace, launcher_grace=launcher_grace,
                       expect=planned)
    return f"agent {s.agent}, launcher {s.launcher}, record {'removed' if s.removed else 'kept'}"


def _do_worktree(p: Plan, c: Candidate) -> str:
    path = Path(c.facts["path"])
    now = {w.path: w for w in _wt.list_worktrees(p.repo)}
    w = now.get(path)
    if w is None:
        raise ReapError(f"{path} is no longer a worktree of {p.repo}")
    if w.head != c.facts["head"]:
        raise ReapError(f"{path}: HEAD moved since the plan ({c.facts['head'][:12]} -> {w.head[:12]})")
    if w.locked:
        raise ReapError(f"{path} is locked")
    if _dirty(path):
        raise ReapError(f"{path} has staged, modified or untracked files")
    if not _merged(p.repo, w.head, p.base_sha):
        raise ReapError(f"{path}: HEAD is not merged into {p.base}")
    cp = _wt.git(p.repo, "worktree", "remove", str(path), check=False)
    if cp.returncode != 0:
        raise ReapError(f"git worktree remove {path}: {(cp.stderr or cp.stdout).strip()}")
    return f"removed {path}"


def _do_branch(p: Plan, c: Candidate) -> str:
    name, sha = c.facts["name"], c.facts["sha"]
    # re-checked now, with the plan's --protect extras: a branch can become protected after the plan
    # (checked out as the current branch, configured as the integration branch)
    if name in protected_branches(p.repo, p.base or "HEAD", p.protect):
        raise ReapError(f"branch {name} is protected")
    for w in _wt.list_worktrees(p.repo):
        if w.branch == name:
            raise ReapError(f"branch {name} is checked out at {w.path}")
    if not _merged(p.repo, sha, p.base_sha):
        raise ReapError(f"branch {name} ({sha[:12]}) is not merged into {p.base}")
    cp = _wt.git(p.repo, "update-ref", "-d", f"refs/heads/{name}", sha, check=False)
    if cp.returncode != 0:
        raise ReapError(f"branch {name} was not deleted (it moved, or git refused): "
                        f"{(cp.stderr or cp.stdout).strip()}")
    _wt.git(p.repo, "config", "--remove-section", f"branch.{name}", check=False)  # absent is fine
    return f"deleted {name} (was {sha[:12]})"


def execute(p: Plan, ids: Sequence[str], *, log: Path | None, agent_grace: float = _sessions.AGENT_GRACE,
            launcher_grace: float = _sessions.LAUNCHER_GRACE) -> list[Result]:
    """Act on exactly `ids`, each of which must be a candidate of `p` (else ReapError, nothing done).
    Order: sessions, jobs, worktrees, branches; a branch whose worktree did not go is skipped."""
    ids = list(dict.fromkeys(ids))
    if not ids:
        raise ReapError("no id confirmed; nothing to do")
    table = p.by_id()
    unknown = [i for i in ids if i not in table]
    if unknown:
        raise ReapError(f"not in the current plan (run the dry run again): {', '.join(unknown)}")
    chosen = sorted((table[i] for i in ids), key=lambda c: (KIND_ORDER.index(c.kind), c.id))
    done: set[str] = set()
    results: list[Result] = []
    for c in chosen:
        if c.after is not None and c.after not in done:
            r = Result(c.id, "skipped", f"needs {c.after} first (confirm it too)")
        else:
            try:
                if c.kind == "job":
                    detail = _do_job(p, c)
                elif c.kind == "session":
                    detail = _do_session(p, c, agent_grace=agent_grace, launcher_grace=launcher_grace)
                elif c.kind == "worktree":
                    detail = _do_worktree(p, c)
                else:
                    detail = _do_branch(p, c)
                r = Result(c.id, "done", detail)
                done.add(c.id)
            except (ReapError, _jobs.JobError, _sessions.SessionError, _procid.ProcIdError,
                    _wt.WorktreeError) as e:
                r = Result(c.id, "failed", str(e))
        _log(log, r)
        results.append(r)
    return results
