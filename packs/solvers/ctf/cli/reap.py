"""ctf reap — the end-of-event reaper: dry run first, then the player confirms each exact id (B-175).

    python -m ctf reap [--workdir D | --jobs-dir D --sessions-dir D] [--no-processes]
                       [--repo DIR [--base REF] [--protect BRANCH]...] [--json]
        Dry run: list every running or lost job, every launcher session (live or stale), and, with
        --repo, every clean merged worktree and merged local branch, each under an exact id
        (job:<id>, session:<name>@<launcher pid>-<start ms>, worktree:<path>, branch:<name>), plus
        what is kept and why. A session id carries its launcher's identity: a name re-claimed after
        the dry run is a new id, and confirming the old one is refused as not in the plan.
        Nothing changes.

    python -m ctf reap [same options] --confirm ID [--confirm ID]... [--log FILE]
        Act on exactly those ids, each re-checked right before acting (pid + start time for a
        process, HEAD/sha and cleanliness for git). An id that is not in the current plan stops the
        run before anything is done. No wildcard and no "all": every id is named.

Process kills and deletions are privileged: an agent shows the dry run; the player runs --confirm.
Each action is appended to --log (default <workdir>/reaper.jsonl).
Exit: 0 ok (dry run, or every confirmed id done), 1 a confirmed id failed or was skipped,
2 usage or an unknown id (nothing done).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import jobs as _jobs
from .. import paths as _paths
from .. import reaper as _reaper
from .. import sessions as _sessions

HELP = "end-of-event reaper: list jobs, sessions, merged worktrees and branches; act only on --confirm IDs"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--workdir", type=Path, help="event workdir (default: $CTF_WORKDIR / the event's)")
    p.add_argument("--jobs-dir", dest="jobs_dir", type=Path, help="job records (default <workdir>/jobs)")
    p.add_argument("--sessions-dir", dest="sessions_dir", type=Path,
                   help="session records (default <workdir>/sessions)")
    p.add_argument("--no-processes", dest="no_processes", action="store_true",
                   help="only worktrees and branches (no event workdir needed)")
    p.add_argument("--repo", type=Path, help="git repo whose worktrees and branches to check")
    p.add_argument("--base", default="HEAD", help="merged means merged into this ref (default HEAD)")
    p.add_argument("--protect", action="append", default=[], metavar="BRANCH",
                   help="never delete this branch (repeatable; main, master, the base and the "
                        "current branch are always protected)")
    p.add_argument("--confirm", action="append", default=[], metavar="ID",
                   help="act on this exact id from the dry run (repeatable)")
    p.add_argument("--log", type=Path, help="action log (default <workdir>/reaper.jsonl)")
    p.add_argument("--json", action="store_true", help="print the plan as JSON")
    p.add_argument("--agent-grace", dest="agent_grace", type=float, default=_sessions.AGENT_GRACE,
                   help=argparse.SUPPRESS)
    p.add_argument("--launcher-grace", dest="launcher_grace", type=float,
                   default=_sessions.LAUNCHER_GRACE, help=argparse.SUPPRESS)


def _workdir(args) -> Path | None:
    if args.workdir:
        return args.workdir.expanduser().resolve()
    try:
        return _paths.workdir()
    except _event.EventError:
        return None


def _roots(args, workdir: Path | None) -> tuple[Path | None, Path | None]:
    if args.no_processes:
        return None, None
    if args.jobs_dir:
        jobs_root = args.jobs_dir.expanduser().resolve()
    elif args.workdir:
        jobs_root = workdir / "jobs"
    else:
        jobs_root = _jobs.jobs_root()            # $CTF_JOBS_DIR, else <workdir>/jobs; JobError if none
    if args.sessions_dir:
        sess_root = args.sessions_dir.expanduser().resolve()
    elif args.workdir:
        sess_root = workdir / "sessions"
    else:
        sess_root = _sessions.sessions_root()    # SessionError if none
    return jobs_root, sess_root


def run(args: argparse.Namespace) -> int:
    try:
        workdir = _workdir(args)
        jobs_root, sess_root = _roots(args, workdir)
        plan = _reaper.plan(jobs_root=jobs_root, sessions_root=sess_root, repo=args.repo,
                            base=args.base, protect=args.protect)
        if not args.confirm:
            if args.json:
                print(json.dumps(_reaper.to_json(plan), indent=1, default=str))
            else:
                sys.stdout.write(_reaper.render(plan))
                if plan.candidates:
                    print("dry run: nothing was changed. The player confirms each item by its exact id: "
                          "python -m ctf reap <same options> --confirm <id> [--confirm <id> ...]")
            return 0
        log = args.log or (workdir / "reaper.jsonl" if workdir else None)
        if log is None:
            raise _reaper.ReapError("no log location for the actions: pass --log FILE or --workdir, "
                                    "or set CTF_WORKDIR / CTF_EVENT")
        results = _reaper.execute(plan, args.confirm, log=log, agent_grace=args.agent_grace,
                                  launcher_grace=args.launcher_grace)
    except (_reaper.ReapError, _jobs.JobError, _sessions.SessionError) as e:
        print(f"ctf reap: {e}", file=sys.stderr)
        return 2
    for r in results:
        print(f"{r.outcome:7}  {r.id}  {r.detail}")
    print(f"logged to {log}")
    return 0 if all(r.outcome == "done" for r in results) else 1
