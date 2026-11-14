"""ctf job — run a long command detached and wait for it with no model turn (B-144).

    python -m ctf job start [--name N] [--cwd D] [--on-exit CMD] -- CMD ARGS...   returns at once
    python -m ctf job wait  ID... [--timeout S] [--any] [--tail N]   blocks until the job(s) end
    python -m ctf job run   [start options] [--timeout S] [--tail N] -- CMD ARGS...   start + wait
    python -m ctf job status [ID...] [--limit N]                    running / exited rc / lost
    python -m ctf job tail  ID [-n N]                               the end of the output, bounded
    python -m ctf job kill  ID                                      stop the job and its children
    python -m ctf job prune --older-than AGE [--dry-run]           remove ended jobs' folders
    python -m ctf job list  [--owner O] [--live] [--json]            the named-job registry (B-175)
    python -m ctf job stop  ID|NAME                                  kill, by id or live job name
    python -m ctf job reap  --owner O [--dry-run]                    stop every live job O owns

Every subcommand takes --jobs-dir (default $CTF_JOBS_DIR, else <event workdir>/jobs). ID may be
`last`. `wait` and `run` print the wake message (exit status, output path, the last lines) and exit
0 when every job exited 0, 1 when one failed, 2 on an error (unknown job, lost supervisor, failed
start), 124 when --timeout passed with the job still running (it keeps running; wait again).

--on-exit CMD (one shell-quoted string, run without a shell) runs once when the job ends, with the
wake message on stdin and CTF_JOB_ID / CTF_JOB_RC / CTF_JOB_LOG / CTF_JOB_DIR / CTF_JOB_SUMMARY set:
the way to wake an agent that ended its turn instead of blocking in `wait`.

Named jobs (B-175): --owner O (default $CTF_JOB_OWNER, set by the agent launchers) records who owns
the job, with the owner's exact identity (pid + start time, $CTF_JOB_OWNER_PID); the launcher reaps
its agent's jobs when the agent exits. --exclusive refuses a second live job of the same --name.
Every stop checks the recorded pid + start time first: a reused pid is never signalled. The
end-of-event cleanup of every job, session, worktree and branch is `python -m ctf reap`.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys

from .. import jobs as _jobs

HELP = ("named jobs: run a long command detached and wait for it with no model turn "
        "(start | wait | run | status | list | tail | kill | stop | reap | prune)")


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--jobs-dir", dest="jobs_dir", metavar="DIR",
                   help="where job records live (default $CTF_JOBS_DIR, else <event workdir>/jobs)")


def _start_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--name", help="short label for the job id (default: the command's name)")
    p.add_argument("--cwd", help="working directory for the command (default: the current one)")
    p.add_argument("--on-exit", dest="on_exit", metavar="CMD",
                   help="command (shell-quoted string, no shell) run once when the job ends, "
                        "wake message on stdin")
    p.add_argument("--owner", help="who owns the job (default $CTF_JOB_OWNER; the launchers set it)")
    p.add_argument("--exclusive", action="store_true",
                   help="refuse when a live job with this --name already exists")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- CMD ARGS...")


def _wait_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--timeout", type=float, default=None,
                   help="give up waiting after S seconds (exit 124; the job keeps running)")
    p.add_argument("--tail", type=int, default=_jobs.TAIL_LINES,
                   help=f"output lines in the wake message (default {_jobs.TAIL_LINES}, 0 for none)")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="job_cmd", required=True)
    ps = sub.add_parser("start", help="start CMD detached; print its id and output path")
    _common(ps)
    _start_opts(ps)
    pw = sub.add_parser("wait", help="block until the job(s) end; print status and a short tail")
    _common(pw)
    pw.add_argument("ids", nargs="+", metavar="ID")
    pw.add_argument("--any", dest="any_", action="store_true", help="return when the first job ends")
    _wait_opts(pw)
    pr = sub.add_parser("run", help="start CMD detached, then wait for it (one call)")
    _common(pr)
    _wait_opts(pr)
    _start_opts(pr)
    pst = sub.add_parser("status", help="list jobs: running, exited rc, lost")
    _common(pst)
    pst.add_argument("ids", nargs="*", metavar="ID")
    pst.add_argument("--limit", type=int, default=20)
    pt = sub.add_parser("tail", help="the last lines of a job's output (bounded)")
    _common(pt)
    pt.add_argument("id", metavar="ID")
    pt.add_argument("-n", dest="lines", type=int, default=_jobs.TAIL_LINES)
    pk = sub.add_parser("kill", help="stop a running job and every process it started")
    _common(pk)
    pk.add_argument("id", metavar="ID")
    pso = sub.add_parser("stop", help="stop a job by id or by the name of its one live job")
    _common(pso)
    pso.add_argument("id", metavar="ID|NAME")
    pl = sub.add_parser("list", help="the named-job registry: name, owner, pid, pgid, state")
    _common(pl)
    pl.add_argument("--owner", help="only this owner's jobs")
    pl.add_argument("--live", action="store_true", help="only running and lost jobs")
    pl.add_argument("--json", action="store_true")
    prp = sub.add_parser("reap", help="stop every live job of one owner (what a launcher does when "
                                      "its agent exits)")
    _common(prp)
    prp.add_argument("--owner", required=True)
    prp.add_argument("--dry-run", dest="dry_run", action="store_true", help="list them, stop nothing")
    pp = sub.add_parser("prune", help="remove the folders of jobs that ended long ago "
                                       "(never running or lost jobs)")
    _common(pp)
    pp.add_argument("--older-than", dest="older_than", required=True, metavar="AGE",
                    help="ended more than AGE ago: seconds, or 90s / 30m / 12h / 7d")
    pp.add_argument("--dry-run", dest="dry_run", action="store_true", help="list them, remove nothing")


def _command(args) -> list[str]:
    cmd = list(args.command or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    return cmd


def _start(args, root):
    on_exit = None
    if args.on_exit is not None:
        try:
            on_exit = shlex.split(args.on_exit)
        except ValueError as e:
            raise _jobs.JobError(f"--on-exit {args.on_exit!r}: {e}") from None
    return _jobs.start(_command(args), root=root, name=args.name, cwd=args.cwd, on_exit=on_exit,
                       owner=args.owner, exclusive=args.exclusive)


def _print_wait(code: int, states, tail: int) -> None:
    for st in states:
        if st.state == "running":
            print(f"job {st.id}: still {_jobs.describe(st)}; it keeps running. Wait again: "
                  f"python -m ctf job wait {st.id}")
        else:
            sys.stdout.write(_jobs.summary(st, lines=max(0, tail)))


def run(args: argparse.Namespace) -> int:
    try:
        root = _jobs.jobs_root(args.jobs_dir)
        cmd = args.job_cmd
        if cmd == "start":
            job = _start(args, root)
            print(f"job {job.id} started (pid {job.pid})")
            print(f"  output: {job.log}")
            print(f"  wait:   python -m ctf job wait {job.id}")
            return 0
        if cmd == "run":
            job = _start(args, root)
            print(f"job {job.id} started (pid {job.pid}); waiting", file=sys.stderr)
            code, states = _jobs.wait([job.id], root=root, timeout=args.timeout)
            _print_wait(code, states, args.tail)
            return code
        if cmd == "wait":
            code, states = _jobs.wait(args.ids, root=root, timeout=args.timeout, any_=args.any_)
            _print_wait(code, states, args.tail)
            return code
        if cmd == "status":
            states = ([_jobs.state(_jobs.job_dir(root, i)) for i in args.ids] if args.ids
                      else _jobs.list_jobs(root)[:max(0, args.limit)])
            if not states:
                print(f"no jobs in {root}")
            for st in states:
                cmdline = " ".join(st.job.get("argv", []))
                print(f"{st.id}  {_jobs.describe(st)}  :: {cmdline[:80]}")
            return 0
        if cmd == "tail":
            d = _jobs.job_dir(root, args.id)
            text = _jobs.tail_text(d / _jobs.LOG_FILE, max(0, args.lines), _jobs.TAIL_MAX_BYTES * 4)
            if text:
                print(text)
            return 0
        if cmd in ("kill", "stop"):
            d = _jobs.job_dir(root, args.id)
            st = _jobs.state(d)
            st = _jobs.kill_lost(d, by="ctf job stop") if st.state == "lost" else _jobs.kill(d)
            sys.stdout.write(_jobs.summary(st, lines=5))
            return 0
        if cmd == "list":
            states = (_jobs.live_jobs(root, owner=args.owner) if args.live else
                      [st for st in _jobs.list_jobs(root)
                       if args.owner is None or st.job.get("owner") == args.owner])
            if args.json:
                keys = ("name", "owner", "owner_pid", "pid", "pgid", "pid_start", "supervisor_pid",
                        "cwd", "started_at", "argv")
                print(json.dumps([{"id": st.id, "state": st.state,
                                   "pidfile": str(st.dir / _jobs.PID_FILE),
                                   **{k: st.job.get(k) for k in keys}} for st in states], indent=1))
                return 0
            if not states:
                print(f"no jobs in {root}" + (f" owned by {args.owner}" if args.owner else ""))
            for st in states:
                own = st.job.get("owner") or "-"
                print(f"{st.id}  name={st.job.get('name')}  owner={own}  pid={st.job.get('pid', '?')}  "
                      f"pgid={st.job.get('pgid', '?')}  {_jobs.describe(st)}")
            return 0
        if cmd == "reap":
            done = _jobs.reap(root, owner=args.owner, dry_run=args.dry_run)
            for r in done:
                print(f"{r.outcome:10}  {r.id}  {r.detail}")
            print(f"{len(done)} live job(s) of owner {args.owner} in {root}")
            return _jobs.EXIT_FAILED if any(r.outcome == "failed" for r in done) else 0
        if cmd == "prune":
            gone = _jobs.prune(root, older_than=_jobs.parse_duration(args.older_than),
                               dry_run=args.dry_run)
            verb = "would remove" if args.dry_run else "removed"
            for st in gone:
                print(f"{verb} {st.id}  {_jobs.describe(st)}")
            print(f"{verb} {len(gone)} job(s) from {root}")
            return 0
        raise _jobs.JobError(f"unknown job command {cmd!r}")
    except _jobs.JobError as e:
        print(f"ctf job: {e}", file=sys.stderr)
        return _jobs.EXIT_ERROR
