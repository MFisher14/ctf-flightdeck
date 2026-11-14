"""ctf work -- the build-time work registry, file claims, fold owners and the idle-machine lock (B-213,
ctf/workreg.py).

    python -m ctf work start AGENT --harness claude|codex|human|other [--branch B] [--worktree DIR]
                             [--pid PID] [--ttl S] [--row ID]... [--file PATTERN]... [--fold F]... [--note N]
    python -m ctf work check [--agent A] [--row ID]... [--file PATTERN]... [--fold F]... [--branch B]
                             [--worktree DIR]
    python -m ctf work claim AGENT [--row ID]... [--file PATTERN]... [--fold F]...
    python -m ctf work release AGENT [--row ID]... [--file PATTERN]... [--fold F]...
    python -m ctf work heartbeat AGENT
    python -m ctf work leave AGENT
    python -m ctf work list [--live]
    python -m ctf work reap
    python -m ctf work idle-status
    python -m ctf work idle-run [--shared] [--label L] [--timeout S] [--poll S] [--max-load X] -- CMD [ARGS...]

Every sub-command takes [--state DIR] (default: ctf.paths.workreg_state(), the git common dir, shared by
every worktree), [--backlog FILE] (the B-138 rows claims are checked against; default docs/backlog.jsonl),
[--master DIR] (the checkout whose events/<slug>/promotion.json fold claims are checked against) and
[--json].

`start` is the pre-spawn step: run it before launching a builder; it registers the agent with its claims
all or nothing, and when anything clashes it registers nothing and names every clash (owner, harness,
branch, claim). The agent name is, by convention, its B-147 branch (`item/<id>`); --branch defaults to it.
`check` is the same test, read-only. A record with --pid is stale once that pid is gone, with --ttl once
it goes S s without `heartbeat`, and with --worktree once that folder is gone; without them it is held
until `leave`. Nothing here signals or stops a process.

`idle-run` runs CMD holding the idle-machine lock: exclusive (a timing suite) by default, --shared for
heavy work timing suites should wait for. `idle-status` says who holds it and who waits.

Exit codes: 0 ok (idle-run: CMD's own code), 1 a claim conflict (each named on stderr) or, for `check`,
any conflict, 2 a named error (bad claim, unknown agent or row, unreadable registry), 3 idle-run gave up
waiting for the lock (--timeout), naming the holder.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .. import paths as _paths
from .. import workreg as _wr

HELP = "build-time work registry: who works on what (agents, branches, rows), file and fold claims, idle lock"

CONFLICT_EXIT = 1
TIMEOUT_EXIT = 3


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--state", type=Path, metavar="DIR", help="registry folder (default: ctf.paths.workreg_state())")
    p.add_argument("--backlog", type=Path, metavar="FILE", help="B-138 backlog for row claims (default: docs/backlog.jsonl)")
    p.add_argument("--master", type=Path, metavar="DIR", help="checkout holding events/<slug>/promotion.json (default: this one)")
    p.add_argument("--json", action="store_true")


def _claims(p: argparse.ArgumentParser) -> None:
    p.add_argument("--row", action="append", default=[], metavar="ID", help="a B-138 backlog row (repeatable)")
    p.add_argument("--file", action="append", default=[], metavar="PATTERN",
                   help="a repo-relative path or glob (* ? **; trailing / = whole directory) (repeatable)")
    p.add_argument("--fold", action="append", default=[], metavar="SLUG:SOURCE:PATH",
                   help="a promotion entry to fold (ctf.promote) (repeatable)")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sp = parser.add_subparsers(dest="action", required=True)
    s = sp.add_parser("start", help="register an agent and its claims before spawn (all or nothing)")
    s.add_argument("agent")
    s.add_argument("--harness", required=True, choices=_wr.HARNESSES)
    s.add_argument("--branch", help="its git branch (default: the agent name, the B-147 convention)")
    s.add_argument("--worktree", type=Path, help="its worktree folder (the record goes stale when it is gone)")
    s.add_argument("--pid", type=int, help="the agent harness's pid (stale once it is gone)")
    s.add_argument("--ttl", type=float, metavar="S", help="stale after S s without `heartbeat`")
    s.add_argument("--note", default="")
    _claims(s)
    _common(s)
    c = sp.add_parser("check", help="would these claims clash? (read-only)")
    c.add_argument("--agent", help="ignore this agent's own claims")
    c.add_argument("--branch")
    c.add_argument("--worktree", type=Path)
    _claims(c)
    _common(c)
    for name, hlp in (("claim", "add claims to a registered agent (all or nothing)"),
                      ("release", "drop some of an agent's claims")):
        x = sp.add_parser(name, help=hlp)
        x.add_argument("agent")
        _claims(x)
        _common(x)
    for name, hlp in (("heartbeat", "stamp an agent's heartbeat (keeps a --ttl record live)"),
                      ("leave", "remove an agent and all its claims (no process is touched)")):
        x = sp.add_parser(name, help=hlp)
        x.add_argument("agent")
        _common(x)
    ls = sp.add_parser("list", help="every registered agent: harness, pid, branch, rows, claims, live or stale")
    ls.add_argument("--live", action="store_true", help="live agents only")
    _common(ls)
    _common(sp.add_parser("reap", help="remove stale records now (registry entries only)"))
    _common(sp.add_parser("idle-status", help="who holds the idle-machine lock and who waits"))
    r = sp.add_parser("idle-run", help="run a command holding the idle-machine lock")
    r.add_argument("--shared", action="store_true", help="take it shared (heavy work), not exclusive (timing)")
    r.add_argument("--label", help="what holds it (default: the command)")
    r.add_argument("--agent", default="", help="the registered agent running it (shown to waiters)")
    r.add_argument("--timeout", type=float, metavar="S", help="give up after S s (exit 3; default: wait)")
    r.add_argument("--poll", type=float, default=_wr.DEFAULT_IDLE_POLL, metavar="S")
    r.add_argument("--max-load", type=float, metavar="X", help="also wait until load1 per CPU <= X")
    r.add_argument("cmd", nargs=argparse.REMAINDER, help="-- CMD [ARGS...]")
    _common(r)


def _state(args) -> Path:
    return args.state.resolve() if args.state else _paths.workreg_state()


def _registry(args) -> _wr.Registry:
    return _wr.Registry(_state(args), backlog=args.backlog, master=args.master)


def _emit(args, obj, text: str) -> None:
    print(json.dumps(obj, indent=1, sort_keys=True) if args.json else text)


def _claim_text(rec: dict) -> str:
    c = rec.get("claims") or {}
    parts = []
    if c.get("row"):
        parts.append("rows " + ", ".join(c["row"]))
    if c.get("file"):
        parts.append("files " + ", ".join(c["file"]))
    if c.get("fold"):
        parts.append("folds " + ", ".join(f["key"] for f in c["fold"]))
    return "; ".join(parts) or "no claims"


def _conflict_exit(args, conflicts) -> int:
    for c in conflicts:
        print(f"ctf work: conflict: {c.describe()}", file=sys.stderr)
    if args.json:
        print(json.dumps({"conflicts": [c.to_dict() for c in conflicts]}, indent=1, sort_keys=True))
    return CONFLICT_EXIT


def _start(args) -> int:
    reg = _registry(args)
    branch = args.agent if args.branch is None else args.branch
    try:
        rec = reg.begin(args.agent, harness=args.harness, branch=branch, worktree=args.worktree, pid=args.pid,
                        ttl=args.ttl, rows=args.row, files=args.file, folds=args.fold, note=args.note)
    except _wr.ClaimConflict as e:
        return _conflict_exit(args, e.conflicts)
    for r in rec["reaped"]:
        print(f"ctf work: reaped stale {r}", file=sys.stderr)
    _emit(args, rec, f"registered {args.agent} ({args.harness}, branch {branch or '-'}): {_claim_text(rec)}")
    return 0


def _check(args) -> int:
    conflicts = _registry(args).check(args.agent, rows=args.row, files=args.file, folds=args.fold,
                                      branch=args.branch, worktree=args.worktree.resolve() if args.worktree else None)
    if conflicts:
        return _conflict_exit(args, conflicts)
    _emit(args, {"conflicts": []}, "no conflict")
    return 0


def _claim(args) -> int:
    try:
        rec = _registry(args).claim(args.agent, rows=args.row, files=args.file, folds=args.fold)
    except _wr.ClaimConflict as e:
        return _conflict_exit(args, e.conflicts)
    _emit(args, rec, f"{args.agent}: {_claim_text(rec)}")
    return 0


def _release(args) -> int:
    rec = _registry(args).release(args.agent, rows=args.row, files=args.file, folds=args.fold)
    _emit(args, rec, f"{args.agent}: {_claim_text(rec)}")
    return 0


def _heartbeat(args) -> int:
    rec = _registry(args).heartbeat(args.agent)
    _emit(args, rec, f"{args.agent}: heartbeat {rec['heartbeat']}")
    return 0


def _leave(args) -> int:
    rec = _registry(args).leave(args.agent)
    _emit(args, rec, f"{args.agent} left (released: {_claim_text(rec)})")
    return 0


def _list(args) -> int:
    views = [v for v in _registry(args).agents() if v.live or not args.live]
    lines = []
    for v in views:
        r = v.record
        state = "live" if v.live else f"STALE ({v.reason})"
        lines.append(f"{v.name}  {r.get('harness')}  branch={r.get('branch') or '-'}  pid={r.get('pid') or '-'}  "
                     f"{state}  {_claim_text(r)}")
    _emit(args, [v.to_dict() for v in views], "\n".join(lines) if lines else "no agent registered")
    return 0


def _reap(args) -> int:
    out = _registry(args).reap()
    _emit(args, {"reaped": out}, "\n".join(f"reaped {r}" for r in out) if out else "nothing stale")
    return 0


def _idle_status(args) -> int:
    st = _wr.idle_status(_state(args))
    lines = [f"idle lock: {st['state']}"]
    lines += [f"  held by {_wr.describe_holder(r)}" for r in st["holders"]]
    lines += [f"  waiting: {_wr.describe_holder(r)}" for r in st["waiting"]]
    lines += [f"  stale record (holder gone): {_wr.describe_holder(r)}" for r in st["stale"]]
    _emit(args, st, "\n".join(lines))
    return 0


def _idle_run(args) -> int:
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("ctf work idle-run: no command given (use: ctf work idle-run -- CMD ...)", file=sys.stderr)
        return 2
    told = {"why": None}

    def on_wait(why: str) -> None:
        if why != told["why"]:
            told["why"] = why
            print(f"ctf work idle-run: waiting: {why}", file=sys.stderr)
            sys.stderr.flush()

    label = args.label or " ".join(" ".join(cmd).split())[:80].strip()   # one line, whatever CMD holds
    lock = _wr.IdleLock(_state(args), label,
                        mode=_wr.SHARED if args.shared else _wr.EXCLUSIVE, agent=args.agent,
                        timeout=args.timeout, poll=args.poll, max_load=args.max_load, on_wait=on_wait)
    try:
        lock.acquire()
    except _wr.IdleLockTimeout as e:
        print(f"ctf work idle-run: {e}", file=sys.stderr)
        return TIMEOUT_EXIT
    try:
        return subprocess.run(cmd).returncode
    finally:
        lock.release()


_ACTIONS = {"start": _start, "check": _check, "claim": _claim, "release": _release, "heartbeat": _heartbeat,
            "leave": _leave, "list": _list, "reap": _reap, "idle-status": _idle_status, "idle-run": _idle_run}


def run(args: argparse.Namespace) -> int:
    try:
        return _ACTIONS[args.action](args)
    except (_wr.WorkRegError, FileNotFoundError) as e:
        print(f"ctf work: error: {e}", file=sys.stderr)
        return 2
