"""ctf slate show | set | pause | resume | remove | history | check | status | plan | env | fence | run
-- the multi-event priority scheduler (B-214, ctf/slate.py).

    python -m ctf slate set SLUG --by WHO --reason WHY [--priority N] [--weight W] [--max-agents N|none]
                             [--min-agents N] [--quota-cap PCT|none] [--workdir DIR|none]
        add an event to the slate or change the player's settings for it (each change is logged)
    python -m ctf slate pause|resume|remove SLUG --by WHO --reason WHY
    python -m ctf slate show [--json]          the events in play, their settings and workdirs
    python -m ctf slate history [--json]       every change: who, why, before and after
    python -m ctf slate check                  exit 1 when the slate cannot work (named problems)
    python -m ctf slate status [--cap N] [--json]
        agents per event now: running, waiting, share of the host cap and why
    python -m ctf slate plan --jobs FILE [--cap N | --no-agents] [--now WHEN] [--json]
        place each event's jobs ({"slug": [{id, kind, ...}]}) on a harness by priority, sharing the
        account's quota windows; held jobs with the reason and when they open
    python -m ctf slate env SLUG               shell lines pinning CTF_EVENT and CTF_WORKDIR to the event
    python -m ctf slate fence SLUG [--write]   the event's fence with every other event's workdir denied
    python -m ctf slate run --event SLUG [--label L] [--timeout S] [--poll S] -- CMD ...
        wait for an agent slot in the event's share of the host, run CMD pinned to the event, free it

Common: --state DIR (default $CTF_SLATE_STATE, else ~/ctf-work/_slate), --events-root DIR.

Exit codes: 0 ok; 1 check found problems; 2 a named error; 3 held (plan) or not admitted within
--timeout (run); run otherwise exits with CMD's code.
"""
from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

HELP = "multi-event priority scheduler: events in play, the player's priorities, shared agents and quota (B-214)"
HELD_EXIT = 3


def _none_or(kind):
    def parse(raw: str):
        if raw.strip().lower() == "none":
            return None
        return kind(raw)
    return parse


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--state", help="slate state folder (default $CTF_SLATE_STATE, else ~/ctf-work/_slate)")
    p.add_argument("--events-root", help="folder holding the event profiles (default events/)")
    sp = p.add_subparsers(dest="action", required=True)

    se = sp.add_parser("set", help="add an event or change its settings")
    se.add_argument("slug")
    se.add_argument("--priority", type=int)
    se.add_argument("--weight", type=float)
    se.add_argument("--max-agents", type=_none_or(int), default=argparse.SUPPRESS)
    se.add_argument("--min-agents", type=int)
    se.add_argument("--quota-cap", type=_none_or(float), default=argparse.SUPPRESS, dest="quota_cap_pct")
    se.add_argument("--workdir", type=_none_or(str), default=argparse.SUPPRESS)
    for name in ("pause", "resume", "remove"):
        x = sp.add_parser(name, help=f"{name} an event on the slate")
        x.add_argument("slug")
    for x in (se, *(sp.choices[n] for n in ("pause", "resume", "remove"))):
        x.add_argument("--by", required=True, help="who decided (the player)")
        x.add_argument("--reason", required=True)

    sh = sp.add_parser("show", help="the events in play")
    sh.add_argument("--json", action="store_true")
    hi = sp.add_parser("history", help="every slate change")
    hi.add_argument("--json", action="store_true")
    sp.add_parser("check", help="exit 1 when the slate cannot work")
    st = sp.add_parser("status", help="agents per event now")
    st.add_argument("--cap", type=int, help="use this host cap instead of the governor's reading")
    st.add_argument("--json", action="store_true")
    pl = sp.add_parser("plan", help="place each event's jobs by priority")
    pl.add_argument("--jobs", required=True, help='JSON file: {"<slug>": [{id, kind, harnesses?, prefer?, est_pct?}]}')
    g = pl.add_mutually_exclusive_group()
    g.add_argument("--cap", type=int, help="host agent cap (default: the governor's reading)")
    g.add_argument("--no-agents", action="store_true", help="plan quota only: no agent limit")
    pl.add_argument("--now", help="plan as of this time (epoch or ISO-8601)")
    pl.add_argument("--json", action="store_true")
    en = sp.add_parser("env", help="shell lines pinning an agent to the event")
    en.add_argument("slug")
    fe = sp.add_parser("fence", help="the event's fence with the other events' workdirs denied")
    fe.add_argument("slug")
    fe.add_argument("--write", action="store_true", help="write the Claude Code settings into the workdir")
    ru = sp.add_parser("run", help="run CMD in an agent slot of the event's share")
    ru.add_argument("--event", required=True)
    ru.add_argument("--label", default="")
    ru.add_argument("--timeout", type=float, default=None)
    ru.add_argument("--poll", type=float, default=5.0)
    ru.add_argument("cmd", nargs=argparse.REMAINDER)


def _store(args):
    from .. import slate
    return slate.Store(args.state, events_root=args.events_root)


def _governor():                       # replaced in tests
    from .. import governor, paths
    return governor.Governor(paths.governor_state(), governor.GovernorPolicy.from_env())


def _show(args, store) -> int:
    from .. import slate
    sl = store.load()
    try:
        ws = {s: str(p) for s, p in slate.workspaces(sl).items()}
        werr = None
    except slate.SlateError as e:
        ws, werr = {}, str(e)
    if args.json:
        print(json.dumps({**sl.to_dict(), "workdirs": ws, "workdir_error": werr}, indent=1))
        return 0
    if not sl.entries:
        print("the slate is empty")
        return 0
    for e in sl.ordered():
        cap = "none" if e.max_agents is None else e.max_agents
        q = "none" if e.quota_cap_pct is None else f"{e.quota_cap_pct:g}%"
        print(f"{e.slug:<16} priority {e.priority:<3} weight {e.weight:<5g} max {cap!s:<5} min {e.min_agents:<3}"
              f" quota-cap {q:<6}{'  PAUSED' if e.paused else ''}")
        print(f"{'':16} workdir {ws.get(e.slug, '?')}; set by {e.set_by} ({e.reason})")
    if werr:
        print(f"WORKDIRS NOT ISOLATED: {werr}")
    return 0


def _status(args, store) -> int:
    from .. import slate
    sched = slate.Scheduler(store, _governor())
    if args.cap is not None:
        sl = store.load()
        running, waiting, _other = sched.census()
        on = {s: n for s, n in running.items() if s in sl.entries}
        demand = {s: on.get(s, 0) + len(waiting.get(s, [])) for s in sl.entries}
        alloc = slate.allocate(sl, args.cap, demand, on)
        basis = f"--cap {args.cap}"
    else:
        alloc = sched.allocation()
        basis = f"governor: {sched.host_reason}"
    _running, waiting, other = sched.census()
    if args.json:
        print(json.dumps({**alloc.to_dict(), "basis": basis, "not_on_slate": other,
                          "waiting": {s: len(v) for s, v in waiting.items()}}, indent=1))
        return 0
    print(f"slate cap {alloc.cap} ({basis}; {other} heavy agent(s) not on the slate)")
    for s, sh in alloc.shares.items():
        print(f"{s:<16} running {sh.running} waiting {len(waiting.get(s, []))} share {sh.agents} "
              f"free {sh.free}: {sh.reason}")
    return 0


def _plan(args, store) -> int:
    from .. import slate
    from .quota import _when
    import time
    sl = store.load()
    try:
        data = json.loads(Path(args.jobs).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise slate.SlateError(f"{args.jobs}: cannot read the job file ({e})") from None
    jobs = slate.load_jobs(data)
    now = _when(args.now, time.time()) if args.now else time.time()
    alloc = None
    if not args.no_agents:
        sched = slate.Scheduler(store, _governor())
        running, _waiting, other = sched.census()
        on = {s: n for s, n in running.items() if s in sl.entries}
        demand = {s: on.get(s, 0) + len(jobs.get(s, [])) for s in sl.entries}
        cap = args.cap if args.cap is not None else max(0, sched.governor.decision().cap - other)
        alloc = slate.allocate(sl, cap, demand, on)
    p = slate.plan(sl, jobs, now=now, allocation=alloc, events_root=args.events_root)
    if args.json:
        print(json.dumps(p.to_dict(), indent=1))
    else:
        from ..quota import fmt_time
        print(f"next release (any event): {fmt_time(p.next_release)}")
        if alloc is not None:
            for s, sh in alloc.shares.items():
                print(f"agents {s}: {sh.free} free of share {sh.agents} ({sh.reason})")
        for a in p.assigned:
            x = a.assignment
            print(f"RUN  {a.slug}/{x.job} [{x.kind}] on {x.harness} ({x.mode}, {x.est_pct:g}%)")
        for h in p.held:
            why = "; ".join(f"{k}: {v}" for k, v in h.reasons.items())
            print(f"HOLD {h.slug}/{h.job} [{h.kind}] until {fmt_time(h.release_at)}: {why}")
        for w in p.warnings:
            print(f"warning: {w}")
    return HELD_EXIT if p.held else 0


def _run(args, store) -> int:
    from .. import governor as _gov
    from .. import slate
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("ctf slate run: no command given (use: ctf slate run --event SLUG -- CMD ...)", file=sys.stderr)
        return 2
    sl = store.load()
    env = slate.child_env(sl, args.event)
    sched = slate.Scheduler(store, _governor())
    told = {"why": None}

    def on_wait(why: str) -> None:
        if told["why"] != why:
            told["why"] = why
            print(f"ctf slate: waiting: {why}", file=sys.stderr)

    try:
        lease = sched.acquire(args.event, args.label or " ".join(cmd)[:80], timeout=args.timeout,
                              poll=args.poll, on_wait=on_wait)
    except _gov.GovernorTimeout as e:
        print(f"ctf slate run: {e}", file=sys.stderr)
        return HELD_EXIT
    try:
        return subprocess.run(cmd, env=env).returncode
    finally:
        sched.release(lease)


def run(args: argparse.Namespace) -> int:
    from .. import event, quota, slate
    store = _store(args)
    try:
        if args.action == "set":
            changes = {k: getattr(args, k) for k in ("priority", "weight", "min_agents")
                       if getattr(args, k) is not None}
            # these take "none" (clear the setting), so they are absent unless given
            changes.update({k: getattr(args, k) for k in ("max_agents", "quota_cap_pct", "workdir")
                            if k in vars(args)})
            e = store.set(args.slug, by=args.by, reason=args.reason, **changes)
            print(f"{e.slug}: priority {e.priority}, weight {e.weight:g}, max_agents {e.max_agents}, "
                  f"min_agents {e.min_agents}, quota_cap_pct {e.quota_cap_pct}, workdir "
                  f"{slate.workdir_of(e)}{', paused' if e.paused else ''}")
            return 0
        if args.action in ("pause", "resume", "remove"):
            getattr(store, args.action)(args.slug, by=args.by, reason=args.reason)
            print(f"{args.slug}: {args.action}d")
            return 0
        if args.action == "show":
            return _show(args, store)
        if args.action == "history":
            h = store.history()
            if args.json:
                print(json.dumps(h, indent=1))
            else:
                for r in h:
                    print(f"{quota.fmt_time(r['ts'])} {r['action']:<7} {r['slug']:<16} by {r['by']}: {r['reason']}")
            return 0
        if args.action == "check":
            probs = slate.check(store.load(), events_root=args.events_root)
            for p in probs:
                print(f"FAIL {p}")
            print("SLATE " + ("OK" if not probs else f"FAILED ({len(probs)} problem(s))"))
            return 1 if probs else 0
        if args.action == "status":
            return _status(args, store)
        if args.action == "plan":
            return _plan(args, store)
        if args.action == "env":
            env = slate.child_env(store.load(), args.slug, base={})
            for k in ("CTF_EVENT", "CTF_WORKDIR"):
                print(f"export {k}={shlex.quote(env[k])}")
            return 0
        if args.action == "fence":
            from .. import fence
            sl = store.load()
            f = slate.fence_for(sl, args.slug, events_root=args.events_root)
            others = [str(w) for s, w in slate.workspaces(sl).items() if s != args.slug]
            print(f"workspace {f.workspace}")
            for o in others:
                print(f"denied (another event) {o}")
            if args.write:
                print(f"claude settings {fence.write_claude_settings(f)}")
            return 0
        if args.action == "run":
            return _run(args, store)
    except (slate.SlateError, event.EventError, quota.QuotaError) as e:
        print(f"ctf slate {args.action}: {e}", file=sys.stderr)
        return 2
    except Exception as e:                                       # noqa: BLE001 - a named error, never a trace
        from .. import fence as _fence, governor as _gov
        if isinstance(e, (_fence.FenceError, _gov.GovernorError)):
            print(f"ctf slate {args.action}: {e}", file=sys.stderr)
            return 2
        raise
    return 2
