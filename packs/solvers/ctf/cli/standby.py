"""ctf standby take | renew | release | status | plan -- the warm standby agent pool (B-037, ctf/standby.py).

    python -m ctf standby take --agent NAME [--owner-pid PID] [--ttl S] [--timeout S] [--poll S]
                               [--pool dispatch|helpers] [--lane L] [--json]
    python -m ctf standby renew --agent NAME ID
    python -m ctf standby release --agent NAME [--force] ID
    python -m ctf standby status [--json]
    python -m ctf standby plan --size N [--ttl S] [--json]

A warm agent is launched ahead of a wave and blocks on `take`: it waits until the no-model dispatcher
(B-004) has written a claim, then is handed exactly one claim and its machine-written handout and returns
at once (wake to first tool in a few seconds instead of a cold launch's 11.5-24.6 s). Two warm agents can
never be handed the same claim. `take` exits 0 on a claim, 4 on timeout, 2 on error. A claim whose
handout is missing is skipped (named on stderr) and the next claim is handed out; if the wait ends with
nothing handed out and such claims were seen, `take` exits 2 naming them. `take` never sleeps past
--timeout, whatever --poll is.

The `take` process exits as soon as it prints the handout, so its own pid says nothing about the agent.
The lease's liveness is therefore explicit: `--owner-pid PID` ties it to the agent harness's pid (stale
once that pid is gone and the lease is older than --stale-after); `--ttl S` makes it a heartbeat lease the
agent keeps with `renew` (stale after S s without one; `renew` exits 1 when the agent no longer holds the
claim); with neither, the lease is held until `release` (the operator frees a crashed holder's claim
with `release --force`). `status` shows the pool; `plan` prints the launch plan (one agent name + argv
per standby slot, and the launcher to start each with: `tools/claude_launch --standby`, 1h prompt cache,
B-118) for the orchestrator to launch ~T-7 min; build work does not launch real agents.
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys

from .. import event as _event
from .. import paths as _paths
from .. import standby as _standby

HELP = "the warm standby agent pool: block for a claim, or inspect/plan the pool"

TIMEOUT_EXIT = 4


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)

    t = sp.add_parser("take", help="block until a claim is available, then take one")
    t.add_argument("--agent", required=True, help="this warm agent's name ([A-Za-z0-9][A-Za-z0-9_.-]{0,63})")
    t.add_argument("--timeout", type=float, default=_standby.DEFAULT_TIMEOUT,
                   help=f"seconds to wait before giving up (default {_standby.DEFAULT_TIMEOUT:g}, "
                        f"max {_standby.MAX_TIMEOUT:g}; must end before the caller's tool wall)")
    t.add_argument("--poll", type=float, default=_standby.DEFAULT_POLL,
                   help=f"seconds between looks (default {_standby.DEFAULT_POLL:g})")
    t.add_argument("--owner-pid", dest="owner_pid", type=int, default=None,
                   help="the warm agent harness's pid: the lease lives while it does (never this "
                        "command's own pid, which exits at once)")
    t.add_argument("--ttl", type=float, default=None,
                   help="heartbeat lease: reclaimable after this many seconds without `standby renew`")
    t.add_argument("--stale-after", dest="stale_after", type=float, default=_standby.DEFAULT_STALE_AFTER,
                   help="with --owner-pid: reclaim once that pid is gone and the lease is older than this")
    t.add_argument("--pool", choices=_standby.POOLS, default=_standby.DISPATCH_POOL,
                   help="which claims to wait for: dispatch (challenge claims, default) or helpers "
                        "(lane-helper claims written on a lane STOP, B-212)")
    t.add_argument("--lane", default=None, help="only claims of this lane")
    t.add_argument("--json", action="store_true", help="print the assignment as one JSON object")

    rn = sp.add_parser("renew", help="heartbeat a lease this agent holds (exit 1 if it no longer does)")
    rn.add_argument("--agent", required=True)
    rn.add_argument("id")

    r = sp.add_parser("release", help="give a leased claim back to the pool")
    r.add_argument("--agent", required=True)
    r.add_argument("--force", action="store_true",
                   help="operator recovery: remove the lease whoever holds it (--agent names the operator)")
    r.add_argument("id")

    s = sp.add_parser("status", help="show the warm pool")
    s.add_argument("--json", action="store_true")

    pl = sp.add_parser("plan", help="print the launch plan for a warm pool of N agents")
    pl.add_argument("--size", type=int, required=True, help="how many warm agents")
    pl.add_argument("--prefix", default="standby", help="agent-name prefix (default 'standby')")
    pl.add_argument("--ttl", type=float, default=None, help="give each slot a heartbeat lease of S seconds")
    pl.add_argument("--json", action="store_true")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _workdir(args: argparse.Namespace):
    return _paths.workdir(_profile(args).slug)


def _lease_note(lease: dict) -> str:
    if lease.get("pid") is not None:
        return f"lease lives while pid {lease['pid']} does"
    if lease.get("ttl") is not None:
        return f"run `standby renew` within {lease['ttl']:g}s or lose the claim"
    return "lease held until `standby release`"


def _take(args: argparse.Namespace) -> int:
    if args.timeout > _standby.MAX_TIMEOUT:
        print(f"ctf standby: --timeout {args.timeout:g} exceeds the {_standby.MAX_TIMEOUT:g}s cap "
              "(it must end before the caller's tool wall)", file=sys.stderr)
        return 2
    wd = _workdir(args)
    # Never this process's own pid: it exits as soon as the handout is printed (module docstring).
    try:
        a = _standby.take(wd, args.agent, timeout=args.timeout, poll=args.poll,
                          stale_after=args.stale_after, owner_pid=args.owner_pid, ttl=args.ttl,
                          pool=args.pool, lane=args.lane)
    except _standby.StandbyTimeout as e:
        print(f"ctf standby: {e}", file=sys.stderr)
        return TIMEOUT_EXIT
    for cid, reason in a.skipped:   # bad claims passed over: loud, but they do not cost this agent its claim
        print(f"ctf standby: skipped claim {cid}: {reason}", file=sys.stderr)
    if args.json:
        print(json.dumps({"challenge_id": a.challenge_id, "lane": a.lane, "waited": a.waited,
                          "claim": a.claim, "handout_path": a.handout_path, "handout": a.handout,
                          "lease": a.lease, "skipped": [list(s) for s in a.skipped]},
                         ensure_ascii=False))
    else:
        print(f"# standby {args.agent}: claimed {a.challenge_id} [{a.lane}] after {a.waited:g}s "
              f"-> {a.handout_path} ({_lease_note(a.lease)})")
        print(a.handout, end="")
    return 0


def _renew(args: argparse.Namespace) -> int:
    if _standby.renew(_workdir(args), args.agent, args.id) is None:
        print(f"ctf standby: {args.agent} no longer holds {args.id}: stop working it", file=sys.stderr)
        return 1
    print(f"renewed {args.id} for {args.agent}")
    return 0


def _status(args: argparse.Namespace) -> int:
    st = _standby.pool_status(_workdir(args))
    if args.json:
        print(json.dumps(st, ensure_ascii=False))
        return 0
    print(f"claims {st['claims']}  available {len(st['available'])}  leased {len(st['leased'])}  "
          f"held {len(st['held_until_release'])}  stale {len(st['stale_leases'])}  "
          f"waiting {st['waiting']}  assigned {st['assigned']}")
    for a in st["agents"]:
        where = f" -> {a['challenge_id']}" if a.get("challenge_id") else ""
        alive = {True: "", False: " (pid gone)", None: " (no pid)"}[a["alive"]]
        print(f"  {a['agent']}: {a['status']}{where}{alive}")
    if st["bad_handouts"]:
        print("  claims skipped for a bad handout: " + ", ".join(st["bad_handouts"]), file=sys.stderr)
    if st["unreadable_claims"]:
        print("  unreadable claims: " + ", ".join(st["unreadable_claims"]), file=sys.stderr)
    return 0


def _plan(args: argparse.Namespace) -> int:
    rows = _standby.plan(args.size, prefix=args.prefix, ttl=args.ttl)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False))
        return 0
    print(f"# warm pool of {args.size} agent(s): launch each ~T-7 min, each blocks on its argv")
    print(f"# start each with: {shlex.join(_standby.LAUNCH_ARGV)} [fence options] -- <claude args> "
          "(1h prompt cache for the wait, B-118)")
    print("# put this in each agent's launch prompt (B-043):")
    for line in rows[0]["brief"].splitlines():
        print(f"#   {line}".rstrip())
    for row in rows:
        print(f"{row['agent']}\t{shlex.join(row['argv'])}")
    return 0


def _release(args: argparse.Namespace) -> int:
    if not _standby.release(_workdir(args), args.agent, args.id, force=args.force):
        who = "nobody" if args.force else args.agent
        print(f"ctf standby: {who} holds a lease on {args.id} (nothing released)", file=sys.stderr)
        return 1
    print(f"released {args.id}" + (" (forced)" if args.force else f" from {args.agent}"))
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        return {"take": _take, "renew": _renew, "status": _status, "plan": _plan,
                "release": _release}[args.action](args)
    except (_event.EventError, _standby.StandbyError) as e:
        print(f"ctf standby: {e}", file=sys.stderr)
        return 2
