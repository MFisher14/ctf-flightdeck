"""ctf failover check | status | switch | rehearse | prune -- harness failover for release mornings (B-170).

    python -m ctf failover check [--primary claude|codex] [--lanes N] [--est PCT] [--json]
        the budget meter's trigger: which harness should hold the lanes now, and the runbook steps
    python -m ctf failover status [--json]
        the active harness, the last switch, the last rehearsal onto each harness, the doctor's check
    python -m ctf failover switch --to HARNESS --by WHO --reason TEXT [--primary claude|codex]
        record that HARNESS now holds the lanes (a failover.switch ledger record) and print the steps
    python -m ctf failover rehearse --to HARNESS --by WHO [--live] [--bin PATH] [--model M]
                                    [--lanes a,b,...] [--parallel N] [--deadline S] [--timeout S] [--json]
        one synthetic lane per lane on HARNESS through its fenced launcher, all at once; without --live
        the binary must be a stub carrying the marker `ctf-harness-stub` (mechanics only); with --live
        it is the real CLI and makes one model session per lane
    python -m ctf failover prune [--keep N] [--dry-run] [--json]
        remove rehearsal lane folders under <workdir>/failover-rehearsal/ but the newest N runs per
        harness (default 1; 0 removes all); the ledger records stay

Common: --event SLUG, --workdir DIR, --now WHEN (epoch or ISO-8601; check and status only).
The runbook is docs/runbooks/harness-failover.md.

Exit codes: check: 0 stay, 3 switch (failover or failback), 1 stranded; rehearse: 0 held, 1 did not
hold; switch, status and prune: 0; every command: 2 a named error.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HELP = "harness failover for release mornings: the meter's trigger, the switch, the rehearsal (B-170)"
SWITCH_EXIT = 3
STRANDED_EXIT = 1


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir (default: the event's)")
    p.add_argument("--now", help="decide as of this time (epoch seconds or ISO-8601; default now)")
    sp = p.add_subparsers(dest="action", required=True)
    ck = sp.add_parser("check", help="which harness should hold the lanes, and the steps")
    ck.add_argument("--primary", choices=("claude", "codex"), default="claude")
    ck.add_argument("--lanes", type=int, help="release lanes to fund at once (default: the event's lanes)")
    ck.add_argument("--est", type=float, help="percent of a window one lane is expected to use")
    ck.add_argument("--json", action="store_true")
    st = sp.add_parser("status", help="active harness, last switch, last rehearsals")
    st.add_argument("--primary", choices=("claude", "codex"), default="claude")
    st.add_argument("--json", action="store_true")
    sw = sp.add_parser("switch", help="record that a harness now holds the lanes")
    sw.add_argument("--to", required=True, choices=("claude", "codex"))
    sw.add_argument("--by", required=True, help="who made the switch")
    sw.add_argument("--reason", required=True, help="the trigger (from `failover check`)")
    sw.add_argument("--primary", choices=("claude", "codex"), default="claude")
    rh = sp.add_parser("rehearse", help="one synthetic lane per lane on a harness, all at once")
    rh.add_argument("--to", required=True, choices=("claude", "codex"), help="the harness to rehearse onto")
    rh.add_argument("--by", required=True, help="who ran it")
    rh.add_argument("--live", action="store_true", help="the real CLI: one model session per lane")
    rh.add_argument("--bin", help="harness binary (default $CLAUDE_BIN / $CODEX_BIN, else the CLI name)")
    rh.add_argument("--model", help="model for every lane (default: the harness's configured model)")
    rh.add_argument("--lanes", help="comma-separated lanes (default: the event's categories as lanes)")
    rh.add_argument("--parallel", type=int, help="lanes at once (default: all of them, release fan-out)")
    rh.add_argument("--deadline", type=float, default=None, help="seconds a lane may take and still hold")
    rh.add_argument("--timeout", type=float, default=None, help="seconds before a lane is killed")
    rh.add_argument("--json", action="store_true")
    pr = sp.add_parser("prune", help="remove old rehearsal lane folders (the ledger records stay)")
    pr.add_argument("--keep", type=int, default=1, help="newest runs to keep per harness (default 1; 0: none)")
    pr.add_argument("--dry-run", action="store_true", help="list what would be removed, remove nothing")
    pr.add_argument("--json", action="store_true")


def _profile(args):
    from .. import event
    return event.load(args.event) if args.event else event.current()


def _workdir(args, prof) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(prof.slug)


def _now(args) -> float:
    if not args.now:
        return time.time()
    from ..budget import _parse_when
    return _parse_when(args.now.strip())


def _check(args, prof, wd: Path, failover, quota, ledger) -> int:
    recs = list(ledger.read(wd))
    lanes = args.lanes if args.lanes is not None else len(failover.profile_lanes(prof))
    snap = quota.snapshot(prof, workdir=wd, now=_now(args))
    d = failover.decide(snap, primary=args.primary, active=failover.active(wd, args.primary, recs),
                        lanes=lanes, est_pct=args.est, records=recs)
    steps = failover.steps(d, prof, workdir=wd)
    if args.json:
        print(json.dumps(dict(d.to_dict(), steps=steps)))
    else:
        tgt = d.target or "none"
        print(f"{d.action.upper()}: active {d.active}, should hold the lanes: {tgt} ({lanes} lane(s); "
              f"next release {quota.fmt_time(d.next_release)})")
        print(f"trigger: {d.trigger}")
        for h, r in d.ready.items():
            print(f"  {h:<6} now {'yes' if r.now else 'no ':<3}  at release {'yes' if r.at_release else 'no':<3}  "
                  f"[{r.status}] {r.why}")
        for i, s in enumerate(steps, 1):
            print(f"{i}. {s}")
    if d.action == "stranded":
        return STRANDED_EXIT
    return SWITCH_EXIT if d.switch else 0


def _status(args, prof, wd: Path, failover, quota, ledger) -> int:
    recs = list(ledger.read(wd))
    last = failover.last_switch(wd, recs)
    act = failover.active(wd, args.primary, recs)
    reh = {h: (failover.rehearsals(recs, h) or [None])[-1] for h in failover.HARNESSES}
    c = failover.check(prof, workdir=wd)
    if args.json:
        print(json.dumps({"active": act, "primary": args.primary, "last_switch": last, "last_rehearsal": reh,
                          "check": c.to_dict()}))
        return 0
    print(f"active: {act} (primary {args.primary})")
    if last:
        print(f"last switch: {last.get('from_harness')} -> {last.get('harness')} at "
              f"{quota.fmt_time(float(last.get('ts') or 0))} by {last.get('by')}: {last.get('reason')}")
    for h, r in reh.items():
        if r is None:
            print(f"onto {h}: never rehearsed")
        else:
            kind = "live" if r.get("live") else "stub"
            print(f"onto {h}: {kind} rehearsal {'HELD' if r.get('held') else 'DID NOT HOLD'} at "
                  f"{quota.fmt_time(float(r.get('ts') or 0))}, {len(r.get('lanes') or [])} lanes, "
                  f"{float(r.get('wall_s') or 0):.0f}s")
    print(c.line())
    return 0


def _rehearse(args, prof, wd: Path, failover) -> int:
    lanes = None
    if args.lanes:
        lanes = [x.strip() for x in args.lanes.split(",") if x.strip()]
    kw = {}
    if args.deadline is not None:
        kw["deadline_s"] = args.deadline
    rep = failover.rehearse(prof, args.to, by=args.by, workdir=wd, lanes=lanes, live=args.live, bin=args.bin,
                            model=args.model, parallel=args.parallel, timeout_s=args.timeout, **kw)
    if args.json:
        print(json.dumps(rep.to_dict()))
    else:
        kind = "LIVE" if rep.live else "stub (mechanics only)"
        print(f"rehearsal onto {rep.harness}, {kind}: {'HELD' if rep.held else 'DID NOT HOLD'} "
              f"({len(rep.lanes)} lanes, {rep.parallel} at once, wall {rep.wall_s:.1f}s, deadline "
              f"{rep.deadline_s:g}s per lane)")
        for ln in rep.lanes:
            print(f"  {ln.lane:<12} {ln.status:<12} {ln.seconds:7.1f}s  {ln.detail}")
        print(f"lane folders: {rep.root}")
    return 0 if rep.held else 1


def _prune(args, wd: Path, failover) -> int:
    gone = failover.prune_rehearsals(wd, keep=args.keep, dry_run=args.dry_run)
    if args.json:
        print(json.dumps({"dry_run": args.dry_run, "keep": args.keep, "removed": [str(p) for p in gone]}))
        return 0
    verb = "would remove" if args.dry_run else "removed"
    print(f"{verb} {len(gone)} rehearsal run folder(s), keeping the newest {args.keep} per harness")
    for p in gone:
        print(f"  {p}")
    return 0


def run(args: argparse.Namespace) -> int:
    from .. import failover, ledger, quota
    from ..event import EventError
    try:
        prof = _profile(args)
        wd = _workdir(args, prof)
        if args.action == "check":
            return _check(args, prof, wd, failover, quota, ledger)
        if args.action == "status":
            return _status(args, prof, wd, failover, quota, ledger)
        if args.action == "switch":
            rec = failover.switch(wd, args.to, by=args.by, reason=args.reason, primary=args.primary)
            print(f"recorded {rec['action']}: {rec['from_harness']} -> {rec['harness']}")
            print(f"next: the {rec['action']} steps in {failover.RUNBOOK} "
                  f"(`python -m ctf failover --event {prof.slug} check` prints them for the meter's state)")
            return 0
        if args.action == "prune":
            return _prune(args, wd, failover)
        return _rehearse(args, prof, wd, failover)
    except (failover.FailoverError, quota.QuotaError, EventError, FileNotFoundError, ValueError, OSError) as e:
        print(f"ctf failover: {e}", file=sys.stderr)
        return 2
