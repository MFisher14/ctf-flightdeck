"""ctf instance -- start/stop/schedule per-team container instances (B-003).

    python -m ctf instance list                       sweep the container challenges' instance state
    python -m ctf instance start <id>                 start (or re-read) our instance for <id>
    python -m ctf instance status <id>                our instance's state + host:port for <id>
    python -m ctf instance renew <id>                 extend our instance's clock for <id>
    python -m ctf instance stop <id>                  tear our instance down, free the slot
    python -m ctf instance stop-all                   tear down every running instance we hold
    python -m ctf instance schedule [--challenge ID]  value-ordered: start the top open challenges up to
                                                      the cap, free a slot on every solved one
                                [--renew-within S]    and renew running unsolved ones expiring within S s
    python -m ctf instance permissions                print the solver harness allow/deny lists

Every call goes through `ctf.platform.get_adapter` (the event profile's `[instances]` plugin and the
scope lock in `ctf.instances`); nothing here talks to the plugin directly, runs a model, or submits. An
event with no `[instances]` section, or one in manual mode, refuses loudly (exit 4).

The local slot cap (`[instances] cap`) binds across processes: every instance started through this CLI
is recorded in a flock-guarded slot ledger under the event's workdir (`ctf.instsched.SlotLedger`), and
`start` and `schedule` re-read those slots' live state and count them before starting anything, so
several solver subagents each running `start` cannot exceed the cap (exit 1, naming the held slots).
Instances started outside this CLI (the web UI) are not in the ledger; the plugin's own limit still
holds them.

The scheduler is `ctf.instsched`: `start` the highest-value open challenges within the cap, `stop` the
moment a challenge is solved (spawn-only-while-working, tear-down-on-solve). `--challenge` names the
container ids explicitly; without it, challenges tagged as containers are selected (plus every slot in
the ledger). `--profile` must name a file under the repo's events/ folder: a profile written elsewhere
could point the platform client, and its credentials, at another host.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .. import event as _event
from .. import instsched as _sched
from .. import paths as _paths
from ..platform import NotSupported, PlatformError, get_adapter, supports_instances

HELP = "start/stop/schedule per-team container instances (B-003)"
REFUSED_EXIT = 4
CAP_EXIT = 1

_now = time.time      # the wall clock the expiry arithmetic uses (the adapter's expires_at is an epoch)


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml under events/ (instead of --event)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sp = p.add_subparsers(dest="action", required=True)
    for verb in ("start", "status", "renew", "stop"):
        s = sp.add_parser(verb, help=f"{verb} our instance for one challenge")
        s.add_argument("id", help="challenge id")
    sp.add_parser("list", help="sweep the container challenges' instance state")
    sp.add_parser("stop-all", help="tear down every running instance we hold")
    sc = sp.add_parser("schedule", help="value-ordered slot schedule (start top-N, free on solve)")
    sc.add_argument("--challenge", action="append", dest="challenge", metavar="ID",
                    help="name a container challenge explicitly (repeatable); default: tag-selected")
    sc.add_argument("--cap", type=int, help="override the profile's local slot cap for this run")
    sc.add_argument("--renew-within", type=float, metavar="S",
                    help="also renew running unsolved instances expiring within S seconds")
    sc.add_argument("--dry-run", action="store_true", help="print the plan; start/stop/renew nothing")
    pm = sp.add_parser("permissions", help="print the solver harness allow/deny lists for this CLI")
    pm.add_argument("--python", default="python", help="interpreter the harness invokes (default: python)")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        root = _paths.events_root().resolve()
        path = Path(args.profile).expanduser().resolve()
        if not path.is_relative_to(root):
            raise _event.EventError(
                f"--profile {args.profile} is outside the repo's events/ folder; instance commands only "
                "load committed event profiles (use --event SLUG)")
        return _event.load_path(path)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _adapter(profile):
    gate = get_adapter(profile)
    if not supports_instances(gate):
        raise NotSupported(
            f"event {profile.slug!r} has no container-instance plugin: add an [instances] section to "
            "its event.toml (B-003), or this platform does not start per-team instances")
    return gate


def _cap(profile, override):
    if override is not None:
        return override
    return profile.instances.cap if profile.instances is not None else None


def _ledger(profile) -> _sched.SlotLedger:
    return _sched.SlotLedger(_sched.slot_ledger_path(_paths.workdir(profile.slug)))


def _warn_status(cid, e) -> None:
    print(f"ctf instance: status {cid}: {e} (slot kept counted)", file=sys.stderr)


def _fmt_info(info) -> str:
    state = getattr(info, "state", "?")
    connect = getattr(info, "connection_info", "") or "-"
    exp = getattr(info, "expires_at", None)
    tail = f"  (expires_at {exp:.0f})" if isinstance(exp, (int, float)) else ""
    return f"{state:<8} {connect}{tail}"


def _print_one(verb: str, cid: str, info, as_json: bool) -> None:
    if as_json:
        print(json.dumps({"op": verb, "challenge_id": cid, "state": getattr(info, "state", None),
                          "connect": getattr(info, "connection_info", "") or None,
                          "expires_at": getattr(info, "expires_at", None)}))
    else:
        print(f"{verb} {cid}: {_fmt_info(info)}")


def _one(gate, verb: str, cid: str, as_json: bool, profile=None) -> int:
    """One per-challenge op. `start` and `stop` go through the slot ledger (`profile` is required for
    them): start is refused at the cap counted across processes, stop frees the ledger slot."""
    if verb in ("start", "stop"):
        if profile is None:
            raise _sched.ScheduleError(f"{verb} needs the event profile (its slot ledger)")
        with _ledger(profile) as led:
            if verb == "start":
                info = _sched.start_capped(gate, led, cid, cap=_cap(profile, None),
                                           errors=PlatformError, on_error=_warn_status)
            else:
                info = _sched.stop_tracked(gate, led, cid)
    else:
        fn = {"status": gate.instance_status, "renew": getattr(gate, "renew_instance", None)}[verb]
        if fn is None:
            raise NotSupported("this event's plugin has no renew route (renew_instance is unavailable)")
        info = fn(cid)
    _print_one(verb, cid, info, as_json)
    return 0


def _sweep(gate, cids):
    """{cid: InstanceInfo} and the set of running ids, from one instance_status per challenge."""
    infos, running = {}, set()
    for cid in cids:
        try:
            info = gate.instance_status(cid)
        except PlatformError as e:
            infos[cid] = None
            print(f"ctf instance: status {cid}: {e}", file=sys.stderr)
            continue
        infos[cid] = info
        if getattr(info, "state", None) in _sched.LIVE_STATES:
            running.add(str(cid))
    return infos, running


def _selected(chs, only, tracked):
    """The container ids to act on: the explicit or tag-selected ones, plus every ledger slot that is on
    the board (so a slot held on an untagged challenge is still counted against the cap)."""
    base = [n.challenge_id for n in _sched.select_needs(chs, only=only)]
    board = {str(getattr(c, "id")) for c in chs}
    extra = sorted(c for c in tracked if c in board and c not in base)
    return base + extra


def _cmd_list(args, gate, profile) -> int:
    chs = gate.list_challenges()
    with _ledger(profile) as led:
        cids = _selected(chs, None, led.ids)
    if not cids:
        print("ctf instance: no container-tagged challenges on the board (name them with "
              "`schedule --challenge ID` if the board does not tag them)", file=sys.stderr)
        return 0
    infos, running = _sweep(gate, cids)
    cap = _cap(profile, None)
    if args.json:
        print(json.dumps({"cap": cap, "running": sorted(running),
                          "instances": {c: (getattr(infos[c], "state", None) if infos[c] else "error")
                                        for c in cids}}))
    else:
        print(f"cap: {cap if cap is not None else 'none'}   running: {len(running)}")
        for c in cids:
            info = infos[c]
            print(f"  {c}: {_fmt_info(info) if info else 'error (see stderr)'}")
    return 0


def _cmd_stop_all(args, gate, profile) -> int:
    chs = gate.list_challenges()
    stopped, failed = [], []
    with _ledger(profile) as led:
        cids = _selected(chs, None, led.ids)
        _, running = _sweep(gate, cids)
        for cid in sorted(running):
            try:
                _sched.stop_tracked(gate, led, cid)
                stopped.append(cid)
            except PlatformError as e:
                failed.append(cid)
                print(f"ctf instance: stop {cid}: {e}", file=sys.stderr)
    if args.json:
        print(json.dumps({"stopped": stopped, "failed": failed}))
    else:
        print(f"stopped {len(stopped)} instance(s): {', '.join(stopped) or '(none running)'}")
    return 1 if failed else 0


def _cmd_schedule(args, gate, profile) -> int:
    only = args.challenge
    renew_within = getattr(args, "renew_within", None)
    if renew_within is not None and renew_within < 0:
        raise _sched.ScheduleError(f"--renew-within must be >= 0, got {renew_within}")
    if renew_within is not None and getattr(gate, "renew_instance", None) is None:
        raise NotSupported("--renew-within asked for, but this event's plugin has no renew route "
                           "(renew_instance is unavailable)")
    chs = gate.list_challenges()
    with _ledger(profile) as led:
        cids = _selected(chs, only, led.ids)
        if not cids:
            print("ctf instance schedule: no container challenges selected (use --challenge ID for a "
                  "board that does not tag containers)", file=sys.stderr)
            return 1
        solved = {str(c.id) for c in chs if getattr(c, "solved_by_team", False)}
        infos, running = _sweep(gate, cids)
        for cid in sorted(led.ids):
            if cid in infos and infos[cid] is None:
                running.add(cid)             # unreadable ledger slot: assume it is still held
            elif cid in infos and cid not in running:
                led.discard(cid)             # the sweep shows it stopped: it no longer holds a slot
        now = _now()
        needs = [_sched.InstanceNeed(n.challenge_id, value=n.value, solved=n.solved, running=n.running,
                                     remaining_s=_sched.remaining_from(infos.get(n.challenge_id), now))
                 for n in _sched.select_needs(chs, only=cids, solved_ids=solved, running_ids=running)]
        cap = _cap(profile, args.cap)
        p = _sched.plan(needs, cap=cap)
        due = (_sched.due_for_renewal(needs, within_s=renew_within)
               if renew_within is not None else [])
        if args.dry_run:
            payload = {"cap": cap, "to_start": list(p.to_start), "to_stop": list(p.to_stop),
                       "keep": list(p.keep), "blocked": list(p.blocked), "to_renew": due}
            print(json.dumps(payload) if args.json
                  else f"plan (cap {cap if cap is not None else 'none'}): start {list(p.to_start)} "
                       f"stop {list(p.to_stop)} keep {list(p.keep)} blocked {list(p.blocked)} "
                       f"renew {due}")
            return 0
        actions = _sched.apply_plan(gate, p, errors=PlatformError)
        for a in actions:
            if a.ok and a.op == "start":
                led.add(a.challenge_id)
            elif a.ok and a.op == "stop":
                led.discard(a.challenge_id)
        actions += _sched.apply_renewals(gate, due, errors=PlatformError)
    failed = [a for a in actions if not a.ok]
    if args.json:
        print(json.dumps({"cap": cap, "actions": [{"op": a.op, "challenge_id": a.challenge_id,
                          "ok": a.ok, "connect": a.connect or None, "error": a.error} for a in actions],
                          "blocked": list(p.blocked)}))
    else:
        for a in actions:
            if a.ok:
                print(f"{a.op} {a.challenge_id}: ok{('  ' + a.connect) if a.connect else ''}")
            else:
                print(f"{a.op} {a.challenge_id}: FAILED {a.error}", file=sys.stderr)
        if p.blocked:
            print(f"blocked (no slot): {', '.join(p.blocked)}")
    return 1 if failed else 0


def _cmd_permissions(args) -> int:
    print(json.dumps(_sched.permission_profile(python=args.python), indent=2))
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "permissions":   # a static allowlist: no event/platform needed
            return _cmd_permissions(args)
        profile = _profile(args)
        gate = _adapter(profile)
        if args.action in ("start", "status", "renew", "stop"):
            return _one(gate, args.action, str(args.id), args.json, profile)
        if args.action == "list":
            return _cmd_list(args, gate, profile)
        if args.action == "stop-all":
            return _cmd_stop_all(args, gate, profile)
        if args.action == "schedule":
            return _cmd_schedule(args, gate, profile)
        raise _event.EventError(f"unknown action {args.action!r}")
    except NotSupported as e:
        print(f"ctf instance: refused: {e}", file=sys.stderr)
        return REFUSED_EXIT
    except _sched.CapReached as e:
        print(f"ctf instance: refused: {e}", file=sys.stderr)
        return CAP_EXIT
    except (_event.EventError, _sched.ScheduleError) as e:
        print(f"ctf instance: {e}", file=sys.stderr)
        return 2
    except PlatformError as e:
        print(f"ctf instance: {e}", file=sys.stderr)
        return 1
