"""ctf governor -- the host resource governor (B-176): load, RAM, battery, thermal state and disk.

    python -m ctf governor status [--json] [--disk-path P]
    python -m ctf governor check [--strict] [--measure S] [--json] [--disk-path P]
    python -m ctf governor run [--label L] [--timeout S] [--poll S] -- CMD [ARGS...]
    python -m ctf governor watch [--once] [--interval S] [--duration S] [--notify]
    python -m ctf governor measure [--interval S] [--json]
    python -m ctf governor disk --need SIZE [--path P] [--min-free SIZE]
    python -m ctf governor copy SRC DST [--min-free SIZE]
    python -m ctf governor evict [--workdir DIR] [--min-mb N] [--apply] [--json]
    python -m ctf governor spotlight DIR [--apply]

`status` reads the host and says how many heavy agents may start now and which limit binds. `check` is
the same as doctor checks (load, RAM, battery, thermal, disk, governor slots, agent RSS, and with
`--measure` the measured per-agent RAM/CPU budget for CTF_CAPACITY_*). `run` waits in the host-wide
queue until the governor admits it, runs CMD holding one heavy slot, and frees the slot when CMD exits.
`watch` alerts (never kills) when an agent tree's RSS crosses CTF_GOVERNOR_RSS_ALERT_MB. `disk` and
`copy` are the disk-budget preflight and the copier that rejects symlinks. `evict` lists (and with
`--apply` deletes) large non-writeup files in challenges whose flag was accepted. `spotlight` reports
(and with `--apply` writes) the Spotlight exclusion marker for a worktree folder.

Exit codes: 0 ok; 1 a check failed / an alert fired / the disk budget refused / a folder is still
indexed; 2 a named error (bad setting, unreadable host, no agent to measure); 3 `run` not admitted
within --timeout. `run` otherwise exits with CMD's own code.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path

from .. import diskguard as _dg
from .. import doctor as _doctor
from .. import governor as _gov
from .. import paths as _paths

HELP = "host resource governor: cap heavy agents by load/RAM/battery/thermal/disk, RSS watchdog, disk guards"

TIMEOUT_EXIT = 3


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    s = sp.add_parser("status", help="host readings and heavy-agent slots free now")
    s.add_argument("--json", action="store_true")
    s.add_argument("--disk-path", help="where free disk is measured (default: the event workdir)")
    c = sp.add_parser("check", help="the governor's doctor checks")
    c.add_argument("--strict", action="store_true", help="warn and skip (unread) fail too")
    c.add_argument("--measure", type=float, metavar="S", help="also measure agent RAM/CPU over S seconds")
    c.add_argument("--json", action="store_true")
    c.add_argument("--disk-path")
    r = sp.add_parser("run", help="wait for a heavy-agent slot, run CMD holding it, then free it")
    r.add_argument("--label", default="", help="what this slot is for (shown in status)")
    r.add_argument("--timeout", type=float, help="give up after S seconds waiting (exit 3)")
    r.add_argument("--poll", type=float, default=5.0, help="seconds between admission checks")
    r.add_argument("--disk-path")
    r.add_argument("cmd", nargs=argparse.REMAINDER, help="-- CMD [ARGS...]")
    w = sp.add_parser("watch", help="alert when an agent tree's RSS crosses the threshold")
    w.add_argument("--once", action="store_true", help="one scan; exit 1 when an alert fires")
    w.add_argument("--interval", type=float, default=30.0)
    w.add_argument("--duration", type=float, help="stop after S seconds (default: run until stopped)")
    w.add_argument("--notify", action="store_true", help="also raise a macOS notification per alert")
    m = sp.add_parser("measure", help="measure per-agent RAM and CPU of the running agents")
    m.add_argument("--interval", type=float, default=10.0)
    m.add_argument("--json", action="store_true")
    d = sp.add_parser("disk", help="disk-budget preflight: is there room for SIZE more?")
    d.add_argument("--need", required=True, help="bytes the job will write (500M, 2G, ...)")
    d.add_argument("--path", help="where it will write (default: the event workdir)")
    d.add_argument("--min-free", help="free space that must remain (default CTF_GOVERNOR_DISK_MIN_GB)")
    cp = sp.add_parser("copy", help="copy a folder, refusing symlinks, after a disk preflight")
    cp.add_argument("src")
    cp.add_argument("dst")
    cp.add_argument("--min-free", help="free space that must remain (default CTF_GOVERNOR_DISK_MIN_GB)")
    e = sp.add_parser("evict", help="large artifacts of accepted challenges (dry run unless --apply)")
    e.add_argument("--workdir", help="event workdir (default: the current event's)")
    e.add_argument("--min-mb", type=int, help="smallest file to evict, MiB (default CTF_GOVERNOR_EVICT_MIN_MB "
                                              f"or {_dg.DEFAULT_EVICT_MIN_MB})")
    e.add_argument("--apply", action="store_true", help="delete them (default: list only)")
    e.add_argument("--json", action="store_true")
    sl = sp.add_parser("spotlight", help="is a worktree folder kept out of Spotlight?")
    sl.add_argument("dir")
    sl.add_argument("--apply", action="store_true", help="write the .metadata_never_index marker")


def _disk_path(arg: str | None) -> tuple[Path, str]:
    if arg:
        return Path(arg), "--disk-path"
    try:
        return _paths.workdir(), "event workdir"
    except Exception as e:  # no event resolvable: say so and measure the governor's own folder
        return _paths.governor_state(), f"governor state (no event workdir: {e})"


def _governor(disk: Path, policy: _gov.GovernorPolicy) -> _gov.Governor:
    return _gov.Governor(_paths.governor_state(), policy, probe=lambda: _gov.probe_host(disk))


def _print_state(state: _gov.HostState, decision: _gov.Decision, where: str) -> None:
    b, t = state.battery, state.thermal
    print(f"load: {state.load1:.1f} {state.load5:.1f} {state.load15:.1f} on {state.cpu_count} CPUs "
          f"({state.load_per_cpu:.2f}/CPU)")
    print(f"ram: {state.available_ram_bytes / _gov.GiB:.1f} of {state.total_ram_bytes / _gov.GiB:.1f} GiB "
          f"available, pressure {state.pressure or 'unread'}")
    if b is None:
        print("battery: unread")
    elif not b.present:
        print("battery: none")
    else:
        print(f"battery: {b.percent:.0f}%, {'plugged in' if b.plugged else 'on battery'}, "
              f"{b.state or 'state unread'}")
    print("thermal: unread" if t is None else
          f"thermal: warning {t.warning_level}, performance {t.performance_level}, "
          f"speed limit {t.speed_limit if t.speed_limit is not None else 100}%")
    print(f"disk: {state.disk_free_bytes / _gov.GiB:.1f} GiB free at {state.disk_path} ({where})")
    for name, why in state.unknown:
        print(f"UNREAD {name}: {why}")
    print(f"heavy agents: {decision.running} running, cap {decision.cap}, {decision.slots} slot(s) free")
    print(f"binding: {decision.reason}")


def _status(args) -> int:
    policy = _gov.GovernorPolicy.from_env()
    disk, where = _disk_path(args.disk_path)
    g = _governor(disk, policy)
    d = g.decision()
    state = g.last_state
    leases, queue = g.leases(), g.queue()
    if args.json:
        print(json.dumps({"host": state.to_dict(), "decision": d.to_dict(),
                          "leases": [{"id": l.id, "pid": l.pid, "label": l.label, "started": l.started}
                                     for l in leases],
                          "queued": len(queue), "reaped": g.reaped, "disk_basis": where}))
        return 0
    _print_state(state, d, where)
    for l in leases:
        print(f"  slot {l.id} pid {l.pid} {l.label}")
    if queue:
        print(f"queued: {len(queue)}")
    for r in g.reaped:
        print(f"reaped stale {r}")
    return 0


def _check(args) -> int:
    policy = _gov.GovernorPolicy.from_env()
    if args.strict:
        policy = replace(policy, strict=True)
    disk, where = _disk_path(args.disk_path)
    g = _governor(disk, policy)
    state = _gov.probe_host(disk)
    d = _gov.decide(state, policy, len(g.leases()))
    procs, unreadable = _gov.snapshot_processes()
    trees = _gov.agent_trees(procs, policy.agent_names)
    meas, merr = None, ""
    if args.measure:
        time.sleep(args.measure)
        after, _ = _gov.snapshot_processes()
        try:
            meas = _gov.measure(procs, after, args.measure, policy.agent_names)
        except _gov.GovernorError as e:
            merr = str(e)
    checks = _gov.host_checks(state, d, policy, trees, meas, merr)
    bad = _doctor.failed(checks, strict=args.strict)
    if args.json:
        print(json.dumps({"passed": not bad, "strict": args.strict, "disk_basis": where,
                          "unreadable_processes": unreadable,
                          "checks": [c.to_dict() for c in checks]}, indent=1))
    else:
        for c in checks:
            print(c.line())
        if unreadable:
            print(f"note: {unreadable} process(es) could not be read (other users' or gone mid-scan)")
        print("HOST " + ("OK" if not bad else f"FAILED: {', '.join(c.name for c in bad)}"))
    return 1 if bad else 0


def _run(args) -> int:
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("ctf governor run: no command given (use: ctf governor run -- CMD ...)", file=sys.stderr)
        return 2
    policy = _gov.GovernorPolicy.from_env()
    disk, where = _disk_path(args.disk_path)
    if not args.disk_path and where != "event workdir":
        print(f"ctf governor run: disk floor measured at {disk}: {where}", file=sys.stderr)
    g = _governor(disk, policy)
    told = {"pos": None}

    def on_wait(d: _gov.Decision, pos: int) -> None:
        if told["pos"] != pos:
            told["pos"] = pos
            print(f"ctf governor: queued (position {pos + 1}): {d.running} running, cap {d.cap} "
                  f"({d.reason})", file=sys.stderr)

    try:
        lease = g.acquire(args.label or " ".join(cmd)[:80], timeout=args.timeout, poll=args.poll,
                          on_wait=on_wait)
    except _gov.GovernorTimeout as e:
        print(f"ctf governor run: {e}", file=sys.stderr)
        return TIMEOUT_EXIT
    try:
        return subprocess.run(cmd).returncode
    finally:
        g.release(lease)


_SAFE = re.compile(r"[^A-Za-z0-9 .,:()/%=+-]")


def _notify(text: str, run=subprocess.run) -> None:
    msg = _SAFE.sub("", text)[:200]
    run(["osascript", "-e", f'display notification "{msg}" with title "ctf governor"'],
        capture_output=True, timeout=10)


def _watch(args) -> int:
    policy = _gov.GovernorPolicy.from_env()
    if args.notify and sys.platform != "darwin":
        print("ctf governor watch: --notify needs macOS (osascript)", file=sys.stderr)
        return 2
    if args.interval <= 0:
        print("ctf governor watch: --interval must be > 0", file=sys.stderr)
        return 2
    import psutil
    total = int(psutil.virtual_memory().total)
    start = time.time()
    fired = False
    while True:
        procs, _ = _gov.snapshot_processes()
        trees = _gov.agent_trees(procs, policy.agent_names)
        alerts = _gov.rss_alerts(trees, policy, total)
        _gov.record_alerts(_paths.governor_state(), alerts)
        for a in alerts:
            fired = True
            print(f"ALERT {a}", file=sys.stderr)
            if args.notify:
                _notify(a)
        if args.once:
            if not alerts:
                print(f"ok: {len(trees)} agent tree(s), none at {policy.rss_alert_mb} MiB")
            return 1 if fired else 0
        if args.duration is not None and time.time() - start >= args.duration:
            return 1 if fired else 0
        time.sleep(args.interval)


def _measure(args) -> int:
    policy = _gov.GovernorPolicy.from_env()
    before, _ = _gov.snapshot_processes()
    time.sleep(args.interval)
    after, unreadable = _gov.snapshot_processes()
    m = _gov.measure(before, after, args.interval, policy.agent_names)
    if args.json:
        print(json.dumps({**m.to_dict(), "unreadable_processes": unreadable}))
        return 0
    print(f"{m.agents} agent(s) over {m.interval:g} s: RSS MiB {list(m.rss_mib)}, CPU % {list(m.cpu_percent)}")
    print(f"set CTF_CAPACITY_AGENT_RAM_MB={m.per_agent_ram_mb}"
          + (f" CTF_CAPACITY_AGENTS_PER_CPU={m.agents_per_cpu}" if m.agents_per_cpu is not None
             else "  (no CPU used in the interval: agents-per-CPU not measured)"))
    return 0


def _min_free(arg: str | None, policy: _gov.GovernorPolicy) -> int:
    return _dg.parse_size(arg) if arg else int(policy.disk_min_gb * _gov.GiB)


def _disk(args) -> int:
    policy = _gov.GovernorPolicy.from_env()
    path = Path(args.path) if args.path else _paths.workdir()
    v = _dg.disk_preflight(path, _dg.parse_size(args.need), _min_free(args.min_free, policy))
    print(("ok: " if v.ok else "REFUSED: ") + v.reason, file=sys.stdout if v.ok else sys.stderr)
    return 0 if v.ok else 1


def _copy(args) -> int:
    policy = _gov.GovernorPolicy.from_env()
    try:
        n = _dg.safe_copytree(args.src, args.dst, min_free_bytes=_min_free(args.min_free, policy))
    except (_dg.SymlinkRejected, _dg.DiskBudgetError) as e:
        print(f"ctf governor copy: {e}", file=sys.stderr)
        return 1
    print(f"copied {n} bytes to {args.dst}")
    return 0


def _evict(args) -> int:
    from .. import env as _env
    wd = Path(args.workdir) if args.workdir else _paths.workdir()
    min_mb = args.min_mb if args.min_mb is not None else _env.get_int(
        "CTF_GOVERNOR_EVICT_MIN_MB", _dg.DEFAULT_EVICT_MIN_MB)
    plan = _dg.eviction_plan(wd, min_bytes=min_mb * _dg.MiB)
    done = _dg.apply_eviction(plan, wd) if args.apply else []
    if args.json:
        print(json.dumps({"applied": args.apply, "challenges": list(plan.challenges), "kept": plan.kept,
                          "bytes": plan.bytes,
                          "files": [{"challenge": f.challenge, "path": str(f.path), "size": f.size,
                                     "accepted": f.why_accepted} for f in plan.files],
                          "results": done}))
        return 0
    verb = "evicted" if args.apply else "would evict"
    for f in plan.files:
        print(f"{verb} {f.path} ({f.size / _dg.MiB:.0f} MiB; {f.challenge}, accepted by {f.why_accepted})")
    for r in done:
        if r["action"] != "evicted":
            print(f"skipped {r['challenge']}/{r['path']}: {r['reason']}", file=sys.stderr)
    print(f"{len(plan.files)} file(s), {plan.bytes / _dg.GiB:.2f} GiB in {len(plan.challenges)} accepted "
          f"challenge(s); {plan.kept} large writeup/script file(s) kept"
          + ("" if args.apply else "  (dry run: --apply deletes)"))
    return 0


def _spotlight(args) -> int:
    st = _dg.exclude_from_spotlight(args.dir) if args.apply else _dg.spotlight_status(args.dir)
    print(("excluded: " if st.excluded else "INDEXED: ") + st.detail)
    return 0 if st.excluded else 1


_ACTIONS = {"status": _status, "check": _check, "run": _run, "watch": _watch, "measure": _measure,
            "disk": _disk, "copy": _copy, "evict": _evict, "spotlight": _spotlight}


def run(args: argparse.Namespace) -> int:
    try:
        return _ACTIONS[args.action](args)
    except (_gov.GovernorError, _dg.DiskGuardError) as e:
        print(f"ctf governor {args.action}: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        from .. import env as _env
        from ..event import EventError
        if isinstance(e, (_env.EnvError, EventError)):
            print(f"ctf governor {args.action}: {e}", file=sys.stderr)
            return 2
        raise
