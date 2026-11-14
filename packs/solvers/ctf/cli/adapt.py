"""`python -m ctf adapt` — the per-lane adaptation loop (B-036, docs/CONTRACTS.md section 29).

    python -m ctf adapt gate LANE...      [--no-warm] [--no-regate] [--cap S] [--recut F] [--json]
    python -m ctf adapt prewarm [LANE...] [--event SLUG]      every lane of the event when none is named
                                [--watch S [--duration S]]    keep going: re-gate a lane when its key changes
    python -m ctf adapt record LANE NAME --engine E --input FILE --expect LINE... [--mode M] [--within S]
                                         [--scope GLOB]... [--note N] [--force]
    python -m ctf adapt chain BASE_ID --lane LANE [--max-retries N] [--json]
    python -m ctf adapt mark CID --by teammate|hand [--note N]
    python -m ctf adapt attempt CID --outcome correct|incorrect|not_submitted|expired [--lane-key K]
    python -m ctf adapt qdiff BASE.json TIMED.json [--json]
    python -m ctf adapt replay ATTEMPT_DIR --solver FILE [--serial] [--stability | --profile] [--budget S] [--json]
    python -m ctf adapt rows LANE --rows DIR --solver FILE [--no-warm] [--budget S] [--json]
    python -m ctf adapt quiet [--json]                  running clocks and the replay policy they set

gate, prewarm and chain take --jobs N|auto (default auto: the deadline-aware quiet check's policy) and
--no-day-scope (key event cases on the whole engine folder). chain takes --artifact-sha256 (a same-artifact
retry); attempt takes --artifact-sha256, --missing N and --learned KEY (B-253).

Common: --workdir DIR (default: the event's), --root DIR (the checkout), --event SLUG (engines run with
CTF_EVENT=SLUG), --guard auto|os|hook. gate, prewarm and chain also take --idle-lock | --no-idle-lock
and --idle-timeout S: hold the idle-machine lock exclusive while cases replay (B-213, ctf.workreg;
default $CTF_IDLE_LOCK, else off; a timeout is an error naming the holder).

Exit codes. gate/prewarm: 0 every lane YES, 1 a lane NO, 3 a lane not run (never green), 2 an error.
chain: 0 start, retry or done; 1 stop; 3 wait or hold; 2 an error. qdiff: 0 nothing needs attention,
1 a change needs attention, 2 an unreadable body. record/mark/attempt: 0 recorded, 2 an error.
replay: 0 answered (stable, with --stability), 1 unstable or the pooled answers differ, 2 an error.
rows: 0 every row green or warm, 1 a row red, 2 an error. quiet: 0.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .. import event as _event
from .. import paths as _paths
from ..adapt import AdaptError
from ..adapt import chain as _chain
from ..adapt import clocks as _clocks
from ..adapt import qdiff as _qdiff
from ..adapt import regress as _regress
from ..adapt import replay as _replay
from ..intake import guard as _guard
from ..workreg import WorkRegError
from ._idle import add_idle_lock_args, idle_lock_factory

HELP = "the per-lane adaptation loop: warm lane gate, prewarm, event cases, timed chaining, qdiff"

_TAG = {_regress.PASS: "pass   ", _regress.WARM: "warm   ", _regress.FAIL: "FAIL   ",
        _regress.CUT: "CUT    ", _regress.NOT_RUN: "not-run"}


def _common(p: argparse.ArgumentParser, *, engines: bool = True) -> None:
    p.add_argument("--workdir", type=Path, metavar="DIR", help="the event workdir (default: ctf.paths.workdir())")
    p.add_argument("--root", type=Path, metavar="DIR", help="the checkout (default: this one)")
    if engines:
        p.add_argument("--event", metavar="SLUG", help="the event profile (engines run with CTF_EVENT=SLUG)")
        p.add_argument("--guard", choices=_guard.MODES, default="auto", help="network guard for the engines")


def _gate_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--cap", type=float, default=_regress.DEFAULT_CAP, help="per-run cap at idle load (s)")
    p.add_argument("--recut", type=float, default=_regress.RECUT_MIN, help="re-replay cap factor (>= 2)")
    p.add_argument("--max-scale", type=float, default=_regress.DEFAULT_MAX_SCALE, help="most the cap grows with load")
    p.add_argument("--no-warm", action="store_true", help="reuse no cached green result")
    p.add_argument("--no-regate", action="store_true", help="do not re-run a failing case before the lane stops")
    p.add_argument("--jobs", type=_jobs, default="auto", metavar="N|auto",
                   help="cases replayed at once (auto: 10 at nice 0, or 3 at nice 10 while a deadline clock runs)")
    p.add_argument("--no-day-scope", action="store_true",
                   help="key every event case on the whole engine folder (no lane-minus-dNN keys)")
    p.add_argument("--json", action="store_true")
    add_idle_lock_args(p)


def _jobs(v: str):
    if v == "auto":
        return v
    try:
        n = int(v)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{v!r}: a positive integer or auto") from None
    if n < 1:
        raise argparse.ArgumentTypeError(f"{v!r}: a positive integer or auto")
    return n


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="action", required=True)
    g = sub.add_parser("gate", help="replay lanes' regression sets: yes / no / not-run")
    g.add_argument("lanes", nargs="+", metavar="LANE")
    _common(g)
    _gate_opts(g)
    pw = sub.add_parser("prewarm", help="run the warm gate ahead of the clock (all event lanes by default)")
    pw.add_argument("lanes", nargs="*", metavar="LANE")
    pw.add_argument("--watch", type=float, metavar="S",
                    help="keep running: every S seconds re-gate each lane whose key changed (a live fix landed)")
    pw.add_argument("--duration", type=float, metavar="S", help="with --watch: stop after S seconds")
    _common(pw)
    _gate_opts(pw)
    r = sub.add_parser("record", help="record an accepted run as an event regression case")
    r.add_argument("lane")
    r.add_argument("name")
    r.add_argument("--engine", required=True)
    r.add_argument("--input", required=True, type=Path)
    r.add_argument("--expect", required=True, action="append", metavar="LINE")
    r.add_argument("--mode", default="base")
    r.add_argument("--within", type=float)
    r.add_argument("--scope", action="append", default=[], metavar="GLOB")
    r.add_argument("--note", default="")
    r.add_argument("--force", action="store_true")
    _common(r, engines=False)
    c = sub.add_parser("chain", help="the next step of a base's timed chain")
    c.add_argument("base_id")
    c.add_argument("--lane", required=True)
    c.add_argument("--max-retries", type=int, default=_chain.DEFAULT_RETRIES)
    c.add_argument("--artifact-sha256", help="the artifact a retry would replay (a same-artifact retry)")
    _common(c)
    _gate_opts(c)
    m = sub.add_parser("mark", help="record a close by a teammate or by hand")
    m.add_argument("challenge_id")
    m.add_argument("--by", required=True, choices=_chain.BY)
    m.add_argument("--note", default="")
    _common(m, engines=False)
    a = sub.add_parser("attempt", help="record a finished timed attempt's outcome")
    a.add_argument("challenge_id")
    a.add_argument("--outcome", required=True, choices=_chain.OUTCOMES)
    a.add_argument("--lane-key")
    a.add_argument("--note")
    a.add_argument("--artifact-sha256", help="sha256 of the delivery the solver ran on")
    a.add_argument("--missing", type=int, help="ids the solver left unanswered")
    a.add_argument("--learned", action="append", default=[], metavar="KEY", help="a key the attempt learned")
    _common(a, engines=False)
    q = sub.add_parser("qdiff", help="diff a timed start's questions against the base's")
    q.add_argument("before", type=Path)
    q.add_argument("after", type=Path)
    q.add_argument("--json", action="store_true")
    rp = sub.add_parser("replay", help="replay a saved attempt through the set pool (stability, profile)")
    rp.add_argument("attempt", type=Path, metavar="ATTEMPT_DIR")
    rp.add_argument("--solver", required=True, type=Path, help="the lane solver file (defines solve_set)")
    rp.add_argument("--serial", action="store_true", help="no set pool")
    how = rp.add_mutually_exclusive_group()
    how.add_argument("--stability", action="store_true", help="two replays at once in two interpreters, compared")
    how.add_argument("--profile", action="store_true", help="a profiled serial solve, then a pooled one")
    rp.add_argument("--budget", type=float, help="solve budget in seconds (default: none)")
    rp.add_argument("--json", action="store_true")
    _common(rp, engines=False)
    rw = sub.add_parser("rows", help="gate a lane's saved rows: pooled stability replays behind a per-prefix cache")
    rw.add_argument("lane")
    rw.add_argument("--rows", required=True, type=Path, metavar="DIR", help="folder of saved attempts")
    rw.add_argument("--solver", required=True, type=Path)
    rw.add_argument("--budget", type=float)
    rw.add_argument("--no-warm", action="store_true")
    rw.add_argument("--no-day-scope", action="store_true")
    rw.add_argument("--json", action="store_true")
    _common(rw, engines=False)
    qt = sub.add_parser("quiet", help="running clocks and the replay policy they set")
    qt.add_argument("--json", action="store_true")
    _common(qt, engines=False)


def _err(msg: str) -> int:
    print(f"ctf adapt: {msg}", file=sys.stderr)
    return 2


def _workdir(args) -> Path:
    if args.workdir:
        return args.workdir
    try:
        return _paths.workdir()
    except Exception as e:  # noqa: BLE001
        raise AdaptError(f"no workdir: pass --workdir, or set CTF_WORKDIR or CTF_EVENT ({e})") from None


def _profile(args):
    slug = getattr(args, "event", None)
    if not slug:
        return None
    try:
        return _event.load(slug)
    except _event.EventError as e:
        raise AdaptError(f"--event {slug}: {e}") from None


def _gate_kw(args, profile) -> dict:
    return dict(cap=args.cap, recut=args.recut, max_scale=args.max_scale, regate=not args.no_regate,
                guard=_guard.resolve(args.guard), profile=profile, jobs=args.jobs,
                idle=idle_lock_factory(args, args.root, f"adapt {args.action}"))


def _keyer(args) -> _regress.Keyer:
    return _regress.Keyer(args.root, day_scoped=not args.no_day_scope)


def _gate_json(g: _regress.LaneGate) -> dict:
    return {"lane": g.lane, "verdict": g.verdict, "reason": g.reason, "lane_key": g.lane_key,
            "seconds": round(g.seconds, 3), "cap": round(g.cap, 3), "scale": round(g.scale, 3), "notes": list(g.notes),
            "jobs": g.jobs, "nice": g.nice,
            "cases": [{"case": c.case, "mode": c.mode, "status": c.status, "reason": c.reason, "runs": c.runs,
                       "recut": c.recut, "regated": c.regated, "seconds": round(c.seconds, 3),
                       "exit_code": c.exit_code} for c in g.cases]}


def _print_gate(g: _regress.LaneGate) -> None:
    print(f"LANE {g.lane}: {g.verdict.upper()}  {len(g.cases)} case(s), ran {g.ran}, warm {g.count(_regress.WARM)}, "
          f"{g.seconds:.2f}s, cap {g.cap:.1f}s (x{g.scale:.2f} load), {g.jobs} at a time at nice {g.nice}")
    for c in g.cases:
        extra = " [recut]" if c.recut else " [re-gated]" if c.regated else ""
        print(f"  [{_TAG.get(c.status, c.status)}] {c.case:<40} {c.mode:<10} {c.reason}{extra}")
    for n in g.notes:
        print(f"  note: {n}")


def _gate_exit(results) -> int:
    if any(r.verdict == _regress.NO for r in results):
        return 1
    if any(r.verdict == _regress.NOT_RUN for r in results):
        return 3
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        return _run(args)
    except (AdaptError, _guard.GuardError, WorkRegError) as e:
        return _err(str(e))


def _run(args) -> int:
    if args.action == "qdiff":
        bodies = []
        for p in (args.before, args.after):
            try:
                bodies.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
                raise AdaptError(f"{p}: unreadable JSON ({type(e).__name__}: {e})") from None
        d = _qdiff.qdiff(*bodies)
        if args.json:
            print(json.dumps([{"what": c.what, "id": c.qid, "before": c.before, "after": c.after,
                               "attention": c.attention} for c in d.changes], indent=2))
        else:
            print("\n".join(d.lines()))
        return 1 if d.attention else 0

    wd = _workdir(args)
    if args.action == "record":
        c = _regress.record_case(args.lane, args.name, engine=args.engine, input_file=args.input, expect=args.expect,
                                 workdir=wd, root=args.root, mode=args.mode, within=args.within,
                                 scope=args.scope, note=args.note, force=args.force)
        print(f"recorded {c.lane}/{c.name} ({c.engine}, {c.mode}): {len(c.expect)} answer line(s), input {c.input}")
        return 0
    if args.action == "mark":
        _chain.mark_closed(args.challenge_id, by=args.by, note=args.note, workdir=wd)
        print(f"marked {args.challenge_id} closed by {args.by}")
        return 0
    if args.action == "attempt":
        _chain.record_attempt(args.challenge_id, args.outcome, lane_key=args.lane_key, note=args.note, workdir=wd,
                              artifact_sha256=args.artifact_sha256, missing=args.missing, learned=args.learned)
        print(f"recorded {args.challenge_id}: {args.outcome}")
        return 0
    if args.action == "quiet":
        return _quiet(args, wd)
    if args.action == "replay":
        return _replay_cmd(args, wd)
    if args.action == "rows":
        g = _replay.gate_rows(_replay.rows_in(args.rows), args.solver, workdir=wd, lane=args.lane,
                              keyer=_regress.Keyer(args.root, day_scoped=not args.no_day_scope),
                              budget=args.budget, warm=not args.no_warm)
        if args.json:
            print(json.dumps({"lane": g.lane, "verdict": g.verdict, "reason": g.reason, "seconds": round(g.seconds, 3),
                              "notes": list(g.notes),
                              "rows": [{"row": r.row, "status": r.status, "reason": r.reason, "days": list(r.days),
                                        "seconds": r.seconds, "stability": r.stability} for r in g.rows]}, indent=2))
        else:
            print(f"ROWS {g.lane}: {g.verdict.upper()}  {len(g.rows)} row(s), warm {g.count(_replay.WARM)}, "
                  f"{g.seconds:.2f}s")
            for r in g.rows:
                print(f"  [{r.status:<5}] {r.row:<40} days {','.join(r.days) or '-'}  {r.reason}")
            for n in g.notes:
                print(f"  note: {n}")
        return 0 if g.ok else 1

    profile = _profile(args)
    kw = _gate_kw(args, profile)
    if args.action == "chain":
        step = _chain.plan(args.base_id, args.lane, workdir=wd, root=args.root, max_retries=args.max_retries,
                           gate_kw=dict(kw, warm=not args.no_warm), keyer=_keyer(args),
                           artifact_sha256=args.artifact_sha256)
        if args.json:
            print(json.dumps({"base": step.base, "challenge_id": step.challenge_id, "mode": step.mode,
                              "action": step.action, "reason": step.reason, "closed": step.closed,
                              "lane_key": step.lane_key, "gate": _gate_json(step.gate) if step.gate else None},
                             indent=2))
        else:
            print(f"{step.action.upper()} {step.challenge_id or step.base}: {step.reason}")
            if step.gate:
                _print_gate(step.gate)
        return {"start": 0, "retry": 0, "done": 0, "stop": 1}.get(step.action, 3)

    lanes = args.lanes
    if getattr(args, "duration", None) is not None and getattr(args, "watch", None) is None:
        raise AdaptError("--duration needs --watch")
    if args.action == "prewarm" and not lanes:
        lanes = _regress.lanes_for(profile, root=args.root, workdir=wd)
        if not lanes:
            raise AdaptError("no lane to prewarm: no opener serves the event's categories and no event case is recorded")
    if args.action == "prewarm" and args.watch is not None:
        def show(g):
            _print_gate(g)
            sys.stdout.flush()
        try:
            results = _regress.watch(lanes, interval=args.watch, duration=args.duration, root=args.root, workdir=wd,
                                     on_gate=show if not args.json else None, day_scoped=not args.no_day_scope, **kw)
        except KeyboardInterrupt:
            return 130
        if args.json:
            print(json.dumps([_gate_json(g) for g in results], indent=2))
        return _gate_exit(results)
    keyer = _keyer(args)
    results = [_regress.gate(lane, root=args.root, workdir=wd, warm=not args.no_warm, keyer=keyer, **kw)
               for lane in lanes]
    if args.json:
        print(json.dumps([_gate_json(g) for g in results], indent=2))
    else:
        for g in results:
            _print_gate(g)
    return _gate_exit(results)


def _quiet(args, wd: Path) -> int:
    clocks = _clocks.running(wd)
    pol = _clocks.replay_policy(wd)
    if args.json:
        print(json.dumps({"busy": pol.busy, "jobs": pol.jobs, "nice": pol.nice, "reason": pol.reason,
                          "clocks": [{"challenge_id": c.challenge_id, "pid": c.pid, "deadline": c.deadline,
                                      "started": c.started} for c in clocks]}, indent=2))
        return 0
    print(f"{'BUSY' if pol.busy else 'IDLE'}: replays {pol.jobs} at a time at nice {pol.nice} ({pol.reason})")
    now = time.time()
    for c in clocks:
        dl = "no deadline" if c.deadline is None else f"deadline in {c.deadline - now:.1f}s"
        print(f"  clock {c.challenge_id}  pid {c.pid}  {dl}")
    return 0


def _replay_cmd(args, wd: Path) -> int:
    if args.stability:
        st = _replay.stability(args.attempt, args.solver, workdir=wd, budget=args.budget, pooled=not args.serial)
        if args.json:
            print(json.dumps({"status": st.status, "reason": st.reason, "seconds": round(st.seconds, 3),
                              "diffs": {k: list(v) for k, v in st.diffs.items()},
                              "runs": [r.to_json() for r in st.runs]}, indent=2, default=str))
        else:
            print(f"STABILITY {st.status.upper()} in {st.seconds:.2f}s" + (f": {st.reason}" if st.reason else ""))
            for i, r in enumerate(st.runs, 1):
                print(f"  replay {i}: {len(r.answers)} answer(s), {r.seconds:.2f}s wall, {r.cpu:.2f}s cpu, "
                      f"pooled {len(r.pooled)} serial {len(r.serial)}")
        return 0 if st.stable else (1 if st.status == _replay.UNSTABLE else 2)
    if args.profile:
        pr = _replay.profile_attempt(args.attempt, args.solver, args.budget, pooled=not args.serial)
        hv = pr.heaviest
        if args.json:
            print(json.dumps({"sets": pr.sets, "deliveries": pr.deliveries, "workers": pr.workers,
                              "serial_seconds": round(pr.serial_seconds, 4), "serial_cpu": round(pr.serial_cpu, 4),
                              "per_set": {str(k): round(v, 4) for k, v in pr.per_set.items()},
                              "pooled": pr.pooled.to_json() if pr.pooled else None, "equal": pr.equal,
                              "top": pr.top}, indent=2, default=str))
        else:
            print(f"PROFILE {pr.sets} set(s), {pr.deliveries} delivery file(s), the pool would fork {pr.workers}")
            print(f"  serial {pr.serial_seconds:.2f}s wall {pr.serial_cpu:.2f}s cpu; heaviest set {hv[0]} {hv[1]:.2f}s")
            if pr.pooled:
                print(f"  pooled {pr.pooled.seconds:.2f}s wall {pr.pooled.cpu:.2f}s cpu; answers "
                      f"{'equal' if pr.equal else 'DIFFER'}")
            print("\n".join("  " + ln for ln in pr.top))
        return 0 if pr.equal else 1
    run = _replay.replay_attempt(args.attempt, args.solver, args.budget, pooled=not args.serial)
    if args.json:
        print(json.dumps(run.to_json(), indent=2, default=str))
    else:
        print(f"REPLAY {len(run.answers)} answer(s) in {run.seconds:.2f}s wall {run.cpu:.2f}s cpu; "
              f"pooled {len(run.pooled)} set(s), serial {len(run.serial)}")
        for n in run.notes:
            print(f"  note: {n}")
    return 0
