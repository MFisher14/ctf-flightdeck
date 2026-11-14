"""ctf helpers watch | arm | deliver | status | check -- no-model helper launch on a lane STOP (B-212, ctf/helpers.py).

    python -m ctf helpers watch [--once] [--duration S] [--poll S] [--from-start] [--json]
    python -m ctf helpers arm (--lane-plan PLAN.json | --matrix MATRIX --report R.json) [--json] [--no-record]
    python -m ctf helpers deliver ID [--outcome delivered|failed] [--note TEXT]
    python -m ctf helpers status [--json]
    python -m ctf helpers check

Common: --workdir DIR (default: ctf.paths.workdir()), --config FILE (default <workdir>/helpers.toml).

`watch` tails the event ledger with no model: on a lane STOP (an `adapt.chain` stop or an `adapt.gate`
verdict no) it starts a helper from the lane's warm brief -- handed to a warm helper agent waiting on
`ctf standby take --pool helpers`, else launched cold through the campaign's fenced launcher -- and when a
helper delivers it records it and re-plans the chain (`adapt chain plan`) for every base waiting on the
lane. `--once` is one pass. `arm` prints which lanes get warm helper agents (only where the look-ahead
forecast predicts work, or the lane is configured warm) with each agent's argv; launching them is the
orchestrator's step. `deliver` is what a helper runs when its fix is in. `check` validates the config and
that every configured lane has its warm brief.

Exit codes: 0 ok; 1 watch --once with an error recorded, arm/check with a lane missing its warm brief;
2 an error (bad config, unreadable state or ledger, unknown helper).
"""
from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

from .. import helpers as _helpers
from .. import paths as _paths

HELP = "no-model helper launch on a lane STOP, warm standby only where predicted"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    w = sp.add_parser("watch", help="tail the ledger: launch helpers on a lane STOP, integrate deliveries")
    w.add_argument("--once", action="store_true", help="one pass, then exit")
    w.add_argument("--duration", type=float, default=None, help="stop after this many seconds")
    w.add_argument("--poll", type=float, default=1.0, help="seconds between passes (default 1)")
    w.add_argument("--from-start", action="store_true",
                   help="on a first start, read the ledger from its beginning instead of its end")
    w.add_argument("--json", action="store_true", help="one JSON object per pass that did something")
    a = sp.add_parser("arm", help="which lanes get warm helper agents (from the look-ahead plan)")
    src = a.add_mutually_exclusive_group(required=True)
    src.add_argument("--lane-plan", type=Path, help="`ctf lookahead plan --json` output")
    src.add_argument("--matrix", type=Path, help="the look-ahead matrix (with --report)")
    a.add_argument("--report", type=Path, help="the look-ahead gate report (lookahead gate --report-out)")
    a.add_argument("--json", action="store_true")
    a.add_argument("--no-record", action="store_true", help="write no helpers.arm ledger record")
    d = sp.add_parser("deliver", help="hand a helper's work back: the watcher integrates and resumes")
    d.add_argument("id")
    d.add_argument("--outcome", choices=_helpers.OUTCOMES, default=_helpers.DELIVERED)
    d.add_argument("--note", default=None)
    s = sp.add_parser("status", help="the helpers and each lane's launch count")
    s.add_argument("--json", action="store_true")
    sp.add_parser("check", help="validate the config and every configured lane's warm brief")
    for x in (w, a, d, s, sp.choices["check"]):
        x.add_argument("--workdir", type=Path, metavar="DIR")
        x.add_argument("--config", type=Path, metavar="FILE")


def _workdir(args) -> Path:
    return Path(args.workdir) if args.workdir else _paths.workdir()


def _config(args, wd: Path) -> _helpers.Config:
    return _helpers.load_config(args.config or _helpers.config_path(wd))


def _watch(args) -> int:
    wd = _workdir(args)
    w = _helpers.Watcher(wd, _config(args, wd), start="beginning" if args.from_start else "end")
    errors = 0

    def show(r: _helpers.TickReport) -> None:
        nonlocal errors
        errors += len(r.errors)
        if r.empty():
            return
        if args.json:
            print(json.dumps(r.__dict__, ensure_ascii=False), flush=True)
        else:
            for line in r.lines():
                print(line, flush=True)

    if args.once:
        show(w.tick())
        return 1 if errors else 0
    w.run(poll=args.poll, duration=args.duration, on_report=show)
    return 0


def _lane_plans(args) -> list:
    if args.lane_plan is not None:
        try:
            body = json.loads(Path(args.lane_plan).read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise _helpers.HelperError(f"{args.lane_plan}: unreadable lane plan ({e})") from None
        if not isinstance(body, list):
            raise _helpers.HelperError(f"{args.lane_plan}: a lane plan is a JSON list (ctf lookahead plan --json)")
        return body
    if args.report is None:
        raise _helpers.HelperError("--matrix needs --report (the look-ahead gate report)")
    from .lookahead import plans_from_matrix       # the same plan `ctf lookahead plan` prints
    return plans_from_matrix(args.matrix, args.report)


def _arm(args) -> int:
    wd = _workdir(args)
    plan = _helpers.arm(_lane_plans(args), _config(args, wd), workdir=wd, record=not args.no_record)
    if args.json:
        print(json.dumps({"lanes": [w.__dict__ for w in plan.lanes], "missing_briefs": plan.missing_briefs},
                         ensure_ascii=False, default=list))
    else:
        for line in plan.lines():
            print(line)
        for a in plan.warm_agents:
            print(f"{a['agent']}\t{shlex.join(a['argv'])}")
    for lane in plan.missing_briefs:
        print(f"ctf helpers: lane {lane} has no warm brief: a STOP there launches nothing", file=sys.stderr)
    return 1 if plan.missing_briefs else 0


def _deliver(args) -> int:
    wd = _workdir(args)
    _helpers.deliver(wd, args.id, outcome=args.outcome, note=args.note)
    print(f"{args.id}: {args.outcome} recorded; the watcher integrates it and resumes the chain")
    return 0


def _status(args) -> int:
    st = _helpers.status(_workdir(args))
    if args.json:
        print(json.dumps(st, ensure_ascii=False))
        return 0
    print(f"helpers {len(st['helpers'])}  open {len(st['open'])}  ledger cursor {st['offset']}")
    for h in st["helpers"]:
        who = f" by {h['agent']}" if h.get("agent") else ""
        print(f"  {h['id']} [{h['lane']}] {h['status']} ({h.get('mode')}){who} "
              f"bases={','.join(h.get('bases') or []) or '-'}")
    for lane, ln in sorted(st["lanes"].items()):
        print(f"  lane {lane}: {ln.get('launched', 0)} launched since healthy"
              + (" (CAPPED)" if ln.get("capped") else ""))
    return 0


def _check(args) -> int:
    wd = _workdir(args)
    cfg = _config(args, wd)
    missing = []
    for lane in sorted(cfg.lanes):
        bp = cfg.brief_path(lane, wd)
        ok = bp.is_file()
        print(f"{'ok  ' if ok else 'MISS'} {lane} [{cfg.lane(lane).mode}] brief {bp}")
        if not ok:
            missing.append(lane)
    print(f"config {cfg.path}: launcher {shlex.join(cfg.launcher)} ({cfg.harness}), handoff_wait "
          f"{cfg.handoff_wait:g}s, max_per_lane {cfg.max_per_lane}")
    return 1 if missing else 0


def run(args: argparse.Namespace) -> int:
    from ..event import EventError
    from ..lookahead import LookaheadError
    try:
        return {"watch": _watch, "arm": _arm, "deliver": _deliver, "status": _status,
                "check": _check}[args.action](args)
    except (_helpers.HelperError, EventError, LookaheadError) as e:
        print(f"ctf helpers: {e}", file=sys.stderr)
        return 2
