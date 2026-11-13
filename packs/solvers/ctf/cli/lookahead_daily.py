"""`python -m ctf lookahead-daily` — the daily look-ahead of a rolling-release event (B-256,
docs/CONTRACTS.md section 35).

    python -m ctf lookahead-daily prepare --matrix M --out DIR --day D [--event SLUG | --profile F] [--report R.json]
            [--tagged LANE --tag TAG [--families a,b] [--containers a,b] [--question-id ID]]...
            [--computed LANE]... [--seed S] [--repo DIR] [--agent-cap N] [--json]
    python -m ctf lookahead-daily finish --plan DIR/D/plan.json [--result RESULT.json]
            [--previous-forecast F.toml] [--json]

prepare is the no-model half before the workflow: it refuses an event that is not rolling-release,
stages the tagged-copy specimens (ctf.lookahead.tagged) and the computed-field specimens
(ctf.lookahead.fixtures) into the matrix, plans the lanes (forecast.plan over the event profile's
lanes), writes DIR/D/plan.json and, when a lane needs an agent, DIR/D/workflow-args.json, and runs the
day-lookahead workflow's pre-launch check on those args. Then launch workflows/day-lookahead.js with the
Workflow tool and save its return value as JSON.

finish writes DIR/D/README.md (every lane named; `<lane>: NOT staged` with its last forecast for a lane
whose agent returned nothing twice) and DIR/D/forecast.toml (the staged lanes' globs, which
`ctf lookahead score` scores the next day).

Exit codes. prepare: 0 args written and checked (launch the workflow), 1 no lane needs an agent (run
finish without --result), 2 an error. finish: 0 every planned lane staged, 1 a lane NOT staged, 2 an
error. Nothing here starts a model or talks to a platform.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import paths as _paths
from .. import workflows as _wf
from ..adapt import qdiff as _qdiff
from ..lookahead import LookaheadError
from ..lookahead import daily as _daily
from ..lookahead import fixtures as _fixtures
from ..lookahead import tagged as _tagged

HELP = "the daily look-ahead of a rolling-release event: plan + no-model staging, then README + forecast"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="action", required=True)
    p = sub.add_parser("prepare", help="stage specimens (no model), plan the lanes, write the workflow args")
    p.add_argument("--matrix", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True, help="the look-ahead folder; the day's is OUT/DAY")
    p.add_argument("--day", required=True)
    ev = p.add_mutually_exclusive_group()
    ev.add_argument("--event", help="event slug (default: the current event)")
    ev.add_argument("--profile", type=Path, help="an event.toml to read instead of a slug")
    p.add_argument("--report", type=Path, help="the last gate report (lookahead gate --report-out)")
    p.add_argument("--tagged", action="append", default=[], metavar="LANE",
                   help="stage the tagged-copy containers into LANE (needs --tag)")
    p.add_argument("--tag", help="the event's tag for the tagged copy (no default)")
    p.add_argument("--families", help="comma-separated families (default: all)")
    p.add_argument("--containers", help="comma-separated containers (default: all)")
    p.add_argument("--question-id", default=_tagged.DEFAULT_QID)
    p.add_argument("--computed", action="append", default=[], metavar="LANE",
                   help="stage the computed-field fixtures into LANE")
    p.add_argument("--seed", help="staging seed (default: the day label)")
    p.add_argument("--repo", type=Path, help="the checkout the agents read (default: this checkout)")
    p.add_argument("--agent-cap", type=int)
    p.add_argument("--json", action="store_true")
    f = sub.add_parser("finish", help="README naming every lane, and forecast.toml for scoring")
    f.add_argument("--plan", type=Path, required=True)
    f.add_argument("--result", type=Path, help="the day-lookahead workflow's return value (JSON)")
    f.add_argument("--previous-forecast", type=Path)
    f.add_argument("--json", action="store_true")


def _read_json(path: Path, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise LookaheadError(f"{what} {path}: not there") from None
    except (OSError, ValueError) as e:
        raise LookaheadError(f"{what} {path}: not readable JSON ({e})") from None


def _csv(v):
    return [x.strip() for x in v.split(",") if x.strip()] if v else None


def _prepare(args) -> int:
    if args.profile:
        profile = _event.load_path(args.profile)
    else:
        profile = _event.load(args.event) if args.event else _event.current()
    _daily.require_rolling(profile)
    day = _daily.check_day(args.day)
    lanes = _daily.profile_lanes(profile)
    seed = args.seed if args.seed is not None else day
    if args.tagged and not args.tag:
        raise LookaheadError("--tagged needs --tag (the event's tag; there is no default)")
    staged: dict[str, list] = {}
    for lane in args.tagged + args.computed:
        if lane not in lanes:
            raise LookaheadError(f"staging lane {lane!r} is not a lane of event {profile.slug!r} "
                                 f"(its lanes: {', '.join(lanes)})")
    for lane in args.tagged:
        staged.setdefault(lane, []).extend(_tagged.stage(
            args.matrix, lane, args.tag, seed=seed, families=_csv(args.families),
            containers=_csv(args.containers), question_id=args.question_id))
    for lane in args.computed:
        staged.setdefault(lane, []).extend(_fixtures.stage_computed(args.matrix, lane, seed=seed))
    reports = None
    if args.report:
        body = _read_json(args.report, "report")
        reports = body if isinstance(body, list) else [body]
    plans = _daily.plan_day(profile, args.matrix, reports)
    doc = _daily.plan_doc(profile, plans, day=day, matrix_dir=args.matrix.resolve(), staged=staged)
    day_dir = args.out / day
    day_dir.mkdir(parents=True, exist_ok=True)
    (day_dir / _daily.PLAN_FILE).write_text(json.dumps(doc, indent=1), encoding="utf-8")
    args_path = day_dir / _daily.ARGS_FILE
    wf_args, planned = None, 0
    if any(ln["agent"] for ln in doc["lanes"]):
        wf_args = _daily.workflow_args(profile, doc, repo=(args.repo or _paths.repo_root()).resolve(),
                                       out=day_dir.resolve(), agent_cap=args.agent_cap)
        planned = _wf.preflight(_wf.get(_daily.WORKFLOW), wf_args)
        args_path.write_text(json.dumps(wf_args, indent=1), encoding="utf-8")
    elif args_path.exists():
        args_path.unlink()          # a stale args file from an earlier run of this day must not be launched
    if args.json:
        print(json.dumps({"plan": str(day_dir / _daily.PLAN_FILE), "args": str(args_path) if wf_args else None,
                          "planned_agents": planned, "staged": staged, "lanes": doc["lanes"]}, indent=1))
    else:
        for p in plans:
            print(p.line())
        for lane, names in staged.items():
            print(f"staged {lane}: {len(names)} specimen(s) (no model)")
        if wf_args:
            print(f"workflow args: {args_path} (dry-run {planned} agent(s) at worst); launch "
                  f"workflows/{_daily.WORKFLOW}.js with them, save its return value, then run finish")
        else:
            print(f"no lane needs an agent; run finish --plan {day_dir / _daily.PLAN_FILE} without --result")
    return 0 if wf_args else 1


def _finish(args) -> int:
    doc = _read_json(args.plan, "plan")
    if not isinstance(doc, dict) or not isinstance(doc.get("lanes"), list):
        raise LookaheadError(f"plan {args.plan}: not a lookahead-daily plan document")
    result = _read_json(args.result, "result") if args.result else None
    rep = _daily.finish(doc, result, args.plan.parent, previous_forecast=args.previous_forecast)
    if args.json:
        print(json.dumps({"day": rep.day, "staged": rep.staged, "not_staged": rep.not_staged,
                          "no_agent": rep.no_agent, "readme": str(rep.readme),
                          "forecast": str(rep.forecast) if rep.forecast else None}, indent=1))
    else:
        print(rep.readme.read_text(encoding="utf-8"), end="")
    return 0 if rep.ok else 1


def run(args: argparse.Namespace) -> int:
    fn = {"prepare": _prepare, "finish": _finish}[args.action]
    try:
        return fn(args)
    except (LookaheadError, _event.EventError, _wf.WorkflowError, _qdiff.QDiffError) as e:
        print(f"lookahead-daily {args.action}: {e}", file=sys.stderr)
        return 2
