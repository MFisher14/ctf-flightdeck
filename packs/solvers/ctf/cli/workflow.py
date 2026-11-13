"""ctf workflow list | lanes | check — the shipped workflow registry and its pre-launch gate (B-194).

    python -m ctf workflow list [--json]                     the shipped workflows, caps and required args
    python -m ctf workflow lanes [--from board|profile] [--event SLUG] [--json]
                                                             the lanes to fan out over (board = dispatch claims)
    python -m ctf workflow check NAME --args-file ARGS.json  validate args + agent-cap dry-run, before launch

`check` is the pre-launch gate: it runs the required-argument schema check and the hard agent-cap
dry-run against ARGS.json and refuses (exit 1, naming the problem) before any agent would be spawned.
`lanes` prints the board- or profile-derived lane list to feed into a workflow's lane argument, so a
workflow never carries a hard-coded lane list. Exit codes: 0 ok, 1 refused / nothing found, 2 bad input.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import workflows as _wf

HELP = "list the shipped workflows, derive their lanes from the board, and gate a launch on schema + cap"


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)

    ls = sp.add_parser("list", help="the shipped workflows, their caps and required arguments")
    ls.add_argument("--json", action="store_true", help="print as JSON")

    la = sp.add_parser("lanes", help="the lanes to fan out over (JSON array)")
    la.add_argument("--from", dest="source", choices=("board", "profile"), default="board",
                    help="board = distinct lanes in the dispatch claims (default); profile = event categories")
    la.add_argument("--event", help="event slug (default: the current event)")
    la.add_argument("--workdir", help="workdir holding dispatch/claims (default: the event workdir)")
    la.add_argument("--json", action="store_true", help="print as a JSON array (default: one per line)")

    ck = sp.add_parser("check", help="validate args + agent-cap dry-run before launch")
    ck.add_argument("name", help="workflow name")
    ck.add_argument("--args-file", required=True, help="JSON object of the args the workflow would launch with")
    ck.add_argument("--json", action="store_true", help="print the verdict as JSON")


def _cmd_list(args) -> int:
    try:
        wfs = _wf.load_all()
    except _wf.WorkflowError as e:
        print(f"ctf workflow list: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps([{
            "name": w.name, "script": w.script, "description": w.description,
            "required": list(w.required), "lane_arg": w.lane_arg, "max_agents": w.max_agents,
        } for w in wfs], indent=2))
        return 0
    if not wfs:
        print("no shipped workflows found")
        return 0
    for w in wfs:
        print(f"{w.name}  (cap {w.max_agents} agents)")
        print(f"    {w.description}")
        print(f"    required: {', '.join(w.required)}")
    return 0


def _cmd_lanes(args) -> int:
    try:
        if args.source == "board":
            workdir = Path(args.workdir) if args.workdir else None
            lanes = _wf.lanes_from_board(workdir)
        else:
            from .. import event as _event
            profile = _event.load(args.event) if args.event else _event.current()
            lanes = _wf.lanes_from_profile(profile)
    except _wf.WorkflowError as e:
        print(f"ctf workflow lanes: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # event load / unknown slug
        print(f"ctf workflow lanes: {e}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(lanes))
    else:
        for lane in lanes:
            print(lane)
    if not lanes:
        print(f"ctf workflow lanes: no lanes from the {args.source}", file=sys.stderr)
        return 1
    return 0


def _cmd_check(args) -> int:
    try:
        wf = _wf.get(args.name)
    except _wf.WorkflowError as e:
        print(f"ctf workflow check: {e}", file=sys.stderr)
        return 2
    path = Path(args.args_file)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"ctf workflow check: cannot read args file {path}: {e}", file=sys.stderr)
        return 2
    if not isinstance(payload, dict):
        print(f"ctf workflow check: args file {path} must be a JSON object", file=sys.stderr)
        return 2
    try:
        planned = _wf.preflight(wf, payload)
    except _wf.WorkflowError as e:
        if args.json:
            print(json.dumps({"ok": False, "workflow": wf.name, "error": str(e)}))
        else:
            print(f"ctf workflow check: REFUSED: {e}", file=sys.stderr)
        return 1
    cap = _wf.effective_cap(wf, payload)
    if args.json:
        print(json.dumps({"ok": True, "workflow": wf.name, "planned_agents": planned, "cap": cap}))
    else:
        print(f"ok: {wf.name} would launch {planned} agent(s), within cap {cap}")
    return 0


def run(args: argparse.Namespace) -> int:
    return {"list": _cmd_list, "lanes": _cmd_lanes, "check": _cmd_check}[args.action](args)
