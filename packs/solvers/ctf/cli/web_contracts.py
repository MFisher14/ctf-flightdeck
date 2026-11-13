"""`ctf web-contracts` -- drive the B-184 web contract library offline.

Every sub-command reads an evidence/request JSON file (or literal fields) and
prints JSON; none of them opens a socket.  `replay` drives an ordered request
plan through a replay file that records each step's response, so a timed mode can
be rehearsed against a saved capture with no live service.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ctf.engines import layout

HELP = "web contract library: fingerprint router, route-trust, forge grid, minimize, replay (B-184)"


def _load_module():
    """Import the solvers/web contract_library engine on the engine sys.path."""
    for p in layout.sys_path():
        if p not in sys.path:
            sys.path.insert(0, p)
    import contract_library  # noqa: E402 -- solvers/web engine on the engine path
    return contract_library


def _read_json(path: str) -> dict:
    data = Path(path).read_text(encoding="utf-8")
    return json.loads(data)


def _emit(obj) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def add_arguments(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_matrix = sub.add_parser("matrix", help="print the cold/agent/none contract class matrix")
    p_matrix.add_argument("--file", help="a contract matrix JSON (default: the shipped one)")

    p_fp = sub.add_parser("fingerprint", help="rank an evidence snapshot against every class")
    p_fp.add_argument("evidence", help="evidence JSON file (clue, method, responses, ...)")
    p_fp.add_argument("--file", help="a contract matrix JSON (default: the shipped one)")

    p_route = sub.add_parser("route", help="full routing decision (classes, trust, plan)")
    p_route.add_argument("evidence", help="evidence JSON file")
    p_route.add_argument("--file", help="a contract matrix JSON (default: the shipped one)")

    p_trust = sub.add_parser("route-trust", help="is a clue-advertised URL trusted to send?")
    p_trust.add_argument("url", help="the candidate URL or route")
    p_trust.add_argument("--base", required=True, help="the target base URL")
    p_trust.add_argument("--advertised", action="append", default=[],
                         help="a route the clue advertises (repeatable)")
    p_trust.add_argument("--clue", default="", help="the clue text")

    p_forge = sub.add_parser("forge-grid", help="simplest-first forge grid with label->wire mutation")
    p_forge.add_argument("--fields", required=True,
                         help="JSON object mapping clue labels to values, e.g. '{\"Event\":\"\",\"Owner\":\"admin\"}'")
    p_forge.add_argument("--max", type=int, default=32, help="max candidates (default 32)")

    p_min = sub.add_parser("minimize", help="minimization plan for an observed accepted request")
    p_min.add_argument("request", help="request JSON file: {\"fields\": {...}, \"transport\": \"json\"}")

    p_replay = sub.add_parser("replay", help="replay an ordered request plan against a recorded capture")
    p_replay.add_argument("plan", help="JSON file: a list of request dicts")
    p_replay.add_argument("--capture", required=True,
                          help="JSON file: a list of response dicts, one per plan entry, replayed in order")
    p_replay.add_argument("--budget", type=int, default=None, help="max sends (step budget)")


def _cmd_matrix(args, cl) -> int:
    matrix = cl.load_matrix(args.file) if args.file else cl.load_matrix()
    _emit(cl.disposition_matrix(matrix))
    return 0


def _cmd_fingerprint(args, cl) -> int:
    matrix = cl.load_matrix(args.file) if args.file else cl.load_matrix()
    ranked = cl.fingerprint(_read_json(args.evidence), matrix)
    _emit([{"id": m.cls.id, "score": m.score, "disposition": m.disposition,
            "handler": m.handler, "reasons": list(m.reasons)} for m in ranked])
    return 0


def _cmd_route(args, cl) -> int:
    matrix = cl.load_matrix(args.file) if args.file else cl.load_matrix()
    _emit(cl.route(_read_json(args.evidence), matrix))
    return 0


def _cmd_route_trust(args, cl) -> int:
    verdict = cl.route_trust(args.url, args.base, advertised=args.advertised, clue=args.clue)
    _emit(verdict.to_dict())
    return 0 if verdict.trusted else 1


def _cmd_forge_grid(args, cl) -> int:
    try:
        fields = json.loads(args.fields)
    except ValueError as exc:
        print(f"error: --fields is not valid JSON: {exc}", file=sys.stderr)
        return 2
    if not isinstance(fields, dict):
        print("error: --fields must be a JSON object", file=sys.stderr)
        return 2
    grid = cl.forge_grid(fields, max_candidates=args.max)
    _emit([c.to_dict() for c in grid])
    return 0


def _cmd_minimize(args, cl) -> int:
    plan = cl.minimize(_read_json(args.request))
    _emit(plan.to_dict())
    return 0


def _cmd_replay(args, cl) -> int:
    plan = _read_json(args.plan)
    capture = _read_json(args.capture)
    if not isinstance(plan, list) or not isinstance(capture, list):
        print("error: plan and capture must both be JSON lists", file=sys.stderr)
        return 2
    responses = list(capture)
    # No silent padding (rule 10): a capture shorter than the plan cannot answer
    # every request, so the run would fabricate empty responses and over-report
    # `sent`. Fail loudly with the counts instead.
    if len(responses) < len(plan):
        print(f"error: capture has {len(responses)} responses but the plan has {len(plan)} "
              f"requests; every planned request needs a recorded response", file=sys.stderr)
        return 2

    def client(_req, _box={"i": 0}):
        i = _box["i"]
        _box["i"] = i + 1
        return responses[i]

    result = cl.replay(plan, client, budget=args.budget)
    _emit(result.to_dict())
    return 0 if result.proof else 1


_DISPATCH = {
    "matrix": _cmd_matrix,
    "fingerprint": _cmd_fingerprint,
    "route": _cmd_route,
    "route-trust": _cmd_route_trust,
    "forge-grid": _cmd_forge_grid,
    "minimize": _cmd_minimize,
    "replay": _cmd_replay,
}


def run(args: argparse.Namespace) -> int:
    cl = _load_module()
    try:
        return _DISPATCH[args.cmd](args, cl)
    except cl.ContractLibraryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
