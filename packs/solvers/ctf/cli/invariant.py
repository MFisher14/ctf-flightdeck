"""ctf invariant -- the business-logic state-invariant harness (B-124, hard-tail fallback #10).

    python -m ctf invariant check --spec S.json --before B.json --after A.json [--accepted N]
    python -m ctf invariant plan  --spec S.json --url URL
    python -m ctf invariant run   --spec S.json --url URL [--event SLUG | --profile P] [--deadline-s S]

The harness never finds the flaw: the spec states the invariant (``stated_by`` names who) and the
harness exercises it (``solvers/web/invariant_harness.py``).  ``check`` evaluates the stated
invariants over two hand-captured snapshots (offline, no network).  ``plan`` validates a full spec
against the target origin and prints the transition ladder with each rung's reserved request count
(sends nothing).  ``run`` drives the ladder live against one scope-locked target: it refuses (exit 4)
unless the event's ``rules.web_state_changing`` is true and the URL is inside its live-service scope.
Nothing is ever submitted.

Exit: 0 the invariant held, 1 it was violated, 2 an error (bad spec, unreadable file, unevaluable
check), 3 a live run ended inconclusive (stopped before a verdict), 4 refused by the event's rules.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .. import event as _event
from .. import paths as _paths
from .. import scope as _scope

HELP = "business-logic state-invariant harness: check / plan / run a stated invariant (B-124)"
REFUSED_EXIT = 4
INCONCLUSIVE_EXIT = 3


def _harness():
    root = _paths.repo_root()
    for sub in ("solvers/web", "solvers/toolkits"):
        p = str(root / sub)
        if p not in sys.path:
            sys.path.insert(0, p)
    import invariant_harness
    return invariant_harness


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="machine-readable output")
    sp = p.add_subparsers(dest="action", required=True)
    c = sp.add_parser("check", help="evaluate stated invariants over a before/after snapshot pair (offline)")
    c.add_argument("--spec", required=True, help="JSON spec (or a bare list of invariants)")
    c.add_argument("--before", required=True, help="JSON snapshot before the transition")
    c.add_argument("--after", required=True, help="JSON snapshot after the transition")
    c.add_argument("--accepted", type=int, default=0,
                   help="transitions the target accepted (scales a per:accepted delta)")
    pl = sp.add_parser("plan", help="validate a spec against the target origin; print the ladder")
    pl.add_argument("--spec", required=True)
    pl.add_argument("--url", required=True, help="the target base URL (origin of every route)")
    r = sp.add_parser("run", help="drive the ladder live against one scope-locked target")
    r.add_argument("--spec", required=True)
    r.add_argument("--url", required=True)
    r.add_argument("--event", help="event slug (default: the current event)")
    r.add_argument("--profile", help="path to an event.toml under events/ (instead of --event)")
    r.add_argument("--deadline-s", type=float, default=120.0, dest="deadline_s",
                   help="wall-clock budget for the whole run in seconds (default 120)")


def _load_json(path: str, what: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read {what} {path}: {type(exc).__name__}: {exc}") from None


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        root = _paths.events_root().resolve()
        path = Path(args.profile).expanduser().resolve()
        if not path.is_relative_to(root):
            raise _event.EventError(f"--profile {args.profile} is outside the repo's events/ folder")
        return _event.load_path(path)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def build_client_factory(profile: _event.EventProfile):
    """A factory of scope-locked, state-changing-capable WebClients (seam the tests replace)."""
    import web as _web  # solvers/toolkits, on sys.path via _harness()

    def make(url, timeout=None):
        return _web.WebClient(url, timeout=timeout or 8.0, get_only=False)
    return make


def _emit(args, payload, lines) -> None:
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        for line in lines:
            print(line)


def _check(args, H) -> int:
    raw = _load_json(args.spec, "spec")
    invariants = raw.get("invariants") if isinstance(raw, dict) else raw
    result = H.check(invariants, _load_json(args.before, "before snapshot"),
                     _load_json(args.after, "after snapshot"), accepted=args.accepted)
    lines = [f"verdict: {result['verdict']} ({args.accepted} accepted)"]
    lines += [f"  {r['id']}: {r['status']} -- {r.get('detail') or r.get('reason')}" for r in result["checks"]]
    _emit(args, result, lines)
    return {"holds": 0, "violated": 1}.get(result["verdict"], 2)


def _plan(args, H) -> int:
    compiled = H.compile_spec(_load_json(args.spec, "spec"), args.url)
    rungs = H.ladder(compiled)
    payload = {"name": compiled["name"], "stated_by": compiled["stated_by"],
               "snapshots": compiled["snapshots"],
               "transition": {"method": compiled["transition"]["method"],
                              "route": compiled["transition"]["route"]},
               "reverse": ({"method": compiled["reverse"]["method"], "route": compiled["reverse"]["route"]}
                           if compiled["reverse"] else None),
               "max_requests": compiled["max_requests"], "ladder": rungs,
               "reserved_total": sum(r["reserve"] for r in rungs)}
    lines = [f"invariant {compiled['name']!r} stated by {compiled['stated_by']}; "
             f"transition {payload['transition']['method']} {payload['transition']['route']}; "
             f"reverse {payload['reverse']['method'] + ' ' + payload['reverse']['route'] if payload['reverse'] else 'NONE (irreversible_ack)'}"]
    lines += [f"  {r['rung']}: reserve {r['reserve']} request(s)" for r in rungs]
    lines.append(f"  worst case {payload['reserved_total']} of max_requests {compiled['max_requests']}")
    _emit(args, payload, lines)
    return 0


def _run(args, H) -> int:
    profile = _profile(args)
    if not profile.rules.web_state_changing:
        print(f"ctf invariant: refused: event {profile.slug!r} has rules.web_state_changing = false "
              f"(Open O-2); the harness drives state-changing transitions", file=sys.stderr)
        return REFUSED_EXIT
    try:
        _scope.check_url(args.url, what="invariant target", profile=profile)
    except _scope.OutOfScope as exc:
        print(f"ctf invariant: refused: {exc}", file=sys.stderr)
        return REFUSED_EXIT
    spec = _load_json(args.spec, "spec")
    previous = _scope.pinned()
    _scope.pin(profile)
    try:
        report = H.run_harness(spec, build_client_factory(profile), base_url=args.url,
                               deadline=time.time() + max(1.0, args.deadline_s))
    finally:
        if previous is not None:
            _scope.pin(previous)
        else:
            _scope.unpin()
    _emit(args, report, H.summary_lines(report))
    if report.get("error") == "refused":
        return REFUSED_EXIT
    if report.get("error"):
        return 2
    return {"holds": 0, "violated": 1}.get(report["verdict"], INCONCLUSIVE_EXIT)


def run(args: argparse.Namespace) -> int:
    H = _harness()
    try:
        if args.action == "check":
            return _check(args, H)
        if args.action == "plan":
            return _plan(args, H)
        return _run(args, H)
    except (ValueError, _event.EventError) as exc:   # InvariantSpecError is a ValueError
        print(f"ctf invariant: {exc}", file=sys.stderr)
        return 2
