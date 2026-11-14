"""ctf escalate run | once | show | stop -- the dispatcher's live escalation ladder (B-016,
ctf/escalation.py).

    python -m ctf escalate run  [--model M ...] [--second-s S] [--third-s S] [--duration S] [--poll S] [--json]
    python -m ctf escalate once [--model M ...] [--second-s S] [--third-s S] [--json]
    python -m ctf escalate show ID [--model M ...] [--second-s S] [--third-s S]
    python -m ctf escalate stop --challenge ID --reason refusal|provider_error --harness H [--model M] [--detail T]

`run` follows this event's ledger and, with no model, writes one `escalation` record per decision as it
comes due for every claimed-or-launched challenge: a second agent on a different model at `--second-s`
(default 180 s) or on the first rejected flag, a third at `--third-s` (default 480 s), and a reroute the
moment an agent stops on a refusal or a provider error. `once` does one pass and exits. `show` prints a
challenge's escalation view (with the same roster and timers as `run`, so `due_now` matches). `stop`
records an `agent_stop` by hand (tools/codex_handoff.sh calls it when its codex run fails; the metered
launchers record it from the agent's own output). Nothing is launched here: an orchestrator or a
warm-standby agent reads the records and starts the agents.

With a [routing] table in the profile (B-201, ctf/router.py) each challenge's roster is ordered by its
route, and its ramp's base effort is the `effort` its first agent_launch records (the effort that launch
ran at, an explicit --effort included), else the route's on that launch's harness; a routing table the
price table rejects is exit 2.

`--model` (repeatable) extends the roster past `[models.primary, *models.fallback]` (for `stop`, it names
the stopped agent's model). Exit 1 when a decision had no unused model to route onto, or one written
earlier still has none (named on stderr); 2 on a named error.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import escalation as _esc
from .. import event as _event
from .. import paths as _paths
from .. import router as _route


HELP = "the dispatcher's live escalation ladder: second/third agents on other models, refusal reroutes"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)
    for name, helptext in (("run", "follow the ledger and escalate as timers fire and stops arrive"),
                           ("once", "write every escalation now due and exit"),
                           ("show", "print one challenge's escalation view")):
        s = sp.add_parser(name, help=helptext)
        if name == "show":
            s.add_argument("id")
        s.add_argument("--model", action="append", default=[], metavar="ID",
                       help="extend the escalation roster (repeatable)")
        s.add_argument("--second-s", type=float, default=_esc.SECOND_S,
                       help=f"seconds before the second agent (default {_esc.SECOND_S:g})")
        s.add_argument("--third-s", type=float, default=_esc.THIRD_S,
                       help=f"seconds before the third agent (default {_esc.THIRD_S:g})")
        if name == "show":
            continue
        s.add_argument("--json", action="store_true", help="print each decision as one JSON line")
        if name == "run":
            s.add_argument("--duration", type=float, help="stop after this many seconds")
            s.add_argument("--poll", type=float, default=_esc.POLL_S, help="seconds between ledger reads")
    st = sp.add_parser("stop", help="record an agent stop (refusal / provider error) by hand")
    st.add_argument("--challenge", required=True, help="challenge id")
    st.add_argument("--reason", required=True, choices=_esc.STOP_REASONS)
    st.add_argument("--harness", required=True, help="which harness stopped (claude, codex, ...)")
    st.add_argument("--model", help="the stopped agent's model (the reroute moves off it)")
    st.add_argument("--detail", help="a short reason string from the stop (optional)")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _emit(d: _esc.Decision, as_json: bool) -> None:
    if as_json:
        print(json.dumps(d.to_fields(), ensure_ascii=False), flush=True)
    elif d.status == _esc.STATUS_NO_MODEL:
        print(f"escalate {d.challenge_id}: {d.action} ({d.trigger}) has NO free model: {d.detail}",
              flush=True)
    else:
        print(f"escalate {d.challenge_id}: {d.action} ({d.trigger}) {d.from_model} -> {d.to_model} "
              f"at effort {d.effort} +{d.elapsed_s:.0f}s", flush=True)


def _router(profile, wd):
    """B-201: the event's model router when its profile has a [routing] table, else None."""
    if profile.routing is None:
        return None
    return _route.Router.from_profile(profile, workdir=wd)


def _escalator(args, profile):
    wd = _paths.workdir(profile.slug)
    return _esc.Escalator(profile, workdir=wd, roster=args.model, second_s=args.second_s,
                          third_s=args.third_s, router=_router(profile, wd),
                          on_decision=lambda d: _emit(d, args.json),
                          on_problem=lambda m: print(f"ctf escalate: {m}", file=sys.stderr, flush=True))


def _rc(esc) -> int:
    return 1 if esc.unrouted or any(d.status == _esc.STATUS_NO_MODEL for d in esc.decisions) else 0


def _once(args, profile) -> int:
    esc = _escalator(args, profile)
    esc.once()
    return _rc(esc)


def _run(args, profile) -> int:
    esc = _escalator(args, profile)
    until = None if args.duration is None else esc.clock() + args.duration
    try:
        esc.run(poll=args.poll, until=until)
    except KeyboardInterrupt:
        pass
    return _rc(esc)


def _show(args, profile) -> int:
    wd = _paths.workdir(profile.slug)
    esc = _esc.Escalator(profile, workdir=wd, roster=args.model, second_s=args.second_s,
                         third_s=args.third_s, record=False, router=_router(profile, wd))
    print(json.dumps(esc.show(args.id), indent=2, default=str))
    return 0


def _stop(args, profile) -> int:
    rec = _esc.record_agent_stop(args.reason, args.challenge, harness=args.harness,
                                 workdir=_paths.workdir(profile.slug), detail=args.detail,
                                 model=args.model)
    print(f"recorded agent_stop: {rec['challenge_id']} {rec['reason']} ({args.harness})")
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
        return {"run": _run, "once": _once, "show": _show, "stop": _stop}[args.action](args, profile)
    except (_event.EventError, _esc.EscalationError, _route.RouterError) as e:
        print(f"ctf escalate: {e}", file=sys.stderr)
        return 2
