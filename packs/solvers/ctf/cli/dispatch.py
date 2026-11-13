"""ctf dispatch run | once | show -- the no-model dispatcher (B-004, ctf/dispatch.py).

    python -m ctf dispatch run [--since SEQ] [--duration S] [--no-intake] [--json]
    python -m ctf dispatch once [--since SEQ] [--no-intake] [--json]
    python -m ctf dispatch show ID

`run` follows this event's watch stream (`ctf watch run` must be polling the board) and, for each new
challenge, writes a claim and a machine-written handout with no model, then starts intake for the batch
in the background (download, sweep, input-adapted engines, recorded as `engine.run`), so it keeps
claiming while intake runs. `once` dispatches the new challenges the stream already shows, waits for
their intake and exits. Both retry intake for claims that never got it, name each intake failure on
stderr, and exit 1 when any intake failed. `show` prints one challenge's handout without touching the
platform; an id the stream and the stored briefs do not know exits 2. The dispatcher never runs a model
and never submits.
"""
from __future__ import annotations

import argparse
import json
import sys

from .. import dispatch as _dispatch
from .. import event as _event
from .. import paths as _paths
from .. import watch as _watch

HELP = "the no-model dispatcher: a claim and a machine-written handout per new challenge"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--profile", help="path to an event.toml (instead of --event)")
    sp = p.add_subparsers(dest="action", required=True)
    for name, helptext in (("run", "follow the stream and dispatch new challenges"),
                           ("once", "dispatch the new challenges the stream already shows")):
        s = sp.add_parser(name, help=helptext)
        s.add_argument("--since", type=int, default=0, help="only stream events with seq greater than this")
        s.add_argument("--no-intake", action="store_true",
                       help="write claims and handouts only; do not start intake")
        s.add_argument("--json", action="store_true", help="print each claim as one JSON line")
        if name == "run":
            s.add_argument("--duration", type=float, help="stop after this many seconds")
            s.add_argument("--poll", type=float, default=0.5, help="seconds between stream reads")
    sh = sp.add_parser("show", help="print one challenge's handout")
    sh.add_argument("id")


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    if args.profile and args.event:
        raise _event.EventError("give --event or --profile, not both")
    if args.profile:
        return _event.load_path(args.profile)
    if args.event:
        return _event.load(args.event)
    return _event.current()


def _intake_runner(profile, workdir):
    def run(ids):
        from .. import intake as _intake
        return _intake.intake_many(ids, profile, workdir=workdir)
    return run


def _emit(claim, as_json: bool) -> None:
    if as_json:
        print(json.dumps(claim.to_dict(), ensure_ascii=False), flush=True)
    else:
        print(f"dispatched {claim.challenge_id} [{claim.lane}] -> {claim.handout}", flush=True)


def _intake_note(res) -> None:
    if res.status == _dispatch.INTAKE_FAILED:
        print(f"ctf dispatch: intake failed for {res.challenge_id}: {res.reason}", file=sys.stderr, flush=True)


def _problem(msg: str) -> None:
    print(f"ctf dispatch: {msg}", file=sys.stderr, flush=True)


def _dispatcher(args, profile, **kw):
    wd = _paths.workdir(profile.slug)
    runner = None if args.no_intake else _intake_runner(profile, wd)
    return _dispatch.Dispatcher(profile, workdir=wd, intake_runner=runner,
                                on_claim=lambda c: _emit(c, args.json), on_intake=_intake_note,
                                on_problem=_problem, **kw)


def _end(d) -> int:
    """Wait for the intake already started; rc 1 when any challenge's intake failed (each was named)."""
    try:
        d.close()
    except KeyboardInterrupt:
        print("ctf dispatch: interrupted while intake was still running", file=sys.stderr)
        return 130
    return 1 if d.failed() else 0


def _once(args, profile) -> int:
    d = _dispatcher(args, profile)
    claims = d.once(since=args.since, wait=False)
    if not claims:
        print("ctf dispatch: no new challenges in the stream (is `ctf watch run` polling?)", file=sys.stderr)
    return _end(d)


def _run(args, profile) -> int:
    d = _dispatcher(args, profile)
    until = None if args.duration is None else d.clock() + args.duration
    try:
        d.run(since=args.since, poll=args.poll, until=until, wait=False)
    except KeyboardInterrupt:
        pass
    return _end(d)


def _show(args, profile) -> int:
    wd = _paths.workdir(profile.slug)
    cid = str(args.id)
    det = None
    for ev in _watch.read_events(wd):
        if ev.get("event") == "challenge_new" and str(ev.get("challenge_id")) == cid:
            det = _dispatch.Detected.from_event(ev)
    if det is None:
        if not _watch.versions(wd, cid):
            raise _dispatch.DispatchError(
                f"challenge {cid!r} is not in this event's watch stream and has no stored brief "
                f"(stream: {_watch.events_path(wd)})")
        b = _dispatch.brief_for(wd, _dispatch.Detected(cid))
        det = _dispatch.Detected(cid, b["name"], b["category"])
    print(_dispatch.handout_md(det, profile, workdir=wd), end="")
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        profile = _profile(args)
        return {"run": _run, "once": _once, "show": _show}[args.action](args, profile)
    except (_event.EventError, _dispatch.DispatchError, _watch.WatchError) as e:
        print(f"ctf dispatch: {e}", file=sys.stderr)
        return 2
