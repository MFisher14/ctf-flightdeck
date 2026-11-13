"""ctf geo-reconcile -- reconcile two geo-sensor logs from an instance and shape its /schema report (B-111).

    python -m ctf geo-reconcile run --challenge ID [--start] [--method FILE] [--out DIR]
        read our running instance for ID (`ctf instance start ID` first, or --start to start it through
        the capped slot ledger), GET /schema and the evidence files, reconcile, write the report.
    python -m ctf geo-reconcile run --url http://HOST:PORT/ --out DIR [--method FILE]
        the same against an instance address you already hold.
    python -m ctf geo-reconcile run ... --send --player-approved
        also POST the report to the judge route, once. Needs rules.web_state_changing = true in the
        event profile AND the player's approval for this POST (--player-approved says the player gave
        it); the report must be complete and schema-valid; the POST ledger paces and caps sends.
        The ledger is <workdir>/geo-reconcile/posts/, one file per challenge id (or, with --url, per
        instance host:port), never per --out folder. A send that may have reached the judge with no
        answer back counts and is not resent unless --resend-unknown is also given.
    python -m ctf geo-reconcile offline PACK_DIR [--method FILE] [--out DIR]
        recompute the report from a mirrored pack (or a folder of evidence files). No network.
    python -m ctf geo-reconcile method
        print the default method as JSON. Edit a copy (columns, clock offset, projection, matching,
        divergence threshold, closest-approach target, report field mapping) and pass it as --method.

The default is a dry run: the evidence is fetched GET-only through the scope guard, the report is
written to <out>/report.json with the facts, decisions and warnings in <out>/reconciliation.json, and
nothing is sent. A flag the judge returns is printed as a candidate; submit it with `ctf submit`.

Exit: 0 report ready (dry run) or accepted (send); 1 report not ready, or sent and not accepted;
2 an error (evidence, method, instance); 4 refused by the event's rules (scope, state-changing
requests, approval, POST pacing/budget).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import instsched as _sched
from .. import paths as _paths
from .. import scope as _scope
from ..platform import NotAllowed, NotSupported, PlatformError, get_adapter, supports_instances

HELP = "reconcile two geo-sensor logs from an instance and shape its /schema report (B-111)"
REFUSED_EXIT = 4


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    r = sp.add_parser("run", help="fetch /schema + evidence (GET-only), reconcile, write the report")
    where = r.add_mutually_exclusive_group(required=True)
    where.add_argument("--challenge", metavar="ID", help="challenge id: use our instance for it")
    where.add_argument("--url", help="the instance base URL (http://host:port/)")
    r.add_argument("--start", action="store_true",
                   help="with --challenge: start the instance through the capped slot ledger if needed")
    r.add_argument("--send", action="store_true", help="POST the report to the judge route (default: dry run)")
    r.add_argument("--player-approved", action="store_true", dest="player_approved",
                   help="the player approved this one POST (required with --send)")
    r.add_argument("--resend-unknown", action="store_true", dest="resend_unknown",
                   help="with --send: resend a report whose earlier POST got no answer (it still counts)")
    o = sp.add_parser("offline", help="recompute the report from a mirrored pack; no network")
    o.add_argument("pack", help="an evidence pack folder (index.json + http/) or a folder of evidence files")
    for s in (r, o):
        s.add_argument("--method", help="a method JSON file (default: the built-in method)")
        s.add_argument("--out", help="output folder (default: <workdir>/geo-reconcile/<id>; the pack for offline)")
        s.add_argument("--event", help="event slug (default: the current event)")
        s.add_argument("--json", action="store_true", help="machine-readable output")
    sp.add_parser("method", help="print the default method as JSON")


def _engine():
    """solvers/toolkits/geo_reconcile.py (and ics_mirror), on the engine sys.path."""
    from ..engines import layout
    for p in layout.sys_path():
        if p not in sys.path:
            sys.path.insert(0, p)
    import geo_reconcile
    import ics_mirror
    return geo_reconcile, ics_mirror


def _profile(args: argparse.Namespace) -> _event.EventProfile:
    return _event.load(args.event) if getattr(args, "event", None) else _event.current()


def _adapter(profile):
    gate = get_adapter(profile)
    if not supports_instances(gate):
        raise NotSupported(f"event {profile.slug!r} has no container-instance plugin ([instances] in its "
                           "event.toml); pass --url with the instance address instead")
    return gate


def _instance_url(args, profile, ics_mirror) -> str:
    """The base URL of our instance for --challenge: read-only unless --start was given."""
    gate = _adapter(profile)
    cid = str(args.challenge)
    if args.start:
        ledger = _sched.SlotLedger(_sched.slot_ledger_path(_paths.workdir(profile.slug)))
        cap = profile.instances.cap if profile.instances is not None else None
        info = ics_mirror.start_instance(gate, ledger, cid, cap=cap)
    else:
        info = gate.instance_status(cid)
    if getattr(info, "state", None) not in _sched.LIVE_STATES or not getattr(info, "connection_info", ""):
        raise ics_mirror.MirrorError(
            f"our instance for {cid} is {getattr(info, 'state', 'unknown')!r} with no address; start it "
            f"(`python -m ctf instance start {cid}`, or pass --start) and run this again")
    return ics_mirror.parse_endpoint(info.connection_info).base_url


def _method(args, geo) -> dict:
    if not args.method:
        return geo.load_method(None)
    try:
        user = json.loads(Path(args.method).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise geo.MethodError(f"cannot read method {args.method}: {e}") from None
    return geo.load_method(user)


def _print(result, geo, as_json: bool, challenge: str | None) -> None:
    prepared, post = result.prepared, result.post
    if as_json:
        doc = prepared.to_dict()
        doc["out_dir"] = str(result.out_dir)
        if post is not None:
            doc["post"] = {k: v for k, v in post.items() if k != "body"}
        print(json.dumps(doc, default=str))
        return
    for line in geo.summarize(prepared):
        print(line)
    for line in prepared.reconciliation.decisions:
        print(f"decision: {line}")
    for line in prepared.reconciliation.warnings:
        print(f"WARNING: {line}")
    for line in prepared.unchecked:
        print(f"schema keyword not checked: {line}")
    print(f"report: {result.out_dir / geo.REPORT_NAME}")
    if not prepared.ready:
        for line in prepared.blockers():
            print(f"NOT READY: {line}")
    if post is None:
        print("dry run: nothing was sent" + (" (the report is ready; --send --player-approved posts it)"
                                             if prepared.ready else ""))
        return
    print(f"POST: {post['outcome']} (HTTP {post['status']}, {post['posts']} request(s), waited "
          f"{post['waited_s']:.0f} s)")
    if post["outcome"] == "ratelimited" and post.get("retry_after_s") is not None:
        print(f"rate-limited: not judged; the judge asks to wait {post['retry_after_s']:.0f} s")
    for flag in post["flags"]:
        print(f"candidate flag: {flag}")
        print(f"submit it through the gate: python -m ctf submit {challenge or '<id>'} '{flag}'")


def run(args: argparse.Namespace) -> int:
    try:
        geo, ics_mirror = _engine()
    except ImportError as e:
        print(f"ctf geo-reconcile: cannot load the engine: {e}", file=sys.stderr)
        return 2
    if args.action == "method":
        print(json.dumps(geo.default_method(), indent=2))
        return 0
    pinned_here = False
    try:
        method = _method(args, geo)
        if args.action == "offline":
            result = geo.run_offline(args.pack, method, out_dir=args.out)
            _print(result, geo, args.json, None)
            return 0 if result.prepared.ready else 1

        profile = _profile(args)
        if args.start and not args.challenge:
            raise geo.MethodError("--start needs --challenge")
        if args.player_approved and not args.send:
            raise geo.MethodError("--player-approved only applies to --send")
        if args.resend_unknown and not args.send:
            raise geo.MethodError("--resend-unknown only applies to --send")
        if args.send:
            # Refuse a send the rules or the player do not allow before the instance is touched at all.
            ics_mirror.authorize_state_change(f"POST {method['submit']}", approved=args.player_approved,
                                              profile=profile)
        if args.out:
            out = Path(args.out)
        elif args.challenge:
            out = _paths.workdir(profile.slug) / "geo-reconcile" / str(args.challenge)
        else:
            raise geo.MethodError("--url needs --out (there is no challenge id to name the folder)")
        base_url = args.url or _instance_url(args, profile, ics_mirror)
        _scope.check_url(base_url, what=f"geo-reconcile target {base_url!r}", profile=profile)
        if _scope.pinned() is None:
            # the web client's own guard reads the process profile: make it the one chosen here
            _scope.pin(profile)
            pinned_here = True
        # The POST ledger is keyed by the challenge (or the instance), not by --out: a new output
        # folder must not reset the budget, the pacing or the no-resend rule.
        ledger = geo.post_ledger_path(_paths.workdir(profile.slug), challenge_id=args.challenge or "",
                                      base_url=base_url) if args.send else None
        result = geo.run_live(base_url, method, out, profile=profile, challenge_id=args.challenge or "",
                              send=args.send, approved=args.player_approved, ledger_path=ledger,
                              resend_unknown=args.resend_unknown)
        if ledger is not None and not args.json:
            print(f"POST ledger: {ledger}")
        _print(result, geo, args.json, args.challenge)
        if not result.prepared.ready:
            return 1
        if result.post is not None:
            return 0 if result.post["outcome"] == "accepted" else 1
        return 0
    except (_scope.OutOfScope, ics_mirror.StateChangeRefused, geo.PostRefused, NotAllowed) as e:
        print(f"ctf geo-reconcile: refused: {e}", file=sys.stderr)
        return REFUSED_EXIT
    except (geo.ReconcileError, ics_mirror.MirrorError, _sched.ScheduleError, _event.EventError,
            NotSupported, PlatformError, OSError) as e:
        print(f"ctf geo-reconcile: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    finally:
        if pinned_here:
            _scope.unpin()
