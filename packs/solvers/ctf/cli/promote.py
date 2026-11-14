"""ctf promote start | inventory | show | decide | accept: the post-event promotion loop (B-038).

    python -m ctf promote start SLUG [--ref REF]          tag event/SLUG/start (refused while an earlier
                                                         event's fold-audit fails against REF)
    python -m ctf promote inventory SLUG --fork DIR [--workspace DIR] [--base REF] [--json]
                                                         list what the event changed, with proposals;
                                                         writes <master>/events/SLUG/promotion.json
    python -m ctf promote show SLUG [--pending] [--json]
    python -m ctf promote decide SLUG ENTRY --engine [--lane L] [--name N]
                                                         [--module M --manifest X --test T] [--commit C]
    python -m ctf promote decide SLUG ENTRY --fold [--dest PATH ...] [--commit C]
    python -m ctf promote decide SLUG ENTRY --drop --reason TEXT
    python -m ctf promote accept SLUG (ENTRY ... | --all)  take the proposal as the decision

ENTRY is `fork:<path>`, `workspace:<path>`, or a path that names one entry. Every command takes
--master DIR (default: this checkout) and --record FILE (default: <master>/events/SLUG/promotion.json).
Then `python -m ctf fold-audit SLUG` checks that every decision reached the master. Exit 0 ok,
1 refused (start), 2 error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import foldaudit as _fa
from .. import paths
from .. import promote as _p

HELP = "post-event promotion: inventory an event's live fixes and scripts, propose engines, record decisions"


def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("slug", help="event slug")
    p.add_argument("--master", type=Path, help="the master checkout (default: this checkout)")
    p.add_argument("--record", type=Path, help="the promotion record (default: <master>/events/SLUG/promotion.json)")


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    s = sp.add_parser("start", help="tag the master commit an event starts from (after the fold-audit)")
    _common(s)
    s.add_argument("--ref", default="HEAD", help="master commit to tag (default HEAD)")
    i = sp.add_parser("inventory", help="inventory the event fork and workspace against the start tag")
    _common(i)
    i.add_argument("--fork", type=Path, help="the event's checkout (clone or worktree of the master)")
    i.add_argument("--workspace", type=Path, help="the event workdir holding solve scripts")
    i.add_argument("--base", help="the start commit when the event has no start tag")
    i.add_argument("--json", action="store_true")
    sh = sp.add_parser("show", help="print the record")
    _common(sh)
    sh.add_argument("--pending", action="store_true", help="only undecided entries")
    sh.add_argument("--json", action="store_true")
    d = sp.add_parser("decide", help="record the decision for one entry")
    _common(d)
    d.add_argument("entry")
    g = d.add_mutually_exclusive_group(required=True)
    g.add_argument("--engine", action="store_true", help="it becomes an engine (module, manifest, test)")
    g.add_argument("--fold", action="store_true", help="it reached (or will reach) the master as is")
    g.add_argument("--drop", action="store_true", help="it is not promoted (needs --reason)")
    d.add_argument("--lane", help="engine lane (solvers/<lane>/); default from the proposal")
    d.add_argument("--name", help="engine name (lower_snake); default from the proposal")
    d.add_argument("--module")
    d.add_argument("--manifest")
    d.add_argument("--test")
    d.add_argument("--dest", action="append", help="master path the fix reached (repeatable)")
    d.add_argument("--commit", help="the master commit that folded it")
    d.add_argument("--reason", help="why it is dropped")
    a = sp.add_parser("accept", help="take the proposals as decisions")
    _common(a)
    a.add_argument("entries", nargs="*")
    a.add_argument("--all", action="store_true", help="every undecided entry")


def _master(args) -> Path:
    return args.master if args.master else paths.repo_root()


def _show(rec: _p.Record, *, pending: bool = False, as_json: bool = False) -> None:
    entries = rec.pending() if pending else rec.entries
    if as_json:
        d = json.loads(rec.to_json())
        if pending:
            d["entries"] = [x for x in d["entries"] if x["decision"] is None]
        print(json.dumps(d, indent=1))
        return
    print(f"promotion record {rec.event}: base {rec.base[:12]} ({rec.base_ref}), "
          f"{len(rec.entries)} entries, {len(rec.pending())} undecided")
    for e in entries:
        d = e.decision
        what = (f"DECIDED {d['action']}" if d else f"proposal {e.proposal.get('action', '?')}")
        where = ""
        src = d or e.proposal
        if src.get("action") == "engine":
            where = f" -> {src['module']} + {src['manifest']} + {src['test']}"
        elif src.get("action") == "fold":
            where = f" -> {', '.join(src.get('dest') or [])}"
        elif src.get("action") == "drop":
            where = f" ({src.get('reason')})"
        stale = " [stale]" if e.stale else ""
        print(f"  {e.key}  {e.change}/{e.state}{stale}  {what}{where}")
        if not d and e.proposal.get("why"):
            print(f"      why: {e.proposal['why']}")


def _engine_decision(args, e: _p.Entry) -> dict:
    prop = e.proposal if e.proposal.get("action") == "engine" else {}
    if args.lane or args.name:
        lane = args.lane or (prop.get("module", "solvers/common/x").split("/")[1])
        name = args.name or _p.engine_name(e.path)
        suffix = Path(e.path).suffix.lower() or ".py"
        dec = {"action": "engine", **_p.engine_paths(lane, name, suffix)}
    else:
        dec = {"action": "engine", **{k: prop[k] for k in ("module", "manifest", "test") if k in prop}}
    for k in ("module", "manifest", "test"):
        if getattr(args, k):
            dec[k] = getattr(args, k)
    if args.commit:
        dec["commit"] = args.commit
    return dec


def _decide(args) -> int:
    master = _master(args)
    rec = _p.load_record(args.slug, master, args.record)
    e = _p.find_entry(rec, args.entry)
    if args.drop:
        dec = {"action": "drop", "reason": args.reason or ""}
    elif args.fold:
        dec = {"action": "fold"}
        if args.dest:
            dec["dest"] = args.dest
        if args.commit:
            dec["commit"] = args.commit
    else:
        dec = _engine_decision(args, e)
    _p.decide(rec, e.key, dec, master=master)
    p = _p.save_record(rec, master, args.record)
    print(f"{e.key}: {e.decision['action']} recorded in {p}")
    return 0


def _accept(args) -> int:
    master = _master(args)
    if not args.all and not args.entries:
        print("ctf promote accept: name entries or pass --all", file=sys.stderr)
        return 2
    rec = _p.load_record(args.slug, master, args.record)
    done = _p.accept(rec, None if args.all else args.entries, master=master)
    p = _p.save_record(rec, master, args.record)
    for e in done:
        print(f"{e.key}: {e.decision['action']}")
    print(f"{len(done)} decision(s) recorded in {p}; {len(rec.pending())} undecided")
    return 0


def _inventory(args) -> int:
    master = _master(args)
    rp = args.record or _p.record_path(args.slug, master)
    prev = _p.load_record(args.slug, master, rp) if Path(rp).is_file() else None
    rec = _p.inventory(args.slug, master=master, fork=args.fork, workspace=args.workspace,
                       base=args.base, previous=prev)
    p = _p.save_record(rec, master, args.record)
    _show(rec, as_json=args.json)
    print(f"wrote {p}", file=sys.stderr if args.json else sys.stdout)
    return 0


def _start(args) -> int:
    master = _master(args)
    try:
        sha, results = _p.tag_start(args.slug, master=master, ref=args.ref)
    except _fa.FoldAuditFailed as e:
        for r in e.results:
            print(_fa.render(r))
        print(f"ctf promote start: refused: {e}; fold those fixes into the master first", file=sys.stderr)
        return 1
    for r in results:
        print(_fa.render(r))
    print(f"tagged {_p.start_tag(args.slug)} -> {sha[:12]} ({len(results)} earlier event(s) audited)")
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        if args.action == "start":
            return _start(args)
        if args.action == "inventory":
            return _inventory(args)
        if args.action == "show":
            _show(_p.load_record(args.slug, _master(args), args.record), pending=args.pending,
                  as_json=args.json)
            return 0
        if args.action == "decide":
            return _decide(args)
        return _accept(args)
    except (_p.PromoteError, _event.EventError) as e:
        print(f"ctf promote: {e}", file=sys.stderr)
        return 2
