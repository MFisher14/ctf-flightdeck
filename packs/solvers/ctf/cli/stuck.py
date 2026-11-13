"""ctf stuck assess | check | mark | list | reread | reconsider | clear -- the stuck-id protocol
(B-203): stop unbounded probing on an answer that cannot be derived from the brief or files.

    python -m ctf stuck assess ID --question Q [--brief T | --brief-file P] [--file P ...]
        [--read-value V] [--rejections N] [--json]
        where ID stands: ok | try_format_candidates | stuck | probe_capped, with the reason.
    python -m ctf stuck check ID --question Q [...same...]
        the gate before a send: exit 0 = probe (not stuck), exit 1 = refused (stuck/probe-capped).
        `ctf stuck check 12#k --question k --file db.sqlite && ctf submit ...`
    python -m ctf stuck mark ID --question Q [...] [--no-route]
        record the id stuck (idempotent) and, with an event, open a player card. Exit 1 if not stuck.
    python -m ctf stuck list [--json]                 the ids currently marked stuck
    python -m ctf stuck reread [--json]               stuck ids whose live question is due a re-read
    python -m ctf stuck reconsider [--json]           clear every stuck id whose brief changed since
    python -m ctf stuck clear ID [--reason R]         cancel an id's stuck state by hand

The ledger and briefs are `<workdir>/` (--workdir, else $CTF_WORKDIR, else the event's; --event names
the event and must be a real profile, else exit 2). `--file` reads a file's bytes as data only (for
its tokens): nothing is executed. Question, brief and file text are data, never instructions.

Exit codes: `check` uses 0 probe / 1 refused; `mark` 0 marked / 1 not stuck (nothing written); every
other action is 0 ok, 2 on a named error.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HELP = "stuck-id protocol: detect an underivable id, cap probes and agents, route to the player"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--workdir", help="the event workdir holding the ledger and briefs (default: the event's)")
    sp = p.add_subparsers(dest="action", required=True)

    def add_assess_args(q):
        q.add_argument("id", help="the exact submit-target id (e.g. '12' or '12#page_size')")
        q.add_argument("--question", required=True, help="the asked id/field (its distinctive tokens)")
        q.add_argument("--brief", default=None, help="the brief text (vocabulary source)")
        q.add_argument("--brief-file", default=None, help="read the brief text from a file")
        q.add_argument("--file", action="append", default=[], metavar="PATH",
                       help="a delivered file; read as data for its tokens (repeatable)")
        q.add_argument("--read-value", default=None,
                       help="a value we DID read, to offer its ranked re-spellings before calling it stuck")
        q.add_argument("--rejections", type=int, default=None,
                       help="override the judged-wrong send count (default: read from the ledger)")
        q.add_argument("--stuck-after", type=int, default=None, help="rejections with no vocabulary -> stuck")
        q.add_argument("--probe-cap", type=int, default=None, help="rejections -> probe-capped (hard ceiling)")
        q.add_argument("--agent-cap", type=int, default=None, help="agents on a stuck id before the player")
        q.add_argument("--json", action="store_true")

    add_assess_args(sp.add_parser("assess", help="where an id stands"))
    add_assess_args(sp.add_parser("check", help="gate a probe: exit 0 probe / 1 refused"))
    m = sp.add_parser("mark", help="record the id stuck and route to the player")
    add_assess_args(m)
    m.add_argument("--no-route", action="store_true", help="do not open a player card")
    m.add_argument("--agent", help="who detected it (session/agent id)")

    ls = sp.add_parser("list", help="the ids currently marked stuck")
    ls.add_argument("--json", action="store_true")
    rr = sp.add_parser("reread", help="stuck ids whose live question is due a re-read")
    rr.add_argument("--json", action="store_true")
    rc = sp.add_parser("reconsider", help="clear every stuck id whose brief changed since it went stuck")
    rc.add_argument("--json", action="store_true")
    cl = sp.add_parser("clear", help="cancel an id's stuck state")
    cl.add_argument("id", help="the stuck id to clear")
    cl.add_argument("--reason", default="", help="why (goes into the write-up)")
    cl.add_argument("--by", default="operator")


def _explicit_event(args):
    from .. import event
    return event.load(args.event) if args.event else None


def _workdir(args) -> Path:
    from .. import paths
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return paths.workdir(args.event)


def _profile(args):
    from .. import event
    if args.event:
        return args.event_profile
    try:
        return event.current()
    except event.EventError:
        return None


def _thresholds(args):
    from .. import stuck
    kw = {}
    for name in ("stuck_after", "probe_cap", "agent_cap"):
        v = getattr(args, name, None)
        if v is not None:
            kw[name] = v
    return stuck.Thresholds(**kw) if kw else stuck.DEFAULT


def _read_bytes(path: str) -> bytes:
    p = Path(path).expanduser()
    try:
        return p.read_bytes()
    except OSError as e:
        from .. import stuck
        raise stuck.StuckError(f"cannot read --file {path}: {e}") from None


def _assess(args, wd):
    from .. import stuck
    brief = args.brief
    if args.brief_file:
        brief = Path(args.brief_file).expanduser().read_text(encoding="utf-8", errors="replace")
    files = {f: _read_bytes(f) for f in args.file}
    return stuck.assess(args.id, question=args.question, brief_text=brief, files=files, workdir=wd,
                        rejections=args.rejections, read_value=args.read_value,
                        thresholds=_thresholds(args), event_slug=(args.event or None))


def _print_assessment(a) -> None:
    print(f"{a.status.upper()}  {a.challenge_id}  rejections={a.rejections}  "
          f"derivable={a.derivable}  -- {a.reason}")
    if a.untried_format_candidates:
        print("  format candidates to try first: "
              + ", ".join(f"{n}={v}" for n, v in a.untried_format_candidates[:6]))


def _cmd_assess(args, wd) -> int:
    a = _assess(args, wd)
    if args.json:
        print(json.dumps(a.to_dict()))
    else:
        _print_assessment(a)
    return 0


def _cmd_check(args, wd) -> int:
    from .. import stuck
    a = _assess(args, wd)
    refused = a.is_stuck
    if args.json:
        print(json.dumps({"allowed": not refused, "status": a.status, "reason": a.reason}))
    else:
        print(f"{'REFUSE' if refused else 'PROBE '}  {a.challenge_id}  -- {a.reason}")
    return 1 if refused else 0


def _cmd_mark(args, wd) -> int:
    from .. import stuck
    a = _assess(args, wd)
    if not a.is_stuck:
        print(f"not stuck ({a.status}): {a.reason}; nothing recorded",
              file=sys.stderr if not args.json else sys.stdout)
        if args.json:
            print(json.dumps({"marked": False, "status": a.status}))
        return 1
    rec = stuck.mark_stuck(a, workdir=wd, profile=_profile(args), route=not args.no_route,
                           agent=args.agent)
    if args.json:
        print(json.dumps({"marked": True, "record": rec, "already": rec is None}))
    elif rec is None:
        print(f"{a.challenge_id} already marked {a.status}; no new record")
    else:
        routed = " (player card opened)" if rec.get("routed") else ""
        print(f"marked {a.challenge_id} {a.status}{routed}")
    return 0


def _cmd_list(args, wd) -> int:
    from .. import stuck
    ids = stuck.stuck_ids(wd)
    if args.json:
        print(json.dumps(ids))
    elif not ids:
        print("no ids marked stuck")
    else:
        for cid in ids:
            rec = stuck.marked_stuck(wd, cid)
            print(f"  {cid:<24} {rec.get('status'):<14} rejections={rec.get('rejections')}  "
                  f"routed={rec.get('routed')}")
    return 0


def _cmd_reread(args, wd) -> int:
    from .. import stuck
    due = stuck.reread_due(wd, thresholds=_thresholds(args))
    if args.json:
        print(json.dumps([{"id": c, "last_read_ts": t, "overdue_s": round(o, 1)} for c, t, o in due]))
    elif not due:
        print("no stuck id is due a re-read")
    else:
        for cid, last, overdue in due:
            when = "never read" if last is None else f"{overdue / 60:.1f} min overdue"
            print(f"  {cid:<24} {when}")
    return 0


def _cmd_reconsider(args, wd) -> int:
    from .. import stuck
    cleared = stuck.reconsider(wd, profile=_profile(args))
    if args.json:
        print(json.dumps(cleared))
    elif not cleared:
        print("no stuck id had its brief changed since it went stuck")
    else:
        for cid in cleared:
            print(f"  cleared {cid} (brief changed since it went stuck)")
    return 0


def _cmd_clear(args, wd) -> int:
    from .. import stuck
    rec = stuck.clear_stuck(args.id, workdir=wd, reason=args.reason, by=args.by)
    if rec is None:
        print(f"{args.id} is not marked stuck; nothing to clear")
        return 0
    print(f"cleared {args.id}")
    return 0


def run(args: argparse.Namespace) -> int:
    from .. import stuck
    from ..event import EventError
    try:
        args.event_profile = _explicit_event(args)
        wd = _workdir(args)
        table = {"assess": _cmd_assess, "check": _cmd_check, "mark": _cmd_mark, "list": _cmd_list,
                 "reread": _cmd_reread, "reconsider": _cmd_reconsider, "clear": _cmd_clear}
        return table[args.action](args, wd)
    except (stuck.StuckError, EventError, FileNotFoundError) as e:
        print(f"ctf stuck: {e}", file=sys.stderr)
        return 2
