"""ctf live: the no-model status surface (B-198). See ctf/live.py for the sources and the contract.

    python -m ctf live [show] [--json] [--event SLUG | --no-event]
    python -m ctf live page --out FILE [--title T] [--refresh S]
    python -m ctf live push [--url URL] [--force] [--min-interval S]
    python -m ctf live loop --every S [--page FILE] [--push] [--count N]
    python -m ctf live smoke URL [--local FILE | --expect-digest D] [--max-age S]
    python -m ctf live job --name NAME -- CMD ...
    python -m ctf live arm [--note TEXT]
    python -m ctf live forget --died

Exit codes: 0 ok; 1 a failed push, a failed smoke check, or a job's own non-zero code; 2 a named
configuration error (no push URL, a refused endpoint, no event to arm, a bad job name).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HELP = "no-model live status: build, gates, jobs, workers, armed vs HEAD, board, solves, percent through plan, ETA; page, push, smoke"


def _event_opts(p: argparse.ArgumentParser, *, sub: bool = False) -> None:
    """--event / --no-event on `ctf live` and on each action (an action's copy never resets the other)."""
    kw = {"default": argparse.SUPPRESS} if sub else {}
    g = p.add_mutually_exclusive_group()
    g.add_argument("--event", help="event slug (default: $CTF_EVENT, or the only profile)", **kw)
    g.add_argument("--no-event", action="store_true", help="leave the event section out", **kw)


def add_arguments(p: argparse.ArgumentParser) -> None:
    _event_opts(p)
    p.add_argument("--json", action="store_true", help="the snapshot as JSON (show)")
    sp = p.add_subparsers(dest="action")
    sh = _sub(sp, "show", help="print the status (the default)")
    sh.add_argument("--json", action="store_true", dest="json_sub")
    pg = _sub(sp, "page", help="write the status as a self-refreshing HTML page")
    pg.add_argument("--out", type=Path, required=True)
    pg.add_argument("--title", help="page title (default: the event name and team)")
    pg.add_argument("--refresh", type=int, default=30, help="browser refresh, seconds (default 30)")
    pu = _sub(sp, "push", help="push the status to the phone when it changed")
    pu.add_argument("--url", help="ntfy-style topic URL (default: $CTF_STATUS_PUSH_URL); never printed")
    pu.add_argument("--force", action="store_true", help="send even when nothing changed")
    pu.add_argument("--min-interval", type=float, default=60.0,
                    help="seconds between pushes unless the alerts changed (default 60)")
    pu.add_argument("--title")
    lo = _sub(sp, "loop", help="regenerate the page and push on change, every S seconds")
    lo.add_argument("--every", type=float, default=30.0)
    lo.add_argument("--page", type=Path, dest="page_out")
    lo.add_argument("--title")
    lo.add_argument("--refresh", type=int, default=30)
    lo.add_argument("--push", action="store_true")
    lo.add_argument("--url")
    lo.add_argument("--min-interval", type=float, default=60.0)
    lo.add_argument("--count", type=int, default=0, help="stop after N rounds (default: run until stopped)")
    sm = _sub(sp, "smoke", help="check the deployed status page answers, is fresh and is ours")
    sm.add_argument("url")
    g = sm.add_mutually_exclusive_group()
    g.add_argument("--local", type=Path, help="the page generated here: the deployed digest must match it")
    g.add_argument("--expect-digest")
    sm.add_argument("--max-age", type=float, default=600.0, help="seconds (default 600)")
    jb = sp.add_parser("job", help="run a command as a recorded job: -- CMD ...")
    jb.add_argument("--name", required=True)
    jb.add_argument("cmd", nargs=argparse.REMAINDER)
    ar = _sub(sp, "arm", help="record HEAD as the commit armed for the event")
    ar.add_argument("--note", default="")
    fo = _sub(sp, "forget", help="remove records of runs that died")
    fo.add_argument("--died", action="store_true", required=True)


def _sub(sp, name: str, **kw) -> argparse.ArgumentParser:
    p = sp.add_parser(name, **kw)
    _event_opts(p, sub=True)
    return p


def _sources(args):
    from .. import live
    return live.default_sources(event_slug=getattr(args, "event", None), no_event=getattr(args, "no_event", False))


def _status_state():
    from .. import paths
    try:
        return paths.status_state()
    except FileNotFoundError as e:
        from ..live import LiveError
        raise LiveError(str(e)) from None


def _show(args) -> int:
    from .. import live
    snap = live.collect(_sources(args))
    if args.json or getattr(args, "json_sub", False):
        print(json.dumps(snap, indent=1, sort_keys=True, default=str))
    else:
        print(live.render_text(snap))
    return 0


def _page(args) -> int:
    from .. import live
    snap = live.collect(_sources(args))
    out = live.write_page(snap, args.out, title=live.page_title(snap, args.title), refresh=args.refresh)
    print(f"live: page {out} digest {snap['digest'][:12]}")
    return 0


def _push_once(args, snap, src) -> int:
    from .. import live
    url = live.push_url(args.url)
    try:
        what = live.push(snap, url, state_dir=_status_state(), title=live.page_title(snap, args.title),
                         force=getattr(args, "force", False), min_interval=args.min_interval, profile=src.profile)
    except live.PushError as e:
        print(f"live: {e}", file=sys.stderr)
        return 1
    print(f"live: push {what}")
    return 0


def _push(args) -> int:
    from .. import live
    src = _sources(args)
    return _push_once(args, live.collect(src), src)


def _loop(args) -> int:
    from .. import live
    if not args.page_out and not args.push:
        raise live.LiveError("loop needs --page FILE, --push, or both")
    if args.push:
        live.push_url(args.url)                 # fail before the first round, naming the variable
    rounds, rc = 0, 0
    while True:
        src = _sources(args)
        snap = live.collect(src)
        if args.page_out:
            live.write_page(snap, args.page_out, title=live.page_title(snap, args.title), refresh=args.refresh)
        if args.push:
            rc = max(rc, _push_once(args, snap, src))
        rounds += 1
        sys.stdout.flush()
        if args.count and rounds >= args.count:
            return rc
        time.sleep(max(0.0, args.every))


def _smoke(args) -> int:
    from .. import live
    expect = args.expect_digest
    if args.local:
        if not args.local.is_file():
            raise live.LiveError(f"--local {args.local}: no such page")
        expect = live.page_meta(args.local.read_text(encoding="utf-8")).get(live.META_DIGEST)
        if not expect:
            raise live.LiveError(f"--local {args.local}: not a ctf live page (no {live.META_DIGEST} meta tag)")
    src = _sources(args)
    checks = live.smoke(args.url, max_age=args.max_age, expect_digest=expect, profile=src.profile)
    for c in checks:
        print(f"{'ok  ' if c.ok else 'FAIL'} {c.name:<7} {c.detail}")
    ok = all(c.ok for c in checks)
    print(f"SMOKE result={'pass' if ok else 'fail'}")
    return 0 if ok else 1


def _job(args) -> int:
    from .. import live, paths, progress
    cmd = list(args.cmd)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    return live.run_job(args.name, cmd, folder=_status_state() / progress.PROGRESS_DIR, repo=paths.repo_root())


def _arm(args) -> int:
    from .. import live
    src = _sources(args)
    if src.workdir is None:
        raise live.LiveError(f"cannot arm: {src.notes.get('event', 'no event')}")
    src.workdir.mkdir(parents=True, exist_ok=True)
    rec = live.arm(src.workdir, src.git, note=args.note)
    print(f"live: armed {rec['commit'][:12]} ({rec['branch']}) for {src.profile.slug}"
          + (f"; warning: {rec['dirty']} uncommitted tracked file(s) are not in the armed commit" if rec["dirty"] else ""))
    return 0


def _forget(args) -> int:
    from .. import live
    src = _sources(args)
    gone = live.forget_died([f for f in (src.gate_progress, src.job_progress) if f is not None])
    print(f"live: removed {len(gone)} died run record(s)" + (": " + ", ".join(gone) if gone else ""))
    return 0


def run(args: argparse.Namespace) -> int:
    from ..live import LiveError
    action = args.action or "show"
    try:
        return {"show": _show, "page": _page, "push": _push, "loop": _loop, "smoke": _smoke, "job": _job,
                "arm": _arm, "forget": _forget}[action](args)
    except LiveError as e:
        print(f"live: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
