"""ctf handoff: the shared Claude/Codex handoff board (B-180). Runbook: docs/handoff.md.

    python -m ctf handoff post --challenge C --mode M [--guidance-file F] [--label L] [--no-launch]
    python -m ctf handoff batch FILE.toml [--no-launch]       many handoffs, validated first
    python -m ctf handoff launch ID                           start a queued/failed detached handoff
    python -m ctf handoff list [--all] [--json]
    python -m ctf handoff show ID [--json]
    python -m ctf handoff inbox --as NAME [--peek]            queued work and new notes for NAME
    python -m ctf handoff claim ID --as NAME                  take a queued handoff; prints its brief path
    python -m ctf handoff note [ID] --as NAME [--to NAME] TEXT
    python -m ctf handoff done ID --as NAME --status solved|stuck|failed [--summary TEXT]
    python -m ctf handoff cancel ID --as NAME --reason TEXT   (a running agent: SIGINT, then SIGTERM)
    python -m ctf handoff reap [--as NAME]                    mark exited, unfinished launches failed
    python -m ctf handoff check-brief FILE                    exit 1 if the brief is truncated/edited
    python -m ctf handoff modes                               the configured modes (fails on bad config)

--as defaults to $CTF_HANDOFF_AS (for reap, to "reaper" when neither is set). Exit codes: 0 ok, 1 a launch failed or a check failed, 2 refused.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .. import env
from .. import event as _event
from .. import handoff as H

HELP = "shared Claude/Codex handoff board: post, launch, claim, note, done"
REAPER = "reaper"


def _common(p: argparse.ArgumentParser, *, who: bool = True) -> None:
    if who:
        p.add_argument("--as", dest="who", help="who is acting (claude, codex, a player); default $CTF_HANDOFF_AS")
    p.add_argument("--config", help="modes config file (default ctf/handoff.toml + events/<slug>/handoff.toml)")


def _launch_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--codex-bin", help="codex executable (default $CODEX_BIN or codex)")
    p.add_argument("--claude-bin", help="claude executable (default $CLAUDE_BIN or claude)")
    p.add_argument("--grace", type=float, default=3.0,
                   help="seconds to watch a launch for an immediate failure (default 3)")


def add_arguments(p: argparse.ArgumentParser) -> None:
    sp = p.add_subparsers(dest="action", required=True)
    po = sp.add_parser("post", help="write a brief and launch or queue it")
    _common(po)
    _launch_opts(po)
    po.add_argument("--challenge", required=True, help="challenge id, folder name or path")
    po.add_argument("--mode", required=True, help="a configured mode (python -m ctf handoff modes)")
    po.add_argument("--to", help="the harness (must match the mode's; default the mode's)")
    po.add_argument("--label", help="short label to tell parallel handoffs apart")
    po.add_argument("--guidance-file", help="the guidance (default: read stdin)")
    po.add_argument("--exclusion-reason", help="why the guidance closes off a technique, when it must")
    po.add_argument("--no-launch", action="store_true", help="queue it even if the mode launches")

    ba = sp.add_parser("batch", help="post (and launch) every [[handoff]] in a TOML file")
    _common(ba)
    _launch_opts(ba)
    ba.add_argument("file")
    ba.add_argument("--no-launch", action="store_true")

    la = sp.add_parser("launch", help="start a queued or failed handoff, detached")
    _common(la)
    _launch_opts(la)
    la.add_argument("id")

    li = sp.add_parser("list", help="the board")
    li.add_argument("--all", action="store_true", help="include done and cancelled")
    li.add_argument("--json", action="store_true")

    sh = sp.add_parser("show", help="one handoff, its notes and whether its brief is intact")
    sh.add_argument("id")
    sh.add_argument("--json", action="store_true")

    ib = sp.add_parser("inbox", help="queued work and new notes for you")
    _common(ib)
    ib.add_argument("--peek", action="store_true", help="do not advance your read cursor")

    cl = sp.add_parser("claim", help="take a queued handoff")
    _common(cl)
    cl.add_argument("id")

    no = sp.add_parser("note", help="post a finding or question to the board")
    _common(no)
    no.add_argument("--to", default=None, help="who it is for (default any)")
    # REMAINDER + an intermixed re-parse in run(): `note h3 --as codex "text"` (options between
    # the id and the text) is how agents write it, and plain argparse rejects that order.
    no.add_argument("args", nargs=argparse.REMAINDER, metavar="[ID] TEXT")

    dn = sp.add_parser("done", help="finish a handoff")
    _common(dn)
    dn.add_argument("id")
    dn.add_argument("--status", required=True, choices=H.DONE_STATUSES)
    dn.add_argument("--summary")

    ca = sp.add_parser("cancel", help="cancel a handoff (stops a running agent)")
    _common(ca)
    ca.add_argument("id")
    ca.add_argument("--reason", required=True)

    rp = sp.add_parser("reap", help="mark launched agents that exited without finishing as failed")
    _common(rp)

    cb = sp.add_parser("check-brief", help="verify a brief's end marker and digest")
    cb.add_argument("file")

    mo = sp.add_parser("modes", help="print the configured modes")
    _common(mo, who=False)


def parse_note(rest: list[str]) -> argparse.Namespace:
    """The words after `note`, options anywhere: `note h3 --as codex "text"` (plain argparse
    rejects options between two positionals, and that is how agents write it)."""
    np = argparse.ArgumentParser(prog="ctf handoff note", exit_on_error=False, add_help=False)
    np.add_argument("--as", dest="who")
    np.add_argument("--to")
    np.add_argument("words", nargs="*")
    try:
        ns, unknown = np.parse_known_intermixed_args(rest)
    except argparse.ArgumentError as e:
        raise H.HandoffError(f"note: {e}") from None
    if unknown:
        raise H.HandoffError(f"note: unrecognized arguments: {' '.join(unknown)}")
    if not ns.words:
        raise H.HandoffError("a note needs text")
    return ns


def _modes(args, profile):
    return H.load_modes(profile.slug, config=getattr(args, "config", None))


def _bins(args) -> dict:
    return dict(codex_bin=args.codex_bin, claude_bin=args.claude_bin, grace=args.grace)


def _guidance(args) -> str:
    if args.guidance_file:
        f = Path(args.guidance_file)
        if not f.is_file():
            raise H.HandoffError(f"guidance file {f} does not exist")
        return f.read_text(encoding="utf-8")
    if sys.stdin is None or sys.stdin.isatty():
        raise H.HandoffError("no guidance: pass --guidance-file FILE or pipe it on stdin")
    return sys.stdin.read()


def _line(h: H.Handoff) -> str:
    st = h.status if h.status != "done" else f"done:{h.done_status}"
    if h.status == "running" and h.pid and not H.pid_alive(h.pid):
        st += " (process gone: run reap)"
    who = f" by {h.claimed_by}" if h.claimed_by else ""
    lab = f" [{h.label}]" if h.label else ""
    return f"{h.id:<5} {st:<22} to {h.to:<7} mode {h.mode:<12} {Path(h.challenge_dir).name}{lab}{who}"


def _after_post(board, h, m, args, by, profile, modes) -> int:
    print(f"POSTED {h.id} -> {h.to} (mode {m.name}: {m.describe()})")
    print(f"  brief  {h.brief}")
    print(f"  result {h.result}")
    if m.launch == "detached" and not args.no_launch:
        r = H.launch(board, h.id, by=by, modes=modes, profile=profile, **_bins(args))
        print(("LAUNCHED " if r.ok else "LAUNCH FAILED ") + r.message, file=sys.stdout if r.ok else sys.stderr)
        if not r.ok and r.handoff.failure:
            tail = H.log_tail(r.handoff.log or str(Path(h.brief).parent / "launch.log"))
            if tail:
                print(tail, file=sys.stderr)
        return 0 if r.ok else 1
    print(f"QUEUED: a ready {h.to} agent runs: python -m ctf handoff claim {h.id} --as {h.to}")
    return 0


def run(args: argparse.Namespace) -> int:
    try:
        return _run(args)
    except H.HandoffError as e:
        print(f"handoff: {e}", file=sys.stderr)
        return 2
    except _event.EventError as e:
        print(f"handoff: {e}", file=sys.stderr)
        return 2


def _run(args: argparse.Namespace) -> int:
    board = H.Board()
    a = args.action
    if a == "check-brief":
        try:
            hid = H.check_brief(args.file)
        except H.HandoffError as e:
            print(f"BRIEF NOT INTACT: {e}", file=sys.stderr)
            return 1
        print(f"brief intact: {hid}")
        return 0
    if a == "list":
        hs = [h for h in board.state().values() if args.all or h.status not in H.TERMINAL]
        if args.json:
            print(json.dumps([h.as_dict() for h in hs], indent=1))
        else:
            for h in hs:
                print(_line(h))
            if not hs:
                print("board empty" if args.all else "nothing open (--all shows finished handoffs)")
        return 0
    if a == "show":
        h = board.get(args.id)
        try:
            H.check_brief(h.brief)
            intact = "intact"
        except H.HandoffError as e:
            intact = f"NOT INTACT: {e}"
        if args.json:
            print(json.dumps({**h.as_dict(), "brief_check": intact}, indent=1))
            return 0
        print(_line(h))
        print(f"  brief  {h.brief} ({intact})")
        print(f"  result {h.result}")
        if h.log:
            print(f"  log    {h.log} (pid {h.pid})")
        if h.failure:
            print(f"  failure: {h.failure}")
        if h.summary:
            print(f"  summary: {h.summary}")
        for n in h.notes:
            print(f"  note {time.strftime('%H:%M:%S', time.localtime(n['ts']))} {n['by']} -> {n['to']}: {n['text']}")
        return 0

    if a == "modes":
        profile = _event.current()
        for m in _modes(args, profile).values():
            print(f"{m.name:<14} {m.describe()}   [{m.source}]")
        return 0

    if a == "note":
        extra = parse_note(args.args)
        by = H.check_who(extra.who or getattr(args, "who", None))
        hid = extra.words[0] if len(extra.words) > 1 and H._ID_RE.match(extra.words[0]) else None
        text = " ".join(extra.words[1:] if hid else extra.words)
        rec = board.note(text, by=by, hid=hid, to=extra.to or args.to or H.TO_ANY)
        print(f"noted #{rec['seq']}" + (f" on {hid}" if hid else ""))
        return 0
    if a == "reap":       # an operator chore: the actor defaults to "reaper", still validated
        by = H.check_who(args.who or env.get("CTF_HANDOFF_AS") or REAPER)
        reaped = board.reap(by=by)
        for h in reaped:
            print(f"{h.id} failed: {h.failure}")
        if not reaped:
            print("nothing to reap")
        return 0
    by = H.check_who(getattr(args, "who", None))
    if a == "post":
        profile = _event.current()
        modes = _modes(args, profile)
        h = H.post(board, challenge=args.challenge, mode=args.mode, guidance=_guidance(args), by=by,
                   to=args.to, label=args.label, exclusion_reason=args.exclusion_reason, modes=modes,
                   profile=profile)
        return _after_post(board, h, modes[h.mode], args, by, profile, modes)
    if a == "batch":
        profile = _event.current()
        modes = _modes(args, profile)
        entries = H.read_batch(args.file)
        errors = []
        for i, e in enumerate(entries, 1):
            try:
                H.preflight_entry(board, e, modes)
            except H.HandoffError as err:
                errors.append(f"  #{i} ({e.challenge}, {e.mode}): {err}")
        if errors:
            print("handoff: batch refused, nothing posted:\n" + "\n".join(errors), file=sys.stderr)
            return 2
        rc = 0
        for e in entries:
            h = H.post(board, challenge=e.challenge, mode=e.mode, guidance=e.guidance, by=by, to=e.to,
                       label=e.label, exclusion_reason=e.exclusion_reason, modes=modes, profile=profile)
            ns = argparse.Namespace(**{**vars(args), "no_launch": args.no_launch or not e.launch})
            rc = max(rc, _after_post(board, h, modes[h.mode], ns, by, profile, modes))
        return rc
    if a == "launch":
        profile = _event.current()
        r = H.launch(board, args.id, by=by, modes=_modes(args, profile), profile=profile, **_bins(args))
        print(("LAUNCHED " if r.ok else "LAUNCH FAILED ") + r.message, file=sys.stdout if r.ok else sys.stderr)
        return 0 if r.ok else 1
    if a == "inbox":
        tasks, notes = board.inbox(by, peek=args.peek)
        for h in tasks:
            print("TASK " + _line(h))
            print(f"     take it: python -m ctf handoff claim {h.id} --as {by}")
        for n in notes:
            on = f" on {n['id']}" if n.get("id") else ""
            print(f"NOTE #{n['seq']} from {n['by']}{on}: {n['text']}")
        if not tasks and not notes:
            print("inbox empty")
        return 0
    if a == "claim":
        h = board.claim(args.id, by=by)     # refuses a truncated brief
        print(f"CLAIMED {h.id} for {by}. Read the whole brief: {h.brief}")
        print(f"  write your answer to {h.result}")
        print(f"  finish with: python -m ctf handoff done {h.id} --as {by} --status solved|stuck|failed")
        return 0
    if a == "done":
        h = board.done(args.id, by=by, status=args.status, summary=args.summary)
        print(f"{h.id} done: {h.done_status}. Result: {h.result}")
        if h.done_status == "solved":
            print("  orchestrator: verify the flag, then submit once through the submit gate")
        return 0
    if a == "cancel":
        h = H.stop(board, args.id, by=by, reason=args.reason)
        print(f"{h.id} cancelled")
        return 0
    raise H.HandoffError(f"unknown action {a}")
