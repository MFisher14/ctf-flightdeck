"""ctf orch report | status | wait | brief | guard | claude-settings -- the thin orchestrator (B-200,
ctf/orch.py).

    python -m ctf orch report ID STATE [NOTE] [--by WHO]   a solver's one status line
    python -m ctf orch status [--all] [--width N] [--max-lines N] [--json]
                                    (text form: the board, then each live cause/steer claim with its
                                     status, B-259; --all adds refuted and retracted ones)
    python -m ctf orch wait [--quiet S] [--max-batch S] [--urgent S] [--min-gap S] [--max-wait S]
                            [--max-lines N] [--peek] [--reset] [--json]
    python -m ctf orch brief [--print]
    python -m ctf orch guard                               a PreToolUse hook (reads the hook JSON on stdin)
    python -m ctf orch claude-settings [--write]           the settings file that installs the guard

`--workdir DIR` (before the sub-command) names the event workdir; otherwise $CTF_WORKDIR, else the
current event's. `wait` is meant to run in the background of the orchestrator session: it prints one
digest when a batch is ready and exits 0 (also 0 when `--max-wait` passes with nothing to report: the
first line says so). Exit 2 is a named error (a corrupt or truncated source, a second `wait` on the same
workdir, a bad state). `guard` exits 0 with a deny decision on stdout, or 2 (blocked, reason on stderr)
when it cannot read the hook input or fails; the installed hook command maps any other exit to 2.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event
from .. import orch as _orch
from .. import paths as _paths

HELP = "the thin orchestrator: status lines, a debounced notifier, a challenge-file guard, a session brief"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--workdir", help="the event workdir (default: $CTF_WORKDIR, else the current event's)")
    p.add_argument("--event", help="event slug for the default workdir")
    sp = p.add_subparsers(dest="action", required=True)

    r = sp.add_parser("report", help="append one status line for a challenge")
    r.add_argument("id")
    r.add_argument("state", choices=_orch.STATES)
    r.add_argument("note", nargs="?", default="")
    r.add_argument("--by", default="agent", help="who reports (e.g. claude:12, codex:12)")

    s = sp.add_parser("status", help="one status line per challenge")
    s.add_argument("--all", action="store_true", help="include solved, done and vanished challenges")
    s.add_argument("--width", type=int, default=_orch.LINE_WIDTH)
    s.add_argument("--max-lines", type=int, default=40)
    s.add_argument("--json", action="store_true")

    w = sp.add_parser("wait", help="block until a batch of updates is ready; print one digest")
    w.add_argument("--quiet", type=float, default=_orch.QUIET_S, help="seconds with no new update that end a batch")
    w.add_argument("--max-batch", type=float, default=_orch.MAX_BATCH_S, help="longest a batch is held")
    w.add_argument("--urgent", type=float, default=_orch.URGENT_S, help="hold after an urgent update")
    w.add_argument("--min-gap", type=float, default=_orch.MIN_GAP_S,
                   help="seconds between two non-urgent digests")
    w.add_argument("--max-wait", type=float, help="give up after this many seconds with nothing to report")
    w.add_argument("--poll", type=float, default=_orch.POLL_S)
    w.add_argument("--max-lines", type=int, default=_orch.DIGEST_LINES)
    w.add_argument("--peek", action="store_true", help="print the digest without moving the cursor")
    w.add_argument("--reset", action="store_true", help="move the cursor to now (skip the backlog) and exit")
    w.add_argument("--json", action="store_true")

    b = sp.add_parser("brief", help="write the fresh-session brief to <workdir>/orch/brief.md")
    b.add_argument("--print", action="store_true", help="also print it")

    sp.add_parser("guard", help="PreToolUse hook: deny the orchestrator's reads of challenge files")

    c = sp.add_parser("claude-settings", help="print the Claude Code settings that install the guard")
    c.add_argument("--write", action="store_true",
                   help=f"write them to <workdir>/orch/{_orch.SETTINGS_NAME} and print the path")


def _workdir(args: argparse.Namespace) -> Path:
    if args.workdir:
        return Path(args.workdir).expanduser().resolve()
    return _paths.workdir(args.event) if args.event else _paths.workdir()


def run(args: argparse.Namespace) -> int:
    try:
        wd = _workdir(args)
    except (_event.EventError, ValueError) as e:
        print(f"ctf orch: no event workdir ({e}); pass --workdir or set CTF_EVENT", file=sys.stderr)
        return 2
    try:
        return _ACTIONS[args.action](args, wd)
    except _orch.OrchError as e:
        print(f"ctf orch: {e}", file=sys.stderr)
        return 2


def _report(args, wd: Path) -> int:
    rec = _orch.report(args.id, args.state, args.note, by=args.by, workdir=wd)
    print(f"{rec['challenge_id']} {rec['state']}" + (f": {rec['note']}" if rec["note"] else ""))
    return 0


def _status(args, wd: Path) -> int:
    rows = _orch.board(wd)
    if args.json:
        for r in rows:
            if args.all or not r.finished:
                print(json.dumps({"line": _orch.status_line(r, args.width), **r.__dict__}, default=str))
        return 0
    print(_orch.render_board(rows, width=args.width, include_finished=args.all, max_lines=args.max_lines))
    claims = _orch.claims_lines(wd, width=args.width, max_lines=args.max_lines, include_final=args.all)
    if claims:                      # B-259: each cause/steer claim with its status
        print("\n".join(claims))
    return 0


def _wait(args, wd: Path) -> int:
    if args.reset:
        offs = _orch.reset(wd)
        print("ctf orch: cursor moved to now (" + ", ".join(f"{k} byte {v}" for k, v in offs.items()) + ")")
        return 0
    with _orch.Notifier(wd, quiet_s=args.quiet, max_batch_s=args.max_batch, urgent_s=args.urgent,
                        min_gap_s=args.min_gap, poll_s=args.poll) as n:
        try:
            d = n.wait(max_wait_s=args.max_wait)
        except KeyboardInterrupt:
            print("ctf orch: wait interrupted; cursor not moved", file=sys.stderr)
            return 130
        print(json.dumps(d.to_dict()) if args.json else d.render(max_lines=args.max_lines), flush=True)
        if not args.peek:
            n.commit(d)
    return 0


def _brief(args, wd: Path) -> int:
    p = _orch.write_brief(wd)
    if args.print:
        print(p.read_text(encoding="utf-8"))
    print(f"ctf orch: brief written to {p}; start the fresh session from it")
    return 0


def _guard(args, wd: Path) -> int:
    try:
        text = sys.stdin.read()
    except Exception as e:              # noqa: BLE001 -- unreadable stdin blocks the call (exit 2)
        print(f"ctf orch guard: cannot read the hook input ({type(e).__name__}: {e}); blocked", file=sys.stderr)
        return 2
    code, out, err = _orch.guard_main(text, workdir=wd)
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    return code


def _settings(args, wd: Path) -> int:
    if args.write:
        p = _orch.write_settings(wd)
        print(p)
        print(f"start the orchestrator session with: claude --settings {p}", file=sys.stderr)
        return 0
    print(json.dumps(_orch.claude_settings(wd), indent=2))
    return 0


_ACTIONS = {"report": _report, "status": _status, "wait": _wait, "brief": _brief, "guard": _guard,
            "claude-settings": _settings}
