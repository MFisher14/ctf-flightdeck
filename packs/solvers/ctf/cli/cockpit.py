"""ctf cockpit: the manual-mode cockpit (B-209). Nothing here touches the platform.

Player:
    ctf cockpit watch [--inbox DIR] [--batch N]     live view: files drops, shows needs + queue
    ctf cockpit add NAME... [--category C] [--points N] [--no-files]
    ctf cockpit describe ID (-|TEXT)                set a description (- reads stdin)
    ctf cockpit focus [ID | --clear]                where loose drops go
    ctf cockpit file SRC ID [--as NAME] [--replace] file one drop by hand
    ctf cockpit next [--copy]                       the next flag to submit (--copy: pbcopy)
    ctf cockpit accepted QID | rejected QID         record the platform's answer
    ctf cockpit confirm QID                         send a held item past the wrong-answer stop
    ctf cockpit done NEED                           close / dismiss a need

Agents and player:
    ctf cockpit sweep                               one pass of the watcher
    ctf cockpit needs [--batch N | --all] [--json]  what the player still has to fetch
    ctf cockpit need ID TEXT [--kind K] [--expect GLOB]
    ctf cockpit enqueue ID FLAG --provenance P [--nonstandard] [--guess] [--confirmed]
    ctf cockpit queue [--all] [--json]
    ctf cockpit withdraw QID [--note N]
    ctf cockpit status [--json]

Exit codes: 0 ok, 2 usage or configuration (not a manual event, unknown challenge, ...), 4 a policy
refusal (the queue or a verdict said no).
"""
from __future__ import annotations

import argparse
import getpass
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .. import event as _event
from ..event import EventError
from ..platform import PlatformError

HELP = "manual-mode cockpit: drop-zone watcher, needs checklist, submission queue (no platform calls)"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--inbox", type=Path, help="the drop zone (default: <workdir>/inbox)")
    p.add_argument("--settle", type=float, default=2.0,
                   help="seconds a file must sit unmodified before it is filed (default 2)")
    sp = p.add_subparsers(dest="action", required=True)

    w = sp.add_parser("watch", help="live view: file drops, show needs and the queue, repeat")
    w.add_argument("--interval", type=float, default=2.0)
    w.add_argument("--batch", type=int, default=3, help="needs listed at a time (the total is always shown)")
    w.add_argument("--once", action="store_true", help="one pass, then exit")
    sp.add_parser("sweep", help="one pass of the drop-zone watcher").add_argument("--json", action="store_true")

    a = sp.add_parser("add", help="register challenges the player sees on the platform")
    a.add_argument("names", nargs="+")
    a.add_argument("--category")
    a.add_argument("--points", type=int)
    a.add_argument("--no-files", action="store_true", help="it has no files to download")

    d = sp.add_parser("describe", help="set a challenge's description")
    d.add_argument("id")
    d.add_argument("text", help="the description, or - to read stdin")

    f = sp.add_parser("focus", help="file loose drops under this challenge")
    f.add_argument("id", nargs="?")
    f.add_argument("--clear", action="store_true")

    fi = sp.add_parser("file", help="file one drop by hand")
    fi.add_argument("src", help="a path, or a name in the inbox / at the drop root")
    fi.add_argument("id")
    fi.add_argument("--as", dest="as_name", help="file it under this name")
    fi.add_argument("--replace", action="store_true", help="replace a different file of the same name")

    n = sp.add_parser("needs", help="what the player still has to fetch, N at a time")
    n.add_argument("--batch", type=int, default=3)
    n.add_argument("--all", action="store_true")
    n.add_argument("--json", action="store_true")

    nd = sp.add_parser("need", help="ask the player for something")
    nd.add_argument("id")
    nd.add_argument("text")
    nd.add_argument("--kind", default="other", help="files, redownload, capture, instance, description, other")
    nd.add_argument("--expect", help="glob of the file that satisfies it (it closes itself when filed)")

    dn = sp.add_parser("done", help="close an added need or dismiss a computed one")
    dn.add_argument("need")
    dn.add_argument("--note", default="")

    e = sp.add_parser("enqueue", help="queue a flag for the player to submit")
    e.add_argument("id")
    e.add_argument("flag")
    e.add_argument("--provenance", required=True, help="where the value came from")
    e.add_argument("--nonstandard", action="store_true", help="an answer the brief defines, not a flag")
    e.add_argument("--guess", action="store_true", help="an unreasoned variant (counts against guess_budget)")
    e.add_argument("--confirmed", action="store_true", help="the player said yes past the wrong-answer stop")

    q = sp.add_parser("queue", help="flags waiting to be submitted")
    q.add_argument("--all", action="store_true", help="include decided ones")
    q.add_argument("--json", action="store_true")

    nx = sp.add_parser("next", help="the next flag to submit")
    nx.add_argument("--copy", action="store_true", help="put it on the clipboard (pbcopy)")

    for verb, hlp in (("accepted", "the platform accepted it"), ("rejected", "the platform rejected it"),
                      ("confirm", "the player's yes: send this held item past the wrong-answer stop "
                                 "(also needs `ctf submit-queue approve <id> --reason ...`)")):
        v = sp.add_parser(verb, help=hlp)
        v.add_argument("qid", type=int)
        v.add_argument("--by", help="who submitted it (default: this user)")
        v.add_argument("--relayed", help="from a script with no terminal: the player's own words")

    wd = sp.add_parser("withdraw", help="drop a queued flag without submitting it")
    wd.add_argument("qid", type=int)
    wd.add_argument("--note", default="")

    sp.add_parser("status", help="one line per challenge").add_argument("--json", action="store_true")


def _cockpit(args):
    from ..cockpit import Cockpit
    prof = _event.load(args.event) if args.event else _event.current()
    return Cockpit(prof, inbox=args.inbox, settle=args.settle)


def _copy(text: str) -> None:
    exe = shutil.which("pbcopy")
    if exe is None:
        raise FileNotFoundError("--copy needs pbcopy on PATH (macOS); it is not there: copy the value "
                                "by hand")
    subprocess.run([exe], input=text.encode("utf-8"), check=True)


def _watch(ck, args) -> int:
    from ..cockpit import board
    ck.track_growth = not args.once        # looping: a file must look the same on two passes
    tty = sys.stdout.isatty()
    try:
        while True:
            try:
                rep = ck.sweep()
                text = board.render(ck.board(), rep, batch=args.batch)
            except (PlatformError, OSError) as e:      # a broken drop folder: say so, keep watching
                text = f"cockpit: error reading the drop folder: {e}"
                if args.once:
                    print(text, file=sys.stderr)
                    return 2
            if tty:
                sys.stdout.write("\x1b[H\x1b[2J")
            print(text, flush=True)
            if args.once:
                return 0
            time.sleep(max(0.2, args.interval))
    except KeyboardInterrupt:
        return 0


def run(args: argparse.Namespace) -> int:
    from ..cockpit import CockpitError, Refused, board
    try:
        ck = _cockpit(args)
        act = args.action
        if act == "watch":
            return _watch(ck, args)
        if act == "sweep":
            rep = ck.sweep()
            if args.json:
                print(json.dumps(rep.to_json(), indent=1))
            else:
                print("\n".join(board.sweep_lines(rep)) or "nothing to file")
            return 0
        if act == "add":
            for name in args.names:
                cid = ck.add(name, category=args.category, points=args.points, no_files=args.no_files)
                print(f"{cid}: {ck.folder(cid)}")
            return 0
        if act == "describe":
            text = sys.stdin.read() if args.text == "-" else args.text
            print(f"{ck.describe(args.id, text)}: description set")
            return 0
        if act == "focus":
            if args.clear or args.id:
                cid = ck.focus(None if args.clear else args.id)
                print(f"focus: {cid}" if cid else "focus cleared")
            else:
                print(f"focus: {ck.current_focus() or '(none)'}")
            return 0
        if act == "file":
            rep = ck.file(args.src, args.id, as_name=args.as_name, replace=args.replace)
            print("\n".join(board.sweep_lines(rep)) or "nothing filed")
            return 0 if rep.filed or rep.duplicates else 4
        if act == "needs":
            items = ck.needs()
            if args.json:
                print(json.dumps([n.__dict__ for n in items], indent=1))
            else:
                print("\n".join(board.needs_lines(items, None if args.all else args.batch)))
            return 0
        if act == "need":
            n = ck.add_need(args.id, args.text, kind=args.kind, expect=args.expect)
            print(f"{n['id']} {n['status']}: {n['challenge']}: {n['text']}"
                  + (f" ({n.get('note')})" if n.get("note") else ""))
            return 0
        if act == "done":
            print(ck.done(args.need, args.note))
            return 0
        if act == "enqueue":
            item = ck.enqueue(args.id, args.flag, provenance=args.provenance, nonstandard=args.nonstandard,
                              guess=args.guess, confirmed=args.confirmed)
            print(f"queued #{item['id']} for {item['challenge']}: the player submits it by hand")
            return 0
        if act == "queue":
            items = ck.queue(all_items=args.all)
            if args.json:
                print(json.dumps(items, indent=1))
            elif args.all:
                for q in items:
                    print(f"#{q['id']} {q['challenge']} {q['status']}: {q['flag']}")
                if not items:
                    print("queue: nothing recorded")
            else:
                print("\n".join(board.queue_lines(items, limit=None)))
            return 0
        if act == "next":
            q = ck.next_item()
            if q is None:
                held = [p for p in ck.queue() if p["held"]]
                print("queue empty: nothing to submit" if not held else
                      f"nothing to submit: {len(held)} held by the event rules (`ctf cockpit queue`; "
                      "`ctf cockpit confirm QID` or `withdraw QID`)")
                return 0
            print("\n".join(board.queue_lines([q])))
            if args.copy:
                _copy(q["flag"])
                print("  (copied to the clipboard)")
            return 0
        if act == "confirm":
            out = ck.confirm(args.qid, by=args.by or getpass.getuser() or "player",
                             interactive=sys.stdin.isatty() and sys.stdout.isatty(), relayed=args.relayed)
            print(f"#{out['id']} {out['challenge']}: confirmed by {out['confirmed_by']}"
                  + (f"; still held: {out['held']}" if out["held"] else "; `ctf cockpit next` serves it"))
            return 0 if out["held"] is None else 4
        if act in ("accepted", "rejected"):
            out = ck.verdict(args.qid, act == "accepted", by=args.by or getpass.getuser() or "player",
                             interactive=sys.stdin.isatty() and sys.stdout.isatty(), relayed=args.relayed)
            print(f"#{out['id']} {out['challenge']}: {out['status']}")
            if act == "accepted":
                print(f"  SOLVED marker written: {ck.folder(out['challenge']) / 'SOLVED'}")
            elif out["stop"]:
                print(f"  wrong_answer_stop: {out['wrong']} wrong answer(s) on {out['challenge']} "
                      f"(limit {ck.profile.rules.wrong_answer_stop}): stop and decide before queueing more")
            if out["held"]:
                print(f"  held now (not served by `next`): {', '.join(f'#{i}' for i in out['held'])}; "
                      "`ctf cockpit confirm QID` to send one anyway, or `withdraw QID`")
            return 0
        if act == "withdraw":
            q = ck.withdraw(args.qid, args.note)
            print(f"#{q['id']} withdrawn")
            return 0
        if act == "status":
            b = ck.board()
            print(json.dumps(b, indent=1) if args.json else "\n".join(board.status_lines(b)))
            return 0
        raise CockpitError(f"unknown action {act!r}")
    except Refused as e:
        print(f"ctf cockpit: refused: {e}", file=sys.stderr)
        return 4
    except (CockpitError, EventError, PlatformError, FileNotFoundError, subprocess.CalledProcessError) as e:
        print(f"ctf cockpit: {e}", file=sys.stderr)
        return 2
