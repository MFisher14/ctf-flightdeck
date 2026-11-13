"""ctf notes: the player-notes feed (B-168): organizer rulings, Discord intel, solve counts.

    python -m ctf notes add TEXT... [--challenge ID] [--kind K] [--file F ...]
    python -m ctf notes add -            the note text from stdin (e.g. `pbpaste | ... add -`)
    python -m ctf notes add --paste      the note text from the clipboard (pbpaste)
    python -m ctf notes retract ID [--reason R]
    python -m ctf notes list [--challenge ID] [--all]
    python -m ctf notes show ID
    python -m ctf notes pending --agent NAME [--challenge ID] [--peek]
                                         notes this agent has not seen yet (moves its cursor)
    python -m ctf notes sync             take in the inbox/ folder and player-notes.md now
    python -m ctf notes where [--init]   the notes folder, its drop folder and its notes file
    python -m ctf notes claude-hooks [--challenge ID]
                                         the hooks JSON for a Claude session not started by
                                         tools/claude_launch (which installs it itself)

The feed lives in <event workdir>/notes (--dir overrides). Kinds: ruling, fix, intel (default),
timing, other. See ctf/notes.py for the drop folder and file formats.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from .. import event as _event
from .. import notes as _notes

HELP = "player-notes feed: add organizer rulings / Discord intel, agents get what is new"


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("--event", help="event slug (default: the current event)")
    p.add_argument("--dir", help="the notes folder (default: <event workdir>/notes)")
    sp = p.add_subparsers(dest="action", required=True)
    ad = sp.add_parser("add", help="add a note (text, '-' for stdin, or --paste)")
    ad.add_argument("text", nargs="*", help="the note; '-' reads it from stdin")
    ad.add_argument("--paste", action="store_true", help="read the note from the clipboard (pbpaste)")
    ad.add_argument("--challenge", help="only for agents on this challenge (default: everyone)")
    ad.add_argument("--kind", default=_notes.DEFAULT_KIND, choices=_notes.KINDS)
    ad.add_argument("--file", action="append", default=[], metavar="F",
                    help="attach a file (a screenshot); copied into the notes folder")
    rt = sp.add_parser("retract", help="withdraw a note (organizers reversed it, it was wrong)")
    rt.add_argument("id", type=int)
    rt.add_argument("--reason", default="")
    ls = sp.add_parser("list", help="the active notes")
    ls.add_argument("--challenge", help="only notes an agent on this challenge would get")
    ls.add_argument("--all", action="store_true", help="include retracted notes")
    sh = sp.add_parser("show", help="one note in full")
    sh.add_argument("id", type=int)
    pe = sp.add_parser("pending", help="notes an agent has not seen yet")
    pe.add_argument("--agent", required=True, help="a stable name for the agent (its cursor)")
    pe.add_argument("--challenge", help="the agent's challenge (default: it gets every note)")
    pe.add_argument("--peek", action="store_true", help="do not move the cursor")
    sp.add_parser("sync", help="take in the inbox/ folder and player-notes.md now")
    wh = sp.add_parser("where", help="print the notes folder, drop folder and notes file")
    wh.add_argument("--init", action="store_true", help="create them")
    ch = sp.add_parser("claude-hooks", help="print the Claude Code hooks block for this feed")
    ch.add_argument("--challenge")


def _feed(args) -> _notes.Feed:
    if args.dir:
        return _notes.Feed(Path(args.dir))
    return _notes.Feed.for_event(args.event)


def _clipboard() -> str:
    tool = shutil.which("pbpaste")
    if tool is None:
        raise _notes.NotesError("--paste needs pbpaste (macOS); pipe the text into `add -` instead")
    r = subprocess.run([tool], capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise _notes.NotesError(f"pbpaste failed (exit {r.returncode})")
    return r.stdout


def _note_text(args) -> str:
    sources = sum([bool(args.paste), args.text == ["-"], bool(args.text) and args.text != ["-"]])
    if sources > 1:
        raise _notes.NotesError("give the note one way: TEXT, '-' (stdin) or --paste")
    if args.paste:
        return _clipboard()
    if args.text == ["-"]:
        return sys.stdin.read()
    return " ".join(args.text)


def _report_problems(got: _notes.Ingested) -> None:
    for prob in got.problems:
        print(f"notes: {prob}", file=sys.stderr)


def run(args: argparse.Namespace) -> int:
    try:
        feed = _feed(args)
        if args.action == "add":
            note = feed.add(_note_text(args), kind=args.kind, challenge=args.challenge,
                            source="paste" if args.paste else "cli", files=args.file)
            scope = f"challenge {note.challenge}" if note.challenge else "every agent"
            print(f"note {note.id} added ({note.kind}, {scope}); running agents get it on their next step")
            return 0
        if args.action == "retract":
            r = feed.retract(args.id, reason=args.reason)
            print(f"note {r.target} retracted (record {r.id}); running agents are told to disregard it")
            return 0
        if args.action == "sync":
            got = feed.sync()
            _report_problems(got)
            for n in got.notes:
                print(f"note {n.id} added from {n.source}")
            if not got.notes:
                print("nothing new")
            return 1 if got.problems else 0
        if args.action == "where":
            if args.init:
                feed.init()
            print(f"notes folder: {feed.root}")
            print(f"drop folder:  {feed.inbox}  (inbox/<challenge id>/ for one challenge)")
            print(f"notes file:   {feed.file_path}  (blocks separated by a --- line)")
            print(f"rendered:     {feed.render_path}")
            return 0
        if args.action == "claude-hooks":
            print(json.dumps({"hooks": _notes.claude_hooks(feed.root, challenge=args.challenge)},
                             indent=2))
            return 0
        got = feed.sync()
        _report_problems(got)
        if args.action == "list":
            ch = _notes.check_challenge(args.challenge)
            shown = [n for n in feed.notes(sync=False)
                     if (args.all or n.retracted is None) and _notes.relevant(n.challenge, ch)]
            for n in shown:
                tag = "" if n.retracted is None else "  [RETRACTED" + (f": {n.retracted}" if n.retracted else "") + "]"
                first = n.text.splitlines()[0] if n.text else ""
                print(f"{_notes.header(n)}  ({n.source}){tag}\n    {first[:120]}")
            if not shown:
                print("no notes")
            return 0
        if args.action == "show":
            n = feed.get(args.id)
            print(_notes.render([n], root=feed.root))
            if n.retracted is not None:
                print(f"\nRETRACTED{': ' + n.retracted if n.retracted else ''}")
            return 0
        if args.action == "pending":
            items = feed.pending(args.agent, challenge=args.challenge, peek=args.peek)
            out = _notes.render(items, root=feed.root,
                                intro=f"{len(items)} new player note(s) for {args.agent}:")
            print(out or "no new player notes")
            return 0
    except (_notes.NotesError, _event.EventError) as e:
        print(f"ctf notes: {e}", file=sys.stderr)
        return 2
    except OSError as e:    # e.g. a fenced Claude session, whose notes folder is write-denied
        print(f"ctf notes: cannot use the notes folder: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    raise AssertionError(args.action)
