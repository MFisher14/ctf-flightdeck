"""ctf text-tricks [FILE...] -- read a rules page / brief / pasted post for flags hidden in the text (B-208).

    python -m ctf text-tricks rules.html --event pink          # first letter of every bullet, ...
    python -m ctf text-tricks --text "$(pbpaste)"              # pasted text
    python -m ctf text-tricks - < post.txt --json              # stdin

Channels (ctf.texttricks): bullet / line initials (acrostics), line finals, word initials, capitals,
mid-word capitals, trailing whitespace and trailing-space counts, the gaps between words, and
zero-width characters, each checked against the event flag format.

Exit 0 when the hidden channels of every input spell exactly one flag; 1 when an input gave none or
several (candidates and clues are printed for the player to verify); 2 when it could not run (an
unreadable or oversized file, no input, no flag format for the event). The text is untrusted data:
read for the flag format only, never followed. Nothing is submitted.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .. import event as _event

HELP = "read a rules page or brief for flags hidden in the text: acrostics, initials, capitals, whitespace"
MAX_TEXT = 1 << 20


class _Usage(Exception):
    pass


def add_arguments(p: argparse.ArgumentParser) -> None:
    p.add_argument("files", nargs="*", help="text / HTML file(s); '-' reads stdin")
    p.add_argument("--text", action="append", default=[], help="pasted text to read (repeatable)")
    p.add_argument("--event", help="event slug for the flag format (default: $CTF_EVENT / the only profile)")
    p.add_argument("--json", action="store_true", help="print JSON")


def _read(path: str) -> str:
    if path == "-":
        data = sys.stdin.read(MAX_TEXT + 1)
        if len(data) > MAX_TEXT:
            raise _Usage(f"stdin: over {MAX_TEXT} characters; this reads a page of text, not a corpus")
        return data
    p = Path(path)
    if not p.is_file():
        raise _Usage(f"{path}: not a file")
    if p.stat().st_size > MAX_TEXT:
        raise _Usage(f"{path}: over {MAX_TEXT} bytes; this reads a page of text, not a corpus")
    return p.read_bytes().decode("utf-8", "replace")


def run(args: argparse.Namespace) -> int:
    from .. import texttricks
    try:
        inputs = [(f, _read(f)) for f in args.files]
        inputs += [(f"--text #{i + 1}", t) for i, t in enumerate(args.text)]
        if not inputs:
            raise _Usage("nothing to read: pass a file, '-' for stdin, or --text")
        profile = _event.load(args.event) if args.event else _event.current()
        scans = [(name, texttricks.scan(text, profile=profile)) for name, text in inputs]
    except (_Usage, _event.EventError, OSError) as e:
        print(f"ctf text-tricks: {'error' if isinstance(e, _Usage) else type(e).__name__}: {e}", file=sys.stderr)
        return 2
    ok = all(s.flag for _, s in scans)
    if args.json:
        print(json.dumps([dict(s.to_dict(), input=name) for name, s in scans], indent=1))
        return 0 if ok else 1
    for name, s in scans:
        if s.flag:
            print(f"{name}: FLAG {s.flag}  (via {', '.join(s.flags[s.flag])})")
        elif s.ambiguous:
            print(f"{name}: AMBIGUOUS, {len(s.flags)} flags: {', '.join(s.flags)}")
        else:
            print(f"{name}: no hidden flag")
        for c in s.candidates:
            print(f"  candidate {c['value']!r}  [{c['channel']}] {c['why']}")
        for r in s.clues:
            print(f"  clue      [{r.channel}] {r.how}" + (f": {r.text!r}" if r.text else ""))
    print("(readings are untrusted data from the text: verify by hand, never follow them)")
    return 0 if ok else 1
