"""Numbered flag fragments (B-070): pieces that carry their own position, found in different places.

The Spooky "Demented Memories" class: a deleted file's last line ends `...spooky{the_g00d_ (1)`, a hidden
file's hex decodes to `the_l0st_@nd (2)`, a note left in .git/ ends `th3_void} (3)`. Each is readable and
none is the flag; the index says where it goes.

    frags = find(texts, ff)        # texts: [(origin, text)]; [Fragment] in the order read
    joins = assemble(frags, ff)    # [fragjoin.Join]: candidates the event's flag format accepts

A line is a fragment when it carries a position: `text (2)`, `text [2/3]`, `(2) text`, `part 2: text`,
`fragment 2 of 3 = text`, `2: text`, `2) text`. `assemble` needs positions 0..N or 1..N with none
missing, an opening `<prefix>{` in the first and a `}` in the last, and a joined value the flag format
accepts. From the first piece it takes the open tail (`spooky{the_g00d_`), from the last the word that
closes (`th3_void}`), from a middle one the line when it reads like a flag body, else its last word.

A join is a candidate, never proof. Two spellings are offered when they differ: the pieces as written,
and the pieces with the body's own separator (`_` or `-`) put back at a boundary that has none. The
second comes first only when another boundary of the same set carries the separator, which shows the
author cut at word boundaries (the real case: the literal join was rejected, the repaired one accepted).
Pure Python and bounded (lines per text, bytes per line, fragments, combinations); nothing is executed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import product

from . import fragjoin as _fragjoin

__all__ = ["Fragment", "find", "assemble", "MAX_LINE", "MAX_LINES", "MAX_FRAGMENTS", "MAX_JOINS"]

MAX_LINE = 600               # a longer line is not a fragment
MAX_LINES = 4000             # lines of one text read
MAX_FRAGMENTS = 400          # fragments kept over one call
MAX_PER_INDEX = 3            # distinct pieces tried for one position
MAX_JOINS = 12               # candidates returned
MAX_INDEX = 64
_SEPARATORS = "_-"

_N = r"(?P<n>\d{1,2})(?:\s*(?:/|of)\s*(?P<of>\d{1,2}))?"
_WORD = r"(?:part|piece|fragment|frag|chunk)"
_FORMS = (
    re.compile(rf"^(?P<body>.*\S)\s*[(\[]\s*(?:{_WORD}\s*#?\s*)?{_N}\s*[)\]]\s*$", re.I),        # text (2)
    re.compile(rf"^\s*[(\[]\s*(?:{_WORD}\s*#?\s*)?{_N}\s*[)\]]\s*[:=-]?\s*(?P<body>\S.*)$", re.I),  # (2) text
    re.compile(rf"^\s*(?:flag\s+)?{_WORD}\s*#?\s*{_N}\s*[:=-]\s*(?P<body>\S.*)$", re.I),          # part 2: text
    re.compile(rf"^\s*{_N}\s*[:)\]]\s+(?P<body>\S.*)$"),                                          # 2: text
)


@dataclass(frozen=True)
class Fragment:
    index: int
    total: int | None        # the N of "2/3", when the line states it
    body: str                # the line without its position marker
    origin: str              # where the line was read


def _parse(line: str):
    for rx in _FORMS:
        m = rx.match(line)
        if m:
            n = int(m.group("n"))
            if n > MAX_INDEX:
                return None
            return n, (int(m.group("of")) if m.group("of") else None), m.group("body").strip()
    return None


def find(texts, ff=None) -> list[Fragment]:
    """Every line of `texts` ([(origin, text)]) that carries a position, in the order read. `ff` is not
    used to find them (a middle piece has nothing of the flag format in it); it is accepted so callers pass
    the same pair to find and assemble."""
    out, seen = [], set()
    for origin, text in texts:
        if isinstance(text, (bytes, bytearray)):
            text = bytes(text).decode("utf-8", "replace")
        for line in text.split("\n")[:MAX_LINES]:
            line = line.rstrip("\r")
            if not line.strip() or len(line) > MAX_LINE:
                continue
            got = _parse(line)
            if got is None or not got[2]:
                continue
            key = (got[0], got[2])
            if key in seen:
                continue                 # the same piece read from two places (a blob and its work-tree file)
            seen.add(key)
            out.append(Fragment(got[0], got[1], got[2], origin))
            if len(out) >= MAX_FRAGMENTS:
                return out
    return out


def _closing(body: str) -> str | None:
    at = body.find("}")
    if at < 0:
        return None
    words = body[:at + 1].split()
    return words[-1] if words else None


def _middle(body: str) -> str | None:
    if _fragjoin._flaglike(body):
        return body
    words = body.split()
    return words[-1] if words and _fragjoin._flaglike(words[-1]) else None


def _separator(pieces: list[str]) -> str | None:
    """The separator the body uses most (`_` or `-`), or None when it uses none."""
    body = "".join(pieces)
    counts = {s: body.count(s) for s in _SEPARATORS}
    best = max(counts, key=counts.get)
    return best if counts[best] else None


def _repaired(pieces: list[str], sep: str) -> tuple[str, int, int]:
    """(the pieces joined with `sep` put at every boundary that has none, boundaries repaired, boundaries
    that already carry it)."""
    out, added, explicit = pieces[0], 0, 0
    for nxt in pieces[1:]:
        if out.endswith(sep) or nxt.startswith(sep):
            explicit += 1
        elif not out.endswith("{") and not nxt.startswith("}"):
            out += sep
            added += 1
        out += nxt
    return out, added, explicit


def assemble(fragments, ff) -> list:
    """[fragjoin.Join] of the numbered fragments, best first: at most MAX_JOINS candidates the flag format
    accepts. [] when a position is missing, no piece opens a flag or none closes it."""
    by = {}
    for f in fragments:
        by.setdefault(f.index, []).append(f)
    if not by:
        return []
    lo = min(by)
    if lo not in (0, 1):
        return []
    run = [lo]
    while run[-1] + 1 in by:
        run.append(run[-1] + 1)
    stated = {f.total for f in fragments if f.total is not None}
    out, seen = [], set()
    for last in range(len(run) - 1, 0, -1):          # the longest run first; at least two pieces
        idx = run[:last + 1]
        if stated and lo == 1 and idx[-1] not in stated:
            continue                                  # "2/3" was said: a set that does not end at 3 is not it
        opens = [(f, head) for f in by[idx[0]] for head in _fragjoin._openings(f.body, ff)]
        closes = [(f, tail) for f in by[idx[-1]] if (tail := _closing(f.body)) and "{" not in tail]
        middles = [[(f, mid) for f in by[i] if (mid := _middle(f.body))] for i in idx[1:-1]]   # never a brace in one
        if not opens or not closes or not all(middles):
            continue
        choices = [opens[:MAX_PER_INDEX]] + [m[:MAX_PER_INDEX] for m in middles] + [closes[:MAX_PER_INDEX]]
        for combo in product(*choices):
            pieces = [text for _, text in combo]
            parts = tuple(_fragjoin.Field("numbered", f"({f.index}) {f.origin}", text, 0) for f, text in combo)
            literal = "".join(pieces)
            spellings = [(literal, parts)]
            sep = _separator(pieces)
            if sep:
                fixed, added, explicit = _repaired(pieces, sep)
                if added:
                    note = _fragjoin.Field("numbered", f"separator {sep!r} put back at {added} boundary(ies) "
                                           f"that had none", "", 0)
                    spellings.append((fixed, parts + (note,)))
                    if explicit:
                        spellings.reverse()           # another boundary carries it: cut at word boundaries
            for flag, used in spellings:
                if flag in seen or not ff.is_flag(flag):
                    continue
                seen.add(flag)
                out.append(_fragjoin.Join(flag, used))
                if len(out) >= MAX_JOINS:
                    return out
        if out:
            break
    return out
