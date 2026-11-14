#!/usr/bin/env python3
"""Toolkit `linefilter`: the "find the one line that does NOT fit" helper for the CSCTF 2024
Extraction 1/2 archetype. Offline, standard library only.

  .venv/bin/python solvers/toolkits/linefilter.py data.txt                       # auto odd-one-out
  .venv/bin/python solvers/toolkits/linefilter.py -v '^[a-fA-F0-9]{32}$' data.txt # grep -E -v
  .venv/bin/python solvers/toolkits/linefilter.py -g '^[A-Z]{4}[a-z]{6}...' data.txt # grep -E (keep matching)

Two modes:
  * pattern given (`-v REGEX` = grep -Ev, or `-g REGEX` = grep -E): print the lines that do NOT match
    (`-v`) or that DO match (`-g`) the extended-regex PATTERN. This is Extraction 1 -- the author
    gives you the format every normal line follows and the flag line is the one that breaks it.
  * no pattern: auto odd-one-out. Each line is reduced to a character-class SHAPE (e.g. all 32 hex
    chars -> 'H{32}'); the minority shape is the odd line. This is Extraction 2 -- "find the non-MD5
    line" without being told the regex (the odd line typically contains 'flag' / CSCTF{...}).

Import use:
    sys.path.insert(0, "solvers/toolkits"); import linefilter
    linefilter.not_matching(lines, r'^[a-f0-9]{32}$')   # grep -Ev
    linefilter.odd_one_out(lines)                        # (odd_lines, common_shape)
    linefilter.flag_lines(lines)                         # lines containing CSCTF{...} or 'flag'
"""
from __future__ import annotations

import os
import re
import sys
from collections import Counter
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

FLAG_RE = flagfmt.TEXT


def read_lines(path: str) -> list:
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    return [ln for ln in text.splitlines()]


def not_matching(lines: list, pattern: str) -> list:
    """grep -E -v: the lines that do NOT fully-or-partially match PATTERN. The pattern is matched with
    re.search (anchor it with ^...$ for a whole-line match, as grep -x would)."""
    rx = re.compile(pattern)
    return [ln for ln in lines if ln.strip() and not rx.search(ln)]


def matching(lines: list, pattern: str) -> list:
    """grep -E: the lines that match PATTERN."""
    rx = re.compile(pattern)
    return [ln for ln in lines if rx.search(ln)]


# ---- auto odd-one-out: reduce each line to a character-class shape ---------------------------------

def shape(line: str) -> str:
    """A compact character-class signature of a line: runs of the same class collapsed with a count.
    'd41d8cd9...' (32 hex) -> 'x{32}'; 'ABCDabcdef1AB12abcdef' -> a run signature. Classes: U upper,
    L lower, x hex-ish is folded into U/L/d, d digit, s space, . other."""
    def cls(c: str) -> str:
        if c.isdigit():
            return "d"
        if c.isupper():
            return "U"
        if c.islower():
            return "L"
        if c.isspace():
            return "s"
        return "."
    out = []
    prev = None
    count = 0
    for c in line:
        k = cls(c)
        if k == prev:
            count += 1
        else:
            if prev is not None:
                out.append(f"{prev}{{{count}}}")
            prev, count = k, 1
    if prev is not None:
        out.append(f"{prev}{{{count}}}")
    return "".join(out)


def odd_one_out(lines: list):
    """(odd_lines, common_shape): group the non-empty lines by their character-class shape and return
    the lines whose shape is in the minority. Ties / all-distinct -> ([], None)."""
    real = [ln for ln in lines if ln.strip()]
    if len(real) < 2:
        return [], None
    shapes = [shape(ln) for ln in real]
    counts = Counter(shapes)
    if len(counts) == 1:
        return [], shapes[0]
    common, n = counts.most_common(1)[0]
    # only meaningful when there is a clear majority
    if n <= len(real) // 2:
        # no majority; fall back to length-based outlier
        lengths = Counter(len(ln) for ln in real)
        cl, cn = lengths.most_common(1)[0]
        if cn > len(real) // 2:
            return [ln for ln in real if len(ln) != cl], f"len={cl}"
        return [], None
    odd = [ln for ln, sh in zip(real, shapes) if sh != common]
    return odd, common


def flag_lines(lines: list) -> list:
    """Lines that contain a CSCTF{...} flag or the word 'flag' (case-insensitive)."""
    out = []
    for ln in lines:
        if FLAG_RE.search(ln) or "flag" in ln.lower():
            out.append(ln)
    return out


def flags(lines: list) -> list:
    out = []
    for ln in lines:
        for m in FLAG_RE.findall(ln):
            if m not in out:
                out.append(m)
    return out


def report(path: str, inv_pattern: str | None = None, keep_pattern: str | None = None) -> str:
    lines = read_lines(path)
    L = [f"linefilter: {path} ({len([x for x in lines if x.strip()])} non-empty lines)"]
    if inv_pattern is not None:
        odd = not_matching(lines, inv_pattern)
        L.append(f"lines NOT matching /{inv_pattern}/ : {len(odd)}")
        for ln in odd[:50]:
            L.append(f"   {ln}")
    elif keep_pattern is not None:
        keep = matching(lines, keep_pattern)
        L.append(f"lines matching /{keep_pattern}/ : {len(keep)}")
        for ln in keep[:50]:
            L.append(f"   {ln}")
    else:
        odd, common = odd_one_out(lines)
        L.append(f"common shape: {common}")
        L.append(f"odd-one-out lines: {len(odd)}")
        for ln in odd[:50]:
            L.append(f"   {ln}")
    fl = flags(lines)
    if fl:
        L.append("")
        L.append("FLAG candidate(s): " + ", ".join(fl))
    else:
        fls = flag_lines(lines)
        if fls:
            L.append("")
            L.append("lines mentioning a flag:")
            for ln in fls[:10]:
                L.append(f"   {ln}")
    return "\n".join(L)


def main(argv) -> int:
    inv = None
    keep = None
    paths = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.split("\n\n")[0], file=sys.stderr)
            return 2
        if a in ("-v", "--invert"):
            inv = argv[i + 1]
            i += 2
            continue
        if a in ("-g", "--grep"):
            keep = argv[i + 1]
            i += 2
            continue
        paths.append(a)
        i += 1
    if not paths:
        print("usage: linefilter.py [-v REGEX | -g REGEX] <file>", file=sys.stderr)
        return 2
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        print(f"linefilter.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 1
    print("\n\n".join(report(p, inv, keep) for p in paths))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
