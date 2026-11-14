#!/usr/bin/env python3
"""Toolkit `flagscan`: the quick "find the flag row" scanner for the CSCTF 2024 Lite (SQLite) and
Database (MySQL dump) archetypes -- the offline equivalent of
`SELECT ... FROM <table> WHERE <col> LIKE '%CSCTF%'`. Offline, standard library only.

  .venv/bin/python solvers/toolkits/flagscan.py <file.db|.sqlite|.csv|.sql|.tsv>...
  .venv/bin/python solvers/toolkits/flagscan.py --pattern 'secret' data.csv

What it scans, by magic (never by file name):
  * SQLite databases -- every text/blob cell of every table, read-only on a temp copy
    (mode=ro&immutable=1, so a hostile file cannot be written through). Reports table, rowid, column.
  * CSV / TSV -- every field (delimiter sniffed).
  * MySQL / SQL text dumps (INSERT ... VALUES) and any other text file -- a straight regex pass over
    the bytes, which is enough to pull a flag out of a `.sql` dump without a MySQL server.

For a plain flag row this is all you need. For browser history / Login Data / deleted-row recovery /
LevelDB, use the richer solvers/toolkits/sqlite_artifacts.py instead; flagscan is deliberately the
light generic finder.

Import use:
    sys.path.insert(0, "solvers/toolkits"); import flagscan
    hits = flagscan.scan_path("mydatabase.db")      # [Hit(...)]
    flagscan.flags(hits)                             # the CSCTF{...} strings found, de-duplicated
"""
from __future__ import annotations

import csv
import os
import re
import sqlite3
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

# The active event's flag format (ctf.flagfmt) plus a loose default substring.
FLAG_RE = flagfmt.TEXT


def default_substr() -> str | None:
    """The loose substring: the active event's own flag prefix (the first in its profile: CSCTF,
    PINK, spooky, flag). None for a format with no known prefix, where FLAG_RE already matches any
    word{...}. Read on every scan, so it follows CTF_EVENT (R-16: it was the literal 'CSCTF')."""
    ff = flagfmt.current()
    return ff.spec.prefixes[0] if ff.known else None


SQLITE_MAGIC = b"SQLite format 3\x00"
MAX_CELL = 4096          # how much of one cell to show
OPEN_SECONDS = 2.0


@dataclass
class Hit:
    source: str          # the file
    table: str           # table name, CSV row label, or '(text)'
    rowid: object        # rowid / line number
    column: str          # column name / field index
    value: str           # the matching cell, truncated

    def __str__(self) -> str:
        v = self.value if len(self.value) <= 200 else self.value[:200] + "..."
        return f"{Path(self.source).name} :: {self.table}#{self.rowid}.{self.column} = {v}"


def _matcher(pattern: str | None, regex: bool):
    """A predicate over a cell's text. Default: the flag regex OR the event's own prefix as a
    substring, any case (so a bare flag with no braces, or a password column holding the flag, is
    still caught)."""
    if pattern is None:
        sub = default_substr()
        low = sub.lower() if sub else None

        def pred(s: str):
            return bool(FLAG_RE.search(s)) or (low is not None and low in s.lower())
        return pred
    if regex:
        rx = re.compile(pattern, re.IGNORECASE)
        return lambda s: bool(rx.search(s))
    low = pattern.lower()
    return lambda s: low in s.lower()


def _as_text(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.decode("latin-1", "replace")
    return str(v)


def scan_sqlite(path: str, pred) -> list:
    """Scan every table of a SQLite file. Read-only immutable copy so an untrusted DB is never
    written through and triggers cannot fire."""
    hits = []
    with tempfile.TemporaryDirectory(prefix="flagscan_") as td:
        copy = Path(td) / "copy.db"
        copy.write_bytes(Path(path).read_bytes())
        wal = Path(path + "-wal")
        if wal.exists():
            (Path(td) / "copy.db-wal").write_bytes(wal.read_bytes())
            uri = f"file:{copy}?mode=ro"
        else:
            uri = f"file:{copy}?mode=ro&immutable=1"
        con = None
        try:
            con = sqlite3.connect(uri, uri=True, timeout=1)
            con.text_factory = lambda b: b.decode("utf-8", "replace")
            import time as _t
            stop = _t.monotonic() + OPEN_SECONDS
            con.set_progress_handler(lambda: 1 if _t.monotonic() > stop else 0, 20000)
            tables = [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            for t in tables:
                try:
                    info = con.execute(f'PRAGMA table_info("{t}")').fetchall()
                    cols = [c[1] for c in info]
                    try:
                        cur = con.execute(f'SELECT rowid, * FROM "{t}"')
                        has_rowid = True
                    except sqlite3.Error:
                        cur = con.execute(f'SELECT * FROM "{t}"')
                        has_rowid = False
                    for row in cur:
                        rid = row[0] if has_rowid else None
                        cells = row[1:] if has_rowid else row
                        for name, val in zip(cols, cells):
                            txt = _as_text(val)
                            if txt and pred(txt):
                                hits.append(Hit(path, t, rid, name, txt[:MAX_CELL]))
                except sqlite3.Error:
                    continue
        except sqlite3.Error:
            pass
        finally:
            if con is not None:
                con.close()
    return hits


def scan_csv(path: str, pred, delimiter: str | None = None) -> list:
    """Scan every field of a CSV/TSV. The delimiter is sniffed when not given."""
    hits = []
    data = Path(path).read_text(encoding="utf-8", errors="replace")
    if delimiter is None:
        try:
            delimiter = csv.Sniffer().sniff(data[:4096], delimiters=",;\t|").delimiter
        except csv.Error:
            delimiter = "\t" if data[:4096].count("\t") > data[:4096].count(",") else ","
    reader = csv.reader(data.splitlines(), delimiter=delimiter)
    header = None
    for i, row in enumerate(reader):
        if i == 0 and any(not _looks_data(c) for c in row):
            header = row
            continue
        for j, cell in enumerate(row):
            if pred(cell):
                col = header[j] if header and j < len(header) else f"col{j}"
                hits.append(Hit(path, "(csv)", i, col, cell[:MAX_CELL]))
    return hits


def _looks_data(cell: str) -> bool:
    return bool(re.search(r"\d", cell)) or len(cell) > 40


def scan_text(path: str, pred) -> list:
    """A line-by-line regex pass -- for SQL/MySQL dumps and anything that is not a DB or CSV."""
    hits = []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return hits
    for i, line in enumerate(text.splitlines(), 1):
        if pred(line):
            hits.append(Hit(path, "(text)", i, "line", line.strip()[:MAX_CELL]))
    return hits


def scan_path(path: str, pattern: str | None = None, regex: bool = False) -> list:
    """Dispatch one file by magic to the right scanner. pattern=None uses the flag matcher."""
    pred = _matcher(pattern, regex)
    try:
        with open(path, "rb") as fh:
            magic = fh.read(16)
    except OSError:
        return []
    if magic == SQLITE_MAGIC:
        hits = scan_sqlite(path, pred)
        if hits:
            return hits
        # a DB the library refuses -> fall back to a raw string scan so a flag is still found
        return scan_text(path, pred)
    ext = Path(path).suffix.lower()
    if ext in (".csv", ".tsv"):
        return scan_csv(path, pred, delimiter="\t" if ext == ".tsv" else None)
    return scan_text(path, pred)


def flags(hits: list) -> list:
    """The distinct CSCTF{...} strings among the hits, best-first (full flag matches before loose
    substring hits)."""
    out = []
    for h in hits:
        for m in FLAG_RE.findall(h.value):
            if m not in out:
                out.append(m)
    return out


def report(paths: list, pattern: str | None = None, regex: bool = False) -> str:
    L = []
    allhits = []
    for p in paths:
        hits = scan_path(p, pattern, regex)
        allhits += hits
        L.append(f"== {p}: {len(hits)} hit(s)")
        for h in hits[:50]:
            L.append(f"   {h}")
        if len(hits) > 50:
            L.append(f"   ... and {len(hits) - 50} more")
    fl = flags(allhits)
    L.append("")
    if fl:
        L.append("FLAG candidate(s): " + ", ".join(fl))
    else:
        L.append("No flag in the event's format in the hits (check the matching cells above by hand).")
    return "\n".join(L)


def main(argv) -> int:
    pattern = None
    regex = False
    paths = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            print(__doc__.split("\n\n")[0], file=sys.stderr)
            return 2
        if a in ("-p", "--pattern"):
            pattern = argv[i + 1]
            i += 2
            continue
        if a in ("-e", "--regex"):
            regex = True
            i += 1
            continue
        paths.append(a)
        i += 1
    if not paths:
        print("usage: flagscan.py [--pattern P] [--regex] <file.db|.csv|.sql>...", file=sys.stderr)
        return 2
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        print(f"flagscan.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(report(paths, pattern, regex))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
