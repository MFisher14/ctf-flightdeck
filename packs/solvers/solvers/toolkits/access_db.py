#!/usr/bin/env python3
"""Toolkit `access_db`: read a Microsoft Access / Jet database (.mdb / .accdb) — tables and rows.

The 2024 Windows "Database" archetype hands you a `.mdb`/`.accdb` (Jet / ACE engine, NOT the ESE engine
that `ese_reader.py` covers, and NOT SQLite). `mdbtools` (mdb-tables / mdb-export / mdb-schema) is the
standard reader; it is a host tool. This wrapper:

  - identifies the file by its on-disk magic ("Standard Jet DB" at offset 4 for .mdb, "Standard ACE DB"
    for .accdb), so you know what you have before reaching for a tool;
  - if `mdbtools` is installed, lists the tables and dumps each as CSV, and (with a pattern) greps the
    dumped rows for the flag — the offline equivalent of `SELECT ... WHERE col LIKE '%CSCTF%'`;
  - if it is NOT installed, prints the exact `brew install mdbtools` + the mdb-tables/mdb-export commands
    so you (or the Docker sandbox) can run them.

RECON / READ ONLY. It shells out only to the read-only mdbtools binaries on the file you pass; it never
writes, executes the database, or guesses a flag — a pattern match is reported for you to read, not
submitted. Flag shape default is the event's (ctf.flagfmt); pass --pattern for a challenge-stated shape.

  identify(path)                 -> "mdb" | "accdb" | None
  tables(path)                   -> list[str]                 (needs mdb-tables)
  dump_table(path, table)        -> str  (CSV)                (needs mdb-export)
  scan(path, pattern=...)        -> dict  (what the CLI prints)
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

__all__ = ["identify", "tables", "dump_table", "scan", "have_mdbtools"]


def have_mdbtools() -> bool:
    return bool(shutil.which("mdb-tables") and shutil.which("mdb-export"))


def identify(path) -> str | None:
    """'mdb' (legacy Jet), 'accdb' (ACE), or None. Reads the 20-byte magic string at offset 4."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(40)
    except OSError:
        return None
    tag = head[4:24]
    if b"Standard Jet DB" in tag:
        return "mdb"
    if b"Standard ACE DB" in tag:
        return "accdb"
    return None


def tables(path) -> list[str]:
    if not shutil.which("mdb-tables"):
        return []
    try:
        res = subprocess.run(["mdb-tables", "-1", str(path)], capture_output=True, timeout=30)
    except Exception:
        return []
    return [t for t in res.stdout.decode("utf-8", "replace").splitlines() if t.strip()]


def dump_table(path, table: str) -> str:
    if not shutil.which("mdb-export"):
        return ""
    try:
        res = subprocess.run(["mdb-export", str(path), table], capture_output=True, timeout=60)
    except Exception:
        return ""
    return res.stdout.decode("utf-8", "replace")


def scan(path, pattern: str | None = None) -> dict:
    """Tables, rows and flag matches. `pattern` (a challenge-stated answer shape) overrides the
    event's flag format (ctf.flagfmt)."""
    shown = pattern or flagfmt.current().pattern
    p = Path(path)
    kind = identify(p)
    rep = {
        "file": str(p),
        "kind": kind,
        "have_mdbtools": have_mdbtools(),
        "tables": [],
        "flag_matches": [],
        "commands": [],
    }
    if kind is None:
        rep["commands"].append("not a Jet/ACE database (no 'Standard Jet/ACE DB' magic at offset 4)")
        return rep
    if not have_mdbtools():
        rep["commands"] = [
            "brew install mdbtools        # or: apt-get install mdbtools / use the Docker sandbox",
            f"mdb-tables -1 {p}",
            f"mdb-export {p} <TABLE>      # dump each table as CSV",
            f"for t in $(mdb-tables -1 {p}); do mdb-export {p} \"$t\"; done | grep -Eo '{shown}'",
        ]
        return rep
    rx = re.compile(pattern) if pattern else flagfmt.TEXT
    seen = set()
    rep["tables"] = tables(p)
    for t in rep["tables"]:
        for m in rx.finditer(dump_table(p, t)):
            v = m.group(0)
            if v not in seen:
                seen.add(v)
                rep["flag_matches"].append({"table": t, "match": v})
    return rep


def _main(argv):
    import argparse
    ap = argparse.ArgumentParser(description="Read a Microsoft Access .mdb/.accdb database (tables + rows).")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--pattern", default=None, help="answer regex (default: the event's flag format)")
    ap.add_argument("--table", help="dump just this table as CSV")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    reports = []
    for f in a.files:
        if a.table:
            print(dump_table(f, a.table))
            continue
        reports.append(scan(f, a.pattern))
    if a.table:
        return 0
    if a.json:
        print(json.dumps(reports, indent=2))
        return 0
    for rep in reports:
        print(f"== {rep['file']}  kind={rep['kind']}  mdbtools={'yes' if rep['have_mdbtools'] else 'MISSING'}")
        if rep["tables"]:
            print(f"  tables: {', '.join(rep['tables'])}")
        for fm in rep["flag_matches"]:
            print(f"  FLAG MATCH [{fm['table']}]: {fm['match']}")
        for c in rep["commands"]:
            print(f"  $ {c}")
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
