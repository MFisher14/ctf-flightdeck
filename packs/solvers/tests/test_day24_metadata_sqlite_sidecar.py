#!/usr/bin/env python3
"""Harness for the Day 24 look-ahead T5 readers: SQLite WAL / rollback-journal sidecars.

  .venv/bin/python -m pytest tests/test_day24_metadata_sqlite_sidecar.py   (or `python tests/test_day24_metadata_sqlite_sidecar.py`)

The WAL fixture is a REAL `-wal` built by the stdlib sqlite3 and captured before the connection
checkpoints it away (CI-safe: sqlite3 is stdlib). The journal fixture uses SQLite's canonical journal
magic (aJournalMagic) with the field layout confirmed from a real DELETE-mode journal. Pins NEVER-WRONG:
  - every WAL / journal field reads its real value but answers UNSURE (new, unjudged keys), never plain;
  - the readers dispatch by TRUE MAGIC, so a decoy extension (a text file named `.db-wal`) is not read;
  - a cut / zeroed-header / non-sidecar input is None or the unsure 'none', never a wrong plain value.
"""
import importlib.util
import os
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
META = ROOT / "solvers" / "metadata-forensics"
COMMON = ROOT / "solvers" / "common"
for p in (str(COMMON), str(META)):
    if p not in sys.path:
        sys.path.insert(0, p)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load("ps_sidecar_test", META / "properties_strict.py")
labels = _load("labels_sidecar_test", COMMON / "labels.py")


def check(name, ok, detail=""):
    print(("ok  " if ok else "FAIL") + " : " + name + ("" if ok else f"   {detail}"))
    assert ok, f"{name}   {detail}"


def real_wal(page_size=4096):
    """A genuine SQLite -wal, captured while the connection still holds it (before checkpoint)."""
    d = tempfile.mkdtemp()
    p = os.path.join(d, "app.db")
    c = sqlite3.connect(p)
    try:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute(f"PRAGMA page_size={page_size}")
        c.execute("create table t(a,b)")
        for i in range(200):
            c.execute("insert into t values(?,?)", (i, "x" * 50))
        c.commit()
        with open(p + "-wal", "rb") as fh:
            wal = fh.read()
        with open(p, "rb") as fh:
            db = fh.read()
    finally:
        c.close()
    return wal, db


def synth_journal(page_size=1024, sector=512, init_pages=7, nrec=0, nonce=0xFE6D4A1B):
    """A rollback journal with SQLite's canonical magic and the confirmed field layout, padded to a sector."""
    hdr = M.JOURNAL_MAGIC + struct.pack(">5I", nrec, nonce, init_pages, sector, page_size)
    return hdr + bytes(sector - len(hdr))


def ask(prop, data, name, kind="exact_text"):
    s = prop.replace(".", "-").replace("_", "-")
    q = {"id": f"d24-{name}-{s}", "answer_id": f"d24-{name}-{s}",
         "question": f"Inspect `{name}`. Determine {prop} for {name}.", "artifact": f"evidence.zip -> {name}",
         "answer_format": {"kind": kind, "syntax": "artifact-derived value"}}
    a = M.answer_question(q, {name: data}, {})
    parsed = labels.parse(a)
    opts = None if parsed is None else (parsed.options if hasattr(parsed, "options") else parsed["o"])
    return a, opts


def is_unsure(a):
    return isinstance(a, str) and a.startswith("??") and labels.parse(a) is not None


def first(opts):
    return opts[0][1] if opts else None


# ------------------------------------------------------------------ WAL (real sample)
wal, db = real_wal(4096)
frames = (len(wal) - 32) // (24 + 4096)
WAL_FIELDS = [
    ("sqlite_wal.page_size", str(4096)), ("sqlite_wal.frame_count", str(frames)),
    ("sqlite_wal.checkpoint_sequence", "0"), ("sqlite_wal.format_version", "3007000"),
]


def test_wal_real_sample():
    for prop, want in WAL_FIELDS:
        a, opts = ask(prop, wal, "app.db-wal")
        check(f"WAL {prop} is UNSURE with the real value first ({want})",
              is_unsure(a) and first(opts) == want, f"{a!r} opts={opts}")

    a, opts = ask("sqlite_wal.magic", wal, "app.db-wal")
    check("WAL magic is UNSURE, 0x form offered", is_unsure(a) and any(v == "0x377f0682" for _, v in opts), f"{opts}")

    a, opts = ask("sqlite.is_wal", wal, "app.db-wal")
    check("sqlite.is_wal is UNSURE true on a real WAL", is_unsure(a) and first(opts) in ("true", "True"), f"{a!r}")
    a, opts = ask("sqlite.is_wal", db, "app.db")
    check("sqlite.is_wal is UNSURE false on a real db", is_unsure(a) and first(opts) in ("false", "False"), f"{a!r}")

    # the aliases all resolve (sqlite_wal / wal / sqlite.wal)
    for ns in ("sqlite_wal", "wal", "sqlite.wal"):
        a, opts = ask(f"{ns}.page_size", wal, "app.db-wal")
        check(f"WAL alias {ns}.page_size resolves to 4096 (unsure)", is_unsure(a) and first(opts) == "4096", f"{a!r}")


# ------------------------------------------------------------------ journal (canonical magic + real layout)
def test_journal_canonical_magic_and_real_layout():
    jour = synth_journal()
    JRN_FIELDS = [("sqlite_journal.page_size", "1024"), ("sqlite_journal.sector_size", "512"),
                  ("sqlite_journal.initial_db_pages", "7")]
    for prop, want in JRN_FIELDS:
        a, opts = ask(prop, jour, "roll.db-journal")
        check(f"journal {prop} is UNSURE with the real value first ({want})",
              is_unsure(a) and first(opts) == want, f"{a!r} opts={opts}")
    a, opts = ask("sqlite_journal.magic", jour, "roll.db-journal")
    check("journal magic is UNSURE, canonical bytes offered",
          is_unsure(a) and any(v == "d9d505f920a163d7" for _, v in opts), f"{opts}")


# ------------------------------------------------------------------ fail-closed / true-magic
def test_fail_closed_true_magic():
    for prop in ("sqlite_wal.page_size", "sqlite_wal.frame_count"):
        a, opts = ask(prop, b"this is a plain text file, not a WAL", "notes.db-wal")
        check(f"{prop} on a decoy (text named .db-wal) is None / unsure 'none', never wrong-plain",
              a is None or is_unsure(a) and first(opts) in ("none", None), f"{a!r}")
    a, opts = ask("sqlite_journal.page_size", bytes(8) + struct.pack(">5I", 0, 1, 7, 512, 1024) + bytes(100), "z.db-journal")
    check("journal with a ZEROED (invalidated) header is not read -> None / 'none'",
          a is None or is_unsure(a) and first(opts) in ("none", None), f"{a!r}")
    a, opts = ask("sqlite_wal.page_size", M.WAL_MAGIC[0] + bytes(10), "cut.db-wal")
    check("a CUT WAL header -> None (Unknown, never a wrong plain value)", a is None or is_unsure(a), f"{a!r}")


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-q"]))
