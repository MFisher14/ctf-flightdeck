# Toolkit `flagscan`: find-the-flag-row scanner

Module: `solvers/toolkits/flagscan.py` (standard library only). Tests: `tests/test_flagscan.py`.
Playbook: `docs/playbooks/linux.md`.

The offline equivalent of `SELECT … WHERE col LIKE '%CSCTF%'`, for the CSCTF 2024 **Lite** (SQLite)
and **Database** (MySQL dump) archetypes. Scans every text/blob cell of a `.db`/`.sqlite`, every field
of a `.csv`/`.tsv`, or a SQL/MySQL text dump by regex.

```bash
.venv/bin/python solvers/toolkits/flagscan.py mydatabase.db
.venv/bin/python solvers/toolkits/flagscan.py dump.sql
.venv/bin/python solvers/toolkits/flagscan.py --pattern secret data.csv
```

Key functions: `scan_path(path, pattern=None, regex=False)` → `[Hit(source, table, rowid, column,
value)]`, `flags(hits)` → the distinct `CSCTF{…}` strings. SQLite is opened read-only on an immutable
temp copy, so an untrusted DB is never written through.

For browser History / Login Data / deleted-row recovery / LevelDB use the richer
`solvers/toolkits/sqlite_artifacts.py`; `flagscan` is the deliberately light generic finder.
