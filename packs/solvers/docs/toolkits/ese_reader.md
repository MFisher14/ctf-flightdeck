# Toolkit `ese_reader`: ESE / EDB table-ROW value reader

Built 2026-10-24 (wave120/ese-row-reader, classic-DFIR coverage). ESE (Extensible Storage Engine, "JET Blue",
`.edb` / `.dat`) is the marquee classic-DFIR database: **SRUM** (`SRUDB.dat`: "how many bytes did app X send",
"when did program Y last run"), the **WebCache** (`WebCacheV01.dat`: container URLs and timestamps) and **NTDS**
(`NTDS.dit`). The specialist forensic toolkits (`windows`, `forensics`, `memory`) read ESE *headers* and the family
only; nothing in the tree reads a table **row**. This toolkit fills that one gap. Offline, static, standard library
only; nothing is mounted, executed, written or carved, and no byte of a delivery is ever run.

No `libesedb` / `pyesedb` / `dissect.esedb` is in the `.venv`, so it is a **minimal bounded parser** of the
documented on-disk format (Joachim Metz, "ESE Database File (EDB) format"). It reads only what it can prove and
returns `None` for the rest — a valid never-wrong outcome.

## Run first

```bash
.venv/bin/python solvers/toolkits/ese_reader.py <SRUDB.dat|WebCacheV01.dat|NTDS.dit|*.edb>...          # header + catalog
.venv/bin/python solvers/toolkits/ese_reader.py <file> --rows                                          # + sample rows (DATA)
.venv/bin/python solvers/toolkits/ese_reader.py <file> --json                                          # as JSON
```

As a solver: `signals()` / `solve_set()` are the runner contract for running the whole file set at once. It is
the **agent's / triage's** tool, run by hand rather than auto-played.

By hand, from Python:

```python
sys.path.insert(0, "solvers/toolkits"); import ese_reader as E
E.read_header(data)          # {page_size, format_version, format_revision, file_type, page_count} or None
E.classify(data)             # {"kind": "ese", "facts": {...}, "tables": [{name, objid, fdp, columns:[...]}]} or None
db = E.Database(data)        # raises E.EseError for a non-ESE / malformed file
db.tables()                  # {objid: {"name", "fdp"}}   from the MSysObjects catalog (FDP page 4)
db.columns(objid)            # [{"name", "fid", "coltyp", ...}]
list(db.rows(objid))         # [{column_name: value}]  bounded leaf-record row values
```

## What it reads

1. **File header** — validated by the signature `0x89abcdef` at offset 4 (no checksum is computed; checksums vary by
   revision and prove nothing about the structure). Page size (offset 236), format version, revision, file type.
2. **Page / B-tree walk** from a table's father-data-page (FDP), **strictly bounded** (pages, rows, columns, depth,
   bytes) and **cycle-guarded**; only data leaf pages are read (space / index / long-value pages are skipped).
3. **The `MSysObjects` catalog** (FDP page 4) → tables (name → objid, FDP) and columns (table objid → name, fid,
   column type, space).
4. **Row values** for leaf records: fixed-size columns (packed in fid order) and variable-size columns, decoded by
   the catalog type (bit, byte, short, long, long-long, single/double, OLE-automation datetime, GUID, text, binary).
   Tagged columns are read best-effort with strict validation. Anything out of bounds, truncated or ambiguous → the
   whole row (or field) is dropped.

## Never-guess / never-wrong

No ESE row value is a fixed label and the file / variant differs per challenge, so **nothing here is treated as
a certain answer**:

- a **structural** fact read by a deterministic reader (page size, format version, counts) is
  `labels.pick(key, [(reader_method, value)])` — the option **name is the reader method**, never equal to the value
  (never a bare-label pick), so an accepted name answers the next variant with that variant's own value;
- a **row value** or a **catalog name** is `labels.candidates(key, options)` whose **key carries the full SHA-256 delivery
  digest** (scoped, so an accepted hypothesis rank can never answer a different variant) and whose option **name is
  the provenance hypothesis**, never the value;
- a page / tree / record that does not parse cleanly, an ambiguous column, a truncated or out-of-bounds offset, and
  the flag are all **`None`**.

Keys are `forensics.ese_<field>/<shape>` — this toolkit shares the `forensics` label prefix. Examples:
`forensics.ese_page_size/header`, `forensics.ese_row_count/table@...`,
`forensics.ese_value@<table>.<column>/<digest>#candidates`.

## Limits (honest)

Without a real `libesedb` the parser follows the documented format and is validated against a hand-built,
spec-faithful SRUM-shaped sample (`tests/test_tk_ese_reader.py`). It is deliberately conservative: separated /
compressed long values, multi-value tagged columns, large-page (>8 KiB) tagged-flag edge cases and the full NTDS
`datatable` schema are read only where they parse cleanly and otherwise return `None`. Because every answer is a
candidate (`labels.pick` / `labels.candidates`) or `None`, a parse that is wrong on an exotic variant is caught
when you read the candidates — never a wrong value reasoned to the flag.
