#!/usr/bin/env python3
"""Offline tests for solvers/toolkits/ese_reader.py (the bounded ESE/EDB table-ROW reader,
wave120/ese-row-reader). No Game Master request, no token, no network: a spec-faithful ESE
database is built in memory from the documented on-disk format, parsed back, and every answer
checked NEVER-WRONG.

  .venv/bin/python tests/test_tk_ese_reader.py

The builder (`build_ese`) encodes the file header, the small-page header, the page tags, and the
new-format data-definition records (fixed / variable columns) exactly as the format specifies, so
parsing it end to end exercises the header read, the catalog (MSysObjects FDP page 4) walk, and
the table row decode. It mirrors a tiny SRUM `SruDbIdMapTable` (AppId / BytesSent / AppName).

Proves: ESE is detected and the header read; the catalog yields tables and columns; table rows
decode (long, long-long, text); a page/tree/record that does not parse cleanly, a truncated file,
a bad page size and a 64-byte blob all read as None / no-match; and EVERY solve_set answer is an
unsure labels.pick / labels.candidates (?? sentinel) or None -- never plain, never a bare-label
pick, and the flag is always None.
"""
import json
import os
import struct
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="test_tk_ese_"))
# labels reads the ledger root from $CTF_WORKDIR on every call (standalone: an empty temp ledger, so
# nothing is ever plain). setdefault: under pytest conftest.py has already set a session temp dir,
# and this module must not redirect other tests.
os.environ.setdefault("CTF_WORKDIR", str(TMP / "challenges"))
os.environ["CTF_TESTING"] = "1"
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / "solvers" / "common"))
sys.path.insert(0, str(REPO / "solvers" / "toolkits"))
import pytest          # noqa: E402
import labels          # noqa: E402
import ese_reader as E  # noqa: E402

FAILED = []
# Standalone (`python tests/test_tk_ese_reader.py`) a failed check is collected and main() exits 1.
# Under pytest a failed check must fail its test, not only print FAIL and report green.
_STANDALONE = __name__ == "__main__"

# The judge-acceptance test asserts that an accepted ledger verdict is replayed PLAIN. That needs
# the judge ledger; on a judge-free event ($CTF_JUDGE_LEDGER=off) labels reads no ledger, so it is
# skipped (reported as not run) instead of passing vacuously.
judge = pytest.mark.judge
needs_judge = pytest.mark.skipif(not labels.judge_ledger(),
                                 reason="no judge ledger ($CTF_JUDGE_LEDGER=off): judge-acceptance replay not available")


def check(label, ok, detail=""):
    print(f"{'ok  ' if ok else 'FAIL'} {label}" + ("" if ok or not detail else f"  [{str(detail)[:400]}]"))
    if not ok:
        FAILED.append(label)
        if not _STANDALONE:
            raise AssertionError(f"{label}  [{str(detail)[:400]}]")


# ---------------------------------------------------------------------------- an ESE builder

PAGE_SIZE = 4096
HDR_SIZE = 40                 # small page header
ROOT, LEAF = E.PAGE_IS_ROOT, E.PAGE_IS_LEAF


def build_record(fixed_cols, fixed_values, var_cols, var_values):
    """A new-format data-definition record. fixed_cols: [(fid, size)] in fid order; fixed_values:
    {fid: bytes|None}; var_cols: [fid>=128] in fid order; var_values: {fid: bytes|None}."""
    size_by_fid = dict(fixed_cols)
    last_fixed = max(size_by_fid, default=0)
    last_variable = max(var_cols) if var_cols else 127
    fixed_region, null = b"", []
    for fid in range(1, last_fixed + 1):
        size = size_by_fid[fid]
        val = fixed_values.get(fid)
        if val is None:
            fixed_region += b"\x00" * size
            null.append(fid)
        else:
            assert len(val) == size, (fid, len(val), size)
            fixed_region += val
    bitmap = bytearray((last_fixed + 7) // 8)
    for fid in null:
        bitmap[(fid - 1) // 8] |= 1 << ((fid - 1) % 8)
    var_count = (last_variable - 127) if var_cols else 0
    var_offsets, var_data, end = b"", b"", 0
    for k in range(var_count):
        fid = 128 + k
        v = var_values.get(fid)
        if v is None:
            var_offsets += struct.pack("<H", end | 0x8000)
        else:
            end += len(v)
            var_data += v
            var_offsets += struct.pack("<H", end)
    body = fixed_region + bytes(bitmap)
    var_offset = 4 + len(body)
    return bytes([last_fixed, last_variable]) + struct.pack("<H", var_offset) + body + var_offsets + var_data


def cell_for(record, key=b"\x00\x00\x00\x00"):
    """A leaf cell: 2-byte local-key size, the key, then the record (no common-key flag)."""
    return struct.pack("<H", len(key)) + key + record


def build_page(flags, cells):
    page = bytearray(PAGE_SIZE)
    struct.pack_into("<H", page, 0x22, len(cells))      # tag count
    struct.pack_into("<I", page, 0x24, flags)
    cur = HDR_SIZE
    tags = []
    for cell in cells:
        page[cur:cur + len(cell)] = cell
        tags.append((len(cell), cur - HDR_SIZE))
        cur += len(cell)
    struct.pack_into("<H", page, 0x20, cur - HDR_SIZE)
    for i, (cb, ib) in enumerate(tags):
        struct.pack_into("<HH", page, PAGE_SIZE - (i + 1) * 4, cb, ib)   # small page: flags in ib hi bits = 0
    return bytes(page)


def utf16(s):
    return s.encode("utf-16-le")


def catalog_table_record(objid, fdp, name):
    """A MSysObjects Type=1 (table) record on the fixed catalog schema (fid 1..9 + Name)."""
    fx = {2: struct.pack("<h", E.CAT_TYPE_TABLE), 3: struct.pack("<i", objid), 4: struct.pack("<i", fdp)}
    return build_record([(1, 4), (2, 2), (3, 4), (4, 4), (5, 4), (6, 4), (7, 4), (8, 1), (9, 2)],
                        fx, [128], {128: utf16(name)})


def catalog_column_record(table_objid, fid, coltyp, name, space, rec_off):
    """A MSysObjects Type=2 (column) record: ObjidTable, Id=fid, ColtypOrPgnoFDP=coltyp,
    SpaceUsage, RecordOffset, Name."""
    fx = {1: struct.pack("<i", table_objid), 2: struct.pack("<h", E.CAT_TYPE_COLUMN),
          3: struct.pack("<i", fid), 4: struct.pack("<i", coltyp), 5: struct.pack("<i", space),
          9: struct.pack("<h", rec_off)}
    return build_record([(1, 4), (2, 2), (3, 4), (4, 4), (5, 4), (6, 4), (7, 4), (8, 1), (9, 2)],
                        fx, [128], {128: utf16(name)})


def build_ese(user_rows, extra_user_records=()):
    """A minimal ESE DB. Two header pages precede the data, so LOGICAL page P sits at PHYSICAL
    index P+1. The MSysObjects catalog has FDP (logical) page 4 -> physical index 5; it describes
    one user table SruDbIdMapTable (objid 7, FDP logical page 5 -> physical index 6) with
    AppId(long)/BytesSent(long-long)/AppName(text). Eight physical pages (0..7).

    `extra_user_records` are raw record bytes appended to the user table page as extra leaf cells
    (used to plant a record that fails to decode, so the row walk must drop it)."""
    pages = {}
    # file header physical page 0
    hdr = bytearray(PAGE_SIZE)
    hdr[4:8] = E.SIGNATURE
    struct.pack_into("<I", hdr, 8, 0x620)      # format version
    struct.pack_into("<I", hdr, 12, 0)         # file type: database
    struct.pack_into("<I", hdr, 228, 0x3)      # lSPNumber (service pack): NOT the revision
    struct.pack_into("<I", hdr, 232, 0x11)     # ulDaeUpdateMajor: the format revision
    struct.pack_into("<I", hdr, 236, PAGE_SIZE)
    struct.pack_into("<I", hdr, 240, 7)        # page count
    pages[0] = bytes(hdr)
    pages[1] = bytes(hdr)                      # shadow header (physical page 1; not read)

    catalog_cells = [b""]                      # tag 0 external header
    catalog_cells.append(cell_for(catalog_table_record(7, 5, "SruDbIdMapTable")))   # FDP logical 5
    catalog_cells.append(cell_for(catalog_column_record(7, 1, 4, "AppId", 4, 0)))
    catalog_cells.append(cell_for(catalog_column_record(7, 2, 15, "BytesSent", 8, 4)))
    catalog_cells.append(cell_for(catalog_column_record(7, 128, 10, "AppName", 0, 0)))
    pages[5] = build_page(ROOT | LEAF, catalog_cells)   # logical page 4 (the catalog FDP)

    user_cells = [b""]
    for app_id, bytes_sent, app_name in user_rows:
        rec = build_record([(1, 4), (2, 8)],
                           {1: struct.pack("<i", app_id), 2: struct.pack("<q", bytes_sent)},
                           [128], {128: utf16(app_name)})
        user_cells.append(cell_for(rec))
    for rec in extra_user_records:
        user_cells.append(cell_for(rec))
    pages[6] = build_page(ROOT | LEAF, user_cells)       # logical page 5 (the table FDP)

    blob = bytearray(PAGE_SIZE * 8)
    for pgno, data in pages.items():
        off = pgno * PAGE_SIZE
        blob[off:off + PAGE_SIZE] = data
    return bytes(blob)


USER_ROWS = [(1, 123456789, "chrome.exe"), (2, 42, "powershell.exe"), (3, 9999, "svchost.exe")]


# ---------------------------------------------------------------------------- tests

def test_header_and_detect():
    data = build_ese(USER_ROWS)
    h = E.read_header(data)
    check("ESE header is read", h is not None and h["page_size"] == PAGE_SIZE
          and h["format_version"] == 0x620 and h["file_type"] == 0 and h["format_revision"] == 0x11, h)
    check("header: a non-ESE blob is None", E.read_header(bytes(4096)) is None)
    check("header: a truncated file is None", E.read_header(data[:100]) is None)
    bad = bytearray(data)
    struct.pack_into("<I", bad, 236, 1234)          # illegal page size
    check("header: an illegal page size is None", E.read_header(bytes(bad)) is None)
    rep = E.classify(data)
    check("classify: kind=ese with facts and tables", rep is not None and rep["kind"] == "ese"
          and rep["facts"]["page_size"] == PAGE_SIZE and rep["tables"], rep and rep.get("kind"))


def test_catalog_and_rows():
    data = build_ese(USER_ROWS)
    db = E.Database(data)
    tables = db.tables()
    check("catalog: SruDbIdMapTable is found (objid 7, FDP 5)",
          7 in tables and tables[7]["name"] == "SruDbIdMapTable" and tables[7]["fdp"] == 5, tables)
    cols = db.columns(7)
    names = [c["name"] for c in cols]
    check("catalog: the three columns are read in fid order", names == ["AppId", "BytesSent", "AppName"], names)
    check("catalog: column types are read", [c["coltyp"] for c in cols] == [4, 15, 10], cols)
    rows = list(db.rows(7))
    check("rows: three leaf records decode", len(rows) == 3, len(rows))
    check("rows: AppId (long), BytesSent (long-long) and AppName (text) decode",
          rows[0] == {"AppId": 1, "BytesSent": 123456789, "AppName": "chrome.exe"}
          and rows[1]["AppName"] == "powershell.exe" and rows[2]["BytesSent"] == 9999, rows)


def test_malformed_is_none():
    data = build_ese(USER_ROWS)
    check("a 64-byte blob is not ESE", E.classify(bytes(64)) is None)
    # Corrupt the catalog page's tag count to an insane value -> catalog reads nothing, no crash.
    # The catalog (logical page 4) is at physical page 5.
    bad = bytearray(data)
    struct.pack_into("<H", bad, 5 * PAGE_SIZE + 0x22, 5000)
    db = E.Database(bytes(bad))
    check("a bad tag count yields an empty catalog, never a crash or a wrong row", db.tables() == {}, db.tables())
    # A record whose variable-offset field runs past the record is dropped (never a wrong value).
    rec = build_record([(1, 4), (2, 8)], {1: struct.pack("<i", 7), 2: struct.pack("<q", 7)}, [128], {128: utf16("x")})
    rec = bytearray(rec)
    struct.pack_into("<H", rec, 2, 9999)            # var_offset past the record
    try:
        E.Database(data)._decode_record(bytes(rec), db.columns(7) if db.tables() else
                                        [{"name": "AppId", "fid": 1, "coltyp": 4, "space": 4, "record_offset": 0},
                                         {"name": "BytesSent", "fid": 2, "coltyp": 15, "space": 8, "record_offset": 4},
                                         {"name": "AppName", "fid": 128, "coltyp": 10, "space": 0, "record_offset": 0}])
        raised = False
    except E.EseError:
        raised = True
    check("a record with an out-of-range variable offset raises EseError (dropped, not guessed)", raised)
    # A file that ends mid-page: classify still returns None or a safe empty catalog.
    trunc = data[:4 * PAGE_SIZE + 10]
    try:
        rep = E.classify(trunc)
        safe = rep is None or rep["kind"] == "ese"
    except Exception:  # noqa: BLE001
        safe = False
    check("a truncated file is handled safely", safe)


def _is_unsure(v):
    return v is None or (isinstance(v, str) and v.strip().startswith(labels.SENTINEL))


def test_never_wrong_answers():
    data = build_ese(USER_ROWS)
    files = {"SRUDB.dat": data}
    qs = [
        {"qid": "a", "answer_id": "a", "question": "What is the ESE database page size?", "answer_format": {"kind": "integer"}},
        {"qid": "b", "answer_id": "b", "question": "How many tables are in the catalog?", "answer_format": {"kind": "integer"}},
        {"qid": "c", "answer_id": "c", "question": "How many rows are in the SruDbIdMapTable table?", "answer_format": {"kind": "integer"}},
        {"qid": "d", "answer_id": "d", "question": "What is the BytesSent value in the SruDbIdMapTable table?", "answer_format": {"kind": "integer"}},
        {"qid": "e", "answer_id": "e", "question": "Name a table in the database.", "answer_format": {"kind": "exact_text"}},
        {"qid": "f", "answer_id": "f", "question": "What is the flag?", "answer_format": {"kind": "exact_text"}},
        {"qid": "g", "answer_id": "g", "question": "What was the DNS server queried?", "answer_format": {"kind": "exact_text"}},
    ]
    ans = E.solve_set(qs, files, {})
    check("every answer is unsure (??) or None -- never plain", all(_is_unsure(v) for v in ans.values()), ans)
    check("the flag is always None", ans["f"] is None, ans["f"])
    check("an unrelated question (DNS) is None (never this reader's)", ans["g"] is None, ans["g"])
    check("page size is answered as an unsure pick", _is_unsure(ans["a"]) and ans["a"] is not None, ans["a"])
    # The page-size pick's option name is a reader method, never equal to the value (not a bare-label pick).
    parsed = labels.parse(ans["a"])
    check("page-size pick: option name is the reader method, not the value",
          parsed is not None and parsed.options and all(n != str(v) for n, v in parsed.options), parsed and list(parsed.options))
    # A row value is a delivery-scoped candidate pick (key carries the digest and ends in #candidates).
    pv = labels.parse(ans["d"])
    check("a row value is a delivery-scoped candidate pick (scoped key, #candidates)",
          ans["d"] is None or (pv is not None and pv.candidate and E._digest(data) in pv.key), pv and pv.key)
    check("a candidate's option name is a provenance hypothesis, never the value",
          ans["d"] is None or all(n != str(v) for n, v in pv.options), pv and list(pv.options))
    # The table-name answer is candidates of the catalog names (scoped), never plain.
    ev = labels.parse(ans["e"])
    check("table-name answer is a scoped candidate pick", ans["e"] is None or (ev is not None and ev.candidate), ev and ev.key)


def _parse(v):
    return labels.parse(v) if (v is not None and labels.is_unsure(v)) else None


def test_counts_are_digest_scoped_candidates():
    """A clean, within-cap COUNT (rows/tables/columns) is a DELIVERY-DIGEST-SCOPED candidate,
    never a cross-variant labels.pick: the key carries the digest and ends in #candidates, and
    the option name is the reader hypothesis, never the value. This is the wrong-plain fix: a
    saturated/incomplete count on a later variant can never be answered plain under an accepted
    count name, because the key is per-delivery."""
    data = build_ese(USER_ROWS)                     # 3 rows, 1 table, 3 columns -- all within cap
    files = {"SRUDB.dat": data}
    dg = E._digest(data)
    qs = [
        {"qid": "rows", "answer_id": "rows", "question": "How many rows are in the SruDbIdMapTable table?",
         "answer_format": {"kind": "integer"}},
        {"qid": "tabs", "answer_id": "tabs", "question": "What is the table count?",
         "answer_format": {"kind": "integer"}},
        {"qid": "cols", "answer_id": "cols", "question": "How many columns are in the SruDbIdMapTable table?",
         "answer_format": {"kind": "integer"}},
    ]
    ans = E.solve_set(qs, files, {})
    want = {"rows": 3, "tabs": 1, "cols": 3}
    for qid, field in (("rows", "ese_row_count"), ("tabs", "ese_table_count"), ("cols", "ese_column_count")):
        v = ans[qid]
        p = _parse(v)
        check(f"{field}: a clean within-cap count is a delivery-scoped CANDIDATE, never a plain pick",
              v is not None and p is not None and p.candidate and dg in p.key and field in p.key, (qid, v))
        check(f"{field}: the candidate carries the true count value under a reader-hypothesis name (not the value)",
              p is not None and [(n, val) for n, val in p.options] and all(n != str(val) for n, val in p.options)
              and any(val == want[qid] for _n, val in p.options), (qid, p and list(p.options)))


def test_saturated_count_is_none():
    """A count SATURATED at the cap is reported incomplete and emitted as None (never the cap
    value plain). Tested directly on count_rows (cap lowered after the catalog is warm) and
    end to end through solve_set (cap above the 4 catalog records, below the 10 user rows)."""
    # Direct: warm the catalog at the real cap, then lower MAX_ROWS so the 3 user rows saturate.
    db = E.Database(build_ese(USER_ROWS))
    db.tables()
    db.columns(7)
    saved = E.MAX_ROWS
    try:
        E.MAX_ROWS = 2                              # 3 real rows now exceed the row cap
        n, complete = db.count_rows(7)
    finally:
        E.MAX_ROWS = saved
    check("count_rows: a count that saturates the row cap is reported incomplete", complete is False, (n, complete))

    # End to end: 10 rows, cap 6 -> the row walk saturates but the 4-record catalog stays intact.
    data = build_ese([(i, i * 1000, f"app{i}.exe") for i in range(10)])
    q = {"qid": "c", "answer_id": "c", "question": "How many rows are in the SruDbIdMapTable table?",
         "answer_format": {"kind": "integer"}}
    saved = E.MAX_ROWS
    try:
        E.MAX_ROWS = 6
        ans = E.solve_set([q], {"SRUDB.dat": data}, {})
    finally:
        E.MAX_ROWS = saved
    check("solve_set: a saturated row count is None -- never the cap value (6) plain",
          ans["c"] is None, ans["c"])


def test_dropped_record_count_is_none():
    """A table with a record that cannot be decoded (raises EseError in the walk) has an
    incomplete count, so the count is refused (None) -- never a wrong undercount plain."""
    good = build_record([(1, 4), (2, 8)], {1: struct.pack("<i", 9), 2: struct.pack("<q", 9)},
                        [128], {128: utf16("x.exe")})
    broken = bytearray(good)
    struct.pack_into("<H", broken, 2, 9999)         # variable-data offset past the record -> _decode_record raises
    data = build_ese(USER_ROWS, extra_user_records=[bytes(broken)])
    db = E.Database(data)
    n, complete = db.count_rows(7)
    check("count_rows: a dropped (undecodable) record marks the count incomplete",
          complete is False, (n, complete))
    q = {"qid": "c", "answer_id": "c", "question": "How many rows are in the SruDbIdMapTable table?",
         "answer_format": {"kind": "integer"}}
    ans = E.solve_set([q], {"SRUDB.dat": data}, {})
    check("solve_set: a row count with a dropped record is None -- never emitted plain", ans["c"] is None, ans["c"])


@judge
@needs_judge
def test_accepted_count_does_not_cross_variants():
    """An accepted count name on delivery A (its own digest-scoped key) answers A plain, but a
    DIFFERENT delivery B (different digest) stays unsure -- the count can never cross variants.
    (Before the fix, the count key had no digest, so accepting it on A answered every variant
    plain, saturated ones included.)"""
    dataA = build_ese(USER_ROWS)                                 # 3 rows
    dataB = build_ese(USER_ROWS + [(4, 7, "extra.exe")])         # 4 rows -> different bytes/digest
    check("the two deliveries have distinct digests", E._digest(dataA) != E._digest(dataB))
    q = {"qid": "c", "answer_id": "c", "question": "How many rows are in the SruDbIdMapTable table?",
         "answer_format": {"kind": "integer"}}
    ansA = E.solve_set([q], {"SRUDB.dat": dataA}, {})
    pA = _parse(ansA["c"])
    check("delivery A's row count is an unsure candidate before any acceptance", pA is not None and pA.candidate, ansA["c"])
    # Accept the count hypothesis for A's OWN key via the runtime ledger (as untimed probing would).
    led = labels.challenges_root() / "_ledger"
    led.mkdir(parents=True, exist_ok=True)
    name = pA.options[0][0]
    ledger = led / "forensics.jsonl"
    prior = ledger.read_bytes() if ledger.exists() else None      # other tests' rows in a shared ledger
    with ledger.open("a") as fh:
        fh.write(json.dumps({"key": pA.key, "name": name, "verdict": "accepted"}) + "\n")
    labels._cache.clear()
    ansA2 = E.solve_set([q], {"SRUDB.dat": dataA}, {})
    ansB2 = E.solve_set([q], {"SRUDB.dat": dataB}, {})
    check("delivery A (the accepted key's own variant) now answers its own count plain", ansA2["c"] == 3, ansA2["c"])
    check("delivery B (a different digest) is NOT answered plain by A's accepted count",
          not isinstance(ansB2["c"], int) and _is_unsure(ansB2["c"]), ansB2["c"])
    # Restore the ledger so later tests see it as it was.
    if prior is None:
        ledger.unlink()
    else:
        ledger.write_bytes(prior)
    labels._cache.clear()


def test_signals():
    data = build_ese(USER_ROWS)
    qs = [{"qid": "a", "question": "How many bytes did the app send according to SRUM in SRUDB.dat?",
           "answer_format": {"kind": "integer"}}]
    s = E.signals(qs, {"SRUDB.dat": data})
    check("signals: a real ESE with SRUM/table vocabulary scores well", s >= 0.5, s)
    check("signals: a 64-byte blob scores 0.0", E.signals(qs, {"x.bin": bytes(64)}) == 0.0)
    check("signals: no files scores 0.0", E.signals(qs, {}) == 0.0)


def test_cli():
    import subprocess
    data = build_ese(USER_ROWS)
    p = TMP / "SRUDB.dat"
    p.write_bytes(data)
    r = subprocess.run([sys.executable, str(REPO / "solvers" / "toolkits" / "ese_reader.py"), str(p), "--rows"],
                       capture_output=True, text=True, timeout=60)
    check("CLI: prints the ESE header, tables and sample rows", r.returncode == 0 and "SruDbIdMapTable" in r.stdout
          and "chrome.exe" in r.stdout and "flag is None" in r.stdout, (r.stdout + r.stderr)[-400:])
    r2 = subprocess.run([sys.executable, str(REPO / "solvers" / "toolkits" / "ese_reader.py"), str(p), "--json"],
                        capture_output=True, text=True, timeout=60)
    out = json.loads(r2.stdout) if r2.stdout.strip() else []
    check("CLI --json: one ese=True row with facts and tables", r2.returncode == 0 and out and out[0]["ese"] is True
          and any(t["name"] == "SruDbIdMapTable" for t in out[0]["tables"]), r2.stdout[:300])


def main():
    import shutil
    try:
        test_header_and_detect()
        test_catalog_and_rows()
        test_malformed_is_none()
        test_never_wrong_answers()
        test_counts_are_digest_scoped_candidates()
        test_saturated_count_is_none()
        test_dropped_record_count_is_none()
        if labels.judge_ledger():
            # judge-acceptance -> plain replay; only meaningful with a judge ledger (see needs_judge)
            test_accepted_count_does_not_cross_variants()
        else:
            print("skip judge-acceptance test: no judge ledger ($CTF_JUDGE_LEDGER=off)")
        test_signals()
        test_cli()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    if FAILED:
        print(f"\n{len(FAILED)} check(s) failed")
        return 1
    print("\nall checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
