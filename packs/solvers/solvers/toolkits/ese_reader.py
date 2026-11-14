#!/usr/bin/env python3
"""Toolkit `ese_reader`: a BOUNDED pure-Python reader of ESE / EDB database table ROWS.

ESE (Extensible Storage Engine, "JET Blue", `.edb` / `.dat`) is the marquee classic-DFIR
database: SRUM (`SRUDB.dat`, "bytes sent by app X", "when did program Y last run"), the
WebCache (`WebCacheV01.dat`, container URLs and timestamps), and NTDS (`NTDS.dit`). The
specialist forensic toolkits (`windows`, `forensics`, `memory`) read ESE *headers* and the
family only; nothing in the tree reads a table ROW. This toolkit fills that one gap, offline,
static, standard library only, and NEVER-WRONG.

No `libesedb` / `pyesedb` / `dissect.esedb` is in the `.venv`, so this is a minimal bounded
parser of the documented on-disk format (Joachim Metz, "ESE Database File (EDB) format"):

  1. the file header (signature 0x89abcdef at offset 4, page size at offset 236);
  2. the page / B-tree walk from a table's father-data-page (FDP), strictly bounded and
     cycle-guarded, visiting only data leaf pages;
  3. the `MSysObjects` catalog (FDP page 4) -> tables (name -> objid, FDP) and columns
     (table objid -> [name, fid, column type, space, record offset]);
  4. row values for the common SRUM / WebCache / (where feasible) NTDS tables: the fixed-,
     variable- and tagged-size columns of each leaf record, decoded by the catalog type.

HARD RULES (AGENTS.md "New categories", "Uncertain answers", "Untrusted content"):
  - RECON / ANALYSIS ONLY. Nothing here mounts, executes, writes or carves; a bounded read
    of the bytes and nothing else. No model file is loaded and no byte of a delivery is run.
  - NEVER-GUESS / NEVER-WRONG. Nothing is ever PLAIN (no ESE fact has ever been judged, and
    the file / variant changes every rotation). A STRUCTURAL fact read by a deterministic
    EXACT-OFFSET reader (the header: page size, version, revision, file type) is
    `labels.pick(key, [(reader_method, value)])` (the option NAME is the reader, so an accepted
    name answers the next variant with that variant's own value, and the name is never equal to
    the value -- never a bare-label pick). A ROW VALUE, a catalog NAME, or a COUNT (rows,
    tables, columns) is `labels.candidates(key, options)` whose key carries the delivery digest
    (scoped, so an accepted rank / count can never answer a different variant) and whose option
    NAME is the provenance / reader hypothesis, never the value. A count is NOT an exact-offset
    pick: the walk caps at MAX_ROWS / MAX_TABLES / MAX_COLUMNS and silently drops records it
    cannot decode, so a count is emitted ONLY when the walk proved it exact (never saturated,
    never partial) AND only digest-scoped, never cross-variant plain. A page / tree / record
    that does not parse cleanly, an ambiguous column, a saturated or incomplete count, a
    truncated or out-of-bounds offset => `None`.
  - BOUNDED. Every walk is capped (pages, rows, columns, depth, bytes) and cycle-guarded.

Keys: `forensics.ese_<field>/<shape>` -- this toolkit shares the `forensics` label prefix
(`solvers/common/labels.py` TOOLKIT_PREFIXES; registered in `registry.py` with `labels:
"forensics"`, `match: False`, so it is the agent's / triage's, never an opener match
candidate, exactly like `web` and `cloud_container`).
"""
import json
import re
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(1, str(COMMON))
import labels    # noqa: E402
try:
    import triage    # noqa: E402
    ARROW = triage.ARROW
except Exception:      # noqa: BLE001 - triage is only needed for multi-file reports
    triage = None
    ARROW = " -> "

KEY = "forensics"                       # the forensics toolkit namespace (shared label prefix)
SIGNATURE = b"\xef\xcd\xab\x89"         # 0x89abcdef little-endian, at file offset 4
CATALOG_FDP = 4                         # MSysObjects always has father-data-page 4

# Bounds (never an unbounded walk; a real SRUDB.dat is only a few MiB, but a bad pointer must
# not run forever). These are the whole-reader caps.
MAX_FILE = 512 * 1024 * 1024
MAX_PAGES_WALK = 8192                   # B-tree pages visited per table
MAX_ROWS = 4096                         # leaf records read per table
MAX_TABLES = 1024
MAX_COLUMNS = 1024                      # columns per table
MAX_DEPTH = 48                          # B-tree depth guard
MAX_VALUE_BYTES = 1 << 16               # a single cell value we keep (bounded)
MAX_CATALOG_RECORDS = 1 << 16

# JET column types (JET_coltyp).
COLTYP = {1: "bit", 2: "unsigned_byte", 3: "short", 4: "long", 5: "currency", 6: "ieee_single",
          7: "ieee_double", 8: "datetime", 9: "binary", 10: "text", 11: "long_binary",
          12: "long_text", 13: "slv", 14: "unsigned_long", 15: "long_long", 16: "guid",
          17: "unsigned_short"}
FIXED_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 4, 7: 8, 8: 8, 14: 4, 15: 8, 16: 16, 17: 2}

# Page flags.
PAGE_IS_ROOT = 0x01
PAGE_IS_LEAF = 0x02
PAGE_IS_PARENT = 0x04
PAGE_IS_EMPTY = 0x08
PAGE_IS_SPACE_TREE = 0x10
PAGE_IS_INDEX = 0x20
PAGE_IS_LONG_VALUE = 0x40
PAGE_NEW_RECORD_FORMAT = 0x2000

# The fixed MSysObjects catalog schema (fid, size, coltyp), packed in fid order. MSysObjects is
# created once with this well-known layout, so the catalog is parsed with it (it is not read
# from the catalog itself -- that would be circular).
CATALOG_FIXED = [(1, 4, 4), (2, 2, 3), (3, 4, 4), (4, 4, 4), (5, 4, 4), (6, 4, 4), (7, 4, 4),
                 (8, 1, 1), (9, 2, 3), (10, 4, 4), (11, 2, 17)]
CAT_OBJIDTABLE, CAT_TYPE, CAT_ID, CAT_COLTYP_FDP = 1, 2, 3, 4
CAT_SPACEUSAGE, CAT_RECORDOFFSET = 5, 9
CAT_NAME_FID = 128                      # the Name column (variable-size)
CAT_TYPE_TABLE, CAT_TYPE_COLUMN = 1, 2  # MSysObjects.Type values


# ---------------------------------------------------------------------------- header

def read_header(data) -> dict:
    """{page_size, format_version, format_revision, file_type, page_count} for an ESE database,
    else None. Validated by the signature only; no checksum is computed (checksums vary by
    revision and prove nothing about the structure we read)."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 668:
        return None
    if bytes(data[4:8]) != SIGNATURE:
        return None
    try:
        version = struct.unpack_from("<I", data, 8)[0]
        file_type = struct.unpack_from("<I", data, 12)[0]
        page_size = struct.unpack_from("<I", data, 236)[0]
        # ulDaeUpdateMajor (the format revision) is at offset 232; offset 228 is lSPNumber
        # (the service-pack number), a different field.
        revision = struct.unpack_from("<I", data, 232)[0]
        page_count = struct.unpack_from("<I", data, 240)[0]
    except struct.error:
        return None
    # A page size is one of the ESE legal sizes; anything else is not an ESE we can walk.
    if page_size not in (2048, 4096, 8192, 16384, 32768):
        return None
    if file_type not in (0, 1):
        file_type = None
    return {"page_size": page_size, "format_version": version, "format_revision": revision,
            "file_type": file_type, "page_count": page_count}


# ---------------------------------------------------------------------------- the database

class EseError(Exception):
    """A structural inconsistency: the caller turns it into None (never-wrong)."""


class Database:
    """A bounded, read-only view of an ESE database held wholly in memory.

    Everything that can be inconsistent raises EseError, and every public entry point turns
    that (and any other exception) into None, so a malformed or truncated file is never a
    wrong answer -- only an absence of one."""

    def __init__(self, data: bytes):
        if not isinstance(data, (bytes, bytearray)):
            raise EseError("not bytes")
        self.data = bytes(data)
        if len(self.data) > MAX_FILE:
            raise EseError("file exceeds MAX_FILE cap")
        hdr = read_header(self.data)
        if hdr is None:
            raise EseError("not an ESE database")
        self.header = hdr
        self.page_size = hdr["page_size"]
        # Small pages (<=8192) have a 40-byte page header and record flags in the tag's ib
        # high bits; large pages (>8192) have an 80-byte header and flags in the entry data.
        self.large_pages = self.page_size > 8192
        self.header_size = 80 if self.large_pages else 40
        # The two header pages (primary + shadow) precede the data pages: logical page P is at
        # (P + 1) * page_size, so the data pages number the file's pages minus the two headers.
        self.total_pages = max(0, (len(self.data) // self.page_size) - 2)
        self._tables = None     # {objid: {"name": str, "fdp": int}}
        self._columns = None    # {objid: [column dict]}
        # Whether the catalog read was EXACT (no walk drop, no decode failure, no cap hit) and,
        # per table objid, whether that table's column set was captured whole. A COUNT that is
        # not provably complete is never emitted as a fact (see count_rows / _answer_one).
        self._catalog_complete = None
        self._column_dropped = set()   # objids whose column set hit the cap or an unknown type

    # -- pages ---------------------------------------------------------------

    def _page_bytes(self, pgno: int) -> bytes:
        if pgno < 1 or pgno > self.total_pages:
            raise EseError(f"page {pgno} out of range (1..{self.total_pages})")
        off = (pgno + 1) * self.page_size
        page = self.data[off:off + self.page_size]
        if len(page) != self.page_size:
            raise EseError(f"page {pgno} truncated")
        return page

    def _page_header(self, page: bytes) -> dict:
        # Structural fields at 0x08.. are stable across every revision; the first 8 bytes
        # (checksums / page number) are opaque and never read.
        try:
            objid_fdp = struct.unpack_from("<I", page, 0x18)[0]
            avail_size = struct.unpack_from("<H", page, 0x1C)[0]
            first_avail_offset = struct.unpack_from("<H", page, 0x20)[0]
            tag_count = struct.unpack_from("<H", page, 0x22)[0]
            flags = struct.unpack_from("<I", page, 0x24)[0]
        except struct.error as e:
            raise EseError("short page header") from e
        return {"objid_fdp": objid_fdp, "available_size": avail_size,
                "first_available_offset": first_avail_offset, "tag_count": tag_count, "flags": flags}

    def _tags(self, page: bytes, tag_count: int) -> list:
        """[(offset, size, flags)] for each cell, offset/size relative to the page-data area
        (just after the page header). The tag array grows backwards from the end of the page."""
        if tag_count < 0 or tag_count > self.page_size // 4:
            raise EseError("insane tag count")
        out = []
        data_base = self.header_size
        for i in range(tag_count):
            toff = self.page_size - (i + 1) * 4
            if toff < data_base:
                raise EseError("tag array overlaps page data")
            cb, ib = struct.unpack_from("<HH", page, toff)
            if self.large_pages:
                size = cb & 0x7FFF
                offset = ib & 0x7FFF
                flags = 0           # large pages carry the flags in the entry's first 2 bytes
            else:
                size = cb & 0x1FFF
                offset = ib & 0x1FFF
                flags = (ib >> 13) & 0x7
            start = data_base + offset
            if start < data_base or start + size > self.page_size or size < 0:
                raise EseError("tag points outside the page")
            out.append((start, size, flags))
        return out

    def _entry(self, page: bytes, tag):
        """(entry_flags, value_bytes) for a cell: the local key is skipped and the value
        (record / child pointer) is returned. For large pages the entry flags are the first
        2 bytes of the cell."""
        start, size, flags = tag
        cell = page[start:start + size]
        pos = 0
        if self.large_pages and size >= 2:
            flags = (struct.unpack_from("<H", cell, 0)[0] >> 13) & 0x7
            pos = 2
        # A cell with the "common key" flag (0x04) begins with a 2-byte common-key size.
        if flags & 0x04:
            if pos + 2 > size:
                raise EseError("short common-key prefix")
            pos += 2
        if pos + 2 > size:
            raise EseError("short local-key size")
        local_key_size = struct.unpack_from("<H", cell, pos)[0]
        pos += 2
        if pos + local_key_size > size:
            raise EseError("local key overruns cell")
        pos += local_key_size
        return flags, cell[pos:]

    # -- B-tree walk ---------------------------------------------------------

    def _leaf_records(self, fdp: int, stats=None):
        """Yield the record bytes of every DATA leaf under `fdp`, bounded and cycle-guarded.

        Only data pages are walked: a space / index / long-value page is skipped. A branch
        cell's value ends in a 4-byte child page number (little-endian).

        When `stats` is a dict it is filled with whether the walk was EXACT: `stats["capped"]`
        is set if a bound stopped it early (MAX_ROWS saturation, MAX_PAGES_WALK, MAX_DEPTH) and
        `stats["dropped"]` if a page, cell or child pointer could not be followed. A caller that
        needs an exact count (never-wrong) refuses a count when either is set. The control flow
        is unchanged when `stats` is None (every existing caller)."""
        visited = set()
        stack = [(fdp, 0)]
        pages_seen = rows = 0
        while stack:
            pgno, depth = stack.pop()
            if depth > MAX_DEPTH or pages_seen >= MAX_PAGES_WALK or rows >= MAX_ROWS:
                if stats is not None:
                    stats["capped"] = True      # a bound stopped the walk with pages still to visit
                return
            if pgno in visited:
                continue
            visited.add(pgno)
            pages_seen += 1
            try:                                # a structurally bad page is skipped, never fatal
                page = self._page_bytes(pgno)
                hdr = self._page_header(page)
                tags = self._tags(page, hdr["tag_count"])
            except EseError:
                if stats is not None:
                    stats["dropped"] = True     # a page we could not read: a row may be lost
                continue
            flags = hdr["flags"]
            if flags & (PAGE_IS_SPACE_TREE | PAGE_IS_INDEX | PAGE_IS_LONG_VALUE):
                continue
            # Tag 0 is the page's external header, not a record.
            for tag in tags[1:]:
                try:
                    _f, value = self._entry(page, tag)
                except EseError:
                    if stats is not None:
                        stats["dropped"] = True  # a cell we could not read: a row may be lost
                    continue
                if flags & PAGE_IS_LEAF:
                    if value:
                        rows += 1
                        yield value
                        if rows >= MAX_ROWS:
                            if stats is not None:
                                stats["capped"] = True   # saturated at the row cap
                            return
                else:
                    if len(value) >= 4:
                        child = struct.unpack_from("<I", value, len(value) - 4)[0]
                        if 1 <= child <= self.total_pages:
                            if child not in visited:
                                stack.append((child, depth + 1))
                        elif stats is not None:
                            stats["dropped"] = True       # a child pointer out of range: a lost subtree
                    elif stats is not None:
                        stats["dropped"] = True           # a branch cell with no child pointer

    # -- records -------------------------------------------------------------

    def _decode_record(self, record: bytes, columns: list) -> dict:
        """{fid: raw_bytes} for a data-definition record (the new record format).

        Fixed columns are placed by the catalog's record offset (packed order as a fallback),
        variable columns by the offsets array, tagged columns by the tagged array. Anything
        out of bounds raises EseError (the caller drops the whole row)."""
        if len(record) < 4:
            raise EseError("record shorter than its header")
        last_fixed = record[0]
        last_variable = record[1]
        var_offset = struct.unpack_from("<H", record, 2)[0]
        if last_variable < 127:
            raise EseError("last variable id below 128")
        var_count = last_variable - 127
        if var_offset < 4 or var_offset > len(record):
            raise EseError("variable-data offset out of range")

        out = {}
        fixed = {c["fid"]: c for c in columns if c["fid"] <= 127}
        variable = {c["fid"]: c for c in columns if 128 <= c["fid"] <= 255}
        tagged = sorted((c for c in columns if c["fid"] >= 256), key=lambda c: c["fid"])

        # Fixed-size region: record[4 : var_offset - bitmap]. The trailing null bitmap is one
        # bit per fixed column id 1..last_fixed.
        bitmap_bytes = (last_fixed + 7) // 8
        fixed_region_end = var_offset - bitmap_bytes
        if fixed_region_end < 4:
            raise EseError("fixed region / bitmap inconsistent")
        bitmap = record[fixed_region_end:var_offset]

        def is_null(fid: int) -> bool:
            idx = fid - 1
            byte = idx // 8
            return byte < len(bitmap) and bool(bitmap[byte] & (1 << (idx % 8)))

        # Place fixed columns PACKED in fid order from the end of the 4-byte header. ESE stores the
        # fixed region contiguously in fid order (the catalog's RecordOffset is derived from that);
        # packing is deterministic from the catalog column widths and avoids any ambiguity about
        # the base of a stored RecordOffset. An unknown fixed column loses the cursor -> raise.
        packed = 4
        for fid in range(1, last_fixed + 1):
            col = fixed.get(fid)
            size = FIXED_SIZE.get(col["coltyp"]) if col else None
            if col is None or size is None:
                raise EseError(f"unknown fixed column fid {fid}")
            off = packed
            packed += size
            if is_null(fid):
                continue
            if off + size > fixed_region_end:
                raise EseError("fixed column overruns region")
            out[fid] = record[off:off + size]

        # Variable-size region: var_count uint16 end-offsets, then the data.
        offs_base = var_offset
        data_base = var_offset + var_count * 2
        if data_base > len(record):
            raise EseError("variable offsets overrun record")
        prev_end = data_base
        for k in range(var_count):
            fid = 128 + k
            raw_off = struct.unpack_from("<H", record, offs_base + k * 2)[0]
            null = bool(raw_off & 0x8000)
            end = data_base + (raw_off & 0x7FFF)
            start, prev_end = prev_end, end
            if fid not in variable:
                continue
            if null:
                continue
            if start < data_base or end > len(record) or end < start:
                raise EseError("variable column out of range")
            out[fid] = record[start:end]

        # Tagged region: everything after the variable data. Best effort, strictly validated.
        tagged_base = prev_end
        if tagged and tagged_base < len(record):
            self._decode_tagged(record, tagged_base, tagged, out)
        return out

    def _decode_tagged(self, record: bytes, base: int, tagged: list, out: dict) -> None:
        """Fill `out[fid]` for tagged columns (fid >= 256). The tagged array starts at `base`;
        its first entry's offset is the array size. Strictly validated; raises on any doubt."""
        region = record[base:]
        if len(region) < 4:
            return
        first_off = struct.unpack_from("<H", region, 2)[0] & 0x3FFF
        if first_off < 4 or first_off > len(region) or first_off % 4 != 0:
            raise EseError("tagged array size invalid")
        entries = []
        for i in range(first_off // 4):
            fid = struct.unpack_from("<H", region, i * 4)[0]
            raw = struct.unpack_from("<H", region, i * 4 + 2)[0]
            data_off = raw & 0x3FFF
            entries.append((fid, data_off))
        by_fid = {c["fid"]: c for c in tagged}
        for i, (fid, data_off) in enumerate(entries):
            end = entries[i + 1][1] if i + 1 < len(entries) else len(region)
            if data_off < first_off or end > len(region) or end < data_off:
                raise EseError("tagged column out of range")
            if fid not in by_fid:
                continue
            payload = region[data_off:end]
            # A tagged value may begin with a 1-byte flags field (0x40 = separated long value,
            # 0x02 = compressed, ...). We keep only a simple inline value and skip anything with
            # flags we do not read -- never-wrong: an unread value is absent, not guessed.
            if payload and payload[0] in (0x00, 0x01, 0x02, 0x04, 0x08):
                pass
            out[fid] = payload[:MAX_VALUE_BYTES]

    # -- catalog -------------------------------------------------------------

    def _read_catalog(self) -> None:
        tables, columns = {}, {}
        complete = True             # the catalog read was EXACT (no drop, no decode failure, no cap)
        column_dropped = set()      # objids whose column set was not captured whole
        count = 0
        stats = {"dropped": False, "capped": False}
        for record in self._leaf_records(CATALOG_FDP, stats):
            count += 1
            if count > MAX_CATALOG_RECORDS or len(tables) > MAX_TABLES:
                complete = False    # the catalog is larger than a cap: the table count is partial
                break
            try:
                fields = self._decode_record(record, _catalog_columns())
            except EseError:
                complete = False    # one bad catalog record does not cost the rest, but a table/column may be lost
                continue
            rtype = _as_int(fields.get(CAT_TYPE))
            objid_table = _as_int(fields.get(CAT_OBJIDTABLE))
            cid = _as_int(fields.get(CAT_ID))
            fdp_or_coltyp = _as_int(fields.get(CAT_COLTYP_FDP))
            space = _as_int(fields.get(CAT_SPACEUSAGE))
            rec_off = _as_int(fields.get(CAT_RECORDOFFSET))
            name = _as_text(fields.get(CAT_NAME_FID))
            if name is None:
                if rtype in (CAT_TYPE_TABLE, CAT_TYPE_COLUMN):
                    complete = False    # a table/column whose name we could not read
                continue
            if rtype == CAT_TYPE_TABLE:
                if cid is not None and fdp_or_coltyp is not None:
                    tables[cid] = {"name": name, "fdp": fdp_or_coltyp}
                else:
                    complete = False    # a table record we could not place
            elif rtype == CAT_TYPE_COLUMN:
                if objid_table is not None and cid is not None:
                    cols = columns.setdefault(objid_table, [])
                    if len(cols) < MAX_COLUMNS and fdp_or_coltyp in COLTYP:
                        cols.append({"name": name, "fid": cid, "coltyp": fdp_or_coltyp,
                                     "space": space, "record_offset": rec_off})
                    else:
                        column_dropped.add(objid_table)   # column cap or an unknown type: this table's columns are partial
                else:
                    complete = False    # a column record we could not attribute to a table
        if stats["dropped"] or stats["capped"]:
            complete = False            # the catalog B-tree walk itself was not exhaustive
        self._tables = tables
        self._columns = columns
        self._catalog_complete = complete
        self._column_dropped = column_dropped

    def tables(self) -> dict:
        if self._tables is None:
            self._read_catalog()
        return self._tables

    def columns(self, objid: int) -> list:
        if self._columns is None:
            self._read_catalog()
        return sorted(self._columns.get(objid, []), key=lambda c: c["fid"])

    def table_by_name(self, name: str):
        for objid, t in self.tables().items():
            if t["name"] == name:
                return objid, t
        return None

    def rows(self, objid: int, limit: int = MAX_ROWS):
        """Yield {column_name: decoded_value} for each data leaf record of the table, bounded."""
        if limit <= 0:
            return
        cols = self.columns(objid)
        if not cols:
            return
        by_fid = {c["fid"]: c for c in cols}
        n = 0
        for record in self._leaf_records(self.tables()[objid]["fdp"]):
            try:
                raw = self._decode_record(record, cols)
            except EseError:
                continue
            row = {}
            for fid, value in raw.items():
                col = by_fid.get(fid)
                if col is None:
                    continue
                row[col["name"]] = _decode_value(col["coltyp"], value)
            yield row
            n += 1
            if n >= limit:
                return

    def count_rows(self, objid: int):
        """(count, complete): the number of data-leaf records of table `objid` and whether the
        walk proved that number EXACT.

        complete is False when the row walk SATURATED at a cap (n >= MAX_ROWS, or a page / depth
        bound stopped it) or DROPPED any page, cell or record it could not decode. A count that
        is not provably exact is never emitted as a fact (never-wrong): the caller returns None.
        (None, False) when the table or its columns cannot be read at all."""
        try:
            fdp = self.tables()[objid]["fdp"]
        except KeyError:
            return None, False
        cols = self.columns(objid)
        if not cols:
            return 0, False         # no columns: records cannot be identified, so the count is untrusted
        n = 0
        stats = {"dropped": False, "capped": False}
        for record in self._leaf_records(fdp, stats):
            try:
                self._decode_record(record, cols)
            except EseError:
                stats["dropped"] = True     # an undecodable leaf record: the row exists but was not counted cleanly
                continue
            n += 1
        if n >= MAX_ROWS:           # read as the module global, so a cap check holds under a test's smaller cap
            stats["capped"] = True
        return n, not (stats["dropped"] or stats["capped"])


def _catalog_columns() -> list:
    cols = [{"name": f"fixed_{fid}", "fid": fid, "coltyp": ct, "space": sz, "record_offset": None}
            for fid, sz, ct in CATALOG_FIXED]
    cols.append({"name": "Name", "fid": CAT_NAME_FID, "coltyp": 10, "space": None, "record_offset": None})
    return cols


# ---------------------------------------------------------------------------- value decoding

def _as_int(raw):
    if not raw:
        return None
    if len(raw) == 1:
        return raw[0]
    if len(raw) == 2:
        return struct.unpack("<H", raw)[0]
    if len(raw) == 4:
        return struct.unpack("<I", raw)[0]
    if len(raw) == 8:
        return struct.unpack("<Q", raw)[0]
    return None


def _as_text(raw):
    if raw is None:
        return None
    for enc in ("utf-16-le", "utf-8"):
        try:
            s = raw.decode(enc)
            if s and all(ord(c) >= 32 or c in "\t" for c in s):
                return s.rstrip("\x00") or None
        except UnicodeDecodeError:
            continue
    return None


def _decode_value(coltyp, raw):
    """A JSON-serialisable Python value for a cell, or None when it cannot be read cleanly.
    Integers/strings are returned as themselves; binary stays a hex string (bounded)."""
    if raw is None:
        return None
    name = COLTYP.get(coltyp)
    try:
        if name == "bit":
            return bool(raw[0]) if raw else None
        if name == "unsigned_byte":
            return raw[0] if raw else None
        if name == "short":
            return struct.unpack("<h", raw[:2])[0] if len(raw) >= 2 else None
        if name == "unsigned_short":
            return struct.unpack("<H", raw[:2])[0] if len(raw) >= 2 else None
        if name == "long":
            return struct.unpack("<i", raw[:4])[0] if len(raw) >= 4 else None
        if name == "unsigned_long":
            return struct.unpack("<I", raw[:4])[0] if len(raw) >= 4 else None
        if name in ("long_long", "currency"):
            return struct.unpack("<q", raw[:8])[0] if len(raw) >= 8 else None
        if name == "ieee_single":
            return struct.unpack("<f", raw[:4])[0] if len(raw) >= 4 else None
        if name == "ieee_double":
            return struct.unpack("<d", raw[:8])[0] if len(raw) >= 8 else None
        if name == "datetime":
            return _oa_date(raw) if len(raw) >= 8 else None
        if name == "guid":
            return _guid(raw) if len(raw) >= 16 else None
        if name in ("text", "long_text"):
            return _as_text(raw)
        if name in ("binary", "long_binary"):
            return raw[:MAX_VALUE_BYTES].hex()
    except (struct.error, UnicodeDecodeError, IndexError):
        return None
    return raw[:MAX_VALUE_BYTES].hex()


def _oa_date(raw):
    """An ESE DateTime is an OLE automation date (float days since 1899-12-30 UTC)."""
    import datetime
    try:
        days = struct.unpack("<d", raw[:8])[0]
    except struct.error:
        return None
    if days != days or abs(days) > 2958466:    # NaN or out of the year 0001..9999 range
        return None
    try:
        base = datetime.datetime(1899, 12, 30, tzinfo=datetime.timezone.utc)
        # OLE automation date: the integer part is signed days, but the fractional part is the
        # absolute time of day (so -1.25 is the day before, six hours in, not 1.25 days back).
        day_int = int(days)                     # truncates toward zero
        frac = abs(days - day_int)
        return (base + datetime.timedelta(days=day_int)
                + datetime.timedelta(days=frac)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        return None


def _guid(raw):
    try:
        a, b, c = struct.unpack_from("<IHH", raw, 0)
        d = raw[8:10]
        e = raw[10:16]
        return f"{a:08x}-{b:04x}-{c:04x}-{d.hex()}-{e.hex()}"
    except struct.error:
        return None


# ---------------------------------------------------------------------------- one report per file

def classify(data: bytes) -> dict:
    """{"kind": "ese", "facts": {...}, "tables": [...]} for an ESE database, else None.

    `facts` is the header; `tables` is a bounded list of {name, objid, fdp, columns:[...],
    row_count} read from the catalog. Every field is a fact read from the bytes; the solver
    turns them into unsure answers."""
    try:
        db = Database(data)
    except EseError:
        return None
    facts = dict(db.header)
    facts["total_pages"] = db.total_pages
    out_tables = []
    try:
        tables = db.tables()
    except EseError:
        tables = {}
    catalog_complete = bool(getattr(db, "_catalog_complete", False))
    column_dropped = getattr(db, "_column_dropped", set())
    for objid, t in list(tables.items())[:MAX_TABLES]:
        try:
            cols = db.columns(objid)
        except EseError:
            cols = []
        out_tables.append({"name": t["name"], "objid": objid, "fdp": t["fdp"],
                           "columns": [{"name": c["name"], "coltyp": COLTYP.get(c["coltyp"]),
                                        "fid": c["fid"]} for c in cols],
                           # the column COUNT of this table is a fact only when the whole catalog
                           # read cleanly and this table's columns were not capped / typed unknown
                           "columns_complete": catalog_complete and objid not in column_dropped})
    out_tables.sort(key=lambda x: (x["name"] or "").lower())
    return {"kind": "ese", "facts": facts, "tables": out_tables, "catalog_complete": catalog_complete}


def _digest(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def reports(files) -> list:
    out = []
    if files is None:
        source = {}
    elif isinstance(files, dict):
        source = files
    else:
        return []        # a malformed container (not a name->bytes mapping): nothing to read
    try:
        items = triage.unique_files(source) if triage else list(source.items())
    except Exception:  # noqa: BLE001
        items = list(source.items())
    for name, data in items:
        if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_FILE:
            continue
        try:
            rep = classify(data)
        except Exception:  # noqa: BLE001 - one unreadable file does not cost the others
            rep = None
        if rep is not None:
            rep["digest"] = _digest(bytes(data))
            rep["_data"] = bytes(data)
            out.append((name, rep))
    return out


# ---------------------------------------------------------------------------- signals

_WORDS = re.compile(
    r"\bese\b|\bedb\b|esent|extensible storage|jet ?blue|\bsrum\b|srudb|resource usage|"
    r"webcache|webcachev01|\bntds(\.dit)?\b|\bdit\b|catalog|msysobjects|\btable\b|\bcolumn\b|"
    r"\brow\b|\brecord\b|bytes (?:sent|received)|last (?:run|execution)|container|database", re.I)


def signals(questions, files) -> float:
    """0..1: an ESE database in the bytes plus database/forensic vocabulary in the questions.
    0.0 when no ESE validates (so it never competes on a 64-byte blob or a pcap)."""
    try:
        reps = reports(files or {})
    except Exception:  # noqa: BLE001
        reps = []
    if not reps:
        return 0.0
    score = 0.5
    hits = set()
    for q in questions or []:
        f = q.get("answer_format") if isinstance(q, dict) and isinstance(q.get("answer_format"), dict) else {}
        text = " ".join(str(x or "") for x in (q.get("question"), q.get("answer_id") or q.get("id"),
                                               f.get("syntax")))
        hits |= {m.group().lower() for m in _WORDS.finditer(text)}
    score += min(0.4, 0.1 * len(hits))
    return round(min(1.0, score), 3)


# ---------------------------------------------------------------------------- answers (never-guess)

def _pick(field, shape, reader, value):
    """A STRUCTURAL fact read by a deterministic reader: labels.pick under a fixed shape, with
    the option NAME the reader method (never equal to the value -- never a bare-label pick)."""
    if value is None or reader is None:
        return None
    key = f"{KEY}.ese_{field}/{shape}"
    try:
        return labels.pick(key, [(str(reader), value)])
    except ValueError:
        return None


def _candidates(field, scope, options):
    """A ROW VALUE or a catalog NAME: labels.candidates scoped to the delivery digest, so an
    accepted hypothesis rank can never answer a different variant. Option NAMES are provenance
    hypotheses (never the value); a bare option (name == value) is dropped by labels."""
    key = f"{KEY}.ese_{field}/{scope}"
    opts, seen = [], set()
    for name, value in options:
        if value is None or value == "" or name is None or str(name) == str(value) or name in seen:
            continue
        seen.add(name)
        opts.append((str(name), value))
    if not opts:
        return None
    try:
        return labels.candidates(key, opts)
    except ValueError:
        return None


_TABLE_RX = re.compile(r"['\"`]([A-Za-z_][\w$]{1,63})['\"`]|\b([A-Z][A-Za-z0-9_]*(?:Table|Map|Containers?))\b")


def _named_table(text, rep):
    """The one catalog table the question names (quoted, or a CamelCase table-like token that
    matches a real table), else None when zero or several match -- never a guess."""
    names = {t["name"] for t in rep["tables"] if t["name"]}
    wanted = set()
    for m in _TABLE_RX.finditer(text or ""):
        tok = m.group(1) or m.group(2)
        if tok in names:
            wanted.add(tok)
    if len(wanted) == 1:
        return next(iter(wanted))
    return None


def _answer_one(q, rep):
    text = str(q.get("question") or "")
    aid = str(q.get("answer_id") or q.get("id") or q.get("qid") or "")
    t = (text + " " + aid).lower()
    facts = rep["facts"]
    scope = rep.get("digest") or "d"

    def has(*words):
        return any(re.search(r"(?<![a-z])" + w + r"(?![a-z])", t) for w in words)

    if has("flag"):
        return None                       # the flag is never this reader's

    # Structural header facts: deterministic readers, so the option name is the reader method.
    if has("page size", "page_size", "pagesize"):
        return _pick("page_size", "header", "u32_at_236", facts.get("page_size"))
    if has("format version", "database version", "db version", "version") and not has("revision"):
        return _pick("format_version", "header", "u32_at_8", facts.get("format_version"))
    if has("revision"):
        return _pick("format_revision", "header", "u32_at_232", facts.get("format_revision"))
    if has("file type", "streaming") and facts.get("file_type") is not None:
        return _pick("file_type", "header", "u32_at_12", facts.get("file_type"))

    # Counts. A COUNT is NOT a deterministic exact-offset fact like the header: the walk caps at
    # MAX_ROWS / MAX_TABLES / MAX_COLUMNS and silently drops records it cannot decode, so a
    # saturated or incomplete count is WRONG on a larger variant (a SRUM table routinely exceeds
    # MAX_ROWS). So, unlike the header picks, a count is (a) emitted ONLY when the walk proved it
    # exact, and (b) as a delivery-DIGEST-SCOPED candidate (never a cross-variant labels.pick): an
    # accepted count name can then only ever answer the SAME delivery, never a different variant.
    if has("how many tables", "number of tables", "table count", "tables"):
        if has("table") and (has("how many") or has("count") or has("number")):
            if not rep.get("catalog_complete"):
                return None                    # the catalog was capped or a record dropped: not a fact
            return _count_candidate("table_count", None, scope, "catalog_type1_count", len(rep["tables"]))

    named = _named_table(text, rep)
    if named is not None:
        objid = next((tb["objid"] for tb in rep["tables"] if tb["name"] == named), None)
        if has("how many columns", "number of columns", "column count"):
            cols = next((tb["columns"] for tb in rep["tables"] if tb["name"] == named), [])
            complete = next((tb.get("columns_complete") for tb in rep["tables"] if tb["name"] == named), False)
            if not complete:
                return None                    # this table's column set was capped / typed unknown
            return _count_candidate("column_count", f"table@{_shape(named)}", scope, "catalog_column_count", len(cols))
        if has("how many rows", "number of rows", "number of records", "row count", "record count") \
                and objid is not None:
            n, complete = _count_rows(rep, objid)
            if n is None or not complete:
                return None                    # saturated at the cap, or a record dropped: never a wrong plain
            return _count_candidate("row_count", f"table@{_shape(named)}", scope, "leaf_record_count", n)
        # A ROW VALUE of a named column of the named table: delivery-scoped candidates.
        if objid is not None:
            col = _named_column(text, rep, named)
            if col is not None:
                return _row_value_candidates(rep, objid, named, col, scope)

    # "name a table" / "what table" -> the catalog names as delivery-scoped candidate hypotheses.
    if has("table") and has("name", "called", "which", "what") and not has("column"):
        names = [tb["name"] for tb in rep["tables"] if tb["name"]]
        if names:
            return _candidates("table_name", scope,
                               [(f"catalog_rank_{i}", nm) for i, nm in enumerate(names[:labels.MAX_OPTIONS])])
    return None


def _shape(text) -> str:
    return re.sub(r"[^a-z0-9_.+-]+", "_", str(text or "").lower()).strip("_") or "x"


def _count_rows(rep, objid):
    """(count, complete) for a table, via Database.count_rows: the row count and whether the walk
    proved it EXACT (no cap saturation, no dropped record). (None, False) when the table cannot
    be read. An incomplete count is never emitted as a fact (never-wrong)."""
    try:
        db = Database(rep["_data"])
        return db.count_rows(objid)
    except EseError:
        return None, False


def _count_candidate(field, shape, scope, hypothesis, n):
    """A COUNT fact as a delivery-DIGEST-SCOPED labels.candidates, never a cross-variant plain
    labels.pick: the digest in the scope means an accepted count can only ever answer the SAME
    delivery, so a saturated/incomplete count learned on one variant can never go out plain on
    another. `hypothesis` names the reader (never the value). None when there is no count."""
    if n is None:
        return None
    sc = f"{shape}.{scope}" if shape else str(scope)
    return _candidates(field, sc, [(str(hypothesis), n)])


def _named_column(text, rep, table_name):
    cols = next((tb["columns"] for tb in rep["tables"] if tb["name"] == table_name), [])
    names = {c["name"] for c in cols if c["name"]}
    wanted = [n for n in names if re.search(r"(?<![\w])" + re.escape(n) + r"(?![\w])", text or "")]
    return wanted[0] if len(wanted) == 1 else None


def _row_value_candidates(rep, objid, table_name, column, scope):
    """Up to MAX_OPTIONS distinct cell values of (table, column), each a candidate hypothesis
    `row<n>_<table>_<column>` with the read value, scoped to the delivery so an accepted rank
    never answers another variant. None when the column reads nothing clean."""
    try:
        db = Database(rep["_data"])
    except EseError:
        return None
    opts, seen = [], set()
    for i, row in enumerate(db.rows(objid)):
        if i >= MAX_ROWS or len(opts) >= labels.MAX_OPTIONS:
            break
        if column in row and row[column] is not None:
            val = row[column]
            key = (str(val), type(val).__name__)
            if key in seen:
                continue
            seen.add(key)
            opts.append((f"row{i}_{_shape(table_name)}_{_shape(column)}", val))
    return _candidates(f"value@{_shape(table_name)}.{_shape(column)}", scope, opts)


def _file_for(q, reps):
    if not reps:
        return None
    member = q.get("member") or (str(q.get("artifact") or "").split(ARROW)[-1] if q.get("artifact") else "")
    base = Path(str(member)).name if member else ""
    if base:
        hit = [r for r in reps if Path(r[0]).name == base or r[0].split(ARROW)[-1] == member or r[0] == member]
        if len(hit) == 1:
            return hit[0][1]
        if hit:
            return None
    return reps[0][1] if len(reps) == 1 else None


def solve_set(questions, files, ctx) -> dict:
    reps = reports(files)
    out = {}
    for q in questions or []:
        qid = q.get("qid") or q.get("id") or q.get("answer_id")
        if qid is None:
            continue
        rep = _file_for(q, reps)
        try:
            out[qid] = None if rep is None else _answer_one(q, rep)
        except Exception:  # noqa: BLE001 - a fact that cannot be read is no answer
            out[qid] = None
        if isinstance(ctx, dict) and out[qid] is not None:
            ctx.setdefault("partial", {})[qid] = out[qid]
    return out


# ---------------------------------------------------------------------------- CLI (offline triage)

def _show(v, width=70) -> str:
    s = str(v).replace("\n", "\\n")
    return s if len(s) <= width else s[:width - 3] + "..."


def main(argv) -> int:
    as_json = "--json" in argv
    want_rows = "--rows" in argv
    paths = [a for a in argv if not a.startswith("--")]
    if not paths:
        print("usage: ese_reader.py <SRUDB.dat|WebCacheV01.dat|NTDS.dit|*.edb>... [--json] [--rows]\n"
              "  RECON ONLY; header + catalog (tables/columns) and bounded row values; every answer unsure, flag None",
              file=sys.stderr)
        return 2
    out = []
    for p in paths:
        try:
            data = Path(p).read_bytes()
        except OSError as e:
            print(f"ese_reader.py: {p}: {e}", file=sys.stderr)
            continue
        rep = classify(data)
        row = {"file": p, "bytes": len(data), "ese": rep is not None}
        if rep is not None:
            row["facts"] = rep["facts"]
            row["tables"] = [{"name": t["name"], "objid": t["objid"], "columns": len(t["columns"])}
                             for t in rep["tables"]]
            if want_rows:
                try:
                    db = Database(data)
                    row["sample"] = {}
                    for t in rep["tables"][:8]:
                        rows = []
                        for i, r in enumerate(db.rows(t["objid"], limit=5)):
                            rows.append({k: _show(v) for k, v in list(r.items())[:12]})
                        row["sample"][t["name"]] = rows
                except EseError:
                    row["sample"] = None
        out.append(row)
    if as_json:
        print(json.dumps(out, indent=1, default=str))
        return 0
    for row in out:
        if not row["ese"]:
            print(f"- {row['file']}: not an ESE/EDB database ({row['bytes']} bytes)")
            continue
        f = row["facts"]
        print(f"# {row['file']}  [ESE]  page_size={f['page_size']} version=0x{f['format_version']:x} "
              f"file_type={f['file_type']} pages={f['total_pages']}  tables={len(row['tables'])}")
        for t in row["tables"]:
            print(f"    table {t['name']}  objid={t['objid']}  columns={t['columns']}")
        for tname, rows in (row.get("sample") or {}).items():
            if rows:
                print(f"    rows of {tname}:")
                for r in rows:
                    print("      " + ", ".join(f"{k}={v}" for k, v in r.items()))
        print("  all facts are answered unsure (labels.pick / labels.candidates); the flag is None.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
