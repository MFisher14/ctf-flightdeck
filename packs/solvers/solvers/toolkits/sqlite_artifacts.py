#!/usr/bin/env python3
"""Toolkit `sqlite_artifacts`: browser and application artifacts in SQLite, LevelDB and extension
folders. Offline: no Game Master request, no token, standard library only on the answering path.

  .venv/bin/python solvers/toolkits/sqlite_artifacts.py <file or folder>...     a triage of the files

What it reads (by schema and magic, never by file name):
  - SQLite databases through a temporary copy (read-only, `immutable=1`; with a `-wal` beside it the
    copy is opened with its WAL so the live view is the committed one): Chromium History (urls,
    visits, downloads and their URL chains, keyword_search_terms), Login Data, Cookies, Web Data;
    Firefox places.sqlite (history, bookmarks, download annotations), cookies.sqlite,
    formhistory.sqlite, webappsstore.sqlite and logins.json; Safari History.db; macOS quarantine
    events; iOS sms.db; WhatsApp msgstore.db (both layouts); Fossil repositories (users, config,
    events, blobs with their deltas applied). Any other database is dumped table by table.
  - deleted rows, with a page parser of its own: every WAL frame (superseded and stale ones too),
    rollback-journal pages, freelist pages, and a record carve over the unallocated space and the
    freeblocks of every page. A row found there that the live view does not hold is `recovered`.
  - Chrome extensions: manifest v2/v3 (permissions, host permissions, background script or service
    worker, content scripts), CRX2/CRX3 header strip, the extension id from the public key.
  - LevelDB `.log` (write batches, deletes included) and `.ldb` tables (snappy in pure Python), with
    the Local Storage key and value prefixes; a string carve when a file does not parse.
  - staged text in URL and title cells: url-encoding, base64 (UTF-16LE too), hex, uuencode, nested.
  - times by the column's own clock (WebKit, PRTime, Unix s/ms, Mac absolute s/ns, Julian day),
    offered in several spellings.
  - encrypted values (DPAPI, v10/v11/v20): None, unless the key is in the delivery (a Local State
    whose os_crypt key is not DPAPI-wrapped) or it is Chromium's fixed Linux key; then unsure.

Never-guess (AGENTS.md, "Uncertain answers"). solve_set answers
  plain    a value copied from one cell (or a count of rows) when the question asks for that field
           in so many words and exactly one reading of exactly one live row is left;
  unsure   labels.pick('sqlite_artifacts.<field>/<artifact kind>', [(name, value), ...]) for every
           time (the spelling is the author's), every recovered row, every decoded or decrypted
           value, a list (its join) and a fact with two readings (first or final URL of a chain);
  None     everything else: a question whose words name no field here, rows that give different
           values, a name in the question that no row carries, a delivery with none of these files.
The label key's lane is `sqlite_artifacts`. Until solvers/common/labels.py lists that lane, pick()
here writes the unsure wire form itself: never sent, read as unsure everywhere, not probed.
"""
import base64
import binascii
import hashlib
import json
import os
import re
import sqlite3
import struct
import sys
import tempfile
import time
import zipfile
import zlib
import io
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote, unquote_plus, urlsplit

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "common"))
try:
    import labels
except Exception:                                  # the toolkit still reads files without it
    labels = None

KEY = "sqlite_artifacts"
UNSURE = "??"
MAX_OPTIONS = 12
ARROW = " -> "
UTC = timezone.utc
MAX_ROWS = 20000            # rows read per table
MAX_PAGES = 4000            # page images parsed for deleted rows
CARVE_SECONDS = 0.6         # the carve stops after this long; what it found by then stays
CARVE_TOTAL_SECONDS = 1.5   # all databases of one delivery together; later ones are not carved
OPEN_SECONDS = 2.0          # the library's reads of one database are interrupted after this long
SQLITE_MAGIC = b"SQLite format 3\x00"


# ---- unsure answers ----------------------------------------------------------------------------------

def _shape(text) -> str:
    return re.sub(r"[^a-z0-9_.+-]+", "_", str(text or "").lower()).strip("_") or "q"


def pick(field: str, shape: str, options):
    """labels.pick under 'sqlite_artifacts.<field>/<shape>'; the bare wire form while labels.py does
    not know the lane. None when no option is left."""
    key = f"{KEY}.{_shape(field)}/{_shape(shape)}"
    opts, seen = [], set()
    for name, value in options:
        if value is None or value == "" or name in seen:
            continue
        seen.add(name)
        opts.append((name, value))
    if not opts:
        return None
    if labels is not None:
        try:
            return labels.pick(key, opts)
        except ValueError:
            pass
    return UNSURE + json.dumps({"k": key, "o": [[n, v] for n, v in opts[:MAX_OPTIONS]]}, separators=(",", ":"))


def options_of(value) -> list:
    """[(name, value)] of an unsure answer; [] for anything else."""
    if not (isinstance(value, str) and value.startswith(UNSURE)):
        return []
    try:
        return [(o[0], o[1]) for o in json.loads(value[len(UNSURE):])["o"]]
    except (ValueError, KeyError, TypeError, IndexError):
        return []


# ---- time ----------------------------------------------------------------------------------------------

_E1601 = datetime(1601, 1, 1, tzinfo=UTC)
_E1970 = datetime(1970, 1, 1, tzinfo=UTC)
_E2001 = datetime(2001, 1, 1, tzinfo=UTC)


def _since(epoch, micro):
    try:
        return epoch + timedelta(microseconds=int(micro))
    except (OverflowError, ValueError, TypeError):
        return None


def from_webkit(n):
    """WebKit/Chrome time: microseconds since 1601-01-01 UTC. 0 is 'never'."""
    return _since(_E1601, n) if n else None


def from_prtime(n):
    """Firefox PRTime: microseconds since 1970-01-01 UTC."""
    return _since(_E1970, n) if n else None


def from_unix(n):
    return _since(_E1970, round(float(n) * 1_000_000)) if n else None


def from_unix_ms(n):
    return _since(_E1970, int(n) * 1000) if n else None


def from_mac_absolute(n):
    """Mac absolute time: seconds since 2001-01-01 UTC; iOS 11+ message dates are nanoseconds."""
    if n is None or n == 0:
        return None
    return _since(_E2001, int(n) // 1000 if abs(float(n)) > 1e12 else round(float(n) * 1_000_000))


def from_julian(n):
    """A Julian day number (Fossil's mtime)."""
    return _since(_E1970, round((float(n) - 2440587.5) * 86400 * 1_000_000)) if n else None


CLOCKS = {"webkit": from_webkit, "prtime": from_prtime, "unix": from_unix, "unix_ms": from_unix_ms,
          "mac_absolute": from_mac_absolute, "julian": from_julian}


def _download_clock(raw) -> str:
    """Chromium's downloads table: WebKit microseconds since 2012 (version 24), Unix seconds before."""
    return "unix" if isinstance(raw, (int, float)) and not isinstance(raw, bool) and 0 < raw < 100000000000 else "webkit"


def stamp(raw, clock: str):
    """(raw, datetime or None) of a time cell read by its column's clock."""
    try:
        return (raw, CLOCKS[clock](raw)) if isinstance(raw, (int, float)) and not isinstance(raw, bool) else (raw, None)
    except (ValueError, OverflowError, TypeError):
        return (raw, None)


def time_options(dt, raw=None) -> list:
    """One moment as labels.pick options, best first. The names agree with
    solvers/common/evidence_core.py: iso_z, iso_space, raw, iso_offset, epoch, epoch_ms; and
    iso_z_seconds, iso_naive, date."""
    out = []
    if dt is not None:
        u = dt.astimezone(UTC)
        frac = f".{u.microsecond:06d}".rstrip("0") if u.microsecond else ""
        sec = u.strftime("%Y-%m-%dT%H:%M:%S")
        out.append(("iso_z", sec + frac + "Z"))
        if frac:
            out.append(("iso_z_seconds", sec + "Z"))
        out.append(("iso_space", u.strftime("%Y-%m-%d %H:%M:%S")))
    if raw is not None and str(raw).strip():
        out.append(("raw", str(raw).strip()))
    if dt is not None:
        out += [("iso_offset", sec + frac + "+00:00"), ("iso_naive", sec),
                ("epoch", str(int((u - _E1970).total_seconds()))),
                ("epoch_ms", str(int((u - _E1970) / timedelta(milliseconds=1)))),
                ("iso_space_utc", u.strftime("%Y-%m-%d %H:%M:%S") + " UTC"), ("date", u.strftime("%Y-%m-%d"))]
    return out


# ---- the SQLite file format, read without the library (for what the library will not show) --------

def varint(buf, off: int):
    """(value, next offset) of a SQLite varint; ValueError for missing bytes."""
    if type(off) is not int or off < 0 or off >= len(buf):
        raise ValueError("varint offset")
    v = 0
    for i in range(8):
        if off + i >= len(buf):
            raise ValueError("truncated varint")
        b = buf[off + i]
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            return v, off + i + 1
    if off + 8 >= len(buf):
        raise ValueError("truncated varint")
    return (v << 8) | buf[off + 8], off + 9


def _serial_size(t: int) -> int:
    if t <= 4:
        return t
    if t == 5:
        return 6
    if t in (6, 7):
        return 8
    if t in (8, 9):
        return 0
    if t in (10, 11):
        raise ValueError("reserved serial type")
    return (t - 12) // 2 if t % 2 == 0 else (t - 13) // 2


def _serial_value(t: int, raw: bytes, enc: str, strict: bool):
    if t == 0:
        return None
    if t <= 6:
        return int.from_bytes(raw, "big", signed=True)
    if t == 7:
        return struct.unpack(">d", raw)[0]
    if t == 8:
        return 0
    if t == 9:
        return 1
    if t % 2 == 0:
        return bytes(raw)
    return raw.decode(enc) if strict else raw.decode(enc, "replace")


def read_record(buf, off: int, end: int, enc: str = "utf-8", strict: bool = False):
    """(values, next offset) of a record that starts at `off` and lies inside buf[:end]; ValueError
    for bytes that are not one. `strict` also refuses text that is not valid in the encoding."""
    try:
        if type(off) is not int or type(end) is not int or not 0 <= off < end <= len(buf):
            raise ValueError("record bounds")
        hs, p = varint(buf, off)
        if hs < 2 or off + hs > end:
            raise ValueError("header")
        types = []
        while p < off + hs:
            t, p = varint(buf, p)
            types.append(t)
        if p != off + hs or not types:
            raise ValueError("header length")
        values = []
        for t in types:
            n = _serial_size(t)
            if p + n > end:
                raise ValueError("body")
            values.append(_serial_value(t, buf[p:p + n], enc, strict))
            p += n
        return values, p
    except (IndexError, UnicodeDecodeError, struct.error) as e:
        raise ValueError(str(e))


def wal_checksum(data, sums, endian: str):
    """The WAL running checksum over `data` (a multiple of 8 bytes), continued from `sums`."""
    s0, s1 = sums
    for x0, x1 in struct.iter_unpack(endian + "II", data):
        s0 = (s0 + x0 + s1) & 0xFFFFFFFF
        s1 = (s1 + x1 + s0) & 0xFFFFFFFF
    return s0, s1


class Pages:
    """A database file as page images, with the page images its WAL and its rollback journal hold.

    Time travel (B-075): `commits()` lists the committed transactions among the valid WAL frames,
    `image_at(k)` is the page overlay as of commit k (0: the main file alone, len(commits()): the
    committed image, `final`), `size_at(k)` the database size in pages then and `image_bytes(k)` the
    whole database file as of commit k."""

    def __init__(self, data: bytes, wal: bytes = None, journal: bytes = None):
        if data[:16] != SQLITE_MAGIC or len(data) < 100:
            raise ValueError("not a SQLite database")
        self.data = data
        ps = struct.unpack_from(">H", data, 16)[0]
        self.page_size = 65536 if ps == 1 else ps
        if self.page_size < 512 or self.page_size & (self.page_size - 1):
            raise ValueError("page size")
        self.reserved = data[20]
        self.usable = self.page_size - self.reserved
        self.enc = {2: "utf-16-le", 3: "utf-16-be"}.get(struct.unpack_from(">I", data, 56)[0], "utf-8")
        self.freelist_trunk, self.freelist_count = struct.unpack_from(">II", data, 32)
        self.wal_mode = data[18] == 2 or data[19] == 2
        self.count = len(data) // self.page_size
        self.wal_endian, self.wal_salt = None, None     # of the WAL header, when there is a readable one
        self.frames = self._wal(wal) if wal else []
        self.journal = self._journal(journal) if journal else []
        # the committed transactions: runs of valid frames that end in a commit frame, oldest first
        self._commits, first, pages = [], None, []
        for fr in self.frames:
            if not fr["valid"]:
                break
            first = fr["frame"] if first is None else first
            pages.append(fr["page"])
            if fr["commit"]:
                self._commits.append({"index": len(self._commits) + 1, "first": first, "last": fr["frame"],
                                      "pages": sorted(set(pages)), "size": fr["commit"]})
                first, pages = None, []
        # the committed image: the main file under the valid frames up to the last commit
        self.final = self.image_at(len(self._commits))

    def commits(self) -> list:
        """[{index, first, last, pages, size}] of the committed transactions in the WAL, oldest first:
        index counts from 1, first and last are frame numbers, pages the page numbers the transaction
        wrote, size the database size in pages after it. Valid frames only (the header's salts, an
        unbroken checksum chain); valid frames after the last commit frame belong to no commit."""
        return [dict(c, pages=list(c["pages"])) for c in self._commits]

    def image_at(self, k: int) -> dict:
        """{page: bytes} of the valid frames up to and including commit k, for page(n, image) and the
        b-tree readers: k = 0 is the main file alone, k = len(commits()) the committed image."""
        if type(k) is not int or not 0 <= k <= len(self._commits):
            raise ValueError(f"commit {k!r}: this WAL has commits 0 (the main file) to {len(self._commits)}")
        image = {}
        if k:
            last = self._commits[k - 1]["last"]
            for fr in self.frames:
                if fr["frame"] > last:
                    break
                image[fr["page"]] = fr["data"]
        return image

    def size_at(self, k: int) -> int:
        """The database size in pages as of commit k (0: the pages of the main file)."""
        if type(k) is not int or not 0 <= k <= len(self._commits):
            raise ValueError(f"commit {k!r}: this WAL has commits 0 (the main file) to {len(self._commits)}")
        return self._commits[k - 1]["size"] if k else self.count

    def image_bytes(self, k: int, image: dict = None, size: int = None) -> bytes:
        """The database file as of commit k: pages 1..size_at(k), each from the WAL image of that
        commit or else from the main file. The bytes are the pages as they are (a WAL-mode header
        still says WAL). `image` and `size` replace the commit's (for an image built from other frames)."""
        image = self.image_at(k) if image is None else image
        size = self.size_at(k) if size is None else size
        return b"".join(self.page(n, image).ljust(self.page_size, b"\0") for n in range(1, size + 1))

    def page(self, n: int, image: dict = None) -> bytes:
        """Page n (1-based) of the committed image, or of the main file alone with image={}."""
        image = self.final if image is None else image
        if n in image:
            return image[n]
        return self.data[(n - 1) * self.page_size:n * self.page_size]

    def _wal(self, wal: bytes) -> list:
        if len(wal) < 32:
            return []
        magic, _, ps, _, salt1, salt2 = struct.unpack_from(">IIIIII", wal, 0)
        if magic not in (0x377F0682, 0x377F0683):
            return []
        if ps != self.page_size:
            return []
        endian = "<" if magic == 0x377F0682 else ">"

        def checksum(data, sums):
            return wal_checksum(data, sums, endian)

        sums = checksum(wal[:24], (0, 0))
        if sums != struct.unpack_from(">II", wal, 24):
            return []
        self.wal_endian, self.wal_salt = endian, (salt1, salt2)
        chain_valid = True
        out, off, n = [], 32, 0
        while off + 24 + ps <= len(wal):
            pg, commit, s1, s2 = struct.unpack_from(">IIII", wal, off)
            if pg == 0:
                break
            sums = checksum(wal[off + 24:off + 24 + ps], checksum(wal[off:off + 8], sums))
            stored = struct.unpack_from(">II", wal, off + 16)
            chain_valid = chain_valid and (s1, s2) == (salt1, salt2) and sums == stored
            # salt and sums are the frame header's own (a stale frame carries an earlier cycle's)
            out.append({"frame": n, "page": pg, "commit": commit, "valid": chain_valid,
                        "data": wal[off + 24:off + 24 + ps], "salt": (s1, s2), "sums": stored})
            off += 24 + ps
            n += 1
        return out

    def _journal(self, j: bytes) -> list:
        """[{page, data}] of a rollback journal: the pages as they were before the transaction. A
        finished journal has a zeroed header; the records behind it are read all the same."""
        out = []
        if len(j) < 512:
            return out
        magic = j[:8]
        sector, ps = struct.unpack_from(">II", j, 20)
        if magic != b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7" or not (512 <= ps <= 65536) or not sector:
            sector, ps = 512, self.page_size
        off = max(sector, 512)
        while off + 4 + ps + 4 <= len(j):
            pg = struct.unpack_from(">I", j, off)[0]
            if not (0 < pg <= max(self.count, 1) + 100000):
                break
            out.append({"page": pg, "data": j[off + 4:off + 4 + ps]})
            off += 4 + ps + 4
        return out

    # -- b-trees

    def _hdr(self, n: int) -> int:
        return 100 if n == 1 else 0

    def _payload(self, pg: bytes, off: int, image=None):
        """(payload bytes or None, rowid, cell end) of a table-leaf cell at `off`."""
        size, p = varint(pg, off)
        rowid, p = varint(pg, p)
        if rowid >= 1 << 63:
            rowid -= 1 << 64
        u = self.usable
        x = u - 35
        if size <= x:
            if p + size > len(pg):
                raise ValueError("cell")
            return pg[p:p + size], rowid, p + size
        m = ((u - 12) * 32 // 255) - 23
        k = m + ((size - m) % (u - 4))
        local = k if k <= x else m
        if p + local + 4 > len(pg):
            raise ValueError("cell")
        chunks, nxt, left = [pg[p:p + local]], struct.unpack_from(">I", pg, p + local)[0], size - local
        hops = 0
        while nxt and left > 0 and hops < 4096:
            op = self.page(nxt, image)
            if len(op) < 4:
                break
            take = min(left, u - 4)
            chunks.append(op[4:4 + take])
            left -= take
            nxt = struct.unpack_from(">I", op, 0)[0]
            hops += 1
        return (b"".join(chunks) if left == 0 else None), rowid, p + local + 4

    def leaf_cells(self, pg: bytes, n: int, image=None) -> list:
        """[(rowid, values)] of the cells a table-leaf page image still points at."""
        h = self._hdr(n)
        if len(pg) < h + 8 or pg[h] != 0x0D:
            return []
        ncells = struct.unpack_from(">H", pg, h + 3)[0]
        out = []
        for i in range(min(ncells, (len(pg) - h - 8) // 2)):
            off = struct.unpack_from(">H", pg, h + 8 + 2 * i)[0]
            try:
                payload, rowid, _ = self._payload(pg, off, image)
                if payload is None:
                    continue
                values, _ = read_record(payload, 0, len(payload), self.enc)
                out.append((rowid, values))
            except (ValueError, IndexError, struct.error):
                continue
        return out

    def free_regions(self, pg: bytes, n: int) -> list:
        """[(start, end, is a freeblock)] of the bytes of a page image no live cell owns: the gap
        between the cell pointers and the cell content, and the freeblocks; a page that is no b-tree
        page, whole."""
        h = self._hdr(n)
        if len(pg) < h + 8:
            return []
        kind = pg[h]
        if kind in (0x02, 0x05, 0x0A):
            return []                   # index and interior pages: their records are not table rows
        if kind != 0x0D:
            return [(h, len(pg), False)] if any(pg[h:]) else []
        first_free, ncells, content = struct.unpack_from(">HHH", pg, h + 1)
        content = content or 65536
        ptr_end = h + 8 + 2 * ncells
        out = []
        if ptr_end < min(content, len(pg)):
            out.append((ptr_end, min(content, len(pg)), False))
        seen, fb = set(), first_free
        while fb and fb not in seen and fb + 4 <= len(pg):
            seen.add(fb)
            nxt, size = struct.unpack_from(">HH", pg, fb)
            if size < 4 or fb + size > len(pg):
                break
            out.append((fb, fb + size, True))
            fb = nxt
        return out

    def table_pages(self, root: int, image=None) -> list:
        """The leaf page numbers of the table b-tree rooted at `root`, in the committed image."""
        leaves, todo, seen = [], [root], set()
        while todo and len(seen) < 100000:
            n = todo.pop()
            if n in seen or n < 1:
                continue
            seen.add(n)
            pg = self.page(n, image)
            h = self._hdr(n)
            if len(pg) < h + 12:
                continue
            if pg[h] == 0x0D:
                leaves.append(n)
            elif pg[h] == 0x05:
                ncells = struct.unpack_from(">H", pg, h + 3)[0]
                pointer_end = h + 12 + 2 * ncells
                if pointer_end > len(pg):
                    continue
                todo.append(struct.unpack_from(">I", pg, h + 8)[0])
                for i in range(ncells):
                    off = struct.unpack_from(">H", pg, h + 12 + 2 * i)[0]
                    if pointer_end <= off and off + 4 <= len(pg):
                        todo.append(struct.unpack_from(">I", pg, off)[0])
        return leaves

    def freelist_pages(self) -> list:
        """Page numbers on the freelist of the committed image (trunks and leaves)."""
        out, trunk, seen = [], struct.unpack_from(">I", self.page(1), 32)[0], set()
        while trunk and trunk not in seen and len(seen) < 100000:
            seen.add(trunk)
            out.append(trunk)
            pg = self.page(trunk)
            if len(pg) < 8:
                break
            nxt, n = struct.unpack_from(">II", pg, 0)
            for i in range(min(n, (len(pg) - 8) // 4)):
                out.append(struct.unpack_from(">I", pg, 8 + 4 * i)[0])
            trunk = nxt
        return out

    def images(self) -> list:
        """[(source, page number, bytes)] of every page image in the file, its WAL and its journal."""
        free = set(self.freelist_pages())
        out = []
        for n in range(1, self.count + 1):
            out.append((f"freelist page {n}" if n in free else f"main page {n}", n, self.page(n, {})))
        for fr in self.frames:
            out.append((f"wal frame {fr['frame']}" + ("" if fr["valid"] else " (stale)"), fr["page"], fr["data"]))
        for jr in self.journal:
            out.append((f"journal page {jr['page']}", jr["page"], jr["data"]))
        return out[:MAX_PAGES]


def _affinity(decl: str) -> str:
    d = (decl or "").upper()
    if "INT" in d:
        return "int"
    if "CHAR" in d or "CLOB" in d or "TEXT" in d:
        return "text"
    if "BLOB" in d or not d:
        return "any"
    if "REAL" in d or "FLOA" in d or "DOUB" in d:
        return "real"
    return "any"


def _fits_table(values: list, cols: list) -> bool:
    """Whether a record's values can be a row of a table with these (name, declared type, pk) columns."""
    if len(values) != len(cols):
        return False
    for v, (_, decl, _) in zip(values, cols):
        a = _affinity(decl)
        if v is None or a == "any":
            continue
        if a == "int" and not isinstance(v, int):
            return False
        if a == "text" and not isinstance(v, str):
            return False
        if a == "real" and not isinstance(v, (int, float)):
            return False
    return True


def _printable(s: str) -> bool:
    return all(c.isprintable() or c in "\r\n\t" for c in s)


# ---- one database: the live view and the recovered rows --------------------------------------------

class Database:
    """A SQLite file with what stands beside it.

      .tables      {table: [row, ...]} of the live (committed) view; a row is a dict of its columns
                   plus `_rowid`, `_table` and `_src` ('live')
      .columns     {table: [(name, declared type, is the rowid alias), ...]}
      .recovered   [row, ...] found in WAL frames, journal pages, freelist pages or unallocated
                   space and not in the live view; `_src` says where, `_table` is None when the
                   record fits more than one table (`_tables` lists them)
      .strings     printable strings of freelist pages and unallocated space
      .error       why the library could not open it, or None
    """

    def __init__(self, data: bytes, wal: bytes = None, journal: bytes = None, name: str = "", carve: bool = True):
        self.name, self.data, self.wal, self.journal_bytes = name, data, wal, journal
        self.tables, self.columns, self.roots, self.sql = {}, {}, {}, {}
        self.recovered, self.strings, self.error, self.pages = [], [], None, None
        self.carve_done = False
        self.truncated = []             # tables read only up to MAX_ROWS, or not read whole
        self._live()
        try:
            self.pages = Pages(data, wal, journal)
        except (ValueError, struct.error, IndexError):
            self.pages = None
        if carve and self.pages is not None and not self.truncated:
            # (with a table not read whole, its unread live rows would pass for deleted ones)
            try:
                self._recover()
            except Exception as e:           # hostile bytes: the live view stays
                self.error = self.error or f"recover: {type(e).__name__}: {e}"

    def _live(self):
        self._open(bool(self.wal))
        if self.wal and not self.tables:
            first = self.error
            self.tables, self.columns, self.roots, self.sql, self.error = {}, {}, {}, {}, None
            self.truncated = []
            self._open(False)               # a WAL the library refuses: the main file alone
            self.error = self.error or (f"opened without its WAL ({first})" if first else None)

    def _open(self, with_wal: bool):
        """The live view through the library, on a temporary copy: read-only and immutable, or with
        the WAL beside it (a copy too) so the committed frames count."""
        with tempfile.TemporaryDirectory(prefix="sqlite_artifacts_") as td:
            p = Path(td) / "copy.db"
            p.write_bytes(self.data)
            if with_wal:
                (Path(td) / "copy.db-wal").write_bytes(self.wal)
                uri = f"file:{p}?mode=rw"
            else:
                uri = f"file:{p}?mode=ro&immutable=1"
            con = None
            try:
                con = sqlite3.connect(uri, uri=True, timeout=1)
                stop = time.monotonic() + OPEN_SECONDS      # hostile bytes must not hold a clock
                con.set_progress_handler(lambda: 1 if time.monotonic() > stop else 0, 20000)
                con.text_factory = lambda b: b.decode("utf-8", "replace")
                master = con.execute("SELECT name, rootpage, sql FROM sqlite_master WHERE type='table'").fetchall()
                for name, root, sql in master:
                    self.roots[name], self.sql[name] = root, sql or ""
                    try:
                        info = con.execute(f'PRAGMA table_info("{name}")').fetchall()
                        ipk = [c for c in info if c[5]]
                        alias = ipk[0][1] if len(ipk) == 1 and (ipk[0][2] or "").upper() == "INTEGER" \
                            and "WITHOUT ROWID" not in (sql or "").upper() else None
                        self.columns[name] = [(c[1], c[2] or "", c[1] == alias) for c in info]
                        names = [c[1] for c in info]
                        try:
                            cur = con.execute(f'SELECT rowid, * FROM "{name}" LIMIT {MAX_ROWS}')
                            rows = [dict(zip(names, r[1:]), _rowid=r[0], _table=name, _src="live") for r in cur]
                        except sqlite3.Error:
                            cur = con.execute(f'SELECT * FROM "{name}" LIMIT {MAX_ROWS}')
                            rows = [dict(zip(names, r), _rowid=None, _table=name, _src="live") for r in cur]
                        self.tables[name] = rows
                        if len(rows) >= MAX_ROWS:
                            self.truncated.append(name)
                    except sqlite3.Error as e:
                        self.tables.setdefault(name, [])
                        self.truncated.append(name)
                        self.error = self.error or f"{name}: {e}"
            except sqlite3.Error as e:
                self.error = str(e)
                self.truncated.append("*")
            finally:
                if con is not None:
                    con.close()

    def _row(self, table: str, rowid, values: list, src: str) -> dict:
        row = {"_rowid": rowid, "_table": table, "_src": src}
        for (name, _, alias), v in zip(self.columns[table], values):
            row[name] = rowid if alias and v is None else v
        return row

    def _table_for(self, values: list, hint: str = None) -> list:
        """The tables a record can be a row of, the page's own table first."""
        fit = [t for t, cols in self.columns.items() if not t.startswith("sqlite_") and _fits_table(values, cols)]
        if hint in fit:
            return [hint]
        return fit

    def _recover(self):
        pg = self.pages
        t0 = time.monotonic()
        owner = {n: "sqlite_master" for n in pg.table_pages(1)}
        for table, root in self.roots.items():
            if isinstance(root, int) and root > 1 and table in self.columns:
                for n in pg.table_pages(root):
                    owner.setdefault(n, table)
        data_cols = {t: [c[0] for c in cols if not c[2]] for t, cols in self.columns.items()}
        live, known = {}, {}            # {table: {(rowid, values)}} and {table: {values}} (values without the rowid alias)
        for table, rows in self.tables.items():
            for r in rows:
                vals = tuple(repr(r.get(c)) for c in data_cols.get(table, []))
                live.setdefault(table, set()).add((r["_rowid"], vals))
                known.setdefault(table, set()).add(vals)
        widths = {len(c) for t, c in self.columns.items() if not t.startswith("sqlite_")}
        seen, strings = set(), []

        def keep(values, rowid, hint, src):
            tabs = self._table_for(values, hint)
            if not tabs:
                return False
            if len(tabs) == 1:
                row = self._row(tabs[0], rowid, values, src)
                vals = tuple(repr(row.get(c)) for c in data_cols[tabs[0]])
                if (row["_rowid"], vals) in live.get(tabs[0], ()):
                    return True
                if rowid is None and vals in known.get(tabs[0], ()):
                    return True                 # the carved copy of a row already known with its rowid
                sig = (tabs[0], row["_rowid"], vals)
                known.setdefault(tabs[0], set()).add(vals)
            else:
                row = {"_rowid": rowid, "_table": None, "_tables": tabs, "_src": src, "_values": values}
                sig = (None, rowid, tuple(repr(v) for v in values))
            if sig in seen:
                return True
            seen.add(sig)
            self.recovered.append(row)
            return True

        images = pg.images()
        for src, n, image in images:            # first the cells page images still point at: they carry rowids
            if owner.get(n) != "sqlite_master":
                for rowid, values in pg.leaf_cells(image, n):
                    keep(values, rowid, owner.get(n), src)
        self.carve_done = True
        for src, n, image in images:
            if owner.get(n) == "sqlite_master":
                continue
            if time.monotonic() - t0 > CARVE_SECONDS:
                self.carve_done = False
                break
            for start, end, freeblock in pg.free_regions(image, n):
                for m in re.finditer(rb"[\x20-\x7e]{5,}", image[start:end]):
                    strings.append(m.group().decode("ascii"))
                off = start
                if freeblock:
                    got = self._carve_freeblock(image, start, end, owner.get(n))
                    if got is not None:
                        table, values, nxt = got
                        if keep(values, None, table, f"{src} (freeblock at {start}, cell header rebuilt)"):
                            off = nxt
                while off < end - 2:
                    got = self._carve_at(image, off, end, widths) if image[off] else None
                    if got is None:
                        off += 1
                        continue
                    values, rowid, nxt = got
                    if keep(values, rowid, owner.get(n), f"{src} (unallocated, offset {off})"):
                        off = nxt
                    else:
                        off += 1
        self.strings = list(dict.fromkeys(strings))[:2000]

    def _carve_at(self, image: bytes, off: int, end: int, widths: set):
        """(values, rowid or None, next offset) of a deleted row at `off`: a whole cell (payload
        length, rowid, record) or the record alone (the first four bytes of a freed cell are
        overwritten by the freeblock header)."""
        enc = self.pages.enc
        try:
            size, p = varint(image, off)
            rowid, p2 = varint(image, p)
            if 2 < size <= end - p2:
                values, nxt = read_record(image, p2, p2 + size, enc, strict=True)
                if nxt == p2 + size and len(values) in widths and self._sane(values):
                    return values, rowid, nxt
        except (ValueError, IndexError):
            pass
        try:
            values, nxt = read_record(image, off, end, enc, strict=True)
            if len(values) in widths and self._sane(values):
                return values, None, nxt
        except (ValueError, IndexError):
            pass
        return None

    def _carve_freeblock(self, image: bytes, fb: int, end: int, hint: str = None):
        """(table, values, next offset) of the freed cell a freeblock begins with. Freeing a cell
        overwrites its first four bytes (payload length, rowid, record header length and, when all
        three were one byte, the first serial type) with the freeblock header; the rest of the
        record header is intact. So for each table: its column count gives the header back, and a
        lost first serial type is the length the freeblock's size leaves for the first column."""
        enc = self.pages.enc
        tables = [t for t in self.columns if not t.startswith("sqlite_")]
        tables.sort(key=lambda t: t != hint)
        size = end - fb
        for table in tables:
            cols = self.columns[table]
            k = len(cols)
            for lost in (0, 1):
                try:
                    p, types = fb + 4, []
                    for _ in range(k - lost):
                        t, p = varint(image, p)
                        types.append(t)
                    lens = [_serial_size(t) for t in types]
                    body = p
                    if lost:
                        hs = 1 + 1 + (p - fb - 4)
                        first = (size - 2) - hs - sum(lens)
                        aff = _affinity(cols[0][1])
                        if first < 0 or body + first + sum(lens) > end:
                            continue
                        raw = image[body:body + first]
                        if cols[0][2] or (aff == "int" and first == 0):
                            if first:
                                continue
                            v0 = None
                        elif aff == "int":
                            if first not in (1, 2, 3, 4, 6, 8):
                                continue
                            v0 = int.from_bytes(raw, "big", signed=True)
                        elif aff == "text":
                            v0 = raw.decode(enc)
                        else:
                            continue
                        values, q = [v0], body + first
                    else:
                        values, q = [], body
                    if q + sum(lens) > end:
                        continue
                    for t, n in zip(types, lens):
                        values.append(_serial_value(t, image[q:q + n], enc, True))
                        q += n
                    if _fits_table(values, cols) and self._sane(values):
                        return table, values, q
                except (ValueError, IndexError, UnicodeDecodeError, struct.error):
                    continue
        return None

    @staticmethod
    def _sane(values: list) -> bool:
        """A carved record is kept only with some text in it, all of it printable."""
        texts = [v for v in values if isinstance(v, str)]
        return bool(texts) and any(len(t) >= 3 for t in texts) and all(_printable(t) for t in texts) \
            and not all(v is None or v == "" for v in values)

    def rows(self, table: str, recovered: bool = True) -> list:
        out = list(self.tables.get(table, []))
        if recovered:
            out += [r for r in self.recovered if r["_table"] == table]
        return out


# ---- encrypted values --------------------------------------------------------------------------------

DPAPI_MAGIC = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")


def protection(blob) -> str:
    """How a stored value is protected: '' (plain or empty), 'dpapi', 'v10', 'v11', 'v20'."""
    if not isinstance(blob, (bytes, bytearray)) or not blob:
        return ""
    if blob.startswith(DPAPI_MAGIC):
        return "dpapi"
    if blob[:3] in (b"v10", b"v11", b"v20"):
        return blob[:3].decode()
    return "blob"


def local_state_key(files: dict):
    """(key bytes, where) from a Chromium `Local State` in the delivery whose os_crypt.encrypted_key
    is a raw 32-byte key; None when there is none or it is DPAPI-wrapped (then the key is not in
    the delivery: it needs the user's master key)."""
    for name, data in files.items():
        if len(data) > 2_000_000 or not data.lstrip()[:1] == b"{":
            continue
        try:
            doc = json.loads(data)
            raw = base64.b64decode(doc["os_crypt"]["encrypted_key"])
        except (ValueError, KeyError, TypeError):
            continue
        if raw.startswith(b"DPAPI") or raw.startswith(DPAPI_MAGIC):
            continue
        if len(raw) == 32:
            return raw, name
    return None


def _aes():
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return Cipher, algorithms, modes, AESGCM
    except Exception:
        return None


def decrypt_value(blob: bytes, files: dict = None, host: str = None):
    """(text, how) of a Chromium v10/v11 value when its key is in the delivery or is Chromium's fixed
    Linux key ('peanuts', or the empty password of a machine with no keyring); None otherwise. The
    result is accepted only when the cipher itself checks it (the GCM tag; valid padding and
    printable UTF-8 for CBC). Callers answer it unsure."""
    kind = protection(blob)
    lib = _aes()
    if kind not in ("v10", "v11") or lib is None:
        return None
    Cipher, algorithms, modes, AESGCM = lib
    body = bytes(blob[3:])
    found = local_state_key(files or {})
    if found and len(body) > 28:
        try:
            plain = AESGCM(found[0]).decrypt(body[:12], body[12:], None)
            return _strip_host(plain, host).decode("utf-8"), f"{kind}_gcm_local_state_key"
        except Exception:
            pass
    if len(body) % 16 == 0 and body:
        for password, how in ((b"peanuts", f"{kind}_cbc_linux_peanuts"), (b"", f"{kind}_cbc_linux_empty")):
            key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1, 16)
            try:
                d = Cipher(algorithms.AES(key), modes.CBC(b" " * 16)).decryptor()
                plain = d.update(body) + d.finalize()
                pad = plain[-1]
                if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
                    continue
                text = _strip_host(plain[:-pad], host).decode("utf-8")
                if text and _printable(text):
                    return text, how
            except Exception:
                continue
    return None


def _strip_host(plain: bytes, host):
    """Chrome 130+ puts SHA-256(host_key) before a cookie's value."""
    if host and len(plain) >= 32 and plain[:32] == hashlib.sha256(host.encode()).digest():
        return plain[32:]
    return plain


# ---- the decoder pass over URL and title cells --------------------------------------------------------

_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")


def _text_of(raw: bytes):
    """(text, extra step) when the bytes are printable text (UTF-8, or UTF-16LE as PowerShell
    -EncodedCommand writes it); None otherwise."""
    if len(raw) >= 8 and len(raw) % 2 == 0 and not any(raw[1::2]) and all(raw[0::2]):
        try:
            t = raw.decode("utf-16-le")
            return (t, "utf16le") if _printable(t) else None
        except UnicodeDecodeError:
            return None
    try:
        t = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return (t, "") if len(t) >= 6 and _printable(t) else None


def _uu_line(line: str):
    """The bytes of one uuencoded line, or None: the first character is the length and the line is
    exactly as long as that length needs."""
    if len(line) < 5 or not all(32 <= ord(c) <= 96 for c in line):
        return None
    n = (ord(line[0]) - 32) & 63
    if n < 1 or len(line) != 1 + ((n + 2) // 3) * 4:
        return None
    try:
        return binascii.a2b_uu(line.encode("ascii"))[:n]
    except (binascii.Error, ValueError):
        return None


def _uudecode(text: str):
    lines = [ln for ln in text.replace("\r", "").split("\n") if ln.strip()]
    if lines and lines[0].startswith("begin "):
        lines = lines[1:]
    lines = [ln for ln in lines if ln not in ("end", "`", " ")]
    if not lines:
        return None
    parts = [_uu_line(ln) for ln in lines]
    if any(p is None for p in parts):
        return None
    return b"".join(parts)


def decodings(text, depth: int = 0, via: str = "") -> list:
    """[(chain, decoded text)] hidden in one cell: 'url', 'base64', 'hex', 'uuencode' and their
    nestings ('url>base64>utf16le'), outermost first. Nothing for a cell that holds no such text."""
    out = []
    if not isinstance(text, str) or len(text) < 8 or depth > 3:
        return out

    def add(step, decoded):
        chain = f"{via}>{step}" if via else step
        if decoded and decoded != text and not any(d == decoded for _, d in out):
            out.append((chain, decoded))
            out.extend(x for x in decodings(decoded, depth + 1, chain) if not any(d == x[1] for _, d in out))

    if re.search(r"%[0-9A-Fa-f]{2}", text):
        dec = unquote(text)
        if dec != text and _printable(dec):
            add("url", dec)
    raw = _uudecode(text)
    if raw is None:
        for tok in re.split(r"[?&=#/]", text):
            if len(tok) >= 9 and (r2 := _uu_line(tok)) is not None and len(r2) >= 6 and _text_of(r2):
                t = _text_of(r2)
                add("uuencode" + (">" + t[1] if t[1] else ""), t[0])
    elif len(raw) >= 6 and (t := _text_of(raw)):
        add("uuencode" + (">" + t[1] if t[1] else ""), t[0])
    for m in _B64.finditer(text):
        tok = m.group().rstrip("=")
        if _HEX.fullmatch(tok) or len(tok) % 4 == 1:
            continue
        if not (re.search(r"[A-Z]", tok) and re.search(r"[a-z0-9]", tok)):
            continue                                    # one case only: a word, not base64
        try:
            raw = base64.b64decode(tok.replace("-", "+").replace("_", "/") + "=" * (-len(tok) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        t = _text_of(raw)
        if t:
            add("base64" + (">" + t[1] if t[1] else ""), t[0])
    for m in _HEX.finditer(text):
        if m.start() and text[m.start() - 1].isalnum() or (m.end() < len(text) and text[m.end()].isalnum()):
            continue
        t = _text_of(bytes.fromhex(m.group()))
        if t:
            add("hex" + (">" + t[1] if t[1] else ""), t[0])
    return out


# ---- LevelDB without a library -------------------------------------------------------------------------

def snappy_decompress(data: bytes) -> bytes:
    """Raw snappy (the block format LevelDB uses)."""
    n, p = _uvarint(data, 0)
    if n > 0xFFFFFFFF:
        raise ValueError("snappy length")
    out = bytearray()
    while p < len(data):
        tag = data[p]
        p += 1
        kind = tag & 3
        if kind == 0:
            ln = tag >> 2
            if ln >= 60:
                nb = ln - 59
                if p + nb > len(data):
                    raise ValueError("truncated snappy literal length")
                ln = int.from_bytes(data[p:p + nb], "little")
                p += nb
            ln += 1
            if p + ln > len(data) or len(out) + ln > n:
                raise ValueError("snappy literal bounds")
            out += data[p:p + ln]
            p += ln
            continue
        if kind == 1:
            ln = ((tag >> 2) & 7) + 4
            if p >= len(data):
                raise ValueError("truncated snappy offset")
            off = ((tag >> 5) << 8) | data[p]
            p += 1
        elif kind == 2:
            ln = (tag >> 2) + 1
            if p + 2 > len(data):
                raise ValueError("truncated snappy offset")
            off = int.from_bytes(data[p:p + 2], "little")
            p += 2
        else:
            ln = (tag >> 2) + 1
            if p + 4 > len(data):
                raise ValueError("truncated snappy offset")
            off = int.from_bytes(data[p:p + 4], "little")
            p += 4
        if off == 0 or off > len(out) or len(out) + ln > n:
            raise ValueError("snappy offset")
        for _ in range(ln):
            out.append(out[-off])
    if len(out) != n:
        raise ValueError("snappy length")
    return bytes(out)


def _uvarint(buf, p):
    v, shift = 0, 0
    while True:
        if p < 0 or p >= len(buf):
            raise ValueError("truncated varint")
        b = buf[p]
        if shift == 63 and b > 1:
            raise ValueError("varint overflow")
        p += 1
        v |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return v, p
        if shift > 63:
            raise ValueError("varint")


def leveldb_log(data: bytes) -> list:
    """[{seq, state: 'live'|'deleted', key, value}] of a LevelDB write-ahead `.log` (32 KiB blocks of
    records; each full record is a write batch). A delete is listed with value None."""
    out, block, payload, off = [], 32768, b"", 0
    while off + 7 <= len(data):
        left = block - off % block
        if left < 7:
            off += left
            continue
        ln, typ = struct.unpack_from("<HB", data, off + 4)
        body = data[off + 7:off + 7 + ln]
        off += 7 + ln
        if typ == 0 and ln == 0:
            off += left - 7
            continue
        if typ in (1, 2):
            payload = body
        else:
            payload += body
        if typ in (1, 4) and len(payload) >= 12:
            try:
                seq, count = struct.unpack_from("<QI", payload, 0)
                p = 12
                for i in range(count):
                    tag = payload[p]
                    p += 1
                    kl, p = _uvarint(payload, p)
                    key = payload[p:p + kl]
                    p += kl
                    if tag == 1:
                        vl, p = _uvarint(payload, p)
                        out.append({"seq": seq + i, "state": "live", "key": key, "value": payload[p:p + vl]})
                        p += vl
                    else:
                        out.append({"seq": seq + i, "state": "deleted", "key": key, "value": None})
            except (IndexError, ValueError, struct.error):
                pass
            payload = b""
    return out


def _ldb_block(data: bytes, off: int, size: int) -> bytes:
    raw = data[off:off + size]
    if len(raw) != size or off + size >= len(data):
        raise ValueError("block")
    return snappy_decompress(raw) if data[off + size] == 1 else raw


def _ldb_entries(block: bytes) -> list:
    if len(block) < 4:
        return []
    restarts = struct.unpack_from("<I", block, len(block) - 4)[0]
    end = len(block) - 4 - 4 * restarts
    out, p, key = [], 0, b""
    while 0 <= p < end:
        shared, p = _uvarint(block, p)
        non, p = _uvarint(block, p)
        vl, p = _uvarint(block, p)
        key = key[:shared] + block[p:p + non]
        p += non
        out.append((key, block[p:p + vl]))
        p += vl
    return out


def leveldb_table(data: bytes) -> list:
    """[{seq, state, key, value}] of a LevelDB table file (`.ldb`, `.sst`); ValueError when the
    footer or a block does not parse."""
    if len(data) < 48 or data[-8:] != struct.pack("<Q", 0xDB4775248B80FB57):
        raise ValueError("not a LevelDB table")
    foot = data[-48:]
    _, p = _uvarint(foot, 0)
    _, p = _uvarint(foot, p)
    ioff, p = _uvarint(foot, p)
    isize, p = _uvarint(foot, p)
    out = []
    for _, handle in _ldb_entries(_ldb_block(data, ioff, isize)):
        boff, q = _uvarint(handle, 0)
        bsize, q = _uvarint(handle, q)
        for ikey, value in _ldb_entries(_ldb_block(data, boff, bsize)):
            if len(ikey) < 8:
                continue
            trailer = int.from_bytes(ikey[-8:], "little")
            live = trailer & 0xFF == 1
            out.append({"seq": trailer >> 8, "state": "live" if live else "deleted", "key": ikey[:-8],
                        "value": value if live else None})
    return out


def _ls_text(raw):
    """A Chromium Local Storage string: a format byte (1 Latin-1, 0 UTF-16LE), then the text."""
    if raw is None:
        return None
    if raw[:1] == b"\x01":
        return raw[1:].decode("latin-1")
    if raw[:1] == b"\x00" and len(raw) % 2 == 1:
        try:
            return raw[1:].decode("utf-16-le")
        except UnicodeDecodeError:
            pass
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def leveldb_records(data: bytes, name: str = "") -> list:
    """Records of one LevelDB file with the Local Storage layout read where it applies:
    [{seq, state, key, value, origin, file}] (key and value as text). A file that parses as neither
    a log nor a table gives its printable strings as records of state 'carved'."""
    try:
        recs = leveldb_table(data)
    except (ValueError, IndexError, struct.error):
        recs = leveldb_log(data)
    out = []
    for r in recs:
        key, origin = r["key"], None
        if key[:1] == b"_" and b"\x00" in key:
            o, _, k = key[1:].partition(b"\x00")
            origin, ktext = o.decode("utf-8", "replace"), _ls_text(k)
            value = _ls_text(r["value"])
        else:
            ktext = key.decode("utf-8", "replace")
            value = None if r["value"] is None else _ls_text(r["value"]) if r["value"][:1] in (b"\x00", b"\x01") \
                else r["value"].decode("utf-8", "replace")
        out.append({"seq": r["seq"], "state": r["state"], "key": ktext, "value": value, "origin": origin, "file": name})
    if not out:
        for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
            out.append({"seq": None, "state": "carved", "key": None, "value": m.group().decode("ascii"),
                        "origin": None, "file": name})
    return out


def is_leveldb(name: str, data: bytes) -> bool:
    tail = name.split(ARROW)[-1].lower()
    if data[-8:] == struct.pack("<Q", 0xDB4775248B80FB57) and len(data) >= 48:
        return True
    return bool(re.search(r"(?:^|/)\d{6}\.log$", tail)) and len(data) >= 7


# ---- Chrome extensions ---------------------------------------------------------------------------------

def _proto(buf: bytes) -> list:
    """[(field number, wire type, value)] of a protobuf message; ValueError for bytes that are none."""
    out, p = [], 0
    while p < len(buf):
        tag, p = _uvarint(buf, p)
        wire = tag & 7
        if wire == 0:
            v, p = _uvarint(buf, p)
        elif wire == 2:
            ln, p = _uvarint(buf, p)
            v = buf[p:p + ln]
            if len(v) != ln:
                raise ValueError("length")
            p += ln
        elif wire == 1:
            v, p = buf[p:p + 8], p + 8
        elif wire == 5:
            v, p = buf[p:p + 4], p + 4
        else:
            raise ValueError("wire type")
        out.append((tag >> 3, wire, v))
    return out


def id_from_bytes(raw16: bytes) -> str:
    return "".join(chr(ord("a") + int(c, 16)) for c in raw16[:16].hex())


def id_from_public_key(der: bytes) -> str:
    """A Chrome extension id: the first 16 bytes of SHA-256 of the public key (DER), as a to p."""
    return id_from_bytes(hashlib.sha256(der).digest())


def crx(data: bytes) -> dict:
    """A .crx file: {version, zip (the bytes behind the header), ids: [(how, id), ...]}; ValueError
    when it is not one. CRX3 states its id in the signed header (`crx_id`) and carries the public
    keys it is signed with; CRX2 carries one key."""
    if data[:4] != b"Cr24" or len(data) < 16:
        raise ValueError("not a CRX")
    version = struct.unpack_from("<I", data, 4)[0]
    ids = []
    try:
        if version == 2:
            klen, slen = struct.unpack_from("<II", data, 8)
            ids.append(("crx2_public_key", id_from_public_key(data[16:16 + klen])))
            body = data[16 + klen + slen:]
        elif version == 3:
            hlen = struct.unpack_from("<I", data, 8)[0]
            body = data[12 + hlen:]
            for no, wire, v in _proto(data[12:12 + hlen]):
                if wire != 2:
                    continue
                if no == 10000:
                    for n2, w2, v2 in _proto(v):
                        if n2 == 1 and w2 == 2 and len(v2) == 16:
                            ids.insert(0, ("crx_id", id_from_bytes(v2)))
                elif no in (2, 3):
                    for n2, w2, v2 in _proto(v):
                        if n2 == 1 and w2 == 2:
                            ids.append(("public_key", id_from_public_key(v2)))
        else:
            raise ValueError(f"CRX version {version}")
    except struct.error as e:
        raise ValueError(str(e))
    return {"version": version, "zip": body, "ids": ids}


_EXT_ID = re.compile(r"(?<![a-z])[a-p]{32}(?![a-z])")


def _manifest(data: bytes):
    if len(data) > 1_000_000:
        return None
    try:
        doc = json.loads(data.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return None
    return doc if isinstance(doc, dict) and isinstance(doc.get("manifest_version"), int) else None


def _as_list(v) -> list:
    if isinstance(v, str):
        return [v]
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def extension(manifest: dict, where: str = "", members: dict = None, ids=()) -> dict:
    """One extension's facts from its manifest (and its folder's other files, for a localised name)."""
    members = members or {}
    bg = manifest.get("background") if isinstance(manifest.get("background"), dict) else {}
    perms = _as_list(manifest.get("permissions"))
    hosts = _as_list(manifest.get("host_permissions"))
    is_host = lambda p: "://" in p or p == "<all_urls>"         # noqa: E731
    name = manifest.get("name")
    if isinstance(name, str) and (m := re.fullmatch(r"__MSG_(\w+)__", name)):
        loc = manifest.get("default_locale") or "en"
        try:
            msgs = json.loads(members.get(f"_locales/{loc}/messages.json", b"{}").decode("utf-8-sig"))
            hit = next((v for k, v in msgs.items() if k.lower() == m.group(1).lower()), None)
            name = hit.get("message", name) if isinstance(hit, dict) else name
        except (ValueError, UnicodeDecodeError, AttributeError):
            pass
    all_ids = list(ids)
    if isinstance(manifest.get("key"), str):
        try:
            all_ids.append(("manifest_key", id_from_public_key(base64.b64decode(manifest["key"]))))
        except (binascii.Error, ValueError):
            pass
    for m in _EXT_ID.finditer(where):
        all_ids.append(("folder_name", m.group()))
    cs = manifest.get("content_scripts") if isinstance(manifest.get("content_scripts"), list) else []
    return {
        "where": where, "manifest_version": manifest.get("manifest_version"), "name": name,
        "version": manifest.get("version"), "description": manifest.get("description"),
        "permissions": perms, "host_permissions": hosts,
        "api_permissions": [p for p in perms if not is_host(p)],
        "host_patterns": hosts + [p for p in perms if is_host(p)],
        "optional_permissions": _as_list(manifest.get("optional_permissions")),
        "service_worker": bg.get("service_worker") if isinstance(bg.get("service_worker"), str) else None,
        "background_scripts": _as_list(bg.get("scripts")),
        "background_page": bg.get("page") if isinstance(bg.get("page"), str) else None,
        "content_scripts": [j for c in cs if isinstance(c, dict) for j in _as_list(c.get("js"))],
        "content_matches": [j for c in cs if isinstance(c, dict) for j in _as_list(c.get("matches"))],
        "update_url": manifest.get("update_url"), "ids": list(dict.fromkeys(all_ids)),
    }


def extensions(files: dict) -> list:
    """Every extension in the delivery: unpacked folders (a manifest.json with manifest_version),
    .crx files, and the manifest of a zip the runner already unpacked."""
    out = []
    for key, data in files.items():
        tail = key.split(ARROW)[-1]
        if data[:4] == b"Cr24":
            try:
                c = crx(data)
                zf = zipfile.ZipFile(io.BytesIO(c["zip"]))
                members = {n: zf.read(n) for n in zf.namelist() if not n.endswith("/") and zf.getinfo(n).file_size < 2_000_000}
                man = _manifest(members.get("manifest.json", b""))
                if man is not None:
                    out.append(extension(man, key, members, c["ids"]))
                    out[-1]["crx_version"] = c["version"]
            except (ValueError, zipfile.BadZipFile, KeyError, IndexError):
                pass
            continue
        if Path(tail).name != "manifest.json":
            continue
        man = _manifest(data)
        if man is None:
            continue
        folder = key[:-len("manifest.json")]
        members = {k[len(folder):]: v for k, v in files.items() if k.startswith(folder) and k != key}
        out.append(extension(man, key, members))
    # the same extension seen twice (the folder and the outer archive's view of it) is one
    uniq, seen = [], set()
    for e in out:
        sig = json.dumps({k: v for k, v in e.items() if k not in ("where", "ids")}, sort_keys=True, default=str)
        if sig not in seen:
            seen.add(sig)
            uniq.append(e)
    return uniq


# ---- Fossil ------------------------------------------------------------------------------------------

_FDIGITS = {c: i for i, c in enumerate("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~")}


def fossil_delta(src: bytes, delta: bytes) -> bytes:
    """Apply a Fossil delta; ValueError when it is malformed."""
    p = 0

    def num():
        nonlocal p
        v, start = 0, p
        while p < len(delta) and chr(delta[p]) in _FDIGITS:
            v = v * 64 + _FDIGITS[chr(delta[p])]
            p += 1
        if p == start:
            raise ValueError("delta number")
        return v

    total = num()
    if delta[p:p + 1] != b"\n":
        raise ValueError("delta size")
    p += 1
    out = bytearray()
    while p < len(delta):
        n = num()
        op = delta[p:p + 1]
        p += 1
        if op == b"@":
            off = num()
            if delta[p:p + 1] != b",":
                raise ValueError("delta copy")
            p += 1
            out += src[off:off + n]
        elif op == b":":
            out += delta[p:p + n]
            p += n
        elif op == b";":
            if len(out) != total:
                raise ValueError("delta length")
            return bytes(out)
        else:
            raise ValueError("delta op")
    raise ValueError("delta unterminated")


def fossil_blobs(db: Database) -> dict:
    """{rid: content bytes} of a Fossil repository: zlib behind a 4-byte size, deltas applied."""
    raw = {}
    for r in db.rows("blob", recovered=False):
        c = r.get("content")
        if isinstance(c, bytes) and len(c) > 4:
            try:
                raw[r.get("rid")] = zlib.decompress(c[4:])
            except zlib.error:
                raw[r.get("rid")] = c
    src = {r.get("rid"): r.get("srcid") for r in db.rows("delta", recovered=False)}
    done = {}

    def full(rid, depth=0):
        if rid in done:
            return done[rid]
        if rid not in raw or depth > 200:
            return None
        if rid in src:
            base = full(src[rid], depth + 1)
            try:
                done[rid] = fossil_delta(base, raw[rid]) if base is not None else None
            except ValueError:
                done[rid] = None
        else:
            done[rid] = raw[rid]
        return done[rid]

    return {rid: c for rid in raw if (c := full(rid)) is not None}


_FLAGLIKE = flagfmt.BYTES
_MANIFEST = re.compile(rb"\A(?:[A-Z] [^\n]*\n)+\Z")


def fossil_notable(blobs: dict, limit: int = 8) -> dict:
    """What stands out among a Fossil repository's artifacts: {'files': n (artifacts that are not
    manifests or control cards), 'flags': [(rid, text)] (contents of the word{...} form),
    'odd': [(rid, size, head)] (file contents whose size no other file content has, when most
    sizes repeat)}. For the triage and for a flag question; a pattern picks them, so never plain."""
    files = {rid: c for rid, c in blobs.items() if not _MANIFEST.match(c)}
    flags = []
    for rid, c in files.items():
        for m in _FLAGLIKE.finditer(c[:65536]):
            text = m.group().decode("utf-8", "replace")
            if re.match(r"(?i)(?:flag|ctf|htb|key|secret)\{", text) or len(flags) < limit:
                flags.append((rid, text))
    flags.sort(key=lambda x: not re.match(r"(?i)flag\{", x[1]))
    sizes = Counter(len(c) for c in files.values())
    repeated = sum(n for n in sizes.values() if n > 1)
    odd = [(rid, len(c), c[:80].decode("utf-8", "replace")) for rid, c in files.items() if sizes[len(c)] == 1] \
        if files and repeated >= 0.8 * len(files) else []
    return {"files": len(files), "flags": flags[:limit], "odd": odd[:limit]}


# ---- known schemas: tables to records ------------------------------------------------------------------

def schema_kind(db: Database) -> str:
    """The artifact a database is, by its tables and columns."""
    t = {name: {c[0] for c in cols} for name, cols in db.columns.items()}
    has = lambda name, *cols: name in t and all(c in t[name] for c in cols)       # noqa: E731
    if has("urls", "url", "visit_count") and "visits" in t:
        return "chromium_history"
    if has("logins", "username_value", "origin_url"):
        return "chromium_login_data"
    if has("cookies", "host_key", "name"):
        return "chromium_cookies"
    if has("autofill", "name", "value") or has("keywords", "short_name", "keyword"):
        return "chromium_web_data"
    if has("moz_places", "url"):
        return "firefox_places"
    if has("moz_cookies", "host", "name"):
        return "firefox_cookies"
    if has("moz_formhistory", "fieldname", "value"):
        return "firefox_formhistory"
    if has("webappsstore2", "key", "value"):
        return "firefox_webappsstore"
    if has("history_items", "url") and has("history_visits", "visit_time"):
        return "safari_history"
    if has("LSQuarantineEvent", "LSQuarantineTimeStamp"):
        return "quarantine_events"
    if has("message", "text", "is_from_me") and "handle" in t:
        return "ios_sms"
    if has("messages", "key_remote_jid", "data") or (has("message", "text_data") and "jid" in t):
        return "whatsapp_msgstore"
    if has("blob", "rid", "content") and "delta" in t and ("rcvfrom" in t or "event" in t):
        return "fossil_repository"
    if has("downloads", "target_path") or has("downloads", "url"):
        return "chromium_history"
    return "sqlite"


def _rec(kind, row, f, t=None, art="", shape=""):
    return {"kind": kind, "src": row.get("_src", "live"), "table": row.get("_table"), "rowid": row.get("_rowid"),
            "f": f, "t": t or {}, "art": art, "shape": shape}


def _by(rows, col):
    """{value of col: row}, live rows winning over recovered ones."""
    out = {}
    for r in rows:
        k = r.get(col)
        if k is not None and (k not in out or (out[k]["_src"] != "live" and r["_src"] == "live")):
            out[k] = r
    return out


def _secret(row, col, files, host=None):
    """(value, state) of a possibly encrypted cell: ('text', 'plain' | how it was decrypted) or
    (None, 'dpapi' | 'v10' | ... ) when the key is not in the delivery."""
    v = row.get(col)
    if isinstance(v, str):
        return (v, "plain") if v else (None, "")
    kind = protection(v)
    if kind in ("v10", "v11"):
        got = decrypt_value(v, files, host)
        if got:
            return got
    if kind == "blob":
        try:
            t = bytes(v).decode("utf-8")
            if t and _printable(t):
                return t, "plain"
        except UnicodeDecodeError:
            pass
    return None, kind


def records(db: Database, files: dict = None, art: str = "") -> list:
    """The database as records of the kinds url, visit, download, search, login, cookie, autofill,
    bookmark, message, storage, fossil_config, fossil_event, fossil_user: {kind, src ('live' or
    where it was recovered), f: {field: value}, t: {field: (raw, datetime)}, art, shape}."""
    files = files or {}
    kind = schema_kind(db)
    out = []
    R = db.rows

    def add(k, row, f, t=None):
        out.append(_rec(k, row, f, t, art, kind))

    if kind == "chromium_history":
        urls = _by(R("urls"), "id")
        live_visits = {}
        for v in db.rows("visits", recovered=False):
            live_visits[v.get("url")] = live_visits.get(v.get("url"), 0) + 1
        for u in R("urls"):
            add("url", u, {"url": u.get("url"), "title": u.get("title"), "visit_count": u.get("visit_count"),
                           "typed_count": u.get("typed_count"),
                           "visit_rows": live_visits.get(u.get("id"), 0) if "visits" in db.tables else None},
                {"last_visit": stamp(u.get("last_visit_time"), "webkit")})
        for v in R("visits"):
            u = urls.get(v.get("url"), {})
            add("visit", v, {"url": u.get("url"), "title": u.get("title"), "transition": v.get("transition")},
                {"time": stamp(v.get("visit_time"), "webkit")})
        chains = {}
        for c in sorted(R("downloads_url_chains"), key=lambda r: (r.get("chain_index") or 0)):
            if isinstance(c.get("url"), str) and c["url"] not in chains.setdefault(c.get("id"), []):
                chains[c.get("id")].append(c["url"])
        for d in R("downloads"):
            chain = chains.get(d.get("id"), []) or ([d["url"]] if isinstance(d.get("url"), str) and d.get("url") else [])
            h = d.get("hash")
            add("download", d, {"url_chain": chain, "tab_url": d.get("tab_url"), "referrer": d.get("referrer"),
                                "tab_referrer_url": d.get("tab_referrer_url"), "site_url": d.get("site_url"),
                                "path": d.get("target_path") or d.get("current_path") or d.get("full_path"),
                                "current_path": d.get("current_path"), "size": d.get("total_bytes"),
                                "received": d.get("received_bytes"), "mime": d.get("mime_type"),
                                "sha256": h.hex() if isinstance(h, bytes) and h else None, "guid": d.get("guid")},
                {"start": stamp(d.get("start_time"), _download_clock(d.get("start_time"))),
                 "end": stamp(d.get("end_time"), _download_clock(d.get("end_time")))})
        for s in R("keyword_search_terms"):
            u = urls.get(s.get("url_id"), {})
            add("search", s, {"term": s.get("term"), "normalized": s.get("normalized_term") or s.get("lower_term"),
                              "url": u.get("url")}, {"time": stamp(u.get("last_visit_time"), "webkit")})
    elif kind == "chromium_login_data":
        for r in R("logins"):
            pw_, state = _secret(r, "password_value", files)
            add("login", r, {"url": r.get("origin_url"), "action_url": r.get("action_url"),
                             "realm": r.get("signon_realm"), "username": r.get("username_value") or None,
                             "password": pw_, "password_state": state, "times_used": r.get("times_used")},
                {"created": stamp(r.get("date_created"), "webkit"), "last_used": stamp(r.get("date_last_used"), "webkit")})
    elif kind == "chromium_cookies":
        for r in R("cookies"):
            value, state = (r.get("value"), "plain") if r.get("value") else _secret(r, "encrypted_value", files, r.get("host_key"))
            add("cookie", r, {"host": r.get("host_key"), "name": r.get("name"), "value": value, "value_state": state,
                              "path": r.get("path"), "secure": r.get("is_secure", r.get("secure")),
                              "httponly": r.get("is_httponly", r.get("httponly"))},
                {"created": stamp(r.get("creation_utc"), "webkit"), "expires": stamp(r.get("expires_utc"), "webkit"),
                 "last_access": stamp(r.get("last_access_utc"), "webkit")})
    elif kind == "chromium_web_data":
        for r in R("autofill"):
            add("autofill", r, {"name": r.get("name"), "value": r.get("value"), "count": r.get("count")},
                {"created": stamp(r.get("date_created"), "unix"), "last_used": stamp(r.get("date_last_used"), "unix")})
        for r in R("keywords"):
            add("search_engine", r, {"name": r.get("short_name"), "keyword": r.get("keyword"), "url": r.get("url")})
    elif kind == "firefox_places":
        places = _by(R("moz_places"), "id")
        seen_visits = {}
        for v in db.rows("moz_historyvisits", recovered=False):
            seen_visits[v.get("place_id")] = seen_visits.get(v.get("place_id"), 0) + 1
        for u in R("moz_places"):
            add("url", u, {"url": u.get("url"), "title": u.get("title"), "visit_count": u.get("visit_count"),
                           "typed_count": u.get("typed"),
                           "visit_rows": seen_visits.get(u.get("id"), 0) if "moz_historyvisits" in db.tables else None},
                {"last_visit": stamp(u.get("last_visit_date"), "prtime")})
        for v in R("moz_historyvisits"):
            u = places.get(v.get("place_id"), {})
            add("visit", v, {"url": u.get("url"), "title": u.get("title"), "transition": v.get("visit_type")},
                {"time": stamp(v.get("visit_date"), "prtime")})
        for b in R("moz_bookmarks"):
            u = places.get(b.get("fk"), {})
            if u.get("url"):
                add("bookmark", b, {"url": u.get("url"), "title": b.get("title")}, {"added": stamp(b.get("dateAdded"), "prtime")})
        attrs = {a.get("id"): a.get("name") for a in R("moz_anno_attributes")}
        for a in R("moz_annos"):
            if attrs.get(a.get("anno_attribute_id")) == "downloads/destinationFileURI":
                u = places.get(a.get("place_id"), {})
                add("download", a, {"url_chain": [u["url"]] if u.get("url") else [], "path": a.get("content"),
                                    "tab_url": None, "referrer": None, "size": None, "received": None, "mime": None},
                    {"start": stamp(a.get("dateAdded"), "prtime")})
        for i in R("moz_inputhistory"):
            u = places.get(i.get("place_id"), {})
            add("typed", i, {"term": i.get("input"), "url": u.get("url")})
    elif kind == "firefox_cookies":
        for r in R("moz_cookies"):
            add("cookie", r, {"host": r.get("host"), "name": r.get("name"), "value": r.get("value"), "value_state": "plain",
                              "path": r.get("path"), "secure": r.get("isSecure"), "httponly": r.get("isHttpOnly")},
                {"created": stamp(r.get("creationTime"), "prtime"), "expires": stamp(r.get("expiry"), "unix"),
                 "last_access": stamp(r.get("lastAccessed"), "prtime")})
    elif kind == "firefox_formhistory":
        for r in R("moz_formhistory"):
            add("autofill", r, {"name": r.get("fieldname"), "value": r.get("value"), "count": r.get("timesUsed")},
                {"created": stamp(r.get("firstUsed"), "prtime"), "last_used": stamp(r.get("lastUsed"), "prtime")})
    elif kind == "firefox_webappsstore":
        for r in R("webappsstore2"):
            add("storage", r, {"origin": (r.get("originKey") or r.get("scope") or "")[::-1] if r.get("originKey") or r.get("scope") else None,
                               "key": r.get("key"), "value": r.get("value")})
    elif kind == "safari_history":
        items = _by(R("history_items"), "id")
        per = {}
        for v in db.rows("history_visits", recovered=False):
            per.setdefault(v.get("history_item"), []).append(v)
        for u in R("history_items"):
            vs = sorted(per.get(u.get("id"), []), key=lambda r: r.get("visit_time") or 0)
            add("url", u, {"url": u.get("url"), "title": vs[-1].get("title") if vs else None,
                           "visit_count": u.get("visit_count"), "visit_rows": len(vs)},
                {"last_visit": stamp(vs[-1].get("visit_time"), "mac_absolute") if vs else (None, None)})
        for v in R("history_visits"):
            u = items.get(v.get("history_item"), {})
            add("visit", v, {"url": u.get("url"), "title": v.get("title")}, {"time": stamp(v.get("visit_time"), "mac_absolute")})
    elif kind == "quarantine_events":
        for r in R("LSQuarantineEvent"):
            add("download", r, {"url_chain": [r["LSQuarantineDataURLString"]] if r.get("LSQuarantineDataURLString") else [],
                                "referrer": r.get("LSQuarantineOriginURLString"), "tab_url": None, "path": None,
                                "agent": r.get("LSQuarantineAgentName"), "size": None, "received": None, "mime": None,
                                "guid": r.get("LSQuarantineEventIdentifier")},
                {"start": stamp(r.get("LSQuarantineTimeStamp"), "mac_absolute")})
    elif kind == "ios_sms":
        handles = _by(R("handle"), "ROWID")
        for m in R("message"):
            h = handles.get(m.get("handle_id"), {})
            add("message", m, {"text": m.get("text"), "sender": h.get("id"), "from_me": m.get("is_from_me"),
                               "service": m.get("service")}, {"time": stamp(m.get("date"), "mac_absolute")})
    elif kind == "whatsapp_msgstore":
        for m in R("messages"):
            add("message", m, {"text": m.get("data"), "sender": m.get("key_remote_jid"), "from_me": m.get("key_from_me")},
                {"time": stamp(m.get("timestamp"), "unix_ms")})
        jids = _by(R("jid"), "_id")
        chats = _by(R("chat"), "_id")
        for m in (R("message") if "messages" not in db.tables else []):
            chat = chats.get(m.get("chat_row_id"), {})
            jid = jids.get(m.get("sender_jid_row_id") or chat.get("jid_row_id"), {})
            add("message", m, {"text": m.get("text_data"), "sender": jid.get("raw_string"), "from_me": m.get("from_me")},
                {"time": stamp(m.get("timestamp"), "unix_ms")})
    elif kind == "fossil_repository":
        for r in R("config"):
            add("fossil_config", r, {"name": r.get("name"), "value": r.get("value")}, {"mtime": stamp(r.get("mtime"), "unix")})
        for r in R("user"):
            add("fossil_user", r, {"login": r.get("login"), "cap": r.get("cap"), "info": r.get("info"), "pw": r.get("pw")},
                {"mtime": stamp(r.get("mtime"), "unix")})
        for r in R("event"):
            add("fossil_event", r, {"type": r.get("type"), "user": r.get("euser") or r.get("user"),
                                    "comment": r.get("ecomment") or r.get("comment")}, {"time": stamp(r.get("mtime"), "julian")})
    return out


def firefox_logins(data: bytes, art: str = "") -> list:
    """Records of a Firefox logins.json: the host is plain; the user name and password are encrypted
    under key4.db (NSS), so they are None with state 'nss'."""
    try:
        doc = json.loads(data)
        rows = doc["logins"]
    except (ValueError, KeyError, TypeError):
        return []
    out = []
    for i, r in enumerate(rows if isinstance(rows, list) else []):
        if not isinstance(r, dict) or "encryptedUsername" not in r:
            continue
        row = {"_src": "live", "_table": "logins.json", "_rowid": r.get("id", i)}
        out.append(_rec("login", row, {"url": r.get("hostname"), "action_url": r.get("formSubmitURL"), "realm": r.get("httpRealm"),
                                       "username": None, "password": None, "password_state": "nss", "username_state": "nss",
                                       "times_used": r.get("timesUsed")},
                        {"created": stamp(r.get("timeCreated"), "unix_ms"), "last_used": stamp(r.get("timeLastUsed"), "unix_ms")},
                        art, "firefox_logins_json"))
    return out


_ENGINE_PARAM = (("google.", "q"), ("bing.com", "q"), ("duckduckgo.com", "q"), ("yahoo.", "p"), ("yandex.", "text"),
                 ("baidu.com", "wd"), ("youtube.com", "search_query"), ("brave.com", "q"), ("startpage.com", "query"))


def search_from_url(url):
    """The search term a search engine's result URL carries, or None."""
    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    for dom, param in _ENGINE_PARAM:
        if dom in host:
            q = dict(parse_qsl(parts.query, keep_blank_values=False))
            return unquote_plus(q[param]) if param in q and q[param] else None
    return None


# ---- a delivery as evidence ----------------------------------------------------------------------------

def _tail(key: str) -> str:
    return key.split(ARROW)[-1]


class Evidence:
    """Everything this toolkit reads in a set of files: .dbs {key: Database}, .kinds {key: artifact
    kind}, .records, .extensions, .storage (LevelDB and Firefox Local Storage records)."""

    def __init__(self, files: dict, carve: bool = True):
        self.files = files
        self.dbs, self.kinds, self.records, self.storage = {}, {}, [], []
        seen = []
        t_start = time.monotonic()
        for key, data in files.items():
            if data[:16] != SQLITE_MAGIC or any(data is d for d in seen):
                continue
            seen.append(data)
            wal = self._beside(key, "-wal")
            journal = self._beside(key, "-journal")
            try:
                db = Database(data, wal, journal, key, carve and time.monotonic() - t_start < CARVE_TOTAL_SECONDS)
            except Exception:
                continue
            self.dbs[key] = db
            self.kinds[key] = schema_kind(db)
            self.records += records(db, files, key)
        for key, data in files.items():
            if data[:16] == SQLITE_MAGIC or any(data is d for d in seen):
                continue
            if data.lstrip()[:1] == b"{" and b"encryptedUsername" in data:
                recs = firefox_logins(data, key)
                if recs:
                    seen.append(data)
                    self.kinds[key] = "firefox_logins_json"
                    self.records += recs
            elif is_leveldb(key, data):
                seen.append(data)
                self.kinds[key] = "leveldb"
                try:
                    self.storage += leveldb_records(data, key)
                except Exception:
                    pass
        for r in self.records:
            if r["kind"] == "storage":
                self.storage.append({"seq": None, "state": "live" if r["src"] == "live" else "recovered", "key": r["f"]["key"],
                                     "value": r["f"]["value"], "origin": r["f"]["origin"], "file": r["art"]})
        self.extensions = extensions(files)
        for e in self.extensions:
            self.kinds.setdefault(e["where"], "chrome_extension")

    def _beside(self, key: str, suffix: str):
        if key + suffix in self.files:
            return self.files[key + suffix]
        # the same file under another key (a bare member name beside its `archive -> member` key):
        # only when the name is one database and one side file, since SQLite ties a WAL to a
        # database by nothing but the WAL's own salts and would replay a stranger's frames
        tail = _tail(key) + suffix
        hits, mains = [], []
        for k, v in self.files.items():
            if _tail(k) == tail and not any(v is h or v == h for h in hits):
                hits.append(v)
            if _tail(k) == _tail(key) and v[:16] == SQLITE_MAGIC and not any(v is m or v == m for m in mains):
                mains.append(v)
        return hits[0] if len(hits) == 1 and len(mains) == 1 else None

    def of(self, *kinds, recovered=None) -> list:
        return [r for r in self.records if r["kind"] in kinds
                and (recovered is None or (r["src"] != "live") == recovered)]

    def staged(self) -> list:
        """[(record, field, chain, decoded text)] for every URL, title, term or path cell that
        hides text (the decoder pass)."""
        out = []
        for r in self.records:
            cells = []
            for name in ("url", "title", "term", "path", "tab_url", "referrer", "value", "text"):
                v = r["f"].get(name)
                if isinstance(v, str):
                    cells.append((name, v))
            cells += [("url_chain", u) for u in r["f"].get("url_chain") or []]
            for name, v in cells:
                for chain, text in decodings(v):
                    if not any(o[3] == text and o[0] is r for o in out):
                        out.append((r, name, chain, text))
        return out


# ---- reading a question --------------------------------------------------------------------------------

def _fmt(q) -> dict:
    f = q.get("answer_format")
    return f if isinstance(f, dict) else {}


def _fits(q, value) -> bool:
    f = _fmt(q)
    rx = f.get("pattern") or f.get("regex")
    if isinstance(rx, str) and rx.strip():
        try:
            return re.fullmatch(rx, str(value)) is not None
        except re.error:
            return False
    if str(f.get("kind") or "") == "integer":
        return re.fullmatch(r"-?\d+", str(value)) is not None
    return True


_NAME_TOKEN = r"[A-Za-z0-9_\-./:%?=&~+@]*[A-Za-z0-9]\.[A-Za-z0-9][A-Za-z0-9_\-./:%?=&~+@]*"
_QUOTED = r"[`'\"\u2018\u201c]([^`'\"\u2019\u201d]{2,200})[`'\"\u2019\u201d]"


def _qtext(q) -> str:
    """The question as one line. The apostrophe of a possessive or a contraction is dropped: it is
    no quote, and two of them would otherwise hide the words between them."""
    text = " ".join(str(q.get("question") or "").split())
    text = re.sub(r"(?<=[A-Za-z0-9])['\u2019]s\b", "", text)          # `the extension's id` asks about the extension
    return re.sub(r"(?<=[A-Za-z0-9])['\u2019](?=[A-Za-z])", "", text)


# what follows one of these is an example of the answer's form, never the name of a row
_HINT = re.compile(r"(?i)\b(?:e\.g\.?|i\.e\.?|for example|example:|formatted as|format:|in the form(?:at)?(?: of)?|such as|"
                   r"answer (?:as|in the form|format))(?=\W|$).*$")


def _hay(q) -> str:
    """The question's words and its answer id's, lowercase, without the names it quotes (a URL that
    holds the word `download` says nothing about what is asked)."""
    aid = str(q.get("answer_id") or q.get("qid") or q.get("id") or "")
    text = _qtext(q)
    text = re.sub(_QUOTED, " ", text)
    text = re.sub(_NAME_TOKEN, lambda m: " " if len(m.group().rstrip(".,;:!?)")) > 2 and "." in m.group().rstrip(".,;:!?)") else m.group(), text)
    return (text + " | " + re.sub(r"[-_./]+", " ", aid)).lower()


_DELETED = re.compile(r"\bdeleted?\b|\bremoved\b|\brecover(?:ed|able)?\b|\berased\b|\bcleared\b|\bwiped\b|\bwal\b|"
                      r"\bwrite ahead\b|\bjournal\b|\bfreelist\b|\bunallocated\b|\bno longer\b")
_STOP_ANCHOR = {"e.g", "i.e", "etc", "vs", "a.m", "p.m", "u.s", "no"}

# A question that asks for something derived from a row, or for another row than the one its words
# pin, has no rule here: with one of these words it is None, whatever else it says.
_OFF_FIELD = re.compile(
    r"\b(?:length|how long|characters?|chars|digits?|letters?|hash(?:es)?|md5|sha[- ]?\d+|checksum|digest|"
    r"kilobytes?|megabytes?|gigabytes?|kb|mb|gb|kib|mib|not|isnt|wasnt|doesnt|didnt|arent|werent|except|excluding|"
    r"other than|without|never|second|third|fourth|fifth|2nd|3rd|4th|5th|before|after|previous|prior|next|following|"
    r"preceding|immediately|fewest|least|longest|shortest|largest|smallest|biggest|lowest|average|ip|"
    r"ipv4|ipv6|port|scheme|protocol|tld|top[- ]level|subdomain|parameters?|query string|duration|elapsed|zip|archive|"
    r"rar|7z|reversed?)\b")
_COUNTISH = re.compile(r"\b(?:how many|how much|number of|count)\b")
_HOSTISH = re.compile(r"\b(?:web ?sites?|sites?|domains?|host ?names?|hosts?|servers?)\b")
_HOST_FIRST = re.compile(r"\b(?:domains?|host ?names?|hosts?|servers?)\b")
_URL_FIELDS = ("download_url", "download_referrer", "download_tab_url", "url")
_NOT_TEXT_KIND = re.compile(r"sha|md5|hash|bool|ipv?\d?$|^ip|port|hex|mitre|enum")
# a count is of the rows themselves: only these words may stand between `how many` and the noun
_COUNT_FILL = r"(?:(?:total|saved|stored|browser|live|deleted|removed|recovered|recoverable|erased|cleared|wiped)\s+)*"


def _count_rx(nouns: str, counted: str = "") -> str:
    rx = rf"\b(?:how many|number of|count of)\s+{_COUNT_FILL}(?P<noun>{nouns})\b"
    return rx + (rf"|\b(?:{counted}) count\b" if counted else "")


# and only these around it (`how many cookies are stored in the database`)
_COUNT_WORDS = set("""what whats is are was were there stored saved recorded present exist exists existed in the this that
    database db file files history browser profile total listed kept held does do did contain contains have has had hold
    holds deleted removed recovered recoverable erased cleared wiped from of evidence artifact table wal journal be can
    been record records rows entries row entry found sqlite chrome chromium edge firefox safari store jar currently still
    a an it on disk write ahead log how many number count cookie cookies download downloads login logins passwords
    password credentials credential urls pages sites websites data web places overall altogether visited browsed""".split())

# which of a row's times `first` and `last` mean, by the question's words; a kind listed here with
# no such word needs every time it has to agree on the row
_EDGE_KEYS = {
    "cookie": ((r"\bexpir\w*\b", "expires"), (r"\baccess\w*\b|\bused\b", "last_access"),
               (r"\bcreat\w*\b|\bset\b|\badded\b|\boldest\b|\bnewest\b", "created")),
    "login": ((r"\bused\b|\blogged\b|\bsigned\b", "last_used"),
              (r"\bcreat\w*\b|\bsaved\b|\badded\b|\bstored\b|\boldest\b|\bnewest\b", "created")),
    "download": ((r"\b(?:end|ended|finish\w*|complet\w*)\b", "end"), (r"", "start")),
    "autofill": ((r"\bused\b", "last_used"), (r"\bcreat\w*\b|\badded\b|\bentered\b", "created")),
}

# (field, what the words must say, the record kinds it is read from)
RULES = (
    ("extension_id", r"\bextension\b.*\bid\b|\bid\b.*\bextension\b|\bextension id\b|\bcrx id\b", ("extension",)),
    ("permission_count", r"\bhow many\b.*\bpermissions?\b|\bnumber of\b.*\bpermissions?\b|\bpermissions? count\b", ("extension",)),
    ("host_permissions", r"\bhost permissions?\b|\bpermissions?\b.*\b(?:hosts?|sites?|urls?|origins?|match patterns?)\b", ("extension",)),
    ("permissions", r"\bpermissions?\b", ("extension",)),
    ("background", r"\bbackground\b|\bservice worker\b", ("extension",)),
    ("content_script", r"\bcontent scripts?\b", ("extension",)),
    ("manifest_version", r"\bmanifest version\b", ("extension",)),
    ("extension_version", r"\bextension\b.*\bversion\b|\bversion\b.*\bextension\b", ("extension",)),
    ("extension_name", r"\bextension\b.*\bname\b|\bname\b.*\bextension\b|\b(?:which|what) extension\b", ("extension",)),
    ("update_url", r"\bupdate url\b", ("extension",)),
    ("staged", r"\bstaged\b|\bdecoded?\b|\bhidden\b|\bencoded\b|\bc2\b|\bcommand\b|\bpayload\b|\bobfuscated\b", ("staged",)),
    ("download_count", _count_rx("downloads?", "downloads?"), ("download",)),
    ("download_referrer", r"\bdownload\w*\b.*\breferr?er\b|\breferr?er\b.*\bdownload\w*\b", ("download",)),
    ("download_tab_url", r"\bdownload\w*\b.*\b(?:tab|page)\b.*\burl\b|\btab url\b", ("download",)),
    ("download_time", r"\bdownload\w*\b.*\b(?:time|timestamp|when|date)\b|\b(?:time|timestamp|when|date)\b.*\bdownload\w*\b", ("download",)),
    ("download_size", r"\bdownload\w*\b.*\b(?:size|bytes)\b|\b(?:size|bytes)\b.*\bdownload\w*\b", ("download",)),
    ("download_mime", r"\bdownload\w*\b.*\bmime\b|\bmime\b.*\bdownload\w*\b", ("download",)),
    ("download_url", r"\bdownload\w*\b.*\b(?:urls?|link|source|address|from where|where .* from)\b|"
                     r"\b(?:urls?|link|source|address)\b.*\bdownload\w*\b|"
                     r"^(?!.*\b(?:what|which) (?:\w+ )?(?:file|program|binary|executable)\b).*\bdownloaded from\b", ("download",)),
    ("download_path", r"\bdownload\w*\b.*\b(?:file ?name|filename|path|saved (?:to|as|at|in)|target|location)\b|"
                      r"\b(?:file ?name|filename|path)\b.*\bdownload\w*\b|\b(?:what|which) file\b.*\bdownload\w*\b|"
                      r"\bname of the (?:\w+ )?file\b.*\bdownload\w*\b|\bname of the download\w* file\b", ("download",)),
    ("search_term", r"\bsearch(?:ed)?\b.*\b(?:terms?|query|queries|keywords?|phrase|for)\b|\b(?:terms?|query|phrase)\b.*\bsearch(?:ed)?\b|"
                    r"\bsearch term\b", ("search",)),
    ("cookie_count", _count_rx("cookies?", "cookies?"), ("cookie",)),
    ("cookie_host", r"\bcookie\w*\b.*\b(?:host|domain|site)\b|\b(?:host|domain|site)\b.*\bcookie\w*\b", ("cookie",)),
    ("cookie_value", r"\bcookie\w*\b.*\bvalue\b|\bvalue\b.*\bcookie\w*\b", ("cookie",)),
    ("cookie_time", r"\bcookie\w*\b.*\b(?:time|when|date|created|expir\w*)\b", ("cookie",)),
    ("cookie_name", r"\bcookie\w*\b.*\bname\b|\bname\b.*\bcookie\w*\b", ("cookie",)),
    ("login_count", _count_rx("logins?|credentials?|passwords?", "logins?"), ("login",)),
    ("password", r"\bpassword\b(?!s? manager)", ("login",)),
    ("username", r"\buser ?name\b|\bsaved (?:user|login|account) ?names?\b|\b(?:login|account) name\b|"
                 r"\bsaved credentials?\b.*\buser\b|\bwhich (?:user|account)\b.*\bsaved\b", ("login",)),
    ("login_url", r"\b(?:login|credential|password)s?\b.*\b(?:url|site|origin|host|domain)\b|"
                  r"\b(?:url|site|origin|host|domain)\b.*\b(?:login|credential)s?\b", ("login",)),
    ("visit_count", r"\bvisit count\b|\btimes\b.*\b(?:visit|brows|open|access|load)\w*\b|\b(?:visit|brows|open|access|load)\w*\b.*\btimes\b|"
                    r"\bnumber of visits\b|\bhow many visits\b", ("url",)),
    ("url_count", _count_rx("urls|web ?sites|sites|pages|history entries"), ("url",)),
    ("visit_time", r"\b(?:visit\w*|brows\w*|access\w*|open\w*)\b.*\b(?:time|timestamp|when|date)\b|"
                   r"\b(?:time|timestamp|when|date)\b.*\b(?:visit\w*|brows\w*|access\w*|open\w*)\b", ("url", "visit")),
    ("title", r"\btitle\b.*\b(?:page|site|url|tab|visit\w*|history|web\w*|brows\w*)\b|"
              r"\b(?:page|site|url|tab|visit\w*|history|web\w*|brows\w*)\b.*\btitle\b", ("url", "visit")),
    ("message_sender", r"\b(?:sender|who sent|sent by|from whom)\b|"
                       r"\b(?:message|sms|text|chat|imessage|whatsapp)\w*\b.*\b(?:(?:what|which|whose) (?:phone )?number|contact|handle|jid)\b|"
                       r"\b(?:what|which|whose) (?:phone )?number\b.*\b(?:message|sms|text|chat)\w*\b", ("message",)),
    ("message_time", r"\b(?:message|sms|chat)\w*\b.*\b(?:time|timestamp|when|date)\b", ("message",)),
    ("message_text", r"\b(?:message|sms|chat|imessage|whatsapp)\w*\b.*\b(?:text|body|contents?|say|says|said|read)\b|"
                     r"\b(?:text|body|contents?)\b.*\b(?:message|sms|chat)\w*\b|"
                     r"\bwhat (?:was|is) the (?:\w+ ){0,2}(?:message|sms)\?? \||"
                     r"\bwhat (?:\w+ )?(?:message|sms) was (?:sent|received|deleted|recovered)\b", ("message",)),
    ("fossil_project", r"\bproject[ -]name\b|\bname of the (?:fossil )?(?:project|repository)\b", ("fossil_config",)),
    ("fossil_comment", r"\b(?:commit|check-?in)\b.*\b(?:comment|message)\b", ("fossil_event",)),
    ("fossil_flag", r"\bflag\b", ("fossil_config",)),
    ("url", r"\burl\b.*\b(?:visited|browsed|opened|history)\b|\b(?:visited|browsed)\b.*\b(?:url|site|page)\b|"
            r"\bwhich (?:url|site|page)\b|\bwhat (?:url|site|page)\b", ("url", "visit")),
)
_RULES = tuple((name, re.compile(rx), kinds) for name, rx, kinds in RULES)
_COUNT_HEAD = {name: rx for name, rx, _ in _RULES if name.endswith("_count")}


def classify(q):
    """(field, record kinds) the question's words and answer id ask for, or None."""
    hay = _hay(q)
    for name, rx, kinds in _RULES:
        if rx.search(hay):
            return name, kinds
    return None


def _anchors(q, files: dict) -> list:
    """The names a question pins its row with: quoted text, anything with a dot in it (a host, a
    file, a URL) and the word after `named` or `called`; never the delivery's own file names."""
    text = _HINT.sub(" ", _qtext(q))
    own = set()
    for k in files:
        for part in k.split(ARROW):
            own.update({part.lower(), Path(part).name.lower()})
    for extra in (q.get("member"), q.get("artifact")):
        for part in str(extra or "").split(ARROW):
            own.update({part.strip().lower(), Path(part.strip()).name.lower()})
    found = [m.group(1) for m in re.finditer(_QUOTED, text)]
    found += [m.group().rstrip(".,;:!?)") for m in re.finditer(_NAME_TOKEN, text)]
    found += [m.group(1) for m in re.finditer(r"\b(?:named|called)\s+([A-Za-z0-9_][\w\-.]{1,80})", text)]
    out = []
    for a in found:
        low = a.strip().rstrip(".,;:!?").lower()
        if len(low) < 3 or low in own or low in _STOP_ANCHOR or re.fullmatch(r"[\d.]+", low) or low in out:
            continue
        out.append(low)
    return out


def _strings(rec: dict):
    for v in rec["f"].values():
        if isinstance(v, str):
            yield v.lower()
        elif isinstance(v, list):
            yield from (x.lower() for x in v if isinstance(x, str))


def _narrow(recs: list, anchor: str) -> list:
    """The records that carry a name: those with a cell equal to it, else those with a cell that
    contains it."""
    exact = [r for r in recs if any(v == anchor for v in _strings(r))]
    return exact or [r for r in recs if any(anchor in v for v in _strings(r))]


_SOFT_FIELDS = ("name", "username", "key", "sender", "host")
_SOFT_STOP = set("""the and for was were are from with that this which what when where who how many much name named value host
    domain site cookie cookies user username login logins password saved account download downloaded url urls link time
    date visit visited visits count title search term query message sender text file path extension permission history
    browser chrome firefox safari database deleted removed recovered first last latest earliest most recent set stored""".split())


def _soft_anchors(q, recs: list) -> list:
    """Words of the question that are, letter for letter, the name of a row (a cookie's name, a
    saved user name, a storage key): they narrow like an anchor, but a word that is none is no
    reason to give up."""
    cells = set()
    for r in recs:
        for k in _SOFT_FIELDS:
            v = r["f"].get(k)
            if isinstance(v, str) and len(v) >= 3:
                cells.add(v.lower())
    words = re.findall(r"[A-Za-z0-9_][\w\-]{2,}", re.sub(_QUOTED, " ", _HINT.sub(" ", _qtext(q))))
    return list(dict.fromkeys(w.lower() for w in words if w.lower() in cells and w.lower() not in _SOFT_STOP))


_PRIMARY_TIME = {"url": "last_visit", "visit": "time", "download": "start", "cookie": "created", "login": "created",
                 "message": "time", "search": "time", "fossil_event": "time", "autofill": "created"}


def select(recs: list, q, files: dict, field: str = ""):
    """The records a question means, or None when its words name something no record carries.
    Anchors narrow first; then, with more than one left, `first`/`last`/`most visited` take the
    one extreme row when there is exactly one."""
    hay = _hay(q)
    for a in _anchors(q, files):
        recs = _narrow(recs, a)
        if not recs:
            return None
    if len(recs) > 1:
        for a in _soft_anchors(q, recs):
            hit = [r for r in recs if any(str(r["f"].get(k) or "").lower() == a for k in _SOFT_FIELDS)]
            recs = hit or recs
    if len(recs) > 1:
        which = None
        if re.search(r"\bmost (?:visited|frequent\w*|often)\b|\bhighest visit\b", hay):
            vals = [(r["f"].get("visit_count"), r) for r in recs if isinstance(r["f"].get("visit_count"), int)]
            if vals:
                top = max(v for v, _ in vals)
                recs = [r for v, r in vals if v == top]
        elif re.search(r"\b(?:first|earliest|oldest)\b", hay):
            which = min
        elif re.search(r"\b(?:last|latest|newest|most recent(?:ly)?)\b", hay):
            which = max
        kinds = {r["kind"] for r in recs}
        if which is not None and len(kinds) == 1 and next(iter(kinds)) in _EDGE_KEYS:
            # a row with several times: the one the words name, else all of them must agree
            num = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool) and v       # noqa: E731
            named = [k for rx, k in _EDGE_KEYS[next(iter(kinds))] if rx and re.search(rx, hay)]
            keys = named[:1] or sorted({k for r in recs for k, tv in r["t"].items() if num(tv[0])}) \
                or [k for rx, k in _EDGE_KEYS[next(iter(kinds))] if not rx]
            picked = []
            for k in keys:
                timed = [(r["t"].get(k, (None, None))[0], r) for r in recs]
                if not all(num(v) for v, _ in timed):
                    return None                 # a row without that time: the extreme is not proven
                edge = which(v for v, _ in timed)
                picked.append([id(r) for v, r in timed if v == edge])
            if not picked or any(sorted(x) != sorted(picked[0]) for x in picked):
                return None
            recs = [r for r in recs if id(r) in picked[0]]
        elif which is not None:
            timed = [(r["t"].get(_PRIMARY_TIME.get(r["kind"], "time"), (None, None))[0], r) for r in recs]
            timed = [(v, r) for v, r in timed if isinstance(v, (int, float)) and v]
            if timed:
                edge = which(v for v, _ in timed)
                recs = [r for v, r in timed if v == edge]
    return recs


def _join_options(items: list, q) -> list:
    """The spellings of one list."""
    kind = str(_fmt(q).get("kind") or "")
    js = [("json", json.dumps(items, separators=(",", ":"))), ("json_sorted", json.dumps(sorted(items), separators=(",", ":")))]
    if kind == "json":
        return js
    out = [("comma", ",".join(items)), ("comma_space", ", ".join(items)), ("sorted_comma", ",".join(sorted(items))),
           ("sorted_comma_space", ", ".join(sorted(items))), ("space", " ".join(items)), ("pipe", "|".join(items)),
           ("semicolon", ";".join(items))] + js + [("newline", "\n".join(items))]
    seen, uniq = set(), []
    for n, v in out:
        if v not in seen:
            seen.add(v)
            uniq.append((n, v))
    return uniq


def _readings(field: str, r: dict, hay: str, q):
    """What one record answers for a field: ('plain', value), ('time', (raw, dt)),
    ('options', [(name, value), ...]) for one fact with several spellings or readings, or None."""
    f, t = r["f"], r["t"]
    one = lambda v: ("plain", v) if v not in (None, "") else None           # noqa: E731
    if field == "download_url":
        chain = f.get("url_chain") or []
        if not chain:
            return None
        if len(chain) == 1:
            return ("plain", chain[0])
        return ("options", [("final_url", chain[-1]), ("first_url", chain[0])])
    if field == "download_referrer":
        return one(f.get("tab_referrer_url") if re.search(r"\btabs?\b", hay) else f.get("referrer"))
    if field == "download_tab_url":
        return one(f.get("tab_url"))
    if field == "download_time":
        return ("time", t.get("end" if re.search(r"\b(?:end|ended|finish\w*|complet\w*)\b", hay) else "start", (None, None)))
    if field == "download_size":
        size, got = f.get("size"), f.get("received")
        if isinstance(size, int) and size > 0 and (got in (None, size)):
            return ("plain", str(size))
        opts = [("total_bytes", str(size) if isinstance(size, int) and size > 0 else None),
                ("received_bytes", str(got) if isinstance(got, int) and got > 0 else None)]
        return ("options", opts)
    if field == "download_mime":
        return one(f.get("mime"))
    if field == "download_path":
        p = f.get("path")
        if not isinstance(p, str) or not p:
            return None
        # Day 14 look-ahead (new-lane finding F4): the file's name and its full path are two facts. Both
        # were offered under the one key download_path with the order turned by the question's words, so
        # the name the judge accepted for "what is the file called" answered "where was it saved" too.
        # A question that asks the name is now under download_name, a key of its own.
        if p.startswith("file://"):
            local = unquote(urlsplit(p).path)
            base = re.split(r"[\\/]", local)[-1]
            return (("options_as", ("download_name", [("file_name", base), ("path", local), ("file_uri", p)]))
                    if not re.search(r"\bpath\b|\blocation\b", hay)
                    else ("options", [("path", local), ("file_uri", p), ("file_name", base)]))
        base = re.split(r"[\\/]", p)[-1]
        if base == p:
            return ("plain", p)
        return (("options", [("path", p), ("file_name", base)]) if re.search(r"\bpath\b|\blocation\b|\bwhere\b", hay)
                else ("options_as", ("download_name", [("file_name", base), ("path", p)])))
    if field == "search_term":
        term, norm = f.get("term"), f.get("normalized")
        if not term:
            return None
        if r["shape"] == "url_query":
            return ("options", [("url_query", term)])
        if norm in (None, "", term):
            return ("plain", term)
        return ("options", [("term", term), ("normalized_term", norm)])
    if field == "cookie_host":
        h = f.get("host")
        if not h:
            return None
        return ("options", [("host_key", h), ("without_leading_dot", h.lstrip("."))]) if h.startswith(".") else ("plain", h)
    if field == "cookie_name":
        return one(f.get("name"))
    if field == "cookie_value":
        if f.get("value") in (None, ""):
            return None
        return ("plain", f["value"]) if f.get("value_state") == "plain" else ("options", [(f["value_state"], f["value"])])
    if field == "cookie_time":
        which = "expires" if re.search(r"\bexpir\w*\b", hay) else "last_access" if re.search(r"\blast access\w*\b", hay) else "created"
        return ("time", t.get(which, (None, None)))
    if field == "username":
        return one(f.get("username"))
    if field == "password":
        if f.get("password") in (None, ""):
            return None
        return ("plain", f["password"]) if f.get("password_state") == "plain" else ("options", [(f["password_state"], f["password"])])
    if field == "login_url":
        u, realm = f.get("url"), f.get("realm")
        if not u:
            return None
        host = None
        try:
            host = urlsplit(u).hostname
        except ValueError:
            pass
        if _HOST_FIRST.search(hay) and host:
            return ("options", [("host", host), ("origin_url", u)])
        if _HOSTISH.search(hay) and host and not re.search(r"\burls?\b|\blinks?\b|\baddress\b", hay):
            return ("options", [("origin_url", u), ("host", host)] + ([("signon_realm", realm)] if realm and realm != u else []))
        opts = [("origin_url", u)] + ([("signon_realm", realm)] if realm and realm != u else []) + \
               ([("action_url", f["action_url"])] if f.get("action_url") and f["action_url"] != u else [])
        return ("plain", u) if len(opts) == 1 else ("options", opts)
    if field == "visit_count":
        col, rows = f.get("visit_count"), f.get("visit_rows")
        if not isinstance(col, int):
            return None
        if rows in (None, col):
            return ("plain", str(col))
        return ("options", [("visit_count_column", str(col)), ("visit_rows", str(rows))])
    if field == "visit_time":
        if r["kind"] == "url":
            return ("time", t.get("last_visit", (None, None)))
        return ("time", t.get("time", (None, None)))
    if field == "title":
        return one(f.get("title"))
    if field == "url":
        return one(f.get("url"))
    if field == "message_text":
        return one(f.get("text"))
    if field == "message_sender":
        who, mine = f.get("sender"), f.get("from_me")
        if not who or mine not in (0, None, False):
            return None                     # the handle of a message that was sent is who received it
        if r["shape"] == "whatsapp_msgstore" or mine is None:
            return ("options", [("chat_jid" if r["shape"] == "whatsapp_msgstore" else "handle", who)])
        return ("plain", who)
    if field == "message_time":
        return ("time", t.get("time", (None, None)))
    if field == "fossil_project":
        return one(f.get("value")) if f.get("name") == "project-name" else None
    if field == "fossil_comment":
        return one(f.get("comment")) if f.get("type") == "ci" else None
    return None


def _extension_readings(field: str, e: dict, hay: str, q):
    one = lambda v: ("plain", str(v)) if v not in (None, "") else None           # noqa: E731
    if field == "extension_id":
        ids = e["ids"]
        if not ids:
            return None
        values = {v for _, v in ids}
        hows = {h for h, _ in ids}
        if len(values) == 1 and hows & {"crx_id", "public_key", "crx2_public_key", "manifest_key"}:
            return ("plain", ids[0][1])
        return ("options", ids)
    if field == "permission_count":
        if e["host_permissions"] or e["optional_permissions"] or len(e["api_permissions"]) != len(e["permissions"]):
            return ("options", [("permissions", str(len(e["permissions"]))),
                                ("with_host_permissions", str(len(e["permissions"]) + len(e["host_permissions"]))),
                                ("api_permissions", str(len(e["api_permissions"]))),
                                ("with_optional", str(len(e["permissions"]) + len(e["host_permissions"]) + len(e["optional_permissions"])))])
        return ("plain", str(len(e["permissions"])))
    if field in ("permissions", "host_permissions"):
        items = e["host_patterns"] if field == "host_permissions" else e["permissions"]
        if not items:
            return None
        if len(items) == 1:
            return ("plain", items[0])
        return ("options", _join_options(items, q))
    if field == "background":
        got = [x for x in [e["service_worker"]] + e["background_scripts"] + [e["background_page"]] if x]
        if not got:
            return None
        return ("plain", got[0]) if len(got) == 1 else ("options", _join_options(got, q))
    if field == "content_script":
        got = e["content_scripts"]
        if not got:
            return None
        return ("plain", got[0]) if len(got) == 1 else ("options", _join_options(got, q))
    if field == "manifest_version":
        return one(e["manifest_version"])
    if field == "extension_version":
        return one(e["version"])
    if field == "extension_name":
        return one(e["name"]) if isinstance(e["name"], str) and not e["name"].startswith("__MSG_") else None
    if field == "update_url":
        return one(e["update_url"])
    return None


def _with_host(reading, host_first: bool):
    """A URL asked for as a `site`, `domain` or `host`: the URL and its host are two spellings of the
    row's one fact, so both are offered and neither is plain."""
    tag, value = reading
    pairs = [("url", value)] if tag == "plain" else list(value)
    urls, hosts = [], []
    for name, v in pairs:
        if not isinstance(v, str) or not v:
            continue
        try:
            h = urlsplit(v).hostname
        except ValueError:
            h = None
        urls.append((name, v))
        if h:
            hosts.append((f"host_of_{name}" if tag != "plain" else "host", h))
    if not urls:
        return None
    return ("options", hosts + urls if host_first else urls + hosts)


def _scope(ev: Evidence, q):
    """The artifact keys a question is about: all of them, or the one its member names. None when
    it names a member that is none of them."""
    member = str(q.get("member") or "").strip()
    if not member:
        return set(ev.kinds)
    base = Path(member).name
    hit = {k for k in ev.kinds if _tail(k) in (member, base) or Path(_tail(k)).name == base
           or (member + "/") in k or k.split(ARROW)[0] == member and ARROW in k}
    if not hit:
        # the member is the archive or folder the artifacts came out of
        hit = {k for k in ev.kinds if any(part.strip() == member or Path(part.strip()).name == base for part in k.split(ARROW)[:-1])}
    return hit or None


def answer(q, ev: Evidence):
    """One question's answer under never-guess: a plain value, an unsure pick, or None."""
    got = classify(q)
    if got is None:
        return None
    field, kinds = got
    kind = str(_fmt(q).get("kind") or "").lower()
    if _NOT_TEXT_KIND.search(kind):
        return None
    scope = _scope(ev, q)
    if scope is None:
        return None
    hay = _hay(q)
    asked = hay.split(" | ")[0]
    if field == "fossil_flag":
        # the one flag{...} among a Fossil repository's file contents: found by its form, so a pick
        found = set()
        for key in scope:
            if ev.kinds.get(key) == "fossil_repository" and key in ev.dbs:
                found |= {text for _, text in fossil_notable(fossil_blobs(ev.dbs[key]), limit=64)["flags"] if re.match(r"(?i)flag\{", text)}
        if len(found) != 1:
            return None
        v = next(iter(found))
        return pick("flag", "fossil_blob", [("flag_form", v)]) if _fits(q, v) else None
    if _OFF_FIELD.search(hay):
        return None
    if field in ("url", "title", "visit_count", "visit_time") and re.search(r"\btyped?\b", hay):
        return None                         # typed_count is another column than visit_count
    if _COUNTISH.search(asked) and not (field.endswith("_count") or field == "download_size"):
        return None                         # a number is asked for, and this field is none
    if kinds == ("extension",) and re.search(r"\bfile ?(?:name)? extension\b|\bextension of (?:the |a )?(?:\w+ )?file\b", hay):
        return None
    want_deleted = _DELETED.search(hay) is not None

    def finish(reading, shape, forced_unsure=False, how="recovered"):
        if reading is None:
            return None
        tag, value = reading
        if tag == "time":
            raw, dt = value
            if dt is None:
                return None
            opts = [(n, v) for n, v in time_options(dt, raw) if _fits(q, v)]
            return pick(field, shape, opts)
        if tag in ("options", "options_as"):
            key_field, value = (field, value) if tag == "options" else value     # options_as: under another field's key
            opts = [(n, v) for n, v in value if v not in (None, "") and _fits(q, v)]
            if forced_unsure:
                opts = [(f"{how}_{n}", v) for n, v in opts]
            return pick(key_field, shape, opts)
        if not _fits(q, value):
            return None
        if forced_unsure:
            return pick(field, shape, [(how, value)])
        return value

    if kinds == ("extension",):
        exts = [e for e in ev.extensions if e["where"] in scope]
        for a in _anchors(q, ev.files):
            hit = [e for e in exts if a in json.dumps(e, default=str).lower()]       # `where` is in it too
            if not hit:
                return None
            exts = hit
        reads = [_extension_readings(field, e, hay, q) for e in exts]
        if not reads or any(r != reads[0] for r in reads):
            return None
        return finish(reads[0], "chrome_extension")

    if kinds == ("staged",):
        hits = [(r, cell, chain, text) for r, cell, chain, text in ev.staged() if r["art"] in scope
                and (r["src"] != "live") == want_deleted]
        if not hits and not want_deleted:
            return None
        for a in _anchors(q, ev.files):
            keep = [h for h in hits if any(a in v for v in _strings(h[0])) or a in h[3].lower()]
            if not keep:
                return None
            hits = keep
        if re.search(r"\btitle\b", hay):
            hits = [h for h in hits if h[1] == "title"]
        elif re.search(r"\burls?\b|\blink\b|\baddress\b", hay):
            hits = [h for h in hits if h[1] in ("url", "url_chain", "tab_url", "referrer")]
        if not hits:
            return None
        # one cell's chain: its innermost text is the staged value; the steps before it are offered after
        cells = {}
        for r, cell, chain, text in hits:
            cells.setdefault((id(r), cell), []).append((chain, text, r))
        finals = {}
        for group in cells.values():
            deepest = max(group, key=lambda g: g[0].count(">"))
            finals.setdefault(deepest[1], (deepest, group))
        if len(finals) != 1:
            return None
        deepest, group = next(iter(finals.values()))
        opts = [(deepest[0], deepest[1])] + [(c, t) for c, t, _ in group if t != deepest[1]]
        opts = [(n, v) for n, v in opts if _fits(q, v)]
        return pick("staged", deepest[2]["shape"], opts)

    count_field = field.endswith("_count") and field not in ("visit_count", "permission_count")
    recs = [r for r in ev.records if r["kind"] in kinds and r["art"] in scope]
    if field == "search_term" and not [r for r in recs if r["src"] == "live"]:
        # no keyword_search_terms row: the term a search engine's URL carries, as a reading of its own
        seen = {}
        for r in ev.of("url", recovered=False):
            term = search_from_url(r["f"].get("url"))
            if term and r["art"] in scope:
                seen.setdefault(term, _rec("search", {"_src": "live", "_table": r["table"], "_rowid": r["rowid"]},
                                           {"term": term, "normalized": None, "url": r["f"].get("url")},
                                           {"time": r["t"].get("last_visit", (None, None))}, r["art"], "url_query"))
        recs = recs + list(seen.values())
    live = [r for r in recs if r["src"] == "live"]
    gone = [r for r in recs if r["src"] != "live"]
    forced = False
    if want_deleted:
        pool, forced = gone, True
    elif live:
        pool = live
    else:
        pool, forced = gone, True
    if not pool:
        return None
    partial = [d for d in (ev.dbs.get(a) for a in {r["art"] for r in pool}) if d is not None and d.truncated]
    if count_field:
        m = _COUNT_HEAD[field].search(asked)
        if m is None and _COUNTISH.search(asked):
            return None                     # the answer id says count; the question counts something else
        around = (asked[:m.start()] + " " + asked[m.end():]) if m else ""
        if any(w not in _COUNT_WORDS for w in re.findall(r"[a-z0-9_]+", around)):
            return None                     # a count of some of the rows (`secure cookies`, `were interrupted`)
        if _anchors(q, ev.files) or partial:
            return None
        if len({r["art"] for r in pool}) != 1:
            return None                     # two databases: which one is counted is not said
        if kind not in ("", "integer", "exact_text", "pattern"):
            return None
        shape, n = pool[0]["shape"], len(pool)
        db = ev.dbs.get(pool[0]["art"])
        if forced:
            return finish(("plain", str(n)), shape, True, "recovered_rows")
        opts = [("live_rows", str(n))]
        if field == "url_count":
            hosts = set()
            for r in pool:
                try:
                    hosts.add(urlsplit(r["f"].get("url") or "").hostname)
                except ValueError:
                    hosts.add(None)
            visits = [r for r in ev.records if r["kind"] == "visit" and r["src"] == "live" and r["art"] == pool[0]["art"]]
            extra = [("distinct_hosts", str(len(hosts)))] + ([("visit_rows", str(len(visits)))] if visits else [])
            noun = (m.group("noun") if m and m.groupdict().get("noun") else "")
            opts = (extra[:1] + opts + extra[1:]) if "site" in noun else (opts + extra[::-1]) if "entr" in noun else (opts + extra)
        if gone:
            opts.append(("with_recovered", str(n + len(gone))))
        if len({v for _, v in opts}) == 1 and (db is None or db.carve_done):
            return finish(("plain", str(n)), shape)
        seen_v, uniq = set(), []
        for name, v in opts:                # one option per number
            if v not in seen_v:
                seen_v.add(v)
                uniq.append((name, v))
        return finish(("options", uniq), shape)
    chosen = select(pool, q, ev.files, field)
    if not chosen:
        return None
    reads = []
    for r in chosen:
        rd = _readings(field, r, hay, q)
        if rd is None or (rd[0] == "time" and rd[1][1] is None):
            return None
        if rd[0] == "time":
            rd = ("time", (rd[1][0], rd[1][1]))
        elif field in _URL_FIELDS and (_HOST_FIRST.search(hay) or _HOSTISH.search(hay)
                                       and not re.search(r"\burls?\b|\blinks?\b|\baddress\b", hay)):
            rd = _with_host(rd, _HOST_FIRST.search(hay) is not None)
            if rd is None:
                return None
        if rd not in reads:
            reads.append(rd)
            if len(reads) > 1:
                return None                 # two rows, two answers (and no walk over 20000 of them)
    if len(reads) != 1:
        return None
    shapes = {r["shape"] for r in chosen}
    if partial and not forced:              # a table that was not read whole: its other rows are unseen
        return finish(reads[0], shapes.pop() if len(shapes) == 1 else "mixed", True, "partial_read")
    return finish(reads[0], shapes.pop() if len(shapes) == 1 else "mixed", forced)


# ---- the runner contract ---------------------------------------------------------------------------------

_Q_WORDS = re.compile(r"\b(?:browser|browsing|history|chrome|chromium|edge|firefox|safari|sqlite|database|cookies?|"
                      r"downloads?|downloaded|visit(?:s|ed)?|visit count|search(?:ed)? (?:term|for)|extension|manifest|"
                      r"permissions?|crx|login data|saved (?:password|username|credential)s?|leveldb|local storage|"
                      r"wal|write-ahead|journal|deleted (?:row|record|message|entry)|sms|whatsapp|imessage|fossil|quarantine)\b", re.I)


def _is_artifact(name: str, data: bytes) -> str:
    """A cheap look, without opening anything: 'sqlite', 'wal', 'crx', 'manifest', 'leveldb',
    'logins', or ''."""
    if data[:16] == SQLITE_MAGIC:
        return "sqlite"
    if data[:4] in (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83"):
        return "wal"
    if data[:4] == b"Cr24":
        return "crx"
    tail = _tail(name)
    if Path(tail).name == "manifest.json" and b'"manifest_version"' in data[:200_000]:
        return "manifest"
    if is_leveldb(name, data):
        return "leveldb"
    if data.lstrip()[:1] == b"{" and b"encryptedUsername" in data[:2_000_000]:
        return "logins"
    return ""


_KNOWN_TABLES = (b"visit_count", b"downloads_url_chains", b"keyword_search_terms", b"username_value", b"host_key",
                 b"moz_places", b"moz_cookies", b"moz_formhistory", b"history_visits", b"LSQuarantineEvent",
                 b"key_remote_jid", b"is_from_me", b"rcvfrom", b"webappsstore2", b"autofill")


def signals(questions, files) -> float:
    """0..1: how strongly a delivery and its questions look like this category. Cheap: magic bytes,
    table names as byte strings, and the questions' words; nothing is opened."""
    kinds = [(_is_artifact(k, v), v) for k, v in files.items()]
    kinds = [(k, v) for k, v in kinds if k]
    score = 0.0
    if any(k == "sqlite" and any(t in v[:4_000_000] for t in _KNOWN_TABLES) for k, v in kinds):
        score = 0.6
    elif any(k in ("crx", "manifest", "leveldb", "logins") for k, _ in kinds):
        score = 0.5
    elif any(k == "wal" for k, _ in kinds):
        score = 0.35
    elif any(k == "sqlite" for k, _ in kinds):
        score = 0.15
    qs = list(questions or [])
    if qs:
        hits = sum(1 for q in qs if _Q_WORDS.search(_hay(q)))
        share = hits / len(qs)
        score += (0.4 if score else 0.2) * share
    return round(min(1.0, score), 3)


def solve_set(questions, files, ctx) -> dict:
    out = {(q.get("qid") or q.get("id")): None for q in questions}
    if not any(_is_artifact(k, v) for k, v in files.items()):
        return out
    wanted = [q for q in questions if classify(q) is not None]
    if not wanted:
        return out
    try:
        ev = Evidence(files)
    except Exception:
        return out
    if isinstance(ctx, dict):
        ctx.setdefault("partial", {})
    for q in wanted:
        qid = q.get("qid") or q.get("id")
        try:
            out[qid] = answer(q, ev)
        except Exception:               # a fact that cannot be read is no answer
            out[qid] = None
        if isinstance(ctx, dict) and out[qid] is not None:
            ctx["partial"][qid] = out[qid]
    return out


# ---- the command ---------------------------------------------------------------------------------------

def _show(v, width=110) -> str:
    if isinstance(v, bytes):
        v = f"<{len(v)} bytes {protection(v) or 'blob'} {v[:12].hex()}>"
    s = str(v).replace("\n", "\\n")
    return s if len(s) <= width else s[:width - 3] + "..."


def _when(t) -> str:
    raw, dt = t
    return "" if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%SZ") + f" (raw {raw})"


def load_paths(paths) -> dict:
    """{name: bytes} of files and folders given on the command line; zip members too."""
    files = {}
    for p in map(Path, paths):
        items = [x for x in sorted(p.rglob("*")) if x.is_file()] if p.is_dir() else [p]
        for x in items:
            name = str(x.relative_to(p.parent)) if p.is_dir() else x.name
            data = x.read_bytes()
            files[name] = data
            if data[:4] == b"PK\x03\x04":
                try:
                    zf = zipfile.ZipFile(io.BytesIO(data))
                    for n in zf.namelist():
                        if not n.endswith("/") and zf.getinfo(n).file_size < 64_000_000:
                            try:
                                files[f"{name}{ARROW}{n}"] = zf.read(n)
                            except (RuntimeError, zipfile.BadZipFile, NotImplementedError):
                                pass
                except zipfile.BadZipFile:
                    pass
    return files


def report(files: dict, limit: int = 25) -> str:
    ev = Evidence(files)
    L = [f"sqlite_artifacts triage: {len(files)} file(s), signal {signals([], files)}"]
    for key, db in ev.dbs.items():
        pg = db.pages
        L.append("")
        L.append(f"== {key}: {ev.kinds[key]}" + (f"  [library: {db.error}]" if db.error else ""))
        if pg is not None:
            L.append(f"   page size {pg.page_size}, {pg.count} pages, text {pg.enc}, freelist {len(pg.freelist_pages())} page(s), "
                     f"wal frames {len(pg.frames)} ({sum(1 for f in pg.frames if not f['valid'])} stale), "
                     f"journal pages {len(pg.journal)}" + ("" if db.carve_done else "  [carve stopped early]"))
        for t, rows in db.tables.items():
            L.append(f"   table {t}: {len(rows)} row(s); columns " + ", ".join(c[0] for c in db.columns.get(t, [])))
        if ev.kinds[key] == "sqlite":
            for t, rows in db.tables.items():
                for r in rows[:5]:
                    L.append(f"     {t}#{r['_rowid']}: " + _show({k: v for k, v in r.items() if not k.startswith('_')}, 200))
        if db.recovered:
            L.append(f"   RECOVERED rows (not in the live view; answered unsure): {len(db.recovered)}")
            for r in db.recovered[:limit]:
                body = r.get("_values") if r["_table"] is None else {k: v for k, v in r.items() if not k.startswith("_")}
                L.append(f"     [{r['_src']}] {r['_table'] or '|'.join(r['_tables'])}#{r['_rowid']}: " + _show(body, 220))
        if db.strings:
            L.append(f"   strings in unallocated space: {len(db.strings)}; " + " | ".join(_show(s, 60) for s in db.strings[:8]))
        if ev.kinds[key] == "fossil_repository":
            blobs = fossil_blobs(db)
            L.append(f"   fossil blobs: {len(blobs)} readable")
            for rid, c in list(blobs.items())[:limit]:
                L.append(f"     rid {rid}: {len(c)} bytes: " + _show(c[:80].decode('utf-8', 'replace'), 90))
            note = fossil_notable(blobs)
            L.append(f"   fossil file contents (artifacts that are not manifests): {note['files']}")
            for rid, text in note["flags"]:
                L.append(f"     FLAG-LIKE in rid {rid}: " + _show(text, 120))
            for rid, size, head in note["odd"]:
                L.append(f"     ODD ONE OUT rid {rid}: {size} bytes (no other file content has this size): " + _show(head, 90))
    by_kind = {}
    for r in ev.records:
        by_kind.setdefault(r["kind"], []).append(r)
    for kind, recs in by_kind.items():
        L.append("")
        L.append(f"-- {kind}: {len(recs)} record(s)")
        for r in recs[:limit]:
            f = {k: v for k, v in r["f"].items() if v not in (None, "", [])}
            times = " ".join(f"{k}={_when(v)}" for k, v in r["t"].items() if v[1] is not None)
            L.append(f"   [{r['src']}] " + _show(f, 240) + (f"  {times}" if times else ""))
    staged = ev.staged()
    if staged:
        L.append("")
        L.append(f"-- decoded cells: {len(staged)}")
        for r, cell, chain, text in staged[:limit]:
            L.append(f"   [{r['src']}] {r['kind']}.{cell} via {chain}: " + _show(text, 200))
    for e in ev.extensions:
        L.append("")
        L.append(f"== extension {e['where']}: {e['name']} {e['version']} (manifest v{e['manifest_version']})")
        L.append("   ids: " + (", ".join(f"{h}={i}" for h, i in e["ids"]) or "none (no key in the manifest, no CRX, no id folder)"))
        for k in ("permissions", "host_permissions", "optional_permissions", "service_worker", "background_scripts",
                  "background_page", "content_scripts", "content_matches", "update_url"):
            if e[k]:
                L.append(f"   {k}: {_show(e[k], 200)}")
    if ev.storage:
        L.append("")
        L.append(f"-- storage records (LevelDB, Local Storage): {len(ev.storage)}")
        for s in ev.storage[:limit * 2]:
            L.append(f"   [{s['state']}] {Path(_tail(s['file'])).name} seq={s['seq']} origin={s['origin']} "
                     f"{_show(s['key'], 60)} = {_show(s['value'], 120)}")
    return "\n".join(L)


def main(argv) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.split("\n\n")[0] + "\n\n  " + "sqlite_artifacts.py <file or folder>...", file=sys.stderr)
        return 2
    missing = [p for p in argv if not os.path.exists(p)]
    if missing:
        print(f"sqlite_artifacts.py: no such file: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(report(load_paths(argv)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
