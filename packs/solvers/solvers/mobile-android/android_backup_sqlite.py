#!/usr/bin/env python3
"""Android backup (.ab) to WAL-aware SQLite recovery, with a BLOB decoder ladder, offline (B-085).

    python -m ctf run mobile_android.android_backup_sqlite <challenge_dir> [--opt password=...]
    tools/ctfpy solvers/mobile-android/android_backup_sqlite.py <file or folder> [--event slug]

One chain, no model, nothing executed:

1. Every Android backup in the handout (`ANDROID BACKUP` magic) is unwrapped: the header is checked
   by `toolkits.ff_androidab_backup.parse_header` (a malformed one is a named error), the payload is
   inflated (bounded) and its tar members are read. The strict tar inventory
   (`ff_androidab_backup.inventory_tar`) is tried first; a tar it refuses (an adb backup often has no
   end-of-archive blocks) is read leniently and the refusal is named in the notes, never dropped.
   An encrypted backup (`AES-256`) without `password` is reported `blocked` with the reason; with
   `password` it is decrypted (PBKDF2-HMAC-SHA1 user key, AES-256-CBC master key blob, then the
   payload). A wrong password is a named error. Nothing is written outside the output folder, member
   paths are normalised and a `..` or absolute path is refused.
2. Every SQLite database (by magic, in the backup or loose in the handout) is paired with the `-wal`
   and `-journal` beside it at the same path, and read by `toolkits.sqlite_artifacts.Database`: the
   committed view (main file plus the valid WAL frames), and the rows only a superseded or stale WAL
   frame, a journal page, a freelist page or unallocated space still holds.
3. A diff of the main file alone against the committed view (rows the WAL added, removed or
   changed), so a message edited or withdrawn after the last checkpoint shows both versions.
4. Every BLOB cell (live, recovered, or only in the main file) goes down a decoder ladder: magic sniff
   (gzip, zlib, bz2, xz, nested SQLite, known file types), protobuf (each length-delimited field read
   on), raw deflate (wbits -15), UTF-8 / UTF-16LE text; text cells and decoded text go through
   `toolkits.embedded_decode.find_blobs` (base64/32/hex substrings); text that still reads as an
   encoding goes to the shared codec graph (`ctf.codec`, core codecs plus the warmups pack, which is
   crib_decode's decoder list) with the event flag format as its oracle.

Result: one distinct flag is `solved`, several are `candidate`; recovered rows, WAL changes or decoded
text with no flag are `unsure` (they are the leads); an encrypted backup that left nothing readable is
`blocked` naming the password; nothing to read is `none`, saying why. CPU time is budgeted
(`budget`, default 30 s, measured with time.process_time).
"""
from __future__ import annotations

import argparse
import bz2
import hashlib
import io
import json
import lzma
import os
import re
import struct
import sys
import tarfile
import time
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

# ctf package import (script runs need the checkout root on sys.path), mirroring the sibling engines.
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt
import ctf  # noqa: F401  (installs the dotted-lane finder)
from solvers.toolkits import embedded_decode as _embedded
from solvers.toolkits import ff_androidab_backup as _ab
from solvers.toolkits import sqlite_artifacts as _sa

ENGINE_ID = "mobile_android.android_backup_sqlite"
AB_MAGIC = b"ANDROID BACKUP\n"
SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGICS = (b"\x37\x7f\x06\x82", b"\x37\x7f\x06\x83")
JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"
SIDE_SUFFIXES = ("-wal", "-journal")

MAX_AB_BYTES = 512 << 20          # one backup file read
MAX_TAR_BYTES = 1 << 30           # its inflated tar
MAX_FILE = 256 << 20              # one loose database / side file read
MAX_MEMBERS = 20000
MAX_DATABASES = 200
MAX_DEPTH = 6                     # decoder ladder depth
MAX_NODES = 256                   # ladder states per BLOB
MAX_INFLATE = 16 << 20            # one decompression step
MAX_READINGS = 400                # decoded readings kept in the report
MAX_GRAPH_BLOBS = 64
MAX_EVIDENCE = 24
MIN_TEXT = 4
DEFAULT_BUDGET_S = 30.0           # CPU seconds for one run
GRAPH_SECONDS = 4.0               # wall seconds the codec graph may take in one run (its own deadline)
GRAPH_BLOB_SECONDS = 1.0
SKIP_DIRS = {"recon", ".git", "__pycache__"}
SKIP_FILES = {".sweep.json", ".sweep-owner", ".lock"}
_SOLVE_OPTS = {"password", "budget", "out", "report", "graph_seconds"}

_ENCODED_TEXT = re.compile(r"[A-Za-z0-9+/=_\-.:%~!*'(),;@$&#{}\[\]|^<>?\\\"` ]{12,4096}")
_FILE_MAGICS = (
    (b"\x89PNG\r\n\x1a\n", "png"), (b"\xff\xd8\xff", "jpeg"), (b"GIF8", "gif"), (b"%PDF-", "pdf"),
    (b"PK\x03\x04", "zip"), (b"RIFF", "riff"), (b"\x7fELF", "elf"), (b"dex\n", "dex"),
    (b"OggS", "ogg"), (b"ID3", "mp3"), (b"bplist00", "bplist"),
)


class BackupError(ValueError):
    """A backup that cannot be read, with the reason (encrypted without a password, wrong password,
    malformed header, over a size limit)."""


class EncryptedBackup(BackupError):
    """An AES-256 backup and no password was given."""


# ---- step 1: the backup ----------------------------------------------------------------------------------

@dataclass
class Backup:
    name: str
    header: dict
    members: dict = field(default_factory=dict)       # {normalised member path: bytes}
    notes: list = field(default_factory=list)
    strict: bool = True                               # the strict tar inventory accepted it


def safe_member_path(name: str) -> str | None:
    """The member path, normalised (no `.` parts, no leading `./`), or None for an absolute path, a
    `..` part, an empty name or a NUL: such a member is never written or paired."""
    if not isinstance(name, str) or not name or "\x00" in name or name.startswith(("/", "\\")):
        return None
    parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts or any(p == ".." for p in parts) or re.match(r"^[A-Za-z]:$", parts[0]):
        return None
    return "/".join(parts)


def _inflate(payload: bytes, limit: int, notes: list, what: str) -> bytes:
    obj = zlib.decompressobj()
    try:
        out = obj.decompress(payload, limit + 1)
    except zlib.error as e:
        raise BackupError(f"{what}: the payload is not a zlib stream ({e})") from None
    if len(out) > limit or obj.unconsumed_tail:
        raise BackupError(f"{what}: the inflated tar is over {limit} bytes (MAX_TAR_BYTES)")
    if not obj.eof:
        notes.append(f"{what}: the zlib stream is truncated; read the {len(out)} bytes it gave")
    elif obj.unused_data:
        notes.append(f"{what}: {len(obj.unused_data)} bytes after the zlib stream ignored")
    return out


def _aes_cbc(key: bytes, iv: bytes, data: bytes, what: str) -> bytes:
    try:
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as e:
        raise BackupError(f"decrypting an encrypted backup needs py:cryptography (not importable: {e})") from None
    if not data or len(data) % 16:
        raise BackupError(f"{what}: the ciphertext is not whole AES blocks")
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    raw = dec.update(data) + dec.finalize()
    unpad = padding.PKCS7(128).unpadder()
    try:
        return unpad.update(raw) + unpad.finalize()
    except ValueError:
        raise BackupError(f"{what}: bad padding (wrong password)") from None


def decrypt_payload(header: dict, payload: bytes, password: str) -> bytes:
    """The plain (still compressed when the header says so) payload of an AES-256 backup.

    Android's scheme: user key = PBKDF2-HMAC-SHA1(password, user salt, rounds, 32 bytes); the master
    key blob, AES-256-CBC under the user key and user IV, holds [len][master IV][len][master key]
    [len][checksum]; the payload is AES-256-CBC under the master key and IV. The master key checksum
    is not checked (its key derivation differs by backup version); a wrong password shows as bad
    padding or a blob of the wrong shape, both named."""
    c = header.get("crypto")
    if not c:
        raise BackupError("the header names no AES parameters")
    user_key = hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), bytes.fromhex(c["user_salt_hex"]),
                                   int(c["kdf_rounds"]), 32)
    blob = _aes_cbc(user_key, bytes.fromhex(c["user_iv_hex"]), bytes.fromhex(c["encrypted_key_blob_hex"]),
                    "the master key blob")
    parts, p = [], 0
    for _ in range(3):
        if p >= len(blob):
            break
        n = blob[p]
        parts.append(blob[p + 1:p + 1 + n])
        p += 1 + n
    if len(parts) != 3 or len(parts[0]) != 16 or len(parts[1]) != 32:
        raise BackupError("the master key blob has the wrong shape (wrong password)")
    return _aes_cbc(parts[1], parts[0], payload, "the backup payload")


def _strict_members(tar: bytes, what: str) -> dict:
    inv = _ab.inventory_tar(tar, limits=_ab.Limits(max_output=MAX_TAR_BYTES, max_member=MAX_FILE,
                                                   max_total=MAX_TAR_BYTES, max_members=MAX_MEMBERS))
    out = {}
    for m in inv["members"]:
        if m["type"] != "file":
            continue
        path = safe_member_path(m["path"])
        if path is not None:
            out[path] = tar[m["data_offset"]:m["data_offset"] + m["size"]]
    return out


def _lenient_members(tar: bytes, what: str, notes: list) -> dict:
    out, refused, total = {}, 0, 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as tf:
            for info in tf:
                if len(out) >= MAX_MEMBERS:
                    notes.append(f"{what}: stopped at {MAX_MEMBERS} members (MAX_MEMBERS)")
                    break
                if not info.isfile():
                    continue
                path = safe_member_path(info.name)
                if path is None or info.size > MAX_FILE or total + info.size > MAX_TAR_BYTES:
                    refused += 1
                    continue
                fh = tf.extractfile(info)
                if fh is None:
                    continue
                out[path] = fh.read()
                total += info.size
    except (tarfile.TarError, EOFError, OSError) as e:
        notes.append(f"{what}: the tar ends early ({type(e).__name__}: {e}); {len(out)} member(s) read before it")
    if refused:
        notes.append(f"{what}: {refused} member(s) refused (unsafe path or over the size limit)")
    return out


def open_backup(data: bytes, name: str, password: str | None = None) -> Backup:
    """The members of one Android backup. BackupError (EncryptedBackup without a password) names why
    a backup cannot be read."""
    if len(data) > MAX_AB_BYTES:
        raise BackupError(f"{name}: over {MAX_AB_BYTES} bytes (MAX_AB_BYTES)")
    try:
        header = _ab.parse_header(data, limits=_ab.Limits(max_input=MAX_AB_BYTES, max_output=MAX_TAR_BYTES))
    except _ab.AndroidBackupError as e:
        raise BackupError(f"{name}: not a readable Android backup header ({e})") from None
    bk = Backup(name, {k: v for k, v in header.items() if k != "crypto"})
    payload = data[header["data_offset"]:]
    if header["encryption"] != "none":
        c = header["crypto"]
        bk.header["kdf_rounds"] = c["kdf_rounds"]
        if not password:
            raise EncryptedBackup(
                f"{name}: encrypted Android backup (version {header['version']}, {header['encryption']}, "
                f"PBKDF2-HMAC-SHA1 with {c['kdf_rounds']} rounds): it needs the backup password; rerun with "
                f"--opt password=<password>")
        try:
            payload = decrypt_payload(header, payload, password)
        except BackupError as e:
            raise BackupError(f"{name}: {e}") from None
        bk.notes.append(f"{name}: decrypted with the given password")
    tar = _inflate(payload, MAX_TAR_BYTES, bk.notes, name) if header["compressed"] else payload
    try:
        bk.members = _strict_members(tar, name)
    except _ab.AndroidBackupError as e:
        bk.strict = False
        bk.notes.append(f"{name}: the strict tar inventory refused it ({e}); members read leniently")
        bk.members = _lenient_members(tar, name, bk.notes)
    return bk


# ---- step 2: the files and the databases -----------------------------------------------------------------

def _head(p: Path, n: int = 16) -> bytes:
    with open(p, "rb") as fh:
        return fh.read(n)


def handout_files(target: Path) -> list[tuple[str, Path]]:
    """[(relative name, path)] of the files to read: the sweep's scratch copy (`unpacked/`) when there is
    one, else `files/`, else the folder itself (a single file is itself); recon output, sweep state and
    links left out."""
    target = Path(target)
    if target.is_file():
        return [(target.name, target)]
    if not target.is_dir():
        raise FileNotFoundError(f"no such challenge folder or file: {target}")
    root = next((target / d for d in ("unpacked", "files") if (target / d).is_dir()), target)
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (here / d).is_symlink())
        for n in sorted(filenames):
            p = here / n
            if n in SKIP_FILES or p.is_symlink() or not p.is_file():
                continue
            out.append((str(p.relative_to(target)), p))
    return out


@dataclass
class DbItem:
    name: str
    data: bytes
    wal: bytes | None = None
    journal: bytes | None = None
    wal_name: str | None = None
    journal_name: str | None = None
    origin: str = "handout"           # handout | backup | blob


def pair_databases(files: dict, origin: Callable[[str], str] = lambda k: "handout") -> tuple[list, list]:
    """([DbItem], [notes]) for {name: bytes}: each SQLite file with the `-wal` and `-journal` stored at its
    own name plus the suffix (never a same-named file elsewhere: SQLite ties a WAL to its database by
    salts alone, so a stranger's frames would be replayed). A WAL or journal with no database beside it
    is named."""
    items, notes, used = [], [], set()
    for key in sorted(files):
        data = files[key]
        if data[:16] != SQLITE_MAGIC:
            continue
        it = DbItem(key, data, origin=origin(key))
        if key + "-wal" in files:
            it.wal, it.wal_name = files[key + "-wal"], key + "-wal"
            used.add(it.wal_name)
            if it.wal[:4] not in WAL_MAGICS:
                notes.append(f"{it.wal_name}: no WAL magic; its frames will not parse")
        if key + "-journal" in files:
            it.journal, it.journal_name = files[key + "-journal"], key + "-journal"
            used.add(it.journal_name)
        items.append(it)
    for key in sorted(files):
        if key in used:
            continue
        if files[key][:4] in WAL_MAGICS or key.endswith("-wal"):
            notes.append(f"{key}: a WAL with no database at {key[:-4] if key.endswith('-wal') else '<its name>-wal'}; "
                         "its frames were not read")
        elif files[key][:8] == JOURNAL_MAGIC:
            notes.append(f"{key}: a rollback journal with no database beside it; not read")
    return items, notes


# ---- step 4: the BLOB decoder ladder ---------------------------------------------------------------------

@dataclass
class Leaf:
    chain: tuple
    kind: str                 # text | sqlite | file:<type> | bytes
    data: bytes
    text: str = ""


def _as_text(b: bytes, min_len: int = MIN_TEXT) -> tuple[str, str] | None:
    """(encoding, text) when the bytes read as text: UTF-8 with no control characters (at least
    `min_len` bytes), or UTF-16LE of printable characters."""
    if len(b) >= min_len:
        try:
            s = b.decode("utf-8")
            if all(c.isprintable() or c in "\t\r\n" for c in s):
                return "utf-8", s
        except UnicodeDecodeError:
            pass
    if len(b) >= 2 * MIN_TEXT and len(b) % 2 == 0 and b[1::2].count(0) * 4 >= len(b) * 3 // 2:
        try:
            s = b.decode("utf-16-le")
            if all(c.isprintable() or c in "\t\r\n" for c in s):
                return "utf-16le", s
        except UnicodeDecodeError:
            pass
    return None


def _uvarint(buf: bytes, p: int) -> tuple[int, int]:
    v = shift = 0
    while True:
        if p >= len(buf) or shift > 63:
            raise ValueError("varint")
        b = buf[p]
        p += 1
        v |= (b & 0x7F) << shift
        if not b & 0x80:
            return v, p
        shift += 7


def protobuf_fields(buf: bytes) -> list[tuple[int, int, object]] | None:
    """[(field number, wire type, value)] when the whole buffer parses as one protobuf message (wire types
    0, 1, 2, 5; field numbers 1 .. 2^29-1; every length in bounds), else None."""
    out, p = [], 0
    try:
        while p < len(buf):
            tag, p = _uvarint(buf, p)
            num, wire = tag >> 3, tag & 7
            if not 1 <= num < (1 << 29):
                return None
            if wire == 0:
                v, p = _uvarint(buf, p)
            elif wire == 1:
                if p + 8 > len(buf):
                    return None
                v, p = buf[p:p + 8], p + 8
            elif wire == 2:
                n, p = _uvarint(buf, p)
                if p + n > len(buf):
                    return None
                v, p = buf[p:p + n], p + n
            elif wire == 5:
                if p + 4 > len(buf):
                    return None
                v, p = buf[p:p + 4], p + 4
            else:
                return None
            out.append((num, wire, v))
    except ValueError:
        return None
    return out or None


def _bounded(fn, data: bytes) -> bytes | None:
    try:
        out = fn(data)
    except Exception:            # hostile bytes: no reading
        return None
    return out if out else None


def _gunzip(b: bytes) -> bytes | None:
    obj = zlib.decompressobj(31)
    out = obj.decompress(b, MAX_INFLATE)
    return out if obj.eof else None


def _zlib(b: bytes) -> bytes | None:
    obj = zlib.decompressobj(15)
    out = obj.decompress(b, MAX_INFLATE)
    return out if obj.eof else None


def _raw_deflate(b: bytes) -> bytes | None:
    obj = zlib.decompressobj(-15)
    out = obj.decompress(b, MAX_INFLATE)
    return out if obj.eof and not obj.unused_data else None


def _bz2(b: bytes) -> bytes | None:
    obj = bz2.BZ2Decompressor()
    out = obj.decompress(b, MAX_INFLATE)
    return out if obj.eof else None


def _xz(b: bytes) -> bytes | None:
    obj = lzma.LZMADecompressor()
    out = obj.decompress(b, MAX_INFLATE)
    return out if obj.eof else None


def decode_blob(data: bytes, *, max_depth: int = MAX_DEPTH, max_nodes: int = MAX_NODES) -> list[Leaf]:
    """Every leaf the ladder reaches from one BLOB, chain first-to-last: decompression by magic (gzip,
    zlib, bz2, xz), a nested SQLite file or a known file type (a leaf), text (UTF-8 or UTF-16LE),
    protobuf (each length-delimited field read on, `protobuf.<n>`), and raw deflate tried on bytes that
    are no text. The input is bytes from a challenge database: decoded, never run."""
    leaves, seen, nodes = [], set(), 0
    todo = [((), bytes(data))]
    while todo and nodes < max_nodes:
        chain, b = todo.pop(0)
        if not b or (chain, b) in seen:
            continue
        seen.add((chain, b))
        nodes += 1
        if b[:16] == SQLITE_MAGIC:
            leaves.append(Leaf(chain, "sqlite", b))
            continue
        kind = next((k for m, k in _FILE_MAGICS if b.startswith(m)), None)
        if kind:
            leaves.append(Leaf(chain, f"file:{kind}", b))
            continue
        if len(chain) >= max_depth:
            leaves.append(Leaf(chain, "bytes", b))
            continue
        nxt = []
        if b[:2] == b"\x1f\x8b":
            nxt.append(("gzip", _bounded(_gunzip, b)))
        elif len(b) >= 2 and b[0] & 0x0F == 8 and (b[0] << 8 | b[1]) % 31 == 0:
            nxt.append(("zlib", _bounded(_zlib, b)))
        elif b[:3] == b"BZh":
            nxt.append(("bz2", _bounded(_bz2, b)))
        elif b[:6] == b"\xfd7zXZ\x00":
            nxt.append(("xz", _bounded(_xz, b)))
        nxt = [(step, out) for step, out in nxt if out]
        # a field inside a decoded structure is text from one byte on ("hq"); a whole BLOB from MIN_TEXT
        text = _as_text(b, 1 if chain else MIN_TEXT) if not nxt else None
        if text is not None:
            enc, s = text
            leaves.append(Leaf(chain + ((enc,) if enc != "utf-8" else ()), "text", b, s))
        if not nxt:
            # Text is read as protobuf only when it starts with a control byte (the tag of fields 1-3:
            # a message of short string fields is printable as a whole, so both readings are kept);
            # prose that happens to parse as protobuf is not split into fields.
            fields = protobuf_fields(b) if text is None or b[0] < 0x20 else None
            if fields and any(w == 2 and v for _, w, v in fields):
                for num, wire, v in fields:
                    if wire == 2 and v:
                        nxt.append((f"protobuf.{num}", v))
            if text is None and not fields:
                raw = _bounded(_raw_deflate, b)
                if raw:
                    nxt.append(("raw-deflate", raw))
        if nxt:
            todo.extend((chain + (step,), out) for step, out in nxt)
        elif text is None:
            leaves.append(Leaf(chain, "bytes", b))
    return leaves


# ---- step 3 and the run ------------------------------------------------------------------------------------

def _cells(row: dict) -> dict:
    if row.get("_table") is None and "_values" in row:
        return {f"c{i}": v for i, v in enumerate(row["_values"])}
    return {k: v for k, v in row.items() if not k.startswith("_")}


def _source_kind(src: str, wal: bool = True, journal: bool = False) -> str:
    """The kind of a row's source. `wal`: the database has a WAL beside it, so a page image of the main
    file ('main page N' from sqlite_artifacts) is the page as it was before the WAL's changes. With only a
    rollback journal beside it (`journal`, no WAL) the main file already holds the state after the change
    and the journal holds the before-pages (sqlite_artifacts does not apply it), so a main page is named
    as such, not as a before-image."""
    if src == "live":
        return "live"
    if src.startswith("wal frame"):
        return "stale WAL frame" if "(stale)" in src else "superseded WAL frame"
    if src.startswith("journal"):
        return "rollback journal"
    if src.startswith("freelist"):
        return "freelist page"
    if src.startswith("main file"):
        return "main file before the WAL"
    if src.startswith("main page"):
        if wal:
            return "main file before the WAL"
        return "main file (journal beside it)" if journal else "main file page"
    if "unallocated" in src or "freeblock" in src:
        return "unallocated space"
    return "page image"


def diff_views(before, after) -> list[dict]:
    """The rows the WAL (and journal) changed: the main file alone (`before`) against the committed view
    (`after`), by table and rowid. [{table, rowid, change, columns, before, after}]."""
    out = []
    for table in sorted(set(before.tables) | set(after.tables)):
        if table.startswith("sqlite_"):
            continue
        b = {r["_rowid"]: r for r in before.tables.get(table, []) if r["_rowid"] is not None}
        a = {r["_rowid"]: r for r in after.tables.get(table, []) if r["_rowid"] is not None}
        for rowid in sorted(set(b) | set(a)):
            rb, ra = b.get(rowid), a.get(rowid)
            if rb is None:
                out.append({"table": table, "rowid": rowid, "change": "added by the WAL", "columns": [],
                            "before": None, "after": _cells(ra)})
            elif ra is None:
                out.append({"table": table, "rowid": rowid, "change": "removed by the WAL", "columns": [],
                            "before": _cells(rb), "after": None})
            else:
                cb, ca = _cells(rb), _cells(ra)
                cols = [k for k in sorted(set(cb) | set(ca)) if cb.get(k) != ca.get(k)]
                if cols:
                    out.append({"table": table, "rowid": rowid, "change": "changed by the WAL", "columns": cols,
                                "before": cb, "after": ca})
    return out


def _show(v, width: int = 160) -> str:
    if isinstance(v, (bytes, bytearray)):
        v = f"<{len(v)} bytes {bytes(v[:16]).hex()}>"
    s = str(v).replace("\n", "\\n")
    return s if len(s) <= width else s[:width - 3] + "..."


def _jsonable(v):
    if isinstance(v, (bytes, bytearray)):
        return {"bytes": len(v), "sha256": hashlib.sha256(v).hexdigest()[:16], "head_hex": bytes(v[:32]).hex()}
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


class Run:
    """One analysis: the state the steps share (flag format, budget, findings)."""

    def __init__(self, ff, *, budget: float = DEFAULT_BUDGET_S, graph_seconds: float = GRAPH_SECONDS,
                 clock: Callable[[], float] = time.process_time, graph=None):
        self.ff = ff
        self.clock = clock
        self.t0 = clock()
        self.budget = float(budget)
        # The codec graph bounds itself by a wall-clock deadline (ctf.codec): one per run, and one per
        # text at a quarter of it (at least GRAPH_BLOB_SECONDS), so a single text cannot take it all.
        self.graph_deadline = time.monotonic() + float(graph_seconds)
        self.graph_blob_seconds = max(GRAPH_BLOB_SECONDS, float(graph_seconds) / 4)
        self._graph = graph
        self.flags: dict[str, list[dict]] = {}       # normalised flag -> where it was found
        self.readings: list[dict] = []
        self.databases: list[dict] = []
        self.backups: list[dict] = []
        self.blocked: list[str] = []
        self.notes: list[str] = []
        self.spent = False
        self.graph_runs = 0
        self._decoded: set = set()

    # -- budget and flags
    def left(self) -> bool:
        if self.clock() - self.t0 > self.budget:
            self.spent = True
        return not self.spent

    def _norm(self, f: str) -> str:
        try:
            return self.ff.normalize(f)
        except ValueError:
            return f

    def add_flag(self, flag: str, where: dict) -> None:
        body = flag[flag.find("{") + 1:-1]
        if any(ord(c) < 0x20 or ord(c) > 0x7E for c in body):
            return                                # a flag shape across binary: not a flag
        self.flags.setdefault(self._norm(flag), []).append(where)

    def scan(self, data, where: dict) -> list[str]:
        found = self.ff.find_flags(data)
        for f in found:
            self.add_flag(f, where)
        return found

    # -- the codec graph
    def graph(self):
        if self._graph is None:
            from ctf.codec import Graph, core, pack
            try:
                codecs = core() + pack.load("warmups")
            except Exception as e:                  # PackMissing / PackLoadError: named, core codecs only
                self.notes.append(f"codec graph: the warmups pack (crib_decode) did not load ({type(e).__name__}: "
                                  f"{e}); core codecs only")
                codecs = core()
            self._graph = Graph(codecs)
        return self._graph

    def graph_decode(self, text: str, where: dict, oracle) -> None:
        if self.graph_runs >= MAX_GRAPH_BLOBS or time.monotonic() >= self.graph_deadline or not self.left():
            return
        self.graph_runs += 1
        res = self.graph().search(text.encode("utf-8", "surrogateescape"), oracle,
                                  deadline=min(self.graph_deadline, time.monotonic() + self.graph_blob_seconds))
        for h in res.hits:
            w = dict(where, chain=where["chain"] + [f"graph:{h.how}"])
            self.add_flag(h.answer, w)
            self._reading(w, h.data.decode("latin-1"), [h.answer])

    def _reading(self, where: dict, text: str, flags: list) -> None:
        if len(self.readings) < MAX_READINGS:
            self.readings.append(dict(where, text=text[:400], flags=list(flags)))

    # -- cells
    def text_cell(self, text: str, where: dict, oracle, *, decoded: bool) -> None:
        found = self.scan(text, where)
        if decoded:
            self._reading(where, text, found)
        if found or len(text) < 16:
            return
        hits = _embedded.find_blobs(text, flag_re=self.ff.bregex, alignments=True)
        done = set()
        for h in hits:
            if h["decoded"] in done or len(done) >= 8:
                continue                      # base64 and base64url often read the same run
            done.add(h["decoded"])
            w = dict(where, chain=where["chain"] + [f"embedded:{h['encoding']}@{h['offset']}"])
            got = self.scan(h["decoded"], w)
            if got or decoded:
                self._reading(w, h["decoded"].decode("utf-8", "replace"), got)
        if not any(h["flag"] for h in hits) and decoded and _ENCODED_TEXT.fullmatch(text.strip()) \
                and text.count(" ") <= len(text) // 10:
            self.graph_decode(text.strip(), where, oracle)

    def blob_cell(self, blob: bytes, where: dict, oracle, nested: list) -> None:
        key = hashlib.sha256(blob).digest()
        if key in self._decoded:
            return
        self._decoded.add(key)
        self.scan(blob, dict(where, chain=["raw"]))
        for leaf in decode_blob(blob):
            w = dict(where, chain=list(leaf.chain))
            if leaf.kind == "text":
                if leaf.chain or leaf.text.strip():
                    self.text_cell(leaf.text, w, oracle, decoded=True)
            elif leaf.kind == "sqlite":
                nested.append(DbItem(f"{where['db']}:{where['table']}#{where['rowid']}.{where['column']}"
                                     + (f" via {'>'.join(leaf.chain)}" if leaf.chain else ""), leaf.data,
                                     origin="blob"))
            elif leaf.chain:
                got = self.scan(leaf.data, w)
                if got or leaf.kind != "bytes":       # undecoded bytes are no reading unless they hold a flag
                    self._reading(w, f"<{leaf.kind}, {len(leaf.data)} bytes>", got)

    # -- one database
    def database(self, item: DbItem, oracle, depth: int = 0) -> None:
        if not self.left():
            return
        rec = {"name": item.name, "origin": item.origin, "wal": item.wal_name, "journal": item.journal_name}
        self.databases.append(rec)
        try:
            committed = _sa.Database(item.data, item.wal, item.journal, item.name)
        except Exception as e:                       # hostile bytes
            rec["error"] = f"{type(e).__name__}: {e}"
            return
        before = None
        if item.wal is not None or item.journal is not None:
            try:
                before = _sa.Database(item.data, None, None, item.name, carve=False)
            except Exception as e:
                rec["error"] = f"main file alone: {type(e).__name__}: {e}"
        pg = committed.pages
        rec.update({
            "library_error": committed.error,
            "tables": {t: len(rows) for t, rows in committed.tables.items()},
            "wal_frames": len(pg.frames) if pg else 0,
            "stale_frames": sum(1 for f in pg.frames if not f["valid"]) if pg else 0,
            "journal_pages": len(pg.journal) if pg else 0,
            "carve_done": committed.carve_done,
        })
        diff = diff_views(before, committed) if before is not None else []
        rec["wal_diff"] = diff
        side = {"wal": item.wal is not None, "journal": item.journal is not None}
        rec["recovered"] = [{"source": r["_src"], "kind": _source_kind(r["_src"], **side),
                             "table": r["_table"] or "|".join(r.get("_tables", [])), "rowid": r["_rowid"],
                             "cells": _cells(r)} for r in committed.recovered]
        rows = [(r, "live") for t, rs in committed.tables.items() if not t.startswith("sqlite_") for r in rs]
        if before is not None:
            # the main-file side of each WAL change comes before the recovered page images: sqlite_artifacts
            # also recovers the overlaid main page, and a value both hold is credited to the row the diff names
            changed = {(d["table"], d["rowid"]) for d in diff if d["before"] is not None}
            rows += [(r, "main file (before the WAL)") for t, rs in before.tables.items() for r in rs
                     if (t, r["_rowid"]) in changed]
        rows += [(r, r["_src"]) for r in committed.recovered]
        nested: list[DbItem] = []
        seen = set()
        for row, src in rows:
            table = row["_table"] or "|".join(row.get("_tables", []))
            for col, v in _cells(row).items():
                if not isinstance(v, (str, bytes)) or not v:
                    continue
                sig = (table, row["_rowid"], col, v)
                if sig in seen:
                    continue
                seen.add(sig)
                if not self.left():
                    return
                where = {"db": item.name, "table": table, "rowid": row["_rowid"], "column": col, "source": src,
                         "source_kind": _source_kind(src, **side), "chain": []}
                if isinstance(v, bytes):
                    self.blob_cell(v, where, oracle, nested)
                else:
                    self.text_cell(v, where, oracle, decoded=src != "live")
        for s in committed.strings[:400]:
            self.scan(s, {"db": item.name, "table": None, "rowid": None, "column": None,
                          "source": "unallocated strings", "source_kind": "unallocated space", "chain": []})
        for name, b in ((item.name, item.data), (item.wal_name, item.wal), (item.journal_name, item.journal)):
            if b:
                self.scan(b, {"db": item.name, "table": None, "rowid": None, "column": None,
                              "source": f"raw bytes of {name}", "source_kind": "raw bytes", "chain": []})
        if depth < 2:
            for sub in nested[:16]:
                self.database(sub, oracle, depth + 1)


def analyze(target, profile, *, password: str | None = None, budget: float = DEFAULT_BUDGET_S,
            graph_seconds: float = GRAPH_SECONDS, out: Path | None = None,
            clock: Callable[[], float] = time.process_time) -> dict:
    """The whole chain over a challenge folder (or one file). Returns the report dict; `out` (a folder)
    receives the backup members (`members/<backup>/...`) and `report.json`."""
    from ctf.codec import FlagOracle
    ff = flagfmt.for_profile(profile)
    oracle = FlagOracle(profile)
    run = Run(ff, budget=budget, graph_seconds=graph_seconds, clock=clock)
    files: dict[str, bytes] = {}
    origin: dict[str, str] = {}
    seen_ab: set = set()
    listed = handout_files(Path(target))
    for rel, p in listed:
        head = _head(p)
        side = rel.endswith(SIDE_SUFFIXES)
        if not (head.startswith(AB_MAGIC[:14]) or head[:16] == SQLITE_MAGIC or head[:4] in WAL_MAGICS
                or head[:8] == JOURNAL_MAGIC or side):
            continue
        size = p.stat().st_size
        if head.startswith(AB_MAGIC[:14]):
            if size > MAX_AB_BYTES:
                run.blocked.append(f"{rel}: over {MAX_AB_BYTES} bytes (MAX_AB_BYTES); not read")
                continue
            data = p.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest in seen_ab:
                run.notes.append(f"{rel}: the same backup as one already read")
                continue
            seen_ab.add(digest)
            entry = {"file": rel, "sha256": digest}
            run.backups.append(entry)
            try:
                bk = open_backup(data, rel, password)
            except EncryptedBackup as e:
                entry["status"] = "encrypted"
                run.blocked.append(str(e))
                continue
            except BackupError as e:
                entry["status"] = "unreadable"
                run.blocked.append(str(e))
                continue
            entry.update(status="read", header=bk.header, strict_tar=bk.strict, members=len(bk.members),
                         member_paths=sorted(bk.members)[:200])
            run.notes.extend(bk.notes)
            for path, b in bk.members.items():
                key = f"{rel}!{path}"
                files[key], origin[key] = b, "backup"
                if b[:16] != SQLITE_MAGIC and not path.endswith(SIDE_SUFFIXES):
                    run.scan(b, {"db": None, "table": None, "rowid": None, "column": None,
                                 "source": f"backup member {key}", "source_kind": "backup member", "chain": []})
            if out is not None:
                entry["written_to"] = str(write_members(bk, Path(out), run.notes))
        elif size > MAX_FILE:
            run.notes.append(f"{rel}: over {MAX_FILE} bytes (MAX_FILE); not read")
        else:
            files[rel], origin[rel] = p.read_bytes(), "handout"
    items, pair_notes = pair_databases(files, lambda k: origin.get(k, "handout"))
    run.notes.extend(pair_notes)
    if len(items) > MAX_DATABASES:
        run.notes.append(f"{len(items)} databases: read the first {MAX_DATABASES} (MAX_DATABASES)")
    for i, item in enumerate(items[:MAX_DATABASES]):
        if not run.left():
            run.notes.append(f"CPU budget of {budget:g} s spent after {i} of {len(items)} database(s): "
                             "rerun with --opt budget=<seconds>")
            break
        run.database(item, oracle)
    else:
        if run.spent:
            run.notes.append(f"CPU budget of {budget:g} s spent inside the last database: rerun with "
                             "--opt budget=<seconds>")
    report = {
        "engine": ENGINE_ID, "target": str(target), "files": len(listed), "backups": run.backups,
        "databases": run.databases, "readings": run.readings,
        "flags": {f: where[:6] for f, where in run.flags.items()}, "blocked": run.blocked, "notes": run.notes,
        "budget": {"cpu_limit_s": budget, "cpu_used_s": round(clock() - run.t0, 3), "spent": run.spent,
                   "graph_runs": run.graph_runs},
    }
    if out is not None:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / "report.json").write_text(json.dumps(_jsonable(report), indent=2, sort_keys=True),
                                               encoding="utf-8")
    return report


def write_members(bk: Backup, out: Path, notes: list | None = None) -> Path:
    """Write a backup's regular-file members under out/members/<backup name>/ (paths already normalised;
    each one is checked to stay inside that folder). A member the file system refuses (a file that is
    also another member's parent folder, a name too long) is skipped and named in `notes` (the backup's
    own notes when none is given); it is still read from memory."""
    notes = bk.notes if notes is None else notes
    base = (out / "members" / re.sub(r"[^A-Za-z0-9._-]", "_", bk.name)).resolve()
    for path, b in bk.members.items():
        dest = (base / path).resolve()
        if base not in dest.parents:
            raise BackupError(f"{bk.name}: member {path!r} would leave the output folder")
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b)
        except OSError as e:
            notes.append(f"{bk.name}: member {path!r} not written ({type(e).__name__}: {e.strerror or e}); "
                         "it was still read")
    return base


# ---- the contract entry and the command --------------------------------------------------------------------

def _where_text(w: dict) -> str:
    if w.get("table") is None:
        return w["source"]
    chain = ">".join(w.get("chain") or []) or "plain"
    return (f"{w['db']} {w['table']}#{w['rowid']}.{w['column']} ({w['source_kind']}: {w['source']}) "
            f"via {chain}")


def result_of(report: dict):
    from ctf.result import Evidence, SolverResult
    flags = list(report["flags"])
    evidence, notes = [], []
    for f, wheres in report["flags"].items():
        for w in wheres[:3]:
            if len(evidence) < MAX_EVIDENCE:
                evidence.append(Evidence(kind="match", detail=f"{f} in {_where_text(w)}"[:300],
                                         path=w.get("db") or None))
    leads = 0
    for db in report["databases"]:
        frames = f"{db.get('wal_frames', 0)} WAL frame(s) ({db.get('stale_frames', 0)} stale)"
        notes.append(f"{db['name']}: {sum(db.get('tables', {}).values())} live row(s), {frames}, "
                     f"{len(db.get('recovered', []))} recovered row(s), {len(db.get('wal_diff', []))} WAL change(s)"
                     + (f"; error {db['error']}" if db.get("error") else ""))
        for d in db.get("wal_diff", [])[:4]:
            leads += 1
            if len(evidence) < MAX_EVIDENCE:
                evidence.append(Evidence(kind="wal-diff", path=db["name"], detail=(
                    f"{d['table']}#{d['rowid']} {d['change']}" + (f" ({', '.join(d['columns'])})" if d['columns'] else "")
                    + f": before "
                    f"{_show(d['before'], 100)} after {_show(d['after'], 100)}")[:300]))
        for r in db.get("recovered", [])[:4]:
            leads += 1
            if len(evidence) < MAX_EVIDENCE:
                evidence.append(Evidence(kind="recovered", path=db["name"], detail=(
                    f"{r['table']}#{r['rowid']} from {r['source']}: {_show(r['cells'], 200)}")[:300]))
        leads += len(db.get("recovered", [])) + len(db.get("wal_diff", []))
    for r in report["readings"]:
        if r["chain"]:
            leads += 1
            if len(evidence) < MAX_EVIDENCE and not r["flags"]:
                evidence.append(Evidence(kind="decoded", path=r["db"], detail=(
                    f"{_where_text(r)}: {_show(r['text'], 160)}")[:300]))
    for b in report["backups"]:
        if b.get("status") == "read":
            notes.append(f"{b['file']}: Android backup v{b['header']['version']}, {b['members']} member(s)"
                         + ("" if b["strict_tar"] else " (tar read leniently)"))
    notes += report["notes"]
    notes += report["blocked"]
    if report["budget"]["spent"]:
        notes.append("CPU budget spent: rerun with --opt budget=<seconds>")
    if len(flags) == 1:
        status = "solved"
    elif flags:
        status = "candidate"
        notes.insert(0, "several distinct flags: not auto-returned")
    elif report["blocked"] and not report["databases"]:
        return SolverResult(status="blocked", engine=ENGINE_ID, evidence=tuple(evidence[:MAX_EVIDENCE]),
                            notes="; ".join(report["blocked"] + [n for n in notes if n not in report["blocked"]]))
    elif leads:
        status = "unsure"
        notes.insert(0, "no flag-format hit; the recovered rows, WAL changes and decoded cells are the leads")
    else:
        status = "none"
        if not report["databases"] and not report["backups"]:
            notes.insert(0, "no Android backup and no SQLite database in the handout")
        else:
            notes.insert(0, "databases read: no flag, no recovered row, no WAL change, no decoded cell")
    if status == "solved" and not evidence:
        evidence.append(Evidence(kind="match", detail="flag found"))
    return SolverResult(status=status, flags=tuple(flags), evidence=tuple(evidence[:MAX_EVIDENCE]),
                        engine=ENGINE_ID, notes="; ".join(notes)[:4000])


def solve(challenge_dir, profile, **opts):
    """Contract entry. Options: `password` (an encrypted backup's password), `budget` (CPU seconds,
    default 30), `graph_seconds` (wall seconds for the codec graph, default 4), `out` (folder for the
    members and report.json; default <challenge>/recon/android_backup_sqlite; `none` writes nothing),
    `report` (a path for the JSON report)."""
    unknown = sorted(set(opts) - _SOLVE_OPTS)
    if unknown:
        raise ValueError(f"unknown option(s) {', '.join(unknown)}; known: {', '.join(sorted(_SOLVE_OPTS))}")
    challenge_dir = Path(challenge_dir)
    out = opts.get("out")
    if out is None:
        out = challenge_dir / "recon" / "android_backup_sqlite" if challenge_dir.is_dir() else None
    elif str(out).lower() == "none":
        out = None
    report = analyze(challenge_dir, profile, password=opts.get("password"),
                     budget=float(opts.get("budget", DEFAULT_BUDGET_S)),
                     graph_seconds=float(opts.get("graph_seconds", GRAPH_SECONDS)),
                     out=Path(out) if out is not None else None)
    if opts.get("report"):
        Path(str(opts["report"])).write_text(json.dumps(_jsonable(report), indent=2, sort_keys=True),
                                             encoding="utf-8")
    return result_of(report)


def render(report: dict, limit: int = 20) -> str:
    L = [f"android_backup_sqlite: {report['files']} file(s), {len(report['backups'])} backup(s), "
         f"{len(report['databases'])} database(s)"]
    for b in report["backups"]:
        L.append(f"== backup {b['file']}: {b.get('status')}"
                 + (f", {b['members']} member(s)" if b.get("status") == "read" else ""))
    for db in report["databases"]:
        L.append(f"== {db['name']} [{db['origin']}] wal={db.get('wal')} journal={db.get('journal')} "
                 f"frames={db.get('wal_frames', 0)} stale={db.get('stale_frames', 0)}"
                 + (f" error={db['error']}" if db.get("error") else ""))
        for t, n in db.get("tables", {}).items():
            L.append(f"   table {t}: {n} live row(s)")
        for d in db.get("wal_diff", [])[:limit]:
            L.append(f"   WAL DIFF {d['table']}#{d['rowid']} {d['change']}: before {_show(d['before'])} "
                     f"after {_show(d['after'])}")
        for r in db.get("recovered", [])[:limit]:
            L.append(f"   RECOVERED [{r['source']}] {r['table']}#{r['rowid']}: {_show(r['cells'], 200)}")
    for r in report["readings"][:limit * 2]:
        L.append(f"   DECODED {_where_text(r)}: {_show(r['text'])}" + (f"  FLAGS {r['flags']}" if r["flags"] else ""))
    for f, wheres in report["flags"].items():
        L.append(f"FLAG {f}: " + " | ".join(_where_text(w) for w in wheres[:3]))
    for n in report["blocked"] + report["notes"]:
        L.append(f"note: {n}")
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Android backup -> WAL-aware SQLite recovery -> BLOB decode")
    ap.add_argument("path", help="an .ab file, a database, or a challenge folder")
    ap.add_argument("--event", help="event slug (default: the current event)")
    ap.add_argument("--password", help="the password of an encrypted backup")
    ap.add_argument("--out", help="write the backup members and report.json here")
    ap.add_argument("--budget", type=float, default=DEFAULT_BUDGET_S, help="CPU seconds (default 30)")
    ap.add_argument("--json", action="store_true", help="print the full report as JSON")
    a = ap.parse_args(argv)
    from ctf import event
    if not os.path.exists(a.path):
        print(f"android_backup_sqlite: no such file or folder: {a.path}", file=sys.stderr)
        return 2
    try:
        profile = event.load(a.event) if a.event else event.current()
    except event.EventError as e:
        print(f"android_backup_sqlite: no event profile ({e}); pass --event <slug>", file=sys.stderr)
        return 2
    report = analyze(Path(a.path), profile, password=a.password, budget=a.budget,
                     out=Path(a.out) if a.out else None)
    print(json.dumps(_jsonable(report), indent=2, sort_keys=True) if a.json else render(report))
    print(result_of(report).to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
