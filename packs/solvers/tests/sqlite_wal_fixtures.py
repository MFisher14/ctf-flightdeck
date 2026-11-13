"""Synthetic SQLite databases with a WAL for the B-075 tests, written by the sqlite3 library in a
temp folder. Nothing here is a challenge file.

    w = build(tmp_path / "make")        # a land registry: five commits, none checkpointed
    w.data, w.wal, w.shm                # the three files' bytes, read while the writer was still open
    w.states[k]                         # {table: rows} as the library itself saw them after commit k
    w.write(folder)                     # registry.db and registry.db-wal in a folder

`rebuild(wal, ...)` rewrites a WAL with its checksums recomputed by a second implementation of the
WAL checksum, so a test can change a frame (or the byte order) and still have a valid chain.
"""
from __future__ import annotations

import sqlite3
import struct
from dataclasses import dataclass
from pathlib import Path

SCHEMA = (
    "CREATE TABLE jobs(job_id TEXT PRIMARY KEY, status TEXT)",
    "CREATE TABLE parcels(parcel INTEGER PRIMARY KEY, owner TEXT, deed BLOB)",
    "CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT) WITHOUT ROWID",
)
DEED = b"\x00\x01deed of parcel one\xff"
# one inner tuple = one transaction = one commit in the WAL
STEPS = (
    (("INSERT INTO jobs VALUES('LR-731', 'QUEUED')", ()), ("INSERT INTO jobs VALUES('LR-700', 'COMPLETED')", ())),
    (("INSERT INTO parcels VALUES(1, 'alice', ?)", (DEED,)), ("INSERT INTO parcels VALUES(2, 'bob', NULL)", ()),
     ("INSERT INTO parcels VALUES(3, 'carol', NULL)", ()), ("INSERT INTO settings VALUES('mode', 'normal')", ())),
    (("UPDATE parcels SET owner = 'mallory' WHERE parcel = 1", ()),
     ("UPDATE jobs SET status = 'RUNNING' WHERE job_id = 'LR-731'", ())),
    (("UPDATE jobs SET status = 'COMPLETED' WHERE job_id = 'LR-731'", ()),),
    (("UPDATE parcels SET owner = 'alice', deed = NULL WHERE parcel = 1", ()), ("DELETE FROM parcels WHERE parcel = 3", ()),
     ("UPDATE settings SET value = 'clean' WHERE key = 'mode'", ())),
)


@dataclass
class Wal:
    data: bytes
    wal: bytes
    shm: bytes
    states: list                    # states[k]: {table: [row, ...]} after step k (0: before the first)

    def write(self, folder: Path, name: str = "registry.db", shm: bool = False, wal_name: str = None) -> Path:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / name).write_bytes(self.data)
        (folder / (wal_name or name + "-wal")).write_bytes(self.wal)
        if shm:
            (folder / (name + "-shm")).write_bytes(self.shm)
        return folder / name


def dump(con) -> dict:
    names = [n for (n,) in con.execute("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")]
    return {n: con.execute(f'SELECT * FROM "{n}" ORDER BY 1').fetchall() for n in names}


def build(folder: Path, steps=STEPS, *, schema=SCHEMA, pre=(), page_size: int = 1024, checkpoint_after=(),
          reader_after: int = None) -> Wal:
    """Run `pre` (transactions that end up in the main file), then `steps` (one commit each in the
    WAL). `checkpoint_after` = step numbers after which a PASSIVE checkpoint runs; `reader_after` = the
    step after which a second connection starts a read transaction and keeps it (a later checkpoint
    then stops at that commit)."""
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "build.db"
    con = sqlite3.connect(path, isolation_level=None)
    reader = None
    try:
        con.execute(f"PRAGMA page_size = {page_size}")
        con.execute("PRAGMA journal_mode = WAL")
        con.execute("PRAGMA wal_autocheckpoint = 0")
        for sql in schema:
            con.execute(sql)
        for step in pre:
            con.execute("BEGIN")
            for sql, params in step:
                con.execute(sql, params)
            con.execute("COMMIT")
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        states = [dump(con)]
        for n, step in enumerate(steps, 1):
            con.execute("BEGIN")
            for sql, params in step:
                con.execute(sql, params)
            con.execute("COMMIT")
            states.append(dump(con))
            if n == reader_after:
                reader = sqlite3.connect(path, isolation_level=None)
                reader.execute("BEGIN")
                reader.execute("SELECT count(*) FROM jobs").fetchall()
            if n in checkpoint_after:
                con.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return Wal(path.read_bytes(), Path(str(path) + "-wal").read_bytes(), Path(str(path) + "-shm").read_bytes(), states)
    finally:
        if reader is not None:
            reader.close()
        con.close()


def _sum(data: bytes, s, order: str):
    s0, s1 = s
    for i in range(0, len(data), 8):
        a, b = struct.unpack_from(order + "II", data, i)
        s0 = (s0 + a + s1) % (1 << 32)
        s1 = (s1 + b + s0) % (1 << 32)
    return s0, s1


def frames_of(wal: bytes) -> list:
    """[[page, commit size, page bytes]] of every frame in the file, in order."""
    page_size = struct.unpack_from(">I", wal, 8)[0]
    out, off = [], 32
    while off + 24 + page_size <= len(wal):
        page, commit = struct.unpack_from(">II", wal, off)
        out.append([page, commit, wal[off + 24:off + 24 + page_size]])
        off += 24 + page_size
    return out


def rebuild(wal: bytes, frames: list = None, *, big_endian: bool = None) -> bytes:
    """The WAL written again from `frames` (default: its own) under its own salts, with the header
    and frame checksums recomputed; `big_endian` picks the checksum byte order (and the magic)."""
    magic, version, page_size, seq, salt1, salt2 = struct.unpack_from(">IIIIII", wal, 0)
    if big_endian is not None:
        magic = 0x377F0683 if big_endian else 0x377F0682
    order = ">" if magic == 0x377F0683 else "<"
    head = struct.pack(">IIIIII", magic, version, page_size, seq, salt1, salt2)
    s = _sum(head, (0, 0), order)
    out = [head + struct.pack(">II", *s)]
    for page, commit, data in (frames_of(wal) if frames is None else frames):
        first = struct.pack(">II", page, commit)
        s = _sum(data, _sum(first, s, order), order)
        out.append(first + struct.pack(">IIII", salt1, salt2, *s) + data)
    return b"".join(out)
