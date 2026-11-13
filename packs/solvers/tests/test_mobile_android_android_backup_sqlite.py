"""B-085: Android backup -> WAL-aware SQLite recovery -> BLOB decoder ladder
(solvers/mobile-android/android_backup_sqlite.py).

Every fixture is built here: SQLite databases written by the sqlite3 module in tmp_path, protobuf and
deflate bytes by hand, the .ab wrapper (plain and AES-256) from its documented layout. No real
challenge file is read.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import shutil
import sqlite3
import sys
import tarfile
import zlib
from pathlib import Path

import pytest

import ctf  # noqa: F401  (the dotted-lane finder)
from ctf import event
from ctf.result import SolverResult
from solvers.mobile_android import android_backup_sqlite as abs_

REPO = Path(__file__).resolve().parents[1]
FLAG = "CSCTF{st4le_fr4me_k3pt_it}"
PKG = "apps/com.courier.medic"


@pytest.fixture(scope="module")
def csctf():
    return event.load("csctf")


# ---- builders ---------------------------------------------------------------------------------------------

def varint(v: int) -> bytes:
    out = b""
    while True:
        b, v = v & 0x7F, v >> 7
        out += bytes([b | (0x80 if v else 0)])
        if not v:
            return out


def pb(fields) -> bytes:
    out = b""
    for n, v in fields:
        if isinstance(v, int):
            out += varint(n << 3) + varint(v)
        else:
            out += varint(n << 3 | 2) + varint(len(v)) + v
    return out


def raw_deflate(b: bytes) -> bytes:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(b) + co.flush()


def secret_payload(text: bytes = b"meet at dawn " + FLAG.encode()) -> bytes:
    """The courier's message: protobuf, sender in field 1, the body raw-deflated in field 5."""
    return pb([(1, b"medic"), (3, 1700000000), (5, raw_deflate(text))])


def withdrawn_payload() -> bytes:
    return pb([(1, b"medic"), (2, b"message withdrawn")])


def _wal_db(folder: Path, *, stale: bool) -> tuple[bytes, bytes]:
    """(main file, WAL) of a messages database whose message 2 was withdrawn.

    stale=True: the secret was written, then withdrawn, then checkpointed (RESTART), then one more write
    restarted the WAL with new salts: the frame holding the pre-withdrawal page is stale (old salts).
    stale=False: the secret was checkpointed into the main file, then withdrawn in a WAL frame that is
    still valid: the main file alone and the committed view differ."""
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "messages.db"
    for side in ("", "-wal", "-shm"):
        Path(str(db) + side).unlink(missing_ok=True)
    con = sqlite3.connect(db, isolation_level=None)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, payload BLOB)")
        con.execute("INSERT INTO messages VALUES(1, 'hq', ?)", (pb([(1, b"hq"), (2, b"status?")]),))
        con.execute("INSERT INTO messages VALUES(2, 'medic', ?)", (secret_payload(),))
        if stale:
            con.execute("UPDATE messages SET payload = ? WHERE id = 2", (withdrawn_payload(),))
            con.execute("PRAGMA wal_checkpoint(RESTART)").fetchall()
            con.execute("INSERT INTO messages VALUES(3, 'hq', 'ack')")
        else:
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            con.execute("UPDATE messages SET payload = ? WHERE id = 2", (withdrawn_payload(),))
        # copied while the connection is open: closing the last connection would checkpoint the WAL away
        return db.read_bytes(), Path(str(db) + "-wal").read_bytes()
    finally:
        con.close()


def tar_of(members: dict, *, eof: bool = True) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.mode = len(data), 1700000000, 0o600
            tf.addfile(info, io.BytesIO(data))
    raw = buf.getvalue()
    if not eof:
        raw = raw[:sum(512 + -(-len(d) // 512) * 512 for d in members.values())]
    return raw


def ab_of(members: dict, *, compressed: bool = True, eof: bool = True, version: int = 5) -> bytes:
    tar = tar_of(members, eof=eof)
    body = zlib.compress(tar) if compressed else tar
    return f"ANDROID BACKUP\n{version}\n{int(compressed)}\nnone\n".encode() + body


def _pkcs7(b: bytes) -> bytes:
    n = 16 - len(b) % 16
    return b + bytes([n]) * n


def encrypted_ab_of(members: dict, password: str, rounds: int = 2000, blob: bytes | None = None) -> bytes:
    """An AES-256 backup; `blob` replaces the plain master key blob (its length is padded to whole
    blocks, so a wrong shape still unpads cleanly)."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    def enc(key, iv, data):
        e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return e.update(_pkcs7(data)) + e.finalize()

    user_salt, ck_salt = bytes(range(64)), bytes(range(64, 128))
    user_iv, master_iv, master_key = bytes(range(16)), bytes(range(16, 32)), bytes(range(100, 132))
    user_key = hashlib.pbkdf2_hmac("sha1", password.encode(), user_salt, rounds, 32)
    if blob is None:
        blob = bytes([16]) + master_iv + bytes([32]) + master_key + bytes([32]) + bytes(32)
        key_blob = enc(user_key, user_iv, blob)
        assert len(key_blob) == 96
    else:
        key_blob = enc(user_key, user_iv, blob)
    payload = enc(master_key, master_iv, zlib.compress(tar_of(members)))
    head = (f"ANDROID BACKUP\n5\n1\nAES-256\n{user_salt.hex().upper()}\n{ck_salt.hex().upper()}\n{rounds}\n"
            f"{user_iv.hex().upper()}\n{key_blob.hex().upper()}\n")
    return head.encode() + payload


def challenge(tmp_path: Path, files: dict) -> Path:
    cd = tmp_path / "9152-medic"
    for name, data in files.items():
        p = cd / "files" / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return cd


def medic_members(tmp_path: Path, *, stale: bool = True) -> dict:
    main, wal = _wal_db(tmp_path / "build", stale=stale)
    return {f"{PKG}/_manifest": b"1\ncom.courier.medic\n", f"{PKG}/db/messages.db": main,
            f"{PKG}/db/messages.db-wal": wal, f"{PKG}/sp/prefs.xml": b"<map><string name='u'>medic</string></map>"}


def text_of(result: SolverResult) -> str:
    return " ".join(e.detail for e in result.evidence) + " " + result.notes


# ---- the chain end to end --------------------------------------------------------------------------------

def test_a_backup_whose_flag_is_only_in_a_stale_wal_frame_is_solved(tmp_path, csctf):
    cd = challenge(tmp_path, {"backup.ab": ab_of(medic_members(tmp_path, stale=True))})
    res = abs_.solve(cd, csctf, out="none")
    assert res.status == "solved", res.notes
    assert res.flags == (FLAG,)
    first = res.evidence[0].detail
    assert "stale WAL frame" in first and "protobuf.5>raw-deflate" in first and "messages#2.payload" in first
    # the flag is in no live view: neither the committed one nor the main file alone hold it
    main, wal = (tmp_path / "build" / "messages.db").read_bytes(), None
    rep = abs_.analyze(cd, csctf)
    db = next(d for d in rep["databases"] if d["name"].endswith("db/messages.db"))
    assert db["wal"].endswith("db/messages.db-wal") and db["stale_frames"] >= 1
    assert [r["source"] for r in db["recovered"] if r["rowid"] == 2] and \
        all("(stale)" in r["source"] for r in db["recovered"] if r["rowid"] == 2)
    assert FLAG.encode() not in main


def test_without_its_wal_the_same_database_gives_no_flag(tmp_path, csctf):
    members = medic_members(tmp_path, stale=True)
    del members[f"{PKG}/db/messages.db-wal"]
    cd = challenge(tmp_path, {"backup.ab": ab_of(members)})
    res = abs_.solve(cd, csctf, out="none")
    assert res.flags == ()
    assert res.status == "unsure"          # the decoded protobuf fields are the leads


def test_the_wal_diff_shows_the_message_before_and_after_it_was_withdrawn(tmp_path, csctf):
    cd = challenge(tmp_path, {"backup.ab": ab_of(medic_members(tmp_path, stale=False))})
    rep = abs_.analyze(cd, csctf)
    db = next(d for d in rep["databases"] if d["name"].endswith("db/messages.db"))
    (change,) = db["wal_diff"]
    assert (change["table"], change["rowid"], change["change"], change["columns"]) == \
        ("messages", 2, "changed by the WAL", ["payload"])
    assert change["before"]["payload"] == secret_payload() and change["after"]["payload"] == withdrawn_payload()
    assert list(rep["flags"]) == [FLAG]
    # the flag is credited to the main-file side of the diff (the row the diff names), not to the overlaid
    # main page sqlite_artifacts also recovers; that page is labelled as the main file before the WAL
    (where,) = rep["flags"][FLAG]
    assert (where["source"], where["source_kind"], where["rowid"]) == \
        ("main file (before the WAL)", "main file before the WAL", 2)
    assert where["chain"] == ["protobuf.5", "raw-deflate"]
    assert [(r["source"], r["kind"]) for r in db["recovered"] if r["rowid"] == 2] == \
        [("main page 2", "main file before the WAL")]
    res = abs_.result_of(rep)
    assert res.status == "solved" and any(e.kind == "wal-diff" for e in res.evidence)


def test_source_kinds_name_where_a_row_came_from():
    k = abs_._source_kind
    assert k("live") == "live"
    assert k("wal frame 3 (stale)") == "stale WAL frame" and k("wal frame 3") == "superseded WAL frame"
    assert k("journal page 2") == "rollback journal" and k("freelist page 4") == "freelist page"
    assert k("main file (before the WAL)") == "main file before the WAL"
    assert k("main page 2") == "main file before the WAL"          # a WAL overlays it
    assert k("main page 2", wal=True, journal=True) == "main file before the WAL"
    # a rollback journal alone holds the before-pages; the main file is the state after the change
    assert k("main page 2", wal=False, journal=True) == "main file (journal beside it)"
    assert k("main page 2", wal=False) == "main file page"        # no WAL, no journal: just a page of the file
    assert k("unallocated space of page 2") == "unallocated space" and k("freeblock 2") == "unallocated space"
    assert k("something else") == "page image"


def test_a_message_in_a_superseded_but_valid_wal_frame_is_recovered(tmp_path, csctf):
    db = tmp_path / "build" / "m.db"
    db.parent.mkdir()
    con = sqlite3.connect(db, isolation_level=None)
    try:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
        con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, payload BLOB)")
        con.execute("INSERT INTO messages VALUES(2, 'medic', ?)", (secret_payload(),))
        con.execute("UPDATE messages SET payload = ? WHERE id = 2", (withdrawn_payload(),))
        main, wal = db.read_bytes(), Path(str(db) + "-wal").read_bytes()
    finally:
        con.close()
    rep = abs_.analyze(challenge(tmp_path, {"m.db": main, "m.db-wal": wal}), csctf)
    (db_rep,) = rep["databases"]
    assert db_rep["stale_frames"] == 0
    (where,) = [w for w in rep["flags"][FLAG] if w["table"]]
    assert where["source_kind"] == "superseded WAL frame" and where["source"].startswith("wal frame ")
    assert [d["change"] for d in db_rep["wal_diff"]] == ["added by the WAL"]   # the table is not in the main file


def test_a_persisted_rollback_journal_gives_back_the_page_before_the_update(tmp_path, csctf):
    db = tmp_path / "build" / "j.db"
    db.parent.mkdir()
    con = sqlite3.connect(db, isolation_level=None)
    con.execute("PRAGMA journal_mode=PERSIST")
    con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, payload BLOB)")
    con.execute("INSERT INTO messages VALUES(2, 'medic', ?)", (secret_payload(),))
    con.execute("UPDATE messages SET payload = ? WHERE id = 2", (withdrawn_payload(),))
    con.close()
    main, journal = db.read_bytes(), Path(str(db) + "-journal").read_bytes()
    assert FLAG.encode() not in main
    rep = abs_.analyze(challenge(tmp_path, {"j.db": main, "j.db-journal": journal}), csctf)
    (db_rep,) = rep["databases"]
    assert db_rep["journal"] == "files/j.db-journal" and db_rep["journal_pages"] >= 1
    (where,) = [w for w in rep["flags"][FLAG] if w["table"]]
    assert where["source_kind"] == "rollback journal"
    alone = abs_.analyze(challenge(tmp_path / "alone", {"j.db": main}), csctf)
    assert alone["flags"] == {}


def test_a_main_page_row_beside_a_journal_alone_is_not_named_a_before_the_wal_image(tmp_path, csctf):
    # an orphaned table page (its schema row removed, the page left in place) is recovered by
    # sqlite_artifacts as 'main page N'; with only a rollback journal beside the file there is no WAL, and
    # the main file holds the state after the change, so the row is not labelled 'main file before the WAL'
    db = tmp_path / "build" / "o.db"
    db.parent.mkdir()
    con = sqlite3.connect(db, isolation_level=None)
    con.execute("PRAGMA journal_mode=PERSIST")
    con.execute("CREATE TABLE messages(id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
    con.execute("INSERT INTO messages VALUES(1, 'medic', 'all clear')")
    con.execute("CREATE TABLE hidden(id INTEGER PRIMARY KEY, sender TEXT, body TEXT)")
    con.execute("INSERT INTO hidden VALUES(7, 'ghost', 'orphaned page row')")
    con.execute("PRAGMA writable_schema=ON")
    con.execute("DELETE FROM sqlite_master WHERE name='hidden'")
    con.close()
    main, journal = db.read_bytes(), Path(str(db) + "-journal").read_bytes()

    def main_page_kinds(files, sub):
        (d,) = abs_.analyze(challenge(tmp_path / sub, files), csctf)["databases"]
        return [r["kind"] for r in d["recovered"]
                if r["source"].startswith("main page ") and r["cells"].get("body") == "orphaned page row"]

    with_journal = main_page_kinds({"o.db": main, "o.db-journal": journal}, "j")
    assert with_journal == ["main file (journal beside it)"]
    assert main_page_kinds({"o.db": main}, "alone") == ["main file page"]


def test_a_flag_shape_across_binary_bytes_is_not_a_flag(tmp_path, csctf):
    cd = challenge(tmp_path, {"b.ab": ab_of({"apps/a/f/bin": b"\x00CSCTF{ab\x01\x02cd}\x00"})})
    res = abs_.solve(cd, csctf, out="none")
    assert res.flags == () and res.status == "none"


def test_a_loose_database_and_wal_in_the_handout_are_read_too(tmp_path, csctf):
    main, wal = _wal_db(tmp_path / "build", stale=True)
    cd = challenge(tmp_path, {"data/messages.db": main, "data/messages.db-wal": wal})
    res = abs_.solve(cd, csctf, out="none")
    assert res.status == "solved" and res.flags == (FLAG,)


def test_members_and_report_are_written_under_the_output_folder(tmp_path, csctf):
    members = medic_members(tmp_path)
    cd = challenge(tmp_path, {"backup.ab": ab_of(members)})
    abs_.solve(cd, csctf)
    out = cd / "recon" / "android_backup_sqlite"
    base = out / "members" / "files_backup.ab"
    for path, data in members.items():
        assert (base / path).read_bytes() == data
    rep = json.loads((out / "report.json").read_text())
    assert FLAG in rep["flags"]
    # the recon output is not read back as handout on a second run
    again = abs_.analyze(cd, csctf)
    assert {d["name"] for d in again["databases"]} == {d["name"] for d in rep["databases"]}


# ---- the backup ------------------------------------------------------------------------------------------

def test_an_encrypted_backup_without_a_password_is_blocked_naming_why(tmp_path, csctf):
    head = (b"ANDROID BACKUP\n5\n1\nAES-256\n" + b"AB" * 64 + b"\n" + b"CD" * 64 + b"\n10000\n" + b"EF" * 16
            + b"\n" + b"01" * 96 + b"\n")
    cd = challenge(tmp_path, {"locked.ab": head + bytes(64)})
    res = abs_.solve(cd, csctf, out="none")
    assert res.status == "blocked"
    assert "encrypted Android backup" in res.notes and "10000 rounds" in res.notes and "password" in res.notes


@pytest.mark.needs_tool("py:cryptography")
def test_an_encrypted_backup_opens_with_its_password_and_a_wrong_one_is_named(tmp_path, csctf):
    cd = challenge(tmp_path, {"locked.ab": encrypted_ab_of(medic_members(tmp_path), "dawn-0600")})
    res = abs_.solve(cd, csctf, out="none", password="dawn-0600")
    assert res.status == "solved" and res.flags == (FLAG,)
    assert "decrypted with the given password" in res.notes
    bad = abs_.solve(cd, csctf, out="none", password="dusk")
    assert bad.status == "blocked" and "wrong password" in bad.notes


@pytest.mark.needs_tool("py:cryptography")
@pytest.mark.parametrize("blob", [
    bytes([12]) + bytes(12) + bytes([32]) + bytes(range(100, 132)) + bytes([32]) + bytes(32),   # 12-byte IV
    bytes([16]) + bytes(range(16, 32)) + bytes([20]) + bytes(20) + bytes([32]) + bytes(32),     # 20-byte key
    bytes([200]) + bytes(79),                                     # a first length past the end: one part
], ids=["iv-length", "key-length", "one-part"])
def test_a_master_key_blob_of_the_wrong_shape_is_named_even_when_it_unpads(tmp_path, blob):
    blob = blob.ljust(80, b"\x00")             # the header holds a 96-byte encrypted blob: 80 plain bytes + padding
    data = encrypted_ab_of({"apps/a/f/x": b"x"}, "pw", blob=blob)
    with pytest.raises(abs_.BackupError, match="master key blob has the wrong shape"):
        abs_.open_backup(data, "s.ab", "pw")


def test_a_tar_with_no_end_blocks_is_read_leniently_and_says_so(tmp_path, csctf):
    members = medic_members(tmp_path)
    data = ab_of(members, eof=False)
    bk = abs_.open_backup(data, "x.ab")
    assert bk.strict is False and any("strict tar inventory refused" in n for n in bk.notes)
    assert f"{PKG}/db/messages.db-wal" in bk.members
    strict = abs_.open_backup(ab_of(members), "y.ab")
    assert strict.strict is True and strict.notes == []
    assert strict.members == bk.members == members


def test_an_uncompressed_backup_is_read(tmp_path):
    bk = abs_.open_backup(ab_of({"apps/a/f/x.txt": b"hello"}, compressed=False), "u.ab")
    assert bk.members == {"apps/a/f/x.txt": b"hello"} and bk.header["compressed"] is False


def test_a_truncated_zlib_stream_is_named_and_what_it_gave_is_kept(tmp_path):
    full = ab_of({"apps/a/f/x.txt": b"y" * 3000})
    bk = abs_.open_backup(full[:-6], "t.ab")
    assert any("zlib stream is truncated" in n for n in bk.notes)


def test_bytes_after_the_zlib_stream_are_named_and_ignored():
    bk = abs_.open_backup(ab_of({"apps/a/f/x.txt": b"hello"}) + b"JUNKJUNK", "j.ab")
    assert bk.members == {"apps/a/f/x.txt": b"hello"}
    assert bk.notes == ["j.ab: 8 bytes after the zlib stream ignored"]


@pytest.mark.parametrize("order", ["file-first", "folder-first"])
def test_a_member_that_is_also_another_members_folder_is_skipped_and_named(tmp_path, csctf, order):
    # "x" is a file and also the parent folder of "x/y": the file system holds only one of them
    pair = [("apps/a/f/x", b"plain"), ("apps/a/f/x/y", b"CSCTF{both_read}")]
    if order == "folder-first":
        pair = [("apps/a/f/x/y", b"plain"), ("apps/a/f/x", b"CSCTF{both_read}")]
    cd = challenge(tmp_path, {"b.ab": ab_of(dict(pair))})
    res = abs_.solve(cd, csctf)
    (first, _), (second, _) = pair
    base = cd / "recon" / "android_backup_sqlite" / "members" / "files_b.ab"
    assert (base / first).read_bytes() == b"plain"
    assert f"files/b.ab: member '{second}' not written" in res.notes
    assert res.status == "solved" and res.flags == ("CSCTF{both_read}",)    # still read from memory
    assert (cd / "recon" / "android_backup_sqlite" / "report.json").is_file()


def test_a_malformed_header_is_a_named_error(tmp_path, csctf):
    with pytest.raises(abs_.BackupError, match="not a readable Android backup header"):
        abs_.open_backup(b"ANDROID BACKUP\n9\n1\nnone\n" + zlib.compress(b"x"), "bad.ab")
    cd = challenge(tmp_path, {"bad.ab": b"ANDROID BACKUP\n9\n1\nnone\n"})
    res = abs_.solve(cd, csctf, out="none")
    assert res.status == "blocked" and "not a readable Android backup header (version" in res.notes
    assert res.notes.count("bad.ab") == 1


def test_member_paths_that_leave_the_folder_are_refused():
    assert abs_.safe_member_path("./apps/a/db/x.db") == "apps/a/db/x.db"
    assert abs_.safe_member_path("apps//a/./b") == "apps/a/b"
    for bad in ("../x", "apps/../../x", "/etc/passwd", "\\x", "C:/x", "", "a\x00b"):
        assert abs_.safe_member_path(bad) is None, bad


def test_a_lenient_tar_never_writes_outside_the_output_folder(tmp_path, csctf):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:   # GNU: strict refuses it
        for name, data in (("../evil.txt", b"x"), ("apps/a/f/ok.txt", b"ok")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    data = b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(buf.getvalue())
    bk = abs_.open_backup(data, "evil.ab")
    assert bk.strict is False and bk.members == {"apps/a/f/ok.txt": b"ok"}
    assert any("1 member(s) refused" in n for n in bk.notes)
    cd = challenge(tmp_path, {"evil.ab": data})
    abs_.solve(cd, csctf)
    assert not (cd / "recon" / "android_backup_sqlite" / "members" / "evil.txt").exists()
    assert not list(tmp_path.rglob("evil.txt"))


def test_a_flag_in_a_plain_backup_member_is_found(tmp_path, csctf):
    cd = challenge(tmp_path, {"b.ab": ab_of({"apps/a/sp/prefs.xml": b"<string>CSCTF{in_shared_prefs}</string>"})})
    res = abs_.solve(cd, csctf, out="none")
    assert res.status == "solved" and res.flags == ("CSCTF{in_shared_prefs}",)
    assert "backup member" in res.evidence[0].detail


# ---- pairing ----------------------------------------------------------------------------------------------

def test_a_wal_is_paired_by_its_own_path_never_by_a_same_named_file_elsewhere(tmp_path):
    main, wal = _wal_db(tmp_path / "build", stale=True)
    files = {"a/messages.db": main, "a/messages.db-wal": wal, "b/messages.db": main,
             "c/messages.db-wal": wal, "a/messages.db-journal": b"\x00" * 600,
             "d/x.db": main, "d/x.db-wal": b"not a wal at all"}
    items, notes = abs_.pair_databases(files)
    by = {i.name: i for i in items}
    assert by["a/messages.db"].wal is wal and by["a/messages.db"].journal_name == "a/messages.db-journal"
    assert by["b/messages.db"].wal is None and by["b/messages.db"].journal is None
    assert any(n.startswith("c/messages.db-wal: a WAL with no database") for n in notes)
    assert "d/x.db-wal: no WAL magic; its frames will not parse" in notes
    assert not any(n.startswith("a/messages.db-wal") for n in notes)


# ---- the BLOB decoder ladder --------------------------------------------------------------------------------

def _texts(leaves):
    return {tuple(leaf.chain): leaf.text for leaf in leaves if leaf.kind == "text"}


@pytest.mark.parametrize("wrap,chain", [
    (lambda b: zlib.compress(b), ("zlib",)),
    (lambda b: gzip.compress(b, mtime=0), ("gzip",)),
    (lambda b: bz2.compress(b), ("bz2",)),
    (lambda b: lzma.compress(b), ("xz",)),
    (raw_deflate, ("raw-deflate",)),
    (lambda b: b.decode().encode("utf-16-le"), ("utf-16le",)),
    (lambda b: pb([(7, raw_deflate(b))]), ("protobuf.7", "raw-deflate")),
    (lambda b: pb([(1, pb([(2, zlib.compress(b))]))]), ("protobuf.1", "protobuf.2", "zlib")),
], ids=["zlib", "gzip", "bz2", "xz", "raw-deflate", "utf16le", "protobuf-deflate", "nested-protobuf-zlib"])
def test_the_ladder_reaches_the_text_and_names_the_chain(wrap, chain):
    text = b"the courier said CSCTF{ladder}"
    assert _texts(abs_.decode_blob(wrap(text)))[chain] == text.decode()


def test_prose_is_not_split_into_protobuf_fields():
    leaves = abs_.decode_blob(b"Hello there, nothing hidden in this sentence at all")
    assert [(leaf.chain, leaf.kind) for leaf in leaves] == [((), "text")]


def test_a_printable_protobuf_that_starts_with_a_control_byte_is_read_both_ways():
    # field 1, length 10 ("\n\n"), then ten printable bytes: the whole BLOB is text, and also a message
    blob = pb([(1, b"radio-0600")])
    assert blob == b"\n\nradio-0600"
    texts = _texts(abs_.decode_blob(blob))
    assert texts == {(): "\n\nradio-0600", ("protobuf.1",): "radio-0600"}


def test_raw_deflate_with_bytes_after_its_end_is_no_reading():
    body = b"the courier said nothing of note"
    assert abs_._raw_deflate(raw_deflate(body)) == body
    assert abs_._raw_deflate(raw_deflate(body) + b"\x00trailing") is None


def test_a_nested_database_and_a_file_type_are_leaves():
    leaves = abs_.decode_blob(pb([(1, b"SQLite format 3\x00" + bytes(100)), (2, b"\x89PNG\r\n\x1a\n" + bytes(8))]))
    kinds = {leaf.chain: leaf.kind for leaf in leaves}
    assert kinds[("protobuf.1",)] == "sqlite" and kinds[("protobuf.2",)] == "file:png"


def test_the_protobuf_parser_takes_only_a_whole_message():
    assert abs_.protobuf_fields(pb([(1, b"ab"), (3, 150)])) == [(1, 2, b"ab"), (3, 0, 150)]
    assert abs_.protobuf_fields(pb([(1, b"ab")])[:-1]) is None            # a length past the end
    assert abs_.protobuf_fields(b"\x0f\x00") is None                       # wire type 7
    assert abs_.protobuf_fields(b"\x02\x00") is None                       # field number 0


def test_a_nested_database_inside_a_blob_is_read_for_its_rows(tmp_path, csctf):
    inner = tmp_path / "inner.db"
    con = sqlite3.connect(inner)
    con.execute("CREATE TABLE notes(t TEXT)")
    con.execute("INSERT INTO notes VALUES('CSCTF{db_in_a_blob}')")
    con.commit()
    con.close()
    outer = tmp_path / "outer.db"
    con = sqlite3.connect(outer)
    con.execute("CREATE TABLE att(id INTEGER PRIMARY KEY, data BLOB)")
    con.execute("INSERT INTO att VALUES(1, ?)", (zlib.compress(inner.read_bytes()),))
    con.commit()
    con.close()
    cd = challenge(tmp_path, {"outer.db": outer.read_bytes()})
    rep = abs_.analyze(cd, csctf)
    assert any(d["origin"] == "blob" and "att#1.data via zlib" in d["name"] for d in rep["databases"])
    where = rep["flags"]["CSCTF{db_in_a_blob}"]
    assert any(w["table"] == "notes" for w in where)


def test_a_base64_flag_inside_a_text_cell_is_decoded(tmp_path, csctf):
    import base64
    db = tmp_path / "t.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE m(id INTEGER PRIMARY KEY, body TEXT)")
    con.execute("INSERT INTO m VALUES(1, ?)", ("note: " + base64.b64encode(b"CSCTF{b64_in_a_cell}").decode() + " end",))
    con.commit()
    con.close()
    rep = abs_.analyze(challenge(tmp_path, {"t.db": db.read_bytes()}), csctf)
    (where,) = rep["flags"]["CSCTF{b64_in_a_cell}"]
    assert where["chain"][0].startswith("embedded:base64")


def test_a_decoded_text_that_still_reads_as_an_encoding_goes_to_the_codec_graph(tmp_path, csctf):
    import base64
    inner = base64.b64encode(b"CSCTF{graph_rung_rot47}").decode()
    rot47 = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in inner)
    db = tmp_path / "g.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE m(id INTEGER PRIMARY KEY, payload BLOB)")
    con.execute("INSERT INTO m VALUES(1, ?)", (pb([(4, zlib.compress(rot47.encode()))]),))
    con.commit()
    con.close()
    cd = challenge(tmp_path, {"g.db": db.read_bytes()})
    rep = abs_.analyze(cd, csctf, graph_seconds=240)        # an explicit, generous bound (machine load)
    (where,) = rep["flags"]["CSCTF{graph_rung_rot47}"]
    assert where["chain"][:2] == ["protobuf.4", "zlib"] and where["chain"][2].startswith("graph:")
    assert rep["budget"]["graph_runs"] >= 1
    none = abs_.analyze(cd, csctf, graph_seconds=0)          # no graph time: the rung does not run
    assert "CSCTF{graph_rung_rot47}" not in none["flags"] and none["budget"]["graph_runs"] == 0


# ---- results, budget, options -------------------------------------------------------------------------------

def test_two_distinct_flags_are_a_candidate(tmp_path, csctf):
    cd = challenge(tmp_path, {"a.ab": ab_of({"apps/a/f/1.txt": b"CSCTF{one}"}),
                              "b.ab": ab_of({"apps/b/f/2.txt": b"CSCTF{two}"})})
    res = abs_.solve(cd, csctf, out="none")
    assert res.status == "candidate" and set(res.flags) == {"CSCTF{one}", "CSCTF{two}"}


def test_a_handout_with_nothing_to_read_is_none_and_says_why(tmp_path, csctf):
    cd = challenge(tmp_path, {"readme.txt": b"just words"})
    res = abs_.solve(cd, csctf, out="none")
    assert res.status == "none" and "no Android backup and no SQLite database" in res.notes


def test_the_cpu_budget_stops_between_databases_and_says_so(tmp_path, csctf):
    main, wal = _wal_db(tmp_path / "build", stale=True)
    cd = challenge(tmp_path, {"a/messages.db": main, "a/messages.db-wal": wal, "b/messages.db": main})
    ticks = iter(range(0, 10 ** 6, 7))                           # a step clock: 7 "seconds" per reading
    rep = abs_.analyze(cd, csctf, budget=5, clock=lambda: next(ticks))
    assert rep["budget"]["spent"] is True
    assert len(rep["databases"]) < 2
    assert any("CPU budget of 5 s spent" in n for n in rep["notes"])
    full = abs_.analyze(cd, csctf, budget=10 ** 6, clock=lambda: 0.0)
    assert len(full["databases"]) == 2 and full["budget"]["spent"] is False


def test_an_unknown_option_is_refused(tmp_path, csctf):
    with pytest.raises(ValueError, match="unknown option"):
        abs_.solve(tmp_path, csctf, pasword="x")


def test_the_command_prints_the_result_json_last(tmp_path, capsys):
    main, wal = _wal_db(tmp_path / "build", stale=True)
    f = tmp_path / "files"
    f.mkdir()
    (f / "messages.db").write_bytes(main)
    (f / "messages.db-wal").write_bytes(wal)
    assert abs_.main([str(f), "--event", "csctf"]) == 0
    out = capsys.readouterr().out.strip().splitlines()
    assert any(line.startswith("FLAG " + FLAG) for line in out)
    res = SolverResult.from_json(out[-1])
    assert res.status == "solved" and res.flags == (FLAG,)
    assert abs_.main([str(tmp_path / "missing"), "--event", "csctf"]) == 2


# ---- routing and intake ---------------------------------------------------------------------------------------

def test_a_backup_or_a_wal_in_the_handout_routes_here_in_any_category(tmp_path):
    from ctf.engines import router
    (tmp_path / "x.ab").write_bytes(ab_of({"apps/a/f/x": b"x"}))
    assert "mobile_android.android_backup_sqlite" in [h.manifest.id for h in router.route("misc", "", tmp_path)]
    other = tmp_path / "o"
    other.mkdir()
    (other / "n.txt").write_text("words")
    assert "mobile_android.android_backup_sqlite" not in [h.manifest.id for h in router.route("misc", "", other)]
    hits = router.route("mobile", "the medic's adb backup", other)
    assert hits[0].manifest.id == "mobile_android.android_backup_sqlite"


def test_intake_runs_the_chain_on_a_backup_with_no_model(tmp_path, csctf):
    from ctf.engines import manifest
    from ctf.intake import engines as E
    from ctf.intake import guard as G
    ms = [m for m in manifest.discover() if m.id == "mobile_android.android_backup_sqlite"]
    cd = tmp_path / "9152-medic"
    (cd / "unpacked").mkdir(parents=True)
    (cd / "unpacked" / "backup.ab").write_bytes(ab_of(medic_members(tmp_path)))
    hook = G.Guard("hook", (), "test: python-level network fence; this engine starts no process")
    plan = E.plan(ms, "forensics", "The Medic's Phone", cd / "unpacked", guard=hook)
    (job,) = plan.jobs
    assert job.engine == "mobile_android.android_backup_sqlite" and job.manifest.intake.run == "challenge"
    ctx = E.Context(challenge_dir=cd, folder=cd / "unpacked", out_root=cd / "recon" / "engines", profile=csctf,
                    guard=hook, root=REPO, python=sys.executable, challenge_id="9152", record=False)
    run = E.run_job(job, ctx)
    assert run.status == "ok", (cd / run.errors).read_text()
    assert run.result_status == "solved" and run.flags == (FLAG,)
    empty = tmp_path / "e"
    empty.mkdir()
    (empty / "n.txt").write_text("words")
    assert E.plan(ms, "forensics", "The Medic's Phone", empty, guard=hook).jobs == []
