from __future__ import annotations

import hashlib
import io
import json
import plistlib
import sqlite3
import struct
import zipfile

import pytest

from solvers.toolkits import mobile_artifacts as mobile


def _database(schema: str, statements=(), *, page_size=1024) -> bytes:
    connection = sqlite3.connect(":memory:")
    connection.execute(f"PRAGMA page_size={page_size}")
    connection.executescript(schema)
    for sql, parameters in statements:
        connection.execute(sql, parameters)
    connection.commit()
    data = connection.serialize()
    connection.close()
    return data


def _updated(database: bytes, statements) -> bytes:
    connection = sqlite3.connect(":memory:")
    connection.deserialize(database)
    for sql, parameters in statements:
        connection.execute(sql, parameters)
    connection.commit()
    data = connection.serialize()
    connection.close()
    return data


def _wal(base: bytes, committed: bytes, latest: bytes) -> bytes:
    page_size = int.from_bytes(base[16:18], "big")
    if page_size == 1:
        page_size = 65536
    salt = (0x10203040, 0x50607080)
    prefix = struct.pack(">6I", 0x377F0682, 3007000, page_size, 0, *salt)

    def checksum(blob, state=(0, 0)):
        first, second = state
        for offset in range(0, len(blob), 8):
            left, right = struct.unpack_from("<II", blob, offset)
            first = (first + left + second) & 0xFFFFFFFF
            second = (second + right + first) & 0xFFFFFFFF
        return first, second

    state = checksum(prefix)
    output = bytearray(prefix + struct.pack(">II", *state))

    def frames(before, after, commit):
        nonlocal state
        pages = max(len(before), len(after)) // page_size
        changed = []
        for page in range(1, pages + 1):
            old = before[(page - 1) * page_size:page * page_size]
            new = after[(page - 1) * page_size:page * page_size]
            if old != new:
                changed.append((page, new))
        for index, (page, body) in enumerate(changed):
            database_size = len(after) // page_size if commit and index == len(changed) - 1 else 0
            header = struct.pack(">4I", page, database_size, *salt)
            state = checksum(header[:8] + body, state)
            output.extend(header + struct.pack(">II", *state))
            output.extend(body)

    frames(base, committed, True)
    frames(committed, latest, False)
    return bytes(output)


def _keyed_archive(**metadata) -> bytes:
    value = {"$archiver": "NSKeyedArchiver", "$version": 100000,
             "$objects": ["$null", metadata], "$top": {"root": plistlib.UID(1)}}
    return plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=True)


def test_sqlite_btree_records_overflow_and_schema():
    blob = bytes(range(256)) * 24
    database = _database(
        "CREATE TABLE records(name TEXT, count INTEGER, payload BLOB, score REAL);",
        [("INSERT INTO records VALUES(?,?,?,?)", ("alpha", -123456, blob, 1.25))],
    )
    report = mobile.parse_sqlite(database)
    assert report["page_size"] == 1024
    table = report["tables"]["records"]
    assert table["columns"] == ["name", "count", "payload", "score"]
    row = table["rows"][0]["values"]
    assert row["name"] == "alpha" and row["count"] == -123456 and row["score"] == 1.25
    assert row["payload"] == blob


def test_sqlite_wal_committed_and_uncommitted_row_recovery():
    base = _database("CREATE TABLE messages(body TEXT, timestamp INTEGER);",
                     [("INSERT INTO messages VALUES(?,?)", ("base", 1))])
    committed = _updated(base, [("INSERT INTO messages VALUES(?,?)", ("committed", 2))])
    latest = _updated(committed, [("DELETE FROM messages WHERE rowid=?", (1,)),
                                  ("INSERT INTO messages VALUES(?,?)", ("uncommitted", 3))])
    wal = _wal(base, committed, latest)
    report = mobile.analyze_sqlite(base, wal)
    committed_rows = report["committed"]["tables"]["messages"]["rows"]
    latest_rows = report["latest"]["tables"]["messages"]["rows"]
    assert [row["values"]["body"] for row in committed_rows] == ["base", "committed"]
    assert [row["values"]["body"] for row in latest_rows] == ["committed", "uncommitted"]
    recovered = {(row["rowid"], row["source"], row["change"]) for row in report["recovered_rows"]}
    assert recovered == {(1, "uncommitted", "deleted"), (2, "committed", "inserted"),
                         (3, "uncommitted", "inserted")}
    assert report["wal"]["last_commit_frame"] is not None
    assert report["wal"]["header_checksum_valid"] is True
    assert all(frame["checksum_valid"] for frame in report["wal"]["frames"])

    foreign = bytearray(wal)
    frame_size = 24 + report["base"]["page_size"]
    for offset in range(32, len(foreign) - frame_size + 1, frame_size):
        struct.pack_into(">I", foreign, offset + 8, 0xDEADBEEF)
    ignored = mobile.analyze_sqlite(base, bytes(foreign))
    assert ignored["latest"]["tables"]["messages"]["rows"] == report["base"]["tables"]["messages"]["rows"]


def test_real_sqlite_wal_checksums_are_validated(tmp_path):
    path = tmp_path / "real.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA page_size=1024")
    assert connection.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("CREATE TABLE events(value TEXT)")
    connection.execute("INSERT INTO events VALUES('captured')")
    connection.commit()
    wal = (tmp_path / "real.db-wal").read_bytes()
    report = mobile.parse_wal(wal)
    connection.close()
    assert report["header_checksum_valid"] is True
    assert report["frames"] and all(frame["checksum_valid"] for frame in report["frames"])


def test_ios_backup_manifest_plists_keyed_metadata_and_keychain():
    file_id = hashlib.sha1(b"keychain artifact").hexdigest()
    keychain = plistlib.dumps({"genp": [{
        "class": "genp", "agrp": "TEAM.shared", "acct": "alice", "svce": "ctf",
        "pdmn": "ak", "data": b"opaque-password", "cdat": "2026-11-04",
    }]}, fmt=plistlib.FMT_BINARY)
    manifest_db = _database(
        "CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB);",
        [("INSERT INTO Files VALUES(?,?,?,?,?)", (
            file_id, "KeychainDomain", "Library/Keychains/keychain-backup.plist", 1,
            _keyed_archive(Size=len(keychain), ProtectionClass=1, UserID=501),
        ))],
    )
    files = {
        "Info.plist": plistlib.dumps({"Device Name": "Synthetic iPhone", "Product Version": "18.0"}),
        "Status.plist": plistlib.dumps({"SnapshotState": "finished", "IsFullBackup": True}),
        "Manifest.plist": plistlib.dumps({"IsEncrypted": True, "BackupKeyBag": b"keybag-bytes"}),
        "Manifest.db": manifest_db,
        f"{file_id[:2]}/{file_id}": keychain,
    }
    report = mobile.analyze_ios_backup(files)
    assert report["platform"] == "ios-backup"
    assert report["plists"]["Manifest.plist"]["value"]["IsEncrypted"] is True
    assert report["plists"]["Manifest.plist"]["value"]["BackupKeyBag"]["length"] == len(b"keybag-bytes")
    item = report["files"][0]
    assert item["body_present"] is True
    assert item["metadata"]["root"]["Size"] == len(keychain)
    assert report["keychain"][0]["items"][0]["acct"] == "alice"
    assert report["keychain"][0]["items"][0]["data"] == {
        "length": len(b"opaque-password"), "sha256": hashlib.sha256(b"opaque-password").hexdigest(),
    }


def test_legacy_mbdb_manifest_metadata_and_body_resolution():
    domain, relative = "HomeDomain", "Library/Preferences/example.plist"

    def field(value):
        if value is None:
            return b"\xff\xff"
        raw = value if isinstance(value, bytes) else value.encode()
        return len(raw).to_bytes(2, "big") + raw

    record = b"".join((field(domain), field(relative), field(""), field(b"\x01\x02"), field(None)))
    record += struct.pack(">H7IQBB", 0o100644, 1, 2, 501, 501, 100, 101, 102, 12, 1, 1)
    record += field("ProtectionClass") + field("NSFileProtectionComplete")
    mbdb = b"mbdb\x05\x00" + record
    parsed = mobile.parse_mbdb(mbdb)
    assert parsed["record_count"] == 1
    file_id = hashlib.sha1(f"{domain}-{relative}".encode()).hexdigest()
    body = plistlib.dumps({"token": "metadata-only"})
    report = mobile.analyze_ios_backup({"Manifest.mbdb": mbdb, f"{file_id[:2]}/{file_id}": body})
    assert report["manifest"]["format"] == "mbdb"
    assert report["files"][0]["mode"] == 0o100644 and report["files"][0]["body_present"]
    assert report["plist_artifacts"][0]["relative_path"] == relative


def test_android_whatsapp_signal_preferences_and_wal_timeline():
    whatsapp = _database(
        "CREATE TABLE messages(key_remote_jid TEXT, key_id TEXT, data TEXT, timestamp INTEGER);"
        "CREATE TABLE chat(_id INTEGER, subject TEXT);"
        "CREATE TABLE jid(_id INTEGER, raw_string TEXT);",
        [("INSERT INTO messages VALUES(?,?,?,?)", ("123@s.whatsapp.net", "m1", "hello", 1000))],
    )
    committed = _updated(whatsapp, [("INSERT INTO messages VALUES(?,?,?,?)",
                                     ("456@s.whatsapp.net", "m2", "from wal", 2000))])
    latest = _updated(committed, [])
    wal = _wal(whatsapp, committed, latest)
    signal = _database(
        "CREATE TABLE sms(address TEXT, body TEXT, date_received INTEGER);"
        "CREATE TABLE mms(thread_id INTEGER, body TEXT, date_received INTEGER);"
        "CREATE TABLE thread(_id INTEGER, recipient_id INTEGER);",
        [("INSERT INTO sms VALUES(?,?,?)", ("+40123", "signal text", 1500))],
    )
    preferences = b'''<?xml version="1.0" encoding="utf-8"?>
<map><string name="registration_id">abc</string><boolean name="enabled" value="true"/>
<set name="servers"><string>one</string><string>two</string></set></map>'''
    files = {
        "databases/msgstore.db": whatsapp,
        "databases/msgstore.db-wal": wal,
        "databases/signal.db": signal,
        "shared_prefs/app.xml": preferences,
        "databases/encrypted.db": b"SQLCipher-looking-ciphertext" * 4,
    }
    report = mobile.analyze_android_appdata(files)
    families = {item["path"]: item["schema"]["family"] for item in report["databases"]}
    assert families == {"databases/msgstore.db": "whatsapp", "databases/signal.db": "signal"}
    assert [item["text"] for item in report["message_leads"]] == ["hello", "signal text", "from wal"]
    assert report["preferences"][0]["report"]["values"] == {
        "registration_id": "abc", "enabled": True, "servers": ["one", "two"],
    }
    assert report["encrypted_database_candidates"][0]["path"] == "databases/encrypted.db"


def test_bundle_routing_cli_and_path_guard(tmp_path, capsys):
    database = _database("CREATE TABLE sms(body TEXT);", [("INSERT INTO sms VALUES(?)", ("hi",))])
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("databases/signal.db", database)
    report = mobile.analyze_bundle(stream.getvalue(), "android")
    assert report["databases"][0]["path"] == "databases/signal.db"
    bundle = tmp_path / "appdata.zip"
    bundle.write_bytes(stream.getvalue())
    assert mobile.main([str(bundle), "--platform", "android"]) == 0
    assert json.loads(capsys.readouterr().out)["platform"] == "android-appdata"

    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("../escape", b"x")
    with pytest.raises(mobile.ArtifactError, match="unsafe"):
        mobile.analyze_bundle(bad.getvalue())


def test_malformed_sqlite_wal_plist_xml_and_archive_fail_closed():
    with pytest.raises(mobile.ArtifactError):
        mobile.parse_sqlite(b"not sqlite")
    with pytest.raises(mobile.ArtifactError):
        mobile.parse_wal(b"not wal")
    with pytest.raises(mobile.ArtifactError):
        mobile.parse_plist_metadata(b"not plist")
    with pytest.raises(mobile.ArtifactError):
        mobile.parse_shared_preferences(b"<map><broken>")
    with pytest.raises(mobile.ArtifactError):
        mobile.analyze_bundle(b"not zip")


def test_sqlite_parser_rejects_every_truncated_prefix():
    database = _database("CREATE TABLE t(v TEXT);", [("INSERT INTO t VALUES(?)", ("value",))])
    for cut in range(min(len(database), 400)):
        with pytest.raises(mobile.ArtifactError):
            mobile.parse_sqlite(database[:cut])
