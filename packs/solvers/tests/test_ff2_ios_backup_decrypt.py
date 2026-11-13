"""Known-answer tests for the iOS-backup decrypt-with-password helper (B-161).

The synthetic backup is built here from the documented layout, with the AES-CBC
done by pycryptodome (not the module's library): a TLV keybag whose class keys
are RFC 3394 wrapped under the two-stage PBKDF2 passcode key, a Manifest.plist
whose ManifestKey has a little-endian class prefix, an encrypted Manifest.db
with a Files table of NSKeyedArchiver records, and per-file encrypted blobs.
RFC 3394 section 4.6 pins the unwrap primitive.  Iteration counts are small so
the KDF costs nothing; production DPIC values are ~10 million.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
import sqlite3
import struct

import pytest
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.keywrap import aes_key_wrap

import ff2_ios_backup_decrypt as D


PASSWORD = b"hunter2-backup"
DPSL = bytes(range(20))
DPIC = 7
SALT = bytes(range(50, 70))
ITER = 3


def tlv(tag: str, value: bytes | int) -> bytes:
    raw = struct.pack(">I", value) if isinstance(value, int) else value
    return tag.encode() + struct.pack(">I", len(raw)) + raw


def expected_passcode_key(password: bytes = PASSWORD, *, double: bool = True) -> bytes:
    secret = hashlib.pbkdf2_hmac("sha256", password, DPSL, DPIC, 32) if double else password
    return hashlib.pbkdf2_hmac("sha1", secret, SALT, ITER, 32)


CLASS_KEYS = {1: bytes([0x11]) * 32, 3: bytes([0x33]) * 32, 4: bytes([0x44]) * 32}
LOCKED_CLASS = 7


def make_keybag(*, double: bool = True, password: bytes = PASSWORD) -> bytes:
    passcode = expected_passcode_key(password, double=double)
    out = tlv("VERS", 4) + tlv("TYPE", 1) + tlv("UUID", bytes(range(16))) + tlv("HMCK", b"H" * 40)
    out += tlv("WRAP", 0) + tlv("SALT", SALT) + tlv("ITER", ITER)
    if double:
        out += tlv("DPWT", 1) + tlv("DPIC", DPIC) + tlv("DPSL", DPSL)
    for number, key in CLASS_KEYS.items():
        out += tlv("UUID", bytes([number]) * 16) + tlv("CLAS", number) + tlv("WRAP", 2)
        out += tlv("KTYP", 0) + tlv("WPKY", aes_key_wrap(passcode, key))
    # a class wrapped with the device UID as well: cannot be opened offline
    out += tlv("UUID", b"\x07" * 16) + tlv("CLAS", LOCKED_CLASS) + tlv("WRAP", 3)
    out += tlv("KTYP", 0) + tlv("WPKY", b"\x99" * 40)
    return out


def cbc(key: bytes, data: bytes) -> bytes:
    count = 16 - len(data) % 16
    return AES.new(key, AES.MODE_CBC, iv=bytes(16)).encrypt(data + bytes((count,)) * count)


def file_record(protection_class: int, size: int, file_key: bytes | None) -> bytes:
    objects: list = ["$null"]
    root = {"$class": plistlib.UID(3), "Size": size, "ProtectionClass": protection_class,
            "RelativePath": plistlib.UID(4), "Mode": 33188}
    objects.append(root)
    holder_index = None
    if file_key is not None:
        holder_index = len(objects) + 3
        root["EncryptionKey"] = plistlib.UID(holder_index)
    objects.append({"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]})
    objects.append({"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]})
    objects.append("relative/path")
    if file_key is not None:
        wrapped = struct.pack("<I", protection_class) + aes_key_wrap(CLASS_KEYS.get(protection_class, b"\x01" * 32), file_key)
        objects.append({"NS.data": wrapped, "$class": plistlib.UID(2)})
        assert len(objects) - 1 == holder_index
    archive = {"$version": 100000, "$archiver": "NSKeyedArchiver", "$top": {"root": plistlib.UID(1)},
               "$objects": objects}
    return plistlib.dumps(archive, fmt=plistlib.FMT_BINARY)


FILES = [
    # fileID, domain, relativePath, protection class, plaintext
    ("a1" + "0" * 38, "HomeDomain", "Library/Notes/notes.txt", 3, b"secret note CSCTF{ios_backup_kat}\n"),
    ("b2" + "1" * 38, "AppDomain-com.example", "Documents/data.bin", 4, bytes(range(256)) * 3),
    ("c3" + "2" * 38, "HomeDomain", "Library/Locked.db", LOCKED_CLASS, b"needs the device"),
]


def build_backup(root, *, manifest_class: int = 3, double: bool = True):
    manifest_key = bytes([0x5A]) * 32
    keybag = make_keybag(double=double)
    wrapped_manifest = struct.pack("<I", manifest_class) + aes_key_wrap(CLASS_KEYS[manifest_class], manifest_key)
    plist = {"IsEncrypted": True, "BackupKeyBag": keybag, "ManifestKey": wrapped_manifest,
             "Version": "10.0", "Lockdown": {"ProductVersion": "17.5"}}
    (root / "Manifest.plist").write_bytes(plistlib.dumps(plist))
    db_path = root / "plain.db"
    connection = sqlite3.connect(db_path)
    connection.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT,"
                       " flags INTEGER, file BLOB)")
    connection.execute("CREATE TABLE Properties (key TEXT PRIMARY KEY, value BLOB)")
    connection.execute("INSERT INTO Files VALUES (?,?,?,?,?)",
                       ("d4" + "3" * 38, "HomeDomain", "Library", 2, file_record(3, 0, None)))
    for index, (file_id, domain, relative, number, plain) in enumerate(FILES):
        file_key = bytes([0xA0 + index]) * 32
        connection.execute("INSERT INTO Files VALUES (?,?,?,?,?)",
                           (file_id, domain, relative, 1, file_record(number, len(plain), file_key)))
        folder = root / file_id[:2]
        folder.mkdir(exist_ok=True)
        (folder / file_id).write_bytes(cbc(file_key, plain))
    connection.commit()
    connection.close()
    database = db_path.read_bytes()
    db_path.unlink()
    (root / "Manifest.db").write_bytes(cbc(manifest_key, database))
    return database


# ------------------------------------------------------------------ primitives

def test_aes_unwrap_rfc3394_section_4_6():
    kek = bytes.fromhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
    wrapped = bytes.fromhex("28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21")
    assert D.aes_unwrap(kek, wrapped).hex() == (
        "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f")
    with pytest.raises(D.IOSBackupDecryptError, match="integrity"):
        D.aes_unwrap(bytes(32), wrapped)


def test_passcode_kdf_two_stage_and_legacy():
    assert D.derive_passcode_key(make_keybag(), PASSWORD) == expected_passcode_key()
    assert D.derive_passcode_key(make_keybag(), PASSWORD.decode()) == expected_passcode_key()
    assert D.derive_passcode_key(make_keybag(double=False), PASSWORD) == expected_passcode_key(double=False)
    assert expected_passcode_key() != expected_passcode_key(double=False)


def test_passcode_kdf_rejects_half_pair_and_huge_iterations():
    bag = make_keybag().replace(tlv("DPSL", DPSL), b"")
    with pytest.raises(D.IOSBackupDecryptError, match="DPSL/DPIC"):
        D.derive_passcode_key(bag, PASSWORD)
    with pytest.raises(D.IOSBackupDecryptError, match="outside"):
        D.derive_passcode_key(make_keybag(), PASSWORD, max_iterations=5)


def test_unlock_keybag_class_keys_and_locked_listed():
    unlocked = D.unlock_keybag(make_keybag(), password=PASSWORD)
    assert unlocked["class_keys"] == CLASS_KEYS
    assert unlocked["passcode_key"] == expected_passcode_key()
    assert [row["protection_class"] for row in unlocked["locked_classes"]] == [LOCKED_CLASS]
    again = D.unlock_keybag(make_keybag(), passcode_key=expected_passcode_key())
    assert again["class_keys"] == CLASS_KEYS


def test_unlock_wrong_password_fails_by_name():
    with pytest.raises(D.IOSBackupDecryptError, match="wrong backup password"):
        D.unlock_keybag(make_keybag(), password=b"not-it")
    with pytest.raises(D.IOSBackupDecryptError, match="exactly one"):
        D.unlock_keybag(make_keybag())


def test_unlock_rejects_non_backup_keybag():
    bag = make_keybag().replace(tlv("TYPE", 1), tlv("TYPE", 0))
    with pytest.raises(D.IOSBackupDecryptError, match="not a backup keybag"):
        D.unlock_keybag(bag, password=PASSWORD)


# ------------------------------------------------------------------ whole backup

def test_decrypt_backup_known_answer(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    database = build_backup(backup)
    out = tmp_path / "out"
    report = D.decrypt_backup(backup, out, password=PASSWORD)
    assert (out / "Manifest.db").read_bytes() == database
    assert report["manifest_class"] == 3
    assert report["unlocked_classes"] == [1, 3, 4]
    assert report["passcode_key_hex"] == expected_passcode_key().hex()
    by_path = {row["relative_path"]: row for row in report["files"]}
    assert set(by_path) == {"Library/Notes/notes.txt", "Documents/data.bin"}
    for file_id, _, relative, _, plain in FILES[:2]:
        row = by_path[relative]
        assert (out / row["output"]).read_bytes() == plain
        assert row["output"] == f"{file_id[:2]}/{file_id}"
        assert row["sha256"] == hashlib.sha256(plain).hexdigest()
        assert row["size_matches"] is True
    assert by_path["Library/Notes/notes.txt"]["flags"] == ["CSCTF{ios_backup_kat}"]
    assert [row["relative_path"] for row in report["errors"]] == ["Library/Locked.db"]
    assert "class 7" in report["errors"][0]["error"]
    index = json.loads((out / "index.json").read_text())
    assert index["files"] == report["files"]


def test_manifest_key_class_prefix_is_little_endian(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    build_backup(backup, manifest_class=4)
    report = D.decrypt_backup(backup, tmp_path / "out", password=PASSWORD, manifest_only=True)
    assert report["manifest_class"] == 4
    assert report["files"] == []


def test_filters_and_max_files(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    build_backup(backup)
    only = D.decrypt_backup(backup, tmp_path / "o1", password=PASSWORD, domain="AppDomain-com.example")
    assert [row["relative_path"] for row in only["files"]] == ["Documents/data.bin"]
    globbed = D.decrypt_backup(backup, tmp_path / "o2", password=PASSWORD, path_glob="Library/Notes/*")
    assert [row["relative_path"] for row in globbed["files"]] == ["Library/Notes/notes.txt"]
    capped = D.decrypt_backup(backup, tmp_path / "o3", password=PASSWORD, max_files=1)
    assert len(capped["files"]) + len(capped["errors"]) == 1
    assert capped["truncated_selection"] is True


def test_wrong_password_and_unencrypted_backup(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    build_backup(backup)
    with pytest.raises(D.IOSBackupDecryptError, match="wrong backup password"):
        D.decrypt_backup(backup, tmp_path / "out", password=b"nope")
    assert not (tmp_path / "out").exists()
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
    with pytest.raises(D.IOSBackupDecryptError, match="not encrypted"):
        D.decrypt_backup(plain, tmp_path / "out2", password=PASSWORD)


def test_tampered_manifest_db_named(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    build_backup(backup)
    data = bytearray((backup / "Manifest.db").read_bytes())
    data[0] ^= 0xFF
    (backup / "Manifest.db").write_bytes(bytes(data))
    with pytest.raises(D.IOSBackupDecryptError, match="not SQLite"):
        D.decrypt_backup(backup, tmp_path / "out", password=PASSWORD)


def test_manifest_db_padding_only_stripped_to_a_page_boundary():
    manifest_key = bytes([0x5A]) * 32
    database = bytearray(b"SQLite format 3\x00" + bytes(1024 - 16))
    database[-1] = 0x01  # looks like one byte of PKCS#7 padding if the file is not padded
    unpadded = AES.new(manifest_key, AES.MODE_CBC, iv=bytes(16)).encrypt(bytes(database))
    assert D.decrypt_manifest_db(unpadded, manifest_key) == bytes(database)
    assert D.decrypt_manifest_db(cbc(manifest_key, bytes(database)), manifest_key) == bytes(database)
    truncated = AES.new(manifest_key, AES.MODE_CBC, iv=bytes(16)).encrypt(bytes(database[:-16]))
    with pytest.raises(D.IOSBackupDecryptError, match="not whole SQLite pages"):
        D.decrypt_manifest_db(truncated, manifest_key)
    with pytest.raises(D.IOSBackupDecryptError, match="not SQLite"):
        D.decrypt_manifest_db(unpadded, bytes(32))


def test_unsafe_file_id_never_becomes_a_path(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    build_backup(backup)
    plain = D.decrypt_backup(backup, tmp_path / "first", password=PASSWORD, manifest_only=True)
    connection = sqlite3.connect(tmp_path / "first" / "Manifest.db")
    connection.execute("UPDATE Files SET fileID = '../../escape' WHERE relativePath = 'Documents/data.bin'")
    connection.commit()
    connection.close()
    manifest_key = bytes([0x5A]) * 32
    (backup / "Manifest.db").write_bytes(cbc(manifest_key, (tmp_path / "first" / "Manifest.db").read_bytes()))
    report = D.decrypt_backup(backup, tmp_path / "out", password=PASSWORD)
    assert plain["files"] == []
    bad = [row for row in report["errors"] if row["relative_path"] == "Documents/data.bin"]
    assert bad and "40-hex" in bad[0]["error"]
    assert not (tmp_path / "escape").exists()


def _record_with(prefix_class: int, protection_class, size: int, wrapped_key: bytes) -> bytes:
    root = {"$class": plistlib.UID(2), "Size": size, "EncryptionKey": plistlib.UID(3)}
    if protection_class is not None:
        root["ProtectionClass"] = protection_class
    objects = ["$null", root, {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]},
               {"NS.data": struct.pack("<I", prefix_class) + wrapped_key, "$class": plistlib.UID(2)}]
    return plistlib.dumps({"$version": 100000, "$archiver": "NSKeyedArchiver",
                           "$top": {"root": plistlib.UID(1)}, "$objects": objects}, fmt=plistlib.FMT_BINARY)


def test_file_protection_class_field_names_the_class_key():
    file_key = bytes([0x77]) * 32
    plain = b"protection class 4 file"
    wrapped = aes_key_wrap(CLASS_KEYS[4], file_key)
    # the key blob's prefix says 3, the record says 4: the record wins (iOS restore behaviour)
    result = D.decrypt_file(cbc(file_key, plain), _record_with(3, 4, len(plain), wrapped), CLASS_KEYS)
    assert result["plaintext"] == plain
    assert (result["protection_class"], result["key_class_prefix"]) == (4, 3)
    # no ProtectionClass field: the prefix is used
    result = D.decrypt_file(cbc(file_key, plain), _record_with(4, None, len(plain), wrapped), CLASS_KEYS)
    assert result["plaintext"] == plain and result["protection_class"] == 4
    with pytest.raises(D.IOSBackupDecryptError, match="integrity"):
        D.decrypt_file(cbc(file_key, plain), _record_with(4, 3, len(plain), wrapped), CLASS_KEYS)


def test_file_cut_to_declared_size():
    file_key = bytes([0x78]) * 32
    plain = b"0123456789abcdefXYZ"
    record = _record_with(1, 1, 16, aes_key_wrap(CLASS_KEYS[1], file_key))
    result = D.decrypt_file(cbc(file_key, plain), record, CLASS_KEYS)
    assert result["plaintext"] == plain[:16]
    assert result["truncated_to_size"] is True and result["size_matches"] is True
    longer = _record_with(1, 1, 99, aes_key_wrap(CLASS_KEYS[1], file_key))
    result = D.decrypt_file(cbc(file_key, plain), longer, CLASS_KEYS)
    assert result["plaintext"] == plain and result["size_matches"] is False


def test_missing_manifest_key_and_file_key_named():
    keyless = plistlib.dumps({"IsEncrypted": True, "BackupKeyBag": make_keybag()})
    with pytest.raises(D.IOSBackupDecryptError, match="no ManifestKey"):
        D.unwrap_manifest_key(keyless, CLASS_KEYS)
    with pytest.raises(D.IOSBackupDecryptError, match="no EncryptionKey"):
        D.decrypt_file(bytes(16), file_record(3, 1, None), CLASS_KEYS)
    with pytest.raises(D.IOSBackupDecryptError, match="not unlocked"):
        D.unwrap_manifest_key(plistlib.dumps({"IsEncrypted": True, "ManifestKey": struct.pack("<I", 9)
                                              + bytes(40)}), CLASS_KEYS)


def test_unwrap_manifest_key_requires_is_encrypted_true():
    manifest_key = bytes([0x5A]) * 32
    blob = struct.pack("<I", 3) + aes_key_wrap(CLASS_KEYS[3], manifest_key)
    good = {"IsEncrypted": True, "BackupKeyBag": make_keybag(), "ManifestKey": blob}
    assert D.unwrap_manifest_key(plistlib.dumps(good), CLASS_KEYS) == (3, manifest_key)
    # a valid ManifestKey is not enough: the plist itself must mark the backup encrypted (a
    # truthy non-boolean such as the string "true" or 1 is not the iOS marker either)
    for flag in (False, "true", 1, None):
        plist = dict(good)
        if flag is None:
            del plist["IsEncrypted"]
        else:
            plist["IsEncrypted"] = flag
        with pytest.raises(D.IOSBackupDecryptError, match="does not mark the backup as encrypted"):
            D.unwrap_manifest_key(plistlib.dumps(plist), CLASS_KEYS)
    with pytest.raises(D.IOSBackupDecryptError, match="does not mark the backup as encrypted"):
        D.unwrap_manifest_key(plistlib.dumps([blob]), CLASS_KEYS)


def test_legacy_single_stage_kdf_backup(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    build_backup(backup, double=False)
    report = D.decrypt_backup(backup, tmp_path / "out", password=PASSWORD,
                              path_glob="Library/Notes/*")
    assert report["passcode_key_hex"] == expected_passcode_key(double=False).hex()
    assert (tmp_path / "out" / report["files"][0]["output"]).read_bytes() == FILES[0][4]


def test_cli(tmp_path, capsys):
    backup = tmp_path / "backup"
    backup.mkdir()
    build_backup(backup)
    password_file = tmp_path / "pw"
    password_file.write_bytes(PASSWORD + b"\n")
    code = D.main([str(backup), str(tmp_path / "out"), "--password-file", str(password_file),
                   "--path-glob", "Library/Notes/*"])
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["files"][0]["flags"] == ["CSCTF{ios_backup_kat}"]
    # the locked-class file is selected without a filter: exit 1 names the failure
    assert D.main([str(backup), str(tmp_path / "out2"), "--passcode-key", expected_passcode_key().hex()]) == 1
    capsys.readouterr()
    assert D.main([str(backup), str(tmp_path / "out3"), "--passcode-key", "00" * 32]) == 2
    assert "wrong backup password" in capsys.readouterr().err
