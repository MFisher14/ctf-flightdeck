"""plistlib plus hand-built Apple keybag TLV vectors."""
from __future__ import annotations

import hashlib
import plistlib
import random
import struct
import uuid

import pytest

import ff2_ios_backup_keybag as ios


def tlv(tag: str, value: bytes | int) -> bytes:
    """Independent flat TLV encoder used by published keybag implementations."""
    if isinstance(value, int):
        value = struct.pack(">I", value)
    raw_tag = tag.encode("ascii")
    assert len(raw_tag) == 4
    return raw_tag + struct.pack(">I", len(value)) + value


def keybag_fixture():
    bag_uuid = uuid.UUID("00112233-4455-6677-8899-aabbccddeeff").bytes
    class1_uuid = uuid.UUID("11111111-2222-3333-4444-555555555555").bytes
    class4_uuid = uuid.UUID("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee").bytes
    salt = bytes(range(20))
    double_salt = bytes(range(32, 64))
    wrapped1 = bytes(range(40))
    wrapped4 = bytes(range(40, 80))
    fields = [
        tlv("VERS", 4), tlv("TYPE", 1), tlv("UUID", bag_uuid),
        tlv("HMCK", b"H" * 40), tlv("WRAP", 0),
        tlv("SALT", salt), tlv("ITER", 10_000),
        tlv("DPSL", double_salt), tlv("DPIC", 10_000_000),
        tlv("UUID", class1_uuid), tlv("CLAS", 1), tlv("WRAP", 2),
        tlv("KTYP", 0), tlv("WPKY", wrapped1),
        tlv("UUID", class4_uuid), tlv("CLAS", 4), tlv("WRAP", 3),
        tlv("KTYP", 0), tlv("WPKY", wrapped4), tlv("XTRA", b"future"),
    ]
    return b"".join(fields), salt, double_salt, wrapped1, wrapped4


def manifest_fixture(fmt=plistlib.FMT_BINARY):
    bag, *_ = keybag_fixture()
    manifest = {
        "IsEncrypted": True,
        "BackupKeyBag": bag,
        "ManifestKey": struct.pack(">I", 4) + b"M" * 40,
        "Lockdown": {"ProductVersion": "17.4", "BuildVersion": "21E219"},
        "Version": "9.1",
    }
    return plistlib.dumps(manifest, fmt=fmt, sort_keys=True), manifest


def test_keybag_published_tlv_semantics_vector():
    raw, salt, double_salt, wrapped1, wrapped4 = keybag_fixture()
    report = ios.parse_keybag(raw)
    assert report["version"] == 4
    assert report["type"] == 1 and report["type_name"] == "backup"
    assert report["uuid"]["uuid"] == "00112233-4455-6677-8899-aabbccddeeff"
    assert report["wrap"] == {"value": 0, "methods": [], "unknown_bits": 0}
    assert [(row["algorithm"], row["iterations"], row["salt"]["hex"])
            for row in report["kdf"]] == [
        ("PBKDF2-HMAC-SHA256", 10_000_000, double_salt.hex()),
        ("PBKDF2-HMAC-SHA1", 10_000, salt.hex()),
    ]
    assert report["class_count"] == 2
    assert [row["protection_class"] for row in report["classes"]] == [1, 4]
    assert report["classes"][0]["wrap"]["methods"] == ["passcode"]
    assert report["classes"][1]["wrap"]["methods"] == ["device-uid", "passcode"]
    assert report["classes"][0]["wrapped_key"] == {
        "length": 40, "sha256": hashlib.sha256(wrapped1).hexdigest()}
    assert report["classes"][1]["wrapped_key"]["sha256"] == hashlib.sha256(wrapped4).hexdigest()
    assert report["classes"][1]["unknown_records"][0]["tag"] == "XTRA"
    assert report["decryption_attempted"] is False


@pytest.mark.parametrize("fmt", [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_manifest_plistlib_oracle(fmt):
    raw, expected = manifest_fixture(fmt)
    assert plistlib.loads(raw) == expected  # independent stdlib oracle
    report = ios.inspect_manifest(raw)
    assert report["is_encrypted"] is True
    assert report["metadata"]["Version"] == "9.1"
    assert report["manifest_key"]["protection_class"] == 4
    assert report["manifest_key"]["wrapped_key"]["length"] == 40
    assert report["manifest_key"]["rfc3394_length_shape"] is True
    assert report["keybag"]["record_count"] == 20
    assert report["decryption_attempted"] is False


def test_unencrypted_manifest_is_metadata_only():
    raw = plistlib.dumps({"IsEncrypted": False, "Version": "3.3"})
    report = ios.inspect_manifest(raw)
    assert report == {
        "format": "ios-backup-manifest", "is_encrypted": False,
        "metadata": {"IsEncrypted": False, "Version": "3.3"},
        "manifest_key": None, "keybag": None, "decryption_attempted": False,
    }


def test_cli_guard_and_raw_mode(tmp_path, capsys):
    raw, *_ = keybag_fixture()
    source = tmp_path / "BackupKeyBag.bin"
    source.write_bytes(raw)
    assert ios.main([str(source), "--raw-keybag"]) == 0
    output = capsys.readouterr().out
    assert '"class_count": 2' in output and '"decryption_attempted": false' in output
    assert ios.main(["--bad-option"]) == 2


@pytest.mark.parametrize("raw", [
    b"VERS\0\0\0\x04\0\0",
    b"\xffERS\0\0\0\x04\0\0\0\x04",
    tlv("VERS", b"\0"),
    tlv("CLAS", 1),
    tlv("VERS", 4) + tlv("VERS", 4),
])
def test_malformed_keybag_declared_error(raw):
    with pytest.raises(ios.FF2IOSBackupError):
        ios.parse_keybag(raw)


def test_fail_closed_fuzz_and_bounds(monkeypatch):
    valid_bag, *_ = keybag_fixture()
    valid_plist, _ = manifest_fixture()
    rng = random.Random(0x105BA6)
    bag_corpus = [None, "ключ", bytearray(b"x"), b"", rng.randbytes(99)]
    bag_corpus.extend(valid_bag[:cut] for cut in range(0, len(valid_bag), 19))
    plist_corpus = [None, "plist", bytearray(b"x"), b"", rng.randbytes(128)]
    plist_corpus.extend(valid_plist[:cut] for cut in range(0, len(valid_plist), 37))
    for function, corpus in ((ios.parse_keybag, bag_corpus),
                             (ios.inspect_manifest, plist_corpus)):
        for raw in corpus:
            try:
                result = function(raw)
                assert isinstance(result, dict)
            except Exception as exc:
                assert type(exc) is ios.FF2IOSBackupError
    monkeypatch.setattr(ios, "MAX_KEYBAG", 32)
    with pytest.raises(ios.FF2IOSBackupError):
        ios.parse_keybag(b"A" * 33)
    monkeypatch.setattr(ios, "MAX_MANIFEST", 32)
    with pytest.raises(ios.FF2IOSBackupError):
        ios.inspect_manifest(b"A" * 33)

