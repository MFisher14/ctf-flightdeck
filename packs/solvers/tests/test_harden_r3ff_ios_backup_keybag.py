"""Independent vectors and fail-closed checks for ``ff2_ios_backup_keybag``.

The keybag bytes are produced by the small reference TLV encoder below (four
ASCII tag bytes, a big-endian uint32 length, then the value), not by the engine.
Manifest bytes are independently encoded and decoded with :mod:`plistlib`.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import plistlib
import random
import struct
import uuid

import pytest

import ff2_ios_backup_keybag as ios


BAG_UUID = uuid.UUID("10213243-5465-7687-98a9-bacbdcedfe0f")
CLASS_UUID = uuid.UUID("0011aa22-bb33-cc44-dd55-ee6677889900")


def ref_tlv(tag: str, value: bytes | int) -> bytes:
    """Encode one flat Apple keybag TLV without calling the engine."""

    raw_tag = tag.encode("ascii")
    assert len(raw_tag) == 4
    raw_value = struct.pack(">I", value) if isinstance(value, int) else value
    return raw_tag + struct.pack(">I", len(raw_value)) + raw_value


def reference_keybag() -> tuple[bytes, bytes, bytes, bytes]:
    classic_salt = bytes.fromhex("00112233445566778899aabbccddeeff00112233")
    wrapped_key = bytes(range(24))
    public_key = bytes(range(32, 64))
    records = (
        ref_tlv("VERS", 3),
        # Low 28 bits identify a backup keybag; high bits are independent flags.
        ref_tlv("TYPE", 0xA0000001),
        ref_tlv("UUID", BAG_UUID.bytes),
        # Both known wrap bits plus one unknown bit.
        ref_tlv("WRAP", 7),
        ref_tlv("SALT", classic_salt),
        ref_tlv("ITER", 123_456),
        ref_tlv("NOTE", b"independent-vector"),
        ref_tlv("UUID", CLASS_UUID.bytes),
        ref_tlv("CLAS", 6),
        ref_tlv("WRAP", 5),
        ref_tlv("KTYP", 2),
        ref_tlv("WPKY", wrapped_key),
        ref_tlv("PBKY", public_key),
    )
    return b"".join(records), classic_salt, wrapped_key, public_key


def reference_manifest(fmt: plistlib.PlistFormat) -> tuple[bytes, dict]:
    keybag, _, _, _ = reference_keybag()
    manifest = {
        "IsEncrypted": True,
        "BackupKeyBag": keybag,
        "ManifestKey": struct.pack(">I", 6) + b"K" * 24,
        "Version": "10.0",
        "BuildVersion": "21F90",
    }
    raw = plistlib.dumps(manifest, fmt=fmt, sort_keys=True)
    # The oracle validates that our independent serialization preserved exact
    # types and bytes before those bytes are handed to the engine.
    assert plistlib.loads(raw) == manifest
    return raw, manifest


def row(report: dict, key: str) -> object:
    assert key in report
    return report[key]


def test_parse_keybag_reference_tlv_vector() -> None:
    raw, salt, wrapped_key, public_key = reference_keybag()
    report = ios.parse_keybag(raw)

    assert report["record_count"] == 13
    assert report["version"] == 3
    assert report["type"] == 0xA0000001
    assert report["type_name"] == "backup"
    assert report["type_flags"] == 0xA0000000
    assert report["uuid"]["uuid"] == str(BAG_UUID)
    assert report["wrap"] == {
        "value": 7,
        "methods": ["device-uid", "passcode"],
        "unknown_bits": 4,
    }
    assert report["kdf"] == [
        {
            "stage": 1,
            "algorithm": "PBKDF2-HMAC-SHA1",
            "salt": {
                "length": len(salt),
                "sha256": hashlib.sha256(salt).hexdigest(),
                "hex": salt.hex(),
            },
            "iterations": 123_456,
            "complete": True,
        }
    ]
    assert report["unknown_header_records"][0]["tag"] == "NOTE"
    assert report["unknown_header_records"][0]["offset"] == 100
    assert report["class_count"] == 1
    class_row = report["classes"][0]
    assert class_row["uuid"]["uuid"] == str(CLASS_UUID)
    assert class_row["protection_class"] == 6
    assert class_row["key_type"] == 2
    assert class_row["wrap"] == {
        "value": 5,
        "methods": ["device-uid"],
        "unknown_bits": 4,
    }
    assert class_row["wrapped_key"] == {
        "length": len(wrapped_key),
        "sha256": hashlib.sha256(wrapped_key).hexdigest(),
    }
    assert class_row["public_key"] == {
        "length": len(public_key),
        "sha256": hashlib.sha256(public_key).hexdigest(),
    }
    assert report["decryption_attempted"] is False


@pytest.mark.parametrize("fmt", [plistlib.FMT_XML, plistlib.FMT_BINARY])
def test_inspect_manifest_matches_plistlib_vector(fmt: plistlib.PlistFormat) -> None:
    raw, manifest = reference_manifest(fmt)
    assert plistlib.loads(raw) == manifest

    report = ios.inspect_manifest(raw)
    assert report["format"] == "ios-backup-manifest"
    assert report["is_encrypted"] is True
    assert report["metadata"] == {
        "BuildVersion": "21F90",
        "IsEncrypted": True,
        "Version": "10.0",
    }
    assert report["manifest_key"]["protection_class"] == 6
    assert report["manifest_key"]["wrapped_key"] == {
        "length": 24,
        "sha256": hashlib.sha256(b"K" * 24).hexdigest(),
    }
    assert report["manifest_key"]["rfc3394_length_shape"] is True
    assert report["keybag"]["uuid"]["uuid"] == str(BAG_UUID)
    assert report["decryption_attempted"] is False


def test_no_key_or_password_api_and_no_kdf_without_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """A tripwire proves metadata inspection never derives or unwraps a key."""

    assert tuple(inspect.signature(ios.parse_keybag).parameters) == ("data",)
    assert tuple(inspect.signature(ios.inspect_manifest).parameters) == ("data",)

    def forbidden_kdf(*_args, **_kwargs):
        raise AssertionError("PBKDF2/decryption must not run during metadata inspection")

    monkeypatch.setattr(ios.hashlib, "pbkdf2_hmac", forbidden_kdf)
    keybag, _, _, _ = reference_keybag()
    manifest, _ = reference_manifest(plistlib.FMT_BINARY)
    assert ios.parse_keybag(keybag)["decryption_attempted"] is False
    inspected = ios.inspect_manifest(manifest)
    assert inspected["decryption_attempted"] is False
    assert inspected["keybag"]["decryption_attempted"] is False


def test_cli_vector_and_argparse_guard(tmp_path, capsys) -> None:
    keybag, _, _, _ = reference_keybag()
    source = tmp_path / "BackupKeyBag.bin"
    source.write_bytes(keybag)
    assert ios.main([str(source), "--raw-keybag"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["record_count"] == 13
    assert output["decryption_attempted"] is False
    assert ios.main(["--definitely-invalid"]) == 2
    assert ios.main(["--help"]) == 0


def _assert_fail_closed(function, value: object) -> None:
    try:
        result = function(value)
    except ios.FF2IOSBackupError:
        return
    except Exception as exc:  # pragma: no cover - contract failure diagnostic
        pytest.fail(f"{function.__name__} leaked {type(exc).__name__}: {exc}")
    assert isinstance(result, dict)


def test_parse_keybag_fail_closed_fuzz() -> None:
    valid, _, _, _ = reference_keybag()
    rng = random.Random(0x105B_A6)
    random_blob = bytes(rng.getrandbits(8) for _ in range(257))
    flipped = bytearray(valid)
    flipped[len(flipped) // 2] ^= 0x80
    corpus = (
        b"",
        random_blob,
        b"\xff" * 257,
        valid[:7],
        valid[:-1],
        bytes(flipped),
        b"A" * (ios.MAX_KEYBAG + 1),
    )
    for value in corpus:
        _assert_fail_closed(ios.parse_keybag, value)


def test_inspect_manifest_fail_closed_fuzz() -> None:
    valid, _ = reference_manifest(plistlib.FMT_BINARY)
    rng = random.Random(0xBACC_0FF)
    random_blob = bytes(rng.getrandbits(8) for _ in range(257))
    flipped = bytearray(valid)
    flipped[len(flipped) // 2] ^= 0x40
    corpus = (
        b"",
        random_blob,
        b"\xff" * 257,
        b"bplist00",  # real binary-plist magic, then truncated
        valid[:-1],
        bytes(flipped),
        b"A" * (ios.MAX_MANIFEST + 1),
    )
    for value in corpus:
        _assert_fail_closed(ios.inspect_manifest, value)


@pytest.mark.parametrize("function", [ios.parse_keybag, ios.inspect_manifest])
@pytest.mark.parametrize("value", [None, "not bytes", bytearray(b"x"), memoryview(b"x")])
def test_parse_entrypoints_reject_non_bytes_with_declared_error(function, value) -> None:
    with pytest.raises(ios.FF2IOSBackupError):
        function(value)
