#!/usr/bin/env python3
"""Inspect encrypted iOS-backup keybag and KDF metadata without decrypting.

``Manifest.plist`` is parsed with the standard property-list implementation.
``BackupKeyBag`` is a flat sequence of four-byte tag / big-endian length / value
records.  This module reports structure, KDF costs and wrap metadata only: it
accepts no password, runs no KDF, unwraps no key, and decrypts no backup data.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime
from functools import wraps
import hashlib
import json
from pathlib import Path
import plistlib
import sys
import uuid


MAX_MANIFEST = 16 << 20
MAX_KEYBAG = 8 << 20
MAX_RECORDS = 4096
MAX_RECORD_VALUE = 1 << 20
MAX_PLIST_ITEMS = 100_000
MAX_PLIST_DEPTH = 64

INTEGER_TAGS = {"VERS", "TYPE", "WRAP", "ITER", "DPIC", "CLAS", "KTYP"}
HEADER_TAGS = {"VERS", "TYPE", "UUID", "HMCK", "WRAP", "SALT", "ITER",
               "DPWT", "DPIC", "DPSL"}
CLASS_TAGS = {"UUID", "CLAS", "WRAP", "KTYP", "WPKY", "PBKY", "SEED", "WKEY"}

__all__ = ["FF2IOSBackupError", "parse_keybag", "inspect_manifest", "main"]


class FF2IOSBackupError(Exception):
    """Malformed, unsupported, or over-budget encrypted-backup metadata."""


def _closed(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FF2IOSBackupError:
            raise
        except Exception as exc:
            raise FF2IOSBackupError(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from exc
    return guarded


def _bytes(data, cap, what):
    if not isinstance(data, bytes) or not data:
        raise FF2IOSBackupError(f"{what} must be nonempty bytes")
    if len(data) > cap:
        raise FF2IOSBackupError(f"{what} exceeds its size cap")


def _plist_budget(root):
    stack = [(root, 0)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > MAX_PLIST_ITEMS or depth > MAX_PLIST_DEPTH:
            raise FF2IOSBackupError("property list exceeds structural cap")
        if isinstance(value, dict):
            if not all(isinstance(key, str) for key in value):
                raise FF2IOSBackupError("property-list dictionary key is not text")
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, (list, tuple)):
            stack.extend((item, depth + 1) for item in value)


def _uuid(raw: bytes) -> str | None:
    return str(uuid.UUID(bytes=raw)) if len(raw) == 16 else None


def _blob(raw: bytes, *, expose=False) -> dict:
    result = {"length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if expose:
        result["hex"] = raw.hex()
    canonical = _uuid(raw)
    if canonical is not None:
        result["uuid"] = canonical
    return result


def _wrap(value: int | None) -> dict | None:
    if value is None:
        return None
    methods = []
    if value & 1:
        methods.append("device-uid")
    if value & 2:
        methods.append("passcode")
    unknown = value & ~3
    return {"value": value, "methods": methods, "unknown_bits": unknown}


def _set_once(target: dict, tag: str, value):
    if tag in target:
        raise FF2IOSBackupError(f"duplicate {tag} record")
    target[tag] = value


@_closed
def parse_keybag(data: bytes) -> dict:
    """Parse one BackupKeyBag TLV blob into header and class-key metadata."""
    _bytes(data, MAX_KEYBAG, "keybag")
    records = []
    cursor = 0
    while cursor < len(data):
        if len(records) >= MAX_RECORDS:
            raise FF2IOSBackupError("keybag record count exceeds cap")
        if cursor + 8 > len(data):
            raise FF2IOSBackupError("truncated keybag record header")
        raw_tag = data[cursor:cursor + 4]
        try:
            tag = raw_tag.decode("ascii")
        except UnicodeDecodeError as exc:
            raise FF2IOSBackupError("keybag tag is not ASCII") from exc
        if any(char < " " or char > "~" for char in tag):
            raise FF2IOSBackupError("keybag tag is not printable ASCII")
        length = int.from_bytes(data[cursor + 4:cursor + 8], "big")
        value_at = cursor + 8
        stop = value_at + length
        if length > MAX_RECORD_VALUE or stop < value_at or stop > len(data):
            raise FF2IOSBackupError("keybag record length leaves input or exceeds cap")
        value = data[value_at:stop]
        if tag in INTEGER_TAGS and length != 4:
            raise FF2IOSBackupError(f"{tag} must be a four-byte integer")
        records.append((tag, value, cursor))
        cursor = stop
    if not records:
        raise FF2IOSBackupError("empty keybag")

    header: dict = {}
    header_unknown: list[dict] = []
    classes: list[dict] = []
    current: dict | None = None
    first_uuid = False
    for tag, raw, offset in records:
        if tag == "UUID":
            if not first_uuid:
                _set_once(header, tag, raw)
                first_uuid = True
                continue
            current = {"UUID": raw, "_offset": offset, "_unknown": []}
            classes.append(current)
            continue
        if current is None:
            # WRAP is valid in both scopes.  Before the second UUID it is the
            # keybag-header wrap method; only class-exclusive fields are early.
            if tag in CLASS_TAGS - HEADER_TAGS - {"UUID"}:
                raise FF2IOSBackupError(f"class tag {tag} appears before a class UUID")
            if tag in HEADER_TAGS:
                parsed = int.from_bytes(raw, "big") if tag in INTEGER_TAGS else raw
                _set_once(header, tag, parsed)
            else:
                header_unknown.append({"tag": tag, "offset": offset, **_blob(raw)})
        else:
            if tag in HEADER_TAGS - {"UUID", "WRAP"} and tag not in CLASS_TAGS:
                raise FF2IOSBackupError(f"header tag {tag} appears inside a class record")
            if tag in CLASS_TAGS:
                parsed = int.from_bytes(raw, "big") if tag in INTEGER_TAGS else raw
                _set_once(current, tag, parsed)
            else:
                current["_unknown"].append({"tag": tag, "offset": offset, **_blob(raw)})

    type_value = header.get("TYPE")
    base_type = type_value & 0x0FFFFFFF if isinstance(type_value, int) else None
    type_name = {0: "system", 1: "backup", 2: "escrow", 3: "icloud"}.get(
        base_type, "unknown"
    )
    warnings = []
    if type_value is not None and base_type != 1:
        warnings.append("TYPE does not identify a backup keybag")
    if not first_uuid:
        warnings.append("keybag UUID is absent")

    kdf = []
    if "DPSL" in header or "DPIC" in header:
        complete = "DPSL" in header and "DPIC" in header
        if not complete:
            warnings.append("double-protection KDF salt/iteration pair is incomplete")
        kdf.append({
            "stage": 1,
            "algorithm": "PBKDF2-HMAC-SHA256",
            "salt": _blob(header["DPSL"], expose=True) if "DPSL" in header else None,
            "iterations": header.get("DPIC"),
            "complete": complete,
        })
    if "SALT" in header or "ITER" in header:
        complete = "SALT" in header and "ITER" in header
        if not complete:
            warnings.append("classic KDF salt/iteration pair is incomplete")
        kdf.append({
            "stage": len(kdf) + 1,
            "algorithm": "PBKDF2-HMAC-SHA1",
            "salt": _blob(header["SALT"], expose=True) if "SALT" in header else None,
            "iterations": header.get("ITER"),
            "complete": complete,
        })

    class_rows = []
    for index, entry in enumerate(classes):
        if "CLAS" not in entry:
            warnings.append(f"class record {index} has no CLAS tag")
        if "WPKY" not in entry and "PBKY" not in entry:
            warnings.append(f"class record {index} has no wrapped/public key material")
        row = {
            "index": index,
            "offset": entry["_offset"],
            "uuid": _blob(entry["UUID"], expose=True),
            "protection_class": entry.get("CLAS"),
            "wrap": _wrap(entry.get("WRAP")),
            "key_type": entry.get("KTYP"),
            "wrapped_key": _blob(entry["WPKY"]) if "WPKY" in entry else None,
            "public_key": _blob(entry["PBKY"]) if "PBKY" in entry else None,
            "seed": _blob(entry["SEED"]) if "SEED" in entry else None,
            "other_key": _blob(entry["WKEY"]) if "WKEY" in entry else None,
            "unknown_records": entry["_unknown"],
        }
        class_rows.append(row)

    return {
        "record_count": len(records),
        "version": header.get("VERS"),
        "type": type_value,
        "type_name": type_name,
        "type_flags": (type_value & 0xF0000000) if isinstance(type_value, int) else None,
        "uuid": _blob(header["UUID"], expose=True) if "UUID" in header else None,
        "wrap": _wrap(header.get("WRAP")),
        "hmac": _blob(header["HMCK"]) if "HMCK" in header else None,
        "kdf": kdf,
        "class_count": len(class_rows),
        "classes": class_rows,
        "unknown_header_records": header_unknown,
        "warnings": warnings,
        "decryption_attempted": False,
    }


def _json_scalar(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return None


@_closed
def inspect_manifest(data: bytes) -> dict:
    """Inspect an iOS backup ``Manifest.plist`` and its keybag metadata."""
    _bytes(data, MAX_MANIFEST, "Manifest.plist")
    try:
        manifest = plistlib.loads(data)
    except Exception as exc:
        raise FF2IOSBackupError("Manifest.plist is not a valid property list") from exc
    _plist_budget(manifest)
    if not isinstance(manifest, dict):
        raise FF2IOSBackupError("Manifest.plist root must be a dictionary")
    encrypted = manifest.get("IsEncrypted")
    if type(encrypted) is not bool:
        raise FF2IOSBackupError("Manifest.plist IsEncrypted must be a Boolean")

    metadata = {}
    for key, value in manifest.items():
        if key in {"BackupKeyBag", "ManifestKey"}:
            continue
        scalar = _json_scalar(value)
        if scalar is not None:
            metadata[key] = scalar

    manifest_key = None
    raw_manifest_key = manifest.get("ManifestKey")
    if raw_manifest_key is not None:
        if not isinstance(raw_manifest_key, bytes) or len(raw_manifest_key) < 4:
            raise FF2IOSBackupError("ManifestKey must be bytes with a class prefix")
        wrapped = raw_manifest_key[4:]
        manifest_key = {
            "protection_class": int.from_bytes(raw_manifest_key[:4], "big"),
            "wrapped_key": _blob(wrapped),
            "rfc3394_length_shape": len(wrapped) >= 24 and len(wrapped) % 8 == 0,
        }

    if not encrypted:
        return {
            "format": "ios-backup-manifest",
            "is_encrypted": False,
            "metadata": metadata,
            "manifest_key": manifest_key,
            "keybag": None,
            "decryption_attempted": False,
        }
    raw_keybag = manifest.get("BackupKeyBag")
    if not isinstance(raw_keybag, bytes):
        raise FF2IOSBackupError("encrypted Manifest.plist lacks a byte BackupKeyBag")
    keybag = parse_keybag(raw_keybag)
    return {
        "format": "ios-backup-manifest",
        "is_encrypted": True,
        "metadata": metadata,
        "manifest_key": manifest_key,
        "keybag": keybag,
        "decryption_attempted": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Manifest.plist or raw keybag")
    parser.add_argument("--raw-keybag", action="store_true",
                        help="interpret input as BackupKeyBag TLV instead of a plist")
    try:
        args = parser.parse_args(argv)
        cap = MAX_KEYBAG if args.raw_keybag else MAX_MANIFEST
        with args.input.open("rb") as handle:
            data = handle.read(cap + 1)
        report = parse_keybag(data) if args.raw_keybag else inspect_manifest(data)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f"ff2_ios_backup_keybag: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
