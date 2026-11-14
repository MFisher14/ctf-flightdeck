#!/usr/bin/env python3
"""Decrypt an encrypted iOS (iTunes/Finder) backup with a supplied password or key.

``ff2_ios_backup_keybag`` reads the keybag and stops before any KDF.  This
helper finishes the job when the backup password (or an already-derived
passcode key) is known:

1. passcode key: ``PBKDF2-HMAC-SHA256(password, DPSL, DPIC, 32)`` then
   ``PBKDF2-HMAC-SHA1(that, SALT, ITER, 32)`` (iOS 10.2+); older keybags without
   ``DPSL``/``DPIC`` run only the SHA-1 stage;
2. every class key whose ``WRAP`` has the passcode bit is RFC 3394 unwrapped
   (``WPKY``) with the passcode key; a failed unwrap means a wrong password;
3. ``ManifestKey`` (4-byte little-endian protection class + wrapped key) is
   unwrapped with that class key and decrypts ``Manifest.db`` (AES-256-CBC, zero
   IV); the result must be an SQLite database;
4. each file row's ``file`` NSKeyedArchiver plist carries ``ProtectionClass`` and
   ``EncryptionKey`` (class prefix + wrapped per-file key); the file at
   ``<fileID[:2]>/<fileID>`` is AES-256-CBC (zero IV) decrypted, PKCS#7 unpadded
   and cut to ``Size``.

Outputs are written as ``<out>/<fileID[:2]>/<fileID>`` (never a path taken from
the backup) with ``<out>/index.json`` mapping each to its domain and relative
path.  Class keys wrapped only with the device UID cannot be opened offline;
they are listed in the report, and a file that needs one fails by name.

CLI::

    tools/ctfpy toolkits.ff2_ios_backup_decrypt BACKUP_DIR OUT_DIR
        (--password-file F | --passcode-key HEX) [--domain D] [--path-glob G] [--max-files N]
    tools/ctfpy toolkits.ff2_ios_backup_decrypt BACKUP_DIR OUT_DIR --password-file F --manifest-only
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
from pathlib import Path
import plistlib
import sqlite3
import sys
from typing import Any

try:
    from ctf import flagfmt
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

try:
    import ff2_ios_backup_keybag as _keybag_reader
except ModuleNotFoundError:
    sys.path.append(str(Path(__file__).resolve().parent))
    import ff2_ios_backup_keybag as _keybag_reader


WRAP_DEVICE = 1
WRAP_PASSCODE = 2
SQLITE_MAGIC = b"SQLite format 3\x00"
SQLITE_MIN_PAGE = 512
MAX_MANIFEST_DB = 2 * 1024 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024 * 1024
MAX_ITERATIONS = 50_000_000
FLAG_SCAN_BYTES = 16 * 1024 * 1024
FILE_FLAG_REGULAR = 1

__all__ = [
    "IOSBackupDecryptError",
    "aes_unwrap",
    "derive_passcode_key",
    "unlock_keybag",
    "unwrap_manifest_key",
    "decrypt_manifest_db",
    "decrypt_file",
    "decrypt_backup",
    "main",
]


class IOSBackupDecryptError(ValueError):
    """The supplied password/key or the backup material does not decrypt; the message says why."""


# --------------------------------------------------------------------------- primitives

def aes_unwrap(kek: bytes, wrapped: bytes) -> bytes:
    """RFC 3394 AES key unwrap; raises on an integrity failure (wrong key)."""

    from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

    try:
        return aes_key_unwrap(bytes(kek), bytes(wrapped))
    except InvalidUnwrap as exc:
        raise IOSBackupDecryptError("RFC 3394 unwrap integrity check failed") from exc
    except ValueError as exc:
        raise IOSBackupDecryptError(f"RFC 3394 unwrap rejected the input: {exc}") from exc


def _cbc_decrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(data) % 16:
        raise IOSBackupDecryptError(f"ciphertext length {len(data)} is not a multiple of 16")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def _pkcs7(data: bytes) -> tuple[bytes, bool]:
    if not data:
        return data, False
    count = data[-1]
    if 1 <= count <= 16 and count <= len(data) and all(b == count for b in data[-count:]):
        return data[:-count], True
    return data, False


# --------------------------------------------------------------------------- keybag

def _records(keybag: bytes) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Raw header and class records (the reader has already validated the layout)."""

    header: dict[str, Any] = {}
    classes: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    seen_uuid = False
    cursor = 0
    while cursor < len(keybag):
        tag = keybag[cursor:cursor + 4].decode("ascii")
        length = int.from_bytes(keybag[cursor + 4:cursor + 8], "big")
        value = keybag[cursor + 8:cursor + 8 + length]
        cursor += 8 + length
        parsed: Any = int.from_bytes(value, "big") if tag in _keybag_reader.INTEGER_TAGS else value
        if tag == "UUID":
            if not seen_uuid:
                header["UUID"] = value
                seen_uuid = True
                continue
            current = {"UUID": value}
            classes.append(current)
            continue
        (header if current is None else current)[tag] = parsed
    return header, classes


def _keybag(keybag: bytes) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    try:
        report = _keybag_reader.parse_keybag(bytes(keybag))
    except _keybag_reader.FF2IOSBackupError as exc:
        raise IOSBackupDecryptError(f"keybag does not parse: {exc}") from exc
    header, classes = _records(bytes(keybag))
    return report, header, classes


def derive_passcode_key(keybag: bytes, password: str | bytes, *, max_iterations: int = MAX_ITERATIONS) -> bytes:
    """Run the backup-password KDF named by the keybag and return the 32-byte passcode key."""

    _, header, _ = _keybag(keybag)
    secret = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    if "SALT" not in header or "ITER" not in header:
        raise IOSBackupDecryptError("keybag has no SALT/ITER: it is not password-protected")
    if ("DPSL" in header) != ("DPIC" in header):
        raise IOSBackupDecryptError("keybag has only one of DPSL/DPIC: the KDF is incomplete")
    for tag in ("DPIC", "ITER"):
        if tag in header and not 1 <= header[tag] <= max_iterations:
            raise IOSBackupDecryptError(f"{tag}={header[tag]} is outside 1..{max_iterations}")
    if "DPSL" in header:
        secret = hashlib.pbkdf2_hmac("sha256", secret, header["DPSL"], header["DPIC"], 32)
    return hashlib.pbkdf2_hmac("sha1", secret, header["SALT"], header["ITER"], 32)


def unlock_keybag(keybag: bytes, *, password: str | bytes | None = None,
                  passcode_key: bytes | None = None) -> dict[str, Any]:
    """Unwrap every passcode-wrapped class key.

    Returns ``{"passcode_key": bytes, "class_keys": {class: bytes}, "locked_classes": [...]}``.
    A wrong password raises instead of returning a partial result.
    """

    if (password is None) == (passcode_key is None):
        raise IOSBackupDecryptError("supply exactly one of password or passcode_key")
    report, _, classes = _keybag(keybag)
    if report["type_name"] != "backup":
        raise IOSBackupDecryptError(f"keybag TYPE is {report['type_name']!r}, not a backup keybag")
    key = derive_passcode_key(keybag, password) if passcode_key is None else bytes(passcode_key)
    if len(key) != 32:
        raise IOSBackupDecryptError(f"passcode key must be 32 bytes, got {len(key)}")
    class_keys: dict[int, bytes] = {}
    locked: list[dict[str, Any]] = []
    for entry in classes:
        number = entry.get("CLAS")
        wrap = entry.get("WRAP", 0)
        if number is None or "WPKY" not in entry:
            continue
        if not wrap & WRAP_PASSCODE:
            locked.append({"protection_class": number, "wrap": wrap,
                           "reason": "not passcode-wrapped (device UID only)"})
            continue
        if wrap & WRAP_DEVICE:
            locked.append({"protection_class": number, "wrap": wrap,
                           "reason": "also wrapped with the device UID: not openable offline"})
            continue
        try:
            class_keys[number] = aes_unwrap(key, entry["WPKY"])
        except IOSBackupDecryptError as exc:
            raise IOSBackupDecryptError(
                f"class {number} key does not unwrap with this passcode key: wrong backup password"
            ) from exc
    if not class_keys:
        raise IOSBackupDecryptError("no class key in the keybag is passcode-wrapped")
    return {"passcode_key": key, "class_keys": class_keys, "locked_classes": locked}


def _class_key(class_keys: dict[int, bytes], number: int, what: str) -> bytes:
    if number not in class_keys:
        raise IOSBackupDecryptError(
            f"{what} needs protection class {number}, which is not unlocked"
            f" (unlocked: {sorted(class_keys)})"
        )
    return class_keys[number]


def _wrapped_with_class(blob: bytes, what: str) -> tuple[int, bytes]:
    if not isinstance(blob, bytes) or len(blob) < 4 + 24:
        raise IOSBackupDecryptError(f"{what} must be a 4-byte class prefix plus a wrapped key")
    return int.from_bytes(blob[:4], "little"), blob[4:]


def unwrap_manifest_key(manifest_plist: bytes, class_keys: dict[int, bytes]) -> tuple[int, bytes]:
    """Return ``(protection_class, key)`` for ``Manifest.db`` from ``Manifest.plist``."""

    try:
        manifest = plistlib.loads(bytes(manifest_plist))
    except Exception as exc:  # noqa: BLE001 - plistlib raises several types
        raise IOSBackupDecryptError(f"Manifest.plist does not parse: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("IsEncrypted") is not True:
        raise IOSBackupDecryptError("Manifest.plist does not mark the backup as encrypted")
    blob = manifest.get("ManifestKey")
    if blob is None:
        raise IOSBackupDecryptError("Manifest.plist has no ManifestKey (pre-iOS 10 backup format)")
    number, wrapped = _wrapped_with_class(blob, "ManifestKey")
    key = aes_unwrap(_class_key(class_keys, number, "ManifestKey"), wrapped)
    return number, key


def decrypt_manifest_db(encrypted_db: bytes, manifest_key: bytes) -> bytes:
    """AES-256-CBC (zero IV) decrypt ``Manifest.db``; the result must be SQLite.

    An SQLite file is a whole number of pages (512 bytes at least), so PKCS#7
    padding is removed only when that leaves a page-aligned file; an unpadded,
    page-aligned plaintext is kept byte for byte.  Anything else is a truncated
    database and fails by name.
    """

    plain = _cbc_decrypt(manifest_key, bytes(encrypted_db))
    if not plain.startswith(SQLITE_MAGIC):
        raise IOSBackupDecryptError("decrypted Manifest.db is not SQLite: wrong manifest key")
    stripped, padded = _pkcs7(plain)
    if padded and len(stripped) % SQLITE_MIN_PAGE == 0:
        return stripped
    if len(plain) % SQLITE_MIN_PAGE == 0:
        return plain
    raise IOSBackupDecryptError(
        f"decrypted Manifest.db is {len(plain)} bytes: not whole SQLite pages, with or without"
        " PKCS#7 padding (truncated file)"
    )


def _file_record(blob: bytes) -> dict[str, Any]:
    try:
        archive = plistlib.loads(blob)
        objects = archive["$objects"]
        root = objects[archive["$top"]["root"].data]
    except Exception as exc:  # noqa: BLE001
        raise IOSBackupDecryptError(f"file record is not an MBFile NSKeyedArchiver plist: {exc}") from exc
    if not isinstance(root, dict):
        raise IOSBackupDecryptError("file record root is not a dictionary")
    key_ref = root.get("EncryptionKey")
    wrapped = None
    if key_ref is not None:
        try:
            holder = objects[key_ref.data]
            wrapped = holder["NS.data"] if isinstance(holder, dict) else holder
        except Exception as exc:  # noqa: BLE001
            raise IOSBackupDecryptError(f"file record EncryptionKey reference is broken: {exc}") from exc
    return {"protection_class": root.get("ProtectionClass"), "size": root.get("Size"),
            "encryption_key": wrapped}


def decrypt_file(encrypted: bytes, file_record: bytes, class_keys: dict[int, bytes]) -> dict[str, Any]:
    """Decrypt one backup file given its ``Files.file`` plist blob."""

    record = _file_record(file_record)
    if record["encryption_key"] is None:
        raise IOSBackupDecryptError("file record has no EncryptionKey")
    prefix, wrapped = _wrapped_with_class(record["encryption_key"], "EncryptionKey")
    # the record's ProtectionClass names the class key (as iOS restore does); the key blob's
    # little-endian prefix normally repeats it and is the fallback when the field is absent
    declared = record["protection_class"]
    number = declared if isinstance(declared, int) and not isinstance(declared, bool) else prefix
    key = aes_unwrap(_class_key(class_keys, number, "file key"), wrapped)
    plain, padded = _pkcs7(_cbc_decrypt(key, bytes(encrypted)))
    if not padded:
        raise IOSBackupDecryptError("decrypted file has no valid PKCS#7 padding: wrong key or corrupt file")
    size = record["size"]
    truncated = False
    if isinstance(size, int) and 0 <= size < len(plain):
        plain, truncated = plain[:size], True
    return {"plaintext": plain, "protection_class": number, "key_class_prefix": prefix,
            "declared_size": size,
            "size_matches": isinstance(size, int) and size == len(plain), "truncated_to_size": truncated}


# --------------------------------------------------------------------------- whole backup

def _read(path: Path, cap: int) -> bytes:
    if not path.is_file():
        raise IOSBackupDecryptError(f"missing backup file {path.name}")
    with path.open("rb") as handle:
        data = handle.read(cap + 1)
    if len(data) > cap:
        raise IOSBackupDecryptError(f"{path.name} exceeds the {cap}-byte cap")
    return data


def _flags(data: bytes) -> tuple[list[str], str | None]:
    try:
        return flagfmt.find_flags(data[:FLAG_SCAN_BYTES]), None
    except Exception as exc:  # noqa: BLE001 - no active event: reported, not hidden
        return [], f"{type(exc).__name__}: {exc}"[:240]


def _safe_file_id(file_id: Any) -> str:
    if not isinstance(file_id, str) or len(file_id) != 40 or any(c not in "0123456789abcdef" for c in file_id):
        raise IOSBackupDecryptError(f"fileID {file_id!r} is not a 40-hex SHA-1 name")
    return file_id


def decrypt_backup(backup_dir: Path | str, out_dir: Path | str, *, password: str | bytes | None = None,
                   passcode_key: bytes | None = None, domain: str | None = None,
                   path_glob: str | None = None, max_files: int | None = None,
                   manifest_only: bool = False) -> dict[str, Any]:
    """Decrypt ``Manifest.db`` and the selected files of a backup folder into ``out_dir``."""

    backup = Path(backup_dir)
    out = Path(out_dir)
    plist_bytes = _read(backup / "Manifest.plist", _keybag_reader.MAX_MANIFEST)
    try:
        inspected = _keybag_reader.inspect_manifest(plist_bytes)
    except _keybag_reader.FF2IOSBackupError as exc:
        raise IOSBackupDecryptError(f"Manifest.plist: {exc}") from exc
    if not inspected["is_encrypted"]:
        raise IOSBackupDecryptError("backup is not encrypted: read Manifest.db directly")
    keybag = plistlib.loads(plist_bytes)["BackupKeyBag"]
    unlocked = unlock_keybag(keybag, password=password, passcode_key=passcode_key)
    manifest_class, manifest_key = unwrap_manifest_key(plist_bytes, unlocked["class_keys"])
    database = decrypt_manifest_db(_read(backup / "Manifest.db", MAX_MANIFEST_DB), manifest_key)
    out.mkdir(parents=True, exist_ok=True)
    (out / "Manifest.db").write_bytes(database)
    report: dict[str, Any] = {
        "type": "ios-backup-decrypt",
        "passcode_key_hex": unlocked["passcode_key"].hex(),
        "unlocked_classes": sorted(unlocked["class_keys"]),
        "locked_classes": unlocked["locked_classes"],
        "manifest_class": manifest_class,
        "manifest_db": str(out / "Manifest.db"),
        "files": [],
        "errors": [],
    }
    if manifest_only:
        return report
    connection = sqlite3.connect(":memory:")
    try:
        connection.deserialize(database)
        rows = connection.execute(
            "SELECT fileID, domain, relativePath, flags, file FROM Files ORDER BY domain, relativePath"
        ).fetchall()
    except sqlite3.Error as exc:
        raise IOSBackupDecryptError(f"Manifest.db has no readable Files table: {exc}") from exc
    finally:
        connection.close()
    selected = 0
    for file_id, file_domain, relative, flags, blob in rows:
        if flags != FILE_FLAG_REGULAR:
            continue
        if domain is not None and file_domain != domain:
            continue
        if path_glob is not None and not fnmatch.fnmatchcase(relative or "", path_glob):
            continue
        if max_files is not None and selected >= max_files:
            report["truncated_selection"] = True
            break
        selected += 1
        entry: dict[str, Any] = {"file_id": file_id, "domain": file_domain, "relative_path": relative}
        try:
            safe_id = _safe_file_id(file_id)
            source = backup / safe_id[:2] / safe_id
            result = decrypt_file(_read(source, MAX_FILE), blob, unlocked["class_keys"])
            target = out / safe_id[:2] / safe_id
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(result["plaintext"])
            flags_found, flag_error = _flags(result["plaintext"])
            entry.update({
                "output": str(target.relative_to(out)),
                "bytes": len(result["plaintext"]),
                "sha256": hashlib.sha256(result["plaintext"]).hexdigest(),
                "protection_class": result["protection_class"],
                "size_matches": result["size_matches"],
                "flags": flags_found,
            })
            if flag_error:
                entry["flag_scan_error"] = flag_error
            report["files"].append(entry)
        except IOSBackupDecryptError as exc:
            entry["error"] = str(exc)
            report["errors"].append(entry)
    (out / "index.json").write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("backup_dir", type=Path)
    parser.add_argument("out_dir", type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--password-file", type=Path, help="file holding the backup password")
    group.add_argument("--passcode-key", help="already-derived 32-byte passcode key, hex")
    parser.add_argument("--domain")
    parser.add_argument("--path-glob")
    parser.add_argument("--max-files", type=int)
    parser.add_argument("--manifest-only", action="store_true")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        password = None
        passcode_key = None
        if args.password_file is not None:
            password = args.password_file.read_bytes().rstrip(b"\r\n")
        else:
            try:
                passcode_key = bytes.fromhex("".join(args.passcode_key.split()))
            except ValueError as exc:
                raise IOSBackupDecryptError("--passcode-key is not hex") from exc
        report = decrypt_backup(args.backup_dir, args.out_dir, password=password,
                                passcode_key=passcode_key, domain=args.domain,
                                path_glob=args.path_glob, max_files=args.max_files,
                                manifest_only=args.manifest_only)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report["errors"] else 0
    except (IOSBackupDecryptError, OSError) as exc:
        print(f"ff2_ios_backup_decrypt: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
