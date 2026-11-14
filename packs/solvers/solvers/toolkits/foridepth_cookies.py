#!/usr/bin/env python3
"""Offline Chrome/Edge AES-GCM cookies with supplied keys and strict host binding.

Chromium's app-bound provider tags AES-256-GCM ciphertext with ``v20``; the
following 12 bytes are the nonce and the final 16 bytes the authentication tag.
Cookie database schema >=24 prepends SHA256(host_key) to the plaintext. Schema
version is independent of the encryption tag. No key extraction, DPAPI calls,
profile discovery, token replay, or browser execution is performed.

SQLite/WAL reading is reused from browser_forensics/sqlite_artifacts. Only live
rows are emitted. Unsupported protection remains explicitly locked; when a key
is supplied, authentication/host failures reject the entire result.
The shared SQLite reader replaces invalid text. Database text containing U+FFFD
is conservatively rejected (including a genuine literal replacement character).
"""
from __future__ import annotations

import argparse
import base64
import functools
import hashlib
import hmac
import json
import sys
from pathlib import Path

MAX_INPUT = 64 << 20
MAX_VALUE = 1 << 20
MAX_ROWS = 100_000
DPAPI_MAGIC = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")


class ForidepthCookieError(ValueError):
    """Malformed, unsupported, unauthenticated, or over-budget evidence."""


def _guard(fn):
    @functools.wraps(fn)
    def checked(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ForidepthCookieError:
            raise
        except Exception as exc:
            # Reader/crypto dependencies also have a single public error contract.
            raise ForidepthCookieError(f"{fn.__name__}: invalid input ({type(exc).__name__})") from exc
    return checked


def _blob(value, cap=MAX_INPUT):
    if not isinstance(value, bytes) or len(value) > cap:
        raise ForidepthCookieError("expected bounded bytes")
    return value


def _text(value):
    if not isinstance(value, str) or len(value) > MAX_VALUE:
        raise ForidepthCookieError("expected bounded text")
    value.encode("utf-8", "strict")
    return value


@_guard
def decrypt_cookie(blob: bytes, key: bytes, *, host_key: str, schema_version: int) -> bytes:
    """Authenticate a Windows AES-GCM v10/v11/v20 cookie with its exact key.

    v10/v11 CBC envelopes from Linux/macOS are deliberately not guessed. For
    schema >=24 a wrong host is an error, never a reason to return the hash as
    part of the value. Bytes preserve non-UTF8 cookie payloads without loss.
    """
    _blob(blob, MAX_VALUE)
    _blob(key, 32)
    _text(host_key)
    if len(key) != 32 or type(schema_version) is not int or not 1 <= schema_version <= 24:
        raise ForidepthCookieError("need a 32-byte AES key and a supported schema (1..24)")
    if len(blob) < 31 or blob[:3] not in (b"v10", b"v11", b"v20"):
        raise ForidepthCookieError("not a supported AES-GCM cookie envelope")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    plain = AESGCM(key).decrypt(blob[3:15], blob[15:], None)
    if schema_version >= 24:
        digest = hashlib.sha256(host_key.encode("utf-8")).digest()
        if len(plain) < 32 or not hmac.compare_digest(plain[:32], digest):
            raise ForidepthCookieError("cookie host binding mismatch")
        plain = plain[32:]
    return plain


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ForidepthCookieError("duplicate Local State JSON key")
        result[key] = value
    return result


@_guard
def inspect_local_state(data: bytes) -> dict:
    """Identify DPAPI/APPB wrapping without exposing or unwrapping the key."""
    doc = json.loads(_blob(data, MAX_VALUE), object_pairs_hook=_no_duplicates)
    if not isinstance(doc, dict) or not isinstance(doc.get("os_crypt"), dict):
        raise ForidepthCookieError("Local State lacks os_crypt object")
    out = {}
    for name, prefix in (("encrypted_key", b"DPAPI"), ("app_bound_encrypted_key", b"APPB")):
        if name not in doc["os_crypt"]:
            continue
        encoded = _text(doc["os_crypt"][name])
        wrapped = base64.b64decode(encoded, validate=True)
        if len(wrapped) <= len(prefix) or not wrapped.startswith(prefix):
            raise ForidepthCookieError(f"invalid {name} wrapper")
        out[name] = {"wrapper": prefix.decode(), "wrapped_bytes": len(wrapped) - len(prefix),
                     "requires_external_key_recovery": True}
    if not out:
        raise ForidepthCookieError("no recognized wrapped keys in Local State")
    return out


def _value_json(value: bytes) -> dict:
    try:
        return {"value": value.decode("utf-8"), "value_encoding": "utf-8"}
    except UnicodeDecodeError:
        return {"value": base64.b64encode(value).decode("ascii"), "value_encoding": "base64"}


@_guard
def read_cookie_database(data: bytes, *, wal: bytes | None = None,
                         v20_key: bytes | None = None, legacy_key: bytes | None = None) -> dict:
    """Read a supplied Cookies SQLite snapshot; keys apply only to their tag family."""
    _blob(data)
    if wal is not None:
        _blob(wal)
    for key in (v20_key, legacy_key):
        if key is not None and (not isinstance(key, bytes) or len(key) != 32):
            raise ForidepthCookieError("each supplied key must be 32 bytes")
    try:
        import browser_forensics as browser
        import sqlite_artifacts as sqlite
    except ImportError:
        from . import browser_forensics as browser, sqlite_artifacts as sqlite
    bundle = browser.validate_sqlite_bundle(data, wal=wal)
    if bundle is None:
        raise ForidepthCookieError("invalid SQLite/WAL bundle")
    db = sqlite.Database(bundle[0], bundle[1], name="Cookies", carve=False)
    if db.error or db.truncated or not browser._database_bounded(db):
        raise ForidepthCookieError("SQLite snapshot is incomplete or over budget")
    columns = {name for name, *_ in db.columns.get("cookies", [])}
    if not {"host_key", "name", "path", "value", "encrypted_value"} <= columns:
        raise ForidepthCookieError("not a Chromium cookie schema")
    if {name.lower() for name in columns} & {"rowid", "_rowid_", "oid"}:
        raise ForidepthCookieError("cookie schema shadows SQLite row identity")
    versions = [row.get("value") for row in db.tables.get("meta", []) if row.get("key") == "version"]
    if len(versions) != 1 or isinstance(versions[0], bool) or str(versions[0]) not in {str(x) for x in range(1, 25)}:
        raise ForidepthCookieError("missing, ambiguous, or unsupported cookie schema version")
    version = int(versions[0])
    rows = db.tables.get("cookies", [])
    if len(rows) > MAX_ROWS:
        raise ForidepthCookieError("too many cookies")
    out = []
    total = 0
    for row in rows:
        if any(isinstance(v, str) and "\ufffd" in v for v in row.values()):
            raise ForidepthCookieError("cookie text may have been replaced during SQLite decoding")
        host, name, path = (_text(row[field]) for field in ("host_key", "name", "path"))
        value = _text(row["value"])
        encrypted = _blob(row["encrypted_value"], MAX_VALUE)
        if encrypted and value:
            raise ForidepthCookieError("cookie contains both plaintext and ciphertext")
        rowid = row.get("_rowid")
        if rowid is not None and (type(rowid) is not int or not -(1 << 63) <= rowid < (1 << 63)):
            raise ForidepthCookieError("invalid SQLite row identity")
        item = {"rowid": rowid, "host_key": host, "name": name, "path": path}
        for field in ("creation_utc", "expires_utc", "last_access_utc", "last_update_utc",
                      "is_secure", "is_httponly", "samesite", "top_frame_site_key"):
            if field in row:
                if field == "top_frame_site_key":
                    item[field] = _text(row[field])
                elif type(row[field]) is int and -(1 << 63) <= row[field] < (1 << 63):
                    item[field] = row[field]
                else:
                    raise ForidepthCookieError(f"invalid cookie metadata field {field}")
        if not encrypted:
            item.update(status="plaintext", protection="none", authenticated=False)
            plain = value.encode("utf-8")
        else:
            tag = encrypted[:3]
            if tag in (b"v10", b"v11", b"v20"):
                if len(encrypted) < 31:
                    # These may be CBC, but this engine is explicit about its GCM scope.
                    raise ForidepthCookieError("short or non-GCM encrypted cookie")
                protection = tag.decode("ascii")
            elif encrypted.startswith(DPAPI_MAGIC):
                protection = "dpapi"
            else:
                protection = "unsupported"
            item["protection"] = protection
            key = v20_key if tag == b"v20" else legacy_key if tag in (b"v10", b"v11") else None
            if key is None:
                item.update(status="locked", authenticated=False, value=None,
                            ciphertext_sha256=hashlib.sha256(encrypted).hexdigest())
                out.append(item)
                continue
            plain = decrypt_cookie(encrypted, key, host_key=host, schema_version=version)
            item.update(status="decrypted", authenticated=True, host_bound=version >= 24)
        total += len(plain)
        if total > MAX_INPUT:
            raise ForidepthCookieError("cookie values exceed output budget")
        item.update(_value_json(plain))
        out.append(item)
    return {"schema_version": version, "wal_frames": bundle[2], "cookies": out,
            "source_sha256": hashlib.sha256(data).hexdigest()}


@_guard
def read_file(path: str, cap: int = MAX_INPUT) -> bytes:
    if type(cap) is not int or not 0 <= cap <= MAX_INPUT:
        raise ForidepthCookieError("invalid read cap")
    with Path(path).open("rb") as stream:
        return _blob(stream.read(cap + 1), cap)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    db = subs.add_parser("database")
    db.add_argument("file")
    db.add_argument("--wal")
    db.add_argument("--v20-key-file", help="supplied raw 32-byte app-bound key")
    db.add_argument("--legacy-key-file", help="supplied raw 32-byte v10/v11 Windows key")
    blob = subs.add_parser("blob")
    blob.add_argument("file")
    blob.add_argument("--key-file", required=True)
    blob.add_argument("--host", required=True)
    blob.add_argument("--schema-version", required=True, type=int)
    state = subs.add_parser("local-state")
    state.add_argument("file")
    try:
        args = parser.parse_args(argv)
        data = read_file(args.file)
        if args.command == "local-state":
            result = inspect_local_state(data)
        elif args.command == "blob":
            result = _value_json(decrypt_cookie(data, read_file(args.key_file, 32),
                                               host_key=args.host, schema_version=args.schema_version))
        else:
            result = read_cookie_database(data, wal=read_file(args.wal) if args.wal else None,
                v20_key=read_file(args.v20_key_file, 32) if args.v20_key_file else None,
                legacy_key=read_file(args.legacy_key_file, 32) if args.legacy_key_file else None)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except (ForidepthCookieError, OSError) as exc:
        print(f"foridepth_cookies: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
