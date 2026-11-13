"""Strict offline browser-forensics readers over caller-supplied bytes.

This module complements :mod:`sqlite_artifacts` and :mod:`browser_session`.  It does not
discover profiles, open caller paths, contact URLs, or execute browser code.  SQLite files are
accepted only with a coherent header and, when supplied, a complete checksum-valid WAL.  LevelDB
records are accepted only from CRC32C-valid log records whose write batches consume exactly.
Malformed, truncated, ambiguous, or resource-exhausting inputs return ``None``.
"""

from __future__ import annotations

import hashlib
import plistlib
import re
import struct
from dataclasses import dataclass
from typing import Mapping, Sequence
from urllib.parse import urlsplit

try:
    import browser_session as _sessions
    import sqlite_artifacts as _sqlite
except ImportError:  # package-style import
    from . import browser_session as _sessions
    from . import sqlite_artifacts as _sqlite


MAX_ARTIFACT = 256 << 20
MAX_WAL = 256 << 20
MAX_SHM = 16 << 20
MAX_RECORDS = 200_000
MAX_VALUE = 16 << 20
MAX_AUX_BYTES = 256 << 20
MAX_LEVELDB_BATCH = 64 << 20
MAX_TEXT = 1 << 20
MAX_HEADERS = 512
MAX_SESSION_ENTRIES = 100_000
SQLITE_MAGIC = b"SQLite format 3\x00"
LEVELDB_BLOCK = 32_768


@dataclass(frozen=True, slots=True)
class BrowserRecord:
    browser: str
    artifact: str
    kind: str
    source: str
    url: str | None = None
    title: str | None = None
    host: str | None = None
    key: str | None = None
    value: str | bytes | None = None
    path: str | None = None
    timestamp: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class BrowserDatabaseReport:
    browser: str
    artifact: str
    schema: str
    records: tuple[BrowserRecord, ...]
    wal_frames: int
    supplied_shm: bool
    sha256: str


@dataclass(frozen=True, slots=True)
class StorageRecord:
    browser: str
    store: str
    sequence: int
    state: str
    origin: str | None
    key: str | bytes
    value: str | bytes | None
    source: str


@dataclass(frozen=True, slots=True)
class CacheObject:
    browser: str
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class SessionEntry:
    browser: str
    url: str
    title: str | None
    selected: bool
    closed: bool
    source_index: int
    semantic_verified: bool


@dataclass(frozen=True, slots=True)
class SessionReport:
    browser: str
    format: str
    entries: tuple[SessionEntry, ...]
    metadata: tuple[tuple[str, str], ...]
    sha256: str


def _blob(value: object, cap: int = MAX_ARTIFACT, *, empty: bool = False) -> bytes | None:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        return None
    if len(value) > cap:
        return None
    raw = bytes(value)
    if (not raw and not empty) or len(raw) > cap:
        return None
    return raw


def _bounded_text(value: object, cap: int = MAX_TEXT) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > cap or "\x00" in value:
        return None
    return value


def _page_size(data: bytes) -> int | None:
    if len(data) < 100 or data[:16] != SQLITE_MAGIC:
        return None
    raw = struct.unpack_from(">H", data, 16)[0]
    size = 65_536 if raw == 1 else raw
    if size < 512 or size > 65_536 or size & (size - 1):
        return None
    if len(data) % size or data[18] not in (1, 2) or data[19] not in (1, 2):
        return None
    if data[20] > size - 480:
        return None
    return size


def _wal_words(data: bytes, endian: str, state: tuple[int, int]) -> tuple[int, int] | None:
    if len(data) % 8:
        return None
    s1, s2 = state
    for off in range(0, len(data), 8):
        a, b = struct.unpack_from(endian + "II", data, off)
        s1 = (s1 + a + s2) & 0xFFFFFFFF
        s2 = (s2 + b + s1) & 0xFFFFFFFF
    return s1, s2


def _validate_wal(wal: bytes, page_size: int) -> int | None:
    if len(wal) < 32:
        return None
    magic, version, size, _checkpoint, salt1, salt2, c1, c2 = struct.unpack_from(">8I", wal, 0)
    if magic not in (0x377F0682, 0x377F0683) or version != 3_007_000:
        return None
    size = 65_536 if size == 1 else size
    if size != page_size:
        return None
    unit = 24 + size
    if (len(wal) - 32) % unit or len(wal) == 32:
        return None
    count = (len(wal) - 32) // unit
    if count > MAX_RECORDS:
        return None
    endian = "<" if magic == 0x377F0682 else ">"
    state = _wal_words(wal[:24], endian, (0, 0))
    if state is None or state != (c1, c2):
        return None
    committed = False
    pending_max = 0
    for index in range(count):
        off = 32 + index * unit
        page, commit, fs1, fs2, fc1, fc2 = struct.unpack_from(">6I", wal, off)
        if page == 0 or (fs1, fs2) != (salt1, salt2):
            return None
        pending_max = max(pending_max, page)
        state = _wal_words(wal[off:off + 8] + wal[off + 24:off + unit], endian, state)
        if state is None or state != (fc1, fc2):
            return None
        if commit:
            if pending_max > commit:
                return None
            committed = True
            pending_max = 0
    return count if committed else None


def _validate_shm(_shm: bytes) -> bool:
    """Conservatively decline WAL-index files.

    A SHM header is native-endian and transient.  Header twins alone do not bind it to the
    supplied database/WAL; safely proving all salts, read marks, checksums, and hash tables would
    require reproducing SQLite's platform-specific wal-index implementation.  SQLite rebuilds the
    index from the checked WAL, so this reader deliberately never consumes SHM evidence.
    """

    return False


def validate_sqlite_bundle(data: object, *, wal: object | None = None,
                           shm: object | None = None) -> tuple[bytes, bytes | None, int] | None:
    """Return ``(database, wal, frame_count)`` only for a complete coherent bundle."""
    raw = _blob(data)
    if raw is None:
        return None
    size = _page_size(raw)
    if size is None:
        return None
    side_wal: bytes | None = None
    frames = 0
    if wal is not None:
        side_wal = _blob(wal, MAX_WAL)
        if side_wal is None:
            return None
        got = _validate_wal(side_wal, size)
        if got is None:
            return None
        frames = got
    if shm is not None:
        # A supplied SHM is never silently trusted or reported as used.
        return None
    return raw, side_wal, frames


def _schema(db: _sqlite.Database) -> tuple[str, str, str] | None:
    cols = {name: {c[0] for c in values} for name, values in db.columns.items()}
    has = lambda table, *names: table in cols and all(name in cols[table] for name in names)
    matches: list[tuple[str, str, str]] = []
    if ((has("urls", "url", "visit_count") and "visits" in cols)
            or has("downloads", "target_path") or has("downloads", "url")):
        matches.append(("chromium", "history", "chromium_history"))
    if has("cookies", "host_key", "name"):
        matches.append(("chromium", "cookies", "chromium_cookies"))
    if has("moz_places", "url"):
        matches.append(("firefox", "history", "firefox_places"))
    if has("moz_cookies", "host", "name"):
        matches.append(("firefox", "cookies", "firefox_cookies"))
    if has("webappsstore2", "key", "value"):
        matches.append(("firefox", "localstorage", "firefox_webappsstore"))
    if has("history_items", "url") and has("history_visits", "visit_time"):
        matches.append(("safari", "history", "safari_history"))
    if has("ItemTable", "key", "value"):
        matches.append(("safari", "localstorage", "safari_localstorage"))
    if has("object_data", "object_store_id", "key", "data"):
        matches.append(("firefox", "indexeddb", "firefox_indexeddb"))
    if (has("cfurl_cache_response", "entry_ID", "request_key")
            and has("cfurl_cache_receiver_data", "entry_ID", "receiver_data")):
        matches.append(("safari", "cache", "safari_cache"))
    # Mixed recognized schemas are ambiguous even when the broad reader would choose one first.
    return matches[0] if len(matches) == 1 else None


def _database_bounded(db: _sqlite.Database) -> bool:
    total_rows = 0
    total_values = 0
    try:
        for table, rows in db.tables.items():
            if table.startswith("sqlite_"):
                continue
            total_rows += len(rows)
            if total_rows > MAX_RECORDS:
                return False
            for row in rows:
                if not isinstance(row, Mapping):
                    return False
                for value in row.values():
                    if isinstance(value, (bytes, str)):
                        total_values += len(value)
                        if len(value) > MAX_VALUE or total_values > MAX_AUX_BYTES:
                            return False
    except Exception:
        return False
    return True


def _meta(values: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    for key, value in values.items():
        if value is None or key.startswith("_"):
            continue
        if isinstance(value, (str, int, float, bool)):
            text = str(value)
        elif isinstance(value, bytes) and len(value) <= 64:
            text = value.hex()
        else:
            continue
        if len(key) <= 128 and len(text) <= 4096:
            out.append((key, text))
    return tuple(sorted(out)[:128])


def _stamp(record: Mapping[str, object]) -> str | None:
    times = record.get("t")
    if not isinstance(times, Mapping):
        return None
    for value in times.values():
        if isinstance(value, tuple) and len(value) == 2 and value[1] is not None:
            try:
                return value[1].isoformat()
            except (AttributeError, ValueError, OverflowError):
                return None
    return None


def _generic_records(db: _sqlite.Database, browser: str, artifact: str) -> tuple[BrowserRecord, ...] | None:
    try:
        records = _sqlite.records(db, art=artifact)
    except Exception:
        return None
    if len(records) > MAX_RECORDS:
        return None
    out: list[BrowserRecord] = []
    for record in records:
        if not isinstance(record, Mapping) or record.get("src") != "live":
            return None
        fields = record.get("f")
        if not isinstance(fields, Mapping):
            return None
        kind = _bounded_text(record.get("kind"), 64)
        if kind is None:
            return None
        chain = fields.get("url_chain")
        url = fields.get("url")
        if url is None and isinstance(chain, list) and chain:
            url = chain[-1]
        value = fields.get("value")
        if isinstance(value, (str, bytes)) and len(value) > MAX_VALUE:
            return None
        if value is not None and not isinstance(value, (str, bytes)):
            value = str(value) if isinstance(value, (int, float, bool)) else None
        out.append(BrowserRecord(
            browser=browser,
            artifact=artifact,
            kind=kind,
            source="live",
            url=_bounded_text(url),
            title=_bounded_text(fields.get("title")),
            host=_bounded_text(fields.get("host"), 4096),
            key=_bounded_text(fields.get("key")),
            value=value,
            path=_bounded_text(fields.get("path")),
            timestamp=_stamp(record),
            metadata=_meta(fields),
        ))
    return tuple(out)


def _custom_records(db: _sqlite.Database, browser: str, artifact: str,
                    schema: str) -> tuple[BrowserRecord, ...] | None:
    out: list[BrowserRecord] = []
    if schema == "safari_localstorage":
        rows = db.rows("ItemTable", recovered=False)
        for row in rows:
            key, value = row.get("key"), row.get("value")
            if _bounded_text(key) is None or not isinstance(value, (str, bytes)) or len(value) > MAX_VALUE:
                return None
            out.append(BrowserRecord(browser, artifact, "storage", "live", key=key,
                                     value=value, metadata=_meta(row)))
    elif schema == "firefox_indexeddb":
        rows = db.rows("object_data", recovered=False)
        for row in rows:
            key, value = row.get("key"), row.get("data")
            if not isinstance(key, (str, bytes)) or not isinstance(value, (str, bytes)):
                return None
            if len(key) > MAX_VALUE or len(value) > MAX_VALUE:
                return None
            out.append(BrowserRecord(browser, artifact, "indexeddb", "live",
                                     key=key if isinstance(key, str) else key.hex(), value=value,
                                     metadata=_meta(row)))
    elif schema == "safari_cache":
        body_rows = db.rows("cfurl_cache_receiver_data", recovered=False)
        response_rows = db.rows("cfurl_cache_response", recovered=False)
        if len(body_rows) + len(response_rows) > MAX_RECORDS:
            return None
        bodies: dict[object, bytes] = {}
        body_total = 0
        for row in body_rows:
            ident, body = row.get("entry_ID"), row.get("receiver_data")
            if ident is None or ident in bodies or not isinstance(body, bytes) or not body:
                return None
            body_total += len(body)
            if len(body) > MAX_VALUE or body_total > MAX_AUX_BYTES:
                return None
            bodies[ident] = body
        seen_responses: set[object] = set()
        for row in response_rows:
            ident, url = row.get("entry_ID"), row.get("request_key")
            if ident is None or ident in seen_responses:
                return None
            seen_responses.add(ident)
            body = bodies.get(ident)
            if _bounded_text(url) is None or not isinstance(body, bytes) or not body:
                return None
            if len(body) > MAX_VALUE:
                return None
            out.append(BrowserRecord(browser, artifact, "cache", "live", url=url, value=body,
                                     metadata=_meta(row)))
        if seen_responses != set(bodies):
            return None
    else:
        return None
    return tuple(out) if len(out) <= MAX_RECORDS else None


def decode_browser_database(data: object, *, wal: object | None = None,
                            shm: object | None = None,
                            artifact: str = "browser.sqlite") -> BrowserDatabaseReport | None:
    """Decode a recognized Chrome/Firefox/Safari database and optional supplied WAL/SHM."""
    if not isinstance(artifact, str) or not artifact or len(artifact) > 4096:
        return None
    bundle = validate_sqlite_bundle(data, wal=wal, shm=shm)
    if bundle is None:
        return None
    raw, side_wal, frames = bundle
    try:
        db = _sqlite.Database(raw, side_wal, None, name=artifact, carve=False)
    except Exception:
        return None
    if db.error or db.truncated or not _database_bounded(db):
        return None
    identified = _schema(db)
    if identified is None:
        return None
    browser, artifact_kind, schema = identified
    if schema in {"safari_localstorage", "firefox_indexeddb", "safari_cache"}:
        records = _custom_records(db, browser, artifact_kind, schema)
    else:
        records = _generic_records(db, browser, artifact_kind)
    if records is None:
        return None
    return BrowserDatabaseReport(browser, artifact_kind, schema, records, frames,
                                 False, hashlib.sha256(raw).hexdigest())


# Castagnoli CRC used by LevelDB log records.
_CRC32C_TABLE: tuple[int, ...] | None = None


def _crc32c(data: bytes) -> int:
    global _CRC32C_TABLE
    if _CRC32C_TABLE is None:
        table = []
        for value in range(256):
            crc = value
            for _ in range(8):
                crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
            table.append(crc & 0xFFFFFFFF)
        _CRC32C_TABLE = tuple(table)
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return (crc ^ 0xFFFFFFFF) & 0xFFFFFFFF


def _unmask_crc(value: int) -> int:
    value = (value - 0xA282EAD8) & 0xFFFFFFFF
    return ((value >> 17) | (value << 15)) & 0xFFFFFFFF


def _varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    shift = 0
    for _ in range(10):
        if offset >= len(data):
            return None
        byte = data[offset]
        offset += 1
        if shift == 63 and byte > 1:
            return None
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
    return None


def _write_batch(data: bytes) -> tuple[tuple[int, str, bytes, bytes | None], ...] | None:
    if len(data) < 12:
        return None
    sequence, count = struct.unpack_from("<QI", data, 0)
    if count == 0 or count > MAX_RECORDS or sequence >= 1 << 56 or sequence + count >= 1 << 56:
        return None
    out: list[tuple[int, str, bytes, bytes | None]] = []
    offset = 12
    for index in range(count):
        if offset >= len(data) or data[offset] not in (0, 1):
            return None
        tag = data[offset]
        offset += 1
        got = _varint(data, offset)
        if got is None:
            return None
        length, offset = got
        if length > MAX_VALUE or offset + length > len(data):
            return None
        key = data[offset:offset + length]
        offset += length
        value = None
        if tag == 1:
            got = _varint(data, offset)
            if got is None:
                return None
            length, offset = got
            if length > MAX_VALUE or offset + length > len(data):
                return None
            value = data[offset:offset + length]
            offset += length
        out.append((sequence + index, "live" if tag else "deleted", key, value))
    return tuple(out) if offset == len(data) else None


def _leveldb_batches(data: bytes) -> tuple[tuple[int, str, bytes, bytes | None], ...] | None:
    fragments: list[bytes] = []
    fragment_total = 0
    output: list[tuple[int, str, bytes, bytes | None]] = []
    last_sequence = -1
    offset = 0
    while offset < len(data):
        block_left = LEVELDB_BLOCK - offset % LEVELDB_BLOCK
        if block_left < 7:
            if any(data[offset:offset + block_left]):
                return None
            offset += block_left
            continue
        if len(data) - offset < 7:
            return (tuple(output) if output and len(data) - offset == block_left
                    and not any(data[offset:]) else None)
        masked, length, kind = struct.unpack_from("<IHB", data, offset)
        if masked == 0 and length == 0 and kind == 0:
            if any(data[offset:offset + block_left]):
                return None
            offset += block_left
            continue
        if kind not in (1, 2, 3, 4) or length > block_left - 7 or offset + 7 + length > len(data):
            return None
        payload = data[offset + 7:offset + 7 + length]
        if _unmask_crc(masked) != _crc32c(bytes([kind]) + payload):
            return None
        offset += 7 + length
        if kind == 1:
            if fragments or len(payload) > MAX_LEVELDB_BATCH:
                return None
            batch = _write_batch(payload)
        elif kind == 2:
            if fragments:
                return None
            fragments = [payload]
            fragment_total = len(payload)
            if fragment_total > MAX_LEVELDB_BATCH:
                return None
            continue
        elif kind == 3:
            if not fragments:
                return None
            fragments.append(payload)
            fragment_total += len(payload)
            if fragment_total > MAX_LEVELDB_BATCH:
                return None
            continue
        else:
            if not fragments:
                return None
            fragments.append(payload)
            fragment_total += len(payload)
            if fragment_total > MAX_LEVELDB_BATCH:
                return None
            batch = _write_batch(b"".join(fragments))
            fragments = []
            fragment_total = 0
        if batch is None or len(output) + len(batch) > MAX_RECORDS:
            return None
        if batch[0][0] <= last_sequence:
            return None
        for index in range(1, len(batch)):
            if batch[index][0] != batch[index - 1][0] + 1:
                return None
        last_sequence = batch[-1][0]
        output.extend(batch)
    if fragments or not output:
        return None
    return tuple(output)


def _local_text(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    if len(raw) > MAX_VALUE:
        return None
    try:
        if raw[:1] == b"\x01":
            return raw[1:].decode("latin-1")
        if raw[:1] == b"\x00" and len(raw) % 2 == 1:
            return raw[1:].decode("utf-16-le")
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def decode_leveldb_storage(data: object, *, store: str,
                           origin: str | None = None,
                           source: str = "000001.log") -> tuple[StorageRecord, ...] | None:
    """Decode a checksum-valid Chromium LevelDB log as localStorage or opaque IndexedDB rows."""
    raw = _blob(data)
    if raw is None or not isinstance(store, str) or store not in {"localstorage", "indexeddb"}:
        return None
    if not isinstance(source, str) or not source or len(source) > 4096:
        return None
    if origin is not None and _bounded_text(origin, 4096) is None:
        return None
    batches = _leveldb_batches(raw)
    if batches is None:
        return None
    out: list[StorageRecord] = []
    for sequence, state, key, value in batches:
        if store == "localstorage":
            if not key.startswith(b"_") or b"\x00" not in key:
                return None
            raw_origin, raw_key = key[1:].split(b"\x00", 1)
            try:
                row_origin = raw_origin.decode("utf-8")
            except UnicodeDecodeError:
                return None
            if _bounded_text(row_origin, 4096) is None:
                return None
            text_key = _local_text(raw_key)
            text_value = _local_text(value)
            if not row_origin or text_key is None or state == "live" and text_value is None:
                return None
            out.append(StorageRecord("chromium", store, sequence, state, row_origin,
                                     text_key, text_value, source))
        else:
            if not key or state == "live" and value is None:
                return None
            out.append(StorageRecord("chromium", store, sequence, state, origin,
                                     key, value, source))
    return tuple(out)


_HEADER_NAME = re.compile(rb"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _valid_chunk_extensions(line: bytes) -> bytes | None:
    parts = line.split(b";")
    size = parts[0]
    if not size or not re.fullmatch(rb"[0-9A-Fa-f]+", size):
        return None
    for extension in parts[1:]:
        if not extension:
            return None
        if b"=" in extension:
            name, value = extension.split(b"=", 1)
        else:
            name, value = extension, None
        if not _HEADER_NAME.fullmatch(name):
            return None
        if value is None:
            continue
        if _HEADER_NAME.fullmatch(value):
            continue
        if len(value) < 2 or value[:1] != b'"' or value[-1:] != b'"':
            return None
        escaped = False
        for byte in value[1:-1]:
            if escaped:
                if not 0x20 <= byte <= 0x7E:
                    return None
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x22 or byte < 0x20 or byte == 0x7F:
                return None
        if escaped:
            return None
    return size


def _chunked(data: bytes) -> bytes | None:
    out = bytearray()
    offset = 0
    while True:
        end = data.find(b"\r\n", offset)
        if end < 0 or end - offset > 128:
            return None
        token = _valid_chunk_extensions(data[offset:end])
        if token is None:
            return None
        size = int(token, 16)
        offset = end + 2
        if size > MAX_VALUE or len(out) + size > MAX_VALUE or offset + size + 2 > len(data):
            return None
        out += data[offset:offset + size]
        offset += size
        if data[offset:offset + 2] != b"\r\n":
            return None
        offset += 2
        if size == 0:
            # Empty trailer block only; richer trailers are intentionally not interpreted here.
            return bytes(out) if offset == len(data) else None


def decode_http_cache_object(data: object, *, browser: str,
                             url: str | None = None) -> CacheObject | None:
    """Decode one complete cached HTTP response exported from a browser cache entry."""
    raw = _blob(data, MAX_VALUE + (1 << 20))
    if raw is None or not isinstance(browser, str) or browser not in {"chromium", "firefox", "safari"}:
        return None
    split = raw.find(b"\r\n\r\n")
    if split < 0 or split > 64 << 10:
        return None
    lines = raw[:split].split(b"\r\n")
    match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [\x20-\x7e]*)?", lines[0])
    if match is None or len(lines) - 1 > MAX_HEADERS:
        return None
    headers: list[tuple[str, str]] = []
    grouped: dict[str, list[str]] = {}
    for line in lines[1:]:
        if b":" not in line:
            return None
        name, value = line.split(b":", 1)
        if not _HEADER_NAME.fullmatch(name):
            return None
        if any(byte < 0x20 and byte != 0x09 or byte == 0x7F for byte in value):
            return None
        try:
            text = value.strip().decode("latin-1")
        except UnicodeDecodeError:
            return None
        lname = name.decode("ascii").lower()
        if len(text) > MAX_TEXT:
            return None
        headers.append((lname, text))
        grouped.setdefault(lname, []).append(text)
    payload = raw[split + 4:]
    if grouped.get("transfer-encoding"):
        if [v.lower() for v in grouped["transfer-encoding"]] != ["chunked"] or "content-length" in grouped:
            return None
        body = _chunked(payload)
        if body is None:
            return None
    else:
        lengths = grouped.get("content-length")
        # ``str.isdigit`` accepts non-ASCII digit characters (e.g. superscripts) and the int()
        # conversion also rejects very long digit runs, so validate as ASCII digits of a bounded
        # length and convert defensively rather than leak a ValueError.
        if (not lengths or len(set(lengths)) != 1
                or not re.fullmatch(r"[0-9]{1,18}", lengths[0])):
            return None
        try:
            length = int(lengths[0])
        except ValueError:
            return None
        if length > MAX_VALUE or len(payload) != length:
            return None
        body = payload
    candidate = url
    if candidate is None and len(grouped.get("content-location", ())) == 1:
        candidate = grouped["content-location"][0]
    if _bounded_text(candidate, 16_384) is None:
        return None
    try:
        parsed = urlsplit(candidate)
    except (TypeError, ValueError, UnicodeError):
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return CacheObject(browser, candidate, int(match.group(1)), tuple(headers), body,
                       hashlib.sha256(body).hexdigest())


def _absolute_url(value: object) -> str | None:
    text = _bounded_text(value, 16_384)
    if text is None or any(ord(char) <= 0x20 or ord(char) == 0x7F for char in text):
        return None
    try:
        parsed = urlsplit(text)
    except (TypeError, ValueError, UnicodeError):
        return None
    if not parsed.scheme or not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed.scheme):
        return None
    if parsed.scheme.lower() in {"http", "https", "ftp", "ws", "wss"} and not parsed.netloc:
        return None
    return text


def _plist_entries(root: Mapping[str, object]) -> tuple[SessionEntry, ...] | None:
    window_keys = [key for key in ("SessionWindows", "Windows", "WindowStates", "SafariStateWindows")
                   if key in root]
    if len(window_keys) != 1 or not isinstance(root.get(window_keys[0]), list):
        return None
    windows = root[window_keys[0]]
    out: list[SessionEntry] = []
    for wi, window in enumerate(windows):
        if not isinstance(window, Mapping):
            return None
        tab_keys = [key for key in ("TabStates", "Tabs", "SessionTabs", "Children") if key in window]
        if len(tab_keys) != 1 or not isinstance(window.get(tab_keys[0]), list):
            return None
        tabs = window[tab_keys[0]]
        selected_index = None
        selected = window.get("SelectedTabIndex")
        if isinstance(selected, int) and not isinstance(selected, bool) and selected >= 0:
            selected_index = selected
        elif "SelectedTabIndex" not in window:
            selected = window.get("SelectedTab")
            if isinstance(selected, int) and not isinstance(selected, bool) and selected >= 1:
                selected_index = selected - 1
        for ti, tab in enumerate(tabs):
            if not isinstance(tab, Mapping):
                return None
            url_keys = [key for key in ("TabURL", "URL", "CurrentURL") if key in tab]
            if len(url_keys) != 1:
                return None
            url = _absolute_url(tab.get(url_keys[0]))
            if url is None or len(out) >= MAX_SESSION_ENTRIES:
                return None
            title_keys = [key for key in ("TabTitle", "Title") if key in tab]
            if len(title_keys) > 1:
                return None
            title = tab.get(title_keys[0]) if title_keys else None
            if title is not None and _bounded_text(title) is None:
                return None
            out.append(SessionEntry("safari", url, title, ti == selected_index, False,
                                    len(out), True))
    return tuple(out) if out else None


def decode_session_restore(data: object, *, browser: str | None = None) -> SessionReport | None:
    """Decode Firefox mozLz4, framed Chromium SNSS, or Safari session plists."""
    raw = _blob(data)
    if raw is None or (browser is not None and not isinstance(browser, str)) or browser not in {
        None, "firefox", "chromium", "safari"
    }:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    if raw.startswith(_sessions.MOZLZ4_MAGIC) and browser in (None, "firefox"):
        try:
            doc = _sessions.read_firefox_session(raw)
        except Exception:
            return None
        windows = doc.get("windows")
        if not isinstance(windows, list) or not windows:
            return None
        to_check = list(windows)
        closed_windows = doc.get("_closedWindows", [])
        if not isinstance(closed_windows, list):
            return None
        to_check.extend(closed_windows)
        for window in to_check:
            if not isinstance(window, Mapping) or not isinstance(window.get("tabs"), list):
                return None
            tabs = list(window.get("tabs", []))
            closed_tabs = window.get("_closedTabs", [])
            if not isinstance(closed_tabs, list):
                return None
            for closed in closed_tabs:
                if not isinstance(closed, Mapping):
                    return None
                tabs.append(closed.get("state", closed))
            for tab in tabs:
                if not isinstance(tab, Mapping) or not isinstance(tab.get("entries"), list):
                    return None
                for entry in tab.get("entries", []):
                    if not isinstance(entry, Mapping) or _absolute_url(entry.get("url")) is None:
                        return None
        try:
            rows = _sessions.firefox_entries(doc, include_closed=True)
        except Exception:
            return None
        if not rows or len(rows) > MAX_SESSION_ENTRIES:
            return None
        entries: list[SessionEntry] = []
        for index, row in enumerate(rows):
            url = _absolute_url(row.get("url"))
            title = row.get("title")
            if url is None or title is not None and _bounded_text(title) is None:
                return None
            entries.append(SessionEntry("firefox", url, title, bool(row.get("is_current") and row.get("is_selected_tab")),
                                        bool(row.get("closed_tab") or row.get("closed_window")), index, True))
        return SessionReport("firefox", "mozlz4", tuple(entries),
                             (("entries", str(len(entries))),), digest)
    if raw.startswith(_sessions.SNSS_MAGIC) and browser in (None, "chromium"):
        try:
            framed = _sessions.read_snss(raw)
            candidates = _sessions.snss_candidate_strings(framed, url_only=True)
        except Exception:
            return None
        version = framed.get("version")
        if (not framed.get("complete") or framed.get("trailing")
                or not isinstance(version, int) or isinstance(version, bool) or not 1 <= version <= 10
                or not candidates or len(candidates) > MAX_SESSION_ENTRIES):
            return None
        entries = []
        for row in candidates:
            url = _absolute_url(row.get("text"))
            if url is None:
                return None
            entries.append(SessionEntry("chromium", url, None, False, False,
                                        int(row.get("command_index", 0)), False))
        return SessionReport("chromium", "snss", tuple(entries),
                             (("commands", str(framed.get("commands"))),
                              ("version", str(framed.get("version"))),
                              ("url_semantics", "candidate-only")), digest)
    if browser in (None, "safari") and raw.startswith((b"bplist00", b"<?xml", b"<plist")):
        try:
            root = plistlib.loads(raw)
        except Exception:
            return None
        if not isinstance(root, Mapping):
            return None
        entries = _plist_entries(root)
        if entries is None:
            return None
        return SessionReport("safari", "plist", entries,
                             (("entries", str(len(entries))),), digest)
    return None


__all__ = [
    "BrowserRecord", "BrowserDatabaseReport", "StorageRecord", "CacheObject",
    "SessionEntry", "SessionReport", "validate_sqlite_bundle", "decode_browser_database",
    "decode_leveldb_storage", "decode_http_cache_object", "decode_session_restore",
]
