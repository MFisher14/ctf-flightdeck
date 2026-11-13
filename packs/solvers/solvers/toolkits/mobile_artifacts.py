#!/usr/bin/env python3
"""Offline mobile backup and app-data forensics.

The engine consumes caller-supplied byte mappings or a supplied ZIP bundle.  It never
opens a device, application, database connection, network service, or child process.
SQLite databases and WAL files are decoded directly from bytes, so even hostile inputs
remain data rather than executable SQL.

Coverage:

* iOS ``Manifest.plist``, ``Info.plist``, ``Status.plist`` and ``Manifest.db``;
* NSKeyedArchiver metadata stored in iOS backup file records;
* keychain/plist artifact metadata without exposing opaque secret blobs;
* Android shared-preference XML and SQLite app data;
* WhatsApp and Signal schema recognition plus normalized message/timeline leads;
* committed and uncommitted SQLite-WAL page recovery with row-level provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import lzma
import plistlib
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zipfile
import zlib
from pathlib import Path
from typing import Any, Mapping
from xml.parsers.expat import ExpatError


MAX_INPUT = 256 << 20
MAX_BUNDLE_FILES = 32_768
MAX_MEMBER = 128 << 20
MAX_TOTAL = 512 << 20
MAX_SQLITE_PAGES = 262_144
MAX_SQLITE_ROWS = 1_000_000
MAX_COLUMNS = 4096
MAX_VALUE = 16 << 20
MAX_PLIST_DEPTH = 64
MAX_PLIST_ITEMS = 100_000

SQLITE_MAGIC = b"SQLite format 3\x00"
WAL_MAGICS = {0x377F0682, 0x377F0683}


class ArtifactError(ValueError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _varint(data: bytes, offset: int, end: int) -> tuple[int, int]:
    value = 0
    for index in range(9):
        if offset >= end:
            raise ArtifactError("truncated SQLite varint")
        byte = data[offset]
        offset += 1
        if index == 8:
            return (value << 8) | byte, offset
        value = (value << 7) | (byte & 0x7F)
        if byte < 0x80:
            return value, offset
    raise ArtifactError("invalid SQLite varint")


def _signed(raw: bytes) -> int:
    return int.from_bytes(raw, "big", signed=True)


def _serial(data: bytes, offset: int, serial: int, encoding: str) -> tuple[Any, int]:
    fixed = {0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 6, 6: 8, 7: 8, 8: 0, 9: 0}
    if serial in (10, 11):
        raise ArtifactError("reserved SQLite serial type")
    if serial in fixed:
        size = fixed[serial]
    elif serial >= 12:
        size = (serial - (12 if serial % 2 == 0 else 13)) // 2
    else:
        raise ArtifactError("invalid SQLite serial type")
    if size < 0 or size > MAX_VALUE or offset + size > len(data):
        raise ArtifactError("SQLite record value exceeds payload or cap")
    raw = data[offset:offset + size]
    if serial == 0:
        value = None
    elif 1 <= serial <= 6:
        value = _signed(raw)
    elif serial == 7:
        value = struct.unpack(">d", raw)[0]
    elif serial == 8:
        value = 0
    elif serial == 9:
        value = 1
    elif serial % 2 == 0:
        value = raw
    else:
        value = raw.decode(encoding, "replace")
    return value, offset + size


def _record(payload: bytes, encoding: str) -> list[Any]:
    if not payload:
        return []
    header_size, cursor = _varint(payload, 0, len(payload))
    if header_size < cursor or header_size > len(payload):
        raise ArtifactError("SQLite record header exceeds payload")
    serials = []
    while cursor < header_size:
        serial, cursor = _varint(payload, cursor, header_size)
        serials.append(serial)
        if len(serials) > MAX_COLUMNS:
            raise ArtifactError("SQLite column count exceeds cap")
    values, value_at = [], header_size
    for serial in serials:
        value, value_at = _serial(payload, value_at, serial, encoding)
        values.append(value)
    return values


def _sql_columns(sql: str | None) -> list[str]:
    if not isinstance(sql, str):
        return []
    opening = sql.find("(")
    if opening < 0:
        return []
    parts, current, depth, quote = [], [], 0, None
    for char in sql[opening + 1:]:
        if quote:
            current.append(char)
            if (quote == "]" and char == "]") or (quote != "]" and char == quote):
                quote = None
            continue
        if char in "'\"`":
            quote = char; current.append(char)
        elif char == "[":
            quote = "]"; current.append(char)
        elif char == "(":
            depth += 1; current.append(char)
        elif char == ")" and depth:
            depth -= 1; current.append(char)
        elif char == ")":
            if current:
                parts.append("".join(current).strip())
            break
        elif char == "," and depth == 0:
            parts.append("".join(current).strip()); current = []
        else:
            current.append(char)
    columns = []
    for part in parts:
        if not part or re.match(r"(?i)^(?:constraint|primary|unique|check|foreign)\b", part):
            continue
        match = re.match(r'^\s*(?:"([^"]+)"|`([^`]+)`|\[([^]]+)\]|([^\s]+))', part)
        if match:
            columns.append(next(value for value in match.groups() if value is not None))
    return columns[:MAX_COLUMNS]


def _integer_primary_key(sql: str | None) -> str | None:
    """Find a rowid alias without executing schema SQL.

    Only the exact INTEGER type aliases rowid. Inline PRIMARY KEY DESC is the
    SQLite exception; a one-column table PRIMARY KEY(... DESC) still aliases.
    Tokenize quotes/comments so literals and nested expressions cannot supply
    a false PRIMARY KEY declaration.
    """
    if not isinstance(sql, str):
        return None
    tokens = re.findall(r'--[^\n]*|/\*[\s\S]*?\*/|"(?:""|[^"])*"|'
                        r"'(?:''|[^'])*'|`(?:``|[^`])*`|\[[^\]]*\]|"
                        r'[A-Za-z_][\w$]*|[^\s]', sql)
    tokens = [t for t in tokens if not t.startswith(('--', '/*'))]
    if '(' not in tokens:
        return None
    parts, part, depth = [], [], 0
    for token in tokens[tokens.index('(') + 1:]:
        if token == ')' and depth == 0:
            parts.append(part)
            break
        if token == ',' and depth == 0:
            parts.append(part)
            part = []
            continue
        part.append(token)
        depth += (token == '(') - (token == ')')
    else:
        return None

    def identifier(token):
        if token[:1] in ('"', "'", '`', '['):
            quote = ']' if token[0] == '[' else token[0]
            return token[1:-1].replace(quote * 2, quote)
        return token

    # SQLite keyword, type and identifier comparison folds ASCII only.
    uppercase = str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    integers, primary = set(), None
    constraints = {'CONSTRAINT', 'PRIMARY', 'NOT', 'UNIQUE', 'CHECK', 'DEFAULT',
                   'COLLATE', 'REFERENCES', 'GENERATED', 'AS'}
    for part in parts:
        if not part:
            continue
        upper = [token.translate(uppercase) for token in part]
        head = 2 if upper[0] == 'CONSTRAINT' else 0
        if upper[head:head + 3] == ['PRIMARY', 'KEY', '(']:
            tail = part[head + 3:]
            key = tail[:tail.index(')')] if ')' in tail else []
            if key and ',' not in key:
                primary = identifier(key[0])
            continue
        if len(part) < 2 or identifier(part[1]).translate(uppercase) != 'INTEGER':
            continue
        if len(part) > 2 and upper[2] not in constraints:
            continue  # INTEGER(8), INTEGER UNSIGNED, etc. are not aliases.
        name = identifier(part[0])
        integers.add(name)
        level = 0
        for i in range(2, len(part)):
            if level == 0 and upper[i:i + 2] == ['PRIMARY', 'KEY']:
                if upper[i + 2:i + 3] != ['DESC']:
                    primary = name
                break
            level += (part[i] == '(') - (part[i] == ')')
    return next((name for name in integers if primary is not None
                 and name.translate(uppercase) == primary.translate(uppercase)), None)


class SQLiteImage:
    """A bounded read-only SQLite b-tree view backed by supplied bytes."""

    def __init__(self, data: bytes):
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("SQLite input must be bytes")
        self.data = bytes(data)
        if len(self.data) < 100 or len(self.data) > MAX_INPUT or not self.data.startswith(SQLITE_MAGIC):
            raise ArtifactError("not a bounded SQLite 3 database")
        page_size = int.from_bytes(self.data[16:18], "big")
        self.page_size = 65536 if page_size == 1 else page_size
        if self.page_size < 512 or self.page_size > 65536 or self.page_size & (self.page_size - 1):
            raise ArtifactError("invalid SQLite page size")
        self.reserved = self.data[20]
        self.usable = self.page_size - self.reserved
        if self.usable < 480:
            raise ArtifactError("invalid SQLite reserved-byte count")
        self.pages = (len(self.data) + self.page_size - 1) // self.page_size
        if self.pages > MAX_SQLITE_PAGES:
            raise ArtifactError("SQLite page count exceeds cap")
        encoding_id = int.from_bytes(self.data[56:60], "big")
        self.encoding = {1: "utf-8", 2: "utf-16le", 3: "utf-16be"}.get(encoding_id, "utf-8")
        self.notes: list[str] = []

    def page(self, number: int) -> bytes:
        if number < 1 or number > self.pages:
            raise ArtifactError(f"SQLite page {number} is outside the artifact")
        offset = (number - 1) * self.page_size
        page = self.data[offset:offset + self.page_size]
        if len(page) != self.page_size:
            raise ArtifactError(f"SQLite page {number} is truncated")
        return page

    def _payload(self, page: bytes, cursor: int, size: int) -> bytes:
        if size > MAX_VALUE:
            raise ArtifactError("SQLite cell payload exceeds cap")
        maximum = self.usable - 35
        minimum = ((self.usable - 12) * 32 // 255) - 23
        local = size
        if size > maximum:
            candidate = minimum + ((size - minimum) % (self.usable - 4))
            local = candidate if candidate <= maximum else minimum
        if cursor + local > len(page):
            raise ArtifactError("SQLite local payload is truncated")
        output = bytearray(page[cursor:cursor + local])
        cursor += local
        if local < size:
            if cursor + 4 > len(page):
                raise ArtifactError("SQLite overflow pointer is truncated")
            next_page = int.from_bytes(page[cursor:cursor + 4], "big")
            seen = set()
            while len(output) < size:
                if next_page in seen or len(seen) >= MAX_SQLITE_PAGES:
                    raise ArtifactError("SQLite overflow chain loops or exceeds cap")
                seen.add(next_page)
                overflow = self.page(next_page)
                next_page = int.from_bytes(overflow[:4], "big")
                take = min(size - len(output), self.usable - 4)
                output.extend(overflow[4:4 + take])
                if len(output) < size and next_page == 0:
                    raise ArtifactError("SQLite overflow chain ends early")
        return bytes(output)

    def table_rows(self, root_page: int) -> list[dict[str, Any]]:
        if not isinstance(root_page, int) or root_page < 1:
            return []
        stack, seen, rows = [root_page], set(), []
        while stack:
            page_number = stack.pop()
            if page_number in seen:
                raise ArtifactError("SQLite b-tree contains a page cycle")
            seen.add(page_number)
            if len(seen) > MAX_SQLITE_PAGES:
                raise ArtifactError("SQLite b-tree page cap exceeded")
            page = self.page(page_number)
            header = 100 if page_number == 1 else 0
            if header + 8 > len(page):
                raise ArtifactError("SQLite b-tree header is truncated")
            kind = page[header]
            count = int.from_bytes(page[header + 3:header + 5], "big")
            if count > self.page_size // 2:
                raise ArtifactError("SQLite cell count exceeds page capacity")
            pointer_at = header + (12 if kind == 5 else 8)
            if pointer_at + count * 2 > len(page):
                raise ArtifactError("SQLite cell-pointer array is truncated")
            pointers = [int.from_bytes(page[pointer_at + i * 2:pointer_at + i * 2 + 2], "big")
                        for i in range(count)]
            if kind == 5:  # table interior
                right = int.from_bytes(page[header + 8:header + 12], "big")
                children = []
                for pointer in pointers:
                    if pointer < pointer_at + count * 2 or pointer + 4 > len(page):
                        raise ArtifactError("SQLite interior cell offset is invalid")
                    children.append(int.from_bytes(page[pointer:pointer + 4], "big"))
                children.append(right)
                stack.extend(reversed(children))
            elif kind == 13:  # table leaf
                for pointer in pointers:
                    if pointer < pointer_at + count * 2 or pointer >= len(page):
                        raise ArtifactError("SQLite leaf cell offset is invalid")
                    size, cursor = _varint(page, pointer, len(page))
                    rowid, cursor = _varint(page, cursor, len(page))
                    if rowid >= 1 << 63:
                        rowid -= 1 << 64
                    payload = self._payload(page, cursor, size)
                    rows.append({"rowid": rowid, "values": _record(payload, self.encoding),
                                 "page": page_number, "cell_offset": pointer})
                    if len(rows) > MAX_SQLITE_ROWS:
                        raise ArtifactError("SQLite row count exceeds cap")
            else:
                raise ArtifactError(f"SQLite root references unsupported b-tree page type {kind:#x}")
        return rows

    def schema(self) -> list[dict[str, Any]]:
        result = []
        for row in self.table_rows(1):
            values = row["values"]
            if len(values) < 5:
                continue
            result.append({"type": values[0], "name": values[1], "table": values[2],
                           "root_page": values[3], "sql": values[4], "rowid": row["rowid"]})
        return result

    def report(self) -> dict[str, Any]:
        schema = self.schema()
        tables: dict[str, Any] = {}
        for entry in schema:
            if entry["type"] != "table" or not isinstance(entry["name"], str) or entry["name"].startswith("sqlite_"):
                continue
            columns = _sql_columns(entry.get("sql"))
            rowid_alias = _integer_primary_key(entry.get("sql"))
            raw_rows = self.table_rows(entry["root_page"]) if isinstance(entry["root_page"], int) else []
            rows = []
            for raw in raw_rows:
                values = raw["values"]
                names = columns + [f"column_{index}" for index in range(len(columns), len(values))]
                row_values = {names[index]: value for index, value in enumerate(values)}
                if rowid_alias in row_values and row_values[rowid_alias] is None:
                    row_values[rowid_alias] = raw["rowid"]
                rows.append({"rowid": raw["rowid"], "page": raw["page"], "values": row_values})
            tables[entry["name"]] = {"root_page": entry["root_page"], "columns": columns,
                                      "sql": entry.get("sql"), "rows": rows}
        return {"page_size": self.page_size, "page_count": self.pages, "encoding": self.encoding,
                "schema": schema, "tables": tables, "notes": self.notes}


def parse_sqlite(data: bytes) -> dict[str, Any]:
    return SQLiteImage(data).report()


def parse_wal(wal: bytes, *, expected_page_size: int | None = None) -> dict[str, Any]:
    if not isinstance(wal, (bytes, bytearray)):
        raise TypeError("WAL input must be bytes")
    raw = bytes(wal)
    if len(raw) < 32 or len(raw) > MAX_INPUT:
        raise ArtifactError("SQLite WAL header is missing or oversized")
    magic, version, page_size, checkpoint, salt1, salt2, checksum1, checksum2 = struct.unpack_from(">8I", raw, 0)
    if magic not in WAL_MAGICS:
        raise ArtifactError("invalid SQLite WAL magic")
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        raise ArtifactError("invalid SQLite WAL page size")
    if expected_page_size is not None and page_size != expected_page_size:
        raise ArtifactError("SQLite database/WAL page sizes disagree")
    checksum_endian = "<" if magic == 0x377F0682 else ">"

    def checksum(blob: bytes, state: tuple[int, int] = (0, 0)) -> tuple[int, int]:
        if len(blob) % 8:
            raise ArtifactError("WAL checksum input is not 8-byte aligned")
        first, second = state
        for offset in range(0, len(blob), 8):
            left, right = struct.unpack_from(checksum_endian + "II", blob, offset)
            first = (first + left + second) & 0xFFFFFFFF
            second = (second + right + first) & 0xFFFFFFFF
        return first, second

    calculated_header = checksum(raw[:24])
    frame_state = (checksum1, checksum2)
    valid_prefix = calculated_header == (checksum1, checksum2)
    frame_size = 24 + page_size
    frames = []
    cursor = 32
    while cursor + frame_size <= len(raw):
        page_number, database_size, fsalt1, fsalt2, fcheck1, fcheck2 = struct.unpack_from(">6I", raw, cursor)
        if page_number < 1 or page_number > MAX_SQLITE_PAGES:
            raise ArtifactError("WAL frame page number exceeds cap")
        calculated = checksum(raw[cursor:cursor + 8] + raw[cursor + 24:cursor + frame_size], frame_state)
        salt_valid = (fsalt1, fsalt2) == (salt1, salt2)
        checksum_valid = calculated == (fcheck1, fcheck2)
        valid_prefix = valid_prefix and salt_valid and checksum_valid
        frames.append({"index": len(frames), "offset": cursor, "page_number": page_number,
                       "database_size": database_size, "salt_valid": salt_valid,
                       "checksum": [fcheck1, fcheck2], "checksum_valid": checksum_valid,
                       "chain_valid": valid_prefix,
                       "data": raw[cursor + 24:cursor + frame_size]})
        frame_state = (fcheck1, fcheck2)
        cursor += frame_size
        if len(frames) > MAX_SQLITE_PAGES:
            raise ArtifactError("WAL frame count exceeds cap")
    header_valid = calculated_header == (checksum1, checksum2)
    commits = [frame["index"] for frame in frames
               if header_valid and frame["database_size"] and frame["chain_valid"]]
    return {"magic": f"0x{magic:08x}", "version": version, "page_size": page_size,
            "checkpoint_sequence": checkpoint, "salt": [salt1, salt2],
            "header_checksum": [checksum1, checksum2], "header_checksum_valid": header_valid,
            "frames": frames,
            "last_commit_frame": commits[-1] if commits else None, "trailing_bytes": len(raw) - cursor}


def _overlay_wal(database: bytes, report: dict[str, Any], through: int | None) -> bytes:
    page_size = report["page_size"]
    if not report["header_checksum_valid"]:
        return database
    candidates = report["frames"] if through is None else report["frames"][:through + 1]
    frames = [frame for frame in candidates if frame["chain_valid"]]
    if not frames:
        return database
    committed_size = next((frame["database_size"] for frame in reversed(frames) if frame["database_size"]), 0)
    max_page = max([frame["page_number"] for frame in frames] + [committed_size])
    if max_page > MAX_SQLITE_PAGES or max_page * page_size > MAX_INPUT:
        raise ArtifactError("WAL overlay exceeds database cap")
    output = bytearray(database)
    if len(output) < max_page * page_size:
        output.extend(b"\x00" * (max_page * page_size - len(output)))
    for frame in frames:
        start = (frame["page_number"] - 1) * page_size
        output[start:start + page_size] = frame["data"]
    if committed_size and through is not None:
        output = output[:committed_size * page_size]
    return bytes(output)


def _stable(value: Any):
    if isinstance(value, bytes):
        return {"bytes": len(value), "sha256": _sha256(value), "hex": value.hex() if len(value) <= 64 else None}
    if isinstance(value, dict):
        return {str(key): _stable(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, list):
        return [_stable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _row_index(report: dict[str, Any]) -> dict[tuple[str, int], dict[str, Any]]:
    return {(table, row["rowid"]): row for table, body in report.get("tables", {}).items()
            for row in body.get("rows", [])}


def _same_row(left: dict[str, Any] | None, right: dict[str, Any] | None) -> bool:
    if left is None or right is None:
        return left is right
    return _stable(left.get("values")) == _stable(right.get("values"))


def analyze_sqlite(database: bytes, wal: bytes | None = None) -> dict[str, Any]:
    base = parse_sqlite(database)
    output: dict[str, Any] = {"base": base, "wal": None, "committed": base, "latest": base,
                              "recovered_rows": []}
    if wal is None:
        return output
    wal_report = parse_wal(wal, expected_page_size=base["page_size"])
    output["wal"] = {key: value for key, value in wal_report.items() if key != "frames"}
    output["wal"]["frames"] = [{key: value for key, value in frame.items() if key != "data"}
                                for frame in wal_report["frames"]]
    commit = wal_report["last_commit_frame"]
    if commit is not None:
        output["committed"] = parse_sqlite(_overlay_wal(database, wal_report, commit))
    if wal_report["frames"]:
        output["latest"] = parse_sqlite(_overlay_wal(database, wal_report, None))
    base_rows, committed_rows, latest_rows = map(_row_index, (base, output["committed"], output["latest"]))
    for key in sorted(set(base_rows) | set(committed_rows) | set(latest_rows), key=lambda item: (item[0], item[1])):
        before, committed_row, latest_row = base_rows.get(key), committed_rows.get(key), latest_rows.get(key)
        if not _same_row(committed_row, before):
            source, after = "committed", committed_row
        elif not _same_row(latest_row, committed_row):
            source, after = "uncommitted", latest_row
        else:
            continue
        change = "inserted" if before is None and after is not None else "deleted" if before is not None and after is None else "updated"
        output["recovered_rows"].append({"table": key[0], "rowid": key[1], "source": source,
                                         "change": change, "before": before, "after": after})
    return output


def parse_mbdb(data: bytes) -> dict[str, Any]:
    """Parse the legacy iTunes ``Manifest.mbdb`` record stream."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("MBDB input must be bytes")
    raw = bytes(data)
    if len(raw) < 6 or len(raw) > MAX_INPUT or raw[:4] != b"mbdb":
        raise ArtifactError("invalid Manifest.mbdb header")
    cursor, records = 6, []

    def string() -> bytes | None:
        nonlocal cursor
        if cursor + 2 > len(raw):
            raise ArtifactError("truncated MBDB string length")
        length = int.from_bytes(raw[cursor:cursor + 2], "big"); cursor += 2
        if length == 0xFFFF:
            return None
        if length > MAX_VALUE or cursor + length > len(raw):
            raise ArtifactError("truncated or oversized MBDB string")
        value = raw[cursor:cursor + length]; cursor += length
        return value

    while cursor < len(raw):
        domain_raw, relative_raw, target, digest, unknown = string(), string(), string(), string(), string()
        fixed = 2 + 4 * 7 + 8 + 2
        if cursor + fixed > len(raw):
            raise ArtifactError("truncated MBDB fixed record")
        mode = int.from_bytes(raw[cursor:cursor + 2], "big"); cursor += 2
        inode = int.from_bytes(raw[cursor:cursor + 4], "big"); cursor += 4
        unknown_id = int.from_bytes(raw[cursor:cursor + 4], "big"); cursor += 4
        user_id = int.from_bytes(raw[cursor:cursor + 4], "big"); cursor += 4
        group_id = int.from_bytes(raw[cursor:cursor + 4], "big"); cursor += 4
        mtime = int.from_bytes(raw[cursor:cursor + 4], "big"); cursor += 4
        atime = int.from_bytes(raw[cursor:cursor + 4], "big"); cursor += 4
        ctime = int.from_bytes(raw[cursor:cursor + 4], "big"); cursor += 4
        length = int.from_bytes(raw[cursor:cursor + 8], "big"); cursor += 8
        flag, property_count = raw[cursor], raw[cursor + 1]; cursor += 2
        properties = {}
        for _ in range(property_count):
            key, value = string(), string()
            properties[(key or b"").decode("utf-8", "replace")] = _stable(value or b"")
        domain = (domain_raw or b"").decode("utf-8", "replace")
        relative = (relative_raw or b"").decode("utf-8", "replace")
        file_id = hashlib.sha1((domain + "-" + relative).encode()).hexdigest()
        records.append({"file_id": file_id, "domain": domain, "relative_path": relative,
                        "link_target": (target or b"").decode("utf-8", "replace"),
                        "data_hash": (digest or b"").hex(), "unknown_blob": _stable(unknown or b""),
                        "mode": mode, "inode": inode, "unknown_id": unknown_id,
                        "user_id": user_id, "group_id": group_id, "mtime": mtime,
                        "atime": atime, "ctime": ctime, "size": length, "flag": flag,
                        "properties": properties})
        if len(records) > MAX_SQLITE_ROWS:
            raise ArtifactError("MBDB record count exceeds cap")
    return {"version": list(raw[4:6]), "record_count": len(records), "records": records}


def _plist_value(value: Any, *, depth: int = 0, budget: list[int] | None = None):
    if budget is None:
        budget = [MAX_PLIST_ITEMS]
    if depth > MAX_PLIST_DEPTH or budget[0] <= 0:
        return {"truncated": True}
    budget[0] -= 1
    if isinstance(value, bytes):
        return {"type": "data", "length": len(value), "sha256": _sha256(value),
                "hex": value.hex() if len(value) <= 32 else None}
    if isinstance(value, plistlib.UID):
        return {"type": "uid", "value": value.data}
    if isinstance(value, dict):
        return {str(key): _plist_value(item, depth=depth + 1, budget=budget)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple)):
        return [_plist_value(item, depth=depth + 1, budget=budget) for item in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def parse_plist_metadata(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_MEMBER:
        raise ArtifactError("plist exceeds member cap")
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError,
            ExpatError, LookupError, RecursionError) as exc:
        raise ArtifactError("invalid plist") from exc
    return {"format": "binary" if data.startswith(b"bplist00") else "xml", "root_type": type(value).__name__,
            "value": _plist_value(value)}


def decode_keyed_archive(data: bytes) -> dict[str, Any] | None:
    try:
        archive = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError,
            ExpatError, LookupError, RecursionError):
        return None
    if not isinstance(archive, dict) or not isinstance(archive.get("$objects"), list):
        return None
    objects = archive["$objects"]

    def resolve(value: Any, depth: int, seen: frozenset[int]):
        if depth > MAX_PLIST_DEPTH:
            return {"truncated": True}
        if isinstance(value, plistlib.UID):
            index = value.data
            if index >= len(objects) or index in seen:
                return {"uid": index, "invalid_or_cycle": True}
            return resolve(objects[index], depth + 1, seen | {index})
        if isinstance(value, dict):
            if isinstance(value.get("NS.keys"), list) and isinstance(value.get("NS.objects"), list):
                keys = [resolve(item, depth + 1, seen) for item in value["NS.keys"]]
                vals = [resolve(item, depth + 1, seen) for item in value["NS.objects"]]
                return {str(key): val for key, val in zip(keys, vals)}
            return {str(key): resolve(item, depth + 1, seen) for key, item in value.items() if key != "$class"}
        if isinstance(value, list):
            return [resolve(item, depth + 1, seen) for item in value]
        return _plist_value(value)

    top = archive.get("$top", {})
    if not isinstance(top, dict):
        return None
    return {"archiver": archive.get("$archiver"), "version": archive.get("$version"),
            "root": resolve(top.get("root", top), 0, frozenset())}


def _keychain_metadata(value: Any) -> dict[str, Any]:
    items = []

    def collect(current: Any, depth: int = 0):
        if depth > MAX_PLIST_DEPTH or len(items) >= MAX_PLIST_ITEMS:
            return
        if isinstance(current, list):
            for child in current:
                collect(child, depth + 1)
        elif isinstance(current, dict):
            if set(current) & {"class", "agrp", "acct", "svce", "labl", "pdmn", "data", "v_Data"}:
                items.append(current)
            else:
                for child in current.values():
                    collect(child, depth + 1)

    collect(value)
    output = []
    for index, item in enumerate(items[:MAX_PLIST_ITEMS]):
        if not isinstance(item, dict):
            continue
        row = {"index": index}
        for key in ("class", "agrp", "acct", "svce", "labl", "pdmn", "cdat", "mdat", "sync", "tomb"):
            if key in item:
                row[key] = _plist_value(item[key])
        for key in ("data", "v_Data", "gena"):
            if isinstance(item.get(key), bytes):
                row[key] = {"length": len(item[key]), "sha256": _sha256(item[key])}
        output.append(row)
    return {"item_count": len(output), "items": output}


def _bundle_files(data: bytes) -> dict[str, bytes]:
    if len(data) > MAX_INPUT:
        raise ArtifactError("bundle exceeds input cap")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_BUNDLE_FILES:
                raise ArtifactError("bundle member count exceeds cap")
            files, total = {}, 0
            for info in infos:
                if info.is_dir():
                    continue
                if info.file_size < 0 or info.file_size > MAX_MEMBER:
                    raise ArtifactError("bundle member exceeds cap")
                total += info.file_size
                if total > MAX_TOTAL:
                    raise ArtifactError("bundle expanded size exceeds cap")
                name = info.filename.replace("\\", "/").lstrip("/")
                if not name or ".." in name.split("/") or name in files:
                    raise ArtifactError("bundle contains an unsafe or duplicate path")
                with archive.open(info) as handle:
                    body = handle.read(info.file_size + 1)
                if len(body) != info.file_size:
                    raise ArtifactError("bundle member is truncated")
                files[name] = body
        return files
    except (zipfile.BadZipFile, OSError, EOFError, NotImplementedError,
            RuntimeError, UnicodeError, struct.error, zlib.error, lzma.LZMAError) as exc:
        raise ArtifactError("bundle is not a readable ZIP") from exc


def _find_file(files: Mapping[str, bytes], name: str) -> bytes | None:
    exact = files.get(name)
    if exact is not None:
        return exact
    matches = [body for path, body in files.items() if path.rsplit("/", 1)[-1] == name]
    return matches[0] if len(matches) == 1 else None


def _physical_body(files: Mapping[str, bytes], file_id: str) -> bytes | None:
    for key in (file_id, f"{file_id[:2]}/{file_id}"):
        if key in files:
            return files[key]
    matches = [body for path, body in files.items() if path.endswith("/" + file_id)]
    return matches[0] if len(matches) == 1 else None


def analyze_ios_backup(files: Mapping[str, bytes]) -> dict[str, Any]:
    if len(files) > MAX_BUNDLE_FILES:
        raise ArtifactError("backup file count exceeds cap")
    output: dict[str, Any] = {"platform": "ios-backup", "plists": {}, "manifest": None,
                              "files": [], "keychain": [], "plist_artifacts": [], "notes": []}
    for name in ("Info.plist", "Status.plist", "Manifest.plist"):
        body = _find_file(files, name)
        if body is not None:
            try:
                output["plists"][name] = parse_plist_metadata(body)
            except ArtifactError as exc:
                output["notes"].append(f"{name}: {exc}")
    database = _find_file(files, "Manifest.db")
    if database is None:
        legacy = _find_file(files, "Manifest.mbdb")
        if legacy is None:
            output["notes"].append("Manifest.db/Manifest.mbdb not supplied")
            return output
        parsed = parse_mbdb(legacy)
        output["manifest"] = {"format": "mbdb", **parsed}
        for record in parsed["records"]:
            body = _physical_body(files, record["file_id"])
            item = {**record, "metadata": {key: record[key] for key in (
                "mode", "user_id", "group_id", "mtime", "atime", "ctime", "size", "data_hash")},
                    "body_present": body is not None}
            relative, domain = record["relative_path"], record["domain"]
            if body is not None and relative.lower().endswith(".plist"):
                try:
                    parsed_plist = plistlib.loads(body)
                    summary = {"domain": domain, "relative_path": relative,
                               "file_id": record["file_id"], "metadata": parse_plist_metadata(body)}
                    output["plist_artifacts"].append(summary)
                    if "keychain" in domain.lower() or "keychain" in relative.lower():
                        output["keychain"].append({**summary, **_keychain_metadata(parsed_plist)})
                except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError,
                        ExpatError, LookupError, RecursionError):
                    output["notes"].append(f"plist artifact is malformed: {domain}/{relative}")
            output["files"].append(item)
        output["files"].sort(key=lambda item: (item["domain"], item["relative_path"]))
        return output
    wal = _find_file(files, "Manifest.db-wal")
    output["manifest"] = analyze_sqlite(database, wal)
    report = output["manifest"]["latest"]
    files_table = next((body for name, body in report["tables"].items() if name.lower() == "files"), None)
    if files_table is None:
        output["notes"].append("Manifest.db has no Files table")
        return output
    for row in files_table["rows"]:
        values = row["values"]
        file_id = values.get("fileID") or values.get("fileid")
        domain = values.get("domain")
        relative = values.get("relativePath") or values.get("relativepath")
        blob = values.get("file")
        item = {"rowid": row["rowid"], "file_id": file_id, "domain": domain,
                "relative_path": relative, "flags": values.get("flags"), "metadata": None,
                "body_present": False}
        if isinstance(blob, bytes):
            item["metadata"] = decode_keyed_archive(blob) or {"blob": _stable(blob)}
        body = _physical_body(files, file_id) if isinstance(file_id, str) else None
        item["body_present"] = body is not None
        if body is not None and isinstance(relative, str) and relative.lower().endswith(".plist"):
            try:
                parsed = plistlib.loads(body)
                summary = {"domain": domain, "relative_path": relative, "file_id": file_id,
                           "metadata": parse_plist_metadata(body)}
                output["plist_artifacts"].append(summary)
                if ((isinstance(domain, str) and "keychain" in domain.lower())
                        or "keychain" in relative.lower()):
                    output["keychain"].append({**summary, **_keychain_metadata(parsed)})
            except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError,
                    ExpatError, LookupError, RecursionError):
                output["notes"].append(f"plist artifact is malformed: {domain}/{relative}")
        output["files"].append(item)
    output["files"].sort(key=lambda item: (str(item.get("domain")), str(item.get("relative_path"))))
    return output


_WHATSAPP_TABLES = {"messages", "message", "chat", "jid", "message_media", "message_quoted",
                    "message_location", "wa_contacts", "group_participants", "receipt_user"}
_SIGNAL_TABLES = {"sms", "mms", "thread", "recipient", "attachment", "reaction", "mention",
                  "story_sends", "distribution_list", "groups", "identities", "sessions"}


def classify_messaging_schema(report: dict[str, Any]) -> dict[str, Any]:
    names = {name.lower() for name in report.get("tables", {})}
    whatsapp = sorted(names & _WHATSAPP_TABLES)
    signal = sorted(names & _SIGNAL_TABLES)
    family = "whatsapp" if len(whatsapp) > len(signal) and whatsapp else "signal" if signal else "unknown"
    return {"family": family, "whatsapp_tables": whatsapp, "signal_tables": signal,
            "confidence": "high" if max(len(whatsapp), len(signal)) >= 3 else "medium" if family != "unknown" else "none"}


def _message_leads(report: dict[str, Any], family: str, source: str) -> list[dict[str, Any]]:
    leads = []
    candidates = ("messages", "message") if family == "whatsapp" else ("sms", "mms") if family == "signal" else ()
    for table_name, body in report.get("tables", {}).items():
        if table_name.lower() not in candidates:
            continue
        for row in body["rows"]:
            values = row["values"]
            lowered = {key.lower(): value for key, value in values.items()}
            timestamp = next((lowered.get(key) for key in (
                "timestamp", "date_sent", "date_received", "received_timestamp", "send_timestamp")
                if lowered.get(key) is not None), None)
            text = next((lowered.get(key) for key in ("text_data", "data", "body", "message", "caption")
                         if isinstance(lowered.get(key), str)), None)
            peer = next((lowered.get(key) for key in (
                "key_remote_jid", "address", "recipient_id", "chat_row_id", "thread_id")
                if lowered.get(key) is not None), None)
            leads.append({"source": source, "table": table_name, "rowid": row["rowid"],
                          "timestamp": timestamp, "peer": peer, "text": text,
                          "message_id": next((lowered.get(key) for key in ("key_id", "server_guid", "unique_id")
                                              if lowered.get(key) is not None), None)})
            if len(leads) >= MAX_SQLITE_ROWS:
                return leads
    return leads


def parse_shared_preferences(data: bytes) -> dict[str, Any]:
    if len(data) > MAX_MEMBER:
        raise ArtifactError("shared-preference XML exceeds cap")
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, LookupError, UnicodeError) as exc:
        raise ArtifactError("invalid shared-preference XML") from exc
    if root.tag != "map":
        raise ArtifactError("shared-preference root is not <map>")
    values = {}
    for node in list(root)[:MAX_PLIST_ITEMS]:
        name = node.attrib.get("name")
        if not name or name in values:
            continue
        if node.tag == "string":
            value: Any = node.text or ""
        elif node.tag in {"int", "long"}:
            try:
                value = int(node.attrib.get("value", ""))
            except ValueError:
                value = node.attrib.get("value")
        elif node.tag == "float":
            try:
                value = float(node.attrib.get("value", ""))
            except ValueError:
                value = node.attrib.get("value")
        elif node.tag == "boolean":
            value = node.attrib.get("value", "").lower() == "true"
        elif node.tag == "set":
            value = [child.text or "" for child in node if child.tag == "string"]
        else:
            value = {"type": node.tag, "attributes": dict(sorted(node.attrib.items()))}
        values[name] = value
    return {"entry_count": len(values), "values": values}


def analyze_android_appdata(files: Mapping[str, bytes]) -> dict[str, Any]:
    if len(files) > MAX_BUNDLE_FILES:
        raise ArtifactError("app-data file count exceeds cap")
    output = {"platform": "android-appdata", "databases": [], "encrypted_database_candidates": [], "preferences": [],
              "message_leads": [], "other_files": [], "notes": []}
    handled = set()
    for path in sorted(files):
        body = files[path]
        if body.startswith(SQLITE_MAGIC):
            wal = files.get(path + "-wal") or files.get(path.rsplit("/", 1)[0] + "/" + path.rsplit("/", 1)[-1] + "-wal")
            try:
                analysis = analyze_sqlite(body, wal)
                schema = classify_messaging_schema(analysis["latest"])
                output["databases"].append({"path": path, "schema": schema, "analysis": analysis})
                output["message_leads"].extend(_message_leads(analysis["latest"], schema["family"], path))
                handled.add(path)
                if wal is not None:
                    handled.add(path + "-wal")
            except ArtifactError as exc:
                output["notes"].append(f"{path}: {exc}")
        elif path.lower().endswith(".xml") and ("shared_prefs" in path or "shared-preferences" in path):
            try:
                output["preferences"].append({"path": path, "report": parse_shared_preferences(body)})
                handled.add(path)
            except ArtifactError as exc:
                output["notes"].append(f"{path}: {exc}")
        elif path.lower().endswith((".db", ".sqlite", ".sqlite3")):
            output["encrypted_database_candidates"].append({
                "path": path, "size": len(body), "sha256": _sha256(body),
                "header_hex": body[:32].hex(),
                "reason": "database-like filename without a SQLite plaintext header (possibly SQLCipher/encrypted)",
            })
            handled.add(path)
    for path in sorted(set(files) - handled):
        body = files[path]
        output["other_files"].append({"path": path, "size": len(body), "sha256": _sha256(body),
                                      "kind": "sqlite-wal" if path.endswith("-wal") else "artifact"})
    def message_order(item):
        timestamp = item["timestamp"]
        if isinstance(timestamp, (int, float)):
            key = (0, timestamp)
        else:
            key = (2 if timestamp is None else 1, str(timestamp))
        return (*key, item["source"], item["rowid"])

    output["message_leads"].sort(key=message_order)
    return output


def analyze_bundle(data: bytes, platform: str = "auto") -> dict[str, Any]:
    files = _bundle_files(data)
    if platform == "auto":
        platform = "ios" if any(_find_file(files, name) is not None
                                for name in ("Manifest.db", "Manifest.mbdb")) else "android"
    if platform == "ios":
        return analyze_ios_backup(files)
    if platform == "android":
        return analyze_android_appdata(files)
    raise ArtifactError("platform must be auto, ios, or android")


def _json_default(value: Any):
    if isinstance(value, bytes):
        return _stable(value)
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="supplied ZIP containing backup/app-data files")
    parser.add_argument("--platform", choices=("auto", "ios", "android"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.bundle.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            raise ArtifactError("bundle exceeds input cap")
        report = analyze_bundle(data, args.platform)
    except (OSError, ValueError) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True, default=_json_default))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
