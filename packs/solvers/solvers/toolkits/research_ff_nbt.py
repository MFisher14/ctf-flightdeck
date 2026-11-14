#!/usr/bin/env python3
"""Bounded, offline Java NBT and Minecraft Anvil-region inspection.

The module parses named-binary-tag streams without importing Minecraft code and inspects
``.mca`` allocation tables without opening external ``.mcc`` files.  It is deliberately a
static reader: it performs no network access, launches no process, and executes no artifact.

Public parsing functions either return JSON-safe dictionaries or raise
``ResearchFFNBTError``.  Malformed input never leaks ``struct.error``, ``IndexError``,
``KeyError``, ``OverflowError``, Unicode errors, or decompressor exceptions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import struct
import sys
import zlib
from pathlib import Path
from typing import Any


MAX_NBT_INPUT = 64 << 20
MAX_REGION_INPUT = 256 << 20
MAX_DECOMPRESSED = 64 << 20
MAX_REGION_CHUNK_DECOMPRESSED = 16 << 20
MAX_REGION_TOTAL_DECOMPRESSED = 128 << 20
MAX_REGION_TOTAL_TAGS = 400_000
MAX_REGION_TOTAL_ARRAY_ITEMS = 2_000_000
MAX_REGION_TOTAL_STRING_BYTES = 16 << 20
MAX_TAGS = 200_000
MAX_DEPTH = 64
MAX_LIST_ITEMS = 200_000
MAX_ARRAY_ITEMS = 1_000_000
MAX_TOTAL_ARRAY_ITEMS = 2_000_000
MAX_TOTAL_STRING_BYTES = 8 << 20

SECTOR_SIZE = 4096
REGION_SLOTS = 1024
REGION_HEADER_SECTORS = 2
MAX_CHUNK_STORED = 255 * SECTOR_SIZE - 4
MAX_ORPHANS = 64
MAX_ORPHAN_CANDIDATES = 16
MAX_ORPHAN_DECOMPRESSED = 8 << 20


class ResearchFFNBTError(ValueError):
    """The bounded reader declined malformed, unsupported, or over-limit input."""


_TAG_NAMES = {
    0: "end",
    1: "byte",
    2: "short",
    3: "int",
    4: "long",
    5: "float",
    6: "double",
    7: "byte_array",
    8: "string",
    9: "list",
    10: "compound",
    11: "int_array",
    12: "long_array",
}
_CHUNK_COMPRESSION = {1: "gzip", 2: "zlib", 3: "raw"}
_CHUNK_COMPRESSION_NAMES = {**_CHUNK_COMPRESSION, 4: "lz4"}


def _fail(message: str) -> ResearchFFNBTError:
    return ResearchFFNBTError(message)


def _as_bytes(data: object, *, cap: int, label: str) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise _fail(f"{label} must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
    except Exception as exc:
        raise _fail(f"{label} size is unavailable") from exc
    if size > cap:
        raise _fail(f"{label} exceeds {cap} byte cap")
    try:
        raw = bytes(data)
    except Exception as exc:
        raise _fail(f"{label} could not be copied safely") from exc
    if len(raw) != size:
        raise _fail(f"{label} size changed while it was copied")
    return raw


class _Reader:
    __slots__ = ("data", "offset")

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0

    def take(self, size: int, label: str) -> bytes:
        if not isinstance(size, int) or size < 0 or size > len(self.data) - self.offset:
            raise _fail(f"truncated {label} at offset {self.offset}")
        start = self.offset
        self.offset += size
        return self.data[start:self.offset]

    def u8(self, label: str) -> int:
        return self.take(1, label)[0]

    def i8(self, label: str) -> int:
        return int.from_bytes(self.take(1, label), "big", signed=True)

    def u16(self, label: str) -> int:
        return int.from_bytes(self.take(2, label), "big")

    def i16(self, label: str) -> int:
        return int.from_bytes(self.take(2, label), "big", signed=True)

    def i32(self, label: str) -> int:
        return int.from_bytes(self.take(4, label), "big", signed=True)

    def i64(self, label: str) -> int:
        return int.from_bytes(self.take(8, label), "big", signed=True)


class _Budget:
    __slots__ = ("tags", "strings", "array_items")

    def __init__(self) -> None:
        self.tags = 0
        self.strings = 0
        self.array_items = 0

    def tag(self, count: int = 1) -> None:
        if count < 0 or count > MAX_TAGS - self.tags:
            raise _fail("NBT tag count exceeds cap")
        self.tags += count

    def string(self, size: int) -> None:
        if size < 0 or size > MAX_TOTAL_STRING_BYTES - self.strings:
            raise _fail("NBT cumulative string bytes exceed cap")
        self.strings += size

    def array(self, count: int) -> None:
        if count < 0 or count > MAX_ARRAY_ITEMS:
            raise _fail("NBT array length is negative or exceeds cap")
        if count > MAX_TOTAL_ARRAY_ITEMS - self.array_items:
            raise _fail("NBT cumulative array items exceed cap")
        self.array_items += count


def _decode_mutf8(raw: bytes) -> str:
    """Decode Java DataInput modified UTF-8, including surrogate-pair encoding."""
    units: list[int] = []
    pos = 0
    while pos < len(raw):
        first = raw[pos]
        pos += 1
        if 1 <= first <= 0x7F:
            units.append(first)
            continue
        if first & 0xE0 == 0xC0:
            if pos >= len(raw):
                raise _fail("truncated modified UTF-8 sequence")
            second = raw[pos]
            pos += 1
            if second & 0xC0 != 0x80:
                raise _fail("invalid modified UTF-8 continuation byte")
            value = ((first & 0x1F) << 6) | (second & 0x3F)
            if value == 0:
                if first != 0xC0 or second != 0x80:
                    raise _fail("invalid modified UTF-8 null encoding")
            elif value < 0x80:
                raise _fail("overlong modified UTF-8 sequence")
            units.append(value)
            continue
        if first & 0xF0 == 0xE0:
            if pos + 2 > len(raw):
                raise _fail("truncated modified UTF-8 sequence")
            second, third = raw[pos], raw[pos + 1]
            pos += 2
            if second & 0xC0 != 0x80 or third & 0xC0 != 0x80:
                raise _fail("invalid modified UTF-8 continuation byte")
            value = ((first & 0x0F) << 12) | ((second & 0x3F) << 6) | (third & 0x3F)
            if value < 0x800:
                raise _fail("overlong modified UTF-8 sequence")
            units.append(value)
            continue
        raise _fail("invalid modified UTF-8 leading byte")

    chars: list[str] = []
    pos = 0
    while pos < len(units):
        value = units[pos]
        pos += 1
        if 0xD800 <= value <= 0xDBFF:
            if pos >= len(units) or not 0xDC00 <= units[pos] <= 0xDFFF:
                raise _fail("unpaired high surrogate in modified UTF-8")
            low = units[pos]
            pos += 1
            chars.append(chr(0x10000 + ((value - 0xD800) << 10) + (low - 0xDC00)))
        elif 0xDC00 <= value <= 0xDFFF:
            raise _fail("unpaired low surrogate in modified UTF-8")
        else:
            chars.append(chr(value))
    return "".join(chars)


def _read_string(reader: _Reader, budget: _Budget, label: str) -> str:
    size = reader.u16(label + " length")
    budget.string(size)
    return _decode_mutf8(reader.take(size, label))


def _json_float(raw: bytes, fmt: str) -> float | str:
    value = struct.unpack(fmt, raw)[0]
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    return value


def _node(tag_id: int, value: Any, name: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type_id": tag_id, "type": _TAG_NAMES[tag_id], "value": value}
    if name is not None:
        result["name"] = name
    return result


def _parse_payload(reader: _Reader, tag_id: int, depth: int, budget: _Budget) -> Any:
    if depth > MAX_DEPTH:
        raise _fail("NBT nesting depth exceeds cap")
    if tag_id == 1:
        return reader.i8("TAG_Byte")
    if tag_id == 2:
        return reader.i16("TAG_Short")
    if tag_id == 3:
        return reader.i32("TAG_Int")
    if tag_id == 4:
        return reader.i64("TAG_Long")
    if tag_id == 5:
        return _json_float(reader.take(4, "TAG_Float"), ">f")
    if tag_id == 6:
        return _json_float(reader.take(8, "TAG_Double"), ">d")
    if tag_id == 7:
        count = reader.i32("TAG_Byte_Array length")
        budget.array(count)
        raw = reader.take(count, "TAG_Byte_Array data")
        return {"length": count, "hex": raw.hex()}
    if tag_id == 8:
        return _read_string(reader, budget, "TAG_String")
    if tag_id == 9:
        element_id = reader.u8("TAG_List element type")
        count = reader.i32("TAG_List length")
        if element_id not in _TAG_NAMES:
            raise _fail(f"invalid TAG_List element type {element_id}")
        if count < 0 or count > MAX_LIST_ITEMS:
            raise _fail("TAG_List length is negative or exceeds cap")
        if element_id == 0 and count != 0:
            raise _fail("TAG_End may only type an empty TAG_List")
        if count > MAX_TAGS - budget.tags:
            raise _fail("NBT tag count exceeds cap")
        items = []
        for _ in range(count):
            budget.tag()
            items.append(_node(element_id, _parse_payload(reader, element_id, depth + 1, budget)))
        return {"element_type_id": element_id, "element_type": _TAG_NAMES[element_id],
                "length": count, "items": items}
    if tag_id == 10:
        children = []
        while True:
            child_id = reader.u8("TAG_Compound child type")
            if child_id == 0:
                return children
            if child_id not in _TAG_NAMES:
                raise _fail(f"invalid NBT tag id {child_id}")
            budget.tag()
            name = _read_string(reader, budget, "tag name")
            value = _parse_payload(reader, child_id, depth + 1, budget)
            children.append(_node(child_id, value, name))
    if tag_id == 11:
        count = reader.i32("TAG_Int_Array length")
        budget.array(count)
        raw = reader.take(count * 4, "TAG_Int_Array data")
        return [int.from_bytes(raw[pos:pos + 4], "big", signed=True)
                for pos in range(0, len(raw), 4)]
    if tag_id == 12:
        count = reader.i32("TAG_Long_Array length")
        budget.array(count)
        raw = reader.take(count * 8, "TAG_Long_Array data")
        return [int.from_bytes(raw[pos:pos + 8], "big", signed=True)
                for pos in range(0, len(raw), 8)]
    raise _fail(f"unsupported NBT tag id {tag_id}")


def _looks_zlib(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flags = data[0], data[1]
    return cmf & 0x0F == 8 and cmf >> 4 <= 7 and ((cmf << 8) | flags) % 31 == 0


def _inflate(data: bytes, wbits: int, label: str, max_output: int) -> bytes:
    if max_output < 1 or max_output > MAX_DECOMPRESSED:
        raise _fail("invalid decompression limit")
    try:
        decoder = zlib.decompressobj(wbits)
        output = bytearray(decoder.decompress(data, max_output + 1))
        if len(output) <= max_output:
            output.extend(decoder.flush(max_output + 1 - len(output)))
    except (zlib.error, ValueError, OverflowError, MemoryError) as exc:
        raise _fail(f"invalid {label} stream") from exc
    if len(output) > max_output or decoder.unconsumed_tail:
        raise _fail(f"{label} output exceeds decompression cap")
    if not decoder.eof:
        raise _fail(f"truncated {label} stream")
    if decoder.unused_data:
        raise _fail(f"trailing bytes after {label} stream")
    return bytes(output)


def _decode_container(data: bytes, compression: str, max_output: int) -> tuple[bytes, str]:
    if compression not in {"auto", "raw", "gzip", "zlib"}:
        raise _fail("compression must be auto, raw, gzip, or zlib")
    actual = compression
    if compression == "auto":
        actual = "gzip" if data.startswith(b"\x1f\x8b") else "zlib" if _looks_zlib(data) else "raw"
    if actual == "raw":
        if len(data) > max_output:
            raise _fail("raw NBT exceeds decompression cap")
        return data, actual
    return _inflate(data, 16 + zlib.MAX_WBITS if actual == "gzip" else zlib.MAX_WBITS,
                    actual, max_output), actual


def _parse_nbt_impl(data: bytes, compression: str, max_output: int) -> dict[str, Any]:
    decoded, actual = _decode_container(data, compression, max_output)
    if not decoded:
        raise _fail("NBT stream is empty")
    reader = _Reader(decoded)
    budget = _Budget()
    root_id = reader.u8("root tag type")
    if root_id == 0 or root_id not in _TAG_NAMES:
        raise _fail(f"invalid root NBT tag id {root_id}")
    budget.tag()
    root_name = _read_string(reader, budget, "root name")
    root_value = _parse_payload(reader, root_id, 0, budget)
    if reader.offset != len(decoded):
        raise _fail(f"trailing bytes after root NBT tag at offset {reader.offset}")
    return {
        "kind": "nbt",
        "compression": actual,
        "input_size": len(data),
        "decompressed_size": len(decoded),
        "tag_count": budget.tags,
        "string_bytes": budget.strings,
        "array_items": budget.array_items,
        "root": _node(root_id, root_value, root_name),
    }


def parse_nbt(data: object, compression: str = "auto") -> dict[str, Any]:
    """Parse one fully consumed Java big-endian NBT stream.

    ``compression`` may be ``auto``, ``raw``, ``gzip``, or ``zlib``.  The only declared
    failure is :class:`ResearchFFNBTError`.
    """
    try:
        raw = _as_bytes(data, cap=MAX_NBT_INPUT, label="NBT input")
        return _parse_nbt_impl(raw, compression, MAX_DECOMPRESSED)
    except ResearchFFNBTError:
        raise
    except Exception as exc:  # fail-closed public boundary
        raise _fail("NBT parser declined input") from exc


def _append_issue(row: dict[str, Any], issue: str) -> None:
    if issue not in row["issues"]:
        row["issues"].append(issue)


def _slack_summary(data: bytes) -> dict[str, Any]:
    first = next((index for index, value in enumerate(data) if value), None)
    nonzero = sum(value != 0 for value in data)
    sample = b"" if first is None else data[first:first + 32]
    strings = []
    start = None
    for index, value in enumerate(data + b"\x00"):
        if 0x20 <= value <= 0x7E:
            if start is None:
                start = index
        elif start is not None:
            if index - start >= 4 and len(strings) < 16:
                raw = data[start:index]
                strings.append({
                    "offset": start,
                    "text": raw[:160].decode("ascii"),
                    "truncated": len(raw) > 160,
                })
            start = None
    return {
        "size": len(data),
        "nonzero_bytes": nonzero,
        "first_nonzero_offset": first,
        "first_nonzero_sample_hex": sample.hex(),
        "ascii_runs": strings,
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _nbt_allowance(stored_size: int, remaining: int, maximum: int) -> int:
    estimate = max(1 << 20, stored_size * 64)
    return min(maximum, remaining, estimate)


def _parse_region_nbt(payload: bytes, compression: str, work: dict[str, int], maximum: int
                      ) -> tuple[dict[str, Any] | None, str | None]:
    allowance = _nbt_allowance(len(payload), work["remaining"], maximum)
    if allowance < 1:
        return None, "region NBT decompression budget exhausted"
    try:
        report = _parse_nbt_impl(payload, compression, allowance)
    except ResearchFFNBTError as exc:
        work["remaining"] = max(0, work["remaining"] - allowance)
        return None, str(exc)
    work["remaining"] = max(0, work["remaining"] - report["decompressed_size"])
    for key, report_key, label in (
            ("tags", "tag_count", "tag"),
            ("arrays", "array_items", "array-item"),
            ("strings", "string_bytes", "string-byte")):
        if report[report_key] > work[key]:
            return None, f"region cumulative {label} budget exhausted"
    work["tags"] -= report["tag_count"]
    work["arrays"] -= report["array_items"]
    work["strings"] -= report["string_bytes"]
    return report, None


def _chunk_record(data: bytes, entry: dict[str, Any], work: dict[str, int]) -> dict[str, Any]:
    start = entry["sector_offset"] * SECTOR_SIZE
    allocation_size = entry["sector_count"] * SECTOR_SIZE
    area = data[start:start + allocation_size]
    report: dict[str, Any] = {
        "file_offset": start,
        "allocation_size": allocation_size,
        "declared_length": None,
        "compression_id": None,
        "compression": None,
        "external": None,
        "external_file_accessed": False,
        "status": "invalid",
        "issues": [],
        "nbt": None,
        "slack": None,
    }
    if len(area) != allocation_size or len(area) < 5:
        report["issues"].append("allocation is truncated")
        return report
    length = int.from_bytes(area[:4], "big")
    report["declared_length"] = length
    if length < 1:
        report["issues"].append("chunk length must include a compression byte")
        return report
    if length > MAX_CHUNK_STORED:
        report["issues"].append("chunk length exceeds Anvil sector-count capacity")
        return report
    record_end = 4 + length
    if record_end > allocation_size:
        report["issues"].append("chunk length exceeds allocated sectors")
        return report
    marker = area[4]
    compression_id = marker & 0x7F
    external = bool(marker & 0x80)
    report["compression_id"] = compression_id
    report["compression"] = _CHUNK_COMPRESSION_NAMES.get(compression_id, "unknown")
    report["external"] = external
    report["slack"] = _slack_summary(area[record_end:])
    payload = area[5:record_end]
    if external:
        if payload:
            report["issues"].append("external chunk record contains inline payload bytes")
        if compression_id not in _CHUNK_COMPRESSION_NAMES:
            report["issues"].append(f"unrecognized external compression id {compression_id}")
        report["status"] = "external"
        return report
    if compression_id not in _CHUNK_COMPRESSION:
        if compression_id == 4:
            report["issues"].append("unsupported compression id 4 (LZ4)")
        else:
            report["issues"].append(f"unsupported compression id {compression_id}")
        return report
    nbt, error = _parse_region_nbt(payload, _CHUNK_COMPRESSION[compression_id], work,
                                   MAX_REGION_CHUNK_DECOMPRESSED)
    if error is not None:
        report["issues"].append("invalid NBT payload: " + error)
        return report
    report["nbt"] = nbt
    report["status"] = "valid"
    return report


def _orphan_chunks(data: bytes, complete_sectors: int, used: set[int], work: dict[str, int]
                   ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    candidates = 0
    sector = REGION_HEADER_SECTORS
    truncated = False
    while sector < complete_sectors and len(rows) < MAX_ORPHANS:
        if sector in used:
            sector += 1
            continue
        start = sector * SECTOR_SIZE
        length = int.from_bytes(data[start:start + 4], "big")
        if not 1 <= length <= MAX_CHUNK_STORED:
            sector += 1
            continue
        marker = data[start + 4]
        compression_id = marker & 0x7F
        if marker & 0x80 or compression_id not in _CHUNK_COMPRESSION:
            sector += 1
            continue
        span = (4 + length + SECTOR_SIZE - 1) // SECTOR_SIZE
        if sector + span > complete_sectors or any(s in used for s in range(sector, sector + span)):
            sector += 1
            continue
        candidates += 1
        if candidates > MAX_ORPHAN_CANDIDATES:
            truncated = True
            break
        payload = data[start + 5:start + 4 + length]
        nbt, error = _parse_region_nbt(payload, _CHUNK_COMPRESSION[compression_id], work,
                                       MAX_ORPHAN_DECOMPRESSED)
        if error is None and nbt is not None and nbt["root"]["type_id"] == 10:
            allocation = data[start:(sector + span) * SECTOR_SIZE]
            rows.append({
                "sector_offset": sector,
                "inferred_sector_count": span,
                "declared_length": length,
                "compression_id": compression_id,
                "compression": _CHUNK_COMPRESSION[compression_id],
                "nbt": nbt,
                "slack": _slack_summary(allocation[4 + length:]),
                "plausibility": "strictly decoded compound NBT in unallocated sectors",
            })
            sector += span
        else:
            sector += 1
        if work["remaining"] <= 0:
            truncated = True
            break
    if len(rows) >= MAX_ORPHANS and sector < complete_sectors:
        truncated = True
    return rows, {"candidate_attempts": candidates, "truncated": truncated,
                  "external_files_accessed": False}


def _inspect_region_impl(data: bytes) -> dict[str, Any]:
    if len(data) < REGION_HEADER_SECTORS * SECTOR_SIZE:
        raise _fail("Anvil region is shorter than its 8192-byte header")
    complete_sectors = len(data) // SECTOR_SIZE
    partial = len(data) % SECTOR_SIZE
    entries: list[dict[str, Any]] = []
    global_issues: list[str] = []
    if partial:
        global_issues.append("file has a partial trailing sector")

    for index in range(REGION_SLOTS):
        location = int.from_bytes(data[index * 4:index * 4 + 4], "big")
        sector_offset, sector_count = location >> 8, location & 0xFF
        timestamp_at = SECTOR_SIZE + index * 4
        timestamp = int.from_bytes(data[timestamp_at:timestamp_at + 4], "big")
        row = {
            "index": index,
            "local_x": index & 31,
            "local_z": index >> 5,
            "sector_offset": sector_offset,
            "sector_count": sector_count,
            "timestamp": timestamp,
            "present": bool(sector_offset or sector_count),
            "zero_pair_valid": (sector_offset == 0) == (sector_count == 0),
            "allocation_in_bounds": False,
            "issues": [],
            "chunk": None,
        }
        if not row["zero_pair_valid"]:
            _append_issue(row, "location offset/count zero-pair is inconsistent")
        if sector_count and sector_offset < REGION_HEADER_SECTORS:
            _append_issue(row, "allocation overlaps reserved header sectors")
        if sector_offset and sector_count:
            row["allocation_in_bounds"] = sector_offset + sector_count <= complete_sectors
            if not row["allocation_in_bounds"]:
                _append_issue(row, "allocation exceeds complete file sectors")
        if not row["present"] and timestamp:
            _append_issue(row, "timestamp is nonzero for an absent location")
        entries.append(row)

    duplicate_map: dict[tuple[int, int], list[int]] = {}
    owners: dict[int, list[int]] = {}
    for row in entries:
        offset, count = row["sector_offset"], row["sector_count"]
        if offset and count:
            duplicate_map.setdefault((offset, count), []).append(row["index"])
        if count and offset < complete_sectors:
            for sector in range(offset, min(complete_sectors, offset + count)):
                owners.setdefault(sector, []).append(row["index"])

    duplicates = []
    for (offset, count), indexes in sorted(duplicate_map.items()):
        if len(indexes) > 1:
            duplicates.append({"sector_offset": offset, "sector_count": count, "entries": indexes})
            for index in indexes:
                _append_issue(entries[index], "duplicate allocation")

    overlap_pairs: set[tuple[int, int]] = set()
    for indexes in owners.values():
        if len(indexes) < 2:
            continue
        unique = sorted(set(indexes))
        for left_pos, left in enumerate(unique):
            for right in unique[left_pos + 1:]:
                overlap_pairs.add((left, right))
    for left, right in sorted(overlap_pairs):
        _append_issue(entries[left], f"allocation overlaps entry {right}")
        _append_issue(entries[right], f"allocation overlaps entry {left}")

    work = {"remaining": MAX_REGION_TOTAL_DECOMPRESSED,
            "tags": MAX_REGION_TOTAL_TAGS,
            "arrays": MAX_REGION_TOTAL_ARRAY_ITEMS,
            "strings": MAX_REGION_TOTAL_STRING_BYTES}
    cache: dict[tuple[int, int], tuple[int, dict[str, Any]]] = {}
    for row in entries:
        if not (row["sector_offset"] and row["sector_count"] and row["allocation_in_bounds"]
                and row["sector_offset"] >= REGION_HEADER_SECTORS):
            continue
        key = (row["sector_offset"], row["sector_count"])
        if key not in cache:
            report = _chunk_record(data, row, work)
            cache[key] = (row["index"], report)
            row["chunk"] = report
        else:
            first_index, first_report = cache[key]
            row["chunk"] = {
                "status": "duplicate-reference",
                "alias_of_entry": first_index,
                "file_offset": first_report["file_offset"],
                "allocation_size": first_report["allocation_size"],
                "external_file_accessed": False,
            }

    used = {0, 1}
    used.update(sector for sector in owners if 0 <= sector < complete_sectors)
    orphans, orphan_scan = _orphan_chunks(data, complete_sectors, used, work)
    data_sectors = set(range(REGION_HEADER_SECTORS, complete_sectors))
    used_data = data_sectors & used
    return {
        "kind": "anvil-region",
        "size": len(data),
        "sector_size": SECTOR_SIZE,
        "complete_sectors": complete_sectors,
        "partial_sector_bytes": partial,
        "issues": global_issues,
        "entries": entries,
        "present_entries": sum(row["present"] for row in entries),
        "valid_inline_chunks": sum(
            row["chunk"] is not None and row["chunk"]["status"] == "valid" for row in entries),
        "external_chunks": sum(
            row["chunk"] is not None and row["chunk"]["status"] == "external" for row in entries),
        "allocation": {
            "used_data_sectors": len(used_data),
            "unallocated_data_sectors": len(data_sectors - used),
            "duplicate_allocations": duplicates,
            "overlap_pairs": [list(pair) for pair in sorted(overlap_pairs)],
        },
        "orphan_chunks": orphans,
        "orphan_scan": orphan_scan,
        "region_decompression_budget_remaining": work["remaining"],
        "external_files_accessed": False,
    }


def inspect_region(data: object) -> dict[str, Any]:
    """Inspect an Anvil ``.mca`` byte string without opening referenced external chunks."""
    try:
        raw = _as_bytes(data, cap=MAX_REGION_INPUT, label="Anvil region input")
        return _inspect_region_impl(raw)
    except ResearchFFNBTError:
        raise
    except Exception as exc:  # fail-closed public boundary
        raise _fail("Anvil region parser declined input") from exc


def analyze_bytes(data: object, *, kind: str = "auto", compression: str = "auto",
                  name: str | None = None) -> dict[str, Any]:
    """Analyze bytes as NBT or Anvil.  ``auto`` honors a ``.mca`` name, then tries NBT."""
    try:
        raw = _as_bytes(data, cap=MAX_REGION_INPUT, label="artifact")
        if kind not in {"auto", "nbt", "mca"}:
            raise _fail("kind must be auto, nbt, or mca")
        selected = kind
        if selected == "auto" and isinstance(name, str) and name.lower().endswith(".mca"):
            selected = "mca"
        if selected == "nbt":
            if len(raw) > MAX_NBT_INPUT:
                raise _fail("NBT input exceeds cap")
            return _parse_nbt_impl(raw, compression, MAX_DECOMPRESSED)
        if selected == "mca":
            return _inspect_region_impl(raw)
        try:
            if len(raw) > MAX_NBT_INPUT:
                raise _fail("NBT input exceeds cap")
            return _parse_nbt_impl(raw, compression, MAX_DECOMPRESSED)
        except ResearchFFNBTError as nbt_error:
            if len(raw) < REGION_HEADER_SECTORS * SECTOR_SIZE:
                raise nbt_error
            return _inspect_region_impl(raw)
    except ResearchFFNBTError:
        raise
    except Exception as exc:  # fail-closed public boundary
        raise _fail("artifact analyzer declined input") from exc


def _read_bounded(path: Path) -> bytes:
    with path.open("rb") as handle:
        data = handle.read(MAX_REGION_INPUT + 1)
    if len(data) > MAX_REGION_INPUT:
        raise _fail("artifact exceeds input cap")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", help="raw/gzip/zlib NBT or an Anvil .mca region")
    parser.add_argument("--kind", choices=("auto", "nbt", "mca"), default="auto")
    parser.add_argument("--compression", choices=("auto", "raw", "gzip", "zlib"), default="auto",
                        help="NBT wrapper; ignored for .mca chunk records")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(json.dumps({"error": "argument parsing failed closed", "kind": "research_ff_nbt",
                          "detail": type(exc).__name__}, sort_keys=True), file=sys.stderr)
        return 2
    try:
        path = Path(args.artifact)
        result = analyze_bytes(_read_bounded(path), kind=args.kind,
                               compression=args.compression, name=path.name)
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
        return 0
    except (OSError, ResearchFFNBTError) as exc:
        print(json.dumps({"error": str(exc), "kind": "research_ff_nbt"}, sort_keys=True),
              file=sys.stderr)
        return 2
    except Exception as exc:  # CLI must not expose low-level parser failures
        print(json.dumps({"error": "analysis failed closed", "kind": "research_ff_nbt",
                          "detail": type(exc).__name__}, sort_keys=True), file=sys.stderr)
        return 2


__all__ = ["ResearchFFNBTError", "parse_nbt", "inspect_region", "analyze_bytes", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
