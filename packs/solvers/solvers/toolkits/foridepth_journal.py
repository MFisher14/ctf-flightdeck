#!/usr/bin/env python3
"""Strict, offline systemd journal reader (classic/compact) and binary export reader.

Sources: systemd.io/JOURNAL_FILE_FORMAT/, systemd.io/JOURNAL_EXPORT_FORMATS/,
and systemd src/basic/compress.c. Only the global ENTRY_ARRAY chain is returned;
orphan entries and allocated arena space after tail_object_offset are not evidence.
Fields are dict[str, list[bytes]], preserving duplicates and binary values. The CLI
renders valid UTF-8 as text, otherwise {"base64": ...}. No hash/FSS authentication
is claimed, nor recovery from corrupt or concurrently changing journal files.
"""
from __future__ import annotations

import argparse
import base64
import json
import lzma
import re
import struct
import sys
from pathlib import Path

MAX_INPUT = 256 << 20
MAX_FIELD = 4 << 20
MAX_TOTAL = 64 << 20
MAX_OBJECTS = 1_000_000
MAX_ENTRIES = 100_000
MAX_FIELDS = 100_000
_NAME = re.compile(rb"[A-Z_][A-Z0-9_]{0,63}\Z")


class ForidepthJournalError(ValueError):
    """Invalid, unsupported, or resource-limited journal input."""


def _input(data):
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ForidepthJournalError("input must be bounded bytes")


def _field(payload):
    name, sep, value = payload.partition(b"=")
    if not sep or not _NAME.fullmatch(name) or len(payload) > MAX_FIELD:
        raise ForidepthJournalError("invalid or oversized journal field")
    return name.decode("ascii"), value


def _decode(payload, flags):
    if flags == 0:
        result = payload
    elif flags == 1:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 << 20)
        result = decoder.decompress(payload, max_length=MAX_FIELD + 1)
        if not decoder.eof or decoder.unused_data:
            raise ForidepthJournalError("truncated, oversized, or trailing XZ frame")
    elif flags == 2:
        import lz4.block
        if len(payload) < 9:
            raise ForidepthJournalError("truncated LZ4 journal blob")
        size = struct.unpack_from("<Q", payload)[0]
        if not 0 < size <= MAX_FIELD:
            raise ForidepthJournalError("LZ4 expanded size exceeds limit")
        result = lz4.block.decompress(payload[8:], uncompressed_size=size)
        if len(result) != size:
            raise ForidepthJournalError("LZ4 expanded size mismatch")
    elif flags == 4:
        import zstandard
        size = zstandard.frame_content_size(payload)
        if size not in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR) and size > MAX_FIELD:
            raise ForidepthJournalError("Zstd expanded size exceeds limit")
        decoder = zstandard.ZstdDecompressor(max_window_size=MAX_FIELD // 1024)
        result = decoder.decompress(payload, max_output_size=MAX_FIELD, allow_extra_data=False)
    else:
        raise ForidepthJournalError("unsupported or conflicting compression flags")
    if len(result) > MAX_FIELD:
        raise ForidepthJournalError("expanded field exceeds limit")
    return result


def parse_journal(data: bytes) -> dict:
    """Read committed entries from one complete file; fail atomically on errors.

    File and entry hashes and Forward Secure Sealing are not verified. Unknown
    compatible flags and unknown object types are skipped as systemd specifies.
    Unknown incompatible flags, dangling references, and corrupt framing fail.
    """
    try:
        return _parse_journal(data)
    except ForidepthJournalError:
        raise
    except Exception as exc:
        raise ForidepthJournalError("invalid journal data or unavailable compression codec") from exc


def _parse_journal(data):
    _input(data)
    if len(data) < 208 or data[:8] != b"LPKSHHRH":
        raise ForidepthJournalError("invalid journal header")
    compatible, incompatible = struct.unpack_from("<II", data, 8)
    if incompatible & ~31 or data[16] > 2:
        raise ForidepthJournalError("unsupported journal flags or state")
    header, arena = struct.unpack_from("<QQ", data, 88)
    tail, nobjects, nentries = struct.unpack_from("<QQQ", data, 136)
    first_array = struct.unpack_from("<Q", data, 176)[0]
    end = header + arena
    if header < 208 or header % 8 or end > len(data):
        raise ForidepthJournalError("invalid header/arena bounds")
    if nobjects > MAX_OBJECTS or nentries > MAX_ENTRIES:
        raise ForidepthJournalError("journal object/entry limit exceeded")
    if bool(tail) != bool(nobjects) or (tail and (tail < header or tail >= end or tail % 8)):
        raise ForidepthJournalError("invalid tail object offset")
    compact = bool(incompatible & 16)
    objects = {}
    fields = {}
    field_bytes = 0
    offset = header
    while tail and offset <= tail:
        if offset + 16 > end:
            raise ForidepthJournalError("truncated object header")
        kind, flags = data[offset:offset + 2]
        size = struct.unpack_from("<Q", data, offset + 8)[0]
        if size < 16 or size > end - offset:
            raise ForidepthJournalError("invalid object size")
        if kind in range(1, 8) and flags and kind != 1:
            raise ForidepthJournalError("compression flag on non-DATA object")
        objects[offset] = (kind, size)
        if len(objects) > MAX_OBJECTS:
            raise ForidepthJournalError("journal object limit exceeded")
        if kind == 1:
            required = {0: 0, 1: 1, 2: 2, 4: 8}.get(flags)
            if required is None or required & incompatible != required:
                raise ForidepthJournalError("DATA compression not declared in header")
            start = 72 if compact else 64
            if size < start:
                raise ForidepthJournalError("truncated DATA object")
            payload = _decode(data[offset + start:offset + size], flags)
            field_bytes += len(payload)
            if field_bytes > MAX_TOTAL:
                raise ForidepthJournalError("total decoded field limit exceeded")
            fields[offset] = _field(payload)
        elif kind == 3 and (size < 64 or (size - 64) % (4 if compact else 16)):
            raise ForidepthJournalError("invalid ENTRY item table")
        elif kind == 6 and (size < 24 or (size - 24) % (4 if compact else 8)):
            raise ForidepthJournalError("invalid ENTRY_ARRAY item table")
        if offset == tail:
            break
        offset = (offset + size + 7) & ~7
    if (tail and offset != tail) or len(objects) != nobjects:
        raise ForidepthJournalError("tail/count does not match object stream")

    def referenced(at, expected):
        obj = objects.get(at)
        if obj is None or obj[0] != expected:
            raise ForidepthJournalError("dangling or wrong-type object reference")
        return obj[1]

    entries = []
    visited = set()
    previous_entry = 0
    output_bytes = output_fields = 0
    array_offset = first_array
    while array_offset:
        if array_offset in visited:
            raise ForidepthJournalError("ENTRY_ARRAY cycle")
        visited.add(array_offset)
        size = referenced(array_offset, 6)
        step = 4 if compact else 8
        saw_empty = False
        for item in range(array_offset + 24, array_offset + size, step):
            entry_offset = int.from_bytes(data[item:item + step], "little")
            if not entry_offset:
                saw_empty = True
                continue
            if saw_empty or entry_offset <= previous_entry:
                raise ForidepthJournalError("unordered or duplicate ENTRY reference")
            previous_entry = entry_offset
            entry_size = referenced(entry_offset, 3)
            if len(entries) >= nentries:
                raise ForidepthJournalError("entry count differs from header")
            seqnum, realtime, monotonic = struct.unpack_from("<QQQ", data, entry_offset + 16)
            row = {"offset": entry_offset, "seqnum": seqnum, "realtime_us": realtime,
                   "monotonic_us": monotonic, "boot_id": data[entry_offset + 40:entry_offset + 56].hex(),
                   "fields": {}}
            entry_step = 4 if compact else 16
            for ref in range(entry_offset + 64, entry_offset + entry_size, entry_step):
                field_offset = int.from_bytes(data[ref:ref + (4 if compact else 8)], "little")
                referenced(field_offset, 1)
                name, value = fields[field_offset]
                output_bytes += len(value)
                output_fields += 1
                if output_bytes > MAX_TOTAL or output_fields > MAX_FIELDS:
                    raise ForidepthJournalError("expanded entry field limit exceeded")
                row["fields"].setdefault(name, []).append(value)
            entries.append(row)
        array_offset = struct.unpack_from("<Q", data, array_offset + 16)[0]
        if saw_empty and array_offset:
            raise ForidepthJournalError("nonterminal partially empty ENTRY_ARRAY")
    if len(entries) != nentries:
        raise ForidepthJournalError("entry count differs from global index")
    return {"format": "systemd-journal", "compact": compact, "state": data[16],
            "file_id": data[24:40].hex(), "machine_id": data[40:56].hex(),
            "compatible_flags": compatible, "incompatible_flags": incompatible,
            "hashes_verified": False, "objects": len(objects), "entries": entries}


def parse_export(data: bytes) -> dict:
    """Read binary-safe journalctl -o export; duplicates and bytes are preserved.

    Entries must have the format's terminating blank line. Truncated final
    entries are rejected, even if preceding entries were complete.
    """
    try:
        _input(data)
        entries, fields = [], {}
        offset = total = count = 0
        while offset < len(data):
            newline = data.find(b"\n", offset, min(len(data), offset + MAX_FIELD + 1))
            if newline < 0:
                raise ForidepthJournalError("missing or oversized export field line")
            line = data[offset:newline]
            offset = newline + 1
            if not line:
                if not fields:
                    raise ForidepthJournalError("empty journal export entry")
                entries.append({"fields": fields})
                fields = {}
                if len(entries) > MAX_ENTRIES:
                    raise ForidepthJournalError("export entry limit exceeded")
                continue
            if b"=" in line:
                name, value = _field(line)
                text = value.decode("utf-8")
                if any(ord(char) < 32 and char != "\t" for char in text):
                    raise ForidepthJournalError("control byte in text export field")
            else:
                if not _NAME.fullmatch(line) or offset + 8 > len(data):
                    raise ForidepthJournalError("invalid binary export field header")
                size = struct.unpack_from("<Q", data, offset)[0]
                offset += 8
                if size > MAX_FIELD or size >= len(data) - offset or data[offset + size] != 10:
                    raise ForidepthJournalError("truncated or oversized binary export field")
                name = line.decode("ascii")
                value = data[offset:offset + size]
                offset += size + 1
            total += len(value)
            count += 1
            if total > MAX_TOTAL or count > MAX_FIELDS:
                raise ForidepthJournalError("export field limit exceeded")
            fields.setdefault(name, []).append(value)
        if fields:
            raise ForidepthJournalError("unterminated export entry")
        return {"format": "journal-export", "entries": entries}
    except ForidepthJournalError:
        raise
    except Exception as exc:
        raise ForidepthJournalError("invalid journal export") from exc


def _json_bytes(value):
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return {"base64": base64.b64encode(value).decode("ascii")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="captured .journal or journalctl -o export file")
    parser.add_argument("--format", choices=("auto", "journal", "export"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with Path(args.input).open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        mode = args.format
        if mode == "auto":
            mode = "journal" if data.startswith(b"LPKSHHRH") else "export"
        result = parse_journal(data) if mode == "journal" else parse_export(data)
        print(json.dumps(result, default=_json_bytes, ensure_ascii=True, indent=2))
        return 0
    except Exception as exc:
        print(f"foridepth_journal: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
