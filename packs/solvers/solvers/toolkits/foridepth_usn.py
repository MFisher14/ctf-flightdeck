#!/usr/bin/env python3
"""Strict offline parser for $UsnJrnl:$J V2/V3/V4 records.

Unlike the legacy V2 carver, this parser never silently skips a damaged record.
Input is the raw $J stream (not an FSCTL response's leading next-USN value).
V2 references retain their sequence number. V3/V4 FILE_ID_128 values are opaque:
their bytes are preserved and no NTFS record/sequence interpretation is invented.
V4 records have neither a timestamp nor a filename; extents are not file contents.

Layouts: Microsoft winioctl.h USN_RECORD_V2, USN_RECORD_V3, USN_RECORD_V4,
USN_RECORD_EXTENT and MS-FSCC 2.3.62. Integer timestamps retain all 100 ns ticks.
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


class ForidepthUsnError(ValueError):
    """Invalid, truncated, unsupported or resource-limit-exceeding USN input."""


MAX_INPUT = 256 * 1024 * 1024
MAX_RECORD = 1024 * 1024
MAX_RECORDS = 500_000
_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
_MAX_TIME = 2650467743999999999
_REASONS = {
    0x1: "DATA_OVERWRITE", 0x2: "DATA_EXTEND", 0x4: "DATA_TRUNCATION",
    0x10: "NAMED_DATA_OVERWRITE", 0x20: "NAMED_DATA_EXTEND",
    0x40: "NAMED_DATA_TRUNCATION", 0x100: "FILE_CREATE", 0x200: "FILE_DELETE",
    0x400: "EA_CHANGE", 0x800: "SECURITY_CHANGE", 0x1000: "RENAME_OLD_NAME",
    0x2000: "RENAME_NEW_NAME", 0x4000: "INDEXABLE_CHANGE",
    0x8000: "BASIC_INFO_CHANGE", 0x10000: "HARD_LINK_CHANGE",
    0x20000: "COMPRESSION_CHANGE", 0x40000: "ENCRYPTION_CHANGE",
    0x80000: "OBJECT_ID_CHANGE", 0x100000: "REPARSE_POINT_CHANGE",
    0x200000: "STREAM_CHANGE", 0x400000: "TRANSACTED_CHANGE",
    0x800000: "INTEGRITY_CHANGE", 0x1000000: "DESIRED_STORAGE_CLASS_CHANGE",
    0x80000000: "CLOSE",
}
_SOURCES = {1: "DATA_MANAGEMENT", 2: "AUXILIARY_DATA",
            4: "REPLICATION_MANAGEMENT", 8: "CLIENT_REPLICATION_MANAGEMENT"}


def _input(data):
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise ForidepthUsnError("input must be bytes-like")
    if isinstance(data, memoryview) and data.nbytes > MAX_INPUT:
        raise ForidepthUsnError("input exceeds 256 MiB limit")
    if len(data) > MAX_INPUT:
        raise ForidepthUsnError("input exceeds 256 MiB limit")
    return bytes(data)


def _reference(raw):
    value = int.from_bytes(raw, "little")
    result = {"bits": len(raw) * 8, "raw_hex": raw.hex(),
              "value": value, "hex": f"{value:0{len(raw) * 2}x}"}
    if len(raw) == 8:
        result.update(mft_entry=value & 0xffffffffffff, sequence=value >> 48)
    return result


def _timestamp(ticks):
    if ticks < 0 or ticks > _MAX_TIME:
        raise ForidepthUsnError("FILETIME outside supported 1601..9999 range")
    if ticks == 0:
        return None
    date = _EPOCH + timedelta(seconds=ticks // 10_000_000)
    return (f"{date.year:04d}-{date.month:02d}-{date.day:02d}T"
            f"{date.hour:02d}:{date.minute:02d}:{date.second:02d}."
            f"{ticks % 10_000_000:07d}Z")


def _record(data, offset):
    if len(data) - offset < 8:
        raise ForidepthUsnError(f"truncated common header at {offset}")
    size, major, minor = struct.unpack_from("<IHH", data, offset)
    header_size = {2: 60, 3: 76, 4: 64}.get(major)
    if header_size is None or minor != 0:
        raise ForidepthUsnError(f"unsupported USN version {major}.{minor} at {offset}")
    if size < header_size or size > MAX_RECORD or size % 8 or size > len(data) - offset:
        raise ForidepthUsnError(f"invalid/truncated record length at {offset}")
    end = offset + size
    width = 8 if major == 2 else 16
    field = offset + 8 + width * 2
    usn = struct.unpack_from("<q", data, field)[0]
    if usn < 0:
        raise ForidepthUsnError(f"negative USN at {offset}")
    result = {"offset": offset, "record_length": size,
              "major_version": major, "minor_version": minor,
              "file_reference": _reference(data[offset + 8:offset + 8 + width]),
              "parent_reference": _reference(data[offset + 8 + width:field]),
              "usn": usn, "timestamp_raw": None, "timestamp_utc": None,
              "filename": None, "security_id": None, "file_attributes": None,
              "extents": [], "remaining_extents": None, "extent_size": None}
    if major in (2, 3):
        ticks, reason, source, security, attrs, nlen, noff = struct.unpack_from(
            "<qIIIIHH", data, field + 8)
        if noff < header_size or noff % 2 or nlen % 2 or noff + nlen > size:
            raise ForidepthUsnError(f"filename outside record or unaligned at {offset}")
        result.update(timestamp_raw=ticks, timestamp_utc=_timestamp(ticks),
                      filename=data[offset + noff:offset + noff + nlen].decode("utf-16-le"),
                      security_id=security, file_attributes=attrs)
    else:
        reason, source, remaining, count, extent_size = struct.unpack_from("<IIIHH", data, field + 8)
        if extent_size < 16 or extent_size % 8 or 64 + count * extent_size > size:
            raise ForidepthUsnError(f"invalid extent table at {offset}")
        # V4.0 uses exactly two signed 64-bit integers per extent. Preserve future
        # extension bytes rather than interpreting them as another extent.
        for index in range(count):
            start = offset + 64 + index * extent_size
            position, length = struct.unpack_from("<qq", data, start)
            if position < 0 or length < 0 or position + length > (1 << 63) - 1:
                raise ForidepthUsnError(f"invalid extent range at {offset}")
            result["extents"].append({"offset": position, "length": length,
                                       "extension_hex": data[start + 16:start + extent_size].hex()})
        result.update(remaining_extents=remaining, extent_size=extent_size)
    result.update(reason=reason, reasons=[name for bit, name in _REASONS.items() if reason & bit],
                  unknown_reason_bits=reason & ~sum(_REASONS), source_info=source,
                  sources=[name for bit, name in _SOURCES.items() if source & bit],
                  unknown_source_bits=source & ~sum(_SOURCES))
    return result, end


def parse_record(data, offset=0):
    """Parse one record at an aligned byte offset; raise only ForidepthUsnError.

    A full stream can be supplied; bytes after this record are not consumed.
    Use parse_usn() to validate every record in a stream atomically.
    """
    try:
        raw = _input(data)
        if type(offset) is not int or offset < 0 or offset % 8 or offset > len(raw):
            raise ForidepthUsnError("offset must be an aligned nonnegative integer")
        return _record(raw, offset)[0]
    except ForidepthUsnError:
        raise
    except Exception as exc:
        raise ForidepthUsnError(f"malformed USN record: {type(exc).__name__}") from None


def parse_usn(data, *, max_records=MAX_RECORDS, allow_zero_padding=True):
    """Return all V2/V3/V4 records or raise; never return a partial parse.

    All-zero runs at record boundaries are accepted as sparse $J padding by
    default. Nonzero damage is never carved through. This is not a path resolver.
    """
    try:
        raw = _input(data)
        if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
            raise ForidepthUsnError(f"max_records must be 1..{MAX_RECORDS}")
        if type(allow_zero_padding) is not bool:
            raise ForidepthUsnError("allow_zero_padding must be bool")
        records, offset = [], 0
        while offset < len(raw):
            if allow_zero_padding and raw[offset:offset + 8] == b"\0" * 8:
                offset += 8
                while raw[offset:offset + 4096] == b"\0" * 4096:
                    offset += 4096
                continue
            if allow_zero_padding and len(raw) - offset < 8 and not any(raw[offset:]):
                break
            if len(records) >= max_records:
                raise ForidepthUsnError("record limit exceeded; refusing partial output")
            item, offset = _record(raw, offset)
            records.append(item)
        return records
    except ForidepthUsnError:
        raise
    except Exception as exc:
        raise ForidepthUsnError(f"malformed USN stream: {type(exc).__name__}") from None


def parse_file(path, *, max_records=MAX_RECORDS, allow_zero_padding=True):
    """Read a supplied file only; no discovery, network, mutation or execution."""
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_INPUT + 1)
        return parse_usn(data, max_records=max_records, allow_zero_padding=allow_zero_padding)
    except ForidepthUsnError:
        raise
    except Exception as exc:
        raise ForidepthUsnError(f"cannot parse USN file: {type(exc).__name__}") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="raw $UsnJrnl:$J stream")
    parser.add_argument("--max-records", type=int, default=MAX_RECORDS)
    parser.add_argument("--no-padding", action="store_true", help="reject zero-filled stream padding")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        result = parse_file(args.file, max_records=args.max_records,
                            allow_zero_padding=not args.no_padding)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except ForidepthUsnError as exc:
        print(f"foridepth_usn: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
