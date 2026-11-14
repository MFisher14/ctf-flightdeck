#!/usr/bin/env python3
"""Bounded OneNote FileDataStoreObject inventory and safe extraction.

This is deliberately narrower than a complete MS-ONESTORE revision-store
reader.  It validates the self-delimiting FileDataStoreObject structure from
MS-ONESTORE 2.6.13 before exposing embedded bytes.  Names are generated from
the object index and a signature sniff; input text is never used as a path.
"""
from __future__ import annotations

import argparse
from functools import wraps
import hashlib
import json
from pathlib import Path
import sys


MAX_INPUT = 128 << 20
MAX_OBJECTS = 4096
MAX_EMBEDDED = 128 << 20

ONE_FILE_GUID = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")
ONETOC_GUID = bytes.fromhex("a12fff43d9ef764c9ee210ea5722765f")
FDSO_HEADER_GUID = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")
FDSO_FOOTER_GUID = bytes.fromhex("22a7fb71790f0b4abb13899256426b24")

__all__ = ["FF2OneNoteError", "inventory", "extract_object", "main"]


class FF2OneNoteError(Exception):
    """Malformed, unsupported, or over-budget OneNote data."""


def _closed(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FF2OneNoteError:
            raise
        except Exception as exc:
            raise FF2OneNoteError(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from exc
    return guarded


def _input(data: bytes) -> None:
    if type(data) is not bytes or not data:
        raise FF2OneNoteError("input must be nonempty bytes")
    if len(data) > MAX_INPUT:
        raise FF2OneNoteError("input exceeds the 128 MiB cap")


def _kind(blob: bytes) -> tuple[str, str, str]:
    """Return an inert (kind, extension, media type) signature classification."""
    if blob.startswith(b"MZ"):
        return "pe", "exe", "application/vnd.microsoft.portable-executable"
    if blob.startswith(b"PK\x03\x04"):
        return "zip", "zip", "application/zip"
    if blob.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole-compound", "ole", "application/x-ole-storage"
    if blob.startswith(b"%PDF-"):
        return "pdf", "pdf", "application/pdf"
    if blob.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "png", "image/png"
    if blob.startswith(b"\xff\xd8\xff"):
        return "jpeg", "jpg", "image/jpeg"
    if blob.startswith((b"{\\rtf", b"{\\urtf")):
        return "rtf", "rtf", "application/rtf"
    if len(blob) >= 20 and blob[:4] == b"L\0\0\0" and blob[4:20] == bytes.fromhex(
        "0114020000000000c000000000000046"
    ):
        return "shell-link", "lnk", "application/x-ms-shortcut"
    return "binary", "bin", "application/octet-stream"


@_closed
def inventory(data: bytes) -> dict:
    """Return a validated structural inventory of embedded file-data objects.

    A real ``.one`` file may validly contain no FileDataStoreObject.  A carved
    fragment, on the other hand, must contain at least one complete object to be
    accepted.  Every header signature encountered outside a validated payload
    must describe a complete, correctly footered object.
    """
    _input(data)
    is_one = data.startswith(ONE_FILE_GUID)
    if data.startswith(ONETOC_GUID):
        raise FF2OneNoteError("OneNote table-of-contents files are not .one sections")

    objects: list[dict] = []
    warnings: list[str] = []
    cursor = 0
    total = 0
    while True:
        at = data.find(FDSO_HEADER_GUID, cursor)
        if at < 0:
            break
        if len(objects) >= MAX_OBJECTS:
            raise FF2OneNoteError("FileDataStoreObject count exceeds cap")
        if at + 36 > len(data):
            raise FF2OneNoteError("truncated FileDataStoreObject header")

        length = int.from_bytes(data[at + 16:at + 24], "little")
        if length > MAX_EMBEDDED or total + length > MAX_EMBEDDED:
            raise FF2OneNoteError("embedded data exceeds aggregate cap")
        data_at = at + 36
        padding = (-(36 + length)) & 7
        footer_at = data_at + length + padding
        end = footer_at + 16
        if footer_at < data_at or end > len(data):
            raise FF2OneNoteError("FileDataStoreObject length leaves the input")
        if data[footer_at:end] != FDSO_FOOTER_GUID:
            raise FF2OneNoteError("FileDataStoreObject footer GUID is missing")

        unused = data[at + 24:at + 28]
        reserved = data[at + 28:at + 36]
        pad_bytes = data[data_at + length:footer_at]
        body = data[data_at:data_at + length]
        kind, extension, media_type = _kind(body)
        index = len(objects)
        violations = []
        if any(unused):
            violations.append("unused field is nonzero")
        if any(reserved):
            violations.append("reserved field is nonzero")
        if any(pad_bytes):
            violations.append("alignment padding is nonzero")
        if violations:
            warnings.extend(f"object {index}: {item}" for item in violations)
        objects.append({
            "index": index,
            "object_offset": at,
            "header_length": 36,
            "data_offset": data_at,
            "data_length": length,
            "padding_offset": data_at + length,
            "padding_length": padding,
            "footer_offset": footer_at,
            "end_offset": end,
            "header_fields_zero": not any(unused + reserved),
            "padding_zero": not any(pad_bytes),
            "sha256": hashlib.sha256(body).hexdigest(),
            "kind": kind,
            "extension": extension,
            "media_type": media_type,
            "generated_name": f"embedded-{index:04d}.{extension}",
            "violations": violations,
        })
        total += length
        cursor = end

    if not is_one and not objects:
        raise FF2OneNoteError("not a OneNote section or FileDataStoreObject fragment")
    return {
        "format": "onenote-section" if is_one else "file-data-store-fragment",
        "file_type_guid": (
            "{7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}" if is_one else None
        ),
        "object_count": len(objects),
        "total_embedded_bytes": total,
        "objects": objects,
        "warnings": warnings,
    }


@_closed
def extract_object(data: bytes, index: int = 0) -> bytes:
    """Return one validated object's exact FileData bytes."""
    if type(index) is not int:
        raise FF2OneNoteError("object index must be an integer")
    report = inventory(data)
    if not 0 <= index < len(report["objects"]):
        raise FF2OneNoteError("object index out of range")
    item = report["objects"][index]
    return data[item["data_offset"]:item["data_offset"] + item["data_length"]]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--extract", type=int, metavar="INDEX",
                       help="extract one validated object")
    group.add_argument("--extract-all", type=Path, metavar="DIRECTORY",
                       help="extract all objects under generated inert names")
    parser.add_argument("--output", type=Path,
                        help="output path for --extract (created, never overwritten)")
    try:
        args = parser.parse_args(argv)
        if (args.extract is None) != (args.output is None):
            parser.error("--extract and --output must be used together")
        with args.input.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        report = inventory(data)
        if args.extract is not None:
            payload = extract_object(data, args.extract)
            with args.output.open("xb") as handle:
                handle.write(payload)
        elif args.extract_all is not None:
            payloads = [extract_object(data, item["index"]) for item in report["objects"]]
            args.extract_all.mkdir(parents=True, exist_ok=True)
            for item, payload in zip(report["objects"], payloads):
                with (args.extract_all / item["generated_name"]).open("xb") as handle:
                    handle.write(payload)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f"ff2_onenote_store: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
