#!/usr/bin/env python3
"""Bounded, offline RAW preview/original recovery, extending readers_formats.

TIFF values are decoded by the existing metadata reader. This adapter supplies
bounded IFD graph traversal, validated extents, DNG original recovery, and a
Canon CR3 box inventory. Maker notes and sensor/compressed pixel data stay opaque.

Sources: Adobe DNG specification (OriginalRawFileData); ExifTool Exif.pm,
Canon.pm and QuickTime.pm. C68B is the original *name*, C68C the original data.
Public parsing/extraction functions raise only RawError on malformed input.
"""
from __future__ import annotations

import argparse
from functools import wraps
import json
from pathlib import Path
import sys
import zlib

try:
    import readers_formats as _metadata
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "metadata-forensics"))
    import readers_formats as _metadata

MAX_INPUT = 128 << 20
MAX_OUTPUT = 128 << 20
MAX_IFDS = 128
MAX_ENTRIES = 8192
MAX_BOXES = 4096
MAX_DEPTH = 16
MAX_PREVIEWS = 128
CANON_UUID = bytes.fromhex("85c0b687820f11e08111f4ce462b6a48")
PREVIEW_UUID = bytes.fromhex("eaf42b5e1c984b88b9fbb7dc406e4d16")

__all__ = ["RawError", "inventory", "decode_original", "extract_preview",
           "extract_original", "main"]


class RawError(Exception):
    """Invalid, unsupported, or over-budget RAW structure."""


def _closed(fn):
    @wraps(fn)
    def guarded(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except RawError:
            raise
        except Exception as exc:
            raise RawError(f"{fn.__name__}: {type(exc).__name__}: {exc}") from exc
    return guarded


def _input(data):
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_INPUT:
        raise RawError("input must be nonempty bytes within the 128 MiB cap")


def _extent(data, offset, length, end=None):
    end = len(data) if end is None else end
    if not (isinstance(offset, int) and isinstance(length, int) and
            0 <= offset <= end <= len(data) and 0 <= length <= end - offset):
        raise RawError("referenced extent leaves its container")


def _uint(data, offset, width, endian="big", end=None):
    _extent(data, offset, width, end)
    return int.from_bytes(data[offset:offset + width], endian)


def _jpeg(data, offset, length):
    _extent(data, offset, length)
    return (length >= 4 and data[offset:offset + 2] == b"\xff\xd8" and
            data[offset + length - 2:offset + length] == b"\xff\xd9")


def _ifds(data, first_extra=0):
    """Add graph/extent accounting without reimplementing TIFF value decoding.

    The uncached existing reader sees one IFD through a temporary root pointer
    and zero next pointer. A memoryview avoids retaining/copying large tag blobs.
    Both temporary fields are restored before any tag is examined.
    """
    _extent(data, 0, 8)
    if data[:2] not in (b"II", b"MM"):
        raise RawError("not a TIFF byte-order marker")
    endian = "little" if data[:2] == b"II" else "big"
    version = _uint(data, 2, 2, endian)
    if version not in (42, 43):
        raise RawError("unsupported TIFF version")
    big = version == 43
    head, entry_size, width, root = (8, 20, 8, 8) if big else (2, 12, 4, 4)
    if big and (_uint(data, 4, 2, endian), _uint(data, 6, 2, endian)) != (8, 0):
        raise RawError("unsupported BigTIFF offset width")
    first = _uint(data, root, width, endian)
    scratch = bytearray(data)
    view = memoryview(scratch)
    pending = [(first, "IFD0", ())]
    if first_extra:
        pending.insert(0, (first_extra, "CR2 raw IFD", ()))
    seen, records, total_entries, total_values = set(), [], 0, 0
    while pending:
        offset, role, ancestors = pending.pop()
        if not offset:
            continue
        if offset in ancestors:
            raise RawError("cyclic IFD graph")
        if offset in seen:
            continue
        if len(seen) >= MAX_IFDS or len(ancestors) >= MAX_DEPTH:
            raise RawError("IFD graph cap exceeded")
        if offset < root + width:
            raise RawError("IFD overlaps TIFF header")
        count = _uint(data, offset, head, endian)
        total_entries += count
        if count > 4096 or total_entries > MAX_ENTRIES:
            raise RawError("IFD entry cap exceeded")
        next_at = offset + head + count * entry_size
        _extent(data, offset, head + count * entry_size + width)
        locations = {}
        for index in range(count):
            at = offset + head + index * entry_size
            tag = _uint(data, at, 2, endian)
            typ = _uint(data, at + 2, 2, endian)
            number = _uint(data, at + 4, width, endian)
            unit = _metadata.TIFF_SIZES.get(typ)
            if unit is None or number > 1 << 24:
                raise RawError("unsupported TIFF tag type/count")
            size = number * unit
            total_values += size
            if total_values > MAX_INPUT * 2:
                raise RawError("aggregate TIFF value cap exceeded")
            value_at = at + entry_size - width
            if size > width:
                value_at = _uint(data, value_at, width, endian)
            _extent(data, value_at, size)
            if tag in locations:
                raise RawError("duplicate TIFF tag")
            locations[tag] = (value_at, size)
        next_ifd = _uint(data, next_at, width, endian)
        saved_root, saved_next = bytes(view[root:root + width]), bytes(view[next_at:next_at + width])
        try:
            scratch[root:root + width] = offset.to_bytes(width, endian)
            scratch[next_at:next_at + width] = b"\0" * width
            decoded = _metadata._tiff.__wrapped__(view)
        finally:
            scratch[root:root + width] = saved_root
            scratch[next_at:next_at + width] = saved_next
        tags = decoded["ifds"][0]
        seen.add(offset)
        records.append((offset, role, decoded, locations))
        lineage = ancestors + (offset,)
        if next_ifd:
            pending.append((next_ifd, "next IFD", lineage))
        for pointer, name in ((330, "SubIFD"), (34665, "ExifIFD"),
                              (34853, "GPSIFD"), (40965, "InteropIFD")):
            if pointer in tags:
                for child in _ints(decoded, pointer):
                    pending.append((child, name, lineage))
        if len(pending) > MAX_ENTRIES:
            raise RawError("IFD pending-reference cap exceeded")
    return endian, big, records


def _ints(decoded, tag):
    entry = decoded["ifds"][0].get(tag)
    if entry is None:
        return []
    if entry[0] not in (1, 3, 4, 13, 16, 18):
        raise RawError(f"tag {tag:#x} must contain unsigned integers")
    if entry[1] > MAX_ENTRIES:
        raise RawError("integer-array count cap exceeded")
    if entry[0] == 18:  # IFD8 is missing from the older reader's scalar helper.
        return [int.from_bytes(entry[2][i:i + 8], "little" if decoded["endian"] == "<" else "big")
                for i in range(0, len(entry[2]), 8)]
    return _metadata._tiff_ints(decoded, tag)


def _one(decoded, tag, default=None):
    values = _ints(decoded, tag)
    if not values:
        return default
    if len(values) != 1:
        raise RawError(f"tag {tag:#x} must have one value")
    return values[0]


def _tiff_inventory(data):
    cr2 = data[8:10] == b"CR"
    raw_ifd = 0
    if cr2:
        if data[:4] != b"II*\0" or data[8:12] != b"CR\x02\0":
            raise RawError("unsupported CR2 header")
        raw_ifd = _uint(data, 12, 4, "little")
    endian, big, records = _ifds(data, raw_ifd)
    result = {"format": "cr2" if cr2 else "tiff", "endian": endian, "bigtiff": big,
              "ifds": [], "previews": [], "originals": []}
    if cr2:
        result["raw_ifd_offset"] = raw_ifd
    extent_count = 0
    for offset, role, decoded, locations in records:
        tags = decoded["ifds"][0]
        if 50706 in tags and not cr2:
            result["format"] = "dng"
        item = {"offset": offset, "role": role, "tags": sorted(tags), "extents": []}
        if 37500 in tags:
            item["maker_note"] = dict(zip(("offset", "length"), locations[37500]), status="opaque")
        compression = _one(decoded, 259)
        photo = _one(decoded, 262)
        for offsets, lengths, kind in ((513, 514, "jpeg-interchange"),
                                      (273, 279, "strip"), (324, 325, "tile")):
            if offsets not in tags and lengths not in tags:
                continue
            starts, sizes = _ints(decoded, offsets), _ints(decoded, lengths)
            if not starts or len(starts) != len(sizes) or len(starts) > MAX_ENTRIES:
                raise RawError("missing or mismatched image extent arrays")
            extent_count += len(starts)
            if extent_count > MAX_ENTRIES:
                raise RawError("aggregate image-extent count cap exceeded")
            for start, size in zip(starts, sizes):
                _extent(data, start, size)
                if size == 0:
                    raise RawError("empty referenced image extent")
                extent = {"offset": start, "length": size, "kind": kind}
                item["extents"].append(extent)
                if kind == "jpeg-interchange" or (compression in (6, 7, 34892) and photo not in (32803, 34892)):
                    if len(result["previews"]) >= MAX_PREVIEWS:
                        raise RawError("preview cap exceeded")
                    result["previews"].append({**extent, "ifd_offset": offset,
                        "recoverable": _jpeg(data, start, size),
                        "width": _one(decoded, 256), "height": _one(decoded, 257)})
        if 0xC68C in tags:
            if tags[0xC68C][0] not in (1, 7):
                raise RawError("OriginalRawFileData must be bytes/undefined")
            name = None
            if 0xC68B in tags:
                if tags[0xC68B][0] not in (1, 2, 7):
                    raise RawError("OriginalRawFileName must be text")
                if tags[0xC68B][1] > 4096:
                    raise RawError("original filename exceeds cap")
                name = bytes(tags[0xC68B][2]).rstrip(b"\0").decode("utf-8", "replace")
            start, size = locations[0xC68C]
            _extent(data, start, 4, start + size)
            result["originals"].append({"offset": start, "length": size, "name": name,
                "ifd_offset": offset, "data_fork_length": _uint(data, start, 4)})
        result["ifds"].append(item)
    return result


def _cr3_inventory(data):
    result = {"format": "cr3", "boxes": [], "ifds": [], "previews": [], "originals": []}
    brands = []
    containers = {"moov", "trak", "mdia", "minf", "stbl", "edts", "dinf", "udta"}

    def walk(start, end, depth, path):
        if depth > MAX_DEPTH:
            raise RawError("BMFF nesting cap exceeded")
        children = _metadata._kids(data, start, end)
        if len(result["boxes"]) + len(children) > MAX_BOXES:
            raise RawError("BMFF box cap exceeded")
        cursor = start
        for kind, body, stop in children:
            if len(result["boxes"]) >= MAX_BOXES:
                raise RawError("BMFF box cap exceeded")
            item = {"type": kind, "offset": cursor, "length": stop - cursor,
                    "data_offset": body, "data_length": stop - body, "path": path + [kind]}
            result["boxes"].append(item)
            if kind == "ftyp":
                if path or stop - body < 8 or (stop - body) % 4:
                    raise RawError("invalid ftyp box")
                brands.extend([data[body:body + 4], *[data[i:i + 4] for i in range(body + 8, stop, 4)]])
            elif kind in containers:
                walk(body, stop, depth + 1, path + [kind])
            elif kind == "uuid":
                _extent(data, body, 16, stop)
                uuid = data[body:body + 16]
                item["uuid"] = uuid.hex()
                if uuid == CANON_UUID:
                    walk(body + 16, stop, depth + 1, path + [kind])
                elif uuid == PREVIEW_UUID:
                    _extent(data, body + 16, 8, stop)
                    if data[body + 16:body + 24] != b"\0\0\0\0\0\0\0\1":
                        raise RawError("unsupported Canon preview UUID header")
                    walk(body + 24, stop, depth + 1, path + [kind])
            elif kind in ("THMB", "PRVW"):
                _extent(data, body, 16, stop)
                if kind == "THMB":
                    if data[body] != 0:
                        item["status"] = "opaque unsupported thumbnail version"
                        cursor = stop
                        continue
                    width, height = _uint(data, body + 4, 2), _uint(data, body + 6, 2)
                    length = _uint(data, body + 8, 4)
                else:
                    width, height = _uint(data, body + 6, 2), _uint(data, body + 8, 2)
                    length = _uint(data, body + 12, 4)
                at = body + 16
                _extent(data, at, length, stop)
                if len(result["previews"]) >= MAX_PREVIEWS:
                    raise RawError("preview cap exceeded")
                result["previews"].append({"offset": at, "length": length, "kind": kind,
                    "width": width, "height": height, "recoverable": _jpeg(data, at, length)})
                item["slack"] = {"offset": at + length, "length": stop - at - length}
            elif kind in ("CMT1", "CMT2", "CMT3", "CMT4"):
                item["status"] = "opaque maker notes" if kind == "CMT3" else "embedded TIFF metadata"
                if kind != "CMT3":
                    endian, big, directories = _ifds(data[body:stop])
                    item.update(endian=endian, bigtiff=big)
                    for offset, role, decoded, _ in directories:
                        if len(result["ifds"]) >= MAX_IFDS:
                            raise RawError("embedded TIFF directory cap exceeded")
                        result["ifds"].append({"offset": body + offset, "relative_offset": offset,
                            "role": role, "box": kind, "tags": sorted(decoded["ifds"][0])})
            cursor = stop
        if cursor != end:
            raise RawError("trailing partial BMFF box")

    walk(0, len(data), 0, [])
    if b"crx " not in brands:
        raise RawError("BMFF file does not declare the Canon crx brand")
    result["brands"] = [brand.decode("latin-1") for brand in brands]
    return result


@_closed
def decode_original(data: bytes, max_output: int = MAX_OUTPUT) -> dict:
    """Decode the eight Adobe OriginalRawFileData blocks, with bounded zlib.

    Fork indexes and lengths are big-endian, independent of TIFF byte order.
    Missing blocks at the end default to zero, as required by the DNG spec.
    Unknown bytes after the eight defined blocks are reported as trailing data.
    """
    _input(data)
    if type(max_output) is not int or not 0 <= max_output <= MAX_OUTPUT:
        raise RawError("invalid original output cap")
    cursor, produced = 0, 0
    result = {}
    for name, is_fork in (("data_fork", True), ("resource_fork", True),
                          ("file_type", False), ("file_creator", False),
                          ("thm_data_fork", True), ("thm_resource_fork", True),
                          ("thm_file_type", False), ("thm_file_creator", False)):
        if cursor == len(data):
            result[name] = b"" if is_fork else b"\0" * 4
            continue
        value = _uint(data, cursor, 4)
        if not is_fork:
            result[name] = data[cursor:cursor + 4]
            cursor += 4
            continue
        length = value
        produced += length
        if produced > max_output:
            raise RawError("original decompressed output cap exceeded")
        if not length:
            result[name] = b""
            cursor += 4
            continue
        count = (length + 65535) // 65536
        header_length = 4 * (count + 2)
        _extent(data, cursor, header_length)
        offsets = [_uint(data, cursor + 4 * (i + 1), 4) for i in range(count + 1)]
        if offsets[0] < header_length or any(a >= b for a, b in zip(offsets, offsets[1:])):
            raise RawError("invalid original fork chunk index")
        _extent(data, cursor, offsets[-1])
        chunks = []
        for i, (start, stop) in enumerate(zip(offsets, offsets[1:])):
            expected = min(65536, length - i * 65536)
            decoder = zlib.decompressobj()
            decoded = decoder.decompress(memoryview(data)[cursor + start:cursor + stop], expected + 1)
            if (len(decoded) != expected or not decoder.eof or decoder.unused_data or
                    decoder.unconsumed_tail):
                raise RawError("original zlib chunk does not match its declared extent/length")
            chunks.append(decoded)
        result[name] = b"".join(chunks)
        cursor += offsets[-1]
    result["trailing"] = {"offset": cursor, "length": len(data) - cursor}
    return result


@_closed
def inventory(data: bytes) -> dict:
    """Inventory bounded TIFF/DNG/CR2 or CR3; image pixels are never decoded."""
    _input(data)
    if data[:2] in (b"II", b"MM"):
        return _tiff_inventory(data)
    return _cr3_inventory(data)


@_closed
def extract_preview(data: bytes, index: int = 0) -> bytes:
    """Recover a referenced SOI/EOI-framed JPEG candidate, without decoding pixels."""
    report = inventory(data)
    if type(index) is not int or not 0 <= index < len(report["previews"]):
        raise RawError("preview index out of range")
    item = report["previews"][index]
    if not item["recoverable"]:
        raise RawError("referenced data lacks JPEG start/end markers")
    return data[item["offset"]:item["offset"] + item["length"]]


@_closed
def extract_original(data: bytes, index: int = 0) -> bytes:
    """Return a DNG original data fork (C68C); embedded filenames are inert."""
    report = inventory(data)
    if type(index) is not int or not 0 <= index < len(report["originals"]):
        raise RawError("original index out of range")
    item = report["originals"][index]
    return decode_original(data[item["offset"]:item["offset"] + item["length"]])["data_fork"]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--extract", type=Path, metavar="DIRECTORY",
                        help="save validated JPEG previews and DNG originals under generated names")
    try:
        args = parser.parse_args(argv)
        with args.input.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        report = inventory(data)
        if args.extract is not None:
            # Validate all recoveries before creating output; names from input are never paths.
            outputs, remaining = [], MAX_OUTPUT
            for i, item in enumerate(report["previews"]):
                if not item["recoverable"]:
                    continue
                if item["length"] > remaining:
                    raise RawError("aggregate extraction cap exceeded")
                payload = data[item["offset"]:item["offset"] + item["length"]]
                outputs.append((f"preview-{i:03d}.jpg", payload))
                remaining -= len(payload)
            for i, item in enumerate(report["originals"]):
                packed = data[item["offset"]:item["offset"] + item["length"]]
                decoded = decode_original(packed, max_output=remaining)
                payload = decoded["data_fork"]
                outputs.append((f"original-{i:03d}.raw", payload))
                remaining -= sum(len(decoded[key]) for key in
                                 ("data_fork", "resource_fork", "thm_data_fork", "thm_resource_fork"))
                del decoded
            args.extract.mkdir(parents=True, exist_ok=True)
            for name, payload in outputs:
                with (args.extract / name).open("xb") as handle:
                    handle.write(payload)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f"ff_raw_inventory: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
