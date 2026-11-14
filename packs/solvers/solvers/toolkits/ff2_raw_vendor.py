#!/usr/bin/env python3
"""Inventory Nikon NEF, Sony ARW, and Fujifilm RAF previews/maker notes.

NEF and ARW reuse :mod:`ff_raw_inventory` for the TIFF/BigTIFF IFD graph and
validated preview extents; this module only adds vendor identity and bounded
maker-note structure.  RAF's fixed big-endian offset directory is parsed here
because it is not a TIFF container at offset zero.  Sensor pixels and opaque or
vendor-encrypted maker-note values are never decoded.
"""
from __future__ import annotations

import argparse
from functools import wraps
import json
from pathlib import Path
import sys

try:
    import ff_raw_inventory as _raw
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import ff_raw_inventory as _raw


MAX_INPUT = 128 << 20
MAX_VENDOR_IFDS = 128
MAX_VENDOR_ENTRIES = 8192
MAX_RAF_RECORDS = 4096
MAX_MAKER_NOTES = 128
RAF_MAGIC = b"FUJIFILMCCD-RAW "

NIKON_TAGS = {
    0x0001: "MakerNoteVersion", 0x0002: "ISO", 0x0003: "ColorMode",
    0x0004: "Quality", 0x0005: "WhiteBalance", 0x0006: "Sharpness",
    0x0007: "FocusMode", 0x0008: "FlashSetting", 0x0009: "FlashType",
    0x000F: "ISOSelection", 0x0011: "PreviewIFD", 0x001D: "SerialNumber",
    0x0084: "Lens", 0x0091: "ShotInfo", 0x0097: "ColorBalance",
}
SONY_TAGS = {
    0x0010: "CameraInfo", 0x0020: "FocusInfo", 0x0102: "Quality",
    0x0114: "CameraSettings", 0x0115: "WhiteBalance",
    0x2001: "PreviewImage", 0xB000: "FileFormat",
}
FUJI_TAGS = {
    0x0000: "Version", 0x0010: "InternalSerialNumber",
    0x1000: "Quality", 0x1001: "Sharpness", 0x1002: "WhiteBalance",
    0x1003: "Saturation", 0x1004: "Contrast", 0x1010: "FlashMode",
    0x1020: "Macro", 0x1021: "FocusMode", 0x1031: "PictureMode",
}
RAF_TAGS = {
    0x0100: "RawImageFullSize", 0x0110: "RawImageCropTopLeft",
    0x0111: "RawImageCroppedSize", 0x0121: "RawImageOutputSize",
    0x0130: "RawInfo", 0x0131: "CFAPattern", 0x2FF0: "CameraMultiplier",
    0xC000: "UnknownData",
}

__all__ = ["FF2RawVendorError", "inventory", "extract_preview",
           "extract_maker_note", "main"]


class FF2RawVendorError(Exception):
    """Malformed, unsupported, or over-budget vendor RAW data."""


def _closed(function):
    @wraps(function)
    def guarded(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except FF2RawVendorError:
            raise
        except Exception as exc:
            raise FF2RawVendorError(
                f"{function.__name__}: {type(exc).__name__}: {exc}"
            ) from exc
    return guarded


def _input(data):
    if not isinstance(data, bytes) or not data:
        raise FF2RawVendorError("input must be nonempty bytes")
    if len(data) > MAX_INPUT:
        raise FF2RawVendorError("input exceeds the 128 MiB cap")


def _extent(data, offset, length, end=None):
    end = len(data) if end is None else end
    if (type(offset) is not int or type(length) is not int or
            not 0 <= offset <= end <= len(data) or not 0 <= length <= end - offset):
        raise FF2RawVendorError("referenced extent leaves its container")


def _ascii(decoded, tag):
    entry = decoded["ifds"][0].get(tag)
    if entry is None or entry[0] != 2 or entry[1] > 4096:
        return None
    return bytes(entry[2]).split(b"\0", 1)[0].decode("latin-1", "replace").strip()


def _byte_order(data):
    if data[:2] == b"II":
        return "little"
    if data[:2] == b"MM":
        return "big"
    raise FF2RawVendorError("invalid TIFF byte order")


def _ifd_table(blob: bytes, offset: int, endian: str, names: dict[int, str],
               *, values_base: int = 0) -> dict:
    """Inventory one classic 12-byte-entry IFD without interpreting sub-blocks.

    Maker-note offset bases vary by vendor.  External values that resolve inside
    ``blob`` are summarized; otherwise their pointer is retained as unresolved.
    This is evidence inventory, not a permissive attempt to follow arbitrary
    pointers into the host file.
    """
    _extent(blob, offset, 2)
    count = int.from_bytes(blob[offset:offset + 2], endian)
    if count > MAX_VENDOR_ENTRIES:
        raise FF2RawVendorError("vendor IFD entry count exceeds cap")
    table_end = offset + 2 + count * 12
    _extent(blob, offset, 2 + count * 12 + 4)
    entries = []
    aggregate = 0
    for index in range(count):
        at = offset + 2 + index * 12
        tag = int.from_bytes(blob[at:at + 2], endian)
        typ = int.from_bytes(blob[at + 2:at + 4], endian)
        number = int.from_bytes(blob[at + 4:at + 8], endian)
        unit = _raw._metadata.TIFF_SIZES.get(typ)
        if unit is None:
            size = None
        else:
            if number > (1 << 24):
                raise FF2RawVendorError("vendor IFD value count exceeds cap")
            size = unit * number
            aggregate += size
            if aggregate > MAX_INPUT:
                raise FF2RawVendorError("vendor IFD aggregate values exceed cap")
        field = blob[at + 8:at + 12]
        row = {"tag": tag, "tag_hex": f"0x{tag:04x}", "name": names.get(tag),
               "type": typ, "count": number, "value_size": size}
        if size is not None and size <= 4:
            row["inline"] = True
            row["value_hex"] = field[:size].hex()
        else:
            pointer = int.from_bytes(field, endian)
            row.update(inline=False, value_offset=pointer)
            if size is not None:
                resolved = values_base + pointer
                if 0 <= resolved <= len(blob) and size <= len(blob) - resolved:
                    row["value_resolved"] = True
                    row["value_hex_prefix"] = blob[resolved:resolved + min(size, 32)].hex()
                else:
                    row["value_resolved"] = False
        entries.append(row)
    return {"offset": offset, "entry_count": count,
            "next_ifd_offset": int.from_bytes(blob[table_end:table_end + 4], endian),
            "tags": [row["tag"] for row in entries], "entries": entries}


def _self_tiff_note(note: bytes, note_offset: int, prefix: int, vendor: str) -> dict:
    nested = note[prefix:]
    try:
        endian, big, records = _raw._ifds(nested)
    except _raw.RawError as exc:
        raise FF2RawVendorError(f"malformed {vendor} embedded TIFF maker note") from exc
    if big:
        raise FF2RawVendorError("BigTIFF maker notes are unsupported")
    names = NIKON_TAGS if vendor == "nikon" else FUJI_TAGS
    if len(records) > MAX_VENDOR_IFDS:
        raise FF2RawVendorError("maker-note IFD count exceeds cap")
    rows = []
    for offset, role, decoded, _locations in records:
        tags = sorted(decoded["ifds"][0])
        rows.append({"offset": note_offset + prefix + offset,
                     "relative_offset": prefix + offset, "role": role, "tags": tags,
                     "known_tags": {f"0x{tag:04x}": names[tag] for tag in tags if tag in names}})
    return {"byte_order": endian, "bigtiff": False, "ifds": rows}


def _maker_note(note: bytes, note_offset: int, vendor: str, outer_endian: str) -> dict:
    base = {"offset": note_offset, "length": len(note), "vendor": vendor,
            "signature_hex": note[:16].hex()}
    if vendor == "nikon":
        if note.startswith(b"Nikon\0\x02"):
            if len(note) < 18:
                raise FF2RawVendorError("truncated Nikon type-3 maker note")
            base.update(format="nikon-type-3", version_hex=note[6:10].hex(),
                        **_self_tiff_note(note, note_offset, 10, "nikon"))
        elif note.startswith(b"Nikon\0\x01"):
            if len(note) < 14:
                raise FF2RawVendorError("truncated Nikon type-2 maker note")
            base.update(format="nikon-type-2", byte_order="little",
                        ifds=[_ifd_table(note, 8, "little", NIKON_TAGS)])
        else:
            base.update(format="nikon-headerless", byte_order=outer_endian,
                        ifds=[_ifd_table(note, 0, outer_endian, NIKON_TAGS)])
    elif vendor == "sony":
        signatures = (b"SONY DSC ", b"SONY CAM ", b"SONY MOBILE", b"\0\0SONY PIC\0")
        prefix = 12 if note.startswith(signatures) else 0
        if len(note) < prefix + 6:
            raise FF2RawVendorError("truncated Sony maker note")
        table = _ifd_table(note, prefix, outer_endian, SONY_TAGS)
        base.update(format="sony-prefixed" if prefix else "sony-headerless",
                    byte_order=outer_endian, ifds=[table])
        file_format = next((row.get("value_hex") for row in table["entries"]
                            if row["tag"] == 0xB000), None)
        if file_format is not None:
            base["file_format_bytes"] = file_format
    elif vendor == "fujifilm":
        if not note.startswith(b"FUJIFILM") or len(note) < 12:
            raise FF2RawVendorError("invalid Fujifilm maker-note header")
        first = int.from_bytes(note[8:12], "little")
        base.update(format="fujifilm", byte_order="little",
                    ifds=[_ifd_table(note, first, "little", FUJI_TAGS)])
    else:
        raise FF2RawVendorError("unsupported maker-note vendor")
    return base


def _jpeg_exif(jpeg: bytes, absolute_start: int):
    if not jpeg.startswith(b"\xff\xd8"):
        return None
    cursor = 2
    while cursor < len(jpeg):
        if jpeg[cursor] != 0xFF:
            return None
        while cursor < len(jpeg) and jpeg[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(jpeg):
            return None
        marker = jpeg[cursor]
        cursor += 1
        if marker in (0xD8, 0xD9) or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            if marker == 0xD9:
                return None
            continue
        if marker == 0xDA:
            return None
        _extent(jpeg, cursor, 2)
        length = int.from_bytes(jpeg[cursor:cursor + 2], "big")
        if length < 2:
            raise FF2RawVendorError("invalid JPEG segment length")
        _extent(jpeg, cursor, length)
        payload_at = cursor + 2
        payload = jpeg[payload_at:cursor + length]
        if marker == 0xE1 and payload.startswith(b"Exif\0\0"):
            return payload[6:], absolute_start + payload_at + 6
        cursor += length
    return None


def _tiff_vendor(data: bytes) -> dict:
    try:
        generic = _raw.inventory(data)
        outer_endian, _big, records = _raw._ifds(data)
    except _raw.RawError as exc:
        raise FF2RawVendorError(f"invalid TIFF-based RAW: {exc}") from exc
    make = model = None
    locations = []
    for _offset, _role, decoded, fields in records:
        make = make or _ascii(decoded, 0x010F)
        model = model or _ascii(decoded, 0x0110)
        if 0x927C in fields:
            locations.append(fields[0x927C])
    if len(locations) > MAX_MAKER_NOTES:
        raise FF2RawVendorError("maker-note count exceeds cap")

    by_make = None
    upper = (make or "").upper()
    if "NIKON" in upper:
        by_make = "nikon"
    elif upper.startswith("SONY"):
        by_make = "sony"
    signatures = set()
    for offset, length in locations:
        _extent(data, offset, length)
        note = data[offset:offset + length]
        if note.startswith(b"Nikon\0"):
            signatures.add("nikon")
        elif note.startswith((b"SONY ", b"\0\0SONY")):
            signatures.add("sony")
    if by_make and signatures and signatures != {by_make}:
        raise FF2RawVendorError("camera make conflicts with maker-note signature")
    if len(signatures) > 1:
        raise FF2RawVendorError("conflicting maker-note vendors")
    vendor = by_make or (next(iter(signatures)) if signatures else None)
    if vendor not in {"nikon", "sony"}:
        raise FF2RawVendorError("TIFF is not identified as Nikon NEF or Sony ARW")

    notes = []
    for offset, length in locations:
        notes.append(_maker_note(data[offset:offset + length], offset, vendor, outer_endian))
    previews = []
    for index, item in enumerate(generic["previews"]):
        previews.append({**item, "index": index})
    return {
        "format": "nef" if vendor == "nikon" else "arw",
        "vendor": vendor,
        "make": make,
        "model": model,
        "endian": generic["endian"],
        "bigtiff": generic["bigtiff"],
        "ifds": generic["ifds"],
        "previews": previews,
        "maker_notes": notes,
        "originals": generic["originals"],
        "sensor_data_decoded": False,
    }


def _raf_records(data: bytes, offset: int, length: int):
    if not offset and not length:
        return [], {"offset": 0, "length": 0}
    _extent(data, offset, length)
    if length < 4:
        raise FF2RawVendorError("RAF metadata directory is truncated")
    end = offset + length
    count = int.from_bytes(data[offset:offset + 4], "big")
    if count > MAX_RAF_RECORDS:
        raise FF2RawVendorError("RAF metadata record count exceeds cap")
    cursor = offset + 4
    rows = []
    for index in range(count):
        _extent(data, cursor, 4, end)
        tag = int.from_bytes(data[cursor:cursor + 2], "big")
        size = int.from_bytes(data[cursor + 2:cursor + 4], "big")
        value_at = cursor + 4
        _extent(data, value_at, size, end)
        value = data[value_at:value_at + size]
        row = {"index": index, "tag": tag, "tag_hex": f"0x{tag:04x}",
               "name": RAF_TAGS.get(tag), "offset": cursor, "value_offset": value_at,
               "length": size, "value_hex_prefix": value[:32].hex()}
        if tag in {0x0100, 0x0110, 0x0111, 0x0121} and size == 4:
            first = int.from_bytes(value[:2], "big")
            second = int.from_bytes(value[2:], "big")
            row["values"] = [first, second]
            if tag in {0x0100, 0x0111, 0x0121}:
                row["height"] = first
                row["width"] = second
        rows.append(row)
        cursor = value_at + size
    return rows, {"offset": cursor, "length": end - cursor}


def _raf(data: bytes) -> dict:
    if len(data) < 108 or data[:16] != RAF_MAGIC:
        raise FF2RawVendorError("invalid or truncated Fujifilm RAF header")
    pairs = {
        "preview": (int.from_bytes(data[0x54:0x58], "big"),
                    int.from_bytes(data[0x58:0x5C], "big")),
        "metadata": (int.from_bytes(data[0x5C:0x60], "big"),
                     int.from_bytes(data[0x60:0x64], "big")),
        "cfa": (int.from_bytes(data[0x64:0x68], "big"),
                int.from_bytes(data[0x68:0x6C], "big")),
    }
    for name, (offset, length) in pairs.items():
        if bool(offset) != bool(length):
            raise FF2RawVendorError(f"RAF {name} offset/length pair is incomplete")
        if offset:
            _extent(data, offset, length)
            if offset < 108:
                raise FF2RawVendorError(f"RAF {name} overlaps the fixed header")

    previews = []
    maker_notes = []
    preview_at, preview_length = pairs["preview"]
    if preview_at:
        jpeg = data[preview_at:preview_at + preview_length]
        recoverable = (len(jpeg) >= 4 and jpeg.startswith(b"\xff\xd8") and
                       jpeg.endswith(b"\xff\xd9"))
        previews.append({"index": 0, "offset": preview_at, "length": preview_length,
                         "kind": "raf-jpeg", "recoverable": recoverable})
        exif = _jpeg_exif(jpeg, preview_at)
        if exif is not None:
            tiff, tiff_at = exif
            try:
                _endian, _big, records = _raw._ifds(tiff)
            except _raw.RawError as exc:
                raise FF2RawVendorError("RAF preview has malformed EXIF TIFF") from exc
            for _offset, _role, _decoded, fields in records:
                location = fields.get(0x927C)
                if location is None:
                    continue
                relative, length = location
                _extent(tiff, relative, length)
                maker_notes.append(_maker_note(tiff[relative:relative + length],
                                                tiff_at + relative, "fujifilm", "little"))
                if len(maker_notes) > MAX_MAKER_NOTES:
                    raise FF2RawVendorError("maker-note count exceeds cap")

    meta_at, meta_length = pairs["metadata"]
    records, trailing = _raf_records(data, meta_at, meta_length)
    cfa_at, cfa_length = pairs["cfa"]
    cfa = {"offset": cfa_at, "length": cfa_length, "kind": "absent"}
    if cfa_at:
        region = data[cfa_at:cfa_at + cfa_length]
        if region[:2] in (b"II", b"MM"):
            try:
                endian, big, directories = _raw._ifds(region)
            except _raw.RawError as exc:
                raise FF2RawVendorError("RAF FujiIFD TIFF region is malformed") from exc
            cfa.update(kind="tiff", endian=endian, bigtiff=big,
                       ifds=[{"offset": cfa_at + offset, "relative_offset": offset,
                              "role": role, "tags": sorted(decoded["ifds"][0])}
                             for offset, role, decoded, _locations in directories])
        else:
            cfa["kind"] = "opaque-cfa"
    model = data[0x1C:0x3C].split(b"\0", 1)[0].decode("latin-1", "replace").strip()
    return {
        "format": "raf",
        "vendor": "fujifilm",
        "header": {
            "format_version": data[0x10:0x14].decode("latin-1"),
            "camera_id": data[0x14:0x1C].decode("latin-1").rstrip("\0"),
            "camera_model": model,
            "directory_version": data[0x3C:0x40].decode("latin-1"),
        },
        "previews": previews,
        "maker_notes": maker_notes,
        "raf_metadata": {"offset": meta_at, "length": meta_length,
                         "record_count": len(records), "records": records,
                         "trailing": trailing},
        "cfa": cfa,
        "sensor_data_decoded": False,
    }


@_closed
def inventory(data: bytes) -> dict:
    """Inventory one supported vendor RAW file without decoding image pixels."""
    _input(data)
    if data.startswith(RAF_MAGIC):
        return _raf(data)
    if data[:2] in (b"II", b"MM"):
        return _tiff_vendor(data)
    raise FF2RawVendorError("not a supported NEF, ARW, or RAF container")


@_closed
def extract_preview(data: bytes, index: int = 0) -> bytes:
    """Return one validated, SOI/EOI-framed embedded JPEG preview."""
    if type(index) is not int:
        raise FF2RawVendorError("preview index must be an integer")
    report = inventory(data)
    if not 0 <= index < len(report["previews"]):
        raise FF2RawVendorError("preview index out of range")
    item = report["previews"][index]
    if not item.get("recoverable"):
        raise FF2RawVendorError("preview does not have complete JPEG framing")
    return data[item["offset"]:item["offset"] + item["length"]]


@_closed
def extract_maker_note(data: bytes, index: int = 0) -> bytes:
    """Return one inventoried maker-note byte range without interpreting values."""
    if type(index) is not int:
        raise FF2RawVendorError("maker-note index must be an integer")
    report = inventory(data)
    if not 0 <= index < len(report["maker_notes"]):
        raise FF2RawVendorError("maker-note index out of range")
    item = report["maker_notes"][index]
    return data[item["offset"]:item["offset"] + item["length"]]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--extract-preview", type=int, metavar="INDEX")
    group.add_argument("--extract-maker-note", type=int, metavar="INDEX")
    parser.add_argument("--output", type=Path,
                        help="output path for an extraction (created, never overwritten)")
    try:
        args = parser.parse_args(argv)
        extracting = args.extract_preview is not None or args.extract_maker_note is not None
        if extracting != (args.output is not None):
            parser.error("an extraction option and --output must be used together")
        with args.input.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        report = inventory(data)
        if args.extract_preview is not None:
            payload = extract_preview(data, args.extract_preview)
            with args.output.open("xb") as handle:
                handle.write(payload)
        elif args.extract_maker_note is not None:
            payload = extract_maker_note(data, args.extract_maker_note)
            with args.output.open("xb") as handle:
                handle.write(payload)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    except Exception as exc:
        print(f"ff2_raw_vendor: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
