#!/usr/bin/env python3
"""Static, bounded inspection of Zstandard frames, metadata, and dictionaries.

The inspector walks framing only.  It never decompresses a block, loads a
dictionary, executes an artifact, performs network I/O, or submits anything.
It understands concatenated ordinary and skippable frames, validates seekable
format tables against the preceding frame boundaries, and identifies the
header of a formatted dictionary produced by ``zstd --train``.

Compressed-block entropy streams and decoded-content checksums cannot be
validated without decompression.  They are therefore inventoried as opaque
bytes instead of being called valid compressed content.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Iterable


MAX_INPUT = 128 * 1024 * 1024
MAX_FRAMES = 65_536
MAX_BLOCKS = 262_144
MAX_PREVIEW = 256

ZSTD_MAGIC = 0xFD2FB528
ZSTD_MAGIC_BYTES = b"\x28\xb5\x2f\xfd"
SKIPPABLE_MAGIC_MIN = 0x184D2A50
SKIPPABLE_MAGIC_MAX = 0x184D2A5F
SEEK_TABLE_MAGIC = 0x184D2A5E
SEEKABLE_FOOTER_MAGIC = 0x8F92EAB1
SEEKABLE_FOOTER_MAGIC_BYTES = b"\xb1\xea\x92\x8f"
DICTIONARY_MAGIC = 0xEC30A437
DICTIONARY_MAGIC_BYTES = b"\x37\xa4\x30\xec"

_BLOCK_NAMES = ("raw", "rle", "compressed", "reserved")


class ResearchFFZstdError(Exception):
    """Declared failure for malformed, unsupported, or over-limit input."""


def _fail(message: str) -> None:
    raise ResearchFFZstdError(message)


def _need(data: bytes, offset: int, size: int, what: str) -> int:
    if offset < 0 or size < 0 or offset > len(data) or size > len(data) - offset:
        _fail(f"truncated {what} at offset {offset}")
    return offset + size


def _uint(data: bytes, offset: int, size: int, what: str) -> int:
    end = _need(data, offset, size, what)
    return int.from_bytes(data[offset:end], "little")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _preview(data: bytes, limit: int) -> tuple[str, bool]:
    return data[:limit].hex(), len(data) > limit


def _checked_preview(preview_bytes: object) -> int:
    if type(preview_bytes) is not int or not 0 <= preview_bytes <= MAX_PREVIEW:
        _fail(f"preview_bytes must be an integer in 0..{MAX_PREVIEW}")
    return preview_bytes


def _coerce(data: object) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        _fail("input must be bytes-like")
    try:
        size = data.nbytes if isinstance(data, memoryview) else len(data)
    except Exception:
        _fail("input byte length is unavailable")
    if not 1 <= size <= MAX_INPUT:
        _fail(f"input size must be in 1..{MAX_INPUT} bytes")
    try:
        raw = bytes(data)
    except Exception:
        _fail("input could not be copied safely")
    if len(raw) != size:
        _fail("input byte length changed while it was copied")
    return raw


def _parse_dictionary(data: bytes, preview_bytes: int) -> dict:
    _need(data, 0, 8, "formatted dictionary header")
    dictionary_id = _uint(data, 4, 4, "dictionary ID")
    if dictionary_id == 0:
        _fail("a formatted Zstandard dictionary cannot have dictionary ID zero")
    tail = data[8:]
    shown, clipped = _preview(tail, preview_bytes)
    if dictionary_id <= 32_767:
        id_range = "reserved_low"
    elif dictionary_id >= 1 << 31:
        id_range = "reserved_high"
    else:
        id_range = "public_free"
    return {
        "format": "zstd_formatted_dictionary",
        "size": len(data),
        "sha256": _digest(data),
        "validation_scope": "formatted dictionary header only; entropy tables and content remain opaque",
        "dictionary": {
            "magic": f"0x{DICTIONARY_MAGIC:08x}",
            "header_size": 8,
            "dictionary_id": dictionary_id,
            "dictionary_id_range": id_range,
            "opaque_tail_offset": 8,
            "opaque_tail_size": len(tail),
            "opaque_tail_sha256": _digest(tail),
            "opaque_tail_preview_hex": shown,
            "opaque_tail_preview_truncated": clipped,
        },
    }


def _parse_ordinary(data: bytes, start: int, preview_bytes: int, block_budget: int) -> tuple[dict, int]:
    descriptor = _uint(data, start + 4, 1, "frame header descriptor")
    # Bit 3 is reserved.  Bit 4 is currently unused and encoders must emit zero;
    # rejecting both gives a fail-closed canonical framing result.
    if descriptor & 0x18:
        _fail(f"reserved or unused frame-header bit set at offset {start + 4}")

    fcs_flag = descriptor >> 6
    single_segment = bool(descriptor & 0x20)
    checksum_present = bool(descriptor & 0x04)
    dictionary_flag = descriptor & 0x03
    pos = start + 5

    window_descriptor = None
    window_size = None
    if not single_segment:
        window_descriptor = _uint(data, pos, 1, "window descriptor")
        pos += 1
        exponent = window_descriptor >> 3
        mantissa = window_descriptor & 7
        window_base = 1 << (10 + exponent)
        window_size = window_base + (window_base >> 3) * mantissa

    dictionary_size = (0, 1, 2, 4)[dictionary_flag]
    dictionary_raw = _uint(data, pos, dictionary_size, "dictionary ID") if dictionary_size else None
    pos += dictionary_size

    fcs_size = ((1 if single_segment else 0), 2, 4, 8)[fcs_flag]
    frame_content_size = None
    if fcs_size:
        frame_content_size = _uint(data, pos, fcs_size, "frame content size")
        if fcs_size == 2:
            frame_content_size += 256
        pos += fcs_size
    if single_segment:
        # The grammar makes FCS mandatory for single-segment frames.
        if frame_content_size is None:
            _fail(f"single-segment frame at offset {start} has no content size")
        window_size = frame_content_size
    if window_size is None:
        _fail(f"frame at offset {start} has no determinable window size")

    header_end = pos
    block_maximum = min(window_size, 128 * 1024)
    blocks: list[dict] = []
    regenerated_size = 0
    regenerated_known = True
    while True:
        if len(blocks) >= block_budget:
            _fail(f"block count exceeds the {MAX_BLOCKS} block cap")
        header_offset = pos
        packed = _uint(data, pos, 3, "block header")
        pos += 3
        last = bool(packed & 1)
        block_type = (packed >> 1) & 3
        block_size = packed >> 3
        if block_type == 3:
            _fail(f"reserved block type at offset {header_offset}")
        if block_size > block_maximum:
            _fail(
                f"block at offset {header_offset} declares {block_size} bytes, "
                f"above frame maximum {block_maximum}"
            )
        encoded_size = 1 if block_type == 1 else block_size
        content_offset = pos
        content_end = _need(data, content_offset, encoded_size, "block content")
        content = data[content_offset:content_end]
        shown, clipped = _preview(content, preview_bytes)
        blocks.append({
            "index": len(blocks),
            "type": _BLOCK_NAMES[block_type],
            "type_id": block_type,
            "last": last,
            "header_offset": header_offset,
            "content_offset": content_offset,
            "end_offset": content_end,
            "declared_size": block_size,
            "encoded_size": encoded_size,
            "content_sha256": _digest(content),
            "content_preview_hex": shown,
            "content_preview_truncated": clipped,
        })
        if block_type in (0, 1):
            regenerated_size += block_size
        else:
            regenerated_known = False
        pos = content_end
        if last:
            break

    known_regenerated_size = regenerated_size if regenerated_known else None
    if frame_content_size is not None and regenerated_size > frame_content_size:
        _fail(
            f"known raw/RLE output in frame at offset {start} already exceeds "
            f"declared size {frame_content_size}"
        )
    if (known_regenerated_size is not None and frame_content_size is not None
            and known_regenerated_size != frame_content_size):
        _fail(
            f"raw/RLE blocks in frame at offset {start} regenerate {known_regenerated_size} bytes, "
            f"not declared size {frame_content_size}"
        )

    checksum = None
    if checksum_present:
        checksum_offset = pos
        checksum_value = _uint(data, pos, 4, "content checksum")
        pos += 4
        checksum = {
            "offset": checksum_offset,
            "value": checksum_value,
            "hex": f"0x{checksum_value:08x}",
            "validated": False,
            "validation_note": "requires decoded content; no decompression was performed",
        }

    record = {
        "kind": "zstd_frame",
        "offset": start,
        "end_offset": pos,
        "encoded_size": pos - start,
        "magic": f"0x{ZSTD_MAGIC:08x}",
        "header": {
            "offset": start + 4,
            "end_offset": header_end,
            "size": header_end - (start + 4),
            "descriptor": descriptor,
            "descriptor_hex": f"0x{descriptor:02x}",
            "single_segment": single_segment,
            "content_checksum_present": checksum_present,
            "dictionary_id_flag": dictionary_flag,
            "dictionary_id_field_size": dictionary_size,
            "dictionary_id_field_value": dictionary_raw,
            "dictionary_id": dictionary_raw if dictionary_raw else None,
            "frame_content_size_flag": fcs_flag,
            "frame_content_size_field_size": fcs_size,
            "frame_content_size": frame_content_size,
            "window_descriptor": window_descriptor,
            "window_size": window_size,
            "block_maximum_size": block_maximum,
        },
        "block_count": len(blocks),
        "blocks": blocks,
        "known_regenerated_size": known_regenerated_size,
        "content_checksum": checksum,
        "validation_scope": "frame/header/block boundaries only; compressed block bodies are opaque",
    }
    return record, pos


def _parse_seek_table(payload: bytes, payload_offset: int) -> dict:
    if len(payload) < 9:
        _fail(f"truncated seek-table footer at offset {payload_offset}")
    footer = len(payload) - 9
    number_of_frames = _uint(payload, footer, 4, "seek-table frame count")
    descriptor = _uint(payload, footer + 4, 1, "seek-table descriptor")
    footer_magic = _uint(payload, footer + 5, 4, "seekable footer magic")
    if footer_magic != SEEKABLE_FOOTER_MAGIC:
        _fail(f"bad seekable footer magic at offset {payload_offset + footer + 5}")
    if descriptor & 0x7C:
        _fail(f"reserved seek-table descriptor bits set at offset {payload_offset + footer + 4}")
    if number_of_frames > MAX_FRAMES:
        _fail(f"seek table exceeds the {MAX_FRAMES} frame cap")
    checksum_flag = bool(descriptor & 0x80)
    entry_size = 12 if checksum_flag else 8
    expected = number_of_frames * entry_size + 9
    if expected != len(payload):
        _fail(
            f"seek-table payload has {len(payload)} bytes but footer requires exactly {expected}"
        )

    entries = []
    compressed_offset = 0
    decompressed_offset = 0
    pos = 0
    for index in range(number_of_frames):
        compressed_size = _uint(payload, pos, 4, "seek-table compressed size")
        decompressed_size = _uint(payload, pos + 4, 4, "seek-table decompressed size")
        checksum = _uint(payload, pos + 8, 4, "seek-table checksum") if checksum_flag else None
        entry = {
            "index": index,
            "compressed_offset": compressed_offset,
            "decompressed_offset": decompressed_offset,
            "compressed_size": compressed_size,
            "decompressed_size": decompressed_size,
            "checksum": checksum,
            "checksum_hex": f"0x{checksum:08x}" if checksum is not None else None,
        }
        entries.append(entry)
        compressed_offset += compressed_size
        decompressed_offset += decompressed_size
        pos += entry_size

    return {
        "number_of_frames": number_of_frames,
        "descriptor": descriptor,
        "descriptor_hex": f"0x{descriptor:02x}",
        "checksum_flag": checksum_flag,
        "unused_descriptor_bits": descriptor & 0x03,
        "entry_size": entry_size,
        "entries": entries,
        "total_compressed_size": compressed_offset,
        "total_decompressed_size": decompressed_offset,
        "footer_offset": payload_offset + footer,
        "footer_magic": f"0x{SEEKABLE_FOOTER_MAGIC:08x}",
        "validated_against_stream": False,
    }


def _parse_skippable(data: bytes, start: int, magic: int, preview_bytes: int) -> tuple[dict, int]:
    payload_size = _uint(data, start + 4, 4, "skippable frame size")
    payload_offset = start + 8
    end = _need(data, payload_offset, payload_size, "skippable frame payload")
    payload = data[payload_offset:end]
    shown, clipped = _preview(payload, preview_bytes)
    record = {
        "kind": "skippable_frame",
        "offset": start,
        "end_offset": end,
        "encoded_size": end - start,
        "magic": f"0x{magic:08x}",
        "skippable_id": magic & 0x0F,
        "payload_offset": payload_offset,
        "payload_size": payload_size,
        "payload_sha256": _digest(payload),
        "payload_preview_hex": shown,
        "payload_preview_truncated": clipped,
        "seek_table": None,
    }
    # Magic 0xE is not sufficient on its own: it remains ordinary metadata
    # unless the distinctive footer magic is at the declared payload's end.
    if magic == SEEK_TABLE_MAGIC and payload.endswith(SEEKABLE_FOOTER_MAGIC_BYTES):
        record["kind"] = "seek_table"
        record["seek_table"] = _parse_seek_table(payload, payload_offset)
    return record, end


def _validate_seek_mapping(frames: list[dict]) -> dict | None:
    table_indexes = [index for index, frame in enumerate(frames) if frame["kind"] == "seek_table"]
    if not table_indexes:
        return None
    if len(table_indexes) != 1 or table_indexes[0] != len(frames) - 1:
        _fail("a recognized seek table must be the one final frame in the input")
    table_index = table_indexes[0]
    preceding = frames[:table_index]
    table = frames[table_index]["seek_table"]
    if table is None:
        _fail("internal seek-table classification failure")
    entries = table["entries"]
    if table["number_of_frames"] != len(preceding):
        _fail(
            f"seek table lists {table['number_of_frames']} frames but {len(preceding)} precede it"
        )

    for entry, frame in zip(entries, preceding):
        if entry["compressed_offset"] != frame["offset"]:
            _fail(f"seek entry {entry['index']} has the wrong cumulative compressed offset")
        if entry["compressed_size"] != frame["encoded_size"]:
            _fail(
                f"seek entry {entry['index']} declares compressed size {entry['compressed_size']}, "
                f"not frame size {frame['encoded_size']}"
            )
        if frame["kind"] == "skippable_frame":
            if entry["decompressed_size"] != 0:
                _fail(f"seek entry {entry['index']} gives a skippable frame nonzero output size")
        elif frame["kind"] == "zstd_frame":
            declared = frame["header"]["frame_content_size"]
            known = frame["known_regenerated_size"]
            if declared is not None and entry["decompressed_size"] != declared:
                _fail(
                    f"seek entry {entry['index']} decompressed size does not match frame content size"
                )
            if known is not None and entry["decompressed_size"] != known:
                _fail(
                    f"seek entry {entry['index']} decompressed size does not match raw/RLE blocks"
                )
        else:
            _fail(f"seek entry {entry['index']} maps an unsupported frame kind")
        entry["frame_kind"] = frame["kind"]
        entry["frame_offset"] = frame["offset"]

    if table["total_compressed_size"] != frames[table_index]["offset"]:
        _fail("seek-table compressed-size sum does not reach the table frame")
    table["validated_against_stream"] = True
    return {
        "table_frame_index": table_index,
        "table_offset": frames[table_index]["offset"],
        "number_of_frames": table["number_of_frames"],
        "checksum_flag": table["checksum_flag"],
        "total_compressed_size": table["total_compressed_size"],
        "total_decompressed_size": table["total_decompressed_size"],
        "validated": True,
    }


def _inspect_stream(data: bytes, preview_bytes: int) -> dict:
    frames: list[dict] = []
    offset = 0
    total_blocks = 0
    while offset < len(data):
        if len(frames) >= MAX_FRAMES:
            _fail(f"frame count exceeds the {MAX_FRAMES} frame cap")
        if len(data) - offset < 4:
            _fail(f"truncated frame magic at offset {offset}")
        magic = _uint(data, offset, 4, "frame magic")
        if magic == ZSTD_MAGIC:
            record, end = _parse_ordinary(data, offset, preview_bytes, MAX_BLOCKS - total_blocks)
            total_blocks += record["block_count"]
        elif SKIPPABLE_MAGIC_MIN <= magic <= SKIPPABLE_MAGIC_MAX:
            record, end = _parse_skippable(data, offset, magic, preview_bytes)
        else:
            _fail(f"unknown trailing bytes or frame magic 0x{magic:08x} at offset {offset}")
        if end <= offset:
            _fail(f"frame at offset {offset} made no progress")
        record["index"] = len(frames)
        frames.append(record)
        offset = end

    seekable = _validate_seek_mapping(frames)
    ordinary_count = sum(frame["kind"] == "zstd_frame" for frame in frames)
    skippable_count = sum(frame["kind"] in {"skippable_frame", "seek_table"} for frame in frames)
    return {
        "format": "zstd_stream",
        "size": len(data),
        "sha256": _digest(data),
        "validation_scope": "complete framing and boundaries; no decompression or checksum verification",
        "frame_count": len(frames),
        "ordinary_frame_count": ordinary_count,
        "skippable_frame_count": skippable_count,
        "block_count": total_blocks,
        "frames": frames,
        "seekable": seekable,
    }


def inspect_zstd(data: object, *, preview_bytes: int = 32) -> dict:
    """Inspect one complete Zstandard stream or formatted dictionary.

    Every malformed, unsupported, wrong-type, over-limit, or internal parsing
    failure is exposed only as :class:`ResearchFFZstdError`.
    """

    try:
        preview = _checked_preview(preview_bytes)
        raw = _coerce(data)
        if raw.startswith(DICTIONARY_MAGIC_BYTES):
            return _parse_dictionary(raw, preview)
        return _inspect_stream(raw, preview)
    except ResearchFFZstdError:
        raise
    except Exception:
        raise ResearchFFZstdError("Zstandard inspection failed safely") from None


def inspect_path(path: object, *, preview_bytes: int = 32) -> dict:
    """Read and inspect one path under the same declared-exception contract."""

    try:
        preview = _checked_preview(preview_bytes)
        source = Path(path)  # type: ignore[arg-type]
        with source.open("rb") as handle:
            data = handle.read(MAX_INPUT + 1)
        if len(data) > MAX_INPUT:
            _fail(f"input exceeds the {MAX_INPUT} byte cap")
        return inspect_zstd(data, preview_bytes=preview)
    except ResearchFFZstdError:
        raise
    except Exception:
        raise ResearchFFZstdError("input path could not be read safely") from None


def _preview_argument(value: str) -> int:
    try:
        number = int(value, 10)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError("preview length must be a decimal integer") from None
    if not 0 <= number <= MAX_PREVIEW:
        raise argparse.ArgumentTypeError(f"preview length must be in 0..{MAX_PREVIEW}")
    return number


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Statically inspect Zstandard frames, skippable metadata, seek tables, or a dictionary"
    )
    parser.add_argument("file", help="Zstandard stream or formatted dictionary")
    parser.add_argument("--preview-bytes", type=_preview_argument, default=32,
                        help=f"payload preview length (0..{MAX_PREVIEW}; default: 32)")
    parser.add_argument("--pretty", action="store_true", help="indent the JSON report")
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        report = inspect_path(args.file, preview_bytes=args.preview_bytes)
        print(json.dumps(
            report,
            indent=2 if args.pretty else None,
            separators=None if args.pretty else (",", ":"),
            sort_keys=True,
        ))
        return 0
    except ResearchFFZstdError as exc:
        print(f"research_ff_zstd: {exc}", file=sys.stderr)
        return 1
    except Exception:
        print("research_ff_zstd: report rendering failed safely", file=sys.stderr)
        return 1


__all__ = ["ResearchFFZstdError", "inspect_path", "inspect_zstd", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
