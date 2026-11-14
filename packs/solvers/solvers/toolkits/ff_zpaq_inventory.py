#!/usr/bin/env python3
"""Bounded static ZPAQ level 1/2 block and segment inventory.

No arithmetic decoding, extraction, or ZPAQL execution occurs. Structural
acceptance does not validate compressed data, programs, or stored SHA-1 values.
Bare streams start at offset zero; embedded streams require the standard locator
tag. Subsequent adjacent blocks may omit the tag. Malformed located streams raise
ZpaqError; unrelated bytes outside located streams are reported as unparsed.

Sources: https://mattmahoney.net/dc/zpaq206.pdf (sections 2, 4, 7, 8),
https://mattmahoney.net/dc/unzpaq206.cpp, and libzpaq.cpp Decoder::skip().
The spec section 2 says little endian for unmodeled chunk sizes, but section 4
and both reference implementations use BIG endian. This reader follows the code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys


MAGIC = b"zPQ"
LOCATOR = bytes.fromhex("376b5374a03183d38cb228b0d3")
MAX_INPUT = 64 << 20
MAX_BLOCKS = 4096
MAX_SEGMENTS = 4096
MAX_COMPONENTS = 65536
MAX_CHUNKS = 65536
MAX_STRING = 65535
MAX_METADATA = 1 << 20
_COMPONENTS = {
    1: ("CONST", 2), 2: ("CM", 3), 3: ("ICM", 2),
    4: ("MATCH", 3), 5: ("AVG", 4), 6: ("MIX2", 6),
    7: ("MIX", 6), 8: ("ISSE", 3), 9: ("SSE", 5),
}


class ZpaqError(ValueError):
    """Invalid, unsupported, truncated, or over-budget ZPAQ structure."""


def _need(data: bytes, pos: int, size: int, label: str) -> None:
    if size > len(data) - pos:
        raise ZpaqError(f"truncated {label} at offset {pos}")


def _sha256(data: bytes, start: int, end: int) -> str:
    return hashlib.sha256(memoryview(data)[start:end]).hexdigest()


def _cstring(data: bytes, pos: int, label: str) -> tuple[bytes, int]:
    end = data.find(b"\0", pos, pos + MAX_STRING + 1)
    if end < 0:
        raise ZpaqError(f"unterminated or oversized {label} at offset {pos}")
    return data[pos:end], end + 1


def _header(data: bytes, pos: int) -> tuple[dict, int]:
    _need(data, pos, 7, "block header")
    level, language = data[pos + 3:pos + 5]
    if level not in (1, 2) or language != 1:
        raise ZpaqError(f"unsupported level or HPROG at offset {pos}")
    hsize = int.from_bytes(data[pos + 5:pos + 7], "little")
    start = pos + 7
    _need(data, start, hsize, "model header")
    if hsize < 7:
        raise ZpaqError("model header is shorter than hh/hm/ph/pm/n and ENDs")
    end = start + hsize
    hh, hm, ph, pm, n = data[start:start + 5]
    if level == 1 and n == 0:
        raise ZpaqError("level 1 requires a model component")
    cursor = start + 5
    components = []
    for index in range(n):
        if cursor >= end - 2:
            raise ZpaqError("components overflow model header")
        kind = data[cursor]
        if kind not in _COMPONENTS:
            raise ZpaqError(f"unknown component type {kind}")
        name, size = _COMPONENTS[kind]
        if cursor + size > end - 2:
            raise ZpaqError("truncated component")
        params = list(data[cursor + 1:cursor + size])
        if kind in (2, 3, 4, 6, 7, 8, 9):
            if params[0] > (26 if kind in (3, 8) else 32):
                raise ZpaqError("component sizebits exceeds format limit")
        if kind == 4 and params[1] > 32:
            raise ZpaqError("MATCH bufbits exceeds format limit")
        refs = (params[:2] if kind == 5 else params[1:3] if kind == 6
                else params[1:2] if kind in (7, 8, 9) else [])
        if any(ref >= index for ref in refs):
            raise ZpaqError("component must refer to an earlier component")
        if kind == 7 and not 1 <= params[2] <= index - params[1]:
            raise ZpaqError("MIX component range is invalid")
        components.append({"index": index, "offset": cursor, "type": kind,
                           "name": name, "parameters": params})
        cursor += size
    if data[cursor] != 0 or data[end - 1] != 0:
        raise ZpaqError("missing COMP or HCOMP END")
    program_start = cursor + 1
    return {"level": level, "hprog": language, "header_offset": start,
            "header_size": hsize, "hh": hh, "hm": hm, "ph": ph, "pm": pm,
            "component_count": n, "components": components,
            "hcomp_offset": program_start, "hcomp_size": end - 1 - program_start,
            "hcomp_sha256": _sha256(data, program_start, end - 1)}, end


def _skip_data(data: bytes, pos: int, modeled: bool, budget: dict) -> tuple[int, dict]:
    start = pos
    if modeled:
        # A coded stream contains no run of four zero bytes before its ending.
        # libzpaq also skips extra ending zeros (encoder can emit 4..7 in total).
        marker = data.find(b"\0\0\0\0", pos)
        if marker < 0:
            raise ZpaqError(f"missing modeled data terminator at offset {pos}")
        pos = marker + 4
        while pos < len(data) and data[pos] == 0:
            pos += 1
            if pos - marker > 7:
                raise ZpaqError("oversized modeled data terminator")
        extra = {"framing": "modeled-zero-terminator",
                 "terminator_offset": marker, "terminator_size": pos - marker}
    else:
        chunks = payload_size = 0
        while True:
            _need(data, pos, 4, "unmodeled chunk size")
            size = int.from_bytes(data[pos:pos + 4], "big")
            pos += 4
            if size == 0:
                break
            budget["chunks"] += 1
            if budget["chunks"] > MAX_CHUNKS:
                raise ZpaqError("chunk count exceeds cap")
            _need(data, pos, size, "unmodeled chunk")
            pos += size
            payload_size += size
            chunks += 1
        extra = {"framing": "unmodeled-big-endian-chunks", "chunk_count": chunks,
                 "framed_payload_size": payload_size,
                 "terminator_offset": pos - 4, "terminator_size": 4}
    extra.update(encoded_offset=start, encoded_size=pos - start,
                 encoded_sha256=_sha256(data, start, pos))
    return pos, extra


def _comment_size(comment: bytes) -> int | None:
    # Conventional decimal size prefix, not an independently verified file size.
    match = re.match(rb"([0-9]{1,20})(?: |$)", comment)
    if match is None:
        return None
    value = int(match[1])
    return value if value <= 0xFFFFFFFFFFFFFFFF else None


def inspect_zpaq(data: bytes) -> dict:
    """Inventory bounded bytes or raise ONLY ZpaqError for invalid input.

    Offsets are absolute and end_offset is exclusive. SHA-256 values hash stored
    bytes; declared_sha1 hashes decompressed bytes and is never verified here.
    A comment size is an untrusted declaration, never measured decoded output.
    """
    if not isinstance(data, bytes) or len(data) > MAX_INPUT:
        raise ZpaqError("input must be bytes within the 64 MiB cap")
    blocks, gaps = [], []
    pos = 0
    budget = {"segments": 0, "components": 0, "chunks": 0, "metadata": 0}
    previous_file = None
    while pos < len(data):
        locator_offset = None
        if not data.startswith(MAGIC, pos):
            locator_offset = data.find(LOCATOR + MAGIC, pos)
            if locator_offset < 0:
                gaps.append({"offset": pos, "end_offset": len(data)})
                break
            if locator_offset > pos:
                gaps.append({"offset": pos, "end_offset": locator_offset})
                previous_file = None
            pos = locator_offset + len(LOCATOR)
        if len(blocks) >= MAX_BLOCKS:
            raise ZpaqError("block count exceeds cap")
        block_start = pos
        header, pos = _header(data, pos)
        budget["components"] += header["component_count"]
        if budget["components"] > MAX_COMPONENTS:
            raise ZpaqError("total component count exceeds cap")
        segments = []
        while True:
            _need(data, pos, 1, "segment or block end")
            if data[pos] == 255:
                pos += 1
                break
            if data[pos] != 1:
                raise ZpaqError(f"missing segment marker at offset {pos}")
            budget["segments"] += 1
            if budget["segments"] > MAX_SEGMENTS:
                raise ZpaqError("segment count exceeds cap")
            segment_start = pos
            filename, pos = _cstring(data, pos + 1, "filename")
            comment, pos = _cstring(data, pos, "comment")
            budget["metadata"] += len(filename) + len(comment)
            if budget["metadata"] > MAX_METADATA:
                raise ZpaqError("total metadata exceeds cap")
            _need(data, pos, 1, "reserved byte")
            if data[pos] != 0:
                raise ZpaqError(f"nonzero reserved byte at offset {pos}")
            pos, framing = _skip_data(data, pos + 1, header["component_count"] > 0, budget)
            _need(data, pos, 1, "segment trailer")
            trailer = pos
            marker = data[pos]
            pos += 1
            declared_sha1 = None
            if marker == 253:
                _need(data, pos, 20, "SHA-1 trailer")
                declared_sha1 = data[pos:pos + 20].hex()
                pos += 20
            elif marker != 254:
                raise ZpaqError(f"invalid segment trailer at offset {trailer}")
            index = budget["segments"] - 1
            continuation = previous_file if not filename else None
            if filename:
                previous_file = index
            segment = {"index": index, "offset": segment_start, "end_offset": pos,
                       "filename": filename.decode("utf-8", "replace"),
                       "filename_hex": filename.hex(),
                       "comment": comment.decode("utf-8", "replace"),
                       "comment_hex": comment.hex(), "continuation_of": continuation,
                       "declared_size": _comment_size(comment), "size_verified": False,
                       "journaling_marker": comment.endswith(b"jDC\x01"),
                       "trailer_offset": trailer, "declared_sha1": declared_sha1,
                       "sha1_verified": False, **framing}
            segments.append(segment)
        blocks.append({"offset": block_start, "end_offset": pos,
                       "locator_offset": locator_offset, **header, "segments": segments,
                       "stored_sha256": _sha256(data, block_start, pos)})
    if not blocks:
        raise ZpaqError("no ZPAQ stream at offset zero or after a locator tag")
    return {"kind": "zpaq_inventory", "input_size": len(data),
            "input_sha256": _sha256(data, 0, len(data)), "blocks": blocks,
            "block_count": len(blocks), "segment_count": budget["segments"],
            "unparsed_ranges": gaps, "payload_verified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file", help="ZPAQ archive or tagged embedded stream")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(args.file, "rb") as stream:
            data = stream.read(MAX_INPUT + 1)
        print(json.dumps(inspect_zpaq(data), indent=2))
    except (ZpaqError, OSError, ValueError) as exc:
        print(f"ff_zpaq_inventory: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
