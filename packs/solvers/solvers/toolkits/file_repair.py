#!/usr/bin/env python3
"""Decode-validated repair and salvage for common CTF file containers.

The engine is deliberately conservative: a candidate is returned only after a second
parse/decompression proves the rebuilt bytes.  It never executes artifacts, invokes a
subprocess, mounts a filesystem, or uses the network.

Supported repairs:

* PNG: restore the signature, recompute chunk CRCs, move the sole IHDR first, and add
  a missing/truncated IEND.  The IDAT zlib stream and every normal or Adam7-interlaced
  scanline are validated before and after repair.
* ZIP: rebuild a central directory and EOCD from intact, CRC-verified local members,
  including deflated members whose sizes/CRC live in a data descriptor.
* PDF: rebuild a classic xref/trailer for structurally complete indirect objects with
  a validated Catalog/Pages root.  Direct and resolved indirect stream lengths are
  boundary-checked and Flate streams are decoded.
* gzip: reconstruct a missing/corrupt trailer when the raw DEFLATE stream reaches EOF.
* bzip2: strip a corrupt tail or salvage a prefix of complete concatenated streams.

All input, output, object counts, dimensions, and decompression are bounded.
"""
from __future__ import annotations

import argparse
import binascii
import bz2
import dataclasses
import gzip
import hashlib
import io
import json
import re
import struct
import sys
import zipfile
import zlib
from pathlib import Path
from typing import Any

MAX_INPUT = 64 * 1024 * 1024
MAX_OUTPUT = 128 * 1024 * 1024
MAX_CHUNKS = 10_000
MAX_OBJECTS = 100_000
MAX_ENTRIES = 65_535

PNG_SIG = b"\x89PNG\r\n\x1a\n"
PNG_IEND = b"\x00\x00\x00\x00IEND\xaeB`\x82"


class RepairError(ValueError):
    """The artifact is unsupported or cannot be repaired without guessing."""


@dataclasses.dataclass(frozen=True)
class RepairResult:
    format: str
    status: str
    diagnostics: tuple[str, ...]
    candidate: bytes | None = None
    recovered_items: int = 0

    def report(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "format": self.format,
            "status": self.status,
            "diagnostics": list(self.diagnostics),
            "recovered_items": self.recovered_items,
            "candidate_size": len(self.candidate) if self.candidate is not None else None,
            "candidate_sha256": hashlib.sha256(self.candidate).hexdigest()
            if self.candidate is not None else None,
        }
        return out


def _inflate(data: bytes, *, wbits: int, expected: int | None = None) -> bytes:
    """Bounded zlib/DEFLATE decode that requires a single complete stream."""
    decoder = zlib.decompressobj(wbits)
    limit = min(MAX_OUTPUT, expected if expected is not None else MAX_OUTPUT)
    out = decoder.decompress(data, limit + 1)
    if len(out) > limit or decoder.unconsumed_tail:
        raise RepairError("decompressed data exceeds its bound")
    tail = decoder.flush(limit + 1 - len(out))
    out += tail
    if len(out) > limit:
        raise RepairError("decompressed data exceeds its bound")
    if not decoder.eof or decoder.unused_data:
        raise RepairError("compressed stream is incomplete or has trailing data")
    if expected is not None and len(out) != expected:
        raise RepairError("decompressed size does not match the header")
    return out


# --------------------------------------------------------------------------- PNG


@dataclasses.dataclass(frozen=True)
class _PngChunk:
    kind: bytes
    payload: bytes
    stored_crc: int


def _parse_png_chunks(data: bytes) -> tuple[list[_PngChunk], bytes]:
    if len(data) < 8:
        raise RepairError("PNG is shorter than its signature")
    pos = 8
    chunks: list[_PngChunk] = []
    while pos + 12 <= len(data) and len(chunks) < MAX_CHUNKS:
        length = struct.unpack_from(">I", data, pos)[0]
        if length > MAX_INPUT or pos + 12 + length > len(data):
            break
        kind = data[pos + 4:pos + 8]
        if not re.fullmatch(rb"[A-Za-z]{4}", kind) or not (65 <= kind[2] <= 90):
            break
        payload = data[pos + 8:pos + 8 + length]
        stored = struct.unpack_from(">I", data, pos + 8 + length)[0]
        chunks.append(_PngChunk(kind, payload, stored))
        pos += 12 + length
        if kind == b"IEND":
            break
    if len(chunks) >= MAX_CHUNKS:
        raise RepairError("PNG chunk-count cap reached")
    return chunks, data[pos:]


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    crc = binascii.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def _validate_png_bytes(data: bytes) -> dict[str, int]:
    if not data.startswith(PNG_SIG):
        raise RepairError("invalid PNG signature")
    chunks, remainder = _parse_png_chunks(data)
    if remainder:
        raise RepairError("trailing or truncated PNG bytes")
    if not chunks or chunks[0].kind != b"IHDR":
        raise RepairError("IHDR is not the first chunk")
    if chunks[-1].kind != b"IEND" or chunks[-1].payload:
        raise RepairError("IEND is missing or malformed")
    if sum(c.kind == b"IHDR" for c in chunks) != 1 or sum(c.kind == b"IEND" for c in chunks) != 1:
        raise RepairError("PNG must contain exactly one IHDR and IEND")
    for chunk in chunks:
        expected_crc = binascii.crc32(chunk.kind + chunk.payload) & 0xFFFFFFFF
        if chunk.stored_crc != expected_crc:
            raise RepairError(f"CRC mismatch in {chunk.kind.decode('ascii')}")
        if not (chunk.kind[0] & 0x20) and chunk.kind not in {b"IHDR", b"PLTE", b"IDAT", b"IEND"}:
            raise RepairError("unknown critical PNG chunk")
    ihdr = chunks[0].payload
    if len(ihdr) != 13:
        raise RepairError("IHDR length is not 13")
    width, height, depth, color, compression, filter_method, interlace = struct.unpack(">IIBBBBB", ihdr)
    if not width or not height or width > 1_000_000 or height > 1_000_000:
        raise RepairError("PNG dimensions outside the supported bound")
    valid_depths = {0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8},
                    4: {8, 16}, 6: {8, 16}}
    if color not in valid_depths or depth not in valid_depths[color]:
        raise RepairError("invalid PNG color type/bit depth")
    if compression != 0 or filter_method != 0 or interlace not in (0, 1):
        raise RepairError("unsupported PNG compression/filter/interlace method")
    kinds = [c.kind for c in chunks]
    idat_positions = [i for i, kind in enumerate(kinds) if kind == b"IDAT"]
    if not idat_positions or idat_positions != list(range(min(idat_positions), max(idat_positions) + 1)):
        raise RepairError("IDAT chunks are absent or non-consecutive")
    pltes = [c for c in chunks if c.kind == b"PLTE"]
    if len(pltes) > 1 or (pltes and kinds.index(b"PLTE") > min(idat_positions)):
        raise RepairError("PLTE count/order is invalid")
    if color == 3:
        if not pltes or len(pltes[0].payload) % 3 or not 1 <= len(pltes[0].payload) // 3 <= 2 ** depth:
            raise RepairError("indexed PNG has an invalid palette")
    elif color in {0, 4} and pltes:
        raise RepairError("grayscale PNG must not contain PLTE")
    samples = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color]
    if interlace == 0:
        passes = [(width, height)]
    else:
        adam7 = ((0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
                 (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2))
        passes = [(0 if width <= x0 else (width - x0 + dx - 1) // dx,
                   0 if height <= y0 else (height - y0 + dy - 1) // dy)
                  for x0, y0, dx, dy in adam7]
    pass_rows = [((pw * samples * depth + 7) // 8, ph) for pw, ph in passes if pw and ph]
    expected = sum(ph * (row_bytes + 1) for row_bytes, ph in pass_rows)
    if expected > MAX_OUTPUT:
        raise RepairError("inflated PNG pixels exceed the output bound")
    compressed = b"".join(c.payload for c in chunks if c.kind == b"IDAT")
    raw = _inflate(compressed, wbits=zlib.MAX_WBITS, expected=expected)
    at = 0
    for row_bytes, rows in pass_rows:
        stride = row_bytes + 1
        if any(raw[at + row * stride] > 4 for row in range(rows)):
            raise RepairError("PNG contains an invalid scanline filter")
        at += rows * stride
    if at != len(raw):
        raise RepairError("PNG scanline layout does not consume the inflated data")
    return {"width": width, "height": height, "chunks": len(chunks), "interlace": interlace}


def repair_png(data: bytes) -> RepairResult:
    """Return a fully validated PNG repair, or diagnostics without a candidate."""
    try:
        info = _validate_png_bytes(data)
        return RepairResult("png", "valid", (f"validated {info['width']}x{info['height']} PNG",))
    except (RepairError, struct.error, zlib.error) as original_error:
        diagnostics = [str(original_error)]
    try:
        chunks, remainder = _parse_png_chunks(data)
        if not chunks:
            raise RepairError("no complete PNG chunks found at offset 8")
        ihdrs = [c for c in chunks if c.kind == b"IHDR"]
        if len(ihdrs) != 1:
            raise RepairError("repair requires exactly one complete IHDR")
        # A partial canonical IEND is safe to replace; arbitrary tails are not.
        if remainder and not PNG_IEND.startswith(remainder):
            raise RepairError("ambiguous bytes follow the last complete chunk")
        ordered = [ihdrs[0]] + [c for c in chunks if c is not ihdrs[0] and c.kind != b"IEND"]
        ordered.append(_PngChunk(b"IEND", b"", binascii.crc32(b"IEND") & 0xFFFFFFFF))
        candidate = PNG_SIG + b"".join(_png_chunk(c.kind, c.payload) for c in ordered)
        info = _validate_png_bytes(candidate)
        changes = []
        if data[:8] != PNG_SIG:
            changes.append("restored signature")
        if chunks[0].kind != b"IHDR":
            changes.append("moved IHDR first")
        if not chunks or chunks[-1].kind != b"IEND" or remainder:
            changes.append("restored IEND")
        if any(c.stored_crc != (binascii.crc32(c.kind + c.payload) & 0xFFFFFFFF) for c in chunks):
            changes.append("recomputed chunk CRCs")
        if candidate == data:
            raise RepairError("no deterministic PNG repair was identified")
        diagnostics.extend(changes or ["canonicalized PNG chunks"])
        diagnostics.append(f"post-repair decode validated {info['width']}x{info['height']} pixels")
        return RepairResult("png", "repaired", tuple(diagnostics), candidate, 1)
    except (RepairError, struct.error, zlib.error) as exc:
        diagnostics.append(str(exc))
        return RepairResult("png", "unrecoverable", tuple(dict.fromkeys(diagnostics)))


# --------------------------------------------------------------------------- ZIP


@dataclasses.dataclass(frozen=True)
class _ZipEntry:
    offset: int
    version: int
    flags: int
    method: int
    mtime: int
    mdate: int
    crc: int
    compressed_size: int
    size: int
    name: bytes
    extra: bytes
    end: int


def _zip_local_entries(data: bytes) -> tuple[list[_ZipEntry], int, str]:
    if not data.startswith(b"PK\x03\x04"):
        raise RepairError("ZIP does not begin with a local file header")
    entries: list[_ZipEntry] = []
    pos = 0
    total = 0
    reason = "end of local members"
    while pos + 4 <= len(data) and data[pos:pos + 4] == b"PK\x03\x04":
        if len(entries) >= MAX_ENTRIES:
            raise RepairError("ZIP entry-count cap reached")
        if pos + 30 > len(data):
            reason = "truncated local header"
            break
        fields = struct.unpack_from("<I5H3I2H", data, pos)
        _, version, flags, method, mtime, mdate, crc, csize, usize, nlen, xlen = fields
        if flags & 1:
            raise RepairError("encrypted ZIP members are not repaired")
        if method not in {0, 8}:
            raise RepairError(f"ZIP compression method {method} is unsupported")
        header_end = pos + 30 + nlen + xlen
        if header_end > len(data):
            reason = "truncated ZIP member"
            break
        if usize > MAX_OUTPUT or total + usize > MAX_OUTPUT:
            raise RepairError("ZIP uncompressed data exceeds the output bound")
        name = data[pos + 30:pos + 30 + nlen]
        extra = data[pos + 30 + nlen:header_end]
        if not name or b"\x00" in name:
            raise RepairError("ZIP member has an invalid name")
        try:
            name.decode("utf-8" if flags & 0x800 else "cp437")
        except UnicodeDecodeError as exc:
            raise RepairError("ZIP member name cannot be decoded") from exc
        if flags & 8:
            # Stored members have no self-delimiting stream, so locating a descriptor would be a
            # guess.  Raw DEFLATE has an exact EOF bit and zlib tells us where its unused tail begins.
            if method != 8:
                raise RepairError("stored ZIP data descriptors are ambiguous")
            decoder = zlib.decompressobj(-15)
            try:
                decoded = decoder.decompress(data[header_end:], MAX_OUTPUT - total + 1)
                decoded += decoder.flush(MAX_OUTPUT - total + 1 - len(decoded))
            except zlib.error as exc:
                reason = f"member {name!r} failed descriptor-stream decompression: {exc}"
                break
            if len(decoded) + total > MAX_OUTPUT:
                raise RepairError("ZIP uncompressed data exceeds the output bound")
            if not decoder.eof or decoder.unconsumed_tail:
                reason = f"member {name!r} has a truncated descriptor-stream"
                break
            compressed_size = len(data[header_end:]) - len(decoder.unused_data)
            member_end = header_end + compressed_size
            descriptor = member_end
            if data[descriptor:descriptor + 4] == b"PK\x07\x08":
                descriptor += 4
            if descriptor + 12 > len(data):
                reason = f"member {name!r} has a truncated data descriptor"
                break
            crc, csize, usize = struct.unpack_from("<III", data, descriptor)
            descriptor_end = descriptor + 12
            if csize != compressed_size:
                reason = f"member {name!r} descriptor compressed size mismatch"
                break
            entry_end = descriptor_end
        else:
            member_end = header_end + csize
            if member_end > len(data):
                reason = "truncated ZIP member"
                break
            compressed = data[header_end:member_end]
            try:
                decoded = compressed if method == 0 else _inflate(compressed, wbits=-15, expected=usize)
            except (RepairError, zlib.error) as exc:
                reason = f"member {name!r} failed decompression: {exc}"
                break
            entry_end = member_end
        if len(decoded) != usize or (binascii.crc32(decoded) & 0xFFFFFFFF) != crc:
            reason = f"member {name!r} failed size/CRC validation"
            break
        entries.append(_ZipEntry(pos, version, flags, method, mtime, mdate, crc,
                                 csize, usize, name, extra, entry_end))
        total += usize
        pos = entry_end
    return entries, pos, reason


def _build_zip(data: bytes, entries: list[_ZipEntry], local_end: int) -> bytes:
    central = bytearray()
    for entry in entries:
        central += struct.pack(
            "<I6H3I5H2I", 0x02014B50, 20, entry.version, entry.flags, entry.method,
            entry.mtime, entry.mdate, entry.crc, entry.compressed_size, entry.size,
            len(entry.name), len(entry.extra), 0, 0, 0, 0, entry.offset,
        )
        central += entry.name + entry.extra
    eocd = struct.pack("<I4H2IH", 0x06054B50, 0, 0, len(entries), len(entries),
                       len(central), local_end, 0)
    return data[:local_end] + bytes(central) + eocd


def _validate_zip_candidate(data: bytes, expected_entries: int | None = None) -> int:
    if len(data) > MAX_INPUT + MAX_OUTPUT:
        raise RepairError("rebuilt ZIP exceeds the size bound")
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            infos = archive.infolist()
            if expected_entries is not None and len(infos) != expected_entries:
                raise RepairError("rebuilt ZIP entry count changed")
            if len(infos) > MAX_ENTRIES:
                raise RepairError("rebuilt ZIP entry-count cap reached")
            for info in infos:
                if info.flag_bits & 1 or info.file_size > MAX_OUTPUT or total + info.file_size > MAX_OUTPUT:
                    raise RepairError("rebuilt ZIP member exceeds safety constraints")
                payload = archive.read(info)
                total += len(payload)
                if len(payload) != info.file_size or (binascii.crc32(payload) & 0xFFFFFFFF) != info.CRC:
                    raise RepairError("rebuilt ZIP member failed CRC validation")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error) as exc:
        raise RepairError(f"rebuilt ZIP did not validate: {exc}") from exc
    return len(infos)


def repair_zip(data: bytes) -> RepairResult:
    try:
        count = _validate_zip_candidate(data)
        return RepairResult("zip", "valid", (f"validated {count} ZIP members",), recovered_items=count)
    except RepairError as original_error:
        diagnostics = [str(original_error)]
    try:
        entries, local_end, stop_reason = _zip_local_entries(data)
        if not entries:
            raise RepairError("no complete CRC-verified ZIP members can be salvaged")
        candidate = _build_zip(data, entries, local_end)
        count = _validate_zip_candidate(candidate, len(entries))
        diagnostics.append(stop_reason)
        diagnostics.append(f"rebuilt central directory for {count} verified members")
        if local_end < len(data) and data[local_end:local_end + 4] == b"PK\x03\x04":
            diagnostics.append("omitted an incomplete trailing member")
        return RepairResult("zip", "repaired", tuple(diagnostics), candidate, count)
    except (RepairError, struct.error) as exc:
        diagnostics.append(str(exc))
        return RepairResult("zip", "unrecoverable", tuple(dict.fromkeys(diagnostics)))


# --------------------------------------------------------------------------- PDF


@dataclasses.dataclass(frozen=True)
class _PdfObject:
    number: int
    generation: int
    offset: int
    end: int
    body: bytes


_OBJ_HEADER = re.compile(rb"(?m)(?<![0-9])([1-9][0-9]{0,6})[ \t]+([0-9]{1,5})[ \t]+obj\b")


def _pdf_stream_length(prefix: bytes, indirect_lengths: dict[tuple[int, int], int] | None = None) -> int:
    length_match = re.search(rb"/Length\s+([0-9]{1,10})(?!\s+[0-9]+\s+R)", prefix)
    if length_match is not None:
        return int(length_match.group(1))
    reference = re.search(rb"/Length\s+([0-9]{1,7})\s+([0-9]{1,5})\s+R", prefix)
    if reference is None or indirect_lengths is None:
        raise RepairError("PDF stream has no resolvable bounded /Length")
    key = (int(reference.group(1)), int(reference.group(2)))
    if key not in indirect_lengths:
        raise RepairError("PDF indirect /Length object is missing or not a plain integer")
    return indirect_lengths[key]


def _decode_pdf_stream(prefix: bytes, data: bytes, indirect_lengths: dict[tuple[int, int], int] | None = None) -> None:
    expected = _pdf_stream_length(prefix, indirect_lengths)
    if expected > MAX_INPUT or len(data) != expected:
        raise RepairError("PDF stream length does not match /Length")
    filters = re.findall(rb"/Filter\s*/([A-Za-z0-9]+)", prefix)
    if b"FlateDecode" in filters:
        try:
            _inflate(data, wbits=zlib.MAX_WBITS)
        except (RepairError, zlib.error) as exc:
            raise RepairError(f"PDF Flate stream failed decoding: {exc}") from exc


def _scan_pdf_objects(data: bytes) -> list[_PdfObject]:
    if not re.match(rb"%PDF-1\.[0-7](?:\r?\n|\r)", data[:16]):
        raise RepairError("invalid or unsupported PDF header")
    cutoff_candidates = [p for p in (data.find(b"\nxref"), data.find(b"\r\nxref")) if p >= 0]
    cutoff = min(cutoff_candidates) if cutoff_candidates else len(data)
    # Resolve only the safe PDF form ``N G obj <decimal> endobj``.  Object streams, expressions,
    # and cyclic references remain unsupported instead of being interpreted.
    indirect_lengths: dict[tuple[int, int], int] = {}
    for match in _OBJ_HEADER.finditer(data, 0, cutoff):
        end = data.find(b"endobj", match.end(), cutoff)
        if end < 0:
            continue
        body = data[match.end():end]
        integer = re.fullmatch(rb"\s*([0-9]{1,10})\s*", body)
        if integer:
            indirect_lengths[(int(match.group(1)), int(match.group(2)))] = int(integer.group(1))
    objects: list[_PdfObject] = []
    pos = data.find(b"\n") + 1
    seen: set[int] = set()
    while pos < cutoff:
        match = _OBJ_HEADER.search(data, pos, cutoff)
        if match is None:
            break
        if len(objects) >= MAX_OBJECTS:
            raise RepairError("PDF object-count cap reached")
        number, generation = int(match.group(1)), int(match.group(2))
        if number in seen:
            raise RepairError("duplicate PDF object number")
        body_start = match.end()
        ordinary_end = data.find(b"endobj", body_start, cutoff)
        if ordinary_end < 0:
            raise RepairError(f"PDF object {number} has no endobj")
        stream_match = re.search(rb"\bstream(?:\r\n|\n|\r)", data[body_start:ordinary_end])
        if stream_match:
            marker_start = body_start + stream_match.start()
            stream_start = body_start + stream_match.end()
            try:
                stream_length = _pdf_stream_length(data[body_start:marker_start], indirect_lengths)
            except RepairError as exc:
                raise RepairError(f"PDF object {number}: {exc}") from exc
            stream_end = stream_start + stream_length
            if stream_end > cutoff:
                raise RepairError(f"PDF object {number} stream is truncated")
            after = stream_end
            if data[after:after + 2] == b"\r\n":
                after += 2
            elif data[after:after + 1] in {b"\r", b"\n"}:
                after += 1
            if data[after:after + 9] != b"endstream":
                raise RepairError(f"PDF object {number} stream boundary is invalid")
            ordinary_end = data.find(b"endobj", after + 9, cutoff)
            if ordinary_end < 0:
                raise RepairError(f"PDF object {number} has no endobj after stream")
            _decode_pdf_stream(data[body_start:marker_start], data[stream_start:stream_end], indirect_lengths)
        end = ordinary_end + len(b"endobj")
        body = data[body_start:ordinary_end]
        objects.append(_PdfObject(number, generation, match.start(), end, body))
        seen.add(number)
        pos = end
    if not objects:
        raise RepairError("no complete indirect PDF objects found")
    return objects


def _pdf_root(objects: list[_PdfObject], original: bytes) -> tuple[int, int]:
    by_number = {obj.number: obj for obj in objects}
    trailers = list(re.finditer(rb"trailer\s*<<(.{0,65536}?)>>", original, re.S))
    root: tuple[int, int] | None = None
    if trailers:
        match = re.search(rb"/Root\s+([0-9]+)\s+([0-9]+)\s+R", trailers[-1].group(1))
        if match:
            root = (int(match.group(1)), int(match.group(2)))
    catalogs = [obj for obj in objects if re.search(rb"/Type\s*/Catalog\b", obj.body)]
    if root is None:
        if len(catalogs) != 1:
            raise RepairError("PDF requires one unambiguous Catalog root")
        root = (catalogs[0].number, catalogs[0].generation)
    target = by_number.get(root[0])
    if target is None or target.generation != root[1] or not re.search(rb"/Type\s*/Catalog\b", target.body):
        raise RepairError("PDF trailer Root does not name a Catalog object")
    pages = re.search(rb"/Pages\s+([0-9]+)\s+([0-9]+)\s+R", target.body)
    if pages is None:
        raise RepairError("PDF Catalog has no direct Pages reference")
    page_obj = by_number.get(int(pages.group(1)))
    if page_obj is None or page_obj.generation != int(pages.group(2)) or not re.search(
            rb"/Type\s*/Pages\b", page_obj.body):
        raise RepairError("PDF Pages reference does not resolve")
    return root


def _build_pdf(data: bytes, objects: list[_PdfObject], root: tuple[int, int]) -> bytes:
    last_end = max(obj.end for obj in objects)
    prefix = data[:last_end].rstrip() + b"\n"
    max_number = max(obj.number for obj in objects)
    if max_number >= MAX_OBJECTS:
        raise RepairError("PDF object number exceeds the xref bound")
    table = {obj.number: obj for obj in objects}
    xref_offset = len(prefix)
    lines = [b"xref\n", f"0 {max_number + 1}\n".encode(), b"0000000000 65535 f \n"]
    for number in range(1, max_number + 1):
        obj = table.get(number)
        if obj is None:
            lines.append(b"0000000000 00000 f \n")
        else:
            lines.append(f"{obj.offset:010d} {obj.generation:05d} n \n".encode())
    trailer = (f"trailer\n<< /Size {max_number + 1} /Root {root[0]} {root[1]} R >>\n"
               f"startxref\n{xref_offset}\n%%EOF\n").encode()
    candidate = prefix + b"".join(lines) + trailer
    if len(candidate) > MAX_INPUT + MAX_OUTPUT:
        raise RepairError("rebuilt PDF exceeds the size bound")
    return candidate


def _validate_pdf_xref(data: bytes) -> int:
    objects = _scan_pdf_objects(data)
    root = _pdf_root(objects, data)
    starts = list(re.finditer(rb"startxref\s+([0-9]+)\s+%%EOF", data))
    if not starts:
        raise RepairError("PDF startxref/EOF is missing")
    xref_offset = int(starts[-1].group(1))
    if xref_offset >= len(data) or data[xref_offset:xref_offset + 5] != b"xref\n":
        raise RepairError("PDF startxref does not point to a classic xref")
    for obj in objects:
        expected = f"{obj.offset:010d} {obj.generation:05d} n ".encode()
        if expected not in data[xref_offset:]:
            raise RepairError(f"xref does not resolve object {obj.number}")
    if f"/Root {root[0]} {root[1]} R".encode() not in data[xref_offset:]:
        raise RepairError("xref trailer lost the Catalog root")
    return len(objects)


def repair_pdf(data: bytes) -> RepairResult:
    try:
        count = _validate_pdf_xref(data)
        return RepairResult("pdf", "valid", (f"validated classic xref for {count} objects",),
                            recovered_items=count)
    except RepairError as original_error:
        diagnostics = [str(original_error)]
    try:
        objects = _scan_pdf_objects(data)
        root = _pdf_root(objects, data)
        candidate = _build_pdf(data, objects, root)
        count = _validate_pdf_xref(candidate)
        diagnostics.append(f"rebuilt and revalidated xref for {count} complete objects")
        return RepairResult("pdf", "repaired", tuple(diagnostics), candidate, count)
    except RepairError as exc:
        diagnostics.append(str(exc))
        return RepairResult("pdf", "unrecoverable", tuple(dict.fromkeys(diagnostics)))


# --------------------------------------------------------------------------- gzip / bzip2


def _gzip_header_end(data: bytes) -> int:
    if len(data) < 10 or data[:3] != b"\x1f\x8b\x08":
        raise RepairError("invalid gzip header")
    flags = data[3]
    if flags & 0xE0:
        raise RepairError("gzip reserved flags are set")
    pos = 10
    if flags & 4:
        if pos + 2 > len(data):
            raise RepairError("truncated gzip extra length")
        length = struct.unpack_from("<H", data, pos)[0]
        pos += 2 + length
    for bit in (8, 16):
        if flags & bit:
            end = data.find(b"\x00", pos, min(len(data), pos + 65536))
            if end < 0:
                raise RepairError("truncated gzip string field")
            pos = end + 1
    if flags & 2:
        if pos + 2 > len(data):
            raise RepairError("truncated gzip header CRC")
        expected = binascii.crc32(data[:pos]) & 0xFFFF
        if struct.unpack_from("<H", data, pos)[0] != expected:
            raise RepairError("gzip header CRC mismatch")
        pos += 2
    if pos > len(data):
        raise RepairError("truncated gzip header")
    return pos


def _bounded_gzip_decompress(data: bytes) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = decoder.decompress(data, MAX_OUTPUT + 1)
    if len(out) > MAX_OUTPUT or decoder.unconsumed_tail:
        raise RepairError("gzip output exceeds the bound")
    out += decoder.flush(MAX_OUTPUT + 1 - len(out))
    if len(out) > MAX_OUTPUT or not decoder.eof or decoder.unused_data:
        raise RepairError("gzip stream is incomplete or has trailing data")
    return out


def repair_gzip(data: bytes) -> RepairResult:
    try:
        decoded = _bounded_gzip_decompress(data)
        return RepairResult("gzip", "valid", (f"validated {len(decoded)} decompressed bytes",),
                            recovered_items=1)
    except (RepairError, zlib.error) as original_error:
        diagnostics = [str(original_error)]
    try:
        header_end = _gzip_header_end(data)
        decoder = zlib.decompressobj(-zlib.MAX_WBITS)
        compressed_and_tail = data[header_end:]
        decoded = decoder.decompress(compressed_and_tail, MAX_OUTPUT + 1)
        if len(decoded) > MAX_OUTPUT or decoder.unconsumed_tail:
            raise RepairError("gzip output exceeds the bound")
        decoded += decoder.flush(MAX_OUTPUT + 1 - len(decoded))
        if len(decoded) > MAX_OUTPUT or not decoder.eof:
            raise RepairError("raw DEFLATE stream is genuinely truncated")
        consumed = len(compressed_and_tail) - len(decoder.unused_data)
        compressed = compressed_and_tail[:consumed]
        trailer = struct.pack("<II", binascii.crc32(decoded) & 0xFFFFFFFF, len(decoded) & 0xFFFFFFFF)
        candidate = data[:header_end] + compressed + trailer
        verified = _bounded_gzip_decompress(candidate)
        if verified != decoded:
            raise RepairError("rebuilt gzip did not round-trip")
        diagnostics.append("reconstructed gzip CRC32/ISIZE trailer")
        return RepairResult("gzip", "repaired", tuple(diagnostics), candidate, 1)
    except (RepairError, zlib.error, struct.error) as exc:
        diagnostics.append(str(exc))
        return RepairResult("gzip", "unrecoverable", tuple(dict.fromkeys(diagnostics)))


def _bzip_complete_prefix(data: bytes) -> tuple[int, int, str]:
    offset = 0
    streams = 0
    total = 0
    stop_reason = "end of bzip2 streams"
    while data[offset:offset + 3] == b"BZh":
        decoder = bz2.BZ2Decompressor()
        try:
            out = decoder.decompress(data[offset:], max_length=MAX_OUTPUT - total + 1)
        except (OSError, EOFError) as exc:
            stop_reason = f"invalid/truncated bzip2 stream: {exc}"
            break
        if len(out) + total > MAX_OUTPUT:
            raise RepairError("bzip2 output exceeds the bound")
        if not decoder.eof:
            stop_reason = "truncated bzip2 stream"
            break
        consumed = len(data[offset:]) - len(decoder.unused_data)
        if consumed <= 0:
            raise RepairError("bzip2 decoder made no progress")
        offset += consumed
        total += len(out)
        streams += 1
        if not decoder.unused_data:
            break
        if not decoder.unused_data.startswith(b"BZh"):
            stop_reason = "non-bzip2 trailing bytes"
            break
    return offset, streams, stop_reason


def repair_bzip2(data: bytes) -> RepairResult:
    try:
        end, streams, reason = _bzip_complete_prefix(data)
        if not streams:
            raise RepairError(reason)
        if end == len(data):
            # Decode once more through the stdlib's concatenated-stream path.
            decoded = bz2.decompress(data)
            if len(decoded) > MAX_OUTPUT:
                raise RepairError("bzip2 output exceeds the bound")
            return RepairResult("bzip2", "valid", (f"validated {streams} bzip2 stream(s)",),
                                recovered_items=streams)
        candidate = data[:end]
        decoded = bz2.decompress(candidate)
        if len(decoded) > MAX_OUTPUT:
            raise RepairError("bzip2 output exceeds the bound")
        return RepairResult("bzip2", "repaired",
                            (reason, f"salvaged and decoded {streams} complete bzip2 stream(s)"),
                            candidate, streams)
    except (RepairError, OSError, EOFError) as exc:
        return RepairResult("bzip2", "unrecoverable", (str(exc),))


# --------------------------------------------------------------------------- dispatch / CLI


def detect_format(data: bytes) -> str | None:
    if data.startswith(PNG_SIG) or (len(data) >= 16 and data[12:16] == b"IHDR"):
        return "png"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"BZh"):
        return "bzip2"
    return None


def repair(data: bytes, kind: str | None = None) -> RepairResult:
    """Detect and conservatively repair one bounded artifact."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not data or len(data) > MAX_INPUT:
        raise RepairError(f"input must be 1..{MAX_INPUT} bytes")
    fmt = kind or detect_format(data)
    if fmt not in {"png", "zip", "pdf", "gzip", "bzip2"}:
        raise RepairError("format is unknown or unsupported")
    return {"png": repair_png, "zip": repair_zip, "pdf": repair_pdf,
            "gzip": repair_gzip, "bzip2": repair_bzip2}[fmt](data)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description="decode-validated offline file repair")
    parser.add_argument("file")
    parser.add_argument("--format", choices=("png", "zip", "pdf", "gzip", "bzip2"))
    parser.add_argument("--output", help="write a validated repair candidate here")
    parser.add_argument("--force", action="store_true", help="allow replacing an existing --output file")
    parser.add_argument("--json", action="store_true")
    try:
        args = parser.parse_args(argv)
        path = Path(args.file)
        if path.stat().st_size > MAX_INPUT:
            raise RepairError(f"input exceeds {MAX_INPUT} bytes")
        result = repair(path.read_bytes(), args.format)
        if result.status == "unrecoverable":
            raise RepairError("; ".join(result.diagnostics))
        if args.output:
            if result.candidate is None:
                raise RepairError("no repair candidate is available to write")
            output_path = Path(args.output)
            if output_path.exists() and not args.force:
                raise RepairError("output already exists (pass --force to replace it)")
            output_path.write_bytes(result.candidate)
        report = result.report()
        if args.output and result.candidate is not None:
            report["output"] = str(Path(args.output))
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            print(f"{result.format}: {result.status}")
            for line in result.diagnostics:
                print(f"  {line}")
            if result.candidate is not None:
                print(f"  candidate: {len(result.candidate)} bytes, sha256={report['candidate_sha256']}")
        return 0
    except (ValueError, TypeError, OSError, EOFError, struct.error, zlib.error) as exc:
        print(f"file_repair: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
