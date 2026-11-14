#!/usr/bin/env python3
"""Bounded offline decoding for iOS KTX snapshots and HEIF/HEIC images.

This engine fills a deliberately narrow gap.  The repository's
``readers_formats.py`` already inventories HEIF boxes, items, properties, and
references; this module does not recreate that metadata reader.  It adds:

* strict KTX1/KTX2 container validation and first-class 2-D snapshot decoding;
* RGBA8/BGRA8 and ASTC 4x4 payloads, including the observed Apple
  ``Compression_APPLE`` LZFSE wrapper used by iOS snapshots;
* reverse-engineered Apple AAPL/ATX HEAD and ASTC/LZFSE snapshot decoding, with
  the raw pixel-format discriminator and confidence kept explicit; and
* bounded HEIF/HEIC top-level image decoding through libheif via ``pillow-heif``.

All inputs are caller-supplied bytes.  No network, device, application, script,
or child process is used.  Unknown layouts and codecs are declined rather than
guessed.  Pixel output is capped before decoding.
"""
from __future__ import annotations

import argparse
import io
import json
import struct
import sys
from pathlib import Path
from typing import Any


class Mobile2MediaError(ValueError):
    """The supplied image is malformed, unsupported, or outside safe limits."""


MAX_INPUT = 64 << 20
MAX_PIXELS = 32_000_000
MAX_OUTPUT = MAX_PIXELS * 4
MAX_DIMENSION = 32_768
MAX_LEVELS = 32
MAX_KV_RECORDS = 4096
MAX_HEIF_IMAGES = 64
MAX_ATX_CHUNKS = 1024

KTX1_MAGIC = b"\xabKTX 11\xbb\r\n\x1a\n"
KTX2_MAGIC = b"\xabKTX 20\xbb\r\n\x1a\n"
AAPL_MAGIC = b"AAPL\r\n\x1a\n"

GL_UNSIGNED_BYTE = 0x1401
GL_RGBA = 0x1908
GL_BGRA = 0x80E1
GL_RGBA8 = 0x8058
GL_COMPRESSED_RGBA_ASTC_4X4 = 0x93B0
GL_COMPRESSED_SRGB8_ALPHA8_ASTC_4X4 = 0x93D0

VK_FORMAT_R8G8B8A8_UNORM = 37
VK_FORMAT_R8G8B8A8_SRGB = 43
VK_FORMAT_ASTC_4X4_UNORM_BLOCK = 157
VK_FORMAT_ASTC_4X4_SRGB_BLOCK = 158

HEIF_BRANDS = {
    "heic", "heix", "hevc", "hevx", "heim", "heis", "hevm", "hevs",
    "mif1", "mif2", "msf1", "miaf", "avif", "avis",
}
HEIC_BRANDS = {"heic", "heix", "hevc", "hevx", "heim", "heis", "hevm", "hevs"}
AVIF_BRANDS = {"avif", "avis"}


def _bounded_bytes(data: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise Mobile2MediaError("input must be bytes")
    raw = bytes(data)
    if not raw:
        raise Mobile2MediaError("input is empty")
    if len(raw) > MAX_INPUT:
        raise Mobile2MediaError("input exceeds 64 MiB cap")
    return raw


def _range(length: int, offset: int, size: int, label: str) -> tuple[int, int]:
    if not isinstance(offset, int) or not isinstance(size, int) or offset < 0 or size < 0:
        raise Mobile2MediaError(f"{label} has a negative range")
    if offset > length or size > length - offset:
        raise Mobile2MediaError(f"{label} exceeds the file")
    return offset, offset + size


def _dimensions(width: int, height: int) -> int:
    if not (1 <= width <= MAX_DIMENSION and 1 <= height <= MAX_DIMENSION):
        raise Mobile2MediaError("image dimensions are zero or exceed the cap")
    pixels = width * height
    if pixels > MAX_PIXELS:
        raise Mobile2MediaError("image pixel count exceeds the cap")
    return pixels


def _text_or_none(value: bytes) -> str | None:
    try:
        return value.rstrip(b"\x00").decode("utf-8")
    except UnicodeDecodeError:
        return None


def _parse_kv(raw: bytes, start: int, length: int, endian: str, version: int) -> tuple[list[dict[str, Any]], str | None]:
    _, end = _range(len(raw), start, length, "KTX key/value area")
    cursor = start
    records: list[dict[str, Any]] = []
    orientation = None
    while cursor < end:
        if len(records) >= MAX_KV_RECORDS:
            raise Mobile2MediaError("KTX key/value record count exceeds cap")
        if end - cursor < 4:
            raise Mobile2MediaError("KTX key/value length is truncated")
        size = struct.unpack_from(endian + "I", raw, cursor)[0]
        cursor += 4
        _, item_end = _range(end, cursor, size, "KTX key/value record")
        body = raw[cursor:item_end]
        split = body.find(b"\x00")
        if split <= 0:
            raise Mobile2MediaError("KTX key/value key is empty or unterminated")
        try:
            key = body[:split].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Mobile2MediaError("KTX key is not UTF-8") from exc
        value = body[split + 1:]
        text = _text_or_none(value)
        records.append({
            "key": key,
            "value_length": len(value),
            "value_hex": value.hex(),
            "value_text": text,
            "record_offset": cursor - 4,
        })
        if key == "KTXorientation" and text is not None:
            orientation = text
        padded_end = (item_end + 3) & ~3
        if padded_end > end:
            raise Mobile2MediaError("KTX key/value padding exceeds its area")
        if any(raw[item_end:padded_end]):
            raise Mobile2MediaError("KTX key/value padding is not zero")
        cursor = padded_end
    if cursor != end:
        raise Mobile2MediaError("KTX key/value area has inconsistent padding")
    if version == 2:
        keys = [item["key"] for item in records]
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise Mobile2MediaError("KTX2 key/value keys are not sorted and unique")
    if orientation is not None:
        _orientation_axes(orientation, version)
    return records, orientation


def _orientation_axes(value: str, version: int) -> tuple[str, str]:
    cleaned = value.strip().rstrip("\x00")
    if version == 1:
        axes: dict[str, str] = {}
        for token in cleaned.split(","):
            pieces = token.strip().split("=", 1)
            if len(pieces) != 2:
                raise Mobile2MediaError("invalid KTX1 orientation value")
            axes[pieces[0].strip().upper()] = pieces[1].strip().lower()
        s, t = axes.get("S"), axes.get("T")
    else:
        if len(cleaned) < 2:
            raise Mobile2MediaError("invalid KTX2 orientation value")
        s, t = cleaned[0].lower(), cleaned[1].lower()
    if s not in ("r", "l") or t not in ("d", "u"):
        raise Mobile2MediaError("unsupported KTX orientation axes")
    return s, t


def _level_expected(kind: str, width: int, height: int) -> int:
    if kind in ("rgba8", "bgra8"):
        return _dimensions(width, height) * 4
    if kind == "astc-4x4":
        _dimensions(width, height)
        return ((width + 3) // 4) * ((height + 3) // 4) * 16
    raise Mobile2MediaError("unsupported KTX pixel format")


def _ktx1_kind(gl_type: int, gl_type_size: int, gl_format: int, internal: int, base: int) -> str:
    if (gl_type, gl_type_size, gl_format) == (GL_UNSIGNED_BYTE, 1, GL_RGBA) and internal in (GL_RGBA8, GL_RGBA):
        return "rgba8"
    if (gl_type, gl_type_size, gl_format) == (GL_UNSIGNED_BYTE, 1, GL_BGRA) and internal in (GL_RGBA8, GL_RGBA):
        return "bgra8"
    if (gl_type, gl_type_size, gl_format) == (0, 1, 0) and internal in (
            GL_COMPRESSED_RGBA_ASTC_4X4, GL_COMPRESSED_SRGB8_ALPHA8_ASTC_4X4):
        if base != GL_RGBA:
            raise Mobile2MediaError("ASTC KTX base format is not RGBA")
        return "astc-4x4"
    return "unsupported"


def _lzfse_output_size(stream: bytes, maximum: int) -> int:
    """Validate an Apple LZFSE stream and total its declared decoded bytes."""
    cursor = 0
    total = 0
    ended = False
    while cursor < len(stream):
        if len(stream) - cursor < 4:
            raise Mobile2MediaError("LZFSE block magic is truncated")
        magic = stream[cursor:cursor + 4]
        if magic == b"bvx$":
            cursor += 4
            ended = True
            break
        if magic == b"bvx-":
            if len(stream) - cursor < 8:
                raise Mobile2MediaError("LZFSE raw block header is truncated")
            raw_size = struct.unpack_from("<I", stream, cursor + 4)[0]
            block_size = 8 + raw_size
        elif magic == b"bvxn":
            if len(stream) - cursor < 12:
                raise Mobile2MediaError("LZVN block header is truncated")
            raw_size, payload_size = struct.unpack_from("<II", stream, cursor + 4)
            block_size = 12 + payload_size
        elif magic == b"bvx1":
            if len(stream) - cursor < 770:
                raise Mobile2MediaError("LZFSE v1 block header is truncated")
            raw_size = struct.unpack_from("<I", stream, cursor + 4)[0]
            literal_size, lmd_size = struct.unpack_from("<II", stream, cursor + 20)
            block_size = 770 + literal_size + lmd_size
        elif magic == b"bvx2":
            if len(stream) - cursor < 32:
                raise Mobile2MediaError("LZFSE v2 block header is truncated")
            raw_size = struct.unpack_from("<I", stream, cursor + 4)[0]
            packed0, packed1, packed2 = struct.unpack_from("<QQQ", stream, cursor + 8)
            header_size = packed2 & 0xFFFFFFFF
            literal_size = (packed0 >> 20) & ((1 << 20) - 1)
            lmd_size = (packed1 >> 40) & ((1 << 20) - 1)
            if header_size < 32:
                raise Mobile2MediaError("LZFSE v2 header size is invalid")
            block_size = header_size + literal_size + lmd_size
        else:
            raise Mobile2MediaError("Apple KTX wrapper is not an LZFSE stream")
        if block_size < 4 or block_size > len(stream) - cursor:
            raise Mobile2MediaError("LZFSE block exceeds the supplied stream")
        if raw_size > maximum - total:
            raise Mobile2MediaError("LZFSE declared output exceeds the pixel cap")
        total += raw_size
        cursor += block_size
    if not ended or cursor != len(stream):
        raise Mobile2MediaError("LZFSE stream lacks a clean end marker")
    return total


def _parse_ktx1(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(raw) < 64:
        raise Mobile2MediaError("KTX1 header is truncated")
    marker = raw[12:16]
    if marker == b"\x01\x02\x03\x04":
        endian, endian_name = "<", "little"
    elif marker == b"\x04\x03\x02\x01":
        endian, endian_name = ">", "big"
    else:
        raise Mobile2MediaError("KTX1 endianness marker is invalid")
    fields = struct.unpack_from(endian + "12I", raw, 16)
    (gl_type, gl_type_size, gl_format, internal, base, width, height, depth,
     arrays, faces, mipmaps, kv_length) = fields
    _dimensions(width, height)
    if depth != 0 or arrays != 0 or faces != 1:
        raise Mobile2MediaError("only 2-D, non-array, one-face KTX snapshots are supported")
    level_count = max(1, mipmaps)
    if level_count > MAX_LEVELS or level_count > max(width, height).bit_length():
        raise Mobile2MediaError("KTX1 mip level count exceeds cap")
    kv, orientation = _parse_kv(raw, 64, kv_length, endian, 1)
    cursor = 64 + kv_length
    kind = _ktx1_kind(gl_type, gl_type_size, gl_format, internal, base)
    apple_lzfse = any(item["key"] == "Compression_APPLE" for item in kv)
    levels: list[dict[str, Any]] = []
    state: dict[str, Any] = {"raw": raw, "kind": kind, "orientation": orientation, "version": 1}
    if apple_lzfse:
        if kind != "astc-4x4" or level_count != 1:
            raise Mobile2MediaError("Apple LZFSE wrapper is supported only for one ASTC 4x4 level")
        if len(raw) - cursor < 16:
            raise Mobile2MediaError("Apple KTX LZFSE wrapper is truncated")
        image_size = struct.unpack_from(endian + "I", raw, cursor)[0]
        stream_offset = cursor + 12
        stream = raw[stream_offset:]
        expected = _level_expected(kind, width, height)
        declared = _lzfse_output_size(stream, expected)
        if declared != expected:
            raise Mobile2MediaError("LZFSE output size does not match ASTC dimensions")
        levels.append({"level": 0, "width": width, "height": height,
                       "image_size_field": image_size, "offset": stream_offset,
                       "stored_length": len(stream), "decoded_length": expected,
                       "compression": "apple-lzfse"})
        state.update({"payload": stream, "compressed": True, "expected": expected})
        trailing = 0
    else:
        for level in range(level_count):
            if len(raw) - cursor < 4:
                raise Mobile2MediaError("KTX1 mip size is truncated")
            image_size = struct.unpack_from(endian + "I", raw, cursor)[0]
            cursor += 4
            level_width = max(1, width >> level)
            level_height = max(1, height >> level)
            expected = _level_expected(kind, level_width, level_height) if kind != "unsupported" else image_size
            if kind != "unsupported" and image_size != expected:
                raise Mobile2MediaError("KTX1 image size disagrees with its format and dimensions")
            _range(len(raw), cursor, image_size, "KTX1 mip payload")
            levels.append({"level": level, "width": level_width, "height": level_height,
                           "image_size_field": image_size, "offset": cursor,
                           "stored_length": image_size, "decoded_length": expected,
                           "compression": "astc" if kind == "astc-4x4" else "none"})
            if level == 0:
                state.update({"payload": raw[cursor:cursor + image_size], "compressed": False,
                              "expected": expected})
            cursor += (image_size + 3) & ~3
            if cursor > len(raw):
                raise Mobile2MediaError("KTX1 mip padding exceeds the file")
        trailing = len(raw) - cursor
    report = {
        "container": "ktx1", "endianness": endian_name, "width": width, "height": height,
        "depth": depth, "array_elements": arrays, "faces": faces,
        "mipmap_levels": mipmaps, "stored_level_count": level_count,
        "gl_type": gl_type, "gl_type_size": gl_type_size, "gl_format": gl_format,
        "gl_internal_format": internal, "gl_base_internal_format": base,
        "pixel_format": kind, "orientation": orientation, "key_values": kv,
        "apple_lzfse": apple_lzfse, "levels": levels, "trailing_bytes": trailing,
        "decodable": kind != "unsupported",
    }
    state.update({"width": width, "height": height})
    return report, state


def _parse_ktx2(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(raw) < 80:
        raise Mobile2MediaError("KTX2 header is truncated")
    values = struct.unpack_from("<13I2Q", raw, 12)
    (vk_format, type_size, width, height, depth, layers, faces, level_count,
     supercompression, dfd_offset, dfd_length, kvd_offset, kvd_length,
     sgd_offset, sgd_length) = values
    _dimensions(width, height)
    if depth != 0 or layers not in (0, 1) or faces != 1:
        raise Mobile2MediaError("only 2-D, one-layer, one-face KTX2 snapshots are supported")
    stored_levels = max(1, level_count)
    if (stored_levels > MAX_LEVELS or stored_levels > max(width, height).bit_length()
            or 80 + stored_levels * 24 > len(raw)):
        raise Mobile2MediaError("KTX2 level index exceeds the file or cap")
    if dfd_length < 28:
        raise Mobile2MediaError("KTX2 data format descriptor is missing")
    _, dfd_end = _range(len(raw), dfd_offset, dfd_length, "KTX2 data format descriptor")
    dfd_total = struct.unpack_from("<I", raw, dfd_offset)[0]
    if dfd_total != dfd_length:
        raise Mobile2MediaError("KTX2 dfdByteLength does not equal dfdTotalSize")
    dfd_cursor = dfd_offset + 4
    while dfd_cursor < dfd_end:
        if dfd_end - dfd_cursor < 8:
            raise Mobile2MediaError("KTX2 descriptor block header is truncated")
        descriptor_word = struct.unpack_from("<I", raw, dfd_cursor + 4)[0]
        descriptor_size = descriptor_word >> 16
        if descriptor_size < 8 or descriptor_size % 4 or descriptor_size > dfd_end - dfd_cursor:
            raise Mobile2MediaError("KTX2 descriptor block size is invalid")
        dfd_cursor += descriptor_size
    if dfd_cursor != dfd_end:
        raise Mobile2MediaError("KTX2 descriptor blocks do not fill dfdByteLength")
    if not kvd_length and kvd_offset:
        raise Mobile2MediaError("KTX2 kvdByteOffset must be zero when no key/value data exists")
    if kvd_length:
        kv, orientation = _parse_kv(raw, kvd_offset, kvd_length, "<", 2)
    else:
        kv, orientation = [], None
    if sgd_length:
        _range(len(raw), sgd_offset, sgd_length, "KTX2 supercompression global data")
    elif sgd_offset:
        raise Mobile2MediaError("KTX2 sgdByteOffset must be zero when no global data exists")
    levels = []
    for level in range(stored_levels):
        offset, stored, decoded = struct.unpack_from("<QQQ", raw, 80 + level * 24)
        _range(len(raw), offset, stored, f"KTX2 level {level}")
        if stored > MAX_OUTPUT or decoded > MAX_OUTPUT:
            raise Mobile2MediaError("KTX2 level exceeds output cap")
        if supercompression == 0 and stored != decoded:
            raise Mobile2MediaError("KTX2 uncompressed level lengths disagree")
        levels.append({"level": level, "offset": offset, "stored_length": stored,
                       "decoded_length": decoded})
    kind = {
        VK_FORMAT_R8G8B8A8_UNORM: "rgba8", VK_FORMAT_R8G8B8A8_SRGB: "rgba8",
        VK_FORMAT_ASTC_4X4_UNORM_BLOCK: "astc-4x4", VK_FORMAT_ASTC_4X4_SRGB_BLOCK: "astc-4x4",
    }.get(vk_format, "unsupported")
    if kind != "unsupported" and type_size != 1:
        raise Mobile2MediaError("KTX2 typeSize disagrees with its 8-bit or block format")
    if kind == "astc-4x4" and level_count == 0:
        raise Mobile2MediaError("KTX2 levelCount zero is invalid for block-compressed formats")
    decodable = kind != "unsupported" and supercompression == 0 and stored_levels >= 1
    if decodable:
        for level, item in enumerate(levels):
            expected_level = _level_expected(kind, max(1, width >> level), max(1, height >> level))
            if item["stored_length"] != expected_level or item["decoded_length"] != expected_level:
                raise Mobile2MediaError("KTX2 level size disagrees with its format and dimensions")
            alignment = 16 if kind == "astc-4x4" else 4
            if item["offset"] % alignment:
                raise Mobile2MediaError("KTX2 level offset violates texel-block alignment")
        expected = _level_expected(kind, width, height)
    else:
        expected = None
    report = {
        "container": "ktx2", "endianness": "little", "width": width, "height": height,
        "depth": depth, "layers": layers, "faces": faces, "level_count": level_count,
        "stored_level_count": stored_levels, "vk_format": vk_format, "type_size": type_size,
        "supercompression_scheme": supercompression,
        "data_format_descriptor": {"offset": dfd_offset, "length": dfd_length},
        "supercompression_global_data": {"offset": sgd_offset, "length": sgd_length},
        "pixel_format": kind, "orientation": orientation, "key_values": kv,
        "levels": levels, "decodable": decodable,
        "decline_reason": ("unsupported vkFormat" if kind == "unsupported" else
                           "supercompressed KTX2 requires a dedicated transcoder" if supercompression else None),
    }
    first = levels[0]
    state = {"raw": raw, "kind": kind, "orientation": orientation, "version": 2,
             "width": width, "height": height,
             "payload": raw[first["offset"]:first["offset"] + first["stored_length"]],
             "compressed": False, "expected": expected, "decodable": decodable}
    return report, state


def _parse_atx(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    """Parse the iLEAPP/atx-core reverse-engineered AAPL chunk layout."""
    chunks: list[dict[str, Any]] = []
    cursor = 8
    while cursor < len(raw):
        if len(chunks) >= MAX_ATX_CHUNKS or len(raw) - cursor < 8:
            raise Mobile2MediaError("AAPL/ATX chunk table is truncated or exceeds cap")
        size, kind = struct.unpack_from("<I4s", raw, cursor)
        header_offset = cursor
        cursor += 8
        _range(len(raw), cursor, size, "AAPL/ATX chunk")
        chunks.append({"type": kind.decode("latin-1"), "header_offset": header_offset,
                       "offset": cursor, "length": size})
        cursor += size
    head_chunk = next((item for item in chunks if item["type"] == "HEAD"), None)
    payload_chunk = next((item for item in chunks if item["type"] in ("astc", "ASTC", "LZFS")), None)
    head = None
    if head_chunk is not None:
        if head_chunk["length"] < 0x54:
            raise Mobile2MediaError("AAPL/ATX HEAD chunk is shorter than the observed layout")
        start = head_chunk["offset"]
        payload = raw[start:start + head_chunk["length"]]
        flags = struct.unpack_from("<I", payload, 0)[0]
        width, height, depth = struct.unpack_from("<III", payload, 0x18)
        layers, mipmaps = struct.unpack_from("<II", payload, 0x28)
        format_a, format_b = struct.unpack_from("<II", payload, 0x4C)
        _dimensions(width, height)
        confidence = {
            (3, 5): "confirmed",
            (1, 1): "inferred",
            (3, 1): "inferred",
        }.get((format_a, format_b))
        head = {
            "flags": flags, "width": width, "height": height, "depth": depth,
            "array_layers": layers, "mipmap_levels": mipmaps,
            "texture_uuid": payload[0x3C:0x4C].hex(),
            "pixel_format_discriminator": [format_a, format_b],
            "pixel_format": "astc-4x4" if confidence else "unknown",
            "format_confidence": confidence,
        }
    payload_report = None
    payload_data = None
    if payload_chunk is not None:
        if payload_chunk["length"] < 4:
            raise Mobile2MediaError("AAPL/ATX texture chunk has no inner size")
        start = payload_chunk["offset"]
        declared = struct.unpack_from("<I", raw, start)[0]
        payload_data = raw[start + 4:start + payload_chunk["length"]]
        payload_report = {
            "type": payload_chunk["type"], "declared_size": declared,
            "offset": start + 4, "stored_length": len(payload_data),
            "compression": "lzfse" if payload_chunk["type"] == "LZFS" else "apple-morton-astc",
        }
    decline = None
    if head is None:
        decline = "AAPL/ATX has no HEAD metadata chunk"
    elif payload_report is None:
        decline = "AAPL/ATX has no astc/ASTC/LZFS payload chunk"
    elif head["format_confidence"] is None:
        decline = "unrecognized AAPL/ATX pixel-format discriminator"
    report = {
        "container": "aapl-atx", "chunks": chunks, "head": head,
        "texture_payload": payload_report, "decodable": decline is None,
        "decline_reason": decline,
        "format_basis": "reverse-engineered iLEAPP/atx-core layout; not an Apple specification",
    }
    state = {"decodable": decline is None, "head": head, "payload": payload_data,
             "payload_type": payload_chunk["type"] if payload_chunk else None}
    return report, state


def _parse_ktx_impl(raw: bytes) -> tuple[dict[str, Any], dict[str, Any]]:
    if raw.startswith(KTX1_MAGIC):
        return _parse_ktx1(raw)
    if raw.startswith(KTX2_MAGIC):
        return _parse_ktx2(raw)
    if raw.startswith(AAPL_MAGIC):
        return _parse_atx(raw)
    raise Mobile2MediaError("input is not KTX1, KTX2, or AAPL/ATX")


def parse_ktx(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Return a bounded KTX/ATX structural report; raise only Mobile2MediaError."""
    try:
        report, _ = _parse_ktx_impl(_bounded_bytes(data))
        return report
    except Mobile2MediaError:
        raise
    except Exception as exc:
        raise Mobile2MediaError("malformed KTX/ATX input") from exc


def _decode_lzfse(stream: bytes, expected: int) -> bytes:
    try:
        import liblzfse
    except Exception as exc:
        raise Mobile2MediaError("Apple LZFSE snapshot requires pyliblzfse") from exc
    try:
        output = liblzfse.decompress(stream)
    except Exception as exc:
        raise Mobile2MediaError("Apple LZFSE payload did not decompress") from exc
    if not isinstance(output, bytes) or len(output) != expected:
        raise Mobile2MediaError("Apple LZFSE output length disagrees with the snapshot")
    return output


def _decode_astc(payload: bytes, width: int, height: int) -> bytes:
    expected = _level_expected("astc-4x4", width, height)
    if len(payload) != expected:
        raise Mobile2MediaError("ASTC payload length disagrees with dimensions")
    try:
        import texture2ddecoder
    except Exception as exc:
        raise Mobile2MediaError("ASTC snapshot requires texture2ddecoder") from exc
    try:
        bgra = texture2ddecoder.decode_astc(payload, width, height, 4, 4)
    except Exception as exc:
        raise Mobile2MediaError("ASTC payload did not decode") from exc
    if not isinstance(bgra, bytes) or len(bgra) != width * height * 4:
        raise Mobile2MediaError("ASTC decoder returned an inconsistent buffer")
    rgba = bytearray(len(bgra))
    rgba[0::4] = bgra[2::4]
    rgba[1::4] = bgra[1::4]
    rgba[2::4] = bgra[0::4]
    rgba[3::4] = bgra[3::4]
    return bytes(rgba)


def _crop_rgba(rgba: bytes, source_width: int, width: int, height: int) -> bytes:
    row_size = width * 4
    return b"".join(
        rgba[row * source_width * 4:row * source_width * 4 + row_size]
        for row in range(height)
    )


def _morton_5bit(index: int) -> tuple[int, int]:
    x = y = 0
    for bit in range(5):
        x |= ((index >> (bit * 2)) & 1) << bit
        y |= ((index >> (bit * 2 + 1)) & 1) << bit
    return x, y


def _atx_detile(payload: bytes, blocks_width: int, blocks_height: int, swap_xy: bool) -> bytes:
    output = bytearray(blocks_width * blocks_height * 16)
    source = 0
    for macro_y in range(0, blocks_height, 32):
        for macro_x in range(0, blocks_width, 32):
            for morton in range(32 * 32):
                local_x, local_y = _morton_5bit(morton)
                if swap_xy:
                    local_x, local_y = local_y, local_x
                destination = ((macro_y + local_y) * blocks_width + macro_x + local_x) * 16
                output[destination:destination + 16] = payload[source:source + 16]
                source += 16
    return bytes(output)


def _atx_seam_score(rgba: bytes, width: int, height: int) -> float:
    def luma(x: int, y: int) -> int:
        offset = (y * width + x) * 4
        red, green, blue = rgba[offset:offset + 3]
        return (red * 299 + green * 587 + blue * 114) // 1000

    total = count = 0
    for x in range(128, width, 128):
        for y in range(height):
            total += abs(luma(x, y) - luma(x - 1, y))
            count += 1
    for y in range(128, height, 128):
        for x in range(width):
            total += abs(luma(x, y) - luma(x, y - 1))
            count += 1
    return total / count if count else 0.0


def _decode_atx(state: dict[str, Any]) -> bytes:
    head = state.get("head")
    payload = state.get("payload")
    if not isinstance(head, dict) or not isinstance(payload, bytes):
        raise Mobile2MediaError("AAPL/ATX metadata or payload is missing")
    width, height = head["width"], head["height"]
    if state.get("payload_type") == "LZFS":
        padded_width = (width + 3) & ~3
        padded_height = (height + 3) & ~3
        expected = _level_expected("astc-4x4", padded_width, padded_height)
        if _lzfse_output_size(payload, expected) != expected:
            raise Mobile2MediaError("AAPL/ATX LZFSE output size disagrees with its dimensions")
        astc = _decode_lzfse(payload, expected)
        rgba = _decode_astc(astc, padded_width, padded_height)
        return _crop_rgba(rgba, padded_width, width, height)
    padded_width = ((width + 127) // 128) * 128
    padded_height = ((height + 127) // 128) * 128
    blocks_width, blocks_height = padded_width // 4, padded_height // 4
    expected = blocks_width * blocks_height * 16
    if len(payload) < expected:
        raise Mobile2MediaError("AAPL/ATX macro-tiled ASTC payload is shorter than its dimensions")
    candidates = []
    for swap_xy in (False, True):
        linear = _atx_detile(payload[:expected], blocks_width, blocks_height, swap_xy)
        padded_rgba = _decode_astc(linear, padded_width, padded_height)
        cropped = _crop_rgba(padded_rgba, padded_width, width, height)
        candidates.append((_atx_seam_score(cropped, width, height), cropped))
    return min(candidates, key=lambda item: item[0])[1]


def _orient_rgba(rgba: bytes, width: int, height: int, orientation: str | None, version: int) -> bytes:
    if orientation is None:
        return rgba
    s_axis, t_axis = _orientation_axes(orientation, version)
    if s_axis == "r" and t_axis == "d":
        return rgba
    rows = [bytearray(rgba[row * width * 4:(row + 1) * width * 4]) for row in range(height)]
    if s_axis == "l":
        for index, row in enumerate(rows):
            pixels = [row[pos:pos + 4] for pos in range(0, len(row), 4)]
            rows[index] = bytearray().join(reversed(pixels))
    if t_axis == "u":
        rows.reverse()
    return b"".join(rows)


def decode_ktx(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode one bounded 2-D KTX snapshot to top-left-origin RGBA bytes."""
    try:
        report, state = _parse_ktx_impl(_bounded_bytes(data))
        if not report.get("decodable") or not state.get("decodable", True):
            raise Mobile2MediaError(report.get("decline_reason") or "KTX format is detected but not decodable")
        if report["container"] == "aapl-atx":
            rgba = _decode_atx(state)
            head = state["head"]
            return {"container": report["container"], "width": head["width"],
                    "height": head["height"], "mode": "RGBA", "pixel_format": "astc-4x4",
                    "format_confidence": head["format_confidence"], "orientation_applied": None,
                    "rgba": rgba, "report": report}
        kind = state["kind"]
        payload = state["payload"]
        if state.get("compressed"):
            payload = _decode_lzfse(payload, state["expected"])
        if kind == "astc-4x4":
            rgba = _decode_astc(payload, state["width"], state["height"])
        elif kind == "rgba8":
            rgba = payload
        elif kind == "bgra8":
            converted = bytearray(len(payload))
            converted[0::4], converted[1::4] = payload[2::4], payload[1::4]
            converted[2::4], converted[3::4] = payload[0::4], payload[3::4]
            rgba = bytes(converted)
        else:
            raise Mobile2MediaError("KTX pixel format is unsupported")
        if len(rgba) != state["width"] * state["height"] * 4:
            raise Mobile2MediaError("decoded KTX pixel buffer has the wrong size")
        rgba = _orient_rgba(rgba, state["width"], state["height"], state["orientation"], state["version"])
        return {"container": report["container"], "width": state["width"], "height": state["height"],
                "mode": "RGBA", "pixel_format": kind, "orientation_applied": state["orientation"],
                "rgba": rgba, "report": report}
    except Mobile2MediaError:
        raise
    except Exception as exc:
        raise Mobile2MediaError("KTX snapshot decode failed") from exc


def _ftyp(raw: bytes) -> dict[str, Any]:
    if len(raw) < 16 or raw[4:8] != b"ftyp":
        raise Mobile2MediaError("input has no leading HEIF file-type box")
    size32 = struct.unpack_from(">I", raw, 0)[0]
    if size32 == 1:
        if len(raw) < 24:
            raise Mobile2MediaError("extended HEIF file-type box is truncated")
        size, header = struct.unpack_from(">Q", raw, 8)[0], 16
    elif size32 == 0:
        size, header = len(raw), 8
    else:
        size, header = size32, 8
    if size < header + 8 or size > len(raw) or (size - header - 8) % 4:
        raise Mobile2MediaError("HEIF file-type box size is invalid")
    try:
        major = raw[header:header + 4].decode("ascii")
        compatible = [raw[pos:pos + 4].decode("ascii") for pos in range(header + 8, size, 4)]
    except UnicodeDecodeError as exc:
        raise Mobile2MediaError("HEIF brand is not ASCII") from exc
    brands = {major, *compatible}
    if not brands & HEIF_BRANDS:
        raise Mobile2MediaError("file-type brands do not identify HEIF/HEIC/AVIF")
    category = "heic" if brands & HEIC_BRANDS else "avif" if brands & AVIF_BRANDS else "heif"
    return {"major_brand": major, "minor_version": struct.unpack_from(">I", raw, header + 4)[0],
            "compatible_brands": compatible, "category": category, "ftyp_size": size}


def inspect_heif(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Identify HEIF brands without duplicating the repo's full metadata reader."""
    try:
        facts = _ftyp(_bounded_bytes(data))
        return {"container": "heif", **facts,
                "metadata_inventory": "use readers_formats.py for items/properties/references"}
    except Mobile2MediaError:
        raise
    except Exception as exc:
        raise Mobile2MediaError("malformed HEIF file-type box") from exc


def decode_heif(data: bytes | bytearray | memoryview) -> dict[str, Any]:
    """Decode all top-level HEIF images to RGBA using libheif security limits."""
    try:
        raw = _bounded_bytes(data)
        brands = _ftyp(raw)
        try:
            import pillow_heif
            from pillow_heif import options as heif_options
        except Exception as exc:
            raise Mobile2MediaError("HEIF pixel decode requires pillow-heif") from exc
        heif_options.DISABLE_SECURITY_LIMITS = False
        try:
            container = pillow_heif.open_heif(io.BytesIO(raw), convert_hdr_to_8bit=True, bgr_mode=False)
        except Exception as exc:
            raise Mobile2MediaError("libheif rejected the supplied image") from exc
        if not 1 <= len(container) <= MAX_HEIF_IMAGES:
            raise Mobile2MediaError("HEIF top-level image count is zero or exceeds cap")
        total_pixels = 0
        dimensions = []
        for image in container:
            width, height = image.size
            total_pixels += _dimensions(width, height)
            if total_pixels > MAX_PIXELS:
                raise Mobile2MediaError("combined HEIF pixel count exceeds cap")
            dimensions.append((width, height))
        images = []
        for index, image in enumerate(container):
            width, height = dimensions[index]
            try:
                pil = image.to_pillow().convert("RGBA")
                rgba = pil.tobytes()
            except Exception as exc:
                raise Mobile2MediaError(f"libheif could not decode image {index}") from exc
            if pil.size != (width, height) or len(rgba) != width * height * 4:
                raise Mobile2MediaError("libheif returned an inconsistent pixel buffer")
            info = image.info if isinstance(image.info, dict) else {}
            images.append({
                "index": index, "width": width, "height": height, "mode": "RGBA", "rgba": rgba,
                "primary": bool(info.get("primary")), "bit_depth": info.get("bit_depth"),
                "chroma": info.get("chroma"),
                "thumbnail_count": len(info.get("thumbnails", [])) if isinstance(info.get("thumbnails", []), list) else 0,
                "depth_image_count": len(info.get("depth_images", [])) if isinstance(info.get("depth_images", []), list) else 0,
                "auxiliary_types": sorted(info.get("aux", {})) if isinstance(info.get("aux"), dict) else [],
            })
        return {"container": "heif", **brands, "image_count": len(images), "images": images,
                "coverage": "all top-level images; use readers_formats.py for complete item relationships"}
    except Mobile2MediaError:
        raise
    except Exception as exc:
        raise Mobile2MediaError("HEIF decode failed") from exc


def _kind(raw: bytes, requested: str) -> str:
    if requested != "auto":
        return requested
    if raw.startswith((KTX1_MAGIC, KTX2_MAGIC, AAPL_MAGIC)):
        return "ktx"
    if len(raw) >= 8 and raw[4:8] == b"ftyp":
        return "heif"
    raise Mobile2MediaError("input is not recognized as KTX/ATX or HEIF")


def _save_png(decoded: dict[str, Any], destination: Path) -> list[str]:
    try:
        from PIL import Image
    except Exception as exc:
        raise Mobile2MediaError("PNG output requires Pillow") from exc
    images = decoded.get("images") or [decoded]
    paths = []
    for index, item in enumerate(images):
        if len(images) == 1:
            path = destination
        else:
            suffix = destination.suffix or ".png"
            path = destination.with_name(f"{destination.stem}-{index}{suffix}")
        rgba = item.get("rgba")
        if not isinstance(rgba, bytes):
            raise Mobile2MediaError("decoded image has no RGBA buffer")
        try:
            image = Image.frombytes("RGBA", (item["width"], item["height"]), rgba)
            image.save(path, format="PNG")
        except Exception as exc:
            raise Mobile2MediaError(f"could not write PNG {path}") from exc
        paths.append(str(path))
    return paths


def _json_safe(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"length": len(value), "omitted": True}
    raise TypeError(type(value).__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    inspect_parser = subparsers.add_parser("inspect", help="report KTX/ATX or HEIF structure")
    inspect_parser.add_argument("input", type=Path)
    inspect_parser.add_argument("--kind", choices=("auto", "ktx", "heif"), default="auto")
    decode_parser = subparsers.add_parser("decode", help="decode pixels and write bounded PNG output")
    decode_parser.add_argument("input", type=Path)
    decode_parser.add_argument("output", type=Path)
    decode_parser.add_argument("--kind", choices=("auto", "ktx", "heif"), default="auto")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with args.input.open("rb") as handle:
            raw = handle.read(MAX_INPUT + 1)
        if len(raw) > MAX_INPUT:
            raise Mobile2MediaError("input exceeds 64 MiB cap")
        kind = _kind(raw, args.kind)
        if args.operation == "inspect":
            report = parse_ktx(raw) if kind == "ktx" else inspect_heif(raw)
        else:
            decoded = decode_ktx(raw) if kind == "ktx" else decode_heif(raw)
            report = {key: value for key, value in decoded.items() if key not in ("rgba", "images")}
            if "images" in decoded:
                report["images"] = [{key: value for key, value in image.items() if key != "rgba"}
                                    for image in decoded["images"]]
            report["outputs"] = _save_png(decoded, args.output)
        print(json.dumps(report, indent=2, sort_keys=True, default=_json_safe))
        return 0
    except (Mobile2MediaError, OSError) as exc:
        print(f"{parser.prog}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
