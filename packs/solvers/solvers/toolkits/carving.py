"""Bounded, signature-and-structure checked file carving for supplied artifacts.

The carver recognizes common foremost-style formats, but a magic match alone is never a
result.  Each object must pass its container structure, length fields, checksums where the
format provides them, and an end marker.  Slack and unallocated recovery merely restrict the
same checked carver to analyst-supplied extents/allocation maps; they do not infer filesystem
geometry or scan a device.
"""

from __future__ import annotations

import bz2
import io
import lzma
import struct
import zipfile
import zlib
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence


MAX_SCAN = 64 * 1024 * 1024
MAX_OBJECT = 128 * 1024 * 1024
MAX_OUTPUT = 256 * 1024 * 1024
MAX_CARVES = 512


@dataclass(frozen=True)
class CarvedObject:
    kind: str
    offset: int
    end: int
    data: bytes
    validation: str


@dataclass(frozen=True)
class FileExtent:
    offset: int
    logical_size: int
    allocated_size: int
    name: str = ""


@dataclass(frozen=True)
class SlackRecovery:
    extent: FileExtent
    slack_offset: int
    slack_end: int
    carvings: tuple[CarvedObject, ...]


@dataclass(frozen=True)
class UnallocatedRecovery:
    start: int
    end: int
    block_start: int
    block_end: int
    carvings: tuple[CarvedObject, ...]


@dataclass(frozen=True)
class PolyglotCandidate:
    formats: tuple[str, ...]
    carvings: tuple[CarvedObject, ...]
    relationship: str


def _u16(data: bytes, offset: int, endian: str = "<") -> int | None:
    try:
        return struct.unpack_from(endian + "H", data, offset)[0]
    except struct.error:
        return None


def _u32(data: bytes, offset: int, endian: str = "<") -> int | None:
    try:
        return struct.unpack_from(endian + "I", data, offset)[0]
    except struct.error:
        return None


def _png_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 8] != b"\x89PNG\r\n\x1a\n":
        return None
    pos, chunks, saw_idat = offset + 8, 0, False
    while pos + 12 <= len(data) and chunks < 100_000:
        length = _u32(data, pos, ">")
        if length is None or length > MAX_OBJECT or pos + 12 + length > len(data):
            return None
        kind = data[pos + 4:pos + 8]
        if len(kind) != 4 or not all(65 <= byte <= 90 or 97 <= byte <= 122 for byte in kind):
            return None
        body = data[pos + 8:pos + 8 + length]
        expected = _u32(data, pos + 8 + length, ">")
        if expected != (zlib.crc32(kind + body) & 0xFFFFFFFF):
            return None
        if chunks == 0:
            if kind != b"IHDR" or length != 13:
                return None
            width, height = struct.unpack_from(">II", body)
            if not 0 < width <= 1_000_000 or not 0 < height <= 1_000_000:
                return None
        if kind == b"IDAT":
            saw_idat = True
        pos += 12 + length
        chunks += 1
        if kind == b"IEND":
            return pos if length == 0 and saw_idat else None
    return None


def _jpeg_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 2] != b"\xff\xd8":
        return None
    pos, saw_sof, saw_sos = offset + 2, False, False
    while pos + 2 <= len(data):
        if data[pos] != 0xFF:
            return None
        while pos < len(data) and data[pos] == 0xFF:
            pos += 1
        if pos >= len(data):
            return None
        marker = data[pos]
        pos += 1
        if marker == 0xD9:
            return pos if saw_sof and saw_sos else None
        if marker in {0x01, *range(0xD0, 0xD8)}:
            continue
        if pos + 2 > len(data):
            return None
        length = _u16(data, pos, ">")
        if length is None or length < 2 or pos + length > len(data):
            return None
        if marker in set(range(0xC0, 0xD0)) - {0xC4, 0xC8, 0xCC}:
            if length < 8:
                return None
            height, width = struct.unpack_from(">HH", data, pos + 3)
            if not width or not height:
                return None
            saw_sof = True
        pos += length
        if marker != 0xDA:
            continue
        saw_sos = True
        while pos + 1 < len(data):
            found = data.find(b"\xff", pos)
            if found < 0 or found + 1 >= len(data):
                return None
            nxt = data[found + 1]
            if nxt == 0x00 or 0xD0 <= nxt <= 0xD7:
                pos = found + 2
                continue
            if nxt == 0xFF:
                pos = found + 1
                continue
            pos = found
            break
    return None


def _skip_subblocks(data: bytes, pos: int) -> int | None:
    while pos < len(data):
        size = data[pos]
        pos += 1
        if size == 0:
            return pos
        if pos + size > len(data):
            return None
        pos += size
    return None


def _gif_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 6] not in (b"GIF87a", b"GIF89a") or offset + 13 > len(data):
        return None
    width, height = struct.unpack_from("<HH", data, offset + 6)
    if not width or not height:
        return None
    packed = data[offset + 10]
    pos = offset + 13 + (3 * (2 << (packed & 7)) if packed & 0x80 else 0)
    frames = 0
    while pos < len(data):
        introducer = data[pos]
        pos += 1
        if introducer == 0x3B:
            return pos if frames else None
        if introducer == 0x21:
            if pos >= len(data):
                return None
            pos = _skip_subblocks(data, pos + 1)
            if pos is None:
                return None
            continue
        if introducer != 0x2C or pos + 9 > len(data):
            return None
        left, top, w, h = struct.unpack_from("<HHHH", data, pos)
        descriptor = data[pos + 8]
        if not w or not h or left + w > width or top + h > height:
            return None
        pos += 9 + (3 * (2 << (descriptor & 7)) if descriptor & 0x80 else 0)
        if pos >= len(data) or not 2 <= data[pos] <= 12:
            return None
        pos = _skip_subblocks(data, pos + 1)
        if pos is None:
            return None
        frames += 1
    return None


def _zip_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 4] not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return None
    limit = min(len(data), offset + MAX_OBJECT)
    pos = offset
    while True:
        eocd = data.find(b"PK\x05\x06", pos, limit)
        if eocd < 0 or eocd + 22 > limit:
            return None
        comment = _u16(data, eocd + 20)
        if comment is None:
            return None
        end = eocd + 22 + comment
        pos = eocd + 1
        if end > limit:
            continue
        candidate = data[offset:end]
        try:
            with zipfile.ZipFile(io.BytesIO(candidate)) as archive:
                infos = archive.infolist()
                # An empty archive (EOCD only, no members) is a valid ZIP written by zipfile.
                if (sum(info.file_size for info in infos) > MAX_OUTPUT
                        or any(info.file_size > MAX_OUTPUT for info in infos)
                        or archive.testzip() is not None):
                    continue
                # Reject central-directory offsets that point outside the carved candidate.
                if any(info.header_offset < 0 or info.header_offset + 30 > len(candidate) for info in infos):
                    continue
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, zlib.error):
            continue
        return end


def _pdf_end(data: bytes, offset: int) -> int | None:
    if offset + 8 > len(data) or data[offset:offset + 5] != b"%PDF-" or data[offset + 5:offset + 8] not in {
        b"1.0", b"1.1", b"1.2", b"1.3", b"1.4", b"1.5", b"1.6", b"1.7", b"2.0",
    }:
        return None
    limit = min(len(data), offset + MAX_OBJECT)
    pos = offset + 8
    while True:
        eof = data.find(b"%%EOF", pos, limit)
        if eof < 0:
            return None
        end = eof + 5
        while end < limit and data[end] in b"\r\n \t":
            end += 1
        body = data[offset:end]
        if re_search(rb"\b\d+\s+\d+\s+obj\b", body) and re_search(rb"startxref\s+\d+\s+%%EOF", body):
            return end
        pos = eof + 1


def re_search(pattern: bytes, data: bytes) -> bool:
    import re
    return re.search(pattern, data, re.S) is not None


def _stream_end(data: bytes, offset: int, kind: str, zdict: bytes | None = None) -> int | None:
    chunk = data[offset:min(len(data), offset + MAX_OBJECT)]
    try:
        if kind == "gzip":
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            output = decoder.decompress(chunk, MAX_OUTPUT + 1)
            if len(output) > MAX_OUTPUT or not decoder.eof:
                return None
            return offset + len(chunk) - len(decoder.unused_data)
        if kind == "zlib":
            decoder = zlib.decompressobj(zdict=zdict) if zdict is not None else zlib.decompressobj()
            output = decoder.decompress(chunk, MAX_OUTPUT + 1)
            if len(output) > MAX_OUTPUT or not decoder.eof:
                return None
            return offset + len(chunk) - len(decoder.unused_data)
        if kind == "bzip2":
            decoder = bz2.BZ2Decompressor()
            output = decoder.decompress(chunk, max_length=MAX_OUTPUT + 1)
            if len(output) > MAX_OUTPUT or not decoder.eof:
                return None
            return offset + len(chunk) - len(decoder.unused_data)
        if kind == "xz":
            decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=MAX_OUTPUT * 4)
            output = decoder.decompress(chunk, max_length=MAX_OUTPUT + 1)
            if len(output) > MAX_OUTPUT or not decoder.eof:
                return None
            return offset + len(chunk) - len(decoder.unused_data)
    except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
        return None
    return None


def _riff_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 4] != b"RIFF" or offset + 12 > len(data):
        return None
    size = _u32(data, offset + 4)
    form = data[offset + 8:offset + 12]
    if size is None or size < 4 or form not in {b"WAVE", b"AVI ", b"WEBP"}:
        return None
    end = offset + 8 + size
    if end > len(data) or end - offset > MAX_OBJECT:
        return None
    pos, chunks, names, avi_header = offset + 12, 0, set(), False
    while pos + 8 <= end:
        name = data[pos:pos + 4]
        length = _u32(data, pos + 4)
        if length is None or pos + 8 + length > end:
            return None
        names.add(name)
        if name == b"LIST" and length >= 4 and data[pos + 8:pos + 12] == b"hdrl":
            avi_header = True
        pos += 8 + length + (length & 1)
        chunks += 1
    if pos != end or not chunks:
        return None
    if form == b"WAVE" and not {b"fmt ", b"data"} <= names:
        return None
    if form == b"WEBP" and not any(name in names for name in (b"VP8 ", b"VP8L", b"VP8X")):
        return None
    if form == b"AVI " and not avi_header:
        return None
    return end


def _bmp_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 2] != b"BM" or offset + 26 > len(data):
        return None
    size = _u32(data, offset + 2)
    pixel_offset = _u32(data, offset + 10)
    dib = _u32(data, offset + 14)
    if size is None or pixel_offset is None or dib not in {12, 40, 52, 56, 64, 108, 124}:
        return None
    end = offset + size
    if not 26 <= pixel_offset < size or end > len(data) or size > MAX_OBJECT:
        return None
    if dib == 12:
        width, height = struct.unpack_from("<HH", data, offset + 18)
    else:
        width, height = struct.unpack_from("<ii", data, offset + 18)
    planes, bpp = struct.unpack_from("<HH", data, offset + (22 if dib == 12 else 26))
    return end if width > 0 and height != 0 and planes == 1 and bpp in {1, 4, 8, 16, 24, 32} else None


def _elf_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 4] != b"\x7fELF" or offset + 52 > len(data):
        return None
    elf_class, byte_order = data[offset + 4], data[offset + 5]
    if elf_class not in (1, 2) or byte_order not in (1, 2) or data[offset + 6] != 1:
        return None
    endian = "<" if byte_order == 1 else ">"
    try:
        if elf_class == 1:
            ehsize, phoff, shoff = struct.unpack_from(endian + "HII", data, offset + 40)[0], _u32(data, offset + 28, endian), _u32(data, offset + 32, endian)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHH", data, offset + 42)
            minimum_header, ph_min, sh_min = 52, 32, 40
        else:
            phoff, shoff = struct.unpack_from(endian + "QQ", data, offset + 32)
            ehsize, phentsize, phnum, shentsize, shnum = struct.unpack_from(endian + "HHHHH", data, offset + 52)
            minimum_header, ph_min, sh_min = 64, 56, 64
    except (struct.error, TypeError):
        return None
    if ehsize < minimum_header or (not phnum and not shnum):
        return None
    maximum = ehsize
    if phnum:
        if phoff is None or phentsize < ph_min or phnum > 65535 or phoff + phentsize * phnum > len(data) - offset:
            return None
        for index in range(phnum):
            pos = offset + phoff + index * phentsize
            try:
                if elf_class == 1:
                    file_offset = struct.unpack_from(endian + "I", data, pos + 4)[0]
                    file_size = struct.unpack_from(endian + "I", data, pos + 16)[0]
                else:
                    file_offset = struct.unpack_from(endian + "Q", data, pos + 8)[0]
                    file_size = struct.unpack_from(endian + "Q", data, pos + 32)[0]
            except struct.error:
                return None
            maximum = max(maximum, file_offset + file_size)
    if shnum:
        if shoff is None or shentsize < sh_min or shnum > 65535 or shoff + shentsize * shnum > len(data) - offset:
            return None
        for index in range(shnum):
            pos = offset + shoff + index * shentsize
            try:
                section_type = struct.unpack_from(endian + "I", data, pos + 4)[0]
                file_offset, file_size = (struct.unpack_from(endian + "II", data, pos + 16) if elf_class == 1
                                          else struct.unpack_from(endian + "QQ", data, pos + 24))
            except struct.error:
                return None
            if section_type != 8:  # SHT_NOBITS (.bss) occupies no bytes in the file.
                maximum = max(maximum, file_offset + file_size)
    end = offset + maximum
    return end if maximum <= MAX_OBJECT and end <= len(data) else None


def _pe_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 2] != b"MZ" or offset + 0x40 > len(data):
        return None
    pe_offset = _u32(data, offset + 0x3C)
    if pe_offset is None or pe_offset < 0x40 or pe_offset > MAX_OBJECT or offset + pe_offset + 24 > len(data):
        return None
    pe = offset + pe_offset
    if data[pe:pe + 4] != b"PE\x00\x00":
        return None
    sections = _u16(data, pe + 6)
    optional_size = _u16(data, pe + 20)
    if sections is None or optional_size is None or not 1 <= sections <= 96:
        return None
    optional = pe + 24
    magic = _u16(data, optional)
    if magic not in (0x10B, 0x20B) or optional_size < (96 if magic == 0x10B else 112):
        return None
    table = optional + optional_size
    if table + sections * 40 > len(data):
        return None
    headers = _u32(data, optional + 60) or 0
    maximum = headers
    for index in range(sections):
        pos = table + index * 40
        raw_size, raw_offset = struct.unpack_from("<II", data, pos + 16)
        if raw_size and raw_offset < headers:
            return None
        maximum = max(maximum, raw_offset + raw_size)
    end = offset + maximum
    return end if maximum and maximum <= MAX_OBJECT and end <= len(data) else None


def _sevenzip_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 6] != b"7z\xbc\xaf\x27\x1c" or offset + 32 > len(data):
        return None
    if data[offset + 6] != 0 or data[offset + 7] > 4:
        return None
    start_crc = _u32(data, offset + 8)
    if start_crc != (zlib.crc32(data[offset + 12:offset + 32]) & 0xFFFFFFFF):
        return None
    next_offset, next_size, next_crc = struct.unpack_from("<QQI", data, offset + 12)
    if next_size == 0 or next_offset > MAX_OBJECT or next_size > MAX_OBJECT:
        return None
    header = offset + 32 + next_offset
    end = header + next_size
    if end > len(data) or end - offset > MAX_OBJECT:
        return None
    return end if (zlib.crc32(data[header:end]) & 0xFFFFFFFF) == next_crc else None


def _sqlite_end(data: bytes, offset: int) -> int | None:
    if data[offset:offset + 16] != b"SQLite format 3\x00" or offset + 100 >= len(data):
        return None
    page_size = _u16(data, offset + 16, ">")
    if page_size == 1:
        page_size = 65536
    if page_size is None or page_size < 512 or page_size > 65536 or page_size & (page_size - 1):
        return None
    if data[offset + 18] not in (1, 2) or data[offset + 19] not in (1, 2):
        return None
    if data[offset + 21:offset + 24] != b"\x40\x20\x20":
        return None
    pages = _u32(data, offset + 28, ">")
    schema = _u32(data, offset + 44, ">")
    encoding = _u32(data, offset + 56, ">")
    if not pages or schema not in (1, 2, 3, 4) or encoding not in (1, 2, 3):
        return None
    end = offset + pages * page_size
    if end > len(data) or end - offset > MAX_OBJECT or data[offset + 100] not in (2, 5, 10, 13):
        return None
    return end


def _zlib_magics() -> tuple[tuple[str, bytes, Callable[[bytes, int], int | None], str], ...]:
    """Every RFC 1950 CMF/FLG pair for deflate, including FDICT variants.

    CINFO 0..7 selects a 256-byte through 32-KiB window and FLEVEL 0..3 is advisory;
    FCHECK is derived so the 16-bit header is divisible by 31.  FDICT streams are recognized
    but only accepted when ``carve_all`` receives the exact dictionary named by their Adler ID.
    """

    entries = []
    for cinfo in range(8):
        cmf = (cinfo << 4) | 8
        for flevel in range(4):
            for dictionary_flag in (0, 0x20):
                flg_base = (flevel << 6) | dictionary_flag
                fcheck = (-((cmf << 8) | flg_base)) % 31
                magic = bytes((cmf, flg_base | fcheck))
                entries.append(("zlib", magic, lambda d, o: _stream_end(d, o, "zlib"),
                                "RFC 1950 CMF/FLG, optional dictionary ID, Adler-32 and EOF"))
    return tuple(entries)


_ZLIB_MAGICS = _zlib_magics()


_MAGICS: tuple[tuple[str, bytes, Callable[[bytes, int], int | None], str], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n", _png_end, "chunk CRCs, IHDR/IDAT/IEND"),
    ("jpeg", b"\xff\xd8\xff", _jpeg_end, "marker lengths, SOF/SOS/EOI"),
    ("gif", b"GIF8", _gif_end, "logical screen, image blocks, trailer"),
    ("zip", b"PK\x03\x04", _zip_end, "EOCD, central directory and member CRCs"),
    ("zip", b"PK\x05\x06", _zip_end, "EOCD-only empty archive"),
    ("pdf", b"%PDF-", _pdf_end, "version, object, startxref and EOF"),
    ("gzip", b"\x1f\x8b\x08", lambda d, o: _stream_end(d, o, "gzip"), "deflate stream CRC and EOF"),
    ("bzip2", b"BZh", lambda d, o: _stream_end(d, o, "bzip2"), "bzip2 block CRC and EOF"),
    ("xz", b"\xfd7zXZ\x00", lambda d, o: _stream_end(d, o, "xz"), "XZ index/footer check and EOF"),
) + _ZLIB_MAGICS + (
    ("riff", b"RIFF", _riff_end, "RIFF size and complete chunk walk"),
    ("bmp", b"BM", _bmp_end, "file/DIB/pixel bounds"),
    ("elf", b"\x7fELF", _elf_end, "ELF header and segment/section file bounds"),
    ("pe", b"MZ", _pe_end, "DOS/PE headers and section file bounds"),
    ("7z", b"7z\xbc\xaf\x27\x1c", _sevenzip_end, "7z start-header and next-header CRCs"),
    ("sqlite", b"SQLite format 3\x00", _sqlite_end, "SQLite header fields, page count and root b-tree page"),
)


def _specific_kind(kind: str, data: bytes, offset: int) -> str:
    if kind == "riff":
        return {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}.get(data[offset + 8:offset + 12], "riff")
    return kind


def carve_all(
    data: object,
    *,
    kinds: Iterable[str] | None = None,
    max_carves: int = MAX_CARVES,
    zlib_dictionaries: Sequence[bytes] = (),
) -> tuple[CarvedObject, ...]:
    """Carve every validated object from supplied bytes, including embedded objects."""

    if (not isinstance(data, (bytes, bytearray, memoryview)) or not isinstance(max_carves, int)
            or isinstance(max_carves, bool) or not 1 <= max_carves <= MAX_CARVES
            or not isinstance(zlib_dictionaries, Sequence) or len(zlib_dictionaries) > 64):
        return ()
    raw = bytes(data)
    if not raw or len(raw) > MAX_SCAN:
        return ()
    if kinds is None:
        allowed = None
    else:
        try:
            allowed = {str(kind).lower() for kind in kinds}
        except TypeError:
            return ()
    dictionaries: dict[int, bytes] = {}
    for dictionary in zlib_dictionaries:
        if not isinstance(dictionary, (bytes, bytearray, memoryview)) or not 0 < len(dictionary) <= 32768:
            return ()
        value = bytes(dictionary)
        dictionaries[zlib.adler32(value) & 0xFFFFFFFF] = value
    out, seen = [], set()
    for base_kind, magic, validator, validation in _MAGICS:
        pos = 0
        while len(out) < max_carves:
            offset = raw.find(magic, pos)
            if offset < 0:
                break
            pos = offset + 1
            kind = _specific_kind(base_kind, raw, offset)
            if allowed is not None and kind not in allowed and base_kind not in allowed:
                continue
            try:
                if base_kind == "zlib" and raw[offset + 1] & 0x20:
                    if offset + 6 > len(raw):
                        end = None
                    else:
                        dictionary = dictionaries.get(int.from_bytes(raw[offset + 2:offset + 6], "big"))
                        end = _stream_end(raw, offset, "zlib", dictionary) if dictionary is not None else None
                else:
                    end = validator(raw, offset)
            except (ValueError, OverflowError, MemoryError, struct.error):
                end = None
            if end is None or not offset < end <= len(raw) or end - offset > MAX_OBJECT:
                continue
            key = (kind, offset, end)
            if key in seen:
                continue
            seen.add(key)
            out.append(CarvedObject(kind, offset, end, raw[offset:end], validation))
    return tuple(sorted(out, key=lambda item: (item.offset, item.end, item.kind)))


def detect_polyglot(data: object) -> PolyglotCandidate | None:
    """Identify a validated same-start or appended multi-format polyglot."""

    if not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    raw = bytes(data)
    objects = carve_all(raw)
    primary = [item for item in objects if item.offset == 0]
    if not primary:
        return None
    same_start = [item for item in primary if item.kind != primary[0].kind]
    if same_start:
        chosen = tuple([primary[0], *same_start])
        return PolyglotCandidate(tuple(dict.fromkeys(item.kind for item in chosen)), chosen, "multiple validated formats start at byte zero")
    appended = [item for item in objects if item.offset >= primary[0].end and item.end == len(raw) and item.kind != primary[0].kind]
    if appended:
        chosen = (primary[0], appended[0])
        return PolyglotCandidate((chosen[0].kind, chosen[1].kind), chosen, "validated format appended after the primary object's end")
    # Containers are expected to hold other files, so do not mislabel ZIP/7z nesting.  A second
    # independently valid format inside a non-container primary (notably PDF+ZIP) is meaningful.
    if primary[0].kind not in {"zip", "7z"}:
        embedded = [item for item in objects if 0 < item.offset and item.end <= primary[0].end and item.kind != primary[0].kind]
        if embedded:
            chosen = (primary[0], embedded[0])
            return PolyglotCandidate((chosen[0].kind, chosen[1].kind), chosen, "validated format embedded within the primary object's byte range")
    return None


def _shift_carving(carving: CarvedObject, delta: int) -> CarvedObject:
    return CarvedObject(carving.kind, carving.offset + delta, carving.end + delta, carving.data, carving.validation)


def carve_file_slack(image: object, extents: Sequence[FileExtent]) -> tuple[SlackRecovery, ...]:
    """Carve validated objects only from explicit logical-to-allocated file slack ranges."""

    if (not isinstance(image, (bytes, bytearray, memoryview)) or not isinstance(extents, Sequence)
            or len(extents) > 1_000_000):
        return ()
    raw = bytes(image)
    out = []
    for extent in extents:
        if not isinstance(extent, FileExtent) or extent.offset < 0 or extent.logical_size < 0 or extent.allocated_size < extent.logical_size:
            continue
        start = extent.offset + extent.logical_size
        end = extent.offset + extent.allocated_size
        if start >= end or end > len(raw):
            continue
        slack = raw[start:end]
        carvings = tuple(_shift_carving(item, start) for item in carve_all(slack))
        if carvings:
            out.append(SlackRecovery(extent, start, end, carvings))
    return tuple(out)


def carve_unallocated(image: object, allocation_bitmap: Sequence[bool], *, block_size: int) -> tuple[UnallocatedRecovery, ...]:
    """Carve validated objects from contiguous blocks explicitly marked unallocated (False)."""

    if (not isinstance(image, (bytes, bytearray, memoryview)) or not isinstance(block_size, int)
            or isinstance(block_size, bool) or not 1 <= block_size <= 16 * 1024 * 1024
            or not isinstance(allocation_bitmap, Sequence)):
        return ()
    raw = bytes(image)
    blocks = (len(raw) + block_size - 1) // block_size
    if len(allocation_bitmap) != blocks or any(type(value) is not bool for value in allocation_bitmap):
        return ()
    out, index = [], 0
    while index < blocks:
        if allocation_bitmap[index]:
            index += 1
            continue
        first = index
        while index < blocks and not allocation_bitmap[index]:
            index += 1
        start, end = first * block_size, min(len(raw), index * block_size)
        carvings = tuple(_shift_carving(item, start) for item in carve_all(raw[start:end]))
        if carvings:
            out.append(UnallocatedRecovery(start, end, first, index, carvings))
    return tuple(out)


__all__ = [
    "CarvedObject", "FileExtent", "PolyglotCandidate", "SlackRecovery",
    "UnallocatedRecovery", "carve_all", "carve_file_slack", "carve_unallocated",
    "detect_polyglot",
]
