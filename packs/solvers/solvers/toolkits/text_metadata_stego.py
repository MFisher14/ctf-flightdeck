"""Checked offline extraction of text and metadata steganography.

The broad repository already knows how to validate/carve file containers and how to parse
PDF/OOXML document structure.  This module deliberately composes those readers.  It adds the
hidden channels they do not expose: zero-width bits, Unicode tag runs, explicit homoglyph
alphabets, trailing whitespace/SNOW-style groups, archive/document metadata, and bytes beyond a
validated container boundary.  It never opens a path, launches a program, renders a document, or
uses a network service.

Text channels are all-or-nothing.  A bit channel must be byte aligned, use both symbols, and
produce either a strongly recognizable payload (complete printable UTF-8/flag or a wholly
validated carved object) or match an analyst-supplied CRC-32.  Container metadata is returned
only after the enclosing ZIP, PDF, or OOXML package has passed its existing complete structural
checks.  Malformed, ambiguous, oversized, or partial inputs return ``None``/an empty tuple.
"""

from __future__ import annotations

import io
import re
import struct
import unicodedata
import zipfile
import zlib
from dataclasses import dataclass
from typing import Mapping, Sequence
from xml.etree import ElementTree as ET

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

try:  # Package import.
    from . import maldoc as _maldoc
    from . import carving as _carving
    from . import document_forensics as _documents
except ImportError:  # Tests place solvers/toolkits directly on sys.path.
    import maldoc as _maldoc  # type: ignore
    import carving as _carving  # type: ignore
    import document_forensics as _documents  # type: ignore


MAX_TEXT_CHARS = 8 * 1024 * 1024
MAX_BITS = 32 * 1024 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
MAX_DOCUMENT = 64 * 1024 * 1024
MAX_FIELD = 2 * 1024 * 1024
MAX_FIELDS = 4096
MAX_MEMBERS = 10_000
MAX_TOTAL_UNCOMPRESSED = 256 * 1024 * 1024
MAX_RATIO = 200

_ZERO_WIDTH_CONTROLS = frozenset(
    {"\u200b", "\u200c", "\u200d", "\u2060", "\u2061", "\u2062", "\u2063", "\ufeff"}
)
_FLAG = flagfmt.BYTES
_ALLOWED_ZIP_FLAGS = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 11)
_PDF_RESOLVE_FAILED = object()


@dataclass(frozen=True, slots=True)
class HiddenPayload:
    """Bytes recovered from one completely checked hidden channel."""

    method: str
    data: bytes
    carrier: str
    evidence: tuple[str, ...]
    crc32: int


@dataclass(frozen=True, slots=True)
class MetadataPayload:
    """A non-empty value from a structurally validated metadata/comment field."""

    container: str
    field: str
    data: bytes
    source: str
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PolyglotPayload:
    """Validated formats and exact byte ranges reported by the existing carver."""

    relationship: str
    formats: tuple[str, ...]
    parts: tuple[HiddenPayload, ...]


def _runtime_limit(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


def _binary(value: object, maximum: object) -> bytes | None:
    """Copy one concrete bytes-like value only after checking its byte extent."""

    limit = _runtime_limit(maximum)
    if limit is None or type(value) not in (bytes, bytearray, memoryview):
        return None
    try:
        size = value.nbytes if type(value) is memoryview else len(value)
    except (TypeError, ValueError, BufferError, OverflowError):
        return None
    if not 0 < size <= limit:
        return None
    try:
        raw = bytes(value)
    except (TypeError, ValueError, BufferError, OverflowError, MemoryError):
        return None
    return raw if len(raw) == size else None


def _blob(value: object, *, maximum: int | None = None) -> bytes | None:
    # Resolve the module constant at call time so an analyst/test lowering the cap cannot be
    # bypassed by the default value captured when the function was defined.
    return _binary(value, MAX_DOCUMENT if maximum is None else maximum)


def _text(value: object) -> str | None:
    limit = _runtime_limit(MAX_TEXT_CHARS)
    if limit is None:
        return None
    if type(value) is str:
        text = value
    elif type(value) in (bytes, bytearray, memoryview):
        raw = _binary(value, limit * 4)
        if raw is None:
            return None
        try:
            text = raw.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
    else:
        return None
    if not 0 < len(text) <= limit:
        return None
    # Python ``str`` can be manually constructed with lone surrogates even though strict UTF-8
    # cannot encode them.  Such a value has no canonical interchange representation and is not a
    # trustworthy Unicode carrier.
    if any(0xD800 <= ord(character) <= 0xDFFF for character in text):
        return None
    return text


def _checksum(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        return -1
    return value


def _unsupported_invisible(character: str, alphabet: frozenset[str]) -> bool:
    """Whether a non-alphabet character can silently carry Unicode state."""

    if character in alphabet:
        return False
    code = ord(character)
    category = unicodedata.category(character)
    # Ordinary line separators are legitimate cover text.  Other C0/C1 controls and every
    # unselected format control can form a second, ambiguous invisible channel.
    if category == "Cf" or (category == "Cc" and character not in "\t\n\r"):
        return True
    # These non-Cf code points are also rendering controls with no standalone glyph.
    return (
        code == 0x034F
        or 0x17B4 <= code <= 0x17B5
        or 0x180B <= code <= 0x180F
        or 0xFE00 <= code <= 0xFE0F
        or 0xE0100 <= code <= 0xE01EF
    )


def _exact_carved(data: bytes) -> bool:
    if not data or len(data) > _carving.MAX_SCAN:
        return False
    try:
        return any(item.offset == 0 and item.end == len(data) for item in _carving.carve_all(data))
    except Exception:
        return False


def _credible(data: bytes) -> bool:
    """Conservative proof gate for an otherwise unchecksummed text channel."""

    payload_limit = _runtime_limit(MAX_PAYLOAD)
    if payload_limit is None or not 2 <= len(data) <= payload_limit:
        return False
    if _FLAG.fullmatch(data):
        return True
    if _exact_carved(data):
        return True
    try:
        value = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    if len(value) < 4 or not value.strip():
        return False
    return all(character.isprintable() or character in "\r\n\t" for character in value)


def _finish_bits(
    bits: Sequence[int],
    *,
    method: str,
    carrier: str,
    bit_order: str,
    expected_crc32: object,
    extra: Sequence[str] = (),
) -> HiddenPayload | None:
    bit_limit = _runtime_limit(MAX_BITS)
    payload_limit = _runtime_limit(MAX_PAYLOAD)
    if bit_limit is None or payload_limit is None \
            or type(bit_order) is not str or bit_order not in {"msb", "lsb"} \
            or not 16 <= len(bits) <= min(bit_limit, payload_limit * 8) or len(bits) % 8:
        return None
    if set(bits) != {0, 1}:
        return None
    output = bytearray()
    for offset in range(0, len(bits), 8):
        octet = bits[offset:offset + 8]
        if bit_order == "lsb":
            octet = tuple(reversed(octet))
        value = 0
        for bit in octet:
            value = (value << 1) | bit
        output.append(value)
    raw = bytes(output)
    expected = _checksum(expected_crc32)
    if expected == -1:
        return None
    actual = zlib.crc32(raw) & 0xFFFFFFFF
    if expected is not None:
        if actual != expected:
            return None
        check = f"CRC-32 {actual:08x} matched supplied value"
    elif _credible(raw):
        check = "complete byte-aligned channel produced a strongly recognized payload"
    else:
        return None
    return HiddenPayload(
        method,
        raw,
        carrier,
        (f"{len(bits)} bits", f"bit order {bit_order}", check, *tuple(extra)),
        actual,
    )


def decode_zero_width(
    data: object,
    *,
    zero: str = "\u200b",
    one: str = "\u200c",
    bit_order: str = "msb",
    expected_crc32: int | None = None,
) -> HiddenPayload | None:
    """Decode one explicit two-symbol zero-width bit channel.

    The default alphabet is ZERO WIDTH SPACE/ZERO WIDTH NON-JOINER.  Other invisible format
    controls make the alphabet ambiguous and reject the entire carrier; callers may instead name
    that exact pair explicitly.  Visible cover text is ignored.
    """

    text = _text(data)
    if text is None or type(zero) is not str or type(one) is not str \
            or len(zero) != 1 or len(one) != 1 or zero == one:
        return None
    if zero not in _ZERO_WIDTH_CONTROLS or one not in _ZERO_WIDTH_CONTROLS:
        return None
    alphabet = frozenset((zero, one))
    if any(_unsupported_invisible(character, alphabet) for character in text):
        return None
    bits = tuple(0 if character == zero else 1 for character in text if character in alphabet)
    return _finish_bits(
        bits,
        method="zero-width",
        carrier="unicode-text",
        bit_order=bit_order,
        expected_crc32=expected_crc32,
        extra=(f"alphabet U+{ord(zero):04X}/U+{ord(one):04X}",),
    )


def decode_unicode_tags(data: object) -> tuple[HiddenPayload, ...]:
    """Decode complete Unicode tag-character runs terminated by CANCEL TAG.

    Both deprecated LANGUAGE TAG-prefixed runs and the modern emoji-style sequence of tag ASCII
    characters are recognized.  Any malformed/unterminated tag control causes a fail-closed empty
    result; an ordinary black flag with subdivision tags is therefore reported as its genuine tag
    value rather than guessed to be a different message.
    """

    text = _text(data)
    payload_limit = _runtime_limit(MAX_PAYLOAD)
    result_limit = _runtime_limit(MAX_FIELDS)
    if text is None or payload_limit is None or result_limit is None:
        return ()
    output: list[HiddenPayload] = []
    index = 0
    saw_tag_control = False
    while index < len(text):
        code = ord(text[index])
        if code == 0xE0001 or 0xE0020 <= code <= 0xE007E:
            saw_tag_control = True
            prefixed = code == 0xE0001
            if prefixed:
                index += 1
            payload = bytearray()
            while index < len(text) and 0xE0020 <= ord(text[index]) <= 0xE007E:
                payload.append(ord(text[index]) - 0xE0000)
                index += 1
                if len(payload) > payload_limit:
                    return ()
            if index >= len(text) or ord(text[index]) != 0xE007F or not payload:
                return ()
            index += 1
            raw = bytes(payload)
            if not _credible(raw):
                return ()
            output.append(HiddenPayload(
                "unicode-tags",
                raw,
                "unicode-text",
                (
                    "LANGUAGE TAG prefix present" if prefixed else "tag ASCII run",
                    "terminated by U+E007F CANCEL TAG",
                    f"{len(raw)} tag bytes",
                ),
                zlib.crc32(raw) & 0xFFFFFFFF,
            ))
            if len(output) > result_limit:
                return ()
            continue
        if 0xE0000 <= code <= 0xE007F:
            saw_tag_control = True
            return ()
        index += 1
    return tuple(output) if saw_tag_control else ()


def decode_homoglyphs(
    data: object,
    pairs: Sequence[tuple[str, str]],
    *,
    bit_order: str = "msb",
    expected_crc32: int | None = None,
) -> HiddenPayload | None:
    """Decode a caller-supplied zero/one homoglyph alphabet.

    A carrier cannot safely reveal which visually similar code point means zero.  Consequently the
    mapping is never guessed: ``pairs`` explicitly lists ``(zero, one)`` code points.  Every code
    point may occur in only one pair, both bit values must occur, and the resulting bytes still
    pass the common payload/CRC gate.
    """

    text = _text(data)
    if text is None or type(pairs) not in (tuple, list):
        return None
    try:
        pair_count = len(pairs)
    except Exception:
        return None
    if not 1 <= pair_count <= 128:
        return None
    alphabet: dict[str, int] = {}
    descriptions: list[str] = []
    for index in range(pair_count):
        try:
            pair = pairs[index]
        except Exception:
            return None
        if type(pair) is not tuple or len(pair) != 2:
            return None
        zero, one = pair
        if type(zero) is not str or type(one) is not str or len(zero) != 1 or len(one) != 1 or zero == one:
            return None
        if zero in alphabet or one in alphabet:
            return None
        alphabet[zero], alphabet[one] = 0, 1
        descriptions.append(f"U+{ord(zero):04X}/U+{ord(one):04X}")
    bits = tuple(alphabet[character] for character in text if character in alphabet)
    return _finish_bits(
        bits,
        method="homoglyph",
        carrier="unicode-text",
        bit_order=bit_order,
        expected_crc32=expected_crc32,
        extra=("explicit alphabet " + ",".join(descriptions),),
    )


def _trailing_runs(text: str) -> tuple[str, ...] | None:
    bit_limit = _runtime_limit(MAX_BITS)
    if bit_limit is None:
        return None
    normalized = text.replace("\r\n", "\n")
    if "\r" in normalized:
        return None
    runs: list[str] = []
    total = 0
    for line in normalized.split("\n"):
        match = re.search(r"[ \t]+\Z", line)
        if match:
            run = match.group()
            total += len(run)
            if total > bit_limit:
                return None
            runs.append(run)
    return tuple(runs)


def decode_whitespace_bits(
    data: object,
    *,
    zero: str = " ",
    one: str = "\t",
    bit_order: str = "msb",
    expected_crc32: int | None = None,
) -> HiddenPayload | None:
    """Decode every trailing space/tab in line order as a checked binary channel."""

    text = _text(data)
    if text is None or type(zero) is not str or type(one) is not str \
            or {zero, one} != {" ", "\t"}:
        return None
    runs = _trailing_runs(text)
    if not runs:
        return None
    bits = tuple(0 if character == zero else 1 for run in runs for character in run)
    return _finish_bits(
        bits,
        method="trailing-whitespace",
        carrier="text-lines",
        bit_order=bit_order,
        expected_crc32=expected_crc32,
        extra=(f"{len(runs)} line(s) carried trailing whitespace",),
    )


def decode_snow(data: object) -> HiddenPayload | None:
    """Decode the uncompressed, unencrypted SNOW three-bit trailing-whitespace channel.

    The author's format starts with one tab, represents bits least-significant first in each
    space count, and requires neither a final tab nor a NUL byte.  Packing bits must be zero.
    The previously supported NUL-terminated, MSB-first variant retains priority when its
    more restrictive framing matches, preserving existing decoded values.
    Compressed/encrypted data without a credible plaintext is not returned as proven bytes.
    """

    legacy = _decode_snow_legacy(data)
    return legacy if legacy is not None else _decode_snow_standard(data)


def _decode_snow_standard(data: object) -> HiddenPayload | None:
    """Matthew Kwan's encode.c framing and bit order, without running a decoder."""
    text = _text(data)
    bit_limit = _runtime_limit(MAX_BITS)
    payload_limit = _runtime_limit(MAX_PAYLOAD)
    if text is None or bit_limit is None or payload_limit is None:
        return None
    runs = _trailing_runs(text)
    if not runs:
        return None
    started = False
    values: list[int] = []
    for run in runs:
        if not started:
            if not run.startswith("\t"):
                continue  # Trailing spaces before the start marker are cover text.
            started = True
            run = run[1:]
        spaces = 0
        for character in run:
            if character == " ":
                spaces += 1
                if spaces > 7:
                    return None
            else:
                values.append(spaces)
                spaces = 0
        if spaces:
            values.append(spaces)  # A positive last group needs no terminating tab.
        if len(values) * 3 > min(bit_limit, payload_limit * 8 + 2):
            return None
    if not values:
        return None
    bits = "".join(f"{value:03b}"[::-1] for value in values)
    padding = len(bits) % 8
    if padding > 2 or (padding and "1" in bits[-padding:]):
        return None
    end = len(bits) - padding
    raw = bytes(int(bits[offset:offset + 8], 2) for offset in range(0, end, 8))
    if not _credible(raw):
        return None
    return HiddenPayload(
        "snow-uncompressed", raw, "text-lines",
        ("single initial tab marker", f"{len(values)} LSB-first three-bit groups",
         "zero-only packing verified; no NUL terminator required"),
        zlib.crc32(raw) & 0xFFFFFFFF,
    )


def _decode_snow_legacy(data: object) -> HiddenPayload | None:
    """Compatibility with the old per-line-tab, MSB-first, NUL-terminated variant.

    This is not the author's SNOW wire format, but remains a supported legacy channel.
    """

    text = _text(data)
    bit_limit = _runtime_limit(MAX_BITS)
    if text is None or bit_limit is None:
        return None
    runs = _trailing_runs(text)
    if not runs:
        return None
    # Each carrier line has its own tab separator between visible cover and encoded groups.
    if any(not run.startswith("\t") for run in runs):
        return None
    stream = "".join(run[1:] for run in runs)
    if not stream or len(stream) > bit_limit:
        return None
    position = 0
    values: list[int] = []
    while position < len(stream):
        spaces = 0
        while position < len(stream) and stream[position] == " ":
            spaces += 1
            position += 1
        if spaces > 7 or position >= len(stream) or stream[position] != "\t":
            return None
        values.append(spaces)
        position += 1
    if not values or len(set(values)) < 2:
        return None
    bits = "".join(f"{value:03b}" for value in values)
    candidates: list[bytes] = []
    for trim in range(3):
        if trim and "1" in bits[-trim:]:
            continue
        candidate_bits = bits[:-trim] if trim else bits
        if not candidate_bits or len(candidate_bits) % 8:
            continue
        raw = bytes(int(candidate_bits[offset:offset + 8], 2) for offset in range(0, len(candidate_bits), 8))
        nul = raw.find(b"\x00")
        if nul < 2 or any(raw[nul + 1:]) or not _credible(raw[:nul]):
            continue
        if raw[:nul] not in candidates:
            candidates.append(raw[:nul])
    if len(candidates) != 1:
        return None
    raw = candidates[0]
    return HiddenPayload(
        "snow-uncompressed",
        raw,
        "text-lines",
        (
            "legacy MSB-first, per-line tab variant",
            f"{len(runs)} carrier line(s), {len(values)} complete three-bit groups",
            "NUL terminator and zero-only packing verified",
        ),
        zlib.crc32(raw) & 0xFFFFFFFF,
    )


def _safe_zip(data: bytes) -> zipfile.ZipFile | None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, ValueError, EOFError, MemoryError):
        return None
    member_limit = _runtime_limit(MAX_MEMBERS)
    total_limit = _runtime_limit(MAX_TOTAL_UNCOMPRESSED)
    field_limit = _runtime_limit(MAX_FIELD)
    ratio_limit = _runtime_limit(MAX_RATIO)
    if (member_limit is None or total_limit is None or field_limit is None or ratio_limit is None
            or not infos or len(infos) > member_limit):
        archive.close()
        return None
    seen: set[str] = set()
    total = 0
    for info in infos:
        name = info.filename
        normalized = name.replace("\\", "/")
        if not name or normalized.startswith("/") or "\x00" in name \
                or any(part in {"", ".", ".."} for part in normalized.rstrip("/").split("/")):
            archive.close()
            return None
        # ZIP permits canonically equivalent Unicode names.  Treat them as one identity so a
        # hidden comment cannot be attributed to an ambiguous look-alike member.
        # A directory marker is not part of a member's canonical identity: ``same`` and
        # ``same/`` would otherwise alias after extraction while evading the duplicate check.
        folded = unicodedata.normalize("NFC", normalized.rstrip("/")).casefold()
        if (folded in seen or info.file_size < 0 or info.compress_size < 0
                or info.file_size > field_limit * 16
                or info.file_size > ratio_limit * max(info.compress_size, 1)
                or info.compress_type not in {
                    zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                    zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA,
                }):
            archive.close()
            return None
        # Only compression tuning, data descriptors and UTF-8 names are supported.  In
        # particular encryption, patched data, strong encryption, and bit 13's masked local
        # headers make independent structural verification impossible.
        method_flags = (1 << 1) | (1 << 2) if info.compress_type != zipfile.ZIP_STORED else 0
        allowed_flags = (_ALLOWED_ZIP_FLAGS & ~((1 << 1) | (1 << 2))) | method_flags
        if info.flag_bits & ~allowed_flags:
            archive.close()
            return None
        try:
            local = info.header_offset
            if local < 0 or local + 30 > len(data) or data[local:local + 4] != b"PK\x03\x04":
                archive.close()
                return None
            local_flags, local_method = struct.unpack_from("<HH", data, local + 6)
        except (struct.error, OverflowError):
            archive.close()
            return None
        if local_flags != info.flag_bits or local_flags & ~allowed_flags \
                or local_method != info.compress_type:
            archive.close()
            return None
        seen.add(folded)
        total += info.file_size
        if total > total_limit:
            archive.close()
            return None
    try:
        if archive.testzip() is not None:
            archive.close()
            return None
    except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError,
            OSError, EOFError, MemoryError, zlib.error):
        archive.close()
        return None
    return archive


def extract_zip_comments(data: object) -> tuple[MetadataPayload, ...]:
    """Return exact archive/member comments only from a wholly validated ZIP."""

    raw = _blob(data)
    if raw is None:
        return ()
    try:
        exact = any(
            item.kind == "zip" and item.offset == 0 and item.end == len(raw)
            for item in _carving.carve_all(raw, kinds=("zip",))
        )
    except Exception:
        return ()
    if not exact:
        return ()
    archive = _safe_zip(raw)
    if archive is None:
        return ()
    output: list[MetadataPayload] = []
    field_limit = _runtime_limit(MAX_FIELD)
    result_limit = _runtime_limit(MAX_FIELDS)
    if field_limit is None or result_limit is None:
        archive.close()
        return ()
    try:
        if archive.comment:
            if len(archive.comment) > field_limit:
                return ()
            output.append(MetadataPayload(
                "zip", "archive.comment", bytes(archive.comment), "end-of-central-directory",
                ("validated EOCD comment length", "all member CRCs verified"),
            ))
        for info in archive.infolist():
            if info.comment:
                if len(info.comment) > field_limit:
                    return ()
                output.append(MetadataPayload(
                    "zip", f"member:{info.filename}:comment", bytes(info.comment), info.filename,
                    ("validated central-directory member comment", "member CRC verified"),
                ))
            if len(output) > result_limit:
                return ()
    finally:
        archive.close()
    return tuple(output)


def _metadata_value(container: str, field: str, value: object, source: str, *checks: str) -> MetadataPayload | None:
    field_limit = _runtime_limit(MAX_FIELD)
    if field_limit is None:
        return None
    if type(value) is str:
        if not value or len(value) > field_limit:
            return None
        try:
            data = value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            return None
        if len(data) > field_limit:
            return None
    elif type(value) in (bytes, bytearray, memoryview):
        data = _binary(value, field_limit)
        if data is None:
            return None
    else:
        return None
    if type(field) is not str or not field or len(field) > 4096 \
            or type(source) is not str or len(source) > 4096:
        return None
    return MetadataPayload(container, field, data, source, tuple(checks))


def _xml_root(raw: bytes) -> ET.Element | None:
    if not raw or len(raw) > MAX_FIELD or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        return None
    try:
        parser = ET.XMLParser(target=ET.TreeBuilder(insert_comments=True))
        return ET.fromstring(raw, parser=parser)
    except (ET.ParseError, ValueError, RecursionError):
        return None


def _local(tag: object) -> str:
    if tag is ET.Comment:
        return "xml-comment"
    return str(tag).rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _exact_container(raw: bytes, kind: str) -> bool:
    """Require one carver-validated primary object to consume the supplied bytes."""

    try:
        matches = tuple(
            item for item in _carving.carve_all(raw, kinds=(kind,))
            if item.kind == kind and item.offset == 0 and item.end == len(raw)
        )
    except Exception:
        return False
    return len(matches) == 1


def _resolved_pdf_name(value: object) -> str | None:
    if type(value) is str:
        return value
    if type(value) is _maldoc.PdfName:
        return str(value)
    return None


def extract_pdf_metadata(data: object) -> tuple[MetadataPayload, ...]:
    """Return PDF Info/XMP/annotation text after strict xref and object resolution."""

    raw = _blob(data)
    result_limit = _runtime_limit(MAX_FIELDS)
    if raw is None or result_limit is None or not _exact_container(raw, "pdf"):
        return ()
    try:
        report = _documents.decode_pdf(raw)
        parsed = _maldoc.pdf(raw) if report is not None else None
    except Exception:
        return ()
    if (type(report) is not _documents.PdfReport or type(parsed) is not dict
            or parsed.get("incomplete") is True or parsed.get("encrypted") is True):
        return ()
    info = parsed.get("info")
    objects = parsed.get("objects")
    resolver = parsed.get("resolve")
    if type(info) is not dict or type(objects) is not dict or not callable(resolver):
        return ()
    if type(report.object_count) is not int or report.object_count != len(objects) \
            or type(parsed.get("object_count")) is not int \
            or parsed.get("object_count") != len(objects):
        return ()
    # Validate the complete mapping before returning even an Info field.  This keeps malformed or
    # monkeypatched parser structures from leaking a valid-looking prefix.
    validated: list[tuple[tuple[int, int], tuple[object, object]]] = []
    try:
        for key, pair in objects.items():
            if (type(key) is not tuple or len(key) != 2
                    or type(key[0]) is not int or type(key[1]) is not int
                    or not 0 <= key[0] <= 0xFFFFFFFF or not 0 <= key[1] <= 0xFFFF
                    or type(pair) is not tuple or len(pair) != 2
                    or (isinstance(pair[0], Mapping) and type(pair[0]) is not dict)
                    or (pair[1] is not None and type(pair[1]) is not bytes)):
                return ()
            validated.append((key, pair))
    except Exception:
        return ()
    if len(validated) != len(objects):
        return ()
    try:
        validated.sort(key=lambda item: item[0])
    except Exception:
        return ()
    try:
        info_items = tuple(info.items())
    except Exception:
        return ()
    if any(type(name) is not str for name, _value in info_items):
        return ()

    def resolve(value: object) -> object:
        try:
            return resolver(value)
        except Exception:
            return _PDF_RESOLVE_FAILED

    output: list[MetadataPayload] = []
    for name, value in sorted(info_items, key=lambda pair: pair[0]):
        item = _metadata_value("pdf", f"Info.{name}", value, "trailer/Info", "resolved PDF Info dictionary")
        if item is None:
            return ()
        output.append(item)
        if len(output) > result_limit:
            return ()
    for key, pair in validated:
        value = pair[0]
        if type(value) is not dict:
            continue
        source = f"object {key[0]} {key[1]}"
        type_name = subtype_name = None
        if "Type" in value:
            resolved = resolve(value["Type"])
            if resolved is _PDF_RESOLVE_FAILED or (type_name := _resolved_pdf_name(resolved)) is None:
                return ()
        if "Subtype" in value:
            resolved = resolve(value["Subtype"])
            if resolved is _PDF_RESOLVE_FAILED or (subtype_name := _resolved_pdf_name(resolved)) is None:
                return ()
        if type_name == "Metadata" or subtype_name == "XML":
            try:
                decoded = _maldoc.pdf_stream(parsed, int(key[0]), int(key[1]))
            except Exception:
                return ()
            if (type(decoded) is not tuple or len(decoded) != 2 or type(decoded[0]) is not bytes
                    or decoded[1] is not True or _xml_root(decoded[0]) is None):
                return ()
            item = _metadata_value("pdf", "XMP", decoded[0], source, "fully decoded Metadata XML stream")
            if item is None:
                return ()
            output.append(item)
        if subtype_name in {"Text", "FreeText", "Stamp"}:
            for field in ("Contents", "T", "Subj", "NM"):
                if field not in value:
                    continue
                resolved = resolve(value[field])
                if resolved is _PDF_RESOLVE_FAILED or type(resolved) is not bytes:
                    return ()
                try:
                    decoded_text = _maldoc._pdf_str(resolved)
                except Exception:
                    return ()
                item = _metadata_value("pdf", f"annotation.{field}", decoded_text, source, "resolved annotation string")
                if item is None:
                    return ()
                output.append(item)
        if len(output) > result_limit:
            return ()
    return tuple(output)


def _office_metadata_part(name: str) -> bool:
    lower = name.casefold()
    return lower in {"docprops/core.xml", "docprops/app.xml", "docprops/custom.xml"} \
        or bool(re.fullmatch(r"(?:word|ppt|xl)/(?:comments(?:/[^/]+)?|comments\d*)\.xml", lower))


def extract_office_metadata(data: object) -> tuple[MetadataPayload, ...]:
    """Return OOXML document properties and comment text after package closure checks."""

    raw = _blob(data)
    if raw is None:
        return ()
    try:
        report = _documents.decode_ooxml(raw)
    except Exception:
        return ()
    if report is None:
        return ()
    archive = _safe_zip(raw)
    if archive is None:
        return ()
    output: list[MetadataPayload] = []
    try:
        members = {info.filename for info in archive.infolist() if not info.is_dir()}
        if members != set(report.members):
            return ()
        for info in sorted(archive.infolist(), key=lambda item: item.filename.casefold()):
            if info.is_dir() or not _office_metadata_part(info.filename):
                continue
            try:
                body = archive.read(info)
            except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, NotImplementedError,
                    OSError, EOFError, MemoryError, zlib.error):
                return ()
            root = _xml_root(body)
            if root is None:
                return ()
            counts: dict[str, int] = {}
            for element in root.iter():
                text = element.text or ""
                if not text.strip():
                    text = ""
                local = _local(element.tag)
                counts[local] = counts.get(local, 0) + 1
                ordinal = counts[local]
                if text:
                    field = f"{info.filename}:{local}[{ordinal}]"
                    item = _metadata_value(
                        "ooxml", field, text, info.filename,
                        "relationship-closed OOXML package", "well-formed metadata/comment XML",
                    )
                    if item is not None:
                        output.append(item)
                for attr_name, attr_value in sorted(element.attrib.items(), key=lambda pair: str(pair[0])):
                    item = _metadata_value(
                        "ooxml", f"{info.filename}:{local}[{ordinal}]@{_local(attr_name)}",
                        attr_value, info.filename,
                        "relationship-closed OOXML package", "well-formed metadata/comment XML attribute",
                    )
                    if item is not None:
                        output.append(item)
                if info.filename.casefold().startswith(("word/comments", "ppt/comments", "xl/comments")) \
                        and local.lower() in {"comment", "cm"}:
                    aggregate = "".join(element.itertext())
                    if aggregate and aggregate != text:
                        item = _metadata_value(
                            "ooxml", f"{info.filename}:{local}[{ordinal}].aggregate",
                            aggregate, info.filename,
                            "relationship-closed OOXML package", "complete comment descendant text",
                        )
                        if item is not None:
                            output.append(item)
                if len(output) > MAX_FIELDS:
                    return ()
    finally:
        archive.close()
    return tuple(output)


def _property_set_well_formed(raw: bytes) -> bool:
    """Validate the complete OLE property-set offset/length graph used by ``maldoc``."""

    if len(raw) < 48 or raw[:2] != b"\xfe\xff" or len(raw) > MAX_FIELD * 4:
        return False
    try:
        sections = struct.unpack_from("<I", raw, 24)[0]
        if not 1 <= sections <= 16 or 28 + 20 * sections > len(raw):
            return False
        offsets: set[int] = set()
        section_ranges: list[tuple[int, int]] = []
        for index in range(sections):
            base = struct.unpack_from("<I", raw, 44 + 20 * index)[0]
            if base in offsets or base < 28 + 20 * sections or base + 8 > len(raw):
                return False
            offsets.add(base)
            size, count = struct.unpack_from("<II", raw, base)
            end = base + size
            if size < 8 or end > len(raw) or count > 4096 or base + 8 + 8 * count > end:
                return False
            section_ranges.append((base, end))
            properties: list[tuple[int, int]] = []
            ids: set[int] = set()
            for prop_index in range(count):
                prop_id, relative = struct.unpack_from("<II", raw, base + 8 + 8 * prop_index)
                if prop_id in ids or relative < 8 + 8 * count or base + relative + 4 > end:
                    return False
                ids.add(prop_id)
                properties.append((prop_id, relative))
            if len({relative for _prop_id, relative in properties}) != len(properties):
                return False
            property_ranges: list[tuple[int, int]] = []
            for _prop_id, relative in properties:
                at = base + relative
                variant = struct.unpack_from("<I", raw, at)[0] & 0xFFFF
                if variant in {2}:  # VT_I2
                    needed = 6
                elif variant in {3}:  # VT_I4
                    needed = 8
                elif variant in {0x40}:  # VT_FILETIME
                    needed = 12
                elif variant in {0x1E, 0x1F}:  # VT_LPSTR / VT_LPWSTR
                    if at + 8 > end:
                        return False
                    length = struct.unpack_from("<I", raw, at + 4)[0]
                    unit = 2 if variant == 0x1F else 1
                    field_limit = _runtime_limit(MAX_FIELD)
                    if (field_limit is None or not 1 <= length <= field_limit
                            or length * unit > end - (at + 8)):
                        return False
                    needed = 8 + length * unit
                    body = raw[at + 8:at + needed]
                    terminator = b"\x00\x00" if variant == 0x1F else b"\x00"
                    if not body.endswith(terminator):
                        return False
                    if variant == 0x1E:
                        if b"\x00" in body[:-1]:
                            return False
                    elif any(body[offset:offset + 2] == b"\x00\x00"
                             for offset in range(0, len(body) - 2, 2)):
                        return False
                else:
                    # Unknown variants are not emitted by the broad parser, but their offset must
                    # still be inside this declared section (already proven above).
                    needed = 4
                if at + needed > end:
                    return False
                property_ranges.append((relative, relative + needed))
            property_ranges.sort()
            if any(left_end > right_start for (_left_start, left_end), (right_start, _right_end)
                   in zip(property_ranges, property_ranges[1:])):
                return False
        section_ranges.sort()
        if any(left_end > right_start for (_left_start, left_end), (right_start, _right_end)
               in zip(section_ranges, section_ranges[1:])):
            return False
    except (struct.error, OverflowError):
        return False
    return True


def extract_ole_metadata(data: object) -> tuple[MetadataPayload, ...]:
    """Return legacy Office SummaryInformation fields from a completely checked CFB."""

    raw = _blob(data)
    if raw is None:
        return ()
    try:
        report = _documents.decode_ole(raw)
        compound = _maldoc.CFB(raw) if report is not None else None
    except Exception:
        return ()
    if report is None or compound is None:
        return ()
    property_streams = []
    for name in ("\x05SummaryInformation", "\x05DocumentSummaryInformation"):
        try:
            if compound.has(name):
                body = compound.stream(name)
                if not _property_set_well_formed(body):
                    return ()
                property_streams.append(name)
        except Exception:
            return ()
    if not property_streams:
        return ()
    try:
        properties = _maldoc.ole_properties(compound)
    except Exception:
        return ()
    if not isinstance(properties, Mapping):
        return ()
    output: list[MetadataPayload] = []
    for name, value in sorted(properties.items(), key=lambda pair: str(pair[0])):
        # Numeric counters and dates are ordinary forensic facts, but this lane returns only byte
        # strings capable of carrying a hidden message.
        if not isinstance(value, (str, bytes, bytearray, memoryview)):
            continue
        item = _metadata_value(
            "ole", f"SummaryInformation.{name}", value,
            ",".join(property_streams),
            "strict CFB stream inventory", "complete OLE property-set offset graph",
        )
        if item is not None:
            output.append(item)
        if len(output) > MAX_FIELDS:
            return ()
    return tuple(output)


def extract_document_metadata(data: object) -> tuple[MetadataPayload, ...]:
    """Content-route one supplied PDF/OOXML/ZIP and return only checked fields."""

    raw = _blob(data)
    if raw is None:
        return ()
    if raw[:1024].find(b"%PDF-") >= 0:
        return extract_pdf_metadata(raw)
    if raw.startswith(_maldoc.OLE_MAGIC):
        return extract_ole_metadata(raw)
    if raw.startswith(b"PK"):
        office = extract_office_metadata(raw)
        comments = extract_zip_comments(raw)
        if office:
            return tuple([*office, *comments])
        return comments
    return ()


def extract_appended_data(data: object) -> HiddenPayload | None:
    """Return bytes beyond one unambiguous, validated primary container boundary."""

    raw = _blob(data)
    if raw is None:
        return None
    try:
        primary = [item for item in _carving.carve_all(raw) if item.offset == 0]
    except Exception:
        return None
    endpoints = {item.end for item in primary}
    if not primary or len(endpoints) != 1:
        return None
    end = endpoints.pop()
    if end >= len(raw):
        return None
    tail = raw[end:]
    if not tail or not tail.strip(b"\x00\t\r\n \x1a") or len(tail) > MAX_PAYLOAD:
        return None
    kinds = tuple(sorted({item.kind for item in primary}))
    return HiddenPayload(
        "appended-data",
        tail,
        "+".join(kinds),
        (
            f"validated primary boundary at byte {end}",
            f"{len(tail)} non-padding trailing bytes",
        ),
        zlib.crc32(tail) & 0xFFFFFFFF,
    )


def extract_polyglot(data: object) -> PolyglotPayload | None:
    """Expose exact parts only when the existing validated carver proves a polyglot."""

    raw = _blob(data)
    if raw is None:
        return None
    try:
        candidate = _carving.detect_polyglot(raw)
    except Exception:
        return None
    if candidate is None or not candidate.carvings:
        return None
    parts: list[HiddenPayload] = []
    for item in candidate.carvings:
        if item.offset < 0 or item.end <= item.offset or item.end > len(raw) or raw[item.offset:item.end] != item.data:
            return None
        parts.append(HiddenPayload(
            "polyglot-part",
            item.data,
            item.kind,
            (item.validation, f"validated byte range [{item.offset}, {item.end})"),
            zlib.crc32(item.data) & 0xFFFFFFFF,
        ))
    return PolyglotPayload(candidate.relationship, candidate.formats, tuple(parts))


def decode_text_channels(data: object) -> tuple[HiddenPayload, ...]:
    """Conservative default survey of self-identifying text channels.

    Homoglyph alphabets and non-default bit conventions are intentionally excluded because they
    require analyst-supplied mappings.  Duplicate payload/method pairs are removed.
    """

    output: list[HiddenPayload] = []
    zero_width = decode_zero_width(data)
    if zero_width is not None:
        output.append(zero_width)
    output.extend(decode_unicode_tags(data))
    whitespace = decode_whitespace_bits(data)
    if whitespace is not None:
        output.append(whitespace)
    snow = decode_snow(data)
    if snow is not None:
        output.append(snow)
    unique: dict[tuple[str, bytes], HiddenPayload] = {}
    for item in output:
        unique[(item.method, item.data)] = item
    return tuple(unique.values())


__all__ = [
    "HiddenPayload",
    "MetadataPayload",
    "PolyglotPayload",
    "decode_zero_width",
    "decode_unicode_tags",
    "decode_homoglyphs",
    "decode_whitespace_bits",
    "decode_snow",
    "decode_text_channels",
    "extract_zip_comments",
    "extract_pdf_metadata",
    "extract_office_metadata",
    "extract_ole_metadata",
    "extract_document_metadata",
    "extract_appended_data",
    "extract_polyglot",
]
