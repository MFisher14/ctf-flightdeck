#!/usr/bin/env python3
"""Bounded, offline decoding of response-body carriers.

This module deliberately does *not* decide whether a response contains a proof,
a useful source file, or a specification.  It turns one response body into
independent byte leaves and records how each leaf was reached.  Callers should
inspect only leaves whose ``searchable`` flag is true.  Container/intermediate
leaves are retained for diagnostics but are never evidence by themselves.

The public API is::

    result = decode_response(body, headers={"Content-Type": "..."})
    result.raw_body                 # the exact input bytes, always retained
    result.leaves                   # immutable CarrierLeaf objects
    result.issues                   # immutable DecodeIssue objects
    result.content_leaves()         # only searchable, semantic content

No fragments are concatenated.  JSON values, MIME parts, JWT claims and archive
members remain separate leaves with separate provenance.  JWT material is
explicitly unverified.  Archive names are metadata only.  The implementation
does no I/O, follows no links, imports no decoded material and invokes no
deserialiser capable of constructing objects or running code.

Every expansion is bounded by :class:`CarrierLimits`: input bytes, bytes in one
leaf, aggregate derived bytes, number of leaves, nesting depth, compression
ratio and approximate decoder work.  Truncated, malformed, unsupported and
over-limit carriers produce an issue and no semantic output from that carrier.
The original body remains available even when decoding fails.
"""

from __future__ import annotations

import base64
import binascii
import bz2
import io
import json
import lzma
import math
import quopri
import re
import stat
import struct
import tarfile
import zipfile
import zlib
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import PurePosixPath
from typing import Iterable, Mapping


_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_GZIP_MAGIC = b"\x1f\x8b"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_B64_RE = re.compile(rb"[A-Za-z0-9+/]*={0,2}\Z")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"([A-Za-z0-9_-]{2,2048}\.[A-Za-z0-9_-]{2,8192}\.[A-Za-z0-9_-]{0,4096})"
    r"(?![A-Za-z0-9_-])"
)
_HEX = frozenset(b"0123456789abcdefABCDEF")
_CONTENT_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_MIME_BOUNDARY = re.compile(r"[0-9A-Za-z'()+_,./:=?-]{1,70}\Z")
_MIME_DELIMITER_LINE = re.compile(
    rb"--[0-9A-Za-z'()+_,./:=?-]{1,70}(?:--)?[ \t]*\Z"
)
_MAX_JSON_NUMBER_CHARS = 256
_MAX_EXPLICIT_RADIX_CHARS = 384 << 10
_MAX_BASE58_CHARS = 16 << 10
_B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {value: index for index, value in enumerate(_B58_ALPHABET)}
_B91_ALPHABET = (
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    b"!#$%&()*+,./:;<=>?@[]^_`{|}~\""
)
_B91_INDEX = {value: index for index, value in enumerate(_B91_ALPHABET)}


def _base58_encode(data: bytes) -> bytes:
    zeros = len(data) - len(data.lstrip(b"\x00"))
    value = int.from_bytes(data, "big")
    out = bytearray()
    while value:
        value, remainder = divmod(value, 58)
        out.append(_B58_ALPHABET[remainder])
    return b"1" * zeros + bytes(reversed(out))


def _base58_decode(data: bytes) -> bytes:
    if any(value not in _B58_INDEX for value in data):
        raise ValueError("invalid base58 alphabet")
    zeros = len(data) - len(data.lstrip(b"1"))
    value = 0
    for item in data:
        value = value * 58 + _B58_INDEX[item]
    decoded = (value.to_bytes((value.bit_length() + 7) // 8, "big") if value else b"")
    out = b"\x00" * zeros + decoded
    if _base58_encode(out) != data:
        raise ValueError("non-canonical base58")
    return out


def _base91_encode(data: bytes) -> bytes:
    queue = bits = 0
    out = bytearray()
    for item in data:
        queue |= item << bits
        bits += 8
        if bits > 13:
            value = queue & 8191
            if value > 88:
                queue >>= 13
                bits -= 13
            else:
                value = queue & 16383
                queue >>= 14
                bits -= 14
            out.extend((_B91_ALPHABET[value % 91], _B91_ALPHABET[value // 91]))
    if bits:
        out.append(_B91_ALPHABET[queue % 91])
        if bits > 7 or queue > 90:
            out.append(_B91_ALPHABET[queue // 91])
    return bytes(out)


def _base91_decode(data: bytes) -> bytes:
    if any(value not in _B91_INDEX for value in data):
        raise ValueError("invalid base91 alphabet")
    queue = bits = 0
    pending = -1
    out = bytearray()
    for item in data:
        value = _B91_INDEX[item]
        if pending < 0:
            pending = value
            continue
        pending += value * 91
        queue |= pending << bits
        bits += 13 if (pending & 8191) > 88 else 14
        while bits > 7:
            out.append(queue & 255)
            queue >>= 8
            bits -= 8
        pending = -1
    if pending >= 0:
        out.append((queue | pending << bits) & 255)
    decoded = bytes(out)
    if _base91_encode(decoded) != data:
        raise ValueError("non-canonical base91")
    return decoded


def _bounded_json_int(raw: str) -> int:
    if len(raw) > _MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON number character limit")
    return int(raw, 10)


def _bounded_json_float(raw: str) -> float:
    if len(raw) > _MAX_JSON_NUMBER_CHARS:
        raise ValueError("JSON number character limit")
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError("non-finite JSON number")
    return value


@dataclass(frozen=True)
class CarrierLimits:
    """Hard resource ceilings for one :func:`decode_response` call."""

    max_input_bytes: int = 1 << 20
    max_leaf_bytes: int = 256 << 10
    max_total_expanded_bytes: int = 4 << 20
    max_leaves: int = 256
    # JSON APIs such as GraphQL introspection routinely nest type wrappers and
    # field metadata beyond six levels.  Expansion remains bounded by byte,
    # node, leaf, member, ratio and work caps, so a deeper structural ceiling
    # improves ordinary API coverage without making recursive carriers open
    # ended.
    max_depth: int = 24
    max_compression_ratio: int = 128
    max_work_bytes: int = 16 << 20
    max_archive_members: int = 128
    max_jwts: int = 16
    max_nodes: int = 4096
    max_issues: int = 256

    def __post_init__(self) -> None:
        for field in self.__dataclass_fields__:
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{field} must be a positive integer")


DEFAULT_LIMITS = CarrierLimits()


@dataclass(frozen=True)
class CarrierLeaf:
    """One independent output fragment.

    ``data`` is never a concatenation of siblings.  ``provenance`` is an ordered
    tuple beginning with ``response``.  ``metadata`` is descriptive only: in
    particular, archive and MIME filenames live there and never in a searchable
    leaf.  ``searchable`` is the safe boundary for a later proof/source scanner.
    """

    data: bytes
    provenance: tuple[str, ...]
    kind: str
    searchable: bool
    media_type: str | None = None
    charset: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()

    def metadata_dict(self) -> dict[str, str]:
        return dict(self.metadata)


@dataclass(frozen=True)
class DecodeIssue:
    code: str
    provenance: tuple[str, ...]
    detail: str = ""


@dataclass(frozen=True)
class DecodeStats:
    expanded_bytes: int
    work_bytes: int
    maximum_depth: int


@dataclass(frozen=True)
class DecodeResult:
    """The exact response plus bounded derived leaves and diagnostics."""

    raw_body: bytes
    leaves: tuple[CarrierLeaf, ...]
    issues: tuple[DecodeIssue, ...]
    stats: DecodeStats

    def content_leaves(self) -> tuple[CarrierLeaf, ...]:
        return tuple(leaf for leaf in self.leaves if leaf.searchable)


class _Pairs(list):
    """A JSON object whose order and duplicate keys must be preserved."""


_JSON_FAILED = object()


class _Limit(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail


def _clean_detail(value: object) -> str:
    # Diagnostics must not accidentally retain an entire response or secret.
    text = " ".join(str(value).replace("\x00", "?").split())
    return text[:240]


def _normalise_headers(headers: Mapping[str, object] | Iterable[tuple[object, object]] | None) -> dict[str, str]:
    if headers is None:
        return {}
    items = headers.items() if isinstance(headers, Mapping) else headers
    out: dict[str, str] = {}
    total_bytes = 0
    for index, row in enumerate(items):
        if index >= 512:
            out["x-csctf-header-limit"] = "count"
            break
        try:
            key, raw_value = row
        except Exception:
            out["x-csctf-header-limit"] = "malformed"
            break
        name = str(key).strip().lower()
        if not name or "\r" in name or "\n" in name:
            continue
        values = raw_value if isinstance(raw_value, (list, tuple)) else (raw_value,)
        for value_index, value in enumerate(values):
            if value_index >= 16:
                out["x-csctf-header-limit"] = "values"
                break
            text = str(value).strip()
            total_bytes += len(name.encode("utf-8", "replace")) + len(text.encode("utf-8", "replace"))
            if total_bytes > 1 << 20:
                out["x-csctf-header-limit"] = "bytes"
                break
            if len(text) > 16 << 10 or "\r" in text or "\n" in text or "\x00" in text:
                if name in ("content-type", "content-encoding"):
                    out["x-csctf-invalid-critical-header"] = name
                continue
            if name == "content-type" and name in out:
                out["x-csctf-conflicting-content-type"] = "1"
                continue
            if name == "content-encoding" and name in out:
                out["x-csctf-conflicting-content-encoding"] = "1"
                continue
            out[name] = f"{out[name]}, {text}" if name in out and name != "content-type" else text
        if out.get("x-csctf-header-limit"):
            break
    return out


def _content_type(raw: str | None) -> tuple[str | None, dict[str, str], str | None]:
    """Parse one unambiguous Content-Type value.

    ``email.message`` deliberately tolerates duplicate parameters and exposes a
    last/first-wins convenience view. Carrier selection cannot use that view:
    two MIME parsers may choose different boundaries or charsets. Reject every
    duplicate (including RFC2231 spellings), malformed media token and invalid
    multipart boundary before any body byte becomes searchable.
    """
    if not raw:
        return None, {}, None
    if len(raw) > 16 << 10 or "\r" in raw or "\n" in raw:
        return None, {}, "invalid Content-Type bytes"
    # Split before handing anything to the email package.  Python 3.9's email
    # parser normalises RFC2231 continuations (``boundary*0``/``boundary*1``)
    # into one ordinary ``boundary`` parameter, erasing the very syntax this
    # security boundary needs to reject.  A small strict scanner also catches
    # bare parameters that permissive MIME implementations silently ignore.
    pieces: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(raw):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == ";":
            pieces.append(raw[start:index])
            start = index + 1
    if quoted or escaped:
        return None, {}, "unterminated Content-Type quoted string"
    pieces.append(raw[start:])

    head = pieces[0].strip()
    if head.count("/") != 1:
        return None, {}, "invalid media type"
    major, minor = head.split("/", 1)
    if not _CONTENT_TOKEN.fullmatch(major) or not _CONTENT_TOKEN.fullmatch(minor):
        return None, {}, "invalid media type"
    media = head.lower()
    params: dict[str, str] = {}
    seen: set[str] = set()
    for raw_param in pieces[1:]:
        if not raw_param.strip() or "=" not in raw_param:
            return None, {}, "malformed Content-Type parameter"
        raw_name, raw_value = raw_param.split("=", 1)
        name = raw_name.strip().lower()
        value = raw_value.strip()
        # Reject every extended/continued spelling before any library can
        # collapse it into an ordinary parameter.  None is needed to select a
        # response charset or multipart boundary.
        if (not name or "*" in name or not _CONTENT_TOKEN.fullmatch(name)
                or name in seen or not value or len(value) > 4096
                or any(char in value for char in ("\r", "\n", "\x00"))):
            return None, {}, "duplicate or invalid Content-Type parameter"
        if value.startswith('"'):
            if len(value) < 2 or not value.endswith('"'):
                return None, {}, "malformed Content-Type quoted parameter"
            decoded: list[str] = []
            escape = False
            for char in value[1:-1]:
                if escape:
                    decoded.append(char)
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    return None, {}, "malformed Content-Type quoted parameter"
                else:
                    decoded.append(char)
            if escape:
                return None, {}, "malformed Content-Type quoted parameter"
            value = "".join(decoded)
        elif not _CONTENT_TOKEN.fullmatch(value):
            return None, {}, "invalid Content-Type parameter value"
        seen.add(name)
        params[name] = value
    if media.startswith("multipart/"):
        boundary = params.get("boundary")
        if boundary is None or not _MIME_BOUNDARY.fullmatch(boundary):
            return None, {}, "missing or invalid multipart boundary"
    return media, params, None


def _meta(**values: object) -> tuple[tuple[str, str], ...]:
    return tuple((key, str(value)) for key, value in sorted(values.items()) if value is not None)


def _safe_name(name: str) -> bool:
    if not name or "\x00" in name or name.startswith(("/", "\\")):
        return False
    normal = name.replace("\\", "/")
    if re.match(r"^[A-Za-z]:", normal):
        return False
    path = PurePosixPath(normal)
    return all(part not in ("", ".", "..") for part in path.parts)


def _looks_zlib(data: bytes) -> bool:
    if len(data) < 2:
        return False
    cmf, flg = data[0], data[1]
    return (cmf & 0x0F) == 8 and (cmf >> 4) <= 7 and ((cmf << 8) + flg) % 31 == 0


def _looks_tar(data: bytes) -> bool:
    return len(data) >= 512 and data[257:263] in (b"ustar\x00", b"ustar ")


def _zstd_frame_size(data: bytes) -> int:
    """Return one ordinary Zstandard frame's exact encoded size.

    The optional binding's streaming reader treats some truncated frames as a
    clean empty stream.  Walking the small public frame grammar first supplies
    the missing completeness/trailing-data check without decompressing bytes.
    Skippable and concatenated frames are intentionally not accepted here.
    """

    if len(data) < 5 or not data.startswith(_ZSTD_MAGIC):
        raise ValueError("missing zstandard frame header")
    descriptor = data[4]
    if descriptor & 0x18:  # reserved and unused bits must both be zero
        raise ValueError("reserved zstandard frame-header bit")
    fcs_flag = descriptor >> 6
    single_segment = bool(descriptor & 0x20)
    checksum = bool(descriptor & 0x04)
    dictionary_flag = descriptor & 0x03
    dictionary_size = (0, 1, 2, 4)[dictionary_flag]
    fcs_size = ((1 if single_segment else 0), 2, 4, 8)[fcs_flag]
    pos = 5 + (0 if single_segment else 1) + dictionary_size + fcs_size
    if pos > len(data):
        raise ValueError("truncated zstandard frame header")
    while True:
        if pos + 3 > len(data):
            raise ValueError("truncated zstandard block header")
        header = int.from_bytes(data[pos:pos + 3], "little")
        pos += 3
        last = bool(header & 1)
        block_type = (header >> 1) & 0x03
        block_size = header >> 3
        if block_type == 3:
            raise ValueError("reserved zstandard block type")
        encoded_size = 1 if block_type == 1 else block_size
        if pos + encoded_size > len(data):
            raise ValueError("truncated zstandard block")
        pos += encoded_size
        if last:
            break
    if checksum:
        pos += 4
        if pos > len(data):
            raise ValueError("truncated zstandard checksum")
    return pos


def _is_json_type(media_type: str | None) -> bool:
    return bool(media_type and (media_type == "application/json" or media_type.endswith("+json")))


def _is_javascript_type(media_type: str | None) -> bool:
    media = str(media_type or "").split(";", 1)[0].strip().lower()
    return (media in {
        "application/javascript", "text/javascript", "application/ecmascript",
        "text/ecmascript", "application/x-javascript", "text/jsx",
    } or media.endswith(("+javascript", "+ecmascript")))


def _looks_structural_json(text: str) -> bool:
    """Conservative sniff for undeclared JSON, excluding templates/CSS/code.

    A JSON object can begin only with a quoted member or ``}``; an array can
    begin only with a JSON value or ``]``.  Merely starting with ``{`` is not
    enough: ``{{template}}`` and CSS/JS fragments are ordinary text carriers
    and must not poison a complete baseline as malformed JSON.
    """
    value = str(text or "").lstrip("\ufeff \t\r\n")
    if len(value) < 2:
        return False
    rest = value[1:].lstrip()
    if value.startswith("{"):
        return bool(rest) and rest[:1] in ('"', "}")
    if value.startswith("["):
        return bool(rest) and rest[:1] in ('"', "{", "[", "]", "-", "t", "f", "n", *tuple("0123456789"))
    return False


def _is_text_type(media_type: str | None) -> bool:
    return bool(media_type and (media_type.startswith("text/") or _is_json_type(media_type)
                                or media_type in ("application/javascript", "application/xml",
                                                  "application/xhtml+xml", "application/jwt")))


class _Decoder:
    def __init__(self, raw: bytes, headers: dict[str, str], limits: CarrierLimits) -> None:
        self.raw = raw
        self.headers = headers
        self.limits = limits
        self.leaves: list[CarrierLeaf] = []
        self.issues: list[DecodeIssue] = []
        self.expanded = 0
        self.work = 0
        self.maximum_depth = 0
        self.nodes = 0
        self._issue_keys: set[tuple[str, tuple[str, ...], str]] = set()

    def issue(self, code: str, provenance: tuple[str, ...], detail: object = "") -> None:
        cleaned = _clean_detail(detail)
        key = (str(code), tuple(provenance), cleaned)
        if key in self._issue_keys or len(self.issues) >= self.limits.max_issues:
            return
        # Reserve the final slot for a stable indication that diagnostics were
        # capped.  This prevents adversarial arrays from allocating hundreds
        # of thousands of distinct issue objects merely by varying indices.
        if len(self.issues) == self.limits.max_issues - 1 and code != "issue_count_limit":
            limit_key = ("issue_count_limit", ("response",),
                         f"maximum {self.limits.max_issues}")
            if limit_key not in self._issue_keys:
                self._issue_keys.add(limit_key)
                self.issues.append(DecodeIssue(*limit_key))
            return
        self._issue_keys.add(key)
        self.issues.append(DecodeIssue(*key))

    def enter_node(self, provenance: tuple[str, ...]) -> bool:
        """Reserve one structured/container traversal node, or fail closed."""
        if self.nodes >= self.limits.max_nodes:
            self.issue("node_count_limit", provenance, f"maximum {self.limits.max_nodes}")
            return False
        if len(self.leaves) >= self.limits.max_leaves:
            self.issue("leaf_count_limit", provenance, f"maximum {self.limits.max_leaves}")
            return False
        if self.work >= self.limits.max_work_bytes:
            self.issue("work_limit", provenance, f"maximum {self.limits.max_work_bytes} bytes")
            return False
        self.nodes += 1
        return True

    def spend_work(self, amount: int) -> None:
        if amount < 0 or self.work + amount > self.limits.max_work_bytes:
            raise _Limit("work_limit", f"maximum {self.limits.max_work_bytes} bytes")
        self.work += amount

    def reserve_expansion(self, amount: int) -> None:
        if amount < 0 or amount > self.limits.max_leaf_bytes:
            raise _Limit("leaf_limit", f"maximum {self.limits.max_leaf_bytes} bytes")
        if self.expanded + amount > self.limits.max_total_expanded_bytes:
            raise _Limit("aggregate_limit", f"maximum {self.limits.max_total_expanded_bytes} bytes")
        self.expanded += amount

    def output_cap(self, compressed_size: int) -> tuple[int, str]:
        caps = (
            (self.limits.max_leaf_bytes, "leaf_limit"),
            (self.limits.max_total_expanded_bytes - self.expanded, "aggregate_limit"),
            (self.limits.max_work_bytes - self.work - compressed_size, "work_limit"),
            (max(1, compressed_size) * self.limits.max_compression_ratio, "compression_ratio"),
        )
        cap, reason = min(caps, key=lambda pair: pair[0])
        if cap < 0:
            raise _Limit(reason)
        return cap, reason

    def emit(self, data: bytes, provenance: tuple[str, ...], kind: str, *, searchable: bool,
             media_type: str | None = None, charset: str | None = None,
             metadata: tuple[tuple[str, str], ...] = (), charge: bool = True) -> bool:
        if len(self.leaves) >= self.limits.max_leaves:
            self.issue("leaf_count_limit", provenance, f"maximum {self.limits.max_leaves}")
            return False
        try:
            if charge:
                self.reserve_expansion(len(data))
        except _Limit as exc:
            self.issue(exc.code, provenance, exc.detail)
            return False
        self.leaves.append(CarrierLeaf(bytes(data), provenance, kind, searchable, media_type, charset, metadata))
        return True

    def _zlib_one(self, data: bytes, wbits: int, cap: int) -> tuple[bytes, bytes]:
        obj = zlib.decompressobj(wbits)
        out = obj.decompress(data, cap + 1)
        if len(out) > cap or obj.unconsumed_tail:
            raise _Limit("output_cap")
        if not obj.eof:
            raise ValueError("truncated compressed stream")
        room = cap + 1 - len(out)
        if room > 0:
            out += obj.flush(room)
        if len(out) > cap:
            raise _Limit("output_cap")
        return out, obj.unused_data

    def decompress(self, data: bytes, encoding: str, provenance: tuple[str, ...]) -> bytes | None:
        encoding = encoding.lower().strip()
        cap_reason = "output_cap"
        textual_encoding = encoding in ("base85", "b85", "base58", "b58", "base91", "b91")
        try:
            self.spend_work(len(data))
            cap, cap_reason = self.output_cap(len(data))
            if cap <= 0:
                raise _Limit(cap_reason)
            if encoding in ("gzip", "x-gzip"):
                pending, pieces = data, []
                remaining = cap
                while pending:
                    piece, tail = self._zlib_one(pending, 16 + zlib.MAX_WBITS, remaining)
                    pieces.append(piece)
                    remaining -= len(piece)
                    if not tail:
                        break
                    if not tail.startswith(_GZIP_MAGIC):
                        raise ValueError("trailing bytes after gzip stream")
                    pending = tail
                out = b"".join(pieces)
            elif encoding == "deflate":
                wbits = zlib.MAX_WBITS if _looks_zlib(data) else -zlib.MAX_WBITS
                out, tail = self._zlib_one(data, wbits, cap)
                if tail:
                    raise ValueError("trailing bytes after deflate stream")
            elif encoding == "zlib":
                out, tail = self._zlib_one(data, zlib.MAX_WBITS, cap)
                if tail:
                    raise ValueError("trailing bytes after zlib stream")
            elif encoding in ("bzip2", "x-bzip2", "bz2"):
                decoder = bz2.BZ2Decompressor()
                out = decoder.decompress(data, max_length=cap + 1)
                if len(out) > cap:
                    raise _Limit(cap_reason)
                if not decoder.eof:
                    if not decoder.needs_input or len(out) >= cap:
                        raise _Limit(cap_reason)
                    raise ValueError("truncated bzip2 stream")
                if decoder.unused_data:
                    raise ValueError("trailing bytes or concatenated bzip2 streams")
            elif encoding in ("xz", "x-xz", "lzma", "x-lzma"):
                fmt = lzma.FORMAT_XZ if encoding in ("xz", "x-xz") else lzma.FORMAT_ALONE
                decoder = lzma.LZMADecompressor(
                    format=fmt, memlimit=self.limits.max_work_bytes)
                out = decoder.decompress(data, max_length=cap + 1)
                if len(out) > cap:
                    raise _Limit(cap_reason)
                if not decoder.eof:
                    if not decoder.needs_input or len(out) >= cap:
                        raise _Limit(cap_reason)
                    raise ValueError("truncated xz/lzma stream")
                if decoder.unused_data:
                    raise ValueError("trailing bytes or concatenated xz/lzma streams")
            elif textual_encoding:
                radix_limit = (_MAX_BASE58_CHARS if encoding in ("base58", "b58")
                               else _MAX_EXPLICIT_RADIX_CHARS)
                if len(data) > radix_limit:
                    raise _Limit(
                        "work_limit", f"explicit radix input exceeds {radix_limit} bytes")
                if encoding in ("base85", "b85"):
                    try:
                        out = base64.b85decode(data)
                    except (binascii.Error, ValueError) as exc:
                        raise ValueError(f"invalid base85: {exc}") from exc
                    if base64.b85encode(out) != data:
                        raise ValueError("non-canonical base85")
                elif encoding in ("base58", "b58"):
                    out = _base58_decode(data)
                else:
                    out = _base91_decode(data)
                if len(out) > cap:
                    raise _Limit(cap_reason)
            elif encoding in ("br", "brotli"):
                try:
                    import brotli  # optional package; decoded data is never imported
                except ImportError:
                    self.issue("unsupported_encoding", provenance, "brotli module is not installed")
                    return None
                try:
                    decoder = brotli.Decompressor()
                    # Old bindings without the bounded interface are deliberately unsupported.
                    out = decoder.process(data, output_buffer_limit=cap + 1)
                except TypeError:
                    self.issue("unsupported_encoding", provenance, "brotli binding has no bounded decoder")
                    return None
                if not decoder.is_finished():
                    if len(out) >= cap:
                        raise _Limit(cap_reason)
                    raise ValueError("truncated brotli stream")
                if len(out) > cap:
                    raise _Limit(cap_reason)
            elif encoding in ("zstd", "zstandard"):
                try:
                    import zstandard
                except ImportError:
                    self.issue("unsupported_encoding", provenance, "zstandard module is not installed")
                    return None
                try:
                    declared = zstandard.frame_content_size(data)
                except Exception as exc:
                    raise ValueError(f"bad zstandard frame: {exc}") from exc
                if isinstance(declared, int) and declared >= 0 and declared > cap:
                    raise _Limit(cap_reason)
                if _zstd_frame_size(data) != len(data):
                    raise ValueError("trailing data or concatenated zstandard frames")
                # max_output_size is a native hard allocation/output bound, including for
                # frames that deliberately omit their content size.
                out = zstandard.ZstdDecompressor().decompress(
                    data, max_output_size=cap + 1, allow_extra_data=False)
                if len(out) > cap:
                    raise _Limit(cap_reason)
            else:
                self.issue("unsupported_encoding", provenance, encoding)
                return None
            self.reserve_expansion(len(out))
            self.spend_work(len(out))
            return bytes(out)
        except _Limit as exc:
            code = cap_reason if exc.code == "output_cap" else exc.code
            self.issue(code, provenance, exc.detail or f"{encoding} output exceeded its bound")
        except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError) as exc:
            self.issue("malformed_encoding" if textual_encoding else "malformed_compression",
                       provenance, f"{encoding}: {exc}")
        except Exception as exc:
            # Optional native decoders use their own exception classes.  They are data errors here.
            self.issue("malformed_encoding" if textual_encoding else "malformed_compression",
                       provenance, f"{encoding}: {exc}")
        return None

    def decode_content_encoding(self, body: bytes, raw: str, provenance: tuple[str, ...]) -> tuple[bytes, tuple[str, ...]] | None:
        encodings = [token.strip().lower() for token in raw.split(",") if token.strip()]
        if not encodings:
            self.issue("malformed_content_encoding", provenance, "empty Content-Encoding")
            return None
        current, path = body, provenance
        # RFC 9110 lists encodings in application order; undo them right-to-left.
        for encoding in reversed(encodings):
            if encoding == "identity":
                path += ("content-encoding:identity",)
                continue
            next_path = path + (f"content-encoding:{encoding}",)
            decoded = self.decompress(current, encoding, next_path)
            if decoded is None:
                return None
            current, path = decoded, next_path
        self.emit(current, path, "content-decoded", searchable=False, charge=False)
        return current, path

    def decode_base64(self, data: bytes, provenance: tuple[str, ...]) -> bytes | None:
        compact = re.sub(rb"[\t\r\n ]", b"", data)
        if len(compact) < 8 or len(compact) % 4 == 1 or not _B64_RE.fullmatch(compact):
            return None
        try:
            if b"=" in compact and len(compact) % 4:
                raise ValueError("padding before an incomplete base64 quantum")
            padded = compact + b"=" * (-len(compact) % 4)
            expected = (len(padded) // 4) * 3 - (2 if padded.endswith(b"==") else 1 if padded.endswith(b"=") else 0)
            self.spend_work(len(compact))
            if expected > self.limits.max_leaf_bytes:
                raise _Limit("leaf_limit")
            self.reserve_expansion(expected)
            decoded = base64.b64decode(padded, validate=True)
            if len(decoded) != expected:
                raise ValueError("base64 length mismatch")
            if base64.b64encode(decoded).rstrip(b"=") != compact.rstrip(b"="):
                raise ValueError("non-canonical base64")
            self.spend_work(len(decoded))
            return decoded
        except _Limit as exc:
            self.issue(exc.code, provenance, exc.detail)
        except (binascii.Error, ValueError) as exc:
            self.issue("malformed_base64", provenance, exc)
        return None

    def decode_b64url(self, segment: str, provenance: tuple[str, ...]) -> bytes | None:
        if not segment or not _B64URL_RE.fullmatch(segment) or len(segment) % 4 == 1:
            self.issue("malformed_jwt", provenance, "non-canonical base64url segment")
            return None
        try:
            self.spend_work(len(segment))
            decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
            if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != segment:
                raise ValueError("non-canonical base64url")
            self.reserve_expansion(len(decoded))
            self.spend_work(len(decoded))
            return decoded
        except _Limit as exc:
            self.issue(exc.code, provenance, exc.detail)
        except (binascii.Error, ValueError) as exc:
            self.issue("malformed_jwt", provenance, exc)
        return None

    def charset_text(self, data: bytes, media_type: str | None, declared: str | None,
                     provenance: tuple[str, ...]) -> tuple[str, str] | None:
        boms = (
            (b"\x00\x00\xfe\xff", "utf-32"), (b"\xff\xfe\x00\x00", "utf-32"),
            (b"\xef\xbb\xbf", "utf-8-sig"),
            (b"\xfe\xff", "utf-16"), (b"\xff\xfe", "utf-16"),
        )
        aliases = {
            "ascii": "ascii", "us-ascii": "ascii",
            "utf8": "utf-8", "utf-8": "utf-8",
            "utf-8-sig": "utf-8-sig",
            "utf16": "utf-16", "utf-16": "utf-16",
            "utf-16le": "utf-16-le", "utf-16-le": "utf-16-le",
            "utf-16be": "utf-16-be", "utf-16-be": "utf-16-be",
            "utf32": "utf-32", "utf-32": "utf-32",
            "utf-32le": "utf-32-le", "utf-32-le": "utf-32-le",
            "utf-32be": "utf-32-be", "utf-32-be": "utf-32-be",
            "latin1": "latin-1", "latin-1": "latin-1", "iso-8859-1": "latin-1",
            "iso-8859-2": "iso8859-2", "iso-8859-15": "iso8859-15",
            "windows-1250": "cp1250", "cp1250": "cp1250",
            "windows-1251": "cp1251", "cp1251": "cp1251",
            "windows-1252": "cp1252", "cp1252": "cp1252",
            "koi8-r": "koi8-r", "macintosh": "mac-roman", "mac-roman": "mac-roman",
            "shift-jis": "shift_jis", "shiftjis": "shift_jis", "sjis": "shift_jis",
            "ms-kanji": "shift_jis",
            "euc-jp": "euc_jp", "eucjp": "euc_jp",
            "gb18030": "gb18030",
            "big5": "big5", "big-5": "big5",
        }
        bom_codec = next((codec for marker, codec in boms if data.startswith(marker)), None)
        declared_key = declared.strip().lower().replace("_", "-") if declared else None
        declared_codec = aliases.get(declared_key) if declared_key else None
        if declared_key and declared_codec is None:
            self.issue("unsupported_charset", provenance, declared_key)
            if bom_codec is None:
                return None
        codec = bom_codec or declared_codec
        if bom_codec and declared_key:
            compatible = declared_codec in (bom_codec, bom_codec.replace("-sig", ""))
            if bom_codec.startswith("utf-16") and declared_codec and declared_codec.startswith("utf-16"):
                compatible = declared_codec == "utf-16"
            if bom_codec.startswith("utf-32") and declared_codec and declared_codec.startswith("utf-32"):
                compatible = declared_codec == "utf-32"
            if not compatible:
                self.issue("charset_bom_conflict", provenance,
                           f"BOM {bom_codec} overrides {declared_codec or declared_key}")

        candidates: list[str]
        if codec:
            candidates = [codec]
        elif _is_json_type(media_type):
            # RFC JSON without an explicit charset is Unicode, with UTF-8 the
            # interoperable/default wire encoding.  Falling through to
            # CP-1252/Latin-1 can normalize an invalid structural byte (for
            # example 0x80 inside a string), after which re-encoding makes a
            # document a strict JSON parser would have rejected look valid.
            # BOMs and an explicit allow-listed charset are handled above.
            candidates = ["utf-8"]
        elif _is_text_type(media_type):
            # HTTP text seen in CTF fixtures is usually UTF-8; CP-1252 and Latin-1 are bounded
            # fallbacks for explicitly textual legacy pages, never for arbitrary binary bytes.
            candidates = ["utf-8", "cp1252", "latin-1"]
        else:
            candidates = ["utf-8"]

        for candidate in candidates:
            try:
                text = data.decode(candidate, errors="strict")
                if not codec and not _is_text_type(media_type):
                    if "\x00" in text:
                        continue
                    printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
                    if text and printable * 10 < len(text) * 9:
                        continue
                self.spend_work(len(data))
                return text, candidate
            except (UnicodeDecodeError, LookupError, _Limit):
                continue
        self.issue("malformed_text", provenance, declared_codec or "no strict text decoding")
        return None

    @staticmethod
    def normalise_surrogates(value: str) -> str:
        # json.loads deliberately preserves UTF-16 surrogate code points.  This joins valid
        # escaped pairs and rejects lone halves rather than smuggling replacement characters.
        return value.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "strict")

    def parse_json_bytes(self, data: bytes, provenance: tuple[str, ...], *,
                         report_malformed: bool = True) -> object:
        try:
            self.spend_work(len(data))
            text = data.decode("utf-8", "strict")
            return json.loads(text, object_pairs_hook=_Pairs,
                              parse_int=_bounded_json_int,
                              parse_float=_bounded_json_float,
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except _Limit as exc:
            self.issue(exc.code, provenance, exc.detail)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
            if report_malformed:
                self.issue("malformed_json", provenance, exc)
        return _JSON_FAILED

    def json_leaves(self, value: object, provenance: tuple[str, ...], depth: int, *,
                    metadata: tuple[tuple[str, str], ...] = (),
                    complete_document: bool = False) -> None:
        self.maximum_depth = max(self.maximum_depth, depth)
        if depth > self.limits.max_depth:
            self.issue("depth_limit", provenance, f"maximum {self.limits.max_depth}")
            return
        # The complete, strictly decoded ``json-document`` leaf is emitted
        # before this optional scalar expansion. Exhausting only the scalar
        # leaf budget loses no document bytes, so it must not poison that
        # coherent structural view. Container/MIME fan-out still reports the
        # limit because no complete parent leaf can replace omitted siblings.
        if complete_document and len(self.leaves) >= self.limits.max_leaves:
            return
        if not self.enter_node(provenance):
            return
        if isinstance(value, _Pairs):
            seen: dict[str, int] = {}
            for raw_key, child in value:
                if (self.nodes >= self.limits.max_nodes
                        or len(self.leaves) >= self.limits.max_leaves
                        or self.work >= self.limits.max_work_bytes):
                    if not complete_document:
                        self.enter_node(provenance + ("json:remaining",))
                    break
                try:
                    key = self.normalise_surrogates(raw_key)
                except (UnicodeEncodeError, UnicodeDecodeError):
                    self.issue("malformed_json_string", provenance, "lone surrogate in object key")
                    continue
                number = seen.get(key, 0)
                seen[key] = number + 1
                escaped = key.replace("~", "~0").replace("/", "~1")
                self.json_leaves(child, provenance + (f"json:/{escaped}#{number}",), depth + 1,
                                 metadata=metadata, complete_document=complete_document)
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                if (self.nodes >= self.limits.max_nodes
                        or len(self.leaves) >= self.limits.max_leaves
                        or self.work >= self.limits.max_work_bytes):
                    if not complete_document:
                        self.enter_node(provenance + ("json:remaining",))
                    break
                self.json_leaves(child, provenance + (f"json:[{index}]",), depth + 1,
                                 metadata=metadata, complete_document=complete_document)
            return
        try:
            if isinstance(value, str):
                normal = self.normalise_surrogates(value)
                data = normal.encode("utf-8", "strict")
                kind = "json-string"
            else:
                data = json.dumps(value, ensure_ascii=False, allow_nan=False,
                                  separators=(",", ":")).encode("utf-8")
                kind = "json-scalar"
        except (UnicodeEncodeError, UnicodeDecodeError, TypeError, ValueError) as exc:
            self.issue("malformed_json_string", provenance, exc)
            return
        if self.emit(data, provenance, kind, searchable=True, media_type="application/json",
                     charset="utf-8", metadata=metadata):
            if isinstance(value, str):
                self.scan_jwts(self.normalise_surrogates(value), provenance, depth + 1, metadata)
                self.maybe_base64(data, provenance, depth + 1, metadata)

    def scan_jwts(self, text: str, provenance: tuple[str, ...], depth: int,
                  inherited: tuple[tuple[str, str], ...] = ()) -> None:
        for index, match in enumerate(_JWT_RE.finditer(text)):
            if index >= self.limits.max_jwts:
                self.issue("jwt_count_limit", provenance, f"maximum {self.limits.max_jwts}")
                break
            jwt_path = provenance + (f"jwt:{index}:unverified",)
            header_seg, payload_seg, _signature = match.group(1).split(".")
            header = self.decode_b64url(header_seg, jwt_path + ("header",))
            payload = self.decode_b64url(payload_seg, jwt_path + ("payload",))
            if header is None or payload is None:
                continue
            hobj = self.parse_json_bytes(
                header, jwt_path + ("header",), report_malformed=False)
            pobj = self.parse_json_bytes(
                payload, jwt_path + ("payload",), report_malformed=False)
            if not isinstance(hobj, _Pairs) or not isinstance(pobj, _Pairs):
                self.issue("malformed_jwt", jwt_path, "header and payload must be JSON objects")
                continue
            base_meta = inherited + _meta(unverified="true")
            self.emit(header, jwt_path + ("header-bytes",), "jwt-section", searchable=False,
                      media_type="application/json", metadata=base_meta, charge=False)
            self.emit(payload, jwt_path + ("payload-bytes",), "jwt-section", searchable=False,
                      media_type="application/json", metadata=base_meta, charge=False)
            self.json_leaves(hobj, jwt_path + ("header-claims",), depth + 1,
                             metadata=base_meta + _meta(jwt_section="header"))
            self.json_leaves(pobj, jwt_path + ("payload-claims",), depth + 1,
                             metadata=base_meta + _meta(jwt_section="payload"))

    def maybe_base64(self, data: bytes, provenance: tuple[str, ...], depth: int,
                     metadata: tuple[tuple[str, str], ...]) -> None:
        compact = re.sub(rb"[\t\r\n ]", b"", data)
        # Short alphabetic words such as "test" are valid base64 but not meaningful carriers.
        if len(compact) < 12 or len(compact) > self.limits.max_input_bytes:
            return
        path = provenance + ("base64",)
        decoded = self.decode_base64(compact, path)
        if decoded is None:
            return
        self.emit(decoded, path, "base64-decoded", searchable=False, metadata=metadata, charge=False)
        self.visit(decoded, path, None, None, depth, metadata)

    def decode_mime_transfer(self, payload: bytes, cte: str, provenance: tuple[str, ...]) -> bytes | None:
        cte = cte.strip().lower()
        try:
            self.spend_work(len(payload))
            if cte in ("", "7bit", "8bit", "binary"):
                out = payload
            elif cte == "base64":
                compact = re.sub(rb"[\t\r\n ]", b"", payload)
                if not compact or len(compact) % 4 or not _B64_RE.fullmatch(compact):
                    raise ValueError("invalid MIME base64")
                out = base64.b64decode(compact, validate=True)
            elif cte == "quoted-printable":
                pos = 0
                while True:
                    pos = payload.find(b"=", pos)
                    if pos < 0:
                        break
                    suffix = payload[pos + 1:pos + 3]
                    if payload[pos + 1:pos + 3] == b"\r\n":
                        pos += 3
                    elif payload[pos + 1:pos + 2] == b"\n":
                        pos += 2
                    elif len(suffix) == 2 and suffix[0] in _HEX and suffix[1] in _HEX:
                        pos += 3
                    else:
                        raise ValueError("invalid quoted-printable escape")
                out = quopri.decodestring(payload)
            else:
                self.issue("unsupported_transfer_encoding", provenance, cte)
                return None
            self.reserve_expansion(len(out))
            self.spend_work(len(out))
            return bytes(out)
        except _Limit as exc:
            self.issue(exc.code, provenance, exc.detail)
        except (binascii.Error, ValueError) as exc:
            self.issue("malformed_transfer_encoding", provenance, exc)
        return None

    def mime(self, data: bytes, content_type: str, provenance: tuple[str, ...], depth: int,
             inherited: tuple[tuple[str, str], ...]) -> None:
        # The stdlib email parser constructs the complete MIME tree before we
        # can walk it.  Enforce a conservative raw delimiter/node ceiling
        # first, otherwise tens of thousands of tiny parts can consume seconds
        # despite a small ``max_leaves`` output cap.  Count line-anchored MIME
        # delimiters of every nested boundary spelling; payload false positives
        # fail closed and can never create evidence.
        delimiter_cap = min(
            self.limits.max_nodes,
            self.limits.max_leaves * 3 + self.limits.max_depth + 4,
        )
        delimiters = 0
        cursor = 0
        while cursor <= len(data):
            newline = data.find(b"\n", cursor)
            end = len(data) if newline < 0 else newline
            line = data[cursor:end]
            if line.endswith(b"\r"):
                line = line[:-1]
            if len(line) <= 80 and _MIME_DELIMITER_LINE.fullmatch(line):
                delimiters += 1
                if delimiters > delimiter_cap:
                    self.issue("leaf_count_limit", provenance,
                               f"MIME delimiter count exceeds {delimiter_cap}")
                    return
            if newline < 0:
                break
            cursor = newline + 1
        try:
            self.spend_work(len(data))
            header = ("MIME-Version: 1.0\r\nContent-Type: " + content_type + "\r\n\r\n").encode("ascii")
            msg = BytesParser(policy=policy.default).parsebytes(header + data)
        except (UnicodeEncodeError, ValueError, RecursionError, _Limit) as exc:
            code = exc.code if isinstance(exc, _Limit) else "malformed_mime"
            self.issue(code, provenance, getattr(exc, "detail", exc))
            return

        broken = []
        pending = [msg]
        tree_nodes = 0
        while pending:
            part = pending.pop()
            tree_nodes += 1
            if tree_nodes > delimiter_cap:
                self.issue("node_count_limit", provenance,
                           f"MIME tree exceeds {delimiter_cap} nodes")
                return
            broken.extend(part.defects)
            if part.is_multipart():
                pending.extend(part.iter_parts())
        if broken or not msg.is_multipart():
            self.issue("malformed_mime", provenance,
                       ", ".join(type(item).__name__ for item in broken) or "not a multipart body")
            return

        part_count = 0
        mime_stopped = False

        def walk(part, path: tuple[int, ...], level: int,
                 parent_metadata: tuple[tuple[str, str], ...]) -> None:
            nonlocal part_count, mime_stopped
            if mime_stopped:
                return
            self.maximum_depth = max(self.maximum_depth, level)
            if level > self.limits.max_depth:
                self.issue("depth_limit", provenance + (f"mime:{'.'.join(map(str, path))}",))
                return
            part_path = provenance + (f"mime:{'.'.join(map(str, path))}",)
            # ``get_all`` exposes values after RFC2231 normalization.  On
            # Python 3.9 that has already joined ``charset*0``/``charset*1``
            # and hidden ambiguous duplicate parameters.  Validate each
            # child's original header spelling before that information is
            # erased by the email convenience API.
            raw_items = list(part.raw_items())
            content_types = [str(value) for name, value in raw_items
                             if str(name).lower() == "content-type"]
            if len(content_types) > 1:
                self.issue("ambiguous_mime_header", part_path, "duplicate Content-Type fields")
                return
            part_media, part_params, content_type_error = _content_type(
                content_types[0] if content_types else None)
            if content_type_error:
                self.issue("ambiguous_mime_header", part_path, content_type_error)
                return
            part_media = part_media or "text/plain"
            transfers = [str(value) for name, value in raw_items
                         if str(name).lower() == "content-transfer-encoding"]
            if len(transfers) > 1:
                self.issue("ambiguous_mime_header", part_path,
                           "duplicate Content-Transfer-Encoding fields")
                return
            if transfers:
                transfer = transfers[0]
                if (len(transfer) > 256 or any(char in transfer for char in "\r\n\x00")
                        or not _CONTENT_TOKEN.fullmatch(transfer.strip())):
                    self.issue("ambiguous_mime_header", part_path,
                               "invalid Content-Transfer-Encoding syntax")
                    return
            # A multipart/form-data disposition may sit on a nested multipart.  Carry that
            # semantic identity into each child without ever joining the children's bytes.
            local_metadata = parent_metadata + _meta(
                filename=part.get_filename(),
                name=part.get_param("name", header="content-disposition"),
            )
            if part.is_multipart():
                if not part_media.startswith("multipart/"):
                    self.issue("malformed_mime", part_path, "multipart tree has non-multipart type")
                    mime_stopped = True
                    return
                for index, child in enumerate(part.iter_parts()):
                    walk(child, path + (index,), level + 1, local_metadata)
                    if mime_stopped:
                        break
                return
            part_count += 1
            if part_count > self.limits.max_leaves:
                self.issue("leaf_count_limit", part_path, "MIME part count")
                mime_stopped = True
                return
            payload = part.get_payload(decode=False)
            if isinstance(payload, str):
                try:
                    payload_bytes = payload.encode("ascii", "surrogateescape")
                except UnicodeEncodeError:
                    payload_bytes = payload.encode("utf-8", "surrogatepass")
            elif isinstance(payload, bytes):
                payload_bytes = payload
            else:
                self.issue("malformed_mime", part_path, "non-byte leaf payload")
                return
            decoded = self.decode_mime_transfer(payload_bytes, transfers[0] if transfers else "", part_path)
            if decoded is None:
                return
            media = part_media
            charset = part_params.get("charset")
            metadata = local_metadata + _meta(part=".".join(map(str, path)))
            self.emit(decoded, part_path, "mime-part", searchable=False, media_type=media,
                      charset=charset, metadata=metadata, charge=False)
            self.visit(decoded, part_path, media, charset, level, metadata)

        walk(msg, (), depth, inherited)

    def zip_archive(self, data: bytes, provenance: tuple[str, ...], depth: int,
                    inherited: tuple[tuple[str, str], ...]) -> None:
        try:
            self.spend_work(len(data))
            archive = zipfile.ZipFile(io.BytesIO(data))
            infos = archive.infolist()
        except (_Limit, OSError, ValueError, zipfile.BadZipFile) as exc:
            code = exc.code if isinstance(exc, _Limit) else "malformed_archive"
            self.issue(code, provenance, getattr(exc, "detail", exc))
            return
        try:
            if len(infos) > self.limits.max_archive_members:
                self.issue("archive_member_limit", provenance, f"{len(infos)} members")
                return
            for index, info in enumerate(infos):
                path = provenance + (f"zip-member:{index}",)
                if info.is_dir():
                    continue
                if not _safe_name(info.filename):
                    self.issue("unsafe_archive_member", path, "unsafe path")
                    continue
                mode = info.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                # Many ZIP writers store only permission bits, without a Unix file type.
                if file_type not in (0, stat.S_IFREG):
                    self.issue("unsafe_archive_member", path, "link or non-regular file")
                    continue
                if info.flag_bits & 1:
                    self.issue("unsupported_archive_member", path, "encrypted ZIP member")
                    continue
                try:
                    cap, reason = self.output_cap(max(1, info.compress_size))
                    if info.file_size > cap:
                        self.issue(reason, path, f"declared member size {info.file_size}")
                        continue
                    self.spend_work(info.compress_size)
                    with archive.open(info, "r") as source:
                        member = source.read(cap + 1)
                    if len(member) > cap or len(member) != info.file_size:
                        self.issue(reason if len(member) > cap else "malformed_archive", path,
                                   "member size mismatch")
                        continue
                    self.reserve_expansion(len(member))
                    self.spend_work(len(member))
                except _Limit as exc:
                    self.issue(exc.code, path, exc.detail)
                    continue
                except (OSError, EOFError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                    self.issue("malformed_archive", path, exc)
                    continue
                metadata = inherited + _meta(archive="zip", filename=info.filename, member=index)
                self.emit(member, path, "archive-member", searchable=False, metadata=metadata, charge=False)
                self.visit(member, path, None, None, depth + 1, metadata)
        finally:
            archive.close()

    def tar_archive(self, data: bytes, provenance: tuple[str, ...], depth: int,
                    inherited: tuple[tuple[str, str], ...]) -> None:
        try:
            self.spend_work(len(data))
            archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        except (_Limit, OSError, EOFError, tarfile.TarError) as exc:
            code = exc.code if isinstance(exc, _Limit) else "malformed_archive"
            self.issue(code, provenance, getattr(exc, "detail", exc))
            return
        try:
            for index, info in enumerate(archive):
                path = provenance + (f"tar-member:{index}",)
                if index >= self.limits.max_archive_members:
                    self.issue("archive_member_limit", path, f"maximum {self.limits.max_archive_members}")
                    break
                if not info.isfile():
                    if info.issym() or info.islnk() or info.isdev():
                        self.issue("unsafe_archive_member", path, "link, device or non-regular file")
                    continue
                if not _safe_name(info.name):
                    self.issue("unsafe_archive_member", path, "unsafe path")
                    continue
                cap = min(self.limits.max_leaf_bytes,
                          self.limits.max_total_expanded_bytes - self.expanded,
                          self.limits.max_work_bytes - self.work)
                if info.size > cap:
                    reason = "leaf_limit" if info.size > self.limits.max_leaf_bytes else "aggregate_limit"
                    self.issue(reason, path, f"declared member size {info.size}")
                    continue
                try:
                    source = archive.extractfile(info)
                    if source is None:
                        raise ValueError("regular member has no data")
                    with source:
                        member = source.read(cap + 1)
                    if len(member) > cap or len(member) != info.size:
                        raise ValueError("member size mismatch")
                    self.reserve_expansion(len(member))
                    self.spend_work(len(member))
                except _Limit as exc:
                    self.issue(exc.code, path, exc.detail)
                    continue
                except (OSError, EOFError, ValueError, tarfile.TarError) as exc:
                    self.issue("malformed_archive", path, exc)
                    continue
                metadata = inherited + _meta(archive="tar", filename=info.name, member=index)
                self.emit(member, path, "archive-member", searchable=False, metadata=metadata, charge=False)
                self.visit(member, path, None, None, depth + 1, metadata)
        finally:
            archive.close()

    def visit(self, data: bytes, provenance: tuple[str, ...], media_type: str | None,
              charset: str | None, depth: int,
              metadata: tuple[tuple[str, str], ...] = ()) -> None:
        self.maximum_depth = max(self.maximum_depth, depth)
        if depth > self.limits.max_depth:
            self.issue("depth_limit", provenance, f"maximum {self.limits.max_depth}")
            return

        if data.startswith(_GZIP_MAGIC):
            path = provenance + ("nested:gzip",)
            out = self.decompress(data, "gzip", path)
            if out is not None:
                self.emit(out, path, "compressed-decoded", searchable=False, metadata=metadata, charge=False)
                self.visit(out, path, None, None, depth + 1, metadata)
            return
        if data.startswith(_ZSTD_MAGIC):
            path = provenance + ("nested:zstd",)
            out = self.decompress(data, "zstd", path)
            if out is not None:
                self.emit(out, path, "compressed-decoded", searchable=False, metadata=metadata, charge=False)
                self.visit(out, path, None, None, depth + 1, metadata)
            return
        # Zlib's two-byte check and tar's offset-257 marker are deliberately
        # weak sniffers.  They are useful for an untyped/binary response, but
        # ordinary explicit text can coincidentally begin with ``b"x "`` or
        # contain ``ustar\0``.  In that case the declared text interpretation
        # wins instead of a failed speculative decoder erasing valid content.
        weak_binary_sniff = not _is_text_type(media_type)
        if weak_binary_sniff and _looks_zlib(data):
            path = provenance + ("nested:zlib",)
            out = self.decompress(data, "zlib", path)
            if out is not None:
                self.emit(out, path, "compressed-decoded", searchable=False, metadata=metadata, charge=False)
                self.visit(out, path, None, None, depth + 1, metadata)
            return
        if data.startswith(_ZIP_MAGICS) or media_type in ("application/zip", "application/x-zip-compressed"):
            self.emit(data, provenance + ("zip",), "archive", searchable=False,
                      media_type="application/zip", metadata=metadata, charge=False)
            self.zip_archive(data, provenance + ("zip",), depth, metadata)
            return
        if ((weak_binary_sniff and _looks_tar(data))
                or media_type in ("application/x-tar", "application/tar")):
            self.emit(data, provenance + ("tar",), "archive", searchable=False,
                      media_type="application/x-tar", metadata=metadata, charge=False)
            self.tar_archive(data, provenance + ("tar",), depth, metadata)
            return

        if media_type and media_type.startswith("multipart/"):
            self.emit(data, provenance + ("multipart",), "multipart", searchable=False,
                      media_type=media_type, metadata=metadata, charge=False)
            # The original Content-Type string (including boundary) is stored by the caller in charset.
            self.mime(data, charset or media_type, provenance + ("multipart",), depth + 1, metadata)
            return

        text_pair = self.charset_text(data, media_type, charset, provenance)
        if text_pair is None:
            # Opaque binary remains non-searchable; consumers can retain it using raw/intermediate leaves.
            self.emit(data, provenance + ("opaque",), "opaque", searchable=False,
                      media_type=media_type, metadata=metadata, charge=False)
            return
        text, used_charset = text_pair
        try:
            utf8 = text.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            self.issue("malformed_text", provenance, exc)
            return

        json_hint = (_is_json_type(media_type)
                     or (_looks_structural_json(text) and not _is_javascript_type(media_type)))
        if json_hint:
            value = self.parse_json_bytes(utf8, provenance + ("json",))
            if value is _JSON_FAILED:
                # A declared/obvious JSON carrier fails closed; its syntax is not a content leaf.
                return
            document_emitted = self.emit(
                utf8, provenance + ("json",), "json-document", searchable=False,
                media_type=media_type or "application/json", charset="utf-8",
                metadata=metadata, charge=True)
            self.json_leaves(value, provenance + ("json",), depth + 1,
                             metadata=metadata, complete_document=document_emitted)
            return

        path = provenance + (f"text:{used_charset}",)
        if not self.emit(utf8, path, "text", searchable=True, media_type=media_type,
                         charset="utf-8", metadata=metadata, charge=True):
            return
        self.scan_jwts(text, path, depth + 1, metadata)
        self.maybe_base64(utf8, path, depth + 1, metadata)

    def run(self) -> DecodeResult:
        root = ("response",)
        if len(self.raw) > self.limits.max_input_bytes:
            self.issue("input_limit", root,
                       f"{len(self.raw)} bytes exceeds {self.limits.max_input_bytes}")
            return self.result()

        if self.headers.get("x-csctf-invalid-critical-header"):
            self.issue("invalid_critical_header", root,
                       self.headers["x-csctf-invalid-critical-header"])
            return self.result()
        if self.headers.get("x-csctf-conflicting-content-type"):
            self.issue("conflicting_content_type", root, "multiple Content-Type header fields")
            return self.result()
        if self.headers.get("x-csctf-conflicting-content-encoding"):
            self.issue("ambiguous_content_encoding", root,
                       "multiple Content-Encoding header fields")
            return self.result()
        if self.headers.get("x-csctf-header-limit"):
            self.issue("header_limit", root, self.headers["x-csctf-header-limit"])
            return self.result()

        content_type_raw = self.headers.get("content-type")
        media_type, params, content_type_error = _content_type(content_type_raw)
        if content_type_error:
            self.issue("ambiguous_content_type", root, content_type_error)
            return self.result()
        content = self.raw
        provenance = root
        encoding = self.headers.get("content-encoding")
        if encoding:
            decoded = self.decode_content_encoding(content, encoding, provenance)
            if decoded is None:
                return self.result()
            content, provenance = decoded

        # MIME needs its complete parameterised Content-Type; other content uses only charset.
        hint = content_type_raw if media_type and media_type.startswith("multipart/") else params.get("charset")
        self.visit(content, provenance, media_type, hint, 0)
        return self.result()

    def result(self) -> DecodeResult:
        return DecodeResult(self.raw, tuple(self.leaves), tuple(self.issues),
                            DecodeStats(self.expanded, self.work, self.maximum_depth))


def decode_response(body: bytes | bytearray | memoryview,
                    headers: Mapping[str, object] | Iterable[tuple[object, object]] | None = None,
                    *, limits: CarrierLimits | None = None) -> DecodeResult:
    """Decode one already-received HTTP response without performing any I/O.

    Malformed carrier data is represented in ``result.issues`` rather than
    raised.  Programmer errors (a non-bytes body or invalid limits) raise
    ``TypeError``/``ValueError``.  Header names are case-insensitive.
    """

    if not isinstance(body, (bytes, bytearray, memoryview)):
        raise TypeError("body must be bytes-like")
    chosen = limits if limits is not None else DEFAULT_LIMITS
    if not isinstance(chosen, CarrierLimits):
        raise TypeError("limits must be CarrierLimits")
    raw = bytes(body)
    return _Decoder(raw, _normalise_headers(headers), chosen).run()


__all__ = [
    "CarrierLeaf", "CarrierLimits", "DecodeIssue", "DecodeResult", "DecodeStats",
    "DEFAULT_LIMITS", "decode_response",
]
