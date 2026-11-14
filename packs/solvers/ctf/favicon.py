"""Favicon multi-hashing (B-089): the first-pass favicon fingerprint, the way scan engines index it.

A favicon is the one object a service hands unchanged to every visitor, so a content hash of it
identifies the host wherever else the same bytes are served. Different scan engines index it under
different hashes, so a lookup needs the matching form:

  Shodan   MurmurHash3 x86_32 over the MIME-base64 of the raw file (`http.favicon.hash:<signed int>`),
  Censys   the plain MD5 of the raw bytes (`services.http.response.favicons.md5_hash:"<md5>"`),
  ZoomEye  the same MD5 (`iconhash:"<md5>"`),
  FOFA     the Shodan mmh3, as a quoted string (`icon_hash="<signed int>"`).

This module computes all of them and writes the ready-made queries, so the first pass records the
fingerprint whichever index the next step needs. It is pure Python and has no dependency on the `mmh3`
C extension (which is not installed): `murmur3_x86_32` is the reference algorithm, and `shodan_hash`
reproduces Shodan's exact recipe, `mmh3.hash(codecs.encode(data, "base64"))`, where the base64 is MIME
(76-character lines, a trailing newline) -- the newlines change the hash, so dropping them is the
classic wrong answer.

    from ctf import favicon
    fh = favicon.fingerprint(icon_bytes)         # FaviconHashes(mmh3, mmh3_unsigned, md5, sha256, size)
    favicon.murmur3_x86_32(b"foo")               # -156908512 (mmh3 README vector)
    favicon.icon_hash_queries(fh)                # {"shodan": "http.favicon.hash:...", "censys": ..., ...}
    favicon.icon_links(html_text, base_url)      # declared <link rel=icon> hrefs, resolved; then /favicon.ico

The fetch of a declared icon is `ctf/cli/favicon.py` (`python -m ctf favicon`), which runs
`scope.check_url` before any GET and routes `.onion` hosts through B-091 (Tor). This module does no
I/O of its own beyond reading a local file.
"""
from __future__ import annotations

import base64
import hashlib
import urllib.parse
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path

# MurmurHash3 x86_32 constants (Austin Appleby's reference implementation).
_C1 = 0xCC9E2D51
_C2 = 0x1B873593
_MASK = 0xFFFFFFFF


def _rotl32(x: int, r: int) -> int:
    return ((x << r) | (x >> (32 - r))) & _MASK


def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 of `data`, returned signed (two's complement in [-2**31, 2**31)), the way
    `mmh3.hash` returns it. Reference vector: murmur3_x86_32(b"foo") == -156908512."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError(f"murmur3_x86_32 needs bytes, not {type(data).__name__}")
    data = bytes(data)
    length = len(data)
    h1 = seed & _MASK
    rounded_end = length & ~0x3
    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24)) & _MASK
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & _MASK
    # tail
    k1 = 0
    rem = length & 3
    if rem >= 3:
        k1 ^= data[rounded_end + 2] << 16
    if rem >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if rem >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * _C1) & _MASK
        k1 = _rotl32(k1, 15)
        k1 = (k1 * _C2) & _MASK
        h1 ^= k1
    # finalization
    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & _MASK
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & _MASK
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def murmur3_x86_32_unsigned(data: bytes, seed: int = 0) -> int:
    """The same hash as `murmur3_x86_32` but as the unsigned 32-bit value."""
    v = murmur3_x86_32(data, seed)
    return v + 0x100000000 if v < 0 else v


def mime_base64(data: bytes) -> bytes:
    """Shodan's base64 of the favicon: MIME (76-char lines, trailing newline). This is what
    `codecs.encode(data, "base64")` and `base64.encodebytes(data)` produce; `base64.b64encode`
    (no newlines) gives a DIFFERENT mmh3, which is the usual mistake."""
    return base64.encodebytes(bytes(data))


def shodan_hash(data: bytes) -> int:
    """The favicon hash as Shodan indexes it: MurmurHash3 x86_32 over the MIME-base64 of the raw bytes,
    signed. Reproduces `mmh3.hash(codecs.encode(data, "base64"))`."""
    return murmur3_x86_32(mime_base64(data))


@dataclass(frozen=True)
class FaviconHashes:
    """Every fingerprint of one favicon's bytes."""
    mmh3: int              # Shodan / FOFA: signed MurmurHash3 x86_32 over MIME-base64
    mmh3_unsigned: int     # the same, unsigned 32-bit
    md5: str               # Censys / ZoomEye: MD5 of the raw bytes, lower hex
    sha256: str            # SHA-256 of the raw bytes, lower hex
    size: int              # byte length, for the Content-Length check

    def to_dict(self) -> dict:
        return {"mmh3": self.mmh3, "mmh3_unsigned": self.mmh3_unsigned,
                "md5": self.md5, "sha256": self.sha256, "size": self.size}


def fingerprint(data: bytes) -> FaviconHashes:
    """All favicon hashes of `data` in one pass."""
    data = bytes(data)
    return FaviconHashes(
        mmh3=shodan_hash(data),
        mmh3_unsigned=murmur3_x86_32_unsigned(mime_base64(data)),
        md5=hashlib.md5(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )


def icon_hash_queries(fh: FaviconHashes) -> dict[str, str]:
    """Ready-made scan-engine lookups for a favicon's fingerprint, each keyed by engine. The Shodan /
    FOFA forms use the signed mmh3; Censys / ZoomEye use the MD5."""
    return {
        "shodan": f"http.favicon.hash:{fh.mmh3}",
        "fofa": f'icon_hash="{fh.mmh3}"',
        "censys": f'services.http.response.favicons.md5_hash:"{fh.md5}"',
        "zoomeye": f'iconhash:"{fh.md5}"',
    }


# ---------------------------------------------------------------- declared icon links

class _IconLinkParser(HTMLParser):
    """Collect the hrefs of <link rel="...icon...">, newest-declared last."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "link":
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        rel = a.get("rel", "").lower()
        # rel is a space-separated token list: "icon", "shortcut icon", "apple-touch-icon", "mask-icon".
        if any("icon" == tok or tok.endswith("-icon") or tok == "icon" for tok in rel.split()):
            href = a.get("href", "").strip()
            if href:
                self.hrefs.append(href)


def icon_links(html: str, base_url: str | None = None) -> list[str]:
    """The icon URLs a page declares, in document order, resolved against `base_url` when given. The
    conventional default `/favicon.ico` is appended (resolved too) when the page declares none, so the
    result is never empty for a real page; duplicates are dropped keeping first-seen order."""
    parser = _IconLinkParser()
    parser.feed(html)
    hrefs = list(parser.hrefs)
    if not hrefs:
        hrefs = ["/favicon.ico"]
    out: list[str] = []
    seen: set[str] = set()
    for href in hrefs:
        resolved = urllib.parse.urljoin(base_url, href) if base_url else href
        if resolved not in seen:
            seen.add(resolved)
            out.append(resolved)
    return out


# ---------------------------------------------------------------- local icon files

ICON_EXTS = (".ico", ".icon")
# File magics that mark an icon payload. .ico is a cur/ico resource (00 00 01 00); handouts also ship
# the icon as a PNG or GIF named favicon.*.
ICON_MAGICS = (b"\x00\x00\x01\x00",)


def looks_like_icon(path: Path) -> bool:
    """True when `path` is an icon by extension (.ico), by an `.ico` magic, or by the name `favicon`."""
    name = path.name.lower()
    if path.suffix.lower() in ICON_EXTS:
        return True
    if name.startswith("favicon"):
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return False
    return any(head.startswith(m) for m in ICON_MAGICS)
