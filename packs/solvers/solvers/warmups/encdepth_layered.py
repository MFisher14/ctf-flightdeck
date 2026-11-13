#!/usr/bin/env python3
"""Bounded static peeling with literal-crib/CSCTF goals, never English guesses.

Reuses codec_decoders, compression_codecs and layered_decode's primitive byte
readers, but does not call their searches or any program interpreter. A candidate
is evidence, not authorization to submit. Search bounds define a finite domain;
quota truncation is explicit and prevents solve() from choosing an answer.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
import json
import re
import sys

import codec_decoders as bases
import compression_codecs as compression
import layered_decode as legacy
import encdepth_unicode as unicode_codecs


# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

class DecodeError(ValueError):
    """Invalid input/options or a failed static decoder contract."""


MAX_BYTES = 1 << 20
MAX_STATES = 512
MAX_TOTAL = 8 << 20
FLAG = flagfmt.TEXT   # applied to latin-1 text of each layer (keeps the left word boundary)
SPACE = b" \t\r\n"
BASES = ("base16", "base64", "base64url", "base32", "base32hex", "ascii85",
         "base85", "z85", "base45", "base58", "base58:flickr", "base58:ripple",
         "base91", "base92", "base122")


@dataclass(frozen=True)
class Candidate:
    payload: bytes
    chain: tuple[str, ...]
    matches: tuple[bytes, ...]


@dataclass(frozen=True)
class SearchResult:
    candidates: tuple[Candidate, ...]
    states: int
    total_bytes: int
    truncated: bool
    reason: str | None
    depth_limit: int


def _integer(value, name, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise DecodeError(f"{name} must be an integer in {minimum}..{maximum}")
    return value


def _bytes(value, name, limit):
    if not isinstance(value, (bytes, bytearray, str)):
        raise DecodeError(f"{name} must be bytes or UTF-8 text")
    if len(value) > limit:
        raise DecodeError(f"{name} exceeds byte limit")
    try:
        raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    except (ValueError, UnicodeError) as exc:
        raise DecodeError(f"invalid {name}") from exc
    if len(raw) > limit:
        raise DecodeError(f"{name} exceeds byte limit")
    return raw


def _strict_base(data, name):
    # Only explicitly permitted ASCII transport whitespace is removed. Base45
    # space is a data symbol and must be preserved, even at either end.
    compact = data if name in ("base45", "base122") else data.translate(None, SPACE)
    if name != "base122" and not compact.isascii():
        return None
    if name not in ("base45", "base122") and any(x in compact for x in (b"\v", b"\f")):
        return None
    if name in ("base64", "base64url", "base32", "base32hex"):
        alphabet = {"base64": rb"[A-Za-z0-9+/]+", "base64url": rb"[A-Za-z0-9_-]+",
                    "base32": rb"[A-Za-z2-7]+", "base32hex": rb"[0-9A-Va-v]+"}[name]
        word = compact.rstrip(b"=")
        if not re.fullmatch(alphabet, word):
            return None
        block = 4 if name.startswith("base64") else 8
        allowed = (0, 2, 3) if block == 4 else (0, 2, 4, 5, 7)
        if len(word) % block not in allowed:
            return None
        # Missing padding is accepted; PRESENT padding must be exactly right.
        pads = len(compact) - len(word)
        if pads and pads != -len(word) % block:
            return None
    # Numeric-base decoding uses large integers; cap those speculative branches.
    if (name.startswith("base58") or name == "base122") and len(compact) > 8192:
        return None
    candidate = bases.decode_base(compact, name)
    return candidate.payload if candidate is not None else None


def _wrapped(data):
    """Explicit containers must validate before any embedded goal is accepted."""
    return (data.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ", b"\xff\xfe",
                             b"\xfe\xff", b"\x00\x00\xfe\xff", b"\xef\xbb\xbf"))
            or (len(data) >= 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7
                and int.from_bytes(data[:2], "big") % 31 == 0)
            or re.match(rb"begin(?:-base64)? [0-7]{3,4} ", data) is not None)


def _peels(data, max_bytes, transforms):
    """Yield signature-based operations before ambiguous alphabet operations."""
    for name, magic, decoder in (
        ("gzip", b"\x1f\x8b\x08", compression.decode_gzip),
        ("bzip2", b"BZh", compression.decode_bzip2),
        ("xz", b"\xfd7zXZ\x00", compression.decode_lzma),
    ):
        if data.startswith(magic):
            out = decoder(data, max_output=max_bytes)
            if out is not None:
                yield name, out
    if len(data) >= 2 and data[0] & 15 == 8 and data[0] >> 4 <= 7 and int.from_bytes(data[:2], "big") % 31 == 0:
        out = compression.decode_zlib(data, max_output=max_bytes)
        if out is not None:
            yield "zlib", out
    # Longest BOM first. Never reinterpret UTF-32LE as UTF-16LE.
    for bom, encoding in ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
                          (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"),
                          (b"\xef\xbb\xbf", "utf-8-sig")):
        if data.startswith(bom):
            try:
                yield encoding, data.decode(encoding, "strict").encode("utf-8")
            except UnicodeError:
                pass
            break
    if b"%" in data and not re.search(rb"%(?![A-Fa-f0-9]{2})", data):
        # Legacy URL reader already uses unquote_to_bytes: '+' is not a space.
        out = legacy.d_url(data)
        if out is not None:
            yield "percent", out
    if b"&" in data:
        out = legacy.d_html(data)
        if out is not None:
            yield "html-entities", out
    # These adapters never invoke a VM; notably formats_more.steps is NOT used.
    import encdepth_transport
    yield from encdepth_transport.steps(data)
    if not data.isascii():
        yield from unicode_codecs.steps(data)
    for name in BASES:
        out = _strict_base(data, name)
        if out is not None:
            yield name, out
    for name, decoder in (("binary", legacy.d_binary), ("decimal", legacy.d_decimal),
                          ("octal", legacy.d_octal)):
        out = decoder(data)
        if out is not None:
            yield name, out
    for name in transforms:
        out = {"rot13": legacy.d_rot13, "reverse": legacy.d_reverse}[name](data)
        if out is not None:
            yield name, out


def peel(data, *, max_bytes=MAX_BYTES, transforms=()):
    """One layer as ordered (operation, bytes) pairs; malformed forms decline.

    Unknown options are errors; unsupported or malformed encoded input has no
    corresponding edge. Identity edges and duplicate outputs are omitted.
    """
    _integer(max_bytes, "max_bytes", 1, 16 << 20)
    raw = _bytes(data, "data", max_bytes)
    if not isinstance(transforms, (tuple, list)) or any(
        not isinstance(t, str) or t not in ("rot13", "reverse") for t in transforms
    ):
        raise DecodeError("transforms must contain only rot13 and/or reverse")
    out, seen = [], {raw}
    try:
        for name, value in _peels(raw, max_bytes, transforms):
            if value and len(value) <= max_bytes and value not in seen:
                seen.add(value)
                out.append((name, value))
    except Exception as exc:
        # Imported legacy readers do not uniformly declare errors. This boundary
        # makes their malformed-input failures a single public error contract.
        raise DecodeError("static decoder rejected input") from exc
    return out


def search(data, *, crib=None, max_depth=8, max_states=MAX_STATES,
           max_bytes=MAX_BYTES, max_total_bytes=MAX_TOTAL, transforms=()):
    """Search a finite decoding graph, preserving exact bytes and provenance.

    No crib: terminal nodes must contain a complete case-sensitive CSCTF flag.
    With crib: terminal nodes must contain the exact nonempty literal crib (no
    regex, prefix-only, case folding or English-score fallback). Terminal nodes
    are not peeled further. Multiple distinct goals remain explicit candidates.
    ``truncated`` reports state/aggregate-byte quotas, not the configured depth.
    """
    _integer(max_depth, "max_depth", 0, 64)
    _integer(max_states, "max_states", 1, 10000)
    _integer(max_bytes, "max_bytes", 1, 16 << 20)
    _integer(max_total_bytes, "max_total_bytes", 1, 128 << 20)
    raw = _bytes(data, "data", max_bytes)
    goal = None if crib is None else _bytes(crib, "crib", 4096)
    if goal == b"":
        raise DecodeError("crib must not be empty")
    if not isinstance(transforms, (tuple, list)) or any(
        not isinstance(t, str) or t not in ("rot13", "reverse") for t in transforms
    ):
        raise DecodeError("transforms must contain only rot13 and/or reverse")
    if len(raw) > max_total_bytes:
        raise DecodeError("input exceeds total byte budget")
    pending = deque([(raw, ())])
    seen, total, found = {raw}, len(raw), []
    reason = None
    while pending:
        current, chain = pending.popleft()
        matches = ((goal,) if goal in current else ()) if goal is not None else tuple(
            dict.fromkeys(match.group(0).encode("latin-1") for match in FLAG.finditer(current.decode("latin-1"))))
        if matches and not _wrapped(current):
            found.append(Candidate(current, chain, matches))
            continue
        if len(chain) >= max_depth:
            continue
        for name, out in peel(current, max_bytes=max_bytes, transforms=transforms):
            if out in seen:
                continue
            if len(seen) >= max_states:
                reason = reason or "state budget exhausted"
                continue
            if total + len(out) > max_total_bytes:
                reason = reason or "total byte budget exhausted"
                continue
            seen.add(out)
            total += len(out)
            pending.append((out, chain + (name,)))
    return SearchResult(tuple(found), len(seen), total, reason is not None, reason, max_depth)


def solve(data, **options):
    """Unique complete-search candidate, or None; never choose among ambiguity.

    For flag mode, duplicate occurrences of one flag across different plaintexts
    are one goal. For crib mode, full payloads must agree, since a shared crib is
    insufficient to choose between two different decoded messages.
    """
    try:
        result = search(data, **options)
    except TypeError as exc:
        raise DecodeError("invalid search options") from exc
    if result.truncated or not result.candidates:
        return None
    goals = {c.payload for c in result.candidates} if options.get("crib") is not None else {
        m for c in result.candidates for m in c.matches}
    return result.candidates[0] if len(goals) == 1 else None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("file")
    p.add_argument("--crib", help="exact UTF-8 literal; default is a complete CSCTF flag")
    p.add_argument("--max-depth", type=int, default=8)
    p.add_argument("--max-states", type=int, default=MAX_STATES)
    p.add_argument("--max-bytes", type=int, default=MAX_BYTES)
    p.add_argument("--max-total-bytes", type=int, default=MAX_TOTAL)
    p.add_argument("--transform", action="append", choices=("rot13", "reverse"), default=[])
    try:
        args = p.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        _integer(args.max_bytes, "max_bytes", 1, 16 << 20)
        with open(args.file, "rb") as fh:
            data = fh.read(args.max_bytes + 1)
        result = search(data, crib=args.crib, max_depth=args.max_depth,
                        max_states=args.max_states, max_bytes=args.max_bytes,
                        max_total_bytes=args.max_total_bytes, transforms=args.transform)
        print(json.dumps({"states": result.states, "total_bytes": result.total_bytes,
                          "truncated": result.truncated, "reason": result.reason,
                          "depth_limit": result.depth_limit, "candidates": [
                              {"chain": c.chain, "matches": [m.decode("utf-8") for m in c.matches],
                               "payload_hex": c.payload.hex()} for c in result.candidates]}, indent=2))
        return 3 if result.truncated else 0 if result.candidates else 1
    except (DecodeError, OSError, ValueError) as exc:
        print(f"encdepth_layered: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
