#!/usr/bin/env python3
"""Strict adapters for existing Unicode codecs, plus concatenated Ecoji records.

The bit decoders and published alphabets are reused from formats_more/formats_tables.
This module adds canonical terminal lengths, explicit variant selection, bounded input,
CR/LF-only transport wrapping and correct Ecoji record framing. No content is executed.
Sources: github.com/qntm/base2048, github.com/qntm/base65536,
github.com/keith-turner/ecoji/blob/main/docs/encoding.md.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import formats_more as _existing
import formats_tables as _tables

MAX_INPUT = 4 * 1024 * 1024
MAX_OUTPUT = 4 * 1024 * 1024
CODECS = ("base2048-qntm", "base2048-rust", "base32768", "base65536",
          "ecoji", "ecoji-v1", "ecoji-v2")


class EncodingError(Exception):
    """Malformed, noncanonical or oversized Unicode-encoded data."""


def _text(data: object) -> str:
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_INPUT:
            raise EncodingError("input exceeds byte limit")
        try:
            value = data.decode("utf-8", "strict")
        except UnicodeError as exc:
            raise EncodingError("input is not UTF-8") from exc
    elif isinstance(data, str):
        if len(data) > MAX_INPUT:
            raise EncodingError("input exceeds byte limit")
        value = data
    else:
        raise EncodingError("input must be bytes or text")
    try:
        if len(value.encode("utf-8", "strict")) > MAX_INPUT:
            raise EncodingError("input exceeds byte limit")
    except UnicodeError as exc:
        raise EncodingError("input contains invalid Unicode") from exc
    # Newlines are transport framing. Spaces, tabs, NBSP and variation selectors
    # are not silently dropped from an encoded alphabet.
    value = value.replace("\r", "").replace("\n", "")
    if any(char.isspace() for char in value):
        raise EncodingError("only CR/LF transport whitespace is permitted")
    return value


def _limit(max_bytes: object) -> int:
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_OUTPUT:
        raise EncodingError("max_bytes must be a positive integer within MAX_OUTPUT")
    return max_bytes


_QNTM = {
    "base2048-qntm": (_existing._B2048, 11, frozenset("01234567")),
    "base32768": (_existing._B32768, 15,
                  frozenset(_existing._expand(_tables.BASE32768_LAST_PAIRS))),
    "base65536": (_existing._B65536, 16,
                  frozenset(_existing._expand(_tables.BASE65536_LAST_PAIRS))),
}


def _qntm(text: str, codec: str, limit: int) -> bytes:
    reader, bits, terminal = _QNTM[codec]
    # Upper bound checked before allocating a decoded buffer.
    if len(text) * bits // 8 > limit + 1:
        raise EncodingError("decoded data exceeds byte limit")
    result = reader(text)
    if result is None:
        raise EncodingError("invalid alphabet or padding")
    count = (len(result) * 8 + bits - 1) // bits
    remainder = (len(result) * 8) % bits
    expects_terminal = 0 < remainder <= bits - 8
    if len(text) != count or (bool(text) and (text[-1] in terminal) != expects_terminal):
        raise EncodingError("noncanonical terminal length")
    return result


def _ecoji(text: str, version: int, limit: int) -> bytes:
    """Split complete records before using the existing single-record decoder."""
    reader = _existing.d_ecoji if version == 1 else _existing.d_ecoji2
    pad = _tables.ECOJI_PAD
    output = bytearray()
    pos = 0
    while pos < len(text):
        end = min(pos + 4, len(text))
        if version == 2:
            # V2 permits one fill token for a short record; optional further fill
            # tokens can extend the record to four. A following data token starts
            # a fresh record, as in the canonical Go decoder's readFour().
            fill = text.find(pad, pos, end)
            if fill >= 0:
                end = fill + 1
                while end < min(pos + 4, len(text)) and text[end] == pad:
                    end += 1
                if end - fill > 1 and end - pos != 4:
                    raise EncodingError("partially extended Ecoji padding")
        group = text[pos:end]
        if version == 1 and len(group) != 4:
            raise EncodingError("Ecoji v1 records require four symbols")
        value = reader(group)
        if value is None:
            raise EncodingError("invalid Ecoji record, version, or padding")
        if len(output) + len(value) > limit:
            raise EncodingError("decoded data exceeds byte limit")
        output.extend(value)
        pos = end
    return bytes(output)


def decode(data: object, codec: str, *, max_bytes: int = MAX_OUTPUT) -> bytes:
    """Decode one explicit format or raise only EncodingError on invalid input.

    Empty input decodes to empty bytes. Ecoji auto mode accepts either complete
    version, never a mixture. All codecs preserve binary output and leading zeros.
    CR/LF line wrapping is permitted; other outside-alphabet characters fail.
    """
    try:
        limit = _limit(max_bytes)
        if not isinstance(codec, str) or codec not in CODECS:
            raise EncodingError("unknown codec")
        text = _text(data)
        if not text:
            return b""
        if codec in _QNTM:
            result = _qntm(text, codec, limit)
        elif codec == "base2048-rust":
            if len(text) * 11 // 8 > limit + 1:
                raise EncodingError("decoded data exceeds byte limit")
            result = _existing._b2048r(text)
            if result is None or len(text) != (8 * len(result) + 10) // 11:
                raise EncodingError("invalid Rust Base2048 encoding")
        elif codec == "ecoji":
            candidates = set()
            for version in (1, 2):
                try:
                    candidates.add(_ecoji(text, version, limit))
                except EncodingError:
                    pass
            if len(candidates) != 1:
                raise EncodingError("invalid or mixed-version Ecoji stream")
            result = candidates.pop()
        else:
            result = _ecoji(text, int(codec[-1]), limit)
        if len(result) > limit:
            raise EncodingError("decoded data exceeds byte limit")
        return result
    except EncodingError:
        raise
    except Exception as exc:
        # The carried decoders predate the declared-exception contract.
        raise EncodingError("invalid Unicode-encoded input") from exc


def steps(data: object) -> list[tuple[str, bytes]]:
    """Bounded strict candidates for an auto-decoder; ASCII-only data is not probed.

    Explicit decode() remains available for valid ASCII-only Base2048 strings.
    Suppressing that ambiguous alphabet in auto mode avoids a high branching cost.
    """
    try:
        text = _text(data)
    except EncodingError:
        return []
    if not any(ord(char) > 127 for char in text):
        return []
    output = []
    for codec in CODECS[:4] + ("ecoji",):
        try:
            value = decode(text, codec)
            if value:
                output.append((codec, value))
        except EncodingError:
            pass
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("codec", choices=CODECS)
    parser.add_argument("file", help="UTF-8 encoded file, or - for stdin")
    parser.add_argument("--max-bytes", type=int, default=MAX_OUTPUT)
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.file == "-":
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
        else:
            with Path(args.file).open("rb") as stream:
                raw = stream.read(MAX_INPUT + 1)
        sys.stdout.buffer.write(decode(raw, args.codec, max_bytes=args.max_bytes))
        return 0
    except (EncodingError, OSError, ValueError) as exc:
        print(f"encdepth_unicode: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
