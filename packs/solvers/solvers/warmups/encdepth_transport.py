#!/usr/bin/env python3
"""Strict offline transport-codec adapters; supplied content is never executed.

Existing warmup readers cover ordinary QP/UU/Ascii85. These adapters add complete
framing/padding checks, PDF end-marker-only and btoa ``y`` bodies, real RFC1924
IPv6, and IDNA2008 validation. RFC2045 QP accepts CRLF or preserved Unix LF;
lowercase escapes require an explicit opt-in. No filenames inside UU are used.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import re
import sys

MAX_INPUT = 1 << 20
_ASCII85_WS = b"\x00\t\n\x0c\r "
_RFC1924 = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"


class TransportError(ValueError):
    """Invalid, unsupported or oversized encoded input."""


def _bytes(data: object) -> bytes:
    if isinstance(data, str):
        if len(data) > MAX_INPUT:
            raise TransportError("input limit exceeded")
        try:
            data = data.encode("ascii")
        except UnicodeError as exc:
            raise TransportError("ASCII input required") from exc
    if not isinstance(data, (bytes, bytearray)):
        raise TransportError("bytes or ASCII text required")
    if len(data) > MAX_INPUT:
        raise TransportError("input limit exceeded")
    return bytes(data)


def _lines(data: bytes) -> list[bytes]:
    """Transport lines without terminators; never silently discard a lone CR."""
    if b"\r" in data.replace(b"\r\n", b""):
        raise TransportError("bare CR is not a line ending")
    rows = data.replace(b"\r\n", b"\n").split(b"\n")
    if rows[-1:] == [b""]:
        rows.pop()
    return rows


def decode_qp(data: object, *, allow_lowercase: bool = False) -> bytes:
    """Decode complete RFC2045 QP syntax, stripping transport trailing SP/TAB.

    The output preserves hard LF/CRLF line endings. Unlike RFC2047 Q encoding,
    underscores remain underscores. Reject raw non-ASCII and malformed escapes.
    """
    raw = _bytes(data)
    if type(allow_lowercase) is not bool:
        raise TransportError("allow_lowercase must be bool")
    _lines(raw)  # validate CRs without changing the original newline representation
    normalized = bytearray()
    hexchars = b"0123456789ABCDEFabcdef" if allow_lowercase else b"0123456789ABCDEF"
    for line in raw.splitlines(keepends=True):
        # splitlines recognizes more controls; those are rejected below.
        ending = b"\r\n" if line.endswith(b"\r\n") else b"\n" if line.endswith(b"\n") else b""
        body = line[:-len(ending)] if ending else line
        if len(body) > 76:
            raise TransportError("QP line exceeds 76 characters")
        body = body.rstrip(b" \t")
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == 61:
                if i == len(body) - 1 and ending:
                    i += 1
                    continue
                if i + 2 >= len(body) or any(c not in hexchars for c in body[i + 1:i + 3]):
                    raise TransportError("invalid QP escape or dangling equals")
                i += 3
                continue
            if ch not in (9, 32) and not (33 <= ch <= 60 or 62 <= ch <= 126):
                raise TransportError("invalid literal QP byte")
            i += 1
        normalized.extend(body + ending)
    try:
        return binascii.a2b_qp(bytes(normalized))
    except (ValueError, binascii.Error) as exc:
        raise TransportError("invalid QP payload") from exc


def decode_uu(data: object) -> bytes:
    """Decode one complete begin/end UU or begin-base64/==== record."""
    rows = _lines(_bytes(data))
    if len(rows) < 2 or not re.fullmatch(rb"begin(?:-base64)? [0-7]{3} [^\x00-\x1f\x7f]+", rows[0]):
        raise TransportError("one framed UU record required")
    if rows[0].startswith(b"begin-base64 "):
        if rows[-1] != b"====":
            raise TransportError("begin-base64 requires ==== terminator")
        body = b"".join(rows[1:-1])
        if any(not row or len(row) > 76 for row in rows[1:-1]):
            raise TransportError("invalid base64 transport line")
        try:
            out = base64.b64decode(body, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise TransportError("invalid base64 payload") from exc
        if base64.b64encode(out) != body:
            raise TransportError("noncanonical base64 padding")
        return out
    if len(rows) < 3 or rows[-1] != b"end" or rows[-2] not in (b"`", b" "):
        raise TransportError("UU requires zero-length line followed by end")
    out = bytearray()
    for row in rows[1:-2]:
        if not row or not 33 <= row[0] <= 77:
            raise TransportError("invalid UU length byte")
        length = row[0] - 32
        if len(row) != 1 + 4 * ((length + 2) // 3) or any(c < 32 or c > 96 for c in row[1:]):
            raise TransportError("UU length/alphabet mismatch")
        try:
            decoded = binascii.a2b_uu(row)
            canonical = binascii.b2a_uu(decoded).rstrip(b"\n")
        except (ValueError, binascii.Error) as exc:
            raise TransportError("invalid UU payload") from exc
        if canonical.replace(b"`", b" ") != row.replace(b"`", b" "):
            raise TransportError("nonzero UU padding bits")
        out.extend(decoded)
    return bytes(out)


def decode_ascii85(data: object, *, dialect: str = "pdf") -> bytes:
    """PDF/Adobe ASCII85 or bare btoa body (``y`` means four spaces).

    ``pdf`` requires ~> and permits optional <~. ``btoa-body`` has no framing:
    a full xbtoa record needs its length/checksum parsed elsewhere. Padding aliases
    and lone final digits are rejected; z and !!!!! are both valid zero words.
    """
    raw = _bytes(data)
    if dialect not in ("pdf", "btoa-body"):
        raise TransportError("dialect must be pdf or btoa-body")
    raw = raw.strip(_ASCII85_WS)
    if dialect == "pdf":
        if not raw.endswith(b"~>"):
            raise TransportError("PDF ASCII85 requires ~> terminator")
        raw = raw[:-2]
        if raw.startswith(b"<~"):
            raw = raw[2:]
    # PDF delimiters are lexical tokens: interior whitespace is permitted only
    # in the encoded body, never between the two characters of either marker.
    raw = raw.translate(None, _ASCII85_WS)
    expanded = bytearray()
    digits = 0
    for ch in raw:
        if ch == 122 or (ch == 121 and dialect == "btoa-body"):
            if digits % 5:
                raise TransportError("ASCII85 abbreviation inside a group")
            expanded.extend(b"!!!!!" if ch == 122 else b"+<VdL")
        elif 33 <= ch <= 117:
            digits += 1
            expanded.append(ch)
        else:
            raise TransportError("invalid ASCII85 symbol")
    if digits % 5 == 1:
        raise TransportError("lone final ASCII85 digit")
    try:
        out = base64.a85decode(raw, foldspaces=dialect == "btoa-body", ignorechars=b"")
        rebuilt = base64.a85encode(out).replace(b"z", b"!!!!!")
    except (ValueError, binascii.Error, OverflowError) as exc:
        raise TransportError("invalid ASCII85 word") from exc
    if rebuilt != expanded:
        raise TransportError("noncanonical final ASCII85 group")
    return out


def decode_rfc1924(data: object) -> bytes:
    """Decode one 20-digit RFC1924 IPv6 integer to exactly 16 network-order bytes."""
    raw = _bytes(data)
    if len(raw) != 20:
        raise TransportError("RFC1924 IPv6 needs exactly 20 digits")
    value = 0
    for ch in raw:
        digit = _RFC1924.find(bytes([ch]))
        if digit < 0:
            raise TransportError("invalid RFC1924 symbol")
        value = value * 85 + digit
    if value >= 1 << 128:
        raise TransportError("RFC1924 value exceeds IPv6 range")
    return value.to_bytes(16, "big")


def decode_idna(data: object) -> bytes:
    """Validate a complete ASCII IDNA2008 domain, return its Unicode UTF-8 form.

    Uses the idna package, not Python's older IDNA2003 codec. No DNS lookup.
    ASCII case is normalized; an optional trailing DNS root dot is retained.
    """
    raw = _bytes(data)
    if not raw or len(raw) > 254:
        raise TransportError("IDNA domain length invalid")
    try:
        import idna
    except ImportError as exc:
        raise TransportError("IDNA2008 requires the idna package") from exc
    try:
        text = idna.decode(raw.lower(), strict=True, uts46=False)
        rebuilt = idna.encode(text, strict=True, uts46=False)
    except (idna.IDNAError, UnicodeError, ValueError) as exc:
        raise TransportError("invalid IDNA2008 domain") from exc
    if rebuilt != raw.lower():
        raise TransportError("IDNA domain does not round-trip")
    return text.encode("utf-8")


def steps(data: object) -> list[tuple[str, bytes]]:
    """Strongly marked adapters for layered search; declines malformed input."""
    try:
        raw = _bytes(data)
    except TransportError:
        return []
    readers = []
    if re.search(rb"=(?:[0-9A-F]{2}|\r?\n)", raw):
        readers.append(("quoted-printable", decode_qp))
    if raw.startswith((b"begin ", b"begin-base64 ")):
        readers.append(("uu-framed", decode_uu))
    stripped = raw.strip(_ASCII85_WS)
    if stripped.startswith(b"<~") or stripped.endswith(b"~>"):
        readers.append(("ascii85-pdf", decode_ascii85))
    if raw.lower().startswith(b"xn--") or b".xn--" in raw.lower():
        readers.append(("idna2008", decode_idna))
    result = []
    for name, reader in readers:
        try:
            value = reader(raw)
        except TransportError:
            continue
        if value != raw:
            result.append((name, value))
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("codec", choices=("qp", "qp-lowercase", "uu", "ascii85-pdf", "btoa-body", "rfc1924", "idna2008"))
    parser.add_argument("file", help="encoded input file; decoded bytes go to stdout")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        with open(args.file, "rb") as stream:
            data = stream.read(MAX_INPUT + 1)
        if args.codec.startswith("qp"):
            output = decode_qp(data, allow_lowercase=args.codec == "qp-lowercase")
        elif args.codec == "uu":
            output = decode_uu(data)
        elif args.codec in ("ascii85-pdf", "btoa-body"):
            output = decode_ascii85(data, dialect="pdf" if args.codec == "ascii85-pdf" else "btoa-body")
        elif args.codec == "rfc1924":
            output = decode_rfc1924(data)
        else:
            output = decode_idna(data)
        sys.stdout.buffer.write(output)
    except (TransportError, OSError, ValueError) as exc:
        print(f"encdepth_transport: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
