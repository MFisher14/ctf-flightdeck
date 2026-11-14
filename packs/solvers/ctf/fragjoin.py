"""Split-metadata flag fragments: read every metadata text field of an image in file order, and join
fragments when one opens a flag (`<prefix>{`) and a later one closes it (`}`) (B-013).

The Spooky "Tormented Tanny" class: a PNG whose flag is cut across a tEXt chunk, the XMP packet in an
iTXt chunk and the eXIf chunk. Every field is readable, and none holds the flag alone.

    fields(data)              [Field(container, name, text, offset)] in file order, for PNG (tEXt, zTXt,
                              iTXt incl. XMP, eXIf, private text chunks), JPEG (Exif, XMP, COM), GIF
                              comments and a bare TIFF/EXIF block. [] for anything else.
    header_fields(headers)    [Field] from HTTP header (name, value) pairs (B-076): every value, or
                              `key=value` item of one, that is strict base64 of printable text, decoded,
                              in the order of the part number its key or header carries (`part1`,
                              `fragment_2`, `3of5`), header order otherwise. Feed it to join().
    join(fields, ff)          [Join(flag, parts)]: every in-order concatenation of an opening fragment,
                              zero or more whole middle fragments and a closing fragment that the event's
                              flag format (ff: ctf.flagfmt.FlagFormat) accepts. Most complete first.

Pure Python, bounded (fields per file, bytes per field, inflate size, IFD count); nothing is executed.
A join is a candidate, never proof: the caller reports it as such.
"""
from __future__ import annotations

import base64
import binascii
import re
import struct
import zlib
from dataclasses import dataclass
from itertools import combinations

MAX_FIELDS = 2000            # fields read from one file
MAX_FIELD = 1 << 16          # bytes of one field kept
MAX_INFLATE = 1 << 20        # a compressed text chunk inflating past this is cut
WINDOW = 12                  # fields after an opening fragment searched for its close
MAX_MIDDLE = 6               # middle fragments considered between an open and a close (2**6 subsets)

PNG_SIG = b"\x89PNG\r\n\x1a\n"
_XMP_TEXT = re.compile(r">([^<>]+)<")
_XMP_ATTR = re.compile(r"\s([A-Za-z_][\w.-]*:[\w.-]+)=\"([^\"]*)\"")
_ATTR_NOISE = ("xmlns", "rdf:", "x:xmptk", "xml:")      # namespace and RDF plumbing, not values

TIFF_TAGS = {0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0131: "Software",
             0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright", 0x9286: "UserComment",
             0x9003: "DateTimeOriginal", 0xA420: "ImageUniqueID", 0x9C9B: "XPTitle", 0x9C9C: "XPComment",
             0x9C9D: "XPAuthor", 0x9C9E: "XPKeywords", 0x9C9F: "XPSubject", 0x000D: "GPSProcessing"}
_TIFF_POINTERS = (0x8769, 0x8825, 0xA005)          # Exif, GPS, Interop IFDs
_TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8}


@dataclass(frozen=True)
class Field:
    container: str           # png:tEXt, png:iTXt/xmp, png:eXIf, jpeg:exif, jpeg:xmp, jpeg:COM, gif:comment, ...
    name: str                # keyword / tag name / XMP element
    text: str
    offset: int              # byte offset of the container in the file


@dataclass(frozen=True)
class Join:
    flag: str
    parts: tuple             # the Fields joined, in order


def _printable(b: bytes) -> bool:
    return bool(b) and sum(32 <= c < 127 or c in (9, 10, 13) for c in b) >= 0.8 * len(b)


def _inflate(b: bytes) -> bytes | None:
    try:
        d = zlib.decompressobj()
        return d.decompress(b, MAX_INFLATE)
    except zlib.error:
        return None


def _xmp(text: str, container: str, offset: int) -> list[Field]:
    """The text nodes and attribute values of an XMP packet, in document order."""
    found = []
    for m in _XMP_TEXT.finditer(text):
        v = m.group(1).strip()
        if v:
            found.append((m.start(), "text", v))
    for m in _XMP_ATTR.finditer(text):
        if m.group(1).startswith(_ATTR_NOISE) or not m.group(2).strip():
            continue
        found.append((m.start(), m.group(1), m.group(2).strip()))
    return [Field(container, name, v[:MAX_FIELD], offset) for _, name, v in sorted(found)]


def _text_or_xmp(container: str, name: str, text: str, offset: int) -> list[Field]:
    if "<x:xmpmeta" in text or "<rdf:RDF" in text:
        return _xmp(text, container + "/xmp", offset)
    text = text.strip("\x00").strip()
    return [Field(container, name, text[:MAX_FIELD], offset)] if text else []


def tiff_fields(b: bytes, container: str, offset: int = 0) -> list[Field]:
    """ASCII, UserComment and XP* fields of a TIFF/EXIF block (b starts at its II/MM header)."""
    if b[:4] == b"II*\x00":
        e = "<"
    elif b[:4] == b"MM\x00*":
        e = ">"
    else:
        return []
    out, seen = [], set()
    todo = [struct.unpack_from(e + "I", b, 4)[0]]
    while todo and len(seen) < 32 and len(out) < MAX_FIELDS:
        ifd = todo.pop(0)
        if ifd in seen or ifd + 2 > len(b) or ifd < 8:
            continue
        seen.add(ifd)
        n = struct.unpack_from(e + "H", b, ifd)[0]
        for k in range(min(n, 512)):
            at = ifd + 2 + 12 * k
            if at + 12 > len(b):
                break
            tag, typ, count = struct.unpack_from(e + "HHI", b, at)
            size = _TYPE_SIZE.get(typ, 0) * count
            if size <= 4:
                raw = b[at + 8:at + 8 + size]
            else:
                ptr = struct.unpack_from(e + "I", b, at + 8)[0]
                raw = b[ptr:ptr + min(size, MAX_FIELD)]
            if tag in _TIFF_POINTERS and typ in (4, 13):
                todo.append(struct.unpack_from(e + "I", b, at + 8)[0])
                continue
            name = TIFF_TAGS.get(tag, f"tag 0x{tag:04x}")
            text = None
            if typ == 2:
                text = raw.split(b"\x00")[0].decode("latin-1")
            elif tag == 0x9286 and len(raw) > 8:
                head, body = raw[:8], raw[8:]
                text = body.decode("utf-16-le" if head.startswith(b"UNICODE") and e == "<" else
                                   "utf-16-be" if head.startswith(b"UNICODE") else "latin-1", "replace")
            elif 0x9C9B <= tag <= 0x9C9F:
                text = raw.decode("utf-16-le", "replace")
            elif typ == 7 and _printable(raw):
                text = raw.decode("latin-1")
            if text is not None:
                out += _text_or_xmp(container, name, text.strip("\x00"), offset)
        nxt = ifd + 2 + 12 * n
        if nxt + 4 <= len(b):
            todo.append(struct.unpack_from(e + "I", b, nxt)[0])
    return out


def _png(data: bytes) -> list[Field]:
    out, i = [], 8
    while i + 12 <= len(data) and len(out) < MAX_FIELDS:
        ln = struct.unpack_from(">I", data, i)[0]
        typ = data[i + 4:i + 8]
        body = data[i + 8:i + 8 + ln]
        if len(body) != ln or not typ.isalpha():
            break
        t = typ.decode("ascii")
        if t == "tEXt":
            k, _, v = body.partition(b"\x00")
            out += _text_or_xmp("png:tEXt", k.decode("latin-1"), v.decode("latin-1"), i)
        elif t == "zTXt":
            k, _, v = body.partition(b"\x00")
            text = _inflate(v[1:])
            if text is not None:
                out += _text_or_xmp("png:zTXt", k.decode("latin-1"), text.decode("latin-1"), i)
        elif t == "iTXt":
            k, _, rest = body.partition(b"\x00")
            if len(rest) >= 2:
                comp = rest[0]
                _lang, _, rest2 = rest[2:].partition(b"\x00")
                _tk, _, v = rest2.partition(b"\x00")
                v = _inflate(v) if comp else v
                if v is not None:
                    out += _text_or_xmp("png:iTXt", k.decode("latin-1"), v.decode("utf-8", "replace"), i)
        elif t == "eXIf":
            out += tiff_fields(body, "png:eXIf", i)
        elif t[0].islower() and t not in ("tRNS", "gAMA", "cHRM", "sRGB", "iCCP", "sBIT", "bKGD", "hIST",
                                         "pHYs", "sPLT", "tIME") and _printable(body):
            out += _text_or_xmp(f"png:{t}", t, body.decode("latin-1"), i)
        if t == "IEND":
            break
        i += 12 + ln
    return out


def _jpeg(data: bytes) -> list[Field]:
    out, i, n = [], 2, len(data)
    while i + 4 <= n and len(out) < MAX_FIELDS:
        if data[i] != 0xFF:
            break
        m = data[i + 1]
        if m == 0xFF:
            i += 1
            continue
        if m in (0xD9, 0xDA):                     # end, or start of scan: no metadata after it
            break
        if m == 0x01 or 0xD0 <= m <= 0xD7:
            i += 2
            continue
        ln = struct.unpack_from(">H", data, i + 2)[0]
        body = data[i + 4:i + 2 + ln]
        if m == 0xE1 and body.startswith(b"Exif\x00\x00"):
            out += tiff_fields(body[6:], "jpeg:exif", i)
        elif m == 0xE1 and body.startswith(b"http://ns.adobe.com/xap/1.0/\x00"):
            out += _xmp(body.split(b"\x00", 1)[1].decode("utf-8", "replace"), "jpeg:xmp", i)
        elif m == 0xFE:
            out += _text_or_xmp("jpeg:COM", "comment", body.decode("utf-8", "replace"), i)
        i += 2 + ln
    return out


def _gif(data: bytes) -> list[Field]:
    out = []
    if len(data) < 13:
        return out
    flags = data[10]
    i = 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)
    while i < len(data) and len(out) < MAX_FIELDS:
        b = data[i]
        if b == 0x3B:
            break
        if b == 0x21 and i + 1 < len(data):
            label, start = data[i + 1], i
            i += 2
        elif b == 0x2C and i + 10 <= len(data):
            lf = data[i + 9]
            i += 10 + (3 * (2 << (lf & 7)) if lf & 0x80 else 0) + 1   # + the LZW minimum code size
            label = start = None
        else:
            break
        parts = []
        while i < len(data):
            ln = data[i]
            if ln == 0:
                i += 1
                break
            parts.append(data[i + 1:i + 1 + ln])
            i += 1 + ln
        if label == 0xFE:
            out += _text_or_xmp("gif:comment", "comment", b"".join(parts).decode("latin-1"), start)
    return out


def fields(data: bytes) -> list[Field]:
    """Every metadata text field of an image, in file order ([] for a file that is no image read here)."""
    data = bytes(data)
    try:
        if data.startswith(PNG_SIG):
            return _png(data)
        if data[:2] == b"\xff\xd8":
            return _jpeg(data)
        if data[:6] in (b"GIF87a", b"GIF89a"):
            return _gif(data)
        if data[:4] in (b"II*\x00", b"MM\x00*"):
            return tiff_fields(data, "tiff", 0)
    except (struct.error, IndexError, ValueError):
        return []                                  # a damaged header: what a reader cannot walk has no fields
    return []


# ---------------------------------------------------------------- HTTP header fragments (B-076)

MIN_B64 = 8                  # a shorter token is a word ("text", "gzip"), not a base64 value
_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_B64URL = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_KEYVAL = re.compile(r"([A-Za-z_][\w.\-]*)=(.+)")
_ITEM_SPLIT = re.compile(r"[;,&\s]+")
# The part number a key or a header name carries: part1, part_2, fragment-3, frag4, piece5, chunk6, seg7,
# 3of5, 3/5. A key with none keeps its place.
_PART = re.compile(r"(?i)(?:part|fragment|frag|piece|chunk|segment|seg)[_\-.]?(\d{1,4})(?!\d)"
                   r"|(?<!\d)(\d{1,4})(?:of|/)\d{1,4}(?!\d)")


def b64_text(token: str) -> str | None:
    """The text a strict base64 (or base64url) token decodes to, or None: at least MIN_B64 characters of
    one alphabet, padding repaired only when missing, and the decoding UTF-8 with no control character
    but tab and line breaks. Nothing else is guessed at."""
    t = token.strip()
    if len(t) < MIN_B64:
        return None
    if _B64.fullmatch(t):
        dec = base64.b64decode
    elif _B64URL.fullmatch(t) and ("-" in t or "_" in t):
        dec = base64.urlsafe_b64decode
    else:
        return None
    body = t.rstrip("=")
    if len(body) % 4 == 1:
        return None
    try:
        raw = dec(body + "=" * (-len(body) % 4))
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text.strip() or any(not (c.isprintable() or c in "\t\r\n") for c in text):
        return None
    return text


def part_number(name: str) -> int | None:
    """The part number a key or header name carries (`deflector_part2` -> 2, `X-Frag-3` -> 3), or None."""
    m = _PART.search(name or "")
    if not m:
        return None
    return int(m.group(1) or m.group(2))


def header_values(name: str, value: str) -> list[tuple[str, str, str]]:
    """[(field name, encoded token, decoded text)] of one header: the whole value when it is base64 of
    text, else each `key=value` item (or bare token) of it that is. The field name is the header's, or
    `<header>:<key>` for an item."""
    out = []
    whole = b64_text(value)
    if whole is not None:
        return [(name, value.strip(), whole)]
    for item in _ITEM_SPLIT.split(value or ""):
        if not item:
            continue
        text = b64_text(item)
        if text is not None:
            out.append((name, item, text))
            continue
        m = _KEYVAL.fullmatch(item)
        if m:
            text = b64_text(m.group(2))
            if text is not None:
                out.append((f"{name}:{m.group(1)}", m.group(2), text))
    return out


def header_fields(headers, container: str = "http:header", offset: int = 0) -> list[Field]:
    """[Field] of the base64 header values of one message (or of several, in order): `headers` is
    [(name, value)]. Fields whose key or header name carries a part number are put in that number's
    order in the places they hold (an unnumbered field keeps its place); join() then reads them in turn."""
    found = []
    for i, (name, value) in enumerate(list(headers)[:MAX_FIELDS]):
        for fname, _token, text in header_values(str(name), str(value)):
            found.append(Field(container, fname, text[:MAX_FIELD], offset + i))
    return part_order(found)


def part_order(found: list[Field]) -> list[Field]:
    """The fields whose name carries a part number sorted by it, in the places such fields hold; every
    other field keeps its place (a stable sort, so two fields of one number keep their order)."""
    found = list(found)
    slots = [i for i, f in enumerate(found) if part_number(f.name) is not None]
    ordered = sorted((found[i] for i in slots), key=lambda f: part_number(f.name))
    for i, f in zip(slots, ordered):
        found[i] = f
    return found


def _word_start(text: str, brace: int) -> int:
    s = brace
    while s > 0 and (text[s - 1].isalnum() or text[s - 1] == "_"):
        s -= 1
    return s


def _openings(text: str, ff) -> list[str]:
    """The tails of `text` that start a flag in the event's format and are not closed in `text`."""
    heads = []
    for at, ch in enumerate(text):
        if ch != "{" or "}" in text[at:]:
            continue
        s = _word_start(text, at)
        word = text[s:at]
        if not word:
            continue
        prefixes = ff.spec.prefixes
        if prefixes:
            for p in sorted(prefixes, key=len, reverse=True):
                same = word.endswith(p) if ff.spec.case == "exact" else word.lower().endswith(p.lower())
                if same:
                    heads.append(text[at - len(p):])
                    break
        elif word[0].isalpha():
            heads.append(text[s:])
    return heads


def _flaglike(text: str) -> bool:
    """A middle fragment that reads like part of a flag body: no white space, no separators of prose."""
    return bool(text) and not any(c.isspace() for c in text) and all(c.isalnum() or c in "_-!@#$%^&*.?+=~" for c in text)


def join(found: list[Field], ff) -> list[Join]:
    """Every flag the event's format accepts made of: the open tail of one field, zero or more whole
    fields after it, and the head of a later field up to its first '}'. Ranked: the fewest middle
    fields that do not read like a flag body ("GIMP 2.10", a date), then the most that do."""
    out, seen = [], set()
    texts = [f.text for f in found]
    for i, f in enumerate(found):
        for head in _openings(f.text, ff):
            for j in range(i + 1, min(len(found), i + 1 + WINDOW)):
                close = texts[j].find("}")
                if close < 0:
                    continue
                tail = texts[j][:close + 1]
                middle = [k for k in range(i + 1, j) if "{" not in texts[k] and "}" not in texts[k]][:MAX_MIDDLE]
                before = len(out)
                for r in range(len(middle), -1, -1):
                    for pick in combinations(middle, r):
                        flag = head + "".join(texts[k] for k in pick) + tail
                        if flag in seen or not ff.is_flag(flag):
                            continue
                        seen.add(flag)
                        out.append(Join(flag, (f,) + tuple(found[k] for k in pick) + (found[j],)))
                if len(out) > before:
                    break                          # the first closing field that makes a flag ends this opening
    def rank(jn):
        middle = [p.text for p in jn.parts[1:-1]]
        return (sum(not _flaglike(t) for t in middle), -sum(_flaglike(t) for t in middle))
    out.sort(key=rank)
    return out
