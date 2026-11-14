#!/usr/bin/env python3
"""Read a specimen's plan by its own codec label (Day 7: .sh advanced fixtures, .mjs Node specimens).

A specimen stores one `Material_<id>` literal and names its codec in `Codec_<id>` =
"representation|transform|key" (either name in any case, paired by the id in any case; row 49). This module reads both as text (nothing is run), decodes the
material exactly as the label says, and accepts the result only when plan_codec's strict plan
grammar does, or, for a plan whose first key after `v=` is not `steps` (the advanced Bash
fixtures: `v=1|feature=...`), when every field is `key=value` with a lowercase key.

    reading(text) -> (str | None, cut)  the plan text, or None (no label, nothing decodes, two plans);
                                   cut when the material was read from a piece: no last field
    read_text(text) -> str | None  the plan text of reading()
    read(text) -> dict | None      the same plan, flattened (plan_codec.flatten)
    answers(text, questions, ext) -> {qid: value}

Since row 37 (2026-10-07) generic.read() calls reading() for every extension, as a second plan
source when plan_codec gives no plan or a cut one, and answers from it through its own tables.
answers() is kept for the command line and for a racer's shapes_<ext>.py.

A piece: a right-hand side that holds code besides its literals and their joins (a call, a
variable, `$(printf ...)` inside a literal), or the first line of a statement that goes on. What
its literals give may be cut short, so the plan's last field is left out, as plan_codec does.

The material is the whole right-hand side of its assignment, also when that runs over several
lines (an open bracket, a line that ends or starts with a join operator, a VB `_`). Rows 56 to 58
(2026-10-07): a here-document, long bracket, template, raw string, here-string or continuation
section is read as ONE value (plan_codec.block_at), a list joined with nothing and a side of
nothing but character calls are whole, and the fallback also inflates zlib and gzip streams, reads
ascii85, z85 and 8-bit binary groups written together, and one nested level. What the
label says is tried first. When that gives no plan (a label in another form, `xor_hex|cd`; a
key written in decimal or with `0x`; a representation this file has no reader for), every
representation reader is tried on the literal text and on its reverse, every byte order, every
transform with every reading of every key the label holds, and the reverse of the result: only
text the plan grammar accepts counts, and two different plans are no plan.

Row 79 (2026-10-07) adds, to the labelled path and to the fallback: RC4 with its key in the label (as
text, hex, `0x` or decimal), Vigenere (letters only, the key advancing per letter or per character)
and ROT13/ROT-N on the letters, a nibble swap, a bit reversal per byte, bz2 and xz/lzma streams beside
zlib and gzip (bounded the same way), percent-encoding with literal characters, UTF-16LE and UTF-16BE
text, base58 and base91, the material's own text, ROT13/ROT-N/Vigenere on the representation's text,
and two stacked transforms in either order (`xor_then_add|5a,13`, `add_then_xor`, `reverse_then_rc4`,
`zlib_then_xor`). The fallback screens every chain on the first bytes of its output (a plan, a UTF-16
plan or a compressed stream must start there) and on its last bytes for the output read backwards,
and decodes in full only what passes. A plan found by anything row 79 added must also pass _strict: a
`steps=` field of step names, or a JSON plan whose keys are names, whose values are printable and whose
steps are a list of step names (a letter rotation that keeps `v=` would otherwise give a second,
garbled plan).

Review fixes (2026-10-07). The fallback runs in two passes: first exactly the search it made before
row 79 (its readers, zlib and gzip, one transform, under _grammar); what that finds is the answer, as
it was, and only when it finds nothing does row 79's search run. A pair of byte maps that one map with
a key the label does not hold matches on most of the input's bytes but not all is a near miss and gives
nothing (it would answer a garbled value: `stage_count=3` for 2). A compressed stream counts only when
it reaches its end, and so its checksum (zlib, gzip, bz2, xz) or its end marker (lzma-alone), within
MAX_INFLATE: one cut short gives no plan (plan_codec._inflated likewise). An opened stream longer than
MAX_SEARCH is only taken as it is, not searched.

Row 92 (2026-10-07): raw (headerless) deflate, as PowerShell's [IO.Compression.DeflateStream], .NET's
DeflateStream and PHP's gzinflate write it (plan_codec.raw_inflate: it must reach its end within
MAX_INFLATE bytes and a ratio, its input must end there too, or with its adler32, or with at most a few
bytes when it gives a plan). Labelled: the decompress transform (deflate, raw_deflate, inflate, gzinflate,
deflatestream ..., alone or stacked) opens a raw stream when no header names another, and a labelled output
that is a raw stream is opened (_accept). The fallback's second pass opens a raw stream in every reading
(_opened) and screens one stage of the label's before a raw stream (_raw_search). A `new byte[] { .. }` side
is read as its numbers, whole.

Answers: the plan's own values (adapter, campaign_id, stage_count, feature, primitive, the asked
indicator), steps joined with '>' when the format says so, role and attack by the judged tables
or labels.pick (unsure) for a step list no day has judged.
"""
import base64
import bz2
import itertools
import json
import lzma
import operator
import re
import sys
import urllib.parse
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE, HERE.parent / "common"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import labels  # noqa: E402
import plan_codec  # noqa: E402

_STR = re.compile(r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"|`((?:[^`\\$]|\\.)*)`")
MAX_RHS = 200_000    # characters of one assignment that are read, at most
MAX_LINES = 400      # lines one assignment may run over


# A Tcl word in braces, `{..}` with nothing in it that Tcl would read (row 71): one literal.
_TCL_WORD = re.compile(r"[ \t]*\{([^{}$\[\]\\\"'\r\n]+)\}[ \t]*")


def _content(rhs: str, dialect: str = "") -> str:
    """The text of a right-hand side's literals, joined; a literal spelled with numeric escapes as the text
    they stand for (row 78: `"\\u{38}\\u{39},.."` is `89,..`, never the numbers of its escapes), read in the
    language's `dialect` (plan_codec.escape_dialect)."""
    word = _TCL_WORD.fullmatch(rhs)
    if word:
        return word.group(1)
    joined = "".join(a or b or c for a, b, c in _STR.findall(rhs)) or rhs
    if "\\" in joined:
        raw = plan_codec.unescaped(joined, dialect)
        if raw and all(32 <= x < 127 for x in raw):
            return bytes(raw).decode("ascii")
    return joined


# ---------------------------------------------------------------- where the material and the label are

# `Material_x = `, `$Material_x = `, `readonly Material_x=`, `const Material_x: string = `,
# `Material_x := `, `Material_x <- `, `set Material_x to `: the name, then the operator. The name
# in any case (Day 5's .py files write `MATERIAL_x`). Row 49 (2026-10-07): Batch's quoted
# `set "Material_x=..."`, whose value ends at the closing quote (group `bq`), and PHP's
# `define('Material_x', ...)`, whose operator is the comma (group `df`). Row 71: a VBA type before the
# operator (`Const Codec_x As String = `), and Tcl's `set Material_x <value>`, whose operator is the
# white space after the name (group `tcl`; never AppleScript's `set .. to`, read by ` to `).
_ASSIGN = (r"(?:(?P<bq>(?<![\w$])(?i:set)[ \t]+\")|(?P<df>(?<![\w$])(?i:define)[ \t]*\([ \t]*['\"])"
           r"|(?P<tcl>(?<![\w$\"])set[ \t]+(?:-[A-Za-z]+[ \t]+)*|\((?:def|define)[ \t]+)|(?<![\w$])\$?)"
           r"(?i:{kind})_(?P<id>\w+)['\"]?(?(tcl)|[ \t]*(?::[ \t]*[\w.\[\]<>|]+[ \t]*|[ \t]As[ \t]+\w+[ \t]*)?)"
           r"(?(df),|(?(tcl)[ \t]+(?!to[ \t])(?=[\"'{{\[\w(#$])|(?:=(?![=>])|:=|<-|[ \t]to[ \t]|:(?=[ \t]*[\"'`\[]))))[ \t]*")
_MATERIAL = re.compile(_ASSIGN.format(kind="Material"))
_BATCH_VAR = re.compile(r"%[A-Za-z_][\w:~,-]*%|![A-Za-z_][\w:~,-]*!")
_CODEC = re.compile(_ASSIGN.format(kind="Codec"))
_OPEN, _CLOSE = "([{", ")]}"
_JOIN_END = re.compile(r"(?:\+|&|\.\.?|\\|(?<![\w.])_|,|[(\[{]|<<)[ \t]*$")
_JOIN_START = re.compile(r"^[ \t]*(?:\+|&|\.\.?(?!\.)|<<)")
_NUMBER = re.compile(r"(?<![\w$])(?:0[xX][0-9A-Fa-f]+|&H[0-9A-Fa-f]+|\d+)(?!\w)")
_INTERPOLATION = re.compile(r"\$[({A-Za-z_]|#\{")
_COMMENT = re.compile(r"(?:#|//|--|')[^\n]*")
_JOINS_ONLY = re.compile(r"[\s+&.,;:()\[\]{}\\_$@]*")
_NEW_ARRAY = re.compile(r"\s*new\s+(?:byte|sbyte|int|uint|short|ushort)\s*\[\s*\]\s*\{\s*(?:(?:0[xX][0-9A-Fa-f]{1,2}|\d{1,3})\s*,\s*)*"
                        r"(?:0[xX][0-9A-Fa-f]{1,2}|\d{1,3})\s*,?\s*\}\s*;?\s*")


def _code(s: str) -> str:
    """`s` without its literals, its numbers and its comments: the code around the material."""
    return _COMMENT.sub("", _NUMBER.sub("", _STR.sub("", s)))


def whole(rhs: str) -> bool:
    """Whether a right-hand side is its literals (or numbers) and nothing but joins between them.
    Anything else (a call, a variable, `$(printf ...)`) may build part of the material, so what
    the literals give is a piece of it."""
    if _TCL_WORD.fullmatch(rhs):
        return True
    # Row 56: a list of literals joined with nothing (implode('', [..]), [..].join(''), -join @(..), over
    # one line or several). Row 58: nothing but character calls (chr(118) . chr(61) . ..).
    if plan_codec.list_value(rhs) is not None or plan_codec.char_value(rhs) is not None:
        return True
    if _NEW_ARRAY.fullmatch(rhs):              # row 92: .NET's `new byte[] { 0x78, .. };`, one list of numbers
        return True
    if any(_INTERPOLATION.search(b or c) for _a, b, c in _STR.findall(rhs)):
        return False            # "$(printf ...)rest", "${part}", "#{x}": code inside a literal that interpolates
    return bool(_JOINS_ONLY.fullmatch(_code(rhs)))


def statement(text: str, start: int) -> str:
    """The right-hand side that begins at `start`: up to the end of its line, or further while a
    bracket is open, a triple-quoted or backquoted literal is open, or a line ends (or the next
    one starts) with a join. A `;` outside brackets ends it."""
    n = min(len(text), start + MAX_RHS)
    i, depth, quote, lines, line_start = start, 0, None, 0, start
    while i < n:
        if quote:
            if text[i] == "\\":
                i += 2
                continue
            if text.startswith(quote, i):
                i += len(quote)
                quote = None
                continue
            if text[i] != "\n" or len(quote) > 1 or quote == "`":
                i += 1
                continue
            quote = None                           # an unclosed one-line literal ends with its line
        c = text[i]
        if c in "'\"`":
            quote = text[i:i + 3] if text[i:i + 3] in ('"""', "'''") else c
            i += len(quote)
            continue
        if c in _OPEN:
            depth += 1
        elif c in _CLOSE:
            depth = max(0, depth - 1)
        elif c == ";" and depth == 0:
            return text[start:i]
        elif c == "\n":
            lines += 1
            j = text.find("\n", i + 1)
            line, rest = _code(text[line_start:i]).rstrip(), text[i + 1:j if j >= 0 else n]
            if lines >= MAX_LINES or depth == 0 and not _JOIN_END.search(line) and not _JOIN_START.match(rest):
                return text[start:i]
            line_start = i + 1
        i += 1
    return text[start:i]


def assignments(text: str, pattern) -> list:
    """[(id, the rest of its line, the whole statement)] for every assignment `pattern` finds, in
    file order. The line alone is what Day 7's files hold; the statement is read only when the
    line gives nothing (a trailing comment that ends in a comma must not join the next line).
    A Batch `set "Material_x=..."` ends at its closing quote: its value, quoted as the literal it
    is, is both its line and its statement (a value with no closing quote, or one that expands
    a `%name%` or `!name!`, is a piece)."""
    out = []
    for m in pattern.finditer(text):
        j = text.find("\n", m.end())
        line = text[m.end():j if j >= 0 else len(text)].rstrip("\r")
        block = None if m.group("bq") or m.group("df") else plan_codec.block_at(text, m.end())
        if block:
            # Row 56: a here-document, a long bracket, a template, a here-string over several lines: its
            # value (plan_codec.block_value) as the one literal it is. Joined to other code, a piece.
            value, piece = block
            q = next((c for c in "'\"" if c not in value), None)
            if q and "\\" not in value:
                side = q + value + q + (" + rest_of_value()" if piece else "")
                out.append((m.group("id"), side, side))
                continue
        if m.group("bq"):
            value, closed, _rest = line.partition('"')
            line = f'"{value}"' if closed and not _BATCH_VAR.search(value) else value
            out.append((m.group("id"), line, line))
            continue
        out.append((m.group("id"), line, statement(text, m.end())))
    return out


# ---------------------------------------------------------------- representations

_Z85 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#"
_B85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"
_Z85_TO_B85 = str.maketrans(_Z85, _B85)


def _byte_list(xs):
    xs = list(xs)
    if not xs or not all(0 <= x < 256 for x in xs):
        raise ValueError("not a byte list")
    return xs


def _hex(s: str):
    """Hex in any spelling: compact pairs, chunks of pairs, or byte tokens with a delimiter, quotes,
    `0x`, `\\x`, `%` or `&H` before them."""
    s = re.sub(r"0[xX]|\\x|&H|%", " ", s.replace('\\"', '"'))
    toks = re.findall(r"[0-9A-Za-z]+", s)
    if not toks or not all(re.fullmatch(r"[0-9A-Fa-f]+", t) for t in toks):
        raise ValueError("not hex")
    if all(len(t) <= 2 for t in toks) and len(toks) > 1:
        return [int(t, 16) for t in toks]
    if all(len(t) % 2 == 0 for t in toks):
        return list(bytes.fromhex("".join(toks)))
    raise ValueError("not hex")


def _b64(s: str):
    t = re.sub(r"\s+", "", s)
    t = t.translate(str.maketrans("-_", "+/"))
    return list(base64.b64decode(t + "=" * (-len(t) % 4), validate=True))


def _b32(s: str):
    t = re.sub(r"\s+", "", s).upper()
    return list(base64.b32decode(t + "=" * (-len(t) % 8)))


def _b85(s: str):
    t = re.sub(r"\s+", "", s)
    for f in (lambda: base64.b85decode(t), lambda: base64.a85decode(t, adobe=t.startswith("<~")),
              lambda: base64.b85decode(t.translate(_Z85_TO_B85))):
        try:
            return list(f())
        except Exception:  # noqa: BLE001 - the next alphabet
            continue
    raise ValueError("not base85")


def _decimal(s: str):
    # Row 213: every number of the material is read, or none is. A free-standing run of four or more digits is two
    # numbers run together (a lost separator), and reading around it gives a plan with bytes missing.
    # The run is looked for only once the list holds a number (no number raises in _byte_list all the same), so a
    # material with none, the common case in the fallback, pays one scan and not two.
    found = re.findall(r"(?<![0-9A-Za-z])\d{1,3}(?![0-9A-Za-z])", s)
    if found and _DECIMAL_RUN.search(s):
        raise ValueError("a run of four or more digits in a decimal list")
    return _byte_list(int(x) for x in found)


# A word (letters and digits) that holds a digit and is not one octal group `(0o)?[0-7]{3}`: one search, in C.
_OCTAL_ODD = re.compile(r"(?<![0-9A-Za-z])(?!(?:0o)?[0-7]{3}(?![0-9A-Za-z]))[A-Za-z]*\d[0-9A-Za-z]*")
_DECIMAL_RUN = re.compile(r"(?<![0-9A-Za-z])\d{4,}(?![0-9A-Za-z])")


def _octal(s: str):
    found = re.findall(r"\\([0-7]{1,3})", s)
    if not found:
        # Row 213: bare groups only when every word of the material that holds a digit is one group of exactly
        # three octal digits (`0o` allowed in front): `123456`, `1234` or `123a` is not read around.
        found = re.findall(r"(?<![0-9A-Za-z])(?:0o)?([0-7]{3})(?![0-9A-Za-z])", s)
        if found and _OCTAL_ODD.search(s):
            raise ValueError("a word that is no three-digit octal group in a bare octal list")
    return _byte_list(int(x, 8) for x in found)


def _binary(s: str):
    t = re.sub(r"\s+", "", s)
    if len(t) >= 64 and len(t) % 8 == 0 and re.fullmatch(r"[01]+", t):     # row 57: the groups written together
        return [int(t[i:i + 8], 2) for i in range(0, len(t), 8)]
    return _byte_list(int(x, 2) for x in re.findall(r"(?<![01])(?:0b)?([01]{8})(?![01])", s))


def _a85(s: str):
    t = re.sub(r"\s+", "", s)
    return list(base64.a85decode(t, adobe=t.startswith("<~") and t.endswith("~>")))


def _z85(s: str):
    return list(base64.b85decode(re.sub(r"\s+", "", s).translate(_Z85_TO_B85)))


def _escapes(s: str):
    found = re.findall(r"\\x([0-9a-fA-F]{2})", s)
    return _byte_list(int(x, 16) for x in found) if found else _octal(s)


def _unicode(s: str):
    return _byte_list(int(x, 16) for x in re.findall(r"\\u\{?([0-9a-fA-F]{4})\}?", s))


# Row 79: base58 (Bitcoin's alphabet), base91 (basE91), percent-encoding with literal characters, and
# the literal's own text. base58 is a big number: read by halves, and at most MAX_B58 characters.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_IDX = {c: i for i, c in enumerate(_B58)}
_B58_TEXT = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
MAX_B58 = 1 << 14
_B91 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\""
_B91_IDX = {c: i for i, c in enumerate(_B91)}
MAX_B91 = 1 << 17
_B64_TEXT = re.compile(r"[A-Za-z0-9+/=]+")
_PCT = re.compile(r"%[0-9A-Fa-f]{2}")
_BAD_PCT = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _b58_int(t: str) -> int:
    if len(t) <= 64:
        n = 0
        for c in t:
            n = n * 58 + _B58_IDX[c]
        return n
    h = len(t) // 2
    return _b58_int(t[:h]) * 58 ** (len(t) - h) + _b58_int(t[h:])


def _b58(s: str):
    t = re.sub(r"\s+", "", s)
    if len(t) < 2 or len(t) > MAX_B58 or not _B58_TEXT.fullmatch(t):
        raise ValueError("not base58")
    n = _b58_int(t)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return list(b"\0" * (len(t) - len(t.lstrip("1"))) + body)


def _b91(s: str):
    t = re.sub(r"\s+", "", s).replace('\\"', '"')
    if len(t) < 2 or len(t) > MAX_B91:
        raise ValueError("not base91")
    if len(t) >= 48 and _B64_TEXT.fullmatch(t):
        # 26 of base91's 91 characters are in no base64 text: 48 characters of base91 (a plan of 39
        # bytes or less) hold none of them about once in 10 million. Base64, hex and letters are not read so.
        raise ValueError("base64 text")
    idx, v, b, n, out = _B91_IDX, -1, 0, 0, bytearray()
    for ch in t:
        c = idx.get(ch)
        if c is None:
            raise ValueError("not base91")
        if v < 0:
            v = c
            continue
        v += c * 91
        b |= v << n
        n += 13 if (v & 8191) > 88 else 14
        while True:
            out.append(b & 255)
            b >>= 8
            n -= 8
            if n <= 7:
                break
        v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    return list(out)


def _url(s: str):
    """Percent-encoding with literal characters between the escapes (`v%3D1%7Csteps%3D..`)."""
    if not _PCT.search(s) or _BAD_PCT.search(s):
        raise ValueError("not percent-encoded")
    return list(urllib.parse.unquote_to_bytes(s))


def _percent(s: str):
    """percent_hex (judged: every byte a `%XX`, read by _hex as before), else percent-encoding."""
    try:
        return _hex(s)
    except ValueError:
        return _url(s)


def _text(s: str):
    """The literal's own characters as bytes (a plan under ROT13 or Vigenere, written as text)."""
    if not s:
        raise ValueError("empty")
    try:
        return list(s.encode("latin-1"))
    except UnicodeEncodeError:
        return list(s.encode("utf-8"))


# One reader per family of representation names, by the words a name holds. Order matters: the
# first family whose word is in the name reads it.
FAMILIES = (
    ("base58", _b58), ("b58", _b58), ("base91", _b91), ("b91", _b91),
    ("base64", _b64), ("b64", _b64), ("base32", _b32), ("b32", _b32), ("base85", _b85), ("ascii85", _b85),
    ("a85", _b85), ("z85", _b85), ("b85", _b85), ("unicode", _unicode), ("escape", _escapes), ("octets", _escapes),
    ("octal", _octal), ("binary", _binary), ("bits", _binary), ("hex", _hex), ("percent", _percent),
    ("url", _url), ("uri", _url),
    ("decimal", _decimal), ("json_numbers", _decimal), ("numbers", _decimal), ("int", _decimal),
    ("byte", _decimal), ("text", _text), ("plain", _text), ("string", _text), ("ascii", _text),
)


def _bytes(rep: str, s: str):
    """The bytes of material `s` read as representation `rep` says. `reversed_<rep>` (or
    `<rep>_reversed`): base64 and the other text codecs read the text backwards, every other
    representation reverses the byte order (reversed_decimal, VBScript's reversed_hex)."""
    rep = rep.lower()
    rev = bool(re.match(r"reversed?_", rep) or re.search(r"_reversed?$", rep) or "reversed_text" in rep)
    for word, f in FAMILIES:
        if word in rep:
            if rev and f in (_b64, _b32, _b85, _b58, _b91, _url, _text):
                return f(re.sub(r"\s+", "", s)[::-1])
            data = f(s)
            return data[::-1] if rev else data
    raise ValueError(f"representation {rep}")


# Every reader, for the fallback (what the label says did not give a plan). Row 57: ascii85 and z85 on their
# own (_b85 takes the first alphabet that decodes, which for ascii85 text may be b85's).
READERS = (_hex, _b64, _decimal, _escapes, _unicode, _octal, _binary, _b32, _b85, _a85, _z85)
# Row 79's readers. What they give is held to _strict. _text last: nested, it would be the same bytes again.
NEW_READERS = (_url, _b58, _b91, _text)
MAX_INFLATE = plan_codec.MAX_INFLATE
_PRINTABLE = re.compile(rb"[\x20-\x7e]*")
_OLD_STREAMS = ("zlib", "gzip")


_UNPACKED = {}


def _stream(b: bytes):
    """A decompressor for the stream `b` begins with (known by its header), or (None, None)."""
    if len(b) > 2 and b[0] & 0x0F == 8 and b[0] >> 4 <= 7 and ((b[0] << 8) | b[1]) % 31 == 0:
        return "zlib", zlib.decompressobj()
    if b[:3] == b"\x1f\x8b\x08":
        return "gzip", zlib.decompressobj(31)
    if len(b) > 4 and b[:3] == b"BZh" and 0x31 <= b[3] <= 0x39:
        return "bz2", bz2.BZ2Decompressor()
    if b[:6] == b"\xfd7zXZ\x00":
        return "xz", lzma.LZMADecompressor(lzma.FORMAT_XZ)
    if len(b) > 13 and b[0] == 0x5D and b[1] == 0:
        return "lzma", lzma.LZMADecompressor(lzma.FORMAT_ALONE)
    return None, None


def _decompress(b: bytes):
    """(name, bytes) of a zlib, gzip, bz2, xz or lzma-alone stream known by its header, or None.
    Row 79 added bz2, xz and lzma. Only a stream that reaches its end within MAX_INFLATE bytes of
    output counts: the end of a zlib, gzip, bz2 or xz stream carries its checksum, which the
    decompressor checks, and an lzma-alone stream (no checksum) must reach its end marker or its
    stated size. A stream cut short, or one that grows past MAX_INFLATE, gives None: what it gave
    would be a plan with its last value cut, under no sign that it was."""
    b = bytes(b)
    if b in _UNPACKED:
        return _UNPACKED[b]
    name, o = _stream(b)
    got = None
    if o is not None:
        try:
            out = o.decompress(b, MAX_INFLATE)
            if o.eof:
                got = name, out
        except (OSError, EOFError, ValueError, zlib.error, lzma.LZMAError):
            pass
    if len(_UNPACKED) > 64:
        _UNPACKED.clear()
    _UNPACKED[b] = got
    return got


MAX_SEARCH = 1 << 16    # bytes of an opened stream the fallback's row 79 search runs on; a longer one is only accepted


def _raw_plan(out: bytes) -> bool:
    """Whether a raw deflate stream's output is a plan (_strict), as plan_codec.raw_inflate asks
    before it takes a stream with a few bytes after its end."""
    t = _plan_bytes(out)
    return bool(t and _strict(t))


def _inflate_raw(b: bytes):
    """Row 92: the output of a raw (headerless) deflate stream, bounded (plan_codec.raw_inflate), or None."""
    return plan_codec.raw_inflate(b, _raw_plan)


def _unpack(b: bytes):
    """(name, bytes) of a stream known by its header (_decompress), else of a raw deflate stream, or None."""
    z = _decompress(b)
    if z:
        return z
    r = _inflate_raw(b)
    return ("raw_deflate", r) if r else None


def _opened(raw: bytes, old: bool, nested: bool = True):
    """(bytes, old, opened) of one reading: itself, its compressed stream opened, or (row 57) one
    nested level: bytes that are printable text read once more by every reader. `old` stays True
    only for what the readers and streams before row 79 give; `opened` marks what a stream gave.
    Row 92: a raw deflate stream (never `old`), and the nested level read whether it is one or not."""
    yield raw, old, False
    z = _decompress(raw) if len(raw) >= 8 else None
    if z:
        yield z[1], old and z[0] in _OLD_STREAMS, True
        return
    r = _inflate_raw(raw)
    if r:
        yield r, False, True
    if nested and len(raw) >= 16 and _PRINTABLE.fullmatch(raw):
        inner = raw.decode("ascii")
        for again in READERS + NEW_READERS[:-1]:
            try:
                data = bytes(again(inner))
            except Exception:  # noqa: BLE001 - not this representation
                continue
            yield from _opened(data, old and again in READERS, nested=False)


def _readings(t: str, readers=READERS, old: bool = True):
    """(bytes, old, opened) for every reader of `readers` that reads `t`; each compressed stream
    also opened, and one nested level (_opened). `old`: READERS on the material as written."""
    for reader in readers:
        try:
            raw = bytes(reader(t))
        except Exception:  # noqa: BLE001 - not this representation
            continue
        yield from _opened(raw, old and reader in READERS)


# ---------------------------------------------------------------- transforms

def key_readings(part: str) -> list:
    """The key lists a label field can mean: hex bytes (`cd`, `af,9e`), `0x` bytes, decimal
    bytes (`205`). A field in none of these forms gives nothing."""
    items = [x for x in re.split(r"[,: ]+", part.strip()) if x]
    out = []
    if items and all(re.fullmatch(r"[0-9A-Fa-f]{1,2}", x) for x in items):
        out.append([int(x, 16) for x in items])
    if items and all(re.fullmatch(r"0[xX][0-9A-Fa-f]{1,2}", x) for x in items):
        out.append([int(x, 16) for x in items])
    if items and all(re.fullmatch(r"\d{1,3}", x) and int(x) < 256 for x in items):
        out.append([int(x) for x in items])
    return [k for i, k in enumerate(out) if k not in out[:i]]


def _undo(tr: str, keys, data):
    """Undo transform `tr` with the key bytes `keys` (a list of ints, or the label's key field)."""
    if isinstance(keys, str):
        keys = (key_readings(keys) or [[]])[0] if keys else []
    tr = tr.lower()
    if tr in ("", "identity", "none", "plain"):
        return data
    if tr in ("reverse_bytes", "reverse"):
        return data[::-1]
    if tr in ("single_byte_xor", "xor"):
        return [b ^ keys[0] for b in data]
    if tr in ("reverse_then_xor", "reverse_xor"):
        return [b ^ keys[0] for b in data][::-1]
    if tr in ("repeating_key_xor", "repeating_xor", "multi_byte_xor"):
        return [b ^ keys[i % len(keys)] for i, b in enumerate(data)]
    if tr in ("add_modulo_256", "add"):
        return [(b - keys[0]) % 256 for b in data]
    if tr in ("subtract_modulo_256", "subtract", "sub"):
        return [(b + keys[0]) % 256 for b in data]
    if tr == "rolling_xor":
        k, out = keys[0], []
        for b in data:
            out.append(b ^ k)
            k = b
        return out
    if tr == "rolling_xor_plain":                  # the key runs on the clear byte (fallback only)
        k, out = keys[0], []
        for b in data:
            out.append(b ^ k)
            k = out[-1]
        return out
    if tr in ("rotate_left", "rol"):               # undone by rotating right
        r = keys[0] % 8
        return [((b >> r) | (b << (8 - r))) & 255 for b in data]
    if tr in ("rotate_right", "ror"):
        r = keys[0] % 8
        return [((b << r) | (b >> (8 - r))) & 255 for b in data]
    raise ValueError(f"transform {tr}")


# The transforms the fallback tried before row 79, each with the first byte of each key reading (the
# repeating xor with the whole list), its output read either way: _Kit marks these stages `old`.
TRANSFORMS = ("identity", "single_byte_xor", "repeating_key_xor", "add_modulo_256", "subtract_modulo_256",
              "rolling_xor", "rolling_xor_plain", "rotate_left", "rotate_right")
KEYLESS = ("identity",)


def _grammar(t: str) -> bool:
    if plan_codec.looks_like_plan(t.encode("latin-1")):
        return not t.startswith("{") or "steps" in plan_codec.flatten(t)   # a JSON blob without steps is no plan
    fields = t.split("|")
    return (len(fields) >= 3 and re.fullmatch(r"v=\d", fields[0]) is not None
            and all(re.fullmatch(r"[a-z][a-z0-9_]*=[\x21-\x7e]+", f) for f in fields[1:]))


def _plan_bytes(out):
    """The text of `out` when the plan grammar accepts it, else None."""
    if len(out) < 8 or not (out[0] == 118 and out[1] == 61 or out[0] == 123):   # `v=` or `{`
        return None
    try:
        t = bytes(out).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None
    return t if _grammar(t) else None


_STEPS_FIELD = re.compile(r"(?:^|\|)steps=[a-z_]+(?:,[a-z_]+)*(?:\||$)")


_JSON_KEY = re.compile(r"[A-Za-z][A-Za-z0-9_]*")
_STEP = re.compile(r"[a-z_]+")
_JSON_VALUE_TEXT = re.compile(r"[\x20-\x7e]*")


def _json_clean(v, depth: int = 0) -> bool:
    """Whether a JSON value is what a plan holds: printable text, a number, a boolean, null, or a
    list or object of those (object keys as _JSON_KEY), at most three levels deep."""
    if isinstance(v, str):
        return _JSON_VALUE_TEXT.fullmatch(v) is not None
    if v is None or isinstance(v, (bool, int, float)):
        return True
    if depth >= 3:
        return False
    if isinstance(v, list):
        return all(_json_clean(x, depth + 1) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and _JSON_KEY.fullmatch(k) and _json_clean(x, depth + 1) for k, x in v.items())
    return False


def _json_strict(t: str) -> bool:
    """A JSON plan held to the same check as a `k=v` plan under _STEPS_FIELD: an object whose keys
    are names, whose values are clean (_json_clean), and whose steps are a list of lowercase step
    names (or one string of them joined by commas)."""
    try:
        d = json.loads(t)
    except ValueError:
        return False
    if not isinstance(d, dict) or not _json_clean(d):
        return False
    steps = d.get("steps")
    if isinstance(steps, str):
        steps = steps.split(",")
    return isinstance(steps, list) and bool(steps) and all(isinstance(s, str) and _STEP.fullmatch(s) for s in steps)


def _strict(t: str) -> bool:
    """The plan grammar, and a `steps` field of step names: `steps=a,b` in a `k=v` plan, a list
    of names in a JSON plan whose keys are names and whose values are printable (_json_strict).
    What row 79 reads must pass it: a rotation of the letters that keeps `v=` passes _grammar
    alone, and a pair of byte maps that matches the real transform on most bytes gives JSON with
    a garbled key or step that json.loads takes."""
    if not _grammar(t):
        return False
    return _json_strict(t) if t.startswith("{") else _STEPS_FIELD.search(t) is not None


def _narrow(b: bytes):
    """The ASCII bytes of UTF-16LE or UTF-16BE text (a BOM, or a zero beside each of the first two
    characters), or None."""
    if len(b) < 16:
        return None
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        enc, b = ("utf-16-le" if b[0] == 0xFF else "utf-16-be"), b[2:]
    elif b[1] == 0 and b[3] == 0 and b[0] and b[2]:
        enc = "utf-16-le"
    elif b[0] == 0 and b[2] == 0 and b[1] and b[3]:
        enc = "utf-16-be"
    else:
        return None
    if len(b) % 2:
        return None
    try:
        return b.decode(enc).encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None


def _accept(out, strict: bool) -> list:
    """The plans `out` holds: as it is (_grammar; with `strict`, _strict), or (always under _strict)
    as UTF-16 text, as a compressed stream, or as UTF-16 text in a compressed stream."""
    out = bytes(out)
    got = []
    t = _plan_bytes(out)
    if t and (not strict or _strict(t)):
        got.append(t)
    inner = [_narrow(out)]
    z = _unpack(out) if len(out) >= 8 else None      # row 92: a raw deflate stream too
    if z:
        inner += [z[1], _narrow(z[1])]
    for b in inner:
        t = _plan_bytes(b) if b else None
        if t and t not in got and _strict(t):
            got.append(t)
    return got


# ---------------------------------------------------------------- row 79: the stages of the fallback

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """a XOR b[:len(a)], in C (b at least as long as a)."""
    n = len(a)
    if not n:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b[:n], "big")).to_bytes(n, "big")


class _Stage:
    """One undo step. A map undoes byte by byte through `table` (bytes.translate); a stream by
    position. head(b) is the output of the first bytes b; tail(sl, n) the last len(sl) - extra
    bytes of the output from the last len(sl) bytes of an input of n bytes, None where the end
    cannot be read alone; endf(d, m), where tail cannot, the last m bytes of the output from the
    whole input d at less cost than full(d); full(b) the whole output. `old`: a transform and key the fallback
    tried before row 79. A stream's `hin`: the two first input bytes that it turns into each head
    (`start` encodes two output bytes back; every stage is one-to-one on its first two bytes)."""
    __slots__ = ("name", "table", "head", "full", "tail", "extra", "old", "hin", "endf")

    def __init__(self, name, old=False, table=None, head=None, full=None, tail=None, extra=0, start=None, endf=None):
        self.name, self.old, self.table, self.extra, self.endf = name, old, table, extra, endf
        self.hin = frozenset(start(t) for t in _HEADS) if start is not None else None
        if table is not None:
            self.head = self.full = lambda b, t=table: b.translate(t)
            self.tail = lambda sl, n, t=table: sl.translate(t)
        else:
            self.head, self.full, self.tail = head, full, tail


def _rot_letters(n: int):
    def f(b):
        if 65 <= b <= 90:
            return (b - 65 - n) % 26 + 65
        if 97 <= b <= 122:
            return (b - 97 - n) % 26 + 97
        return b
    return f


def _map_fn(kind: str, k):
    if kind == "identity":
        return lambda b: b
    if kind == "xor":
        return lambda b: b ^ k
    if kind == "add":                       # undone by subtracting
        return lambda b: b - k
    if kind == "sub":
        return lambda b: b + k
    if kind == "rol":                       # undone by rotating right
        r = k % 8
        return lambda b: (b >> r) | (b << (8 - r))
    if kind == "ror":
        r = k % 8
        return lambda b: (b << r) | (b >> (8 - r))
    if kind == "nibble":
        return lambda b: (b << 4) | (b >> 4)
    if kind == "bitrev":
        return lambda b: int(f"{b:08b}"[::-1], 2)
    if kind == "rot":                       # ROT-N on the letters, undone by N back
        return _rot_letters(k % 26)
    raise ValueError(kind)


MAP_KINDS = ("identity", "xor", "add", "sub", "rol", "ror", "nibble", "bitrev", "rot")
_MAPS = {}


def _map_stage(kind: str, k=None, old: bool = False) -> _Stage:
    table = _MAPS.get((kind, k))
    if table is None:
        f = _map_fn(kind, k)
        table = _MAPS[(kind, k)] = bytes(f(b) & 255 for b in range(256))
    return _Stage(f"{kind}:{k}", old, table=table)


def _repxor(key: bytes, old: bool = False) -> _Stage:
    n_key = len(key)

    def head(b):
        return bytes(x ^ key[i % n_key] for i, x in enumerate(b))

    def full(b):
        return _xor_bytes(b, key * (len(b) // n_key + 1))

    def tail(sl, n):
        s = n - len(sl)
        return bytes(x ^ key[(s + i) % n_key] for i, x in enumerate(sl))
    return _Stage(f"repeating_key_xor:{key.hex()}", old, head=head, full=full, tail=tail,
                  start=lambda t: bytes((t[0] ^ key[0], t[1] ^ key[1 % n_key])))


def _rolling(k: int, old: bool = False) -> _Stage:
    """rolling_xor as labelled: each byte was XORed with the stored byte before it (the key first)."""
    def full(b):
        return _xor_bytes(b, bytes((k,)) + b[:-1])

    def tail(sl, n):
        return full(sl)[1:] if len(sl) >= n else _xor_bytes(sl[1:], sl[:-1])
    return _Stage(f"rolling_xor:{k}", old, head=full, full=full, tail=tail, extra=1,
                  start=lambda t: bytes((t[0] ^ k, t[1] ^ t[0] ^ k)))


def _xor_all(b: bytes) -> int:
    """The XOR of every byte of b, folded in C: the bytes as one number, halved until one byte."""
    v, n = int.from_bytes(b, "big"), len(b)
    while n > 1:
        h = n // 2
        v = (v >> (8 * h)) ^ (v & ((1 << (8 * h)) - 1)) if n % 2 == 0 else \
            ((v >> 8) >> (8 * h)) ^ ((v >> 8) & ((1 << (8 * h)) - 1)) ^ (v & 255)
        n = h
    return v & 255


def _rolling_plain(k: int, old: bool = False) -> _Stage:
    """rolling_xor_plain: the key runs on the clear byte; its end is the XOR of everything before
    (endf: that XOR folded in C, then the last bytes in Python)."""
    def full(b):
        return bytes(itertools.accumulate(b, operator.xor, initial=k))[1:]

    def endf(d, m):
        return bytes(itertools.accumulate(d[-m:], operator.xor, initial=k ^ _xor_all(d[:-m])))[1:]
    return _Stage(f"rolling_xor_plain:{k}", old, head=full, full=full, tail=None,
                  start=lambda t: bytes((t[0] ^ k, t[1] ^ t[0])), endf=endf)


_KEYSTREAMS = {}
MAX_RC4 = 1 << 17      # bytes of RC4 keystream made for reading an input from its end


def _keystream(key: bytes, n: int) -> bytes:
    """RC4's keystream for `key`, at least n bytes (kept per key, made again longer when asked)."""
    have = _KEYSTREAMS.get(key)
    if have is not None and len(have) >= n:
        return have
    m = max(n, 64, 2 * len(have) if have else 0)
    s, j, n_key = list(range(256)), 0, len(key)
    for i in range(256):
        j = (j + s[i] + key[i % n_key]) & 255
        s[i], s[j] = s[j], s[i]
    out, i, j = bytearray(m), 0, 0
    for p in range(m):
        i = (i + 1) & 255
        si = s[i]
        j = (j + si) & 255
        sj = s[j]
        s[i], s[j] = sj, si
        out[p] = s[(si + sj) & 255]
    if len(_KEYSTREAMS) > 64:
        _KEYSTREAMS.clear()
    have = _KEYSTREAMS[key] = bytes(out)
    return have


def _rc4(key: bytes, old: bool = False) -> _Stage:
    def full(b):
        return _xor_bytes(b, _keystream(key, len(b)))

    def tail(sl, n):
        if n > MAX_RC4:
            return None
        return _xor_bytes(sl, _keystream(key, n)[n - len(sl):n])
    ks = _keystream(key, 2)
    return _Stage(f"rc4:{key.hex()}", old, head=full, full=full, tail=tail,
                  start=lambda t: bytes((t[0] ^ ks[0], t[1] ^ ks[1])))


def _vig_undo(b: bytes, shifts, every: bool, start: int = 0) -> bytes:
    """Vigenere undone on the letters (case kept, every other byte as it is). The key advances per
    letter, or with `every` per byte; `start` is the key position of b[0]."""
    out, n_key, j = bytearray(b), len(shifts), start
    for i, c in enumerate(b):
        if 65 <= c <= 90:
            out[i] = (c - 65 - shifts[j % n_key]) % 26 + 65
            j += 1
        elif 97 <= c <= 122:
            out[i] = (c - 97 - shifts[j % n_key]) % 26 + 97
            j += 1
        elif every:
            j += 1
    return bytes(out)


_NOT_LETTERS = bytes(c for c in range(256) if not (65 <= c <= 90 or 97 <= c <= 122))


def _vig(letters: bytes, every: bool, old: bool = False) -> _Stage:
    shifts = [(c | 32) - 97 for c in letters]

    def full(b):
        return _vig_undo(b, shifts, every)
    tail = (lambda sl, n: _vig_undo(sl, shifts, True, n - len(sl))) if every else None
    # The key advancing per letter: the key position of the last m bytes is the count of letters
    # before them (counted in C), so the end is read without undoing the whole input.
    endf = None if every else (lambda d, m: _vig_undo(d[-m:], shifts, False, len(d[:-m].translate(None, _NOT_LETTERS))))
    back = [-x for x in shifts]
    return _Stage(f"vigenere{'_every' if every else ''}:{letters.decode()}", old, head=full, full=full, tail=tail,
                  start=lambda t: _vig_undo(t, back, every), endf=endf)


def text_keys(part: str) -> list:
    """The byte strings a label field can mean as a cipher key (RC4, Vigenere, a repeating XOR):
    every key_readings() list, the field as one hex number (`6b6579`, `0x6b6579`), and the field
    as text (`huntress`)."""
    p = part.strip()
    out = [bytes(k) for k in key_readings(p)]
    h = p[2:] if p[:2] in ("0x", "0X") else p
    if len(h) >= 2 and len(h) % 2 == 0 and re.fullmatch(r"[0-9A-Fa-f]+", h):
        out.append(bytes.fromhex(h))
    if re.fullmatch(r"[\x21-\x7e]+", p):
        out.append(p.encode("ascii"))
    return [k for i, k in enumerate(out) if k and k not in out[:i]]


def _letters(key: bytes) -> bytes:
    return bytes(c for c in key if 65 <= c <= 90 or 97 <= c <= 122)


# What a chain's output may start with: a plan (`v=`; `{` and a quote or white space, as a JSON object with
# a key must), a UTF-16 plan, a compressed stream.
_PLAN_HEADS = (b"v=", b'{"', b"{ ", b"{\t", b"{\n", b"{\r", b"v\x00", b"\x00v", b"\xff\xfe", b"\xfe\xff", b"{\x00",
               b"\x00{")
_ZLIB_HEADS = tuple(bytes((c, f)) for c in range(0x08, 0x80, 0x10) for f in range(256) if (c * 256 + f) % 31 == 0)
_PACK_HEADS = (b"\x1f\x8b", b"BZ", b"\xfd7", b"\x5d\x00")
_HEADS = frozenset(_PLAN_HEADS + _ZLIB_HEADS + _PACK_HEADS)
MAX_BYTE_KEYS = 8      # one-byte keys a label gives the fallback, at most
MAX_TEXT_KEYS = 6      # cipher keys
SMALL = 1 << 14        # an input this short is decoded whole to read a chain's end that cannot be read alone
WINDOW = 64            # output bytes a screened chain is checked on before it is decoded whole
_JSON_TEXT = re.compile(rb"[\x20-\x7f\t\n\r]*")
_WIDE_LE = re.compile(rb"(?:[\x20-\x7e\t\n\r]\x00)*[\x20-\x7e\t\n\r]?")


def _hit(x: bytes) -> bool:
    return x[:2] in _HEADS


def _plausible(x: bytes) -> bool:
    """Whether the first bytes x of an output may begin what _accept takes: printable plan text,
    JSON text, UTF-16 text, or a compressed stream whose own first bytes decode to one of these."""
    if x[:2] == b"v=":
        return _PRINTABLE.fullmatch(x) is not None
    if x[:1] == b"{":
        return x[1:2] != b"\x00" and _JSON_TEXT.fullmatch(x) is not None or x[1:2] == b"\x00" and bool(_WIDE_LE.fullmatch(x))
    if x[:2] in (b"\xff\xfe", b"\xfe\xff"):
        x = x[2:] if x[0] == 0xFF else x[3:]
        return bool(_WIDE_LE.fullmatch(x))
    if x[:2] == b"v\x00":
        return bool(_WIDE_LE.fullmatch(x))
    if x[:1] == b"\x00":
        return bool(_WIDE_LE.fullmatch(x[1:]))
    try:
        if x[:2] in _ZLIB_HEADS or x[:3] == b"\x1f\x8b\x08":
            o = zlib.decompressobj(31 if x[0] == 0x1F else 15)
            got = o.decompress(x, 16)
        elif x[:10] == b"BZh" + x[3:4] + b"1AY&SY" and 0x31 <= x[3] <= 0x39:
            return True
        elif x[:6] == b"\xfd7zXZ\x00":
            return True
        elif x[:2] == b"\x5d\x00" and len(x) > 13:
            got = lzma.LZMADecompressor(lzma.FORMAT_ALONE).decompress(x, 16)
        else:
            return False
    except (zlib.error, lzma.LZMAError, EOFError, ValueError):
        return False
    return not got or _hit(got) or got[:1] == b"{" or len(got) < 2


class _Kit:
    """The stages one label gives the fallback, and an index of the maps by the two input bytes
    that each map turns into a head (`index2`)."""

    def __init__(self, label: str):
        fields = label.split("|")[1:]
        lists = [k for p in fields for k in key_readings(p)]
        k0 = list(dict.fromkeys(k[0] for k in lists))           # what the fallback tried before row 79
        kb = list(dict.fromkeys(k0 + [b for k in lists for b in k]))[:MAX_BYTE_KEYS]
        keys = list(dict.fromkeys(k for p in fields for k in text_keys(p)))[:MAX_TEXT_KEYS]
        self.maps, tables = [], set()

        def add(st):
            if st.table not in tables:
                tables.add(st.table)
                self.maps.append(st)
        add(_map_stage("identity", old=True))
        for k in kb:
            for kind in ("xor", "add", "sub", "rol", "ror"):
                add(_map_stage(kind, k, old=k in k0))
        add(_map_stage("nibble"))
        add(_map_stage("bitrev"))
        for n in range(1, 26):
            add(_map_stage("rot", n))
        self.identity = self.maps[0]
        # The maps a stream is stacked with: not ROT-N (a letter rotation stacked on a cipher of bytes is
        # not a pair the author's style suggests, and 25 of them would cost most of the search).
        self.pair_maps = [st for st in self.maps[1:] if not st.name.startswith("rot:")]
        streams = [_repxor(bytes(k), old=True) for k in lists if len(k) >= 2]
        for k in kb:
            streams += [_rolling(k, k in k0), _rolling_plain(k, k in k0)]
        for key in keys:
            if len(key) >= 2:
                streams.append(_repxor(key))
            streams.append(_rc4(key))
            letters = _letters(key)
            if letters:
                streams += [_vig(letters, False), _vig(letters, True)]
        self.streams = list({s.name: s for s in reversed(streams)}.values())[::-1]   # the first of each name
        self.rots = [int(x) for p in fields for x in re.split(r"[,: ]+", p.strip()) if x.isdigit() and 0 < int(x) < 26]
        self.vig = list(dict.fromkeys(_letters(k) for k in keys if _letters(k)))
        self.index2 = {}
        for st in self.maps:
            inv = bytearray(256)
            for i, v in enumerate(st.table):
                inv[v] = i
            for t in _HEADS:
                self.index2.setdefault(bytes((inv[t[0]], inv[t[1]])), []).append(st)

    def after(self, x: bytes):
        """The maps that turn bytes starting with x into a head."""
        return self.index2.get(x[:2], ())


_KITS = {}


def _kit(label: str) -> _Kit:
    kit = _KITS.get(label)
    if kit is None:
        if len(_KITS) > 256:
            _KITS.clear()
        kit = _KITS[label] = _Kit(label)
    return kit


HEAD = 4


def _chains(d: bytes, kit: _Kit):
    """(chain, backwards) of every chain of one or two stages whose output (read backwards, with
    `backwards`) starts with a head. A map chain is screened forwards only: read backwards it is
    the same chain on the reversed input, which the fallback tries too. A stream is screened at
    the end too where its end can be read alone, alone or before a map; a stream that cannot,
    only alone and only on SMALL input (or as the fallback did before row 79)."""
    n, h, out = len(d), d[:HEAD], []
    h2, index = h[:2], kit.index2
    for a in kit.maps:
        bs = index.get(h2.translate(a.table))
        if bs:
            out += [((a, b), False) for b in bs]
    heads = [(a, h2.translate(a.table)) for a in kit.pair_maps]
    for s in kit.streams:
        x = s.head(h)
        out += [((s, b), False) for b in kit.after(x)]
        x2, hin = x[:2], s.hin
        out += [((s, s2), False) for s2 in kit.streams if x2 in s2.hin]
        out += [((a, s), False) for a, y in heads if y in hin]
        if s.extra:
            # A rolling xor read from its end: its key touches one byte there (and an XOR before it cancels
            # in its differences), so only the single transform the fallback tried before row 79 is read so.
            if s.old and n > 3 and kit.identity in kit.after(s.tail(d[-3:], n)[::-1]):
                out.append(((s, kit.identity), True))
            continue
        m = 2
        end = s.tail(d[-m:], n) if s.tail is not None and n > m else None
        if end is not None:
            out += [((s, b), True) for b in kit.after(end[::-1])]
            sl = d[-m:]
            out += [((a, s), True) for a in kit.pair_maps if _hit(s.tail(sl.translate(a.table), n)[::-1])]
        elif s.endf is not None and n > m:
            out += [((s, b), True) for b in kit.after(s.endf(d, m)[::-1])]
        elif s.tail is None and (s.old or n <= SMALL):
            full = s.full(d)
            out += [((s, b), True) for b in kit.after(full[-2:][::-1])]
    return out


def _window(chain, d: bytes, backwards: bool):
    """The first WINDOW bytes of the chain's output (of the output read backwards, with
    `backwards`), from as few input bytes as that takes; None where only the whole output tells."""
    n = len(d)
    if not backwards:
        x = d[:WINDOW]
        for st in chain:
            x = st.head(x)
        return x
    need = WINDOW + sum(st.extra for st in chain)
    if n <= need:
        return None
    x = d[-need:]
    for i, st in enumerate(chain):
        if st.tail is not None:
            x = st.tail(x, n)
        elif i == 0 and st.endf is not None:
            x = st.endf(d, need)
        else:
            return None
        if x is None:
            return None
    return x[::-1]


_SINGLE_TABLES = []
NEAR = 2 / 3      # a pair of maps that one map (any key) matches on this share of the input's bytes, but not all, is a near miss


def _single_tables() -> list:
    """The table of every single byte map with any key: xor, add (sub is add of the negated key),
    rol (ror is rol the other way), nibble swap, bit reversal, ROT-N."""
    if not _SINGLE_TABLES:
        tabs = {_map_stage("identity").table}
        for k in range(1, 256):
            tabs |= {_map_stage("xor", k).table, _map_stage("add", k).table}
        for k in range(1, 8):
            tabs.add(_map_stage("rol", k).table)
        tabs |= {_map_stage("nibble").table, _map_stage("bitrev").table}
        tabs |= {_map_stage("rot", n).table for n in range(1, 26)}
        _SINGLE_TABLES.extend(tabs)
    return _SINGLE_TABLES


def _near_miss(chain, d: bytes) -> bool:
    """Whether a chain of two byte maps is a near miss: one single map with some key (in the label
    or not) undoes the input's bytes to what the pair does for most of them but not for all. The
    real transform is then that map with a key the label does not hold, and the pair turns the
    other bytes into a plan with a value garbled (`stage_count=3` for 2, `relnte` for `remote`).
    A pair of the label's keys that is the real transform agrees with no single map that far
    (a one-bit xor before an add, the closest, on about half), its own two maps aside: a ROT-N
    in the pair leaves every byte that is no letter to the other map."""
    if len(chain) != 2 or chain[0].table is None or chain[1].table is None:
        return False
    present = bytes(sorted(set(d)))
    got = present.translate(chain[0].table).translate(chain[1].table)
    need, n = NEAR * len(present), len(present)
    own = {chain[0].table, chain[1].table}
    for t in _single_tables():
        if t in own:
            continue
        same = sum(1 for x, y in zip(got, present.translate(t)) if x == y)
        if need <= same < n:
            return True
    return False


def _search(d: bytes, kit: _Kit, old: bool, found: list):
    """Add to `found` the plans of every chain _chains() screens in, each decoded whole. A pair of
    byte maps that is a near miss of one map (_near_miss) gives nothing."""
    done = set()
    for chain, backwards in _chains(d, kit):
        chain = tuple(st for st in chain if st is not kit.identity) or (kit.identity,)
        sig = (tuple(map(id, chain)), backwards)
        if sig in done:
            continue
        done.add(sig)
        w = _window(chain, d, backwards)
        if w is not None and not _plausible(w):
            continue
        x = d
        for st in chain:
            x = st.full(x)
        if backwards:
            x = x[::-1]
        strict = not (old and len(chain) == 1 and chain[0].old)
        got = _accept(x, strict)
        if got and _near_miss(chain, d):
            continue
        for p in got:
            if p not in found:
                found.append(p)


RAW_WINDOW = 256        # input bytes a raw deflate stream behind a stage is screened on


def _raw_start(x: bytes) -> bool:
    """Whether x may begin a raw deflate stream whose output begins a plan: no block of type 3, the
    first RAW_WINDOW bytes inflate without an error, and the first bytes they give (if any) are a
    plan's (_hit, or `{`)."""
    if len(x) < 8 or (x[0] >> 1) & 3 == 3:
        return False
    try:
        got = zlib.decompressobj(-15).decompress(x[:RAW_WINDOW], 16)
    except zlib.error:
        return False
    return len(got) < 2 or _hit(got) or got[:1] == b"{"


def _raw_search(d: bytes, kit: _Kit, found: list):
    """Row 92: the plans of a raw deflate stream under one stage of the label's (a byte map or a
    stream: xor, add, RC4 ...), which _chains cannot screen, for such a stream has no head. Each
    stage is screened on its first RAW_WINDOW output bytes (_raw_start) and undone whole only then;
    what the stream gives is held to _strict (_accept)."""
    if len(d) < 8:
        return
    for st in kit.pair_maps + [s for s in kit.streams if not s.name.startswith("vigenere")]:
        if not _raw_start(st.head(d[:RAW_WINDOW])):
            continue
        x = st.full(d)
        r = _inflate_raw(x)
        if not r:
            continue
        for p in _accept(r, True):
            if p not in found:
                found.append(p)


MAX_TEXT_ROTS = 3       # ROT-N readings of the material's text: ROT13 and the label's first numbers
MAX_TEXT_VIG = 2        # Vigenere keys the material's text is read under


def _text_variants(m: str, kit: _Kit) -> list:
    """Row 79: the material's text under ROT13, the label's ROT-N, and Vigenere with the label's keys
    undone (a representation whose text was rotated), when it holds letters. Bounded: ROT13 and the
    label's first two numbers, its first two Vigenere keys."""
    if len(m) > SMALL or not re.search(r"[A-Za-z]", m):
        return []
    b = m.encode("latin-1", "replace")
    out = [b.translate(_map_stage("rot", n).table) for n in list(dict.fromkeys([13] + kit.rots))[:MAX_TEXT_ROTS]]
    for letters in kit.vig[:MAX_TEXT_VIG]:
        shifts = [(c | 32) - 97 for c in letters]
        out += [_vig_undo(b, shifts, False), _vig_undo(b, shifts, True)]
    return [x.decode("latin-1") for x in out]


def _old_stages(label: str) -> list:
    """The one-transform undos the fallback tried before row 79, as stages: identity, and for each
    key list a label field gives, xor, add, sub, rol, ror, rolling xor (either way) with its first
    byte and the repeating xor with the whole list."""
    stages, names, tables = [_map_stage("identity", old=True)], set(), set()
    for k in (k for p in label.split("|")[1:] for k in key_readings(p)):
        for kind in ("xor", "add", "sub", "rol", "ror"):
            stages.append(_map_stage(kind, k[0], old=True))
        if len(k) >= 2:
            stages.append(_repxor(bytes(k), old=True))
        stages += [_rolling(k[0], True), _rolling_plain(k[0], True)]
    out = []
    for st in stages:
        sig = st.table if st.table is not None else st.name
        if sig not in (tables if st.table is not None else names):
            (tables if st.table is not None else names).add(sig)
            out.append(st)
    return out


_GRAMMAR_HEADS = (b"v=", b"{")


def _last2(st: _Stage, data: bytes) -> bytes:
    """The last two bytes of the stage's output on data, at less cost than its whole output."""
    n = len(data)
    if st.tail is not None and n > 2 + st.extra:
        return st.tail(data[-(2 + st.extra):], n)[-2:]
    if st.endf is not None and n > 2:
        return st.endf(data, 2)
    return st.full(data)[-2:]


def _old_search(data: bytes, stages, found: list):
    """The search the fallback made before row 79: each stage undone on the whole data, its output
    read either way, held to the plan grammar (_grammar) as it was. A stage is undone whole only
    when its output begins (or ends, read backwards) the way a plan does."""
    for st in stages:
        fwd = st.head(data[:2])
        if not (fwd[:2] == b"v=" or fwd[:1] == b"{"):
            end = _last2(st, data)[::-1]
            if not (end[:2] == b"v=" or end[:1] == b"{"):
                continue
        x = st.full(data)
        for o in (x, x[::-1]):
            if o[:2] == b"v=" or o[:1] == b"{":
                p = _plan_bytes(o)
                if p and p not in found:
                    found.append(p)


def fallback(texts, label: str) -> list:
    """Every grammar-valid plan the material gives under any reading (see the module text):
    `texts` are the material's spellings (_materials), each also read backwards.

    Two passes. The first is the search the fallback made before row 79 (its readers, zlib and
    gzip, one transform with the first byte of a key or the whole key list, the output either
    way), held to _grammar as before: what it finds is the answer, as it was, and nothing row 79
    added runs. Only when it finds nothing does the second pass run, with every reading, stage and
    pair row 79 added, held to _strict. An opened stream longer than MAX_SEARCH is not searched
    there, only taken as it is (_accept)."""
    olds = list(dict.fromkeys(x for m in texts if m for x in (m, m[::-1])))
    items = [(raw, old, opened) for t in olds for raw, old, opened in _readings(t) if len(raw) >= 8]
    found, seen = [], set()
    stages = _old_stages(label)
    for raw, old, _opened_ in items:
        if not old:
            continue
        for data in (raw, raw[::-1]):
            if data not in seen:
                seen.add(data)
                _old_search(data, stages, found)
    if found:
        return found
    kit = _kit(label)
    news = list(dict.fromkeys(x for m in olds for v in _text_variants(m, kit) for x in (v, v[::-1]) if x not in olds))
    # Row 79's readers on the material as written (_text last: a plan under ROT-N or Vigenere written as text),
    # and every reader but _text on its rotated text (the text of a rotated representation).
    items += [(raw, False, opened) for t in olds for raw, _o, opened in _readings(t, NEW_READERS, False) if len(raw) >= 8]
    items += [(raw, False, opened) for t in news for raw, _o, opened in _readings(t, READERS + NEW_READERS[:-1], False)
              if len(raw) >= 8]
    seen = set()
    for raw, _old, opened in items:
        for data in (raw, raw[::-1]):
            if data in seen:
                continue
            seen.add(data)
            if opened and len(data) > MAX_SEARCH:
                for p in _accept(data, True):
                    if p not in found:
                        found.append(p)
            else:
                _search(data, kit, False, found)
                if not opened:
                    _raw_search(data, kit, found)     # row 92: a raw deflate stream behind one stage
    return found


# ---------------------------------------------------------------- row 79: the labelled path's new names

# Every transform name _undo knew before row 79: read by _undo alone, exactly as before.
OLD_NAMES = frozenset(("", "identity", "none", "plain", "reverse_bytes", "reverse", "single_byte_xor", "xor",
                       "reverse_then_xor", "reverse_xor", "repeating_key_xor", "repeating_xor", "multi_byte_xor",
                       "add_modulo_256", "add", "subtract_modulo_256", "subtract", "sub", "rolling_xor",
                       "rolling_xor_plain", "rotate_left", "rol", "rotate_right", "ror"))
# The spellings of each transform, the author's style first (snake_case, `<what>_<how>` as in Day 6 and 7's
# single_byte_xor, add_modulo_256, reverse_then_xor). (kind, fixed key or None).
_SPELLINGS = {
    ("identity", None): "identity none plain noop raw copy",
    ("reverse", None): "reverse reverse_bytes reversed reversal byte_reverse bytes_reversed reverse_order",
    ("xor", None): "xor single_byte_xor xor_byte byte_xor single_xor xor_single one_byte_xor",
    ("repxor", None): "repeating_key_xor repeating_xor multi_byte_xor multibyte_xor xor_key key_xor xor_repeating "
                      "cyclic_xor xor_cycle",
    ("add", None): "add add_modulo_256 add_mod_256 add_mod256 addition add_byte byte_add plus",
    ("sub", None): "sub subtract subtract_modulo_256 subtract_mod_256 sub_mod_256 subtraction sub_byte minus",
    ("rol", None): "rol rotate_left rotl rotate_bits_left bit_rotate_left rotate_left_bits",
    ("ror", None): "ror rotate_right rotr rotate_bits_right bit_rotate_right rotate_right_bits",
    ("rolling", None): "rolling_xor chained_xor xor_chain xor_chained cbc_xor feedback_xor",
    ("rolling_plain", None): "rolling_xor_plain",
    ("rc4", None): "rc4 arc4 arcfour rc4_stream rc4_cipher rc4_key rc4_xor rc4_encrypt rc4_encrypted",
    ("vig", None): "vigenere vigenere_cipher vigenere_text vigenere_shift vigenere_letters vigenere_encrypt",
    ("vig_every", None): "vigenere_every vigenere_all vigenere_bytes_position vigenere_running",
    ("rot", 13): "rot13 rot_13 rot13_text rot13_letters",
    ("rot", None): "rot_n rotn rot rot_text caesar caesar_shift caesar_cipher shift_letters letter_shift rot_letters",
    ("nibble", None): "nibble_swap swap_nibbles nibble_swapped nibbles_swapped nybble_swap swap_nybbles nibble "
                      "nibbles swap_halves",
    ("bitrev", None): "bit_reverse reverse_bits bit_reversal bitrev bits_reversed bit_reversed reflect_bits "
                      "mirror_bits bit_mirror reverse_bit_order bit_order_reverse",
    ("decompress", None): "zlib deflate gzip bz2 bzip2 lzma xz lzma_xz lzma2 compress compressed zlib_compress "
                          "gzip_compress bz2_compress bzip2_compress lzma_compress xz_compress zlib_deflate "
                          "zlib_compressed gzip_compressed bz2_compressed lzma_compressed xz_compressed "
                          # row 92: raw deflate (DeflateStream, PHP gzinflate/gzdeflate), the author's style first
                          "raw_deflate inflate deflate_raw compress_deflate gzinflate deflatestream deflate_stream "
                          "raw_inflate inflate_raw rawdeflate gzdeflate deflate_compress deflate_compressed "
                          "raw_deflate_compressed deflated",
    ("utf16", None): "utf16 utf_16 utf16le utf_16le utf16_le utf_16_le utf16be utf_16be utf16_be utf_16_be "
                     "unicode_le unicode_be ucs2 ucs_2 wide wide_text",
}
TRANSFORM_NAMES = {name: kind for kind, names in _SPELLINGS.items() for name in names.split()}
_SEPARATORS = ("_and_then_", "_followed_by_", "_then_", " then ", "+", ">", "__", ",")
_KEYED = {"xor", "add", "sub", "rol", "ror", "rolling", "rolling_plain", "repxor", "rc4", "vig", "vig_every", "rot"}
MAX_LABEL_TRIES = 64


def parse_stages(name: str):
    """The transforms a label's transform field names, in the order they were applied, as (kind,
    fixed key) pairs; several orders when the name is fused (`xor_add`); [] for a name it does not
    know. `xor_then_add` (xor first, then add), `xor+add`, `add>xor`, `rc4_then_zlib`."""
    name = name.strip().lower().replace("->", ">").replace("-", "_")
    if name in TRANSFORM_NAMES:
        return [[TRANSFORM_NAMES[name]]]
    for sep in _SEPARATORS:
        if sep in name:
            parts = [p.strip("_ ") for p in name.split(sep)]
            if 2 <= len(parts) <= 3 and all(p in TRANSFORM_NAMES for p in parts):
                return [[TRANSFORM_NAMES[p] for p in parts]]
    cuts = [i for i, c in enumerate(name) if c == "_"]
    out = []
    for i in cuts:
        a, b = name[:i], name[i + 1:]
        if a in TRANSFORM_NAMES and b in TRANSFORM_NAMES:
            pair = [TRANSFORM_NAMES[a], TRANSFORM_NAMES[b]]
            out += [pair, pair[::-1]]        # a fused name does not say its order: either
    return [o for i, o in enumerate(out) if o not in out[:i]]


def _stage_keys(kind: str, fixed, field: str) -> list:
    """The keys one stage may take from one label field."""
    if fixed is not None:
        return [fixed]
    if kind in ("xor", "add", "sub", "rol", "ror", "rolling", "rolling_plain"):
        return list(dict.fromkeys(k[0] for k in key_readings(field)))
    if kind == "repxor":
        return list(dict.fromkeys([bytes(k) for k in key_readings(field)] + text_keys(field)))
    if kind in ("rc4",):
        return text_keys(field)
    if kind in ("vig", "vig_every"):
        return list(dict.fromkeys(x for x in map(_letters, text_keys(field)) if x))
    if kind == "rot":
        f = field.strip()
        got = [int(f)] if f.isdigit() else []
        got += [k[0] for k in key_readings(f) if len(k) == 1]
        return [n % 26 for n in dict.fromkeys(got) if n % 26]
    return [None]


def _assignments(stages, fields):
    """Key per stage: each keyed stage its own field (`rep|xor_then_add|5a|13`), its own item of
    the one field (`5a,13`, `5a:13`), or the whole field each."""
    keyed = [i for i, (kind, fixed) in enumerate(stages) if kind in _KEYED and fixed is None]
    fields = [f for f in fields if f is not None] or [""]
    ways = []
    if len(keyed) >= 2 and len(fields) >= len(keyed) and all(f.strip() for f in fields[:len(keyed)]):
        ways.append(fields[:len(keyed)])
    items = [x for x in re.split(r"[,:;/ ]+", fields[0].strip()) if x]
    if len(keyed) >= 2 and len(items) == len(keyed):
        ways.append(items)
    ways.append([fields[0]] * len(keyed))
    for way in ways:
        per = []
        for i, (kind, fixed) in enumerate(stages):
            per.append(_stage_keys(kind, fixed, way[keyed.index(i)] if i in keyed else ""))
        yield from itertools.islice(itertools.product(*per), MAX_LABEL_TRIES)


def _apply(kind: str, key, data: bytes) -> bytes:
    """Undo one stage of a labelled chain on the whole data."""
    if kind == "identity" or kind == "utf16":
        return data
    if kind == "reverse":
        return data[::-1]
    if kind in MAP_KINDS:
        return data.translate(_map_stage(kind, key).table)
    if kind == "repxor":
        return _repxor(key).full(data)
    if kind == "rolling":
        return _rolling(key).full(data)
    if kind == "rolling_plain":
        return _rolling_plain(key).full(data)
    if kind == "rc4":
        return _rc4(key).full(data)
    if kind in ("vig", "vig_every"):
        return _vig(key, kind == "vig_every").full(data)
    if kind == "decompress":
        z = _unpack(data)                   # row 92: a raw deflate stream when no header says otherwise
        if not z:
            raise ValueError("no compressed stream")
        return z[1]
    raise ValueError(kind)


def label_outputs(tr: str, fields, data):
    """What undoing the label's transform `tr` (with its key fields) gives: _undo alone for a name
    known before row 79, else every order and key assignment of row 79's names, bounded."""
    if tr.strip().lower() in OLD_NAMES:
        yield _undo(tr, fields[0] if fields else "", data)
        return
    data = bytes(data)
    tries = 0
    for stages in parse_stages(tr):
        for keys in _assignments(stages, list(fields)):
            tries += 1
            if tries > MAX_LABEL_TRIES:
                return
            try:
                out = data
                for (kind, _fixed), key in reversed(list(zip(stages, keys))):
                    out = _apply(kind, key, out)
            except Exception:  # noqa: BLE001 - not this key or order
                continue
            yield out


def _label_plan(out, strict: bool = False):
    """The plan of a labelled reading: the plan grammar on the output (as before; with `strict`, a
    transform name row 79 added, _strict), else (row 79, under _strict) the output as UTF-16 text
    or a compressed stream."""
    t = _plan_bytes(out)
    if t and (not strict or _strict(t)):
        return t
    got = _accept(out, True)
    return got[0] if len(got) == 1 else None


def _materials(rhs: str, dialect: str = "") -> list:
    """The texts a right-hand side can hold its material as: its literals joined, the side as
    written, and its one long literal alone when the others are short (`Buffer.from('4d06..',
    'hex')`). Never one of several long literals alone: that may be a piece of the material."""
    long = [x for a, b, c in _STR.findall(rhs) for x in (a or b or c,) if len(x) >= 16]
    chars = plan_codec.char_value(rhs)        # row 58: the characters the calls give, and their numbers
    spelled = [''.join(map(chr, chars)), ','.join(map(str, chars))] if chars else []
    # Row 92: a side that holds no literal but one list of numbers (.NET's `new byte[] { 0x78, .. }`), its
    # numbers in decimal: the text that every representation reading numbers (byte, decimal) reads. Last.
    arrays = [] if _STR.search(rhs) else list(plan_codec.NUMS_RE.finditer(rhs))
    listed = [','.join(map(str, plan_codec._ints(arrays[0].group(1))))] if len(arrays) == 1 else []
    return list(dict.fromkeys(spelled + [_content(rhs, dialect), rhs] + (long if len(long) == 1 else []) + listed))


def reading(text: str, ext=None):
    """(plan text, cut) of the one plan the file's labelled material gives, or (None, False).

    `cut` is True when the material was read from a piece (see whole(); or the first line of a
    statement that goes on; or, row 78, a material whose variable is appended to elsewhere, as
    plan_codec's GROWS_RE reads it): the plan then comes without its last field, as plan_codec gives a
    plan read from a piece, for that value may be cut short. `ext` says how the language reads its
    numeric escapes (plan_codec.escape_dialect)."""
    low = text.lower()
    if "material_" not in low or "codec_" not in low:
        return None, False
    codecs = {}      # by the id in lower case: `MATERIAL_ab12` pairs with `Codec_AB12`
    for ident, line, _stmt in assignments(text, _CODEC):
        codecs.setdefault(ident.lower(), _content(line).strip())
    plans = {}
    dialect = plan_codec.escape_dialect(ext) if hasattr(plan_codec, "escape_dialect") else ""
    grown = {n.lower() for n in plan_codec._grown(text)}
    materials = assignments(text, _MATERIAL)
    # Day 27 (script residuals): a Material_<id> beside a Material_<id><more> holding text (a suffix variable:
    # `set "Material_x_tail=<rest>"`, `Material_x_tail = '<rest>'`) may be the head of a material the script joins
    # at run time; read alone it was taken whole and its cut last value went out PLAIN. Its plan is a piece.
    suffixed = {i.lower() for i, _, _ in materials
                if any(o.lower() != i.lower() and o.lower().startswith(i.lower()) and len(_content(ol).strip()) >= 4
                       for o, ol, _ in materials)}
    for ident, line, stmt in materials:
        label = codecs.get(ident.lower())
        if not label or not line.strip() and not stmt.strip():
            continue
        parts = label.split("|") + ["", ""]
        # The whole statement first: its first line alone may be a piece that the loose grammar
        # takes for a shorter plan. The line second, for a statement that took in what follows
        # it; then that line is a piece unless it closes its brackets and ends without a join.
        sides = list(dict.fromkeys((stmt, line)))
        found, side = [], None
        for rhs in sides:
            for s in _materials(rhs, dialect):
                # A name known before row 79 has one output, read as before. A row 79 name may have several
                # (its key read as hex and as decimal, a fused name either way round): one plan or none.
                got = []
                strict = parts[1].strip().lower() not in OLD_NAMES
                try:
                    for out in label_outputs(parts[1], parts[2:-2] or [""], _bytes(parts[0], s)):
                        p = _label_plan(out, strict)
                        if p and p not in got:
                            got.append(p)
                except Exception:  # noqa: BLE001 - not this codec as labelled
                    got = []
                t = got[0] if len(got) == 1 else None
                if t:
                    found, side = [t], rhs
                    break
            if found:
                break
        # A label in another form, a key in another notation, a representation without a
        # reader: every reading, and only text the plan grammar accepts counts.
        for rhs in sides:
            if found:
                break
            found, side = fallback(_materials(rhs, dialect), label), rhs
        piece = bool(found) and (not whole(side) or side is not stmt and _open(side)
                                 or f"material_{ident.lower()}" in grown or ident.lower() in suffixed)
        for t in found:
            if piece:
                t = t[:t.rfind("|") + 1]
            plans[t] = plans.get(t, True) and piece
    # A plan that only begins another one is a piece of it (a literal alone, a line of a statement).
    keep = [p for p in plans if not any(q != p and q.startswith(p) for q in plans)]
    return (keep[0], plans[keep[0]]) if len(keep) == 1 else (None, False)


def _open(line: str) -> bool:
    """Whether a line leaves its statement open: an unclosed bracket, or a join at its end."""
    code = _code(line)
    return sum(code.count(c) for c in _OPEN) > sum(code.count(c) for c in _CLOSE) or bool(_JOIN_END.search(code.rstrip()))


def read_text(text: str):
    """The plan text of reading(), or None (cut or not: a cut one has lost its last field)."""
    return reading(text)[0]


def read(text: str):
    """The flattened plan (read_text), or None."""
    t = read_text(text)
    return plan_codec.flatten(t) if t else None


ROLE = {
    ("decode_configuration", "return_configuration"): "benign_utility",
    ("acquire_remote", "dispatch_memory"): "stager",
    ("decode_embedded", "write_file"): "dropper",
    ("acquire_remote", "write_file"): "downloader",
    ("locate_local", "dispatch_process"): "launcher",
}
ATTACK = {"benign_utility": "none", "stager": "T1105", "dropper": "T1140", "downloader": "T1105"}
ID_ROLE = {"persistence": "persistence_descriptor", "advanced": "advanced_syntax", "benign": "benign_utility",
           "stager": "stager", "dropper": "dropper", "downloader": "downloader", "uploader": "uploader",
           "launcher": "launcher", "chain": "staged_chain", "relay": "relay", "impact": "impact"}
STEP_TECH = (("schedule", ("T1053.003", "T1053.006", "T1543.002", "T1053")),
             ("register_descriptor", ("T1053.003", "T1053.006", "T1543.002", "T1053")),
             ("transmit", ("T1041", "T1048", "T1567")))


def _techniques(ext):
    """The own-interpreter candidates of an extension: generic's tables (TECHNIQUES, ANY_INTERPRETER)."""
    gen = plan_codec.optional("generic")
    return gen.techniques(ext) if gen is not None and hasattr(gen, "techniques") else []


def _qid(q):
    return re.sub(r"^set\d+\.", "", str(q.get("qid") or q.get("id") or ""))


def _answer(q, plan, ext):
    qid, text = _qid(q), str(q.get("question") or "")
    fmt = q.get("answer_format") if isinstance(q.get("answer_format"), dict) else {}
    allowed = fmt.get("accepted_values") or None
    steps = tuple(s for s in str(plan.get("steps", "")).split(",") if s)
    tail = qid.split("-")[-1]
    if qid.endswith("-steps"):
        if not steps:
            return None
        syn = str(fmt.get("syntax") or "")
        if "joined by >" in syn and "no surrounding spaces" in syn:
            return ">".join(steps)
        return labels.pick(f"script.steps/{ext}.separator", [("gt", ">".join(steps)), ("gt_spaced", " > ".join(steps))])
    if qid.endswith("-role"):
        if steps in ROLE:
            return ROLE[steps]
        if not steps:
            return None
        names = [ID_ROLE[w] for w in qid.split("-") if w in ID_ROLE]
        names += [n for n in re.findall(r"[a-z]+(?:_[a-z]+)*", text.split(" as ", 1)[-1]) if allowed and n in allowed]
        names = [n for i, n in enumerate(names) if n not in names[:i] and (not allowed or n in allowed)]
        return labels.pick(f"script.role/{ext}.{'+'.join(steps)}", names) if names else None
    if qid.endswith("-attack"):
        role = ROLE.get(steps)
        # The advanced-syntax plan (Day 7) is the own-interpreter question; it was known by the word
        # `interpreter` in the text, which Day 12's rubric writes into every attack question.
        if steps == ("recognize_syntax", "reconstruct_intent") or role == "launcher":
            own = _techniques(ext)
            gen = plan_codec.optional("generic")     # the key generic asks under (not the four Day 12 spent)
            key = gen.own_key(ext) if gen is not None and hasattr(gen, "own_key") else f"script.attack/{ext}"
            return labels.pick(key, own) if own else None
        if role:
            return ATTACK[role]
        if not steps:
            return None
        opts = []
        for word, ts in STEP_TECH:
            if word in "_".join(steps):
                opts += [t for t in ts if t not in opts]
        return labels.pick(f"script.attack/{ext}.{'+'.join(steps)}", opts) if opts else None
    if qid.endswith("-campaign"):
        return plan.get("campaign_id") or None
    if qid.endswith("-stage-count"):
        v = plan.get("stage_count")
        return v if v and v.isdigit() else None
    # The id first (Day 12): the longest plan key its last words spell (`-cron-path` is cron_path, never
    # `path`). The text's "exact <key> indicator" only for a key the id's last word can mean, or a short id.
    words = qid.split("-")
    for n in (3, 2, 1):
        k = "_".join(words[-n:])
        if len(words) > n and k in plan:
            return plan.get(k) or None
    named = re.search(r"exact (\w+) indicator", text)
    if named:
        key = named.group(1)
        if len(words) < 3 or key.startswith(tail + "_") or key.endswith("_" + tail) or key == tail:
            return plan.get(key) or None
        return None
    if tail in plan:
        return plan.get(tail) or None
    k = "_".join(qid.split("-")[-2:])
    return plan.get(k) or None


def answers(text, questions, ext) -> dict:
    wanted = [q for q in questions or () if isinstance(q, dict)]
    if not wanted:
        return {}
    plan = read(text)
    if plan is None:
        return {}
    out = {}
    for q in wanted:
        try:
            v = _answer(q, plan, ext)
        except Exception as e:  # noqa: BLE001
            print(f"[label_plan] {_qid(q)} raised {type(e).__name__}: {e}", file=sys.stderr)
            continue
        if v not in (None, ""):
            out[q.get("qid") or q.get("id")] = v
    return out


def main(argv) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: label_plan.py <script> [...]")
        return 0
    if not argv:
        print("label_plan.py: expected at least one script", file=sys.stderr)
        return 2
    try:
        for path in argv:
            print(path, read(Path(path).read_text(encoding="utf-8", errors="replace")))
    except Exception as exc:
        print(f"label_plan.py: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
