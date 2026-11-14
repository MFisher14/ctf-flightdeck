#!/usr/bin/env python3
"""The tagged analysis descriptor of a Script Analysis specimen, read whole or not at all (rows 101 and 113).

Usage:
  python3 solvers/script-analysis/descriptor.py <specimen> [...]     print what each file's descriptor gives

Day 8's twelve new specimens (PHP and the host files in .js and .vbs) store their whole plan twice: in a
comment `HUNTRESS_ANALYSIS_V1:<TAG>-<payload>` and in a literal `descriptor_<hex8> = "<payload>"`. The tag
names the encoding (B64, HEX, HB64 = hex of base64, FRAG = hex pieces joined by one separator) and the plan
is version 3 with its fields in an order of its own:

    v=3|language=..|role=..|verdict=..|attack=..|adapter=..|host_profile=..|obfuscation_profile=..|
    stage_profile=..|next_language=..|stage_count=..|steps=a,b|campaign_id=..|url=..|file_path=..

Nothing is run. reading(text) returns one of

    None                      the file holds no tagged comment and no `descriptor_<id>` literal that reads
    (plan text, how, None)    ONE plan, read whole
    (None, None, why)         a descriptor is there and is not ONE whole plan: nothing may be answered from it

reading_ex(text) says the same with one more state, for generic.read(): `open`, a whole comment beside a
literal written as a join, which another reading of that literal has to confirm.

A descriptor is whole only when all of this holds (row 113: on mangled copies the Day 8 reader answered a
cut `host-profile=hta_js` plain, because its pattern stopped at the first foreign character and its grammar
took a plan's prefix):

  the comment       its payload runs to the end of its line (a comment closer and blanks may follow, nothing
                    else) and ALL of it decodes; a payload that decodes only in part is no reading. A payload
                    that gives no plan as it stands is tried once more without a closer of CLOSER_MORE (a
                    template engine's, a docstring's quotes, the quote of a string value); read that way the
                    comment is one copy that only a whole literal confirms (trimmed). A comment that
                    does not decode because a note stands behind its payload, or because it is wrapped
                    over comment lines, is still not read; when it is the file's ONE whole literal so
                    decorated (decorated), that literal is read as one copy (reading_ex: fallback; Day
                    13 preparation) and the strict reading() still refuses the file;
  the literal       it is the whole right-hand side of its assignment (`;`, `,`, `)` or a comment may follow;
                    a join operator, a call or a second literal may not), and ALL of it decodes;
  agreement         every comment and every literal of the file give the same plan;
  the grammar       plan_codec.grammar_plan: `v=<n>` first, every field `key=value` with a lowercase key, no
                    key twice, `steps=` a list of step names, at least four fields, printable ASCII (or a JSON
                    object with `steps`);
  stage_count       in a version-3 plan it is a whole number equal to the number of steps (true of all 84
                    descriptors of the seven Day 8 deliveries; a version-1 plan counts otherwise). The
                    number of steps is asked of ONE copy only: a comment and a whole literal that give the
                    same plan with every field prove the count the plan states (checked: two_copies);
  the fields        a version-3 plan holds all fifteen fields those 84 hold (PLAN_KEYS), in any order.

One copy is not two (review of 2026-10-08). Only a comment AND a whole literal that give the same plan say
that the plan's last value is not cut. One copy alone is whole only while nothing says it is a piece: the
comment's next line reading as more of its payload (continued: a comment wrapped at a column), the literal's
variable appended to, assigned twice or used in a join (literals), the next line going on with `+ ".."`,
plan_codec reading the same file as a piece or as another plan. Then reading() is not whole, and
generic.by_descriptor takes the plan without its last field.

complete(plan, keys) is the caller's last check: every asked field must be in the plan, for a plan cut
between two fields passes everything above when both copies were cut alike.

How a payload is decoded. The tag's own chain first (TAGS; a composite tag `GZ+B64`, `B64_REV`, `XOR5A-..`
reads as its parts). When the tag is unknown or its chain gives no plan, every chain of up to three layers
(LAYERS: base64 in either alphabet, hex compact, in pieces or with `0x` or `\\x` on every byte, base32,
base85 in three alphabets, percent text, a decimal list, zlib/gzip/raw deflate reaching their end, the text
reversed, ROT13, base58 and base91 through label_plan's readers, ASCII text as UTF-16LE behind another
layer; base64 too may come in pieces with one separator) is tried, each
result under every transform a plan's first bytes fix (plan_codec.undo: xor, add, rolling and repeating xor,
rotation, reversed bytes). Only a text the grammar accepts counts, and two different plans are no plan. So a
tag never decides an answer: it only says which chain to try first.

Six more layers are read ONLY under the tag word that names them (TAG_LAYERS, Day 18 look-ahead B2): OCT and
BIN (octal and 8-bit groups, one byte each), QP (quoted-printable), B36, ROT47 and ROT18 (letters by 13 and
digits by 5). They are never part of the free search, and no letter cipher (ATBASH, CAESAR-n) is among them.
Day 26 adds base45, base62, uuencode and ASCII85 spellings to TAGS (B45, B62, UU, ADOBE85) and base45/base62/uu to
the free search (appended last), and yEnc and brotli as tag-only layers (YENC, BROTLI and their B64/HEX spellings).
Row 306 adds three more of that kind: UTF-16BE text, bzip2 and xz/lzma (U16BE, BZ2, XZ, LZMA and their B64/HEX
spellings), each whole or nothing.  The Day-30 composition build adds bounded, complete-frame zstd, LZ4-frame and
Snappy-framed layers under their named B64/HEX tags and at the selective end of the free layer search.
A comment followed by markup on its own line (`<!-- HUNTRESS..:<TAG>-<payload> --><desc>..`, B7) is read as
the payload up to the comment closer, as a trimmed copy.
"""
import base64
import binascii
import bisect
import codecs
import json
import re
import sys
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import plan_codec  # noqa: E402

# `HUNTRESS_ANALYSIS_V1:` (also with `-` for `_`, any version number), then the rest of the line.
MARK = re.compile(r"HUNTRESS[_-]ANALYSIS[_-]V(\d+)[ \t]*[:=][ \t]*([^\r\n]*)")
# Any other `HUNTRESS_<NAME>:<TAG>-<payload>` line whose tag this table knows (a later day may rename the
# mark). It counts only when its payload decodes to one plan; otherwise it is some other note of the
# fixture (HUNTRESS-MATERIAL, HUNTRESS-CODEC and HUNTRESS-EXTENSION are plan_codec's and never read here).
SOFT_MARK = re.compile(r"HUNTRESS[_-](?!ANALYSIS[_-]V\d|MATERIAL\b|CODEC\b|EXTENSION\b)[A-Za-z][A-Za-z0-9_-]{1,40}?"
                       r"[ \t]*[:=][ \t]*([A-Za-z][A-Za-z0-9_+>]{0,31})-([^\s\r\n]{24,})[ \t]*\r?$", re.M)
TAGGED = re.compile(r"([A-Za-z][A-Za-z0-9_+>]{0,31}?)[ \t]*[-:=|][ \t]*(\S(?:.*\S)?)", re.S)
# What may close a comment after the payload (Day 16 look-ahead: `--->`, ColdFusion's, too): */ --> ---> --%> #> %> ?> ]]> ]] =end --]] |# *) -}
CLOSER = re.compile(r"[ \t]*(?:\*/|-{2,3}%?>|#>|%>|\?>|\]\]>?|=end|--\]\]|\|#|\*\)|-\})$")
# Day 12 look-ahead (S2): what else may stand behind a payload on its line, tried only when the payload as it
# stands gave no plan (reading_ex). A blank and a run of punctuation that ends as a closer does ( #}  *@  *}
# --}}  */}}  *#  +/  =#  ]#  } ), the quotes that close a docstring, the quote that closes a string value with
# closing punctuation behind it ( ",  ";  ")  "/> ), an XML end tag. Never a word, and never a run that ends in
# an operator or a line continuation ( +  .  &  \  _ ): such a line goes on. The payload in front must still
# decode WHOLE to one plan, and a comment read this way is one copy whose end this reader chose: only a whole
# literal that gives the same plan proves its last value (reading_ex: trimmed).
CLOSER_MORE = re.compile(r"(?:[ \t]+[^\sA-Za-z0-9]{0,5}[}@#/)\]>]|[ \t]*(?:\"\"\"|'''|[\"'`][;,)\]}/>]{0,4}|</[A-Za-z][\w:.-]*>))$")
MORE_SPAN = 96           # characters at a line's end in which a CLOSER_MORE closer is looked for (closer_more)
# Day 18 look-ahead (B7): a one-line SVG, XAML or MSBuild file writes the comment and the markup after it on ONE
# line (`<svg ...><!-- HUNTRESS_ANALYSIS_V1:B64-<payload> --><desc ...>..</desc></svg>`), and the whole family
# was None (44 ids). A payload that gives no plan as it stands, and none without a CLOSER_MORE closer, is cut
# where a comment closer is followed by markup (`<` and a name, `/`, `!` or `?`). Read that way the comment is
# one copy whose end this reader chose (trimmed): its last field is unsure (one_copy) unless a whole literal
# gives the same plan.
MARKUP_AFTER = re.compile(r"(\S+?)[ \t]*(?:-{2,3}%?>|\*/|%>|\?>|#>)[ \t]*<[A-Za-z/!?]")
# `descriptor_<id>` assigned one quoted literal: $descriptor_x = "..";  const descriptor_x = '..';
# descriptor_x := `..`  descriptor_x <- ".."  set descriptor_x ".."  (def descriptor_x "..")  descriptor_x: str = ".."
# property descriptor_x : ".."  {descriptor_x:".."}  (AppleScript, Day 13: 2026-10-13. Without the `:` a
# .applescript file had ONE copy, its comment, and a comment that was wrapped or decorated emptied it.
# literals() takes the `:` form only as a copy of the tagged comment's payload: see there.)
LITERAL = re.compile(
    r"(?m)(?<![A-Za-z0-9])descriptor_(\w+)"            # as Day 8 wrote it: lower case (not DeScRiPtOr_Text)
    r"(?:[ \t]*:[ \t]*[A-Za-z_][\w.\[\]<>]*|[ \t]+[Aa]s[ \t]+\w+)?"
    r"[ \t]*(?P<op>=>|:=|<-|=|:|\bto\b|[ \t])[ \t]*"
    r"[bBrRuU]{0,2}(?P<q>[\"'`])(?P<body>[^\r\n]*?)(?P=q)(?P<post>[^\r\n]*)$")
# After the closing quote of a whole right-hand side: `;` `,` `)` blanks, then nothing or a comment.
# An apostrophe starts a comment in VBScript and a second literal anywhere else (`"abc" 'def'` is ONE value in
# Python and in a shell): it is read as a comment only when no second apostrophe follows it.
WHOLE_POST = re.compile(r"""[ \t]*[;,)\]}]*[ \t]*(?:(?:\#|//|--|;|(?i:rem)\b|/\*)[^\r\n]*|'[^'\r\n]*)?""")
# What makes a `descriptor_<id>` variable a piece of a longer value where it stands elsewhere in the file
# (review of 2026-10-08): a call on it that adds text, a list or a call it shares with a quoted literal, an
# interpolation. plan_codec.glued sees the operators (`x += ..`, `x = x & ..`, `x + ".."`); these it does not.
ADDS_AFTER = re.compile(r"\}?[ \t]*(?:\.(?:concat|append|push|add|extend|insert|prepend|join|padEnd|padStart|format|write)\b"
                        r"|,[ \t]*[bBrRuU]{0,2}[\"'`]|[ \t]+[bBrRuU]{0,2}[\"'`])")
ADDS_BEFORE = re.compile(r"(?:[\"'`][ \t]*,[ \t]*|[\"'`][ \t]+|\$\{|\#\{|\\\(|\{)\$?$")
# The start of a line that goes on with a comment: its leader, before the text.
LEADER = re.compile(r"[ \t]*(?:\#+|;+|\*+|//+|::|--|'|<!--|(?i:rem)\b)?[ \t]*")
NEXT_LINE = re.compile(r"\r?\n([^\r\n]*)")
MIN_PAYLOAD = 24         # characters: a shorter `descriptor_x = ".."` is another kind of value
# The Day 21 look-ahead: a body that is nothing but interpolations (`"${part0}${part1}"`, `"$a$b"`, `"#{a}#{b}"`,
# `"\(a)\(b)"`, Groovy's `"${'5a1f'}${'..'}"`) is a value built from other values, not a literal copy: it is no
# whole copy (a join, `open`), so the tagged comment is settled by plan_codec's reading of it as for any join. Read
# as a whole literal it decoded to nothing, and the file was refused (44 of 44 ids None on a `.groovy` family).
INTERP_ONLY = re.compile(r"(?:\$\{[^{}\r\n]*\}|\$[A-Za-z_]\w*|#\{[^{}\r\n]*\}|\\\([^()\r\n]*\))+")
# The Day 21 look-ahead: R's raw string `r"(..)"` (also `[..]`, `{..}`, dashes around: `r"-(..)-"`) and C++'s
# `R"delim(..)delim"` hold their text inside the brackets; read with them, the literal disagreed with the tagged
# comment and the file was refused (44 of 44 ids None).
_RAW_R = re.compile(r"(-*)([(\[{])(.*)([)\]}])\1", re.S)
_RAW_CPP = re.compile(r"([^()\\\s]{0,16})\((.*)\)\1", re.S)
_RAW_PAIRS = {"(": ")", "[": "]", "{": "}"}


def _raw_body(text: str, m) -> str:
    """The literal's body without a raw string's delimiters, when it is one (`r"(..)"`, `R"x(..)x"`)."""
    body = m.group("body")
    a = m.start("q")
    if a == 0 or text[a - 1] not in "rR" or (a >= 2 and (text[a - 2].isalnum() or text[a - 2] == "_")):
        return body
    r = _RAW_R.fullmatch(body)
    if r is not None and _RAW_PAIRS[r.group(2)] == r.group(4):
        return r.group(3)
    if text[a - 1] == "R":
        c = _RAW_CPP.fullmatch(body)
        if c is not None:
            return c.group(2)
    return body
MAX_PAYLOAD = 400_000    # characters of one payload that are read
MAX_LAYERS = 3
MAX_INFLATE = plan_codec.MAX_INFLATE


# ---------------------------------------------------------------- layers: text or bytes -> text or bytes

def _text(x):
    """`x` as text when it is ASCII text, else None."""
    if isinstance(x, str):
        return x
    try:
        t = x.decode("ascii")
    except UnicodeDecodeError:
        return None
    # t is ASCII, so this is exactly `all(32 <= ord(c) < 127 or c in "\t\r\n" for c in t)`: an ASCII character is
    # printable iff it is 0x20..0x7E, and tab, CR and LF are taken out before the second look (perf, Day 27).
    return t if t.isprintable() or t.translate(_TAB_CR_LF).isprintable() else None


_TAB_CR_LF = {9: None, 10: None, 13: None}


def _b64_one(t: str):
    if len(t) < 2 or not re.fullmatch(r"(?:[A-Za-z0-9+/]+|[A-Za-z0-9_-]+)={0,2}", t):
        return None
    core = t.rstrip("=")
    if len(core) % 4 == 1 or (len(t) != len(core) and len(t) % 4):
        return None
    try:
        return base64.b64decode(core.translate(plan_codec.URLSAFE) + "=" * (-len(core) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


B64_SEPARATORS = ".:,;|"


def _b64(x):
    """Base64 in either alphabet, padded or not; also in pieces with ONE separator between them (a
    fragmented payload): the pieces joined when that is base64, else each piece decoded by itself."""
    t = _text(x)
    if t is None:
        return None
    t = re.sub(r"\s", "", t)
    if len(t) < 8:
        return None
    seps = {c for c in t if c in B64_SEPARATORS}
    if not seps:
        return _b64_one(t)
    if len(seps) != 1:
        return None
    parts = t.split(next(iter(seps)))
    if not all(parts):
        return None
    whole = _b64_one("".join(parts)) if not any("=" in p for p in parts[:-1]) else None
    if whole is not None:
        return whole
    each = [_b64_one(p) for p in parts]
    return b"".join(each) if all(e is not None for e in each) else None


FRAG_SEPARATORS = ".-:,|;_ \t/"       # `/` since the Day 12 look-ahead (S3): for hex only, base64 is written with it


def frag_hex(t: str):
    """The bytes of hex text written compact, or in pieces with ONE separator between them (FRAG: `763d.337c`,
    also `76:3d`, `763d 337c`, `763d/337c`, each piece a whole number of bytes), or None."""
    t = t.strip()
    if re.fullmatch(r"(?:[0-9A-Fa-f]{2})+", t):
        return bytes.fromhex(t)
    seps = {c for c in t if c not in "0123456789abcdefABCDEF"}
    if len(seps) != 1 or next(iter(seps)) not in FRAG_SEPARATORS:
        return None
    parts = t.split(next(iter(seps)))
    if not all(p and len(p) % 2 == 0 for p in parts):
        return None
    return bytes.fromhex("".join(parts))


# Day 12 look-ahead (S3): hex with a prefix on EVERY byte, `0x76,0x3d` (a comma, blanks or both between the
# bytes) or `\x76\x3d`. One byte without its prefix makes it another text.
HEX_PREFIXED = re.compile(r"(?:0[xX][0-9A-Fa-f]{2}(?:[ \t]*,[ \t]*|[ \t]+))*0[xX][0-9A-Fa-f]{2}|(?:\\x[0-9A-Fa-f]{2})+")


def hex_prefixed(t: str):
    """The bytes of hex text whose every byte carries `0x` or `\\x` (HEX_PREFIXED), or None."""
    t = t.strip()
    if not HEX_PREFIXED.fullmatch(t):
        return None
    return bytes.fromhex("".join(re.findall(r"[xX]([0-9A-Fa-f]{2})", t)))


def _hex(x):
    t = _text(x)
    if t is None or len(t.strip()) < 8:
        return None
    got = frag_hex_ok(t)
    return got if got is not None else hex_prefixed(t)


def _utf16(x):
    """ASCII text written as UTF-16LE (the form PowerShell's -EncodedCommand takes), as its bytes: every second
    byte is NUL, a byte-order mark may stand in front. Day 12 look-ahead (S3): the plan behind a base64 layer."""
    if isinstance(x, str) or len(x) < 16 or len(x) % 2:
        return None
    b = bytes(x)[2:] if bytes(x[:2]) == b"\xff\xfe" else bytes(x)
    if any(b[1::2]) or not all(32 <= c < 127 or c in (9, 10, 13) for c in b[::2]):
        return None
    return b[::2]


def _b32(x):
    t = _text(x)
    if t is None:
        return None
    t = re.sub(r"\s", "", t)
    core = t.rstrip("=")
    if len(core) < 16 or not (re.fullmatch(r"[A-Z2-7]+", core) or re.fullmatch(r"[a-z2-7]+", core)) \
            or len(core) % 8 in (1, 3, 6):
        return None
    try:
        return base64.b32decode(core.upper() + "=" * (-len(core) % 8))
    except (binascii.Error, ValueError):
        return None


def _b85(x):
    t = _text(x)
    if t is None or len(t.strip()) < 10:
        return None
    try:
        return base64.b85decode(t.strip())
    except ValueError:
        return None


def _a85(x):
    t = _text(x)
    if t is None or len(t.strip()) < 10:
        return None
    t = t.strip()
    try:
        return base64.a85decode(t, adobe=t.startswith("<~") and t.endswith("~>"))
    except ValueError:
        return None


def _z85(x):
    t = _text(x)
    if t is None or len(t.strip()) < 10 or len(t.strip()) % 5:
        return None
    try:
        return base64.b85decode(t.strip().translate(plan_codec._Z85_TO_B85))
    except ValueError:
        return None


def _by_label_plan(name: str):
    """A reader of label_plan.py (base58, base91) as a layer: None when the file or the reader is not there."""
    def layer(x):
        t = _text(x)
        lp = plan_codec.optional("label_plan")
        fn = getattr(lp, name, None) if lp is not None else None
        if t is None or fn is None or len(t.strip()) < 16 or re.search(r"\s", t.strip()):
            return None
        try:
            return bytes(fn(t.strip()))
        except Exception:  # noqa: BLE001 - not this alphabet
            return None
    return layer


def _percent(x):
    t = _text(x)
    if t is None or "%" not in t or re.search(r"%(?![0-9A-Fa-f]{2})", t) or re.search(r"\s", t.strip()):
        return None
    return urllib.parse.unquote_to_bytes(t.strip())


def _decimal(x):
    t = _text(x)
    if t is None:
        return None
    parts = re.split(r"[ \t]*[,;:. \t][ \t]*", t.strip())
    if len(parts) < 8 or not all(re.fullmatch(r"\d{1,3}", p) for p in parts):
        return None
    vals = [int(p) for p in parts]
    return bytes(vals) if max(vals) < 256 else None


def _inflate(x):
    if isinstance(x, str) or len(x) < 8:
        return None
    z = plan_codec._inflated(bytes(x))
    if z:
        return z[1]
    return plan_codec.raw_inflate(bytes(x), _is_plan_bytes)


def _reverse(x):
    t = _text(x)
    return t[::-1] if t is not None and len(t) > 1 and t[::-1] != t else None


def _rot13(x):
    t = _text(x)
    return codecs.encode(t, "rot13") if t is not None and re.search(r"[A-Za-z]", t) else None


LAYERS = {"b64": _b64, "hex": _hex, "b32": _b32, "b85": _b85, "a85": _a85, "z85": _z85, "pct": _percent,
          "dec": _decimal, "inflate": _inflate, "rev": _reverse, "rot13": _rot13,
          "b58": _by_label_plan("_b58"), "b91": _by_label_plan("_b91"), "u16": _utf16}


# ---------------------------------------------------------------- Day 26 build: base45, base62, uuencode, yEnc, brotli
#
# Measured gap (2026-10-25): a v=3 plan written as Base45 (RFC 9285, tag word B45) was read by nothing: neither TAGS
# nor the free search knew it, and a live fix took about 2:48. Same route as every layer above: a decoder is a layer,
# a tag word names it (TAGS), the free search may try it (LAYERS, appended LAST so no earlier chain is displaced),
# and what it gives is accepted by the plan grammar alone (plan_text) and then by the two-copy check like any other
# reading. Each decoder is whole or nothing and strict about its alphabet, so a near-miss alphabet gives None.
# Tag-only (TAG_LAYERS): yEnc (no magic, bytes above 127) and brotli (no magic at all).

B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_INDEX = {c: i for i, c in enumerate(B45_ALPHABET)}


def _b45(x):
    """Base45 (RFC 9285): three characters give two bytes (c + 45 d + 2025 e <= 65535), a final pair gives one
    (c + 45 d <= 255). The SPACE is index 36 and part of the text; a trailing blank that the comment reader
    trimmed is put back when that is the only way the length can be right. Anything else is None."""
    t = _text(x)
    if t is None:
        return None
    t = t.strip("\r\n")
    if not (8 <= len(t) <= MAX_PAYLOAD) or any(c not in _B45_INDEX for c in t):
        return None
    if len(t) % 3 == 1:
        t += " "
        if len(t) % 3 == 1:
            return None
    v = [_B45_INDEX[c] for c in t]
    out = bytearray()
    for i in range(0, len(v) - 2, 3):
        n = v[i] + v[i + 1] * 45 + v[i + 2] * 2025
        if n > 0xFFFF:
            return None
        out += n.to_bytes(2, "big")
    if len(v) % 3:
        n = v[-2] + v[-1] * 45
        if n > 0xFF:
            return None
        out.append(n)
    return bytes(out)


_B62_ALPHABETS = {"b62": "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                  "b62l": "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
                  "b62a": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"}
B62_MAX = 6000        # characters: the number is big; a longer text is not read


def _b62_with(alphabet):
    index = {c: i for i, c in enumerate(alphabet)}

    def layer(x):
        t = _text(x)
        if t is None:
            return None
        t = t.strip()
        if not (8 <= len(t) <= B62_MAX) or any(c not in index for c in t):
            return None
        n = 0
        for c in t:
            n = n * 62 + index[c]
        return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else None
    return layer


_b62, _b62l, _b62a = (_b62_with(_B62_ALPHABETS[k]) for k in ("b62", "b62l", "b62a"))
# a layer name -> the other alphabets tried under the same tag word when this one gives no plan (decode)
ALT_LAYERS = {"b62": ("b62l", "b62a")}

_UU_FIRST = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"


def _uu(x):
    """uuencode: the lines of an optional `begin <mode> <name>` .. `end` block, or the bare lines; separated by
    newlines, or by a literal backslash-n (a one-line comment cannot hold a newline). At least two lines, every
    line checked by binascii (a bad length byte or trailing garbage is None); the closing backtick or blank line
    is dropped. Whole or nothing."""
    t = _text(x)
    if t is None:
        return None
    t = t.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\r", "")
    lines = t.split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    if lines and lines[0].startswith("begin "):
        lines.pop(0)
    while lines and lines[-1].strip() in ("", "`"):
        lines.pop()
    if lines and lines[-1].strip() == "end":
        lines.pop()
    while lines and lines[-1].strip() in ("", "`"):
        lines.pop()
    if len(lines) < 2 or len(lines) > 20000:
        return None
    out = bytearray()
    try:
        for ln in lines:
            if not ln or ln[0] not in _UU_FIRST or (ord(ln[0]) - 32) & 63 == 0:
                return None                  # a zero-length line ends the data: it is not inside it
            if len(ln) != 1 + ((((ord(ln[0]) - 32) & 63) + 2) // 3) * 4:
                return None                  # a line cut short (or padded): its length byte says how long it is
            out += binascii.a2b_uu(ln.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    return bytes(out) if len(out) >= 8 else None


_YBEGIN = re.compile(r"=ybegin\b[^\r\n]*?\bsize=(\d+)[^\r\n]*\r?\n", re.I)


def _yenc(x):
    """yEnc: every byte minus 42; `=` escapes the next byte (minus 64 more). Taken as latin-1 text or bytes, with
    or without the `=ybegin`/`=yend` lines. When a header gives `size=` (and `=yend` gives `crc32=`/`pcrc32=`) the
    decoded length (and checksum) must agree, else None; a bare body must not end in a dangling `=`."""
    if isinstance(x, str):
        try:
            data = x.encode("latin-1")
        except UnicodeEncodeError:
            return None
    else:
        data = bytes(x)
    size = crc = None
    text = data.decode("latin-1")
    m = _YBEGIN.match(text)
    if m:
        size = int(m.group(1))
        body = text[m.end():]
        e = re.search(r"\r?\n?=yend\b([^\r\n]*)\s*$", body, re.I)
        if e is None:
            return None
        c = re.search(r"\bp?crc32=([0-9A-Fa-f]{8})", e.group(1))
        crc = int(c.group(1), 16) if c else None
        body = re.sub(r"^=ypart[^\r\n]*\r?\n", "", body[:e.start()])
        data = body.encode("latin-1")
    data = data.replace(b"\r", b"").replace(b"\n", b"")
    if not (8 <= len(data) <= MAX_PAYLOAD):
        return None
    out, i, n = bytearray(), 0, len(data)
    while i < n:
        c = data[i]
        if c == 0x3D:
            i += 1
            if i >= n:
                return None                  # a dangling escape: cut
            c = (data[i] - 64) & 255
        out.append((c - 42) & 255)
        i += 1
    if size is not None and len(out) != size:
        return None
    if crc is not None and binascii.crc32(bytes(out)) & 0xFFFFFFFF != crc:
        return None
    return bytes(out) if len(out) >= 8 else None


BROTLI_MAX = 1 << 20


def _brotli(x):
    """A brotli stream that reaches its end with nothing behind it (declined when `brotli` is not installed)."""
    if isinstance(x, str) or len(x) < 4:
        return None
    try:
        import brotli
    except Exception:  # noqa: BLE001 - no decompressor here: decline, never half-read
        return None
    try:
        d = brotli.Decompressor()
        out = d.process(bytes(x))
        if not d.is_finished() or len(out) > BROTLI_MAX or not out:
            return None
        return out
    except Exception:  # noqa: BLE001 - not brotli
        return None


# appended LAST: the free search walks LAYERS in order and keeps 64 states per level, so nothing earlier moves
LAYERS.update({"b45": _b45, "b62": _b62, "b62l": _b62l, "b62a": _b62a, "uu": _uu})


# ---------------------------------------------------------------- layers read ONLY by their tag word
#
# Day 18 look-ahead (B2, 2026-10-17; extends row 234). A fifth descriptor tag left the new family None in the
# base and in every Mastery set for OCT, BIN, QP, B36, ROT47 and ROT18 (44 ids each). These layers are applied
# only when the comment's own tag word names them (TAG_LAYERS, through TAGS): they are never part of the free
# search of decode(), which walks LAYERS alone, so an unknown tag is searched exactly as before (row 211's
# rotation guard included). No letter cipher (ATBASH, CAESAR-n) is here: how the author treats capitals under
# one is not knowable, and an ATBASH layer gave 12 wrong plain campaigns in the prototype. Each layer is whole
# or nothing, and what it gives must still pass the grammar and the two-copy checks like any other reading.

def _digit_groups(x, base: int, width: int):
    """Octal (base 8, three digits) or 8-bit binary (base 2) groups, one byte each: with one separator run
    between them (`166.075`, `166 075`, `\\166\\075`) or written together when every byte has its full width."""
    t = _text(x)
    if t is None:
        return None
    digits = "[0-7]" if base == 8 else "[01]"
    parts = [p for p in re.split(r"[^0-9A-Za-z]+", t.strip()) if p]
    if len(parts) == 1 and len(parts[0]) % width == 0:
        parts = [parts[0][i:i + width] for i in range(0, len(parts[0]), width)]
    if len(parts) < 8 or not all(re.fullmatch(f"{digits}{{{width}}}", p) for p in parts):
        return None
    vals = [int(p, base) for p in parts]
    return bytes(vals) if max(vals) < 256 else None


def _rot47(x):
    t = _text(x)
    return None if t is None else "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in t)


def _rot18(x):
    """Letters by 13 and digits by 5: only where the tag says ROT18 (the free search cannot tell it from rot13)."""
    t = _text(x)
    if t is None:
        return None
    return "".join(chr(48 + (ord(c) - 43) % 10) if "0" <= c <= "9" else codecs.encode(c, "rot13") if c.isascii() and c.isalpha()
                   else c for c in t)


def _quoted_printable(x):
    t = _text(x)
    if t is None or "=" not in t or re.search(r"=(?![0-9A-Fa-f]{2}|\r?\n)", t):
        return None
    import quopri
    try:
        return quopri.decodestring(t.encode("ascii"))
    except Exception:  # noqa: BLE001 - not quoted-printable
        return None


def _b36(x):
    t = _text(x)
    if t is None:
        return None
    t = t.strip()
    if not (8 <= len(t) <= 4000) or not (re.fullmatch(r"[0-9a-z]+", t) or re.fullmatch(r"[0-9A-Z]+", t)):
        return None
    try:
        n = int(t, 36)
    except ValueError:
        return None
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else None


# Row 306 (Day 20 build): UTF-16BE text, bzip2 and xz/lzma are tag-only layers too, for the same reason: in the
# free search they would widen every unknown tag's walk. Each is whole or nothing: UTF-16BE is ASCII with every
# first byte NUL (a FE FF mark may stand in front); bzip2 and xz must reach their stream's end with nothing
# behind it, and give at most TAG_INFLATE_MAX bytes.
TAG_INFLATE_MAX = 1 << 20


def _utf16be(x):
    if isinstance(x, str) or len(x) < 16 or len(x) % 2:
        return None
    b = bytes(x)[2:] if bytes(x[:2]) == b"\xfe\xff" else bytes(x)
    if not b or any(b[0::2]) or not all(32 <= c < 127 or c in (9, 10, 13) for c in b[1::2]):
        return None
    return b[1::2]


def _whole_stream(make, data):
    d = make()
    try:
        out = d.decompress(data, max_length=TAG_INFLATE_MAX)
    except Exception:  # noqa: BLE001 - not this stream
        return None
    if not d.eof or d.unused_data or not out:
        return None
    return out


def _bunzip2(x):
    if isinstance(x, str) or not bytes(x[:3]) == b"BZh":
        return None
    import bz2
    return _whole_stream(bz2.BZ2Decompressor, bytes(x))


def _unxz(x):
    if isinstance(x, str) or not (bytes(x[:6]) == b"\xfd7zXZ\x00" or bytes(x[:3]) == b"\x5d\x00\x00"):
        return None
    import lzma
    return _whole_stream(lambda: lzma.LZMADecompressor(lzma.FORMAT_AUTO), bytes(x))


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
LZ4_MAGIC = b"\x04\x22\x4d\x18"
SNAPPY_MAGIC = b"\xff\x06\x00\x00sNaPpY"
COMPRESS_IN_STEP = 1 << 10


def _zstd(x):
    """One complete zstd frame, incrementally bounded and checksum-verified by python-zstandard."""
    if isinstance(x, str) or bytes(x[:4]) != ZSTD_MAGIC:
        return None
    try:
        import zstandard
        data = bytes(x)
        # python-zstandard takes max_window_size in bytes.  The former // 1024 value therefore admitted only
        # 1 KiB frames and made the tiny fixture a false green.  Preflight the declared size/window and use
        # max_output_size for a content-size-less frame before the exact-frame pass below.  This first pass
        # makes the later decompressobj allocation safe: the same frame has already proved it expands to at
        # most TAG_INFLATE_MAX bytes.
        params = zstandard.get_frame_parameters(data)
        if params.window_size > TAG_INFLATE_MAX:
            return None
        if params.content_size not in (zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR):
            if params.content_size > TAG_INFLATE_MAX:
                return None
        bounded = zstandard.ZstdDecompressor(max_window_size=TAG_INFLATE_MAX).decompress(
            data, max_output_size=TAG_INFLATE_MAX, read_across_frames=False, allow_extra_data=True)
        if not bounded or len(bounded) > TAG_INFLATE_MAX:
            return None

        # decompress(..., read_across_frames=False) can accept bytes after a content-size-less frame.  A second,
        # now output-safe pass retains the original exact-one-frame guarantee through unused_data/pos checks.
        dec = zstandard.ZstdDecompressor(max_window_size=TAG_INFLATE_MAX).decompressobj()
        pieces, total, pos = [], 0, 0
        while pos < len(data) and not dec.eof:
            end = min(len(data), pos + COMPRESS_IN_STEP)
            out = dec.decompress(data[pos:end])
            pos = end
            total += len(out)
            if total > TAG_INFLATE_MAX:
                return None
            if out:
                pieces.append(out)
        if not dec.eof or dec.unused_data or pos != len(data):
            return None                    # truncated, trailing bytes, or a concatenated second frame
        tail = dec.flush()
        total += len(tail)
        if total > TAG_INFLATE_MAX:
            return None
        if tail:
            pieces.append(tail)
        out = b"".join(pieces)
        return out if out == bounded else None
    except Exception:  # noqa: BLE001 - missing library, wrong dictionary, corrupt/checksum-failed frame
        return None


def _lz4(x):
    """One complete checksummed LZ4 frame, draining it through a bounded output window."""
    if isinstance(x, str) or bytes(x[:4]) != LZ4_MAGIC:
        return None
    try:
        import lz4.frame
        dec = lz4.frame.LZ4FrameDecompressor()
        data, pieces, total, pos, feed = bytes(x), [], 0, 0, b""
        while not dec.eof:
            if dec.needs_input:
                if pos >= len(data):
                    return None
                end = min(len(data), pos + (1 << 14))
                feed, pos = data[pos:end], end
            out = dec.decompress(feed, max_length=TAG_INFLATE_MAX - total + 1)
            feed = b""
            total += len(out)
            if total > TAG_INFLATE_MAX:
                return None
            if out:
                pieces.append(out)
            if not out and not dec.needs_input and not dec.eof:
                return None
        if dec.unused_data or pos != len(data):
            return None
        out = b"".join(pieces)
        return out or None
    except Exception:  # noqa: BLE001 - missing library or malformed/checksum-failed frame
        return None


def _snappy(x):
    """One complete Snappy framed stream; raw Snappy remains unsupported without an explicit size oracle."""
    if isinstance(x, str) or bytes(x[:10]) != SNAPPY_MAGIC:
        return None
    try:
        import snappy
        data, dec, pieces, total, pos, saw_data = bytes(x), snappy.StreamDecompressor(), [], 0, 0, False
        while pos < len(data):
            if pos + 4 > len(data):
                return None
            kind = data[pos]
            size = int.from_bytes(data[pos + 1:pos + 4], "little")
            end = pos + 4 + size
            if end > len(data):
                return None
            chunk = data[pos:end]
            if pos == 0:
                if chunk != SNAPPY_MAGIC:
                    return None
            elif kind in (0, 1):
                if size < 4:
                    return None
                saw_data = True
            elif kind == 0xff or kind < 0x80:
                return None                    # duplicate identifier or unknown unskippable chunk
            out = dec.decompress(chunk)
            total += len(out)
            if total > TAG_INFLATE_MAX:
                return None
            if out:
                pieces.append(out)
            pos = end
        tail = dec.flush()
        total += len(tail)
        if not saw_data or total > TAG_INFLATE_MAX:
            return None
        if tail:
            pieces.append(tail)
        out = b"".join(pieces)
        return out or None
    except Exception:  # noqa: BLE001 - missing library or malformed/checksum-failed frame
        return None


TAG_LAYERS = {"oct": lambda x: _digit_groups(x, 8, 3), "bin": lambda x: _digit_groups(x, 2, 8), "rot47": _rot47,
              "rot18": _rot18, "qp": _quoted_printable, "b36": _b36,
              "u16be": _utf16be, "bz2": _bunzip2, "xz": _unxz, "zstd": _zstd, "lz4": _lz4,
              "snappy": _snappy, "yenc": _yenc, "brotli": _brotli}
# Unlike raw Brotli, these framed codecs carry selective magics and are safe at the end of the free search.
LAYERS.update({"zstd": _zstd, "lz4": _lz4, "snappy": _snappy})
# A tag word -> the layers it names, outermost first. A word that is not here is searched for (decode).
TAGS = {
    "B64": ["b64"], "BASE64": ["b64"], "B64U": ["b64"], "B64URL": ["b64"], "UB64": ["b64"], "URLB64": ["b64"],
    "HEX": ["hex"], "H": ["hex"], "HEXSTR": ["hex"], "FRAG": ["hex"], "FRAGHEX": ["hex"], "HEXFRAG": ["hex"],
    "HB64": ["hex", "b64"], "HEXB64": ["hex", "b64"], "B64HEX": ["b64", "hex"], "B64H": ["b64", "hex"],
    "B32": ["b32"], "BASE32": ["b32"], "B85": ["b85"], "BASE85": ["b85"], "A85": ["a85"], "ASCII85": ["a85"],
    "Z85": ["z85"], "B58": ["b58"], "BASE58": ["b58"], "B91": ["b91"], "BASE91": ["b91"],
    "FRAGB64": ["b64"], "B64FRAG": ["b64"], "FRAGHB64": ["hex", "b64"], "BB64": ["b64", "b64"], "HHEX": ["hex", "hex"],
    "B64R": ["b64"], "URL": ["pct"], "PCT": ["pct"], "PERCENT": ["pct"], "URLENC": ["pct"],
    "DEC": ["dec"], "DECIMAL": ["dec"], "CHARCODES": ["dec"],
    "GZ": ["b64", "inflate"], "GZIP": ["b64", "inflate"], "GZB64": ["b64", "inflate"], "B64GZ": ["b64", "inflate"],
    "ZLIB": ["b64", "inflate"], "ZB64": ["b64", "inflate"], "DEFLATE": ["b64", "inflate"], "ZHEX": ["hex", "inflate"],
    "GZHEX": ["hex", "inflate"], "HGZ": ["hex", "inflate"],
    "REV": ["rev"], "REVERSE": ["rev"], "RB64": ["rev", "b64"], "REVB64": ["rev", "b64"], "RHEX": ["rev", "hex"],
    "REVHEX": ["rev", "hex"], "ROT13": ["rot13"], "R13": ["rot13"],
    "XOR": [], "XB64": ["b64"], "XORB64": ["b64"], "XHEX": ["hex"], "XORHEX": ["hex"],   # the key is the crib's
    "PLAIN": [], "RAW": [], "TEXT": [], "NONE": [],
    # B2 (Day 18 look-ahead): TAG_LAYERS, applied only under these words, never searched for
    "OCT": ["oct"], "OCTAL": ["oct"], "BIN": ["bin"], "BINARY": ["bin"], "QP": ["qp"], "QUOPRI": ["qp"],
    "B36": ["b36"], "BASE36": ["b36"], "ROT47": ["rot47"], "ROT18": ["rot18"],
    # Row 306 (Day 20 build): tag-only too; like GZ, a bare word carries base64 as its text layer
    "U16BE": ["b64", "u16be"], "UTF16BE": ["b64", "u16be"], "U16BEB64": ["b64", "u16be"], "UTF16BEB64": ["b64", "u16be"],
    "B64U16BE": ["b64", "u16be"], "B64UTF16BE": ["b64", "u16be"], "U16BEHEX": ["hex", "u16be"],
    "UTF16BEHEX": ["hex", "u16be"], "HEXU16BE": ["hex", "u16be"], "HEXUTF16BE": ["hex", "u16be"],
    "BZ": ["b64", "bz2"], "BZ2": ["b64", "bz2"], "BZIP2": ["b64", "bz2"], "BZB64": ["b64", "bz2"],
    "BZ2B64": ["b64", "bz2"], "B64BZ2": ["b64", "bz2"], "BZHEX": ["hex", "bz2"], "BZ2HEX": ["hex", "bz2"],
    "HEXBZ2": ["hex", "bz2"],
    "XZ": ["b64", "xz"], "LZMA": ["b64", "xz"], "XZB64": ["b64", "xz"], "B64XZ": ["b64", "xz"],
    "LZMAB64": ["b64", "xz"], "XZHEX": ["hex", "xz"], "HEXXZ": ["hex", "xz"], "LZMAHEX": ["hex", "xz"],
    # Day 30: framed compressors, complete/checksummed and bounded.  A bare format word carries Base64,
    # matching the older GZ/BZ2/XZ convention; RAW names are available for an already-binary explicit layer.
    "ZSTD": ["b64", "zstd"], "ZST": ["b64", "zstd"], "ZSTDB64": ["b64", "zstd"],
    "B64ZSTD": ["b64", "zstd"], "ZSTDHEX": ["hex", "zstd"], "HEXZSTD": ["hex", "zstd"],
    "ZSTDRAW": ["zstd"],
    "LZ4": ["b64", "lz4"], "LZ4B64": ["b64", "lz4"], "B64LZ4": ["b64", "lz4"],
    "LZ4HEX": ["hex", "lz4"], "HEXLZ4": ["hex", "lz4"], "LZ4RAW": ["lz4"],
    "SNAPPY": ["b64", "snappy"], "SNAPPYB64": ["b64", "snappy"], "B64SNAPPY": ["b64", "snappy"],
    "SNAPPYHEX": ["hex", "snappy"], "HEXSNAPPY": ["hex", "snappy"], "SNAPPYRAW": ["snappy"],
    # Day 26 build: base45 (RFC 9285; the compressed form is the COVID certificate's), base62, uuencode, yEnc, brotli
    "B45": ["b45"], "BASE45": ["b45"], "B45Z": ["b45", "inflate"], "B45ZLIB": ["b45", "inflate"],
    "B45GZ": ["b45", "inflate"], "B45INFLATE": ["b45", "inflate"], "ZB45": ["b45", "inflate"],
    "B62": ["b62"], "BASE62": ["b62"], "B62GZ": ["b62", "inflate"], "B62Z": ["b62", "inflate"],
    "UU": ["uu"], "UUE": ["uu"], "UUENCODE": ["uu"], "UUENCODED": ["uu"], "UUGZ": ["uu", "inflate"],
    "YENC": ["yenc"], "ADOBE85": ["a85"], "ADOBE": ["a85"],
    "BR": ["b64", "brotli"], "BROTLI": ["b64", "brotli"], "BRB64": ["b64", "brotli"], "B64BR": ["b64", "brotli"],
    "BROTLIB64": ["b64", "brotli"], "B64BROTLI": ["b64", "brotli"], "BRHEX": ["hex", "brotli"],
    "HEXBR": ["hex", "brotli"], "BROTLIHEX": ["hex", "brotli"], "HEXBROTLI": ["hex", "brotli"],
}


def tag_chain(tag: str):
    """The layers a tag names, or None for a tag (or a part of one) this table does not hold. A composite
    tag is read as its parts in order: `REV+B64`, `HEX_B64`, `GZ>B64`; digits after a word are dropped
    (`XOR5A`, `B64V2`).

    B-217: a composite tag this table misses (a part spelled with a separator or synonym it does not hold,
    `rev.gz`, `base64-zlib`, `GUNZIP`) is handed to lang_table.descriptor_chain, which tokenises on any
    separator and normalises synonyms. That reader only ever returns a chain of atoms descriptor.py can
    apply, and it runs ONLY here, after the hardcoded table gave None, so no known tag changes."""
    word = (tag or "").upper()
    if word in TAGS:
        return list(TAGS[word])
    chain = []
    for part in re.split(r"[+>_]", word):
        part = part if part in TAGS else re.sub(r"\d+[A-F0-9]*$", "", part)
        if part not in TAGS:
            return _lang_table_chain(tag)
        chain += TAGS[part]
    return chain


def _lang_table_chain(tag: str):
    """The B-217 composite-label fallback: lang_table.descriptor_chain(tag), or None when it is absent or the
    tag holds a token no reader knows (a new descriptor shape -- reported there as `unknown`)."""
    try:
        import lang_table
    except ImportError:
        return None
    return lang_table.descriptor_chain(tag)


# ---------------------------------------------------------------- the grammar

def plan_text(x):
    """The plan a decoded value IS, as [(plan text, transform)]: the value itself, or under one of the
    transforms a plan's first bytes fix (plan_codec.undo). Only the grammar accepts."""
    data = x.encode("latin-1", "replace") if isinstance(x, str) else bytes(x)
    out = []
    if len(data) < 8:
        return out
    for tr, raw in plan_codec.undo(data):
        t = _is_plan_bytes(raw)
        if t and all(t != p for p, _ in out):
            out.append((t, tr))
    return out


def _is_plan_bytes(raw):
    try:
        t = bytes(raw).decode("ascii")
    except UnicodeDecodeError:
        return None
    t = t.strip("\r\n\t ")
    if plan_codec.grammar_plan(t) is not None:
        return t
    if t[:1] == "{" and t[-1:] == "}":
        try:
            d = json.loads(t)
        except ValueError:
            return None
        if isinstance(d, dict) and "steps" in d and t.isprintable():     # t is ASCII: all 32 <= ord(c) < 127
            return t
    return None


def _apply(payload, chain):
    x = payload
    for name in chain:
        fn = LAYERS.get(name)
        if fn is not None:
            x = fn(x)
        else:
            try:
                x = TAG_LAYERS[name](x)      # B2: a tag-only layer that fails on this value is not its layer
            except Exception:  # noqa: BLE001
                return None
        if x is None:
            return None
    return x


def decode(tag, payload: str):
    """[(plan text, how)] for one payload: the tag's chain when it gives a plan, else every plan any chain of
    up to MAX_LAYERS layers gives (each plan once). `how` is `descriptor:<layers>|<transform>`.

    Perf (Day 27 speed build): _decode is a pure function of (tag, payload) and returns a list of tuples of
    strings, so while analyze.solve_set runs (plan_codec.memo_cache(), the reading cache's dict, which lives
    for the outermost solve_set only) its result is kept per (tag, payload) and a repeat call gets a fresh
    list of the same tuples. A specimen's payloads are decoded again by day23_fold's second reading and by
    the rewritten text's solve: on the Day 24 Time Trial 650 calls held 245 distinct payloads. Off (every
    path but analyze.solve_set) this is _decode exactly."""
    cache = plan_codec.memo_cache() if hasattr(plan_codec, "memo_cache") else None
    if cache is None or not isinstance(payload, str) or not (tag is None or isinstance(tag, str)):
        return _decode(tag, payload)
    key = ("descriptor.decode", tag, payload)
    hit = cache.get(key)
    if hit is None:
        hit = cache[key] = tuple(_decode(tag, payload))
    return list(hit)


def _decode(tag, payload: str):
    """decode() itself (see decode)."""
    if not isinstance(payload, str) or not payload or len(payload) > MAX_PAYLOAD:
        return []
    chain = tag_chain(tag) if tag else None
    if chain is not None:
        # An explicit tag is the author naming the layers (ROT13 means rot13, digits unchanged), so a
        # tagged plan is trusted as given. Only the free search below guesses rot13 and is guarded.
        applied = _apply(payload, chain)
        got = plan_text(applied) if applied is not None else []
        if got:
            return [(t, f"descriptor:{'+'.join(chain) or 'plain'}|{tr}") for t, tr in got]
        for k, name in enumerate(chain):          # Day 26: the other base62 alphabets, only under that word
            for alt in ALT_LAYERS.get(name, ()):
                ch2 = chain[:k] + [alt] + chain[k + 1:]
                applied = _apply(payload, ch2)
                got = plan_text(applied) if applied is not None else []
                if got:
                    return [(t, f"descriptor:{'+'.join(ch2)}|{tr}") for t, tr in got]
    found, level = {}, [((), payload)]
    for t, tr in plan_text(payload):
        found.setdefault(t, f"descriptor:plain|{tr}")
    for _ in range(MAX_LAYERS):
        if found:
            break
        nxt = []
        for done, x in level:
            for name, fn in LAYERS.items():
                if done and done[-1] == name and name in ("rev", "rot13"):
                    continue                     # twice is the value itself
                try:
                    y = fn(x)
                except Exception:  # noqa: BLE001 - a layer that fails on this value is not its layer
                    y = None
                if y is None or len(y) < 8 or len(y) > MAX_INFLATE:
                    continue
                for t, tr in plan_text(y):
                    found.setdefault(t, f"descriptor:{'+'.join(done + (name,))}|{tr}")
                nxt.append((done + (name,), y))
        level = nxt[:64]
    return _drop_rotation(list(found.items()))


# Row 211 (review, Script wrong_plain): the free search tries rot13 on a payload whose tag it does not
# know (ROT18 and ROT5 strip to ROT, which is not a tag, so they fall here). rot13 turns only letters, so
# a payload the author rotated with ROT18 (letters by 13, digits by 5), read by rot13, comes back with the
# right field names but digits still shifted (v=3 read as v=8), and the grammar accepts it as a wrong plain
# plan. The risk is only when rot13 is the LAST step producing the plan text (the chain ends in rot13): a
# rot13-then-base64/hex plan comes from decoded bytes, so its digits are exact. The search cannot tell
# rot13 from rot18, so a plan whose chain ends in rot13 and carries any digit is unproven and dropped; its
# fields fall to unsure or None. An explicit ROT13 tag is trusted (handled above); a letters-only plan
# keeps no digit to be wrong.
def _drop_rotation(items):
    def ends_in_rot13(how):
        chain = how.split("|", 1)[0].split(":", 1)[-1]   # e.g. 'rot13', 'rot13+b64', 'plain'
        return chain.split("+")[-1] == "rot13"
    return [(t, how) for t, how in items if not (ends_in_rot13(how) and any(c.isdigit() for c in t))]


# ---------------------------------------------------------------- one file

def comments(text: str) -> list:
    """[(tag or None, payload, rest)] of every tagged comment: `rest` is everything after the mark up to
    the end of its line, without a comment closer; `payload` is `rest` without its tag."""
    out = []
    for m in MARK.finditer(text):
        rest = m.group(2).rstrip()
        closer = CLOSER.search(rest)
        if closer and closer.start() > 0:
            rest = rest[:closer.start()]
        t = TAGGED.fullmatch(rest)
        tag, payload = (t.group(1), t.group(2)) if t else (None, rest)
        if t and tag_chain(tag) is None and not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", tag):
            tag, payload = None, rest
        out.append((tag, payload, rest))
    return out


def closer_more(line: str):
    """Where a CLOSER_MORE closer at the end of `line` starts (the blanks in front of it count as the closer),
    or None. Only the last MORE_SPAN characters are searched (review of S2): a closer is a few characters, and
    the pattern, tried from every blank of a long run of blanks, took 2.3 s more on a line that holds 16,000."""
    more = CLOSER_MORE.search(line, max(0, len(line) - MORE_SPAN))
    return len(line[:more.start()].rstrip(" \t")) if more else None


# Day 27 (review of the variants track). The comment leaders a wrapped comment's next line may begin with beyond
# LEADER: Erlang's, LaTeX's and MATLAB's `%`, Fortran's `!`, Vim's `"`, `--` doubled further, OCaml's and
# AppleScript's `(*`, Haskell's `{-`, `@rem` and m4's `dnl`. With LEADER alone a `%` comment wrapped onto its next
# line (`% <rest>`) was no continuation, and an Erlang .escript comment with no literal copy was read whole with its
# cut last value, PLAIN. Read by continued() only: decorated() joins comment lines with LEADER as before, so no
# comment it did not join is joined now.
CONT_LEADER = re.compile(r"[ \t]*(?:\#+|;+|\*+|//+|::|-{2,}|'|<!--|%+|!+|\"|\(\*|\{-|(?i:@?rem)\b|(?i:dnl)\b)?[ \t]*")
CONT_JOIN = 16           # lines joined behind a payload when a plain-word next line is tried as more of it
# Day 27 (script residuals; left open by the review of the variants track): a comment wrapped PAST A BLANK LINE.
# continued() and wrapped_proven() read the line right after the payload's, and a blank one (empty, blanks only,
# `\r` alone, or a comment leader alone: `%`, `%%`, `--`, `#`, ` *`, `REM`) is no token: a lone tagged comment
# whose payload went on after it was read whole, and its cut last value went out PLAIN in every language (`.escript`
# and `.lua` among them; staged: 658 of 1,080 such comments). They now pass over up to BLANK_SKIP such lines to the
# next one that holds anything, and read that one as before. wrapped_old() (the reading of before Day 27) does not,
# so by_descriptor asks such a cut copy's pick under one_copy_wrapped, which no accepted one_copy name answers.
BLANK_SKIP = 8
_MARKUP_TAG = re.compile(r"</?[A-Za-z][\w:.-]*(?:\s[^<>]*)?/?>")


def _blank(raw: str, lead: str = "") -> bool:
    """Whether a line holds nothing but blanks, or a comment leader alone (CONT_LEADER, or the tag line's own)."""
    s = raw.strip()
    return not s or CONT_LEADER.fullmatch(s) is not None or (bool(lead) and s == lead)


def next_line(text: str, at: int, lead: str = ""):
    """NEXT_LINE.match(text, at) past blank lines (_blank): the first of the next BLANK_SKIP + 1 lines that holds
    anything, or the last one looked at, or None at the end of the text."""
    m = NEXT_LINE.match(text, at)
    for _ in range(BLANK_SKIP):
        if not m or not _blank(m.group(1), lead):
            return m
        m = NEXT_LINE.match(text, m.end())
    return m


_HEX_CHARS = frozenset("0123456789abcdefABCDEF")
_B32_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_")
# The punctuation of the 85-character alphabets (ascii85 `!`..`u`, RFC 1924's base85, Z85): a payload whose
# punctuation is all of one of them may hold the rest of that alphabet in its next line.
_A85_CHARS = frozenset(chr(c) for c in range(33, 118))
_B85_CHARS = frozenset("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~")
_Z85_CHARS = frozenset("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")


def _alphabet(payload: str) -> frozenset:
    """The characters more of `payload` may hold: its own, and the whole of every encoding alphabet (hex, base32,
    base64 in either form, and the 85-character ones by its punctuation) its characters all belong to. A
    continuation line holds characters its first line lacks (Day 27: `y` in a Day 23 .php LYR-b64_b64_b64 payload,
    `9` in a .lua one), and the old test, the first line's own characters only, did not see it."""
    own = set(payload or "")
    core = {c for c in own if c.isalnum()}
    out = set(own)
    narrow = [alpha for alpha in (_HEX_CHARS, _B32_CHARS) if core <= alpha]
    for alpha in narrow or [_B64_CHARS]:                     # the narrowest alphabet(s) that hold every letter and digit
        if core <= alpha:
            out |= alpha
    if own - _B64_CHARS - set("=.:,|;_ \t"):                 # punctuation that is no separator of pieces
        for alpha in (_A85_CHARS, _B85_CHARS, _Z85_CHARS):
            if own <= alpha:
                out |= alpha
    return frozenset(out)


def _closer_start(line: str):
    """Where CLOSER.search(line) would start a match (the closer at the line's end, with the blanks in front of it),
    or None: searched in the last 12 characters (a closer is at most 5) and widened over the blanks by index, since
    CLOSER.search over a whole line backtracks once for every blank of a long run of them."""
    m = CLOSER.search(line, max(0, len(line) - 12))
    if not m:
        return None
    s = m.start()
    while s > 0 and line[s - 1] in " \t":
        s -= 1
    return s


def _closer_off(line: str) -> str:
    """A line without a closer behind it (CLOSER, else CLOSER_MORE)."""
    at = _closer_start(line)
    if at is not None:
        return line[:at].rstrip()
    # Review of S2: the closers reading_ex now takes off a payload end a wrapped comment too. A docstring,
    # an XML element or a template comment that went on in its next line (`<rest>'''`, `<rest></note>`,
    # `<rest> #}`) was not seen as continued, and its first line was answered alone with its cut value.
    try:
        more = closer_more(line)
    except Exception:  # noqa: BLE001 - a look that fails takes nothing off: the line is read as before the review
        more = None
    return line[:more] if more is not None else line


_RUN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_.:,%-")


def _trimmed(w: str) -> str:
    """`w` without the characters outside _RUN_CHARS at its two ends (by index: no regex that backtracks)."""
    i, j = 0, len(w)
    while i < j and w[i] not in _RUN_CHARS:
        i += 1
    while j > i and w[j - 1] not in _RUN_CHARS:
        j -= 1
    return w[i:j]


def _bodies(raw: str, lead: str = "") -> list:
    """The ways a comment line may read without its leader and a closer: with LEADER (the reading of before Day
    27, first), with CONT_LEADER, without `lead` (what stands before the marker on the tag's own line), and, for a
    line whose only word with a letter or digit in it is one run, that run (a decorated leader `#: `, a line
    continuation behind it `<rest> \\`, punctuation around it)."""
    out = []
    cands = [raw[LEADER.match(raw).end():].rstrip(), raw[CONT_LEADER.match(raw).end():].rstrip()]
    st = raw.lstrip(" \t")
    if lead and st.startswith(lead):
        cands.append(st[len(lead):].strip())
    for c in cands:
        c = _closer_off(c)
        if c not in out:
            out.append(c)
    for c in [raw] + cands:
        runs = [w for w in re.split(r"[\s\"'`\\(){}\[\];]+", c) if re.search(r"[A-Za-z0-9]", w)]
        if len(runs) != 1 or "=" in c.replace(runs[0], "", 1):    # never a name assigned (`descriptor_x = ""`)
            continue
        w = _trimmed(runs[0])
        for x in (w, re.sub(r"^(?:/{2,}|::?|-{2,}|%+)", "", w)):   # with a leader glued to it, and without
            if x and x not in out:
                out.append(x)
    return out


def _token_of(line: str, alphabet) -> bool:
    """Whether a line (leader and closer taken off) is one unbroken token of a payload's alphabet, two or more
    characters, in the alphabets a line of code is not written in (base64, hex, pieces, percent text, a decimal
    list): a payload in base85 or base91 holds `(`, `;` and `=`, and `declare(strict_types=1);` would read as more
    of it."""
    return len(line) >= 2 and set(line) <= alphabet and re.fullmatch(r"[A-Za-z0-9+/=_.:,%-]+", line) is not None


def continued(text: str, end: int, payload: str, lead: str = "", rejoin=None, core=None) -> bool:
    """Whether the line after a tagged comment (its line ends at `end`) reads as more of its payload: a
    comment wrapped at a column, the way base64 is. That line, without a comment leader and a closer (CLOSER,
    else CLOSER_MORE), is then one unbroken token of the payload's characters, two or more, that is no
    plain word (it holds a digit, `+`, `/`, `=`, or a capital behind a small letter). The comment's own line
    end proves nothing then (review of 2026-10-08: such a comment alone was answered with its cut last value).

    Day 27 (review of the variants track), each only ever turning a False into a True: the line may begin with
    CONT_LEADER's leaders and with `lead` (what stands before the marker on the tag's own line); its characters
    may be any of the encoding alphabet of `core` (the payload without its tag; default `payload`), not only the
    first line's own (`_alphabet`); and a plain word (a short base32 or base64 tail holds no digit) counts when
    `rejoin(more)` says the payload with it, and the lines of its kind after it, decodes to another plan.

    Day 27 (script residuals): the next line is the next one that holds anything (next_line: blank lines and lines
    of a comment leader alone are passed over), here and between the lines joined behind a plain word. A line
    reached past a blank one that is a markup tag alone (`</script>`, the end of an .aspx script block whose
    literal line is empty) is no payload: read as its one run it is `/script`, a base64 token."""
    m = next_line(text, end, lead)
    if not m:
        return False
    first = NEXT_LINE.match(text, end)
    if (first is None or m.start() != first.start()) and _MARKUP_TAG.fullmatch(m.group(1).strip()):
        return False
    old = set(payload) | {"="}
    alphabet = old | _alphabet(core if core else payload)
    lines = _bodies(m.group(1), lead)
    if any(_token_of(line, old) and re.search(r"[0-9+/=]|[a-z][A-Z]", line) for line in lines[:1]):
        return True                              # the reading of before Day 27, exactly
    for line in lines:
        if not _token_of(line, alphabet):
            continue
        if re.search(r"[0-9+/=]|[a-z][A-Z]", line):
            return True
        if rejoin is None:
            continue
        more, at = line, m.end()
        for _ in range(CONT_JOIN):
            try:
                if rejoin(more):
                    return True
            except Exception:  # noqa: BLE001 - a decode that fails says nothing
                break
            nxt = next_line(text, at, lead)
            if not nxt:
                break
            body = next((b for b in _bodies(nxt.group(1), lead) if _token_of(b, alphabet)), None)
            if body is None:
                break
            more, at = more + body, nxt.end()
    return False


def _lead_of(text: str, at: int) -> str:
    """What stands before position `at` on its line, blanks taken off (a comment's leader: `%`, `REM`, `//`)."""
    return text[text.rfind("\n", 0, at) + 1:at].strip()


def _rejoin_with(tag, payload):
    """rejoin() for continued(): whether `payload` with `more` behind it decodes to one plan, and another than
    `payload` alone gives, by the very layers the payload alone decoded by (decode's `how`: the tag's chain or the
    free search's), else, for a payload that alone decodes to nothing, the tag's own chain. The joined text is never
    sent through the free search of every chain: on a long joined text that took seconds a try. A payload read as it
    stands (descriptor:plain, the PLAIN tag or an untagged plan text) proves nothing so: any text behind it
    lengthens its last value; nor does a line that repeats the payload's own end (a whole payload with its tail
    again on the next line, beside a whole literal that agrees, is whole: tests/test_script_review.py)."""
    state = {}

    def layers():
        if "chain" not in state:
            head = decode(tag, payload) if payload else []
            specs = {how.split("|", 1)[0].split(":", 1)[-1] for _t, how in head}
            state["heads"] = [t for t, _h in head]
            if "plain" in specs or len(specs) > 1:
                state["chain"] = None            # read as it stands, or by two chains: nothing to join by
            elif specs:
                state["chain"] = next(iter(specs)).split("+")
            else:
                try:
                    known = tag_chain(tag) if tag else None
                except Exception:  # noqa: BLE001
                    known = None
                state["chain"] = known or None   # [] (PLAIN) and None: nothing to join by
        return state["chain"]

    def rejoin(more):
        if not payload or not more or len(payload) + len(more) > MAX_PAYLOAD or payload.endswith(more):
            return False                         # a line that repeats the payload's own end adds nothing to it
        chain = layers()
        if not chain:
            return False
        applied = _apply(payload + more, chain)
        got = [t for t, _tr in plan_text(applied)] if applied is not None else []
        return len(got) == 1 and got[0] not in state["heads"]
    return rejoin


def _tagged_comments(text: str) -> list:
    """[(mark match, tag, payload, the text continued() was handed before Day 27)] of every tagged comment (MARK,
    then SOFT_MARK)."""
    marks = list(MARK.finditer(text))
    parsed = comments(text) if marks else []
    out = [(m, parsed[i][0] if i < len(parsed) else None, parsed[i][1] if i < len(parsed) else None, m.group(2))
           for i, m in enumerate(marks)]
    out += [(m, m.group(1), m.group(2), m.group(2)) for m in (SOFT_MARK.finditer(text) if "HUNTRESS" in text else ())]
    return out


def wrapped(text: str) -> bool:
    """Whether any tagged comment of the file goes on in its next line (continued)."""
    for m, tag, pl, given in _tagged_comments(text):
        if continued(text, m.end(), given, _lead_of(text, m.start()), _rejoin_with(tag, pl) if pl else None, pl or None):
            return True
    return False


def wrapped_old(text: str) -> bool:
    """wrapped() as it read before Day 27 (LEADER, the first line's own characters, no rejoin): by_descriptor keeps
    such a doubt's one_copy key as it was unless wrapped_proven() shows the wrap (AutoHotkey v1's `#NoEnv` behind a
    base64 comment reads as more of it, and the comment is whole)."""
    for m, _tag, _pl, given in _tagged_comments(text):
        nxt = NEXT_LINE.match(text, m.end())
        if nxt:
            line = _bodies(nxt.group(1))[0]
            if _token_of(line, set(given) | {"="}) and re.search(r"[0-9+/=]|[a-z][A-Z]", line):
                return True
    return False


def wrapped_proven(text: str) -> bool:
    """Whether a tagged comment of the file is SHOWN to go on in its next lines: its payload with them behind it
    (each without a leader and a closer, joined) decodes to one plan, and another than the payload alone gives.
    Day 27 (script residuals): blank lines between them are passed over (next_line)."""
    for m, tag, pl, _given in _tagged_comments(text):
        if not pl:
            continue
        rejoin, lead = _rejoin_with(tag, pl), _lead_of(text, m.start())
        more, at = "", m.end()
        for _ in range(CONT_JOIN):
            nxt = next_line(text, at, lead)
            if not nxt:
                break
            bodies = [b for b in _bodies(nxt.group(1), lead) if b and not re.search(r"\s", b)]
            if not bodies:
                break
            try:
                if any(rejoin(more + b) for b in bodies):
                    return True
            except Exception:  # noqa: BLE001 - a decode that fails shows nothing
                break
            more, at = more + bodies[0], nxt.end()
    return False


def _joined_elsewhere(text: str, name: str, a: int) -> bool:
    """Whether the variable `name`, assigned the literal that starts at `a`, is used somewhere else with more
    text joined on: `x.concat("..")`, `[x, ".."].join("")`, `"${x}.."`, `x ".."`."""
    own = text.rfind("\n", 0, a) + 1
    for m in re.finditer(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", text):
        if own <= m.start() < a:
            continue                             # the name the literal is assigned to
        line = text.rfind("\n", 0, m.start()) + 1
        if ADDS_AFTER.match(text, m.end()) or ADDS_BEFORE.search(text[max(line, m.start() - 8):m.start()]):
            return True
        behind = text[m.end():m.end() + 1]
        if text.count('"', line, m.start()) % 2 and behind not in ('"', "") and not behind.isspace():
            return True                          # "$x.." inside a double-quoted string: text right behind it
    return False


def soft_comments(text: str) -> list:
    """[(tag, payload)] of the lines SOFT_MARK finds whose tag is a known one."""
    if "HUNTRESS" not in text:
        return []
    return [(m.group(1), m.group(2)) for m in SOFT_MARK.finditer(text) if tag_chain(m.group(1)) is not None]


def _colon_body(m) -> str:
    """The value of a `name : ".."` literal: AppleScript writes a backslash as two."""
    body = m.group("body")
    if "\\" in body and re.fullmatch(r'(?:[^\\]|\\[\\"])*', body):
        body = re.sub(r'\\([\\"])', r"\1", body)
    return body


def _colon_copy(body: str, marks: list) -> bool:
    """Whether a `name : ".."` literal is a second copy of a tagged comment's payload.

    `name : ".."` is AppleScript's literal (`property descriptor_x : ".."`), and it is also a YAML key, a
    ternary's second arm, a `case` label and a URL after a scheme. It is taken only as what the fixtures
    write: no blank in it (a payload has none), the file holds a tagged comment, and that comment's payload,
    as far as its line gives it, is the START of this literal (all of it, or its first part when the comment
    is wrapped). A shorter literal, another text, or a file with no tagged comment is not read by this form
    at all, as before 2026-10-13 (the review of that day: a prose `descriptor_note:` line, a ternary, a
    label, a scheme-less URL and a half payload each emptied thirty specimens)."""
    if not body or " " in body or "\t" in body:
        return False
    head = body[:MIN_PAYLOAD]
    for rest in marks:
        at = rest.find(head)
        token = rest[at:].split()[0] if at >= 0 and rest[at:].split() else ""
        if token and body.startswith(token):
            return True
    return False


def literals(text: str) -> list:
    """[(payload, whole)] of every `descriptor_<id>` assigned a literal of MIN_PAYLOAD characters or more.
    `whole` says the literal is all of the variable's value as far as the file shows: it is the whole
    right-hand side of its assignment (WHOLE_POST), the name is assigned one such literal only, and nothing
    is joined to the literal or to its variable anywhere (plan_codec.glued: an operator beside it,
    `x += ..`, `x = x & ..`, a use of x in a join; _joined_elsewhere: a call that adds, a shared list, an
    interpolation). Review of 2026-10-08: `x = "<cut>"` followed by `x += "<rest>"` was read as whole."""
    found = [m for m in LITERAL.finditer(text) if len(m.group("body")) >= MIN_PAYLOAD]
    if any(m.group("op") == ":" for m in found):
        marks = [mm.group(2) for mm in MARK.finditer(text)]
        found = [m for m in found if m.group("op") != ":" or _colon_copy(_colon_body(m), marks)]
    names = [m.group(1) for m in found]
    grown, out = None, []
    for m in found:
        whole = WHOLE_POST.fullmatch(m.group("post")) is not None and names.count(m.group(1)) == 1 \
            and not plan_codec.NEXT_JOINS.match(text, m.end()) \
            and not INTERP_ONLY.fullmatch(m.group("body"))          # the next line goes on with `+ ".."`
        if whole:
            try:
                if grown is None:
                    grown = plan_codec._grown(text)
                a = m.start("q")
                whole = not plan_codec.glued(text, a, m.end("body") + 1, grown) \
                    and not _joined_elsewhere(text, "descriptor_" + m.group(1), a)
            except Exception:  # noqa: BLE001 - a check that fails proves nothing: not whole
                whole = False
        body = _colon_body(m) if m.group("op") == ":" else _raw_body(text, m)
        out.append((body, whole))
    return out


# ---------------------------------------------------------------- the SPLIT container (row 354, Day 19 build)
#
# Day 18's .gs family moved the tagged copy out of the comment: a bare marker `// HUNTRESS_ANALYSIS_V1:SPLIT`
# (no payload), the tagged copy `<TAG>-<payload>` as ONE value joined from string pieces and named
# `HUNTRESS_ANALYSIS_V1_SPLIT_<id>`, and the bare copy a second joined value cut at other places. The marker
# made reading_ex refuse the file (a tagged comment that does not decode), and the whole family was None.
# split_values() reads such values in the idioms of the Day 19 look-ahead's table (splitlangs19.py: an array
# join, the language's concatenation, one literal, a value made of two such constants), and reading_ex treats
# the tagged value as the comment's copy and a bare value equal to its payload as the literal's: the two must
# agree as before. A value whose text this reader does not know (a template literal, a comment inside the
# array, an escape, a call it does not list, pieces stored reversed) is not read at all.
SPLIT_WORDS = ("SPLIT", "WRAPPED", "REVERSED")
# The marker: the comment's whole rest is the word, or the word and a short id (`SPLIT:<id>`).
SPLIT_REST = re.compile(r"(%s)(?:[ \t]*[:=-][ \t]*[A-Za-z0-9_]{1,16})?" % "|".join(SPLIT_WORDS))
SPLIT_NAME = re.compile(r"HUNTRESS[_-]?ANALYSIS[_-]?V\d+[_-]?SPLIT(?:[_-]|$)", re.I)
SPLIT_IDENT = re.compile(r"(?<![\w])HUNTRESS[_-]?ANALYSIS[_-]?V\d+[_-]?SPLIT(?:[_-][\w-]*)?(?![\w-])", re.I)
# Whether the split reader looks at a file at all: a SPLIT name, or a quoted value that starts `<TAG>-`.
SPLIT_HINT = re.compile(r"HUNTRESS[_-]?ANALYSIS[_-]?V\d+[_-]?SPLIT|[\"']([A-Z][A-Z0-9_+]{0,31})-[A-Za-z0-9+/=._:-]{8}")
TAGGED_VALUE = re.compile(r"([A-Z][A-Z0-9_+]{0,31})-(\S+)")
ASSIGN = re.compile(r"(?<![\w$.])(\$?(?:script:|global:)?[A-Za-z_]\w*)(\[\])?"
                    r"(?:[ \t]*:[ \t]*[A-Za-z_][\w.<>\[\], ]{0,60}?)?[ \t]*(=(?![=>~])|:=|<-|\bto\b)[ \t]*")
# Where a value is read (review of the Day 19 build): an assignment that BEGINS a line of code, behind at most
# three words (`const`, `local`, `my`, `Dim`, a type) and, once, a short statement before a `:` or `;` on that
# line (VBScript's `Dim N : N = ..`). A name=value pair inside a string, a URL or a comment line is no head.
HEAD_PLAIN = re.compile(r"(?m)^[ \t]*(?:[A-Za-z_]\w*[ \t]+){0,3}" + ASSIGN.pattern)
HEAD_AFTER = re.compile(r"(?m)^[ \t]*(?:[\w$]+[ \t]+){0,3}[\w$]+[ \t]*[:;][ \t]*(?:[A-Za-z_]\w*[ \t]+){0,3}"
                        + ASSIGN.pattern)
TCL_SET = re.compile(r"(?m)^[ \t]*set[ \t]+([A-Za-z_]\w*)[ \t]+(?=[\[\"{])")
SPLIT_SCAN = 1 << 20          # characters of a file the split reader looks at
SPLIT_RHS = 200_000           # characters of one right-hand side
SPLIT_WORK = 4                # all right-hand sides together read at most this many times the file's length
_Q, _E, _V = "\x01", "\x02", "\x03"
_L = "%s(?:,%s)*,?" % (_Q, _Q)          # a comma list of pieces
_A = "%s+" % _Q                          # pieces side by side (shell, Tcl)
def _form(p: str) -> str:
    """A form below with its placeholders <L> (a comma list of pieces), <A> (pieces side by side), <Q> (one
    piece), <E> (an empty literal) and <V> (a value's name) put in, anchored at the end."""
    return (p.replace("<L>", _L).replace("<A>", _A).replace("<Q>", _Q).replace("<E>", _E).replace("<V>", _V)
            .replace("<N>", r"\$?[A-Za-z_]\w*") + "$")


# The joins, written over the right-hand side with its blanks taken out, every non-empty quoted piece as <Q> and
# every empty one (the separator) as <E>. Each joins its pieces with nothing between them.
JOIN_FORMS = [re.compile(_form(p)) for p in (
    r"\[<L>\]\.join(?:\(<E>?\)|<E>)?",             # JavaScript, Apps Script, TypeScript, CoffeeScript, Ruby, Groovy, Dart, Nim
    r"<E>\.join\(\[<L>\]\)", r"<E>\.join\(\(<L>\)\)",  # Python
    r"-join@\(<L>\)", r"@\(<L>\)-join<E>",           # PowerShell
    r"implode\(<E>,\[<L>\]\)", r"implode\(<E>,array\(<L>\)\)",
    r"table\.concat\(\{<L>\}\)",                 # Lua
    r"join\(<E>,\(<L>\)\)", r"join\(<E>,<L>\)",        # Perl
    r"Join\(Array\(<L>\),<E>\)",                   # VBScript
    r"listOf\(<L>\)\.joinToString\(<E>\)",         # Kotlin
    r"[Ss]tring\.Join\(<E>,new(?:string)?\[\]\{<L>\}\)",   # C#
    r"strings\.Join\(\[\]string\{<L>\},<E>\)",     # Go
    r"\[<L>\]\.joined\(\)",                      # Swift
    r"paste0?\(c\(<L>\),collapse=<E>\)",           # R
    r"join\(\[<L>\]\)", r"join\(\[<L>\],<E>\)",      # Julia
    r"\[join\[list<A>\]<E>\]",                     # Tcl
    r"Enum\.join\(\[<L>\]\)", r"Enum\.join\(\[<L>\],<E>\)",   # Elixir
    r"StrJoin\(\[<L>\]\)",                       # AutoHotkey
    r"\(\{<L>\}astext\)",                        # AppleScript
    r"<E>(?:\.concat\(<L>\))+",                    # JavaScript "".concat(..), and "".concat(..).concat(..)
    # Day 20 (row 372 a): more join idioms a SPLIT family may use, each ordering its pieces as written. `.join``
    # (a tagged template with an empty template) is read by the first form above, whose `<E>` branch takes the
    # empty template _tokens leaves as a separator.
    # The Day 20 speed build (row 388 a): a reducer is read only when it is the accumulator first and the item
    # second under the reducer's OWN two names (`(acc,s)=>acc+s`, `function(a,b){return a+b}`, `a.concat(b)`);
    # `(a,b)=>b+a` (the pieces reversed), `a+c`, `a+b.x()`, a non-empty initial value and `.reduceRight` are not.
    # `Array.of(..).join()` with no separator joins with commas in JavaScript, its only language: not read.
    r"\[<L>\]\.reduce\(\((<N>),(?!\1\))(<N>)\)=>(?:\1\+\2|\1\.concat\(\2\))(?:,<E>)?\)",   # [..].reduce((a,b)=>a+b)
    r"\[<L>\]\.reduce\(function\((<N>),(?!\1\))(<N>)\)\{return(?:\1\+\2|\1\.concat\(\2\));?\}(?:,<E>)?\)",
    r"Array\.of\(<L>\)\.join(?:\(<E>\)|<E>)",       # Array.of(..).join("") and Array.of(..).join``  (JavaScript)
    r"<Q>(?:\.concat\(<L>\))+",                     # "a".concat("b","c"), a String.prototype.concat chain
    r"String\.prototype\.concat\.call\(<E>,<L>\)",   # String.prototype.concat.call("", ..)
    r"String\.prototype\.concat\.apply\(<E>,\[<L>\]\)", r"<E>\.concat\.apply\(<E>,\[<L>\]\)",
    r"<E>\.concat\(\.\.\.\[<L>\]\)",               # "".concat(...[..])
    r"<Q>(?:(?:\+|\.\.|\.|&|<>)<Q>)*",             # one literal, or pieces joined by the language's operator
    r"<Q><Q>+",                                    # a shell's pieces side by side
    r"paste0\(<L>\)", r"\[stringcat<A>\]",         # R, Tcl
)]
ARRAY_FORM = re.compile(r"\[%s\]$" % _L)                       # AutoIt: Local $parts[] = [..]
ARRAY_JOIN = [re.compile(_form(p)) for p in (
    r"_ArrayToString\(<V>,<E>\)", r"<V>\.join\(<E>?\)")]
VAR_JOIN = [re.compile(_form(p)) for p in (
    r"<V>(?:(?:\+|\.\.|\.|&|<>)<V>)+", r"paste0\(<V>(?:,<V>)+\)", r"\[stringcat<V>+\]", r"<V><V>+")]
# The Day 19 look-ahead's B4: three more containers, each read ONLY under the marker word that names it, and on the
# same agreement check (the tagged value and a bare copy equal to its payload). One piece each, nothing around it.
#   WRAPPED   the value is base64 of its text: atob("..") (JavaScript), base64.b64decode("..").decode() (Python)
#   REVERSED  the value is its text reversed: "..".split("").reverse().join(""), ".."[::-1]
#   SPLIT     the value as character codes: String.fromCharCode(118, 61, ..), bytes([118, 61, ..]).decode()
MARKED_FORMS = {
    "WRAPPED": [re.compile(_form(p)) for p in (r"atob\(<Q>\)", r"base64\.b64decode\(<Q>\)\.decode\(\)")],
    "REVERSED": [re.compile(_form(p)) for p in (r"<Q>\.split\(<E>\)\.reverse\(\)\.join\(<E>\)", r"<Q>\[::-1\]")],
}
CHAR_CODES = [re.compile(p) for p in (r"String\.fromCharCode\((\d{1,3}(?:,\d{1,3})*)\)$",
                                      r"bytes\(\[(\d{1,3}(?:,\d{1,3})*)\]\)\.decode\(\)$")]
# The Day 19 look-ahead's numbered-chunk map (B4's last container, the Day 20 build), read ONLY under the SPLIT
# marker word and on the same agreement check: the tagged copy as an object of numbered pieces in any order,
# `N = {3: "..", 0: "..", ..}`, and the value that joins them by their numbers. The numbers must be distinct
# whole numbers running 0 to n-1 or 1 to n with no hole (a missing piece is a missing part of the text), and the
# join one of the forms below, each of which orders by the number (JavaScript's Object.values and Object.keys
# give integer keys in ascending order; a .sort() with no comparator would order 10 before 2 and is not read).
CHUNK_MAP = re.compile(r"\{(\d{1,4}):%s(?:,(\d{1,4}):%s)*,?\}$" % (_Q, _Q))
CHUNK_KEYS = re.compile(r"[{,](\d{1,4}):%s" % _Q)
CHUNK_JOIN = [re.compile(_form(p)) for p in (
    r"Object\.keys\(<V>\)\.sort\(\(a,b\)=>a-b\)\.map\(k=><V>\[k\]\)\.join\(<E>\)",     # the look-ahead's shape
    r"Object\.keys\(<V>\)\.sort\(\(a,b\)=>Number\(a\)-Number\(b\)\)\.map\(k=><V>\[k\]\)\.join\(<E>\)",
    r"Object\.keys\(<V>\)\.map\(k=><V>\[k\]\)\.join\(<E>\)",
    r"Object\.values\(<V>\)\.join\(<E>\)",
    r"<E>\.join\(vfor_,vinsorted\(<V>\.items\(\)\)\)", r"<E>\.join\(vfork,vinsorted\(<V>\.items\(\)\)\)",
    r"<E>\.join\(<V>\[k\]forkinsorted\(<V>\)\)", r"<E>\.join\(<V>\[i\]foriinsorted\(<V>\)\)",
)]


def _chunk_map(skel: str, pieces: list):
    """The text of a numbered-chunk map's pieces in the order of their numbers, or None."""
    if not CHUNK_MAP.match(skel):
        return None
    found = CHUNK_KEYS.findall(skel)
    if any(len(k) > 1 and k[0] == "0" for k in found):
        return None                              # 010 is the octal 8 in sloppy-mode JavaScript: no reading
    keys = [int(k) for k in found]
    if len(keys) != len(pieces) or len(keys) < 2 or sorted(keys) not in (list(range(len(keys))), list(range(1, len(keys) + 1))):
        return None
    return "".join(p for _, p in sorted(zip(keys, pieces)))


def _marked(word: str, piece: str):
    """The text of a WRAPPED or REVERSED value of one piece, or None when it is no such value."""
    if word == "REVERSED":
        return piece[::-1]
    try:
        t = base64.b64decode(piece, validate=True).decode("ascii")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return t if t and all(32 < ord(c) < 127 for c in t) else None


def _codes(skel: str):
    """The text of a SPLIT value written as character codes, or None."""
    for f in CHAR_CODES:
        m = f.match(skel)
        if m:
            ns = [int(x) for x in m.group(1).split(",")]
            return "".join(map(chr, ns)) if all(32 < n < 127 for n in ns) else None
    return None


_IDENT = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$?(?:script:)?([A-Za-z_]\w*)")

# Text that is no live code (review of the Day 19 build: a commented-out older pair of copies was read as the
# answer). Each opener masks to its closer, or to the end of the file where it does not close (`ends`): a mask
# too wide only leaves a value unread. (opener regex, closer, masks to the end when open, extensions or None)
DEAD = [
    (r"/\*", r"\*/", True, None), (r"<!--", r"-->", True, None), (r"<#", r"#>", True, None),
    (r"--\[(=*)\[", None, True, None),                                   # Lua --[[ ]] / --[==[ ]==]
    (r'"""', r'"""', True, None), (r"'''", r"'''", True, None),         # Python, Elixir, Kotlin, Swift, Julia ...
    (r"(?m)^=begin\b", r"(?m)^=end\b", True, None),                      # Ruby
    (r"(?m)^=[a-z]\w*", r"(?m)^=cut\b", True, None),                     # Perl POD
    (r"(?im)^[ \t]*#c(?:s|omments-start)\b", r"(?im)^[ \t]*#c(?:e|omments-end)\b", True, None),   # AutoIt
    (r'(?m)@"[ \t]*$', r'(?m)^"@', True, None), (r"(?m)@'[ \t]*$", r"(?m)^'@", True, None),       # here-strings
    (r"<<<?[-~]?[ \t]*([\"']?)([A-Z_][A-Z0-9_]*)\1(?![\w])", None, False, None),   # heredocs (shell, Ruby, Perl, PHP)
    (r"`", r"`", True, ("js", "mjs", "cjs", "jsx", "ts", "tsx", "gs", "jse", "go", "coffee")),
    (r"###", r"###", True, ("coffee",)), (r"#=", r"=#", False, ("jl",)), (r"#\[", r"\]#", False, ("nim",)),
    (r"\(\*", r"\*\)", False, ("applescript",)), (r"\[(=*)\[", None, False, ("lua",)),
]
_DEAD = [(re.compile(o), re.compile(c) if c else None, e, x) for o, c, e, x in DEAD]


def live_code(text: str, ext=None) -> str:
    """`text` with every comment block, multi-line string and heredoc above blanked (line ends kept), so that
    positions stay the same. Line comments are not blanked: a value is read only where a line of code begins.
    Linear in the file: each opener and each fixed closer is searched for again only past its last match."""
    ext = (ext or "").lower().lstrip(".")
    rules = [(o, c, e) for o, c, e, x in _DEAD if x is None or ext in x]
    nxt = [o.search(text) for o, _, _ in rules]
    closed_at = {}                              # a closer's pattern: where its last search began, and its match
    alone = None                                # a heredoc's word: the line starts and ends where it stands alone
    out, i, n = [], 0, len(text)
    while i < n:
        best = None
        for r, (o, c, e) in enumerate(rules):
            if nxt[r] is not None and nxt[r].start() < i:
                nxt[r] = o.search(text, i)
            if nxt[r] is not None and (best is None or nxt[r].start() < best[0].start()):
                best = (nxt[r], c, e)
        if best is None:
            break
        m, c, e = best
        if c is None and m.re.pattern.startswith("<<"):                 # a heredoc: to the line of its word alone
            if alone is None:
                alone = {}
                for w in re.finditer(r"(?m)^[ \t]*([A-Z_][A-Z0-9_]*)[ \t]*$", text):
                    alone.setdefault(w.group(1), []).append(w.end())
            ends = alone.get(m.group(2), [])
            at = bisect.bisect_right(ends, m.end())
            end = ends[at] if at < len(ends) else None
        else:
            if c is None:                                                 # a Lua long bracket
                c = re.compile(r"\]%s\]" % re.escape(m.group(1)))
            key = c.pattern
            last = closed_at.get(key)
            if last is not None and last[0] <= m.end() and (last[1] is None or last[1].start() >= m.end()):
                k = last[1]
            else:
                k = c.search(text, m.end())
                closed_at[key] = (m.end(), k)
            end = k.end() if k else (n if e else None)
        if end is None:
            out.append(text[i:m.end()])
            i = m.end()
            continue
        if m.group(0).startswith("`") and end == m.end() + 1 and text[m.end():end] == "`":
            out.append(text[i:end])              # an empty template `` holds no material: keep it (a `.join``` sep)
        else:
            out.append(text[i:m.start()])
            out.append(re.sub(r"[^\n]", " ", text[m.start():end]))
        i = end
    out.append(text[i:])
    return "".join(out)


_JOINISH = re.compile(r"(?i)(?:join|concat|\bcat\b|paste|implode|format|sprintf|strcat|append|insert|push|extend|"
                      r"replace|revers|sort|splice|unshift|shift|substr|slice|\b(?:left|right|mid)\s*\(|split|"
                      r"reduce|\bchr\s*\(|fromcharcode|decode|encode|atob|btoa|[+&~]|\.\.|<>)")


USE_SPAN = 512                # characters on each side of a mention that _whole_use looks at


def _whole_use(text: str, s: int, e: int) -> bool:
    """Whether the mention text[s:e] of a value's name uses the value whole (`descriptor: N`, `return N`,
    `d.Add "descriptor", N`, `"${N}"`), and not as a part of another value, a value it changes, or an
    operand of anything (`N + tail()`, `N[1] = ..`, `N.reverse()`, `[N, t].join("")`, `"$N/x"`).

    A name in quotes is whole only as an interpolation (`"${N}"`, `"$N"`): the quoted bare name (`"N"`, `'N'`)
    is the name as a string, which reflection assigns through (`globals()["N"] = ..`,
    `Object.defineProperty(globalThis, "N", ..)`), so it is never a whole use (review of the Day 19 build)."""
    if 0 < s and e < len(text) and text[s - 1] == '"' and text[e] == '"' and text[s] == "$":
        s, e = s - 1, e + 1                                              # "${N}": the string is the value
    elif (s > 0 and text[s - 1] not in " \t\r\n([{=,:>") or (e < len(text) and text[e] not in " \t\r\n)]};,"):
        return False
    ls, le = text.rfind("\n", max(0, s - USE_SPAN), s) + 1, text.find("\n", e, e + USE_SPAN)
    ls, le = max(ls, s - USE_SPAN), min(len(text), e + USE_SPAN) if le < 0 else le
    before, after = text[ls:s].rstrip(" \t"), text[e:le].lstrip(" \t")
    if before[-1:] and before[-1] in "+&~|*/%^.-" or before.endswith(("<>", "<<")):
        return False
    if after[:1] and after[0] in "+&~|*/%^.[(-=$\"'" or after.startswith(("<>", "<<")) or after[:1].isalnum():
        return False
    if len(re.findall(r"%s", text[ls:le])) > 1:
        return False                                                     # printf '%s%s' .. N ..: a join
    # the innermost bracket around the mention, on its line: no join, concatenation or call that changes text
    depth, j, lo = 0, s - 1, ls
    while j >= lo:
        c = text[j]
        if c in ")]}":
            depth += 1
        elif c in "([{":
            if not depth:
                break
            depth -= 1
        j -= 1
    if j < lo:
        return _JOINISH.search(text[ls:s] + " " + text[e:le]) is None
    depth, k, hi = 0, e, min(len(text), e + USE_SPAN)
    while k < hi:
        c = text[k]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if not depth:
                break
            depth -= 1
        k += 1
    tail_end = text.find("\n", k, k + USE_SPAN)
    tail_end = min(len(text), k + USE_SPAN) if tail_end < 0 else tail_end
    head_start = max(text.rfind("\n", max(0, j - USE_SPAN), j) + 1, j - USE_SPAN)
    around = text[head_start:s] + " " + text[e:tail_end]
    return _JOINISH.search(around) is None


MENTION = re.compile(r"(?<![\w$])(?:\$\{([A-Za-z_]\w*)\}|\$?(?:script:)?([A-Za-z_]\w*))")
GROWN_AT = re.compile(r"[ \t]*(?:\+=|\.=|&=|\.\.=|<<|\.(?:append|push|concat|extend|insert)\b)")
MAX_USES = 64                 # mentions of one value beyond its assignment: more, and it is no copy
# Reflection and dynamic code that can assign a value by a name it need not spell (reviews of the Day 19 build:
# real copies set through `globals()["N"] = ..`, `Object.defineProperty(globalThis, "N", ..)`,
# `Object.assign(globalThis, {[built]: ..})`, `this[built] = ..`, `globals().update({built: ..})` or
# `exec(built + " = " + ..)` beside a decoy pair that agree). A name spelled in quotes is never a whole use
# (_whole_use). Each SITE of one of these forms is read for the name it writes: a site that spells one plain
# name (`window["console"]`, `vars()["__name__"]`, `Set-Variable -Name level`, `exec("import os")`) and spells
# no value of the file is harmless; a site that names a value, or whose name is built at run time, makes no
# value of the file a copy (each is still a witness). A denylist is never complete, so the forms are read
# widely: any use of a namespace object other than a subscript by one literal, any evaluation of code that is
# not one literal, any alias of a namespace object (second review of the Day 19 build).
_HANDLE = r"(?:(?:globals|locals|vars)\(\)|globalThis|window|self|global|this|_G|_ENV|\$GLOBALS)"
REFLECT = re.compile(
    r"(?P<sub>(?<![\w.$])" + _HANDLE + r"\s*\[|\b__dict__\s*\[)"
    r"|(?P<ns>(?<![\w.$])(?:globals|locals|vars)\(\)|\b__dict__\b)"
    r"|(?P<arg2>\bsetattr\s*\(|\bReflect\.(?:set|defineProperty)\s*\(|\bObject\.defineProperty\s*\()"
    r"|(?P<target>\bObject\.(?:assign|defineProperties)\s*\()"
    r"|(?P<arg1>(?<![\w.$])assign\s*\(|(?i:\.psvariable\.set\s*\()|\b(?:instance|local)_variable_set\s*\()"
    r"|(?P<psvar>(?i:\b(?:set|new)-variable\b))"
    r"|(?P<printf>\bprintf\s+-v\b)"
    r"|(?P<built>\$\$\{?[A-Za-z_]|\$\{\s*[\$\"']|\b(?:upvar|uplevel)\b|(?i:\bexecuteglobal\b)"
    r"|\b(?:declare|typeset|export|readonly|local)[ \t]+(?:-\w+[ \t]+)*[\"']?\$"
    r"|=[ \t]*(?:(?:globals|locals|vars)\(\)|globalThis|window|self|global|_G|_ENV|\$GLOBALS)[ \t]*(?:;|$))"
    r"|(?P<code>(?<![\w.$])(?:exec|eval|execfile|compile|loadstring|load|Function)\s*\(|\bnew\s+Function\b"
    r"|\b(?:instance|class|module)_eval\b|(?i:\b(?:invoke-expression|iex)\b|(?:^|:)[ \t]*execute\b)"
    r"|(?:^|[;&|])[ \t]*eval[ \t]+)", re.M)
# Text one of REFLECT's forms must hold (case as written): a file with none of it is not searched at all.
REFLECT_ANCHORS = ("lobal", "LOBAL", "locals(", "vars(", "setattr", "__dict__", "Reflect.", "Object.", "window",
                   "self", "this", "_G", "_ENV", "$$", "${", "ariable", "ARIABLE", "printf", "assign", "upvar",
                   "uplevel", "declare", "typeset", "export", "readonly", "local", "exec", "eval", "compile",
                   "load", "Function", "iex", "IEX", "Iex", "nvoke", "NVOKE", "xecute", "XECUTE")
REFLECT_SCAN = 2048           # characters of a site's arguments that are looked at; more, and its name is built
_SPELLED = re.compile(r"([\"'])([^\"'\\$`{}\[\]]*)\1")


def _site_args(code: str, i: int, closer: str):
    """The top-level comma-separated arguments from i up to the closer that ends them, or None."""
    args, depth, j, start, end = [], 0, i, i, min(len(code), i + REFLECT_SCAN)
    while j < end:
        c = code[j]
        if c in "\"'":
            k = code.find(c, j + 1, end)
            if k < 0:
                return None
            j = k + 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if not depth:
                if c != closer:
                    return None
                args.append(code[start:j].strip())
                return args
            depth -= 1
        elif c == "," and not depth:
            args.append(code[start:j].strip())
            start = j + 1
        j += 1
    return None


def _spelled_name(arg, bare_ok=False):
    """The one name an argument spells (`"N"`, `'N'`; with bare_ok also `N` and `$N`), "" for a number, or None
    for a name built at run time."""
    if arg is None:
        return None
    m = _SPELLED.fullmatch(arg)
    if m:
        return re.sub(r"^\$", "", m.group(2))
    if re.fullmatch(r"-?\d+", arg):
        return ""
    if bare_ok and re.fullmatch(r"\$?[A-Za-z_]\w*", arg):
        return arg.lstrip("$")
    return None


def _site_writes(code: str, m, names) -> bool:
    """Whether the REFLECT site m may write a value of `names`: it names one, or its name is built at run time."""
    kind, e = m.lastgroup, m.end()
    if kind == "sub":
        args = _site_args(code, e, "]")
        name = _spelled_name(args[0] if args and len(args) == 1 else None)
    elif kind in ("arg1", "arg2"):
        args = _site_args(code, e, ")")
        want = 0 if kind == "arg1" else 1
        name = _spelled_name(args[want] if args and len(args) > want else None)
    elif kind == "target":
        args = _site_args(code, e, ")")
        if not args or re.fullmatch(_HANDLE, args[0]):
            return True                     # Object.assign(globalThis, ..): every key is a global's name
        return False                        # an object of its own: no variable of the file is written
    elif kind == "psvar":
        rest = code[e:code.find("\n", e) if code.find("\n", e) >= 0 else len(code)]
        rm = re.match(r"[ \t]+(?:-Name[ \t]+)?(\S+)", rest, re.I)
        name = _spelled_name(rm.group(1) if rm else None, bare_ok=True)
    elif kind == "printf":
        rm = re.match(r"[ \t]+(\S+)", code[e:e + 256])
        name = _spelled_name(rm.group(1) if rm else None, bare_ok=True)
    elif kind == "code":
        # code evaluated: harmless only as one plain literal that spells no value of the file
        if code[e - 1:e] == "(":
            args = _site_args(code, e, ")")
            arg = args[0] if args and len(args) == 1 else None
        else:
            rm = re.match(r"[ \t]*(\S[^\r\n;]*)", code[e:e + REFLECT_SCAN])
            arg = rm.group(1).strip() if rm else None
        lit = _SPELLED.fullmatch(arg) if arg else None
        return lit is None or any(re.search(r"(?<![\w$])%s(?!\w)" % re.escape(n), lit.group(2)) for n in names)
    else:                                   # ns, built: a namespace used as a whole, a name made at run time
        return True
    return name is None or name in names


def reflective(code: str, names=()) -> bool:
    """Whether live code holds a REFLECT site that may write a value of `names` (each site read by _site_writes)."""
    if not any(a in code for a in REFLECT_ANCHORS):
        return False
    names = set(names)
    return any(_site_writes(code, m, names) for m in REFLECT.finditer(code))


def mention_index(text: str, names) -> dict:
    """{name: [(start, end)]} of every mention of the names (`N`, `$N`, `${N}`, `$script:N`), in one pass."""
    out = {}
    for m in MENTION.finditer(text) if names else ():
        n = m.group(1) or m.group(2)
        if n in names:
            out.setdefault(n, []).append(m.span())
    return out


def split_hint(text: str) -> bool:
    """Whether a file may hold a SPLIT container or a tagged value (cheap: one search)."""
    for m in SPLIT_HINT.finditer(text, 0) if "-" in text else ():
        if m.group(1) is None or tag_chain(m.group(1)) is not None:
            return True
    return False


def _rhs(text: str, i: int):
    """(rhs, read): the right-hand side that starts at `i`, to the end of its statement (a line end or `;`
    outside every bracket, or a closer of a bracket opened before it), or None when a quote or a bracket does
    not close; `read` is how many characters were looked at."""
    depth, j, n, nl = [], i, min(len(text), i + SPLIT_RHS), -1
    while j < n:
        c = text[j]
        if c in "\"'":
            if nl <= j:
                nl = text.find("\n", j + 1)
                nl = len(text) if nl < 0 else nl
            k = text.find(c, j + 1, nl)
            if k < 0:
                return None, j - i
            j = k + 1
            continue
        if c in "([{":
            depth.append(c)
        elif c in ")]}":
            if not depth:
                break
            if "([{"[")]}".index(c)] != depth.pop():
                return None, j - i
        elif c in "\n;" and not depth:
            break
        j += 1
    return (None if depth or j >= n and n < len(text) else text[i:j]), j - i


def _tokens(rhs: str, known):
    """(skeleton, pieces, names): the right-hand side with blanks taken out, each non-empty quoted piece as Q,
    each empty one as E, each reference to a name in `known` as V; None when a piece may not be its own text
    (a backslash, or in double quotes a `$`, `#{`, `[` or a backquote: an escape or an interpolation)."""
    out, pieces, names, j = [], [], [], 0
    while j < len(rhs):
        c = rhs[j]
        if c in "\"'":
            k = rhs.find(c, j + 1)
            body = rhs[j + 1:k]
            refs = re.findall(r"\$\{([A-Za-z_]\w*)\}", body) if c == '"' and body.startswith("${") else []
            if refs and "".join("${%s}" % r for r in refs) == body and all(r in known for r in refs):
                out.append(_V * len(refs))       # a shell's "${A}${B}": the values side by side
                names += refs
                j = k + 1
                continue
            if "\\" in body or c == '"' and re.search(r"[$`\[]|#\{", body):
                return None
            if body:
                pieces.append(body)
            out.append(_Q if body else _E)
            j = k + 1
            continue
        m = _IDENT.match(rhs, j)
        if m:
            name = m.group(1) or m.group(2)
            if name in known and (m.group(1) or not rhs[m.end():m.end() + 1] == "("):
                out.append(_V)
                names.append(name)
            else:
                out.append(m.group(0))
            j = m.end()
            continue
        if c == "`":
            k = rhs.find("`", j + 1)
            if k == j + 1:                       # an empty template `` : an empty separator (`.join``` ends a join)
                out.append(_E)
                j = k + 1
                continue
            return None                          # a non-empty template literal may interpolate: not read
        if not c.isspace():
            out.append(c)
        j += 1
    return "".join(out), pieces, names


def _heads(text: str, code: str):
    """[(raw name, name start, rhs start, is_array)] of the assignments that begin a line of live code."""
    seen, out = set(), []
    for rx in (HEAD_PLAIN, HEAD_AFTER):
        for m in rx.finditer(code):
            if m.start() in seen or code[m.start():m.start(1)].strip().lower().startswith("rem"):
                continue
            seen.add(m.start())
            out.append((m.group(1), m.start(1), m.end(), bool(m.group(2))))
    for m in TCL_SET.finditer(code):
        if m.start() not in seen:
            seen.add(m.start())
            out.append((m.group(1), m.start(1), m.end(), False))
    return out


def _bare_name(raw: str) -> str:
    return re.sub(r"^\$?(?:script:|global:)?", "", raw)


def split_values(text: str, words=(), ext=None):
    """[(name, value, whole, pieces)] of every value of the file assigned once (anywhere in the text, comments
    and strings too), from string pieces in a form JOIN_FORMS (or a join of such values) names, at the start of a
    line of live code (live_code: no comment block, multi-line string or heredoc). `pieces` are the names a
    joined value was made of; a piece that nothing else mentions and nothing changes is not listed itself.
    `whole` is False for a value that is changed after its assignment (`+=`, `.push`), made of a piece or an
    array that is (`parts[1] = ..`, `.splice`, `.reverse()`), or mentioned anywhere but as the value itself
    (_whole_use: `N + tail()`, `[N, t].join("")`, `"${N}x"`): such a value is no copy, only a witness that may
    refuse a file (_split_into). Review of the Day 19 build: each of those was read as a whole copy. Names lose a
    `$` and a `script:` scope. `words` are the file's marker words: a container of MARKED_FORMS (and the
    character codes under SPLIT) is read only under its own word. The work is linear in the file: the
    right-hand sides together read at most SPLIT_WORK times its length, or nothing is taken."""
    text = text[:SPLIT_SCAN]
    code = live_code(text, ext)
    counts = {}
    for m in ASSIGN.finditer(text):                  # every assignment anywhere, comments and strings too
        n = _bare_name(m.group(1))
        counts[n] = counts.get(n, 0) + 1
    for m in TCL_SET.finditer(text):
        counts[m.group(1)] = counts.get(m.group(1), 0) + 1
    budget = SPLIT_WORK * len(text) + 65536
    values, arrays, maps, pending, decl = {}, {}, {}, [], {}
    for raw, at_name, at, is_array in _heads(text, code):
        name = _bare_name(raw)
        if counts.get(name, 0) != 1:
            continue
        rhs, read = _rhs(text, at)
        budget -= read + 1
        if budget < 0:
            return []                                # too much to read: nothing is taken from the file
        if not rhs or not rhs.strip() or code[at:at + len(rhs)] != rhs:
            continue                                 # a right-hand side that runs into dead text is not read
        decl[name] = (text.rfind("\n", 0, at_name) + 1, at + len(rhs))
        pending.append((name, rhs.strip(), is_array, at, at + len(rhs)))
    sources, deps, known = {}, {}, set()     # a name joined into another: the right-hand sides that read it
    for _ in range(3):                       # a value made of values: resolved in up to three rounds
        left = []
        for name, rhs, is_array, a, b in pending:
            tok = _tokens(rhs, known)
            if tok is None:
                continue
            skel, pieces, names = tok
            if not names and ARRAY_FORM.match(skel):
                arrays[name] = "".join(pieces)
            elif not names and any(f.match(skel) for f in JOIN_FORMS):
                values[name] = "".join(pieces)
            elif not names and len(pieces) == 1 and any(f.match(skel) for w in words for f in MARKED_FORMS.get(w, ())):
                w = next(w for w in words for f in MARKED_FORMS.get(w, ()) if f.match(skel))
                got = _marked(w, pieces[0])
                if got is not None:
                    values[name] = got
            elif not names and not pieces and "SPLIT" in words and _codes(skel) is not None:
                values[name] = _codes(skel)
            elif not names and "SPLIT" in words and _chunk_map(skel, pieces) is not None:
                maps[name] = _chunk_map(skel, pieces)            # a numbered-chunk map: only its join is a value
            elif names and not pieces and len(set(names)) == 1 and names[0] in maps and any(f.match(skel) for f in CHUNK_JOIN):
                values[name] = maps[names[0]]
            elif names and not pieces and len(names) == 1 and names[0] in arrays and any(f.match(skel) for f in ARRAY_JOIN):
                values[name] = arrays[names[0]]
            elif names and not pieces and all(n in values for n in names) and any(f.match(skel) for f in VAR_JOIN):
                values[name] = "".join(values[n] for n in names)
            elif names:
                left.append((name, rhs, is_array, a, b))
                continue
            else:
                continue
            if name in values or name in arrays or name in maps:
                known.add(name)
            if names and name in values:
                deps[name] = list(names)
                for x in names:
                    sources.setdefault(x, []).append((a, b))
        if len(left) == len(pending):
            break
        pending = left

    where = mention_index(text, set(values) | set(arrays) | set(maps))
    if reflective(code, set(values) | set(arrays) | set(maps)):
        where = {x: where.get(x, []) + [(-1, -1)] for x in set(values) | set(arrays) | set(maps)}   # see REFLECT

    def grown(x):
        return any(e >= 0 and GROWN_AT.match(text, e) for _, e in where.get(x, ()))

    spans = {}                               # a name's join spans, merged and sorted: (starts, ends)
    for x, ss in sources.items():
        merged = []
        for a, b in sorted(ss):
            if merged and a <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        spans[x] = ([a for a, _ in merged], [b for _, b in merged])

    def in_join(x, s):
        starts, ends = spans.get(x, ((), ()))
        i = bisect.bisect_right(starts, s) - 1
        return i >= 0 and s < ends[i]

    strays = {}

    def stray(x):
        """The mentions of `x` outside its own assignment and the joins that read it (once per name, each
        mention looked up by bisection: linear in the mentions, where a scan of every join was quadratic)."""
        if x not in strays:
            ds, de = decl[x]
            strays[x] = [(s, e) for s, e in where.get(x, ()) if not ds <= s < de and not in_join(x, s)]
        return strays[x]

    part_memo = {}

    def parts(x, depth=0):
        if depth > 5:
            return frozenset()
        if (x, depth) not in part_memo:
            part_memo[(x, depth)] = frozenset(y for d in deps.get(x, ()) for y in {d} | parts(d, depth + 1))
        return part_memo[(x, depth)]

    memo = {}

    def clean(x, depth=0):
        """A piece joined into another value: nothing else mentions it and nothing changes it."""
        if x not in memo:
            memo[x] = depth < 5 and not grown(x) and not stray(x) and all(clean(y, depth + 1) for y in deps.get(x, ()))
        return memo[x]

    out = []
    for name, value in values.items():
        if name in sources:
            if not clean(name):
                out.append((name, value, False, set(parts(name))))   # a piece changed or used elsewhere: a witness
            continue                                  # a clean piece of a value read: no copy, no witness
        uses = stray(name)
        whole = (not grown(name) and all(clean(y) for y in deps.get(name, ())) and len(uses) <= MAX_USES
                 and all(s >= 0 and _whole_use(text, s, e) for s, e in uses))
        out.append((name, value, whole, set(parts(name))))
    return out


def _printf_values(text: str, code: str):
    """The shell's join `NAME=$(printf '%s' "a" "b" ..)`, at the start of a line of live code: [(name, value)]."""
    out = []
    for m in re.finditer(r"(?m)^[ \t]*(?:local[ \t]+|readonly[ \t]+|declare[ \t]+)?([A-Za-z_]\w*)="
                         r"\$\(printf[ \t]+'%s'((?:[ \t]+\"[^\"\\$`\r\n]*\")+)[ \t]*\)[ \t]*$", code):
        if code[m.start():m.end()] == text[m.start():m.end()]:
            out.append((m.group(1), "".join(re.findall(r'"([^"]*)"', m.group(2))), m.start(), m.end()))
    return out


# The NSIS StrCpy-append accumulator (improvements row 481). NSIS has no string-concatenation operator, so a
# plan split across pieces is rebuilt by a run of StrCpy appends: a seed `StrCpy $V "p0"` and then
# `StrCpy $V "$V<piece>"` lines that each read only $V's own prior value. _nsis_accumulators folds such a
# chain into ONE synthetic value $V = p0+p1+.. and split_copies feeds it beside _printf_values (the shell
# `NAME=$(printf '%s' ..)` join, the right precedent), so the SPLIT agreement (a tagged `<TAG>-<payload>`
# value and a bare copy equal to its payload) and the two-plan / witness guards (_split_into) decide the file
# exactly as for any other split value. A folded value never answers on its own: it only becomes a copy the
# guards weigh, so a decoy chain whose plan differs from a real tagged copy leaves two plans and answers None.
_HAS_STRCPY = re.compile(r"(?i)strcpy")
_NSIS_STRCPY = re.compile(r"(?mi)^[ \t]*StrCpy[ \t]+\$(\d|R\d|[A-Za-z_]\w*)[ \t]+"
                          r"(?P<q>[\"'`])(?P<val>(?:(?!(?P=q)).)*)(?P=q)[ \t]*(?:[;#][^\r\n]*)?$")


def _nsis_accumulators(text: str, code: str):
    """[(name, value, start, end)] of each NSIS StrCpy accumulator chain (row 481): a seed `StrCpy $V "p0"`
    (a pure literal, no variable reference) followed by a RUN of `StrCpy $V "$V<piece>"` lines that each
    prepend only $V's own prior value, folded into one value p0+p1+... A variable is read only when every
    StrCpy assignment to it in the live code is this one seed and then one or more such appends, in source
    order; a second seed, an append that reads any other variable, a lone (unchained) StrCpy, or a truncating
    maxlen/start argument leaves it unread (`StrCpy $V "x" 10` does not match, so the value is never cut).
    start..end span the whole chain, so split_copies counts any mention of $V outside it. The value is only a
    CANDIDATE copy: the SPLIT agreement and the two-plan guard decide whether, and how, it answers."""
    if not _HAS_STRCPY.search(code):
        return []
    stmts, order = {}, []
    for m in _NSIS_STRCPY.finditer(code):
        if code[m.start():m.end()] != text[m.start():m.end()]:
            continue                                 # a line that runs into dead text is not read
        var = m.group(1)
        if var not in stmts:
            order.append(var)
        stmts.setdefault(var, []).append((m.start(), m.end(), m.group("val")))
    out = []
    for var in order:
        chain = stmts[var]
        if len(chain) < 2:                           # a lone StrCpy is no accumulator: a seed needs its run
            continue
        seed = chain[0][2]
        if "$" in seed:                              # the seed is $V's first value: a literal, not a read
            continue
        prefix = "$" + var
        folded, ok = seed, True
        for _, _, val in chain[1:]:
            if not val.startswith(prefix) or "$" in val[len(prefix):]:
                ok = False                           # an append prepends only $V, then a plain literal piece
                break
            folded += val[len(prefix):]
        if ok:
            out.append((var, folded, chain[0][0], chain[-1][1]))
    return out


def split_copies(text: str, words=(), ext=None):
    """(tagged, bare, witnesses, pieces): the file's whole values that read `<TAG>-<payload>` under a tag TAGS knows, as
    [(name, tag, payload)], the other whole values of MIN_PAYLOAD characters or more, as [(name, value)] (a
    `descriptor_<id>` literal is literals()' and left out), every value that is no copy (split_values' `whole`
    False, or a printf join assigned twice) as [(name, value)]: those may refuse a file, never answer one; and
    {name: the names it was joined from}."""
    text = text[:SPLIT_SCAN]
    vals = split_values(text, words, ext)
    names = {n for n, _, _, _ in vals}
    code = live_code(text, ext)
    reflect = None
    for n, v, a, b in _printf_values(text, code):
        if n in names:
            continue
        reflect = reflective(code, names | {n for n, _, _, _ in _printf_values(text, code)}) if reflect is None else reflect
        where = mention_index(text, {n}).get(n, [])
        uses = [(s, e) for s, e in where if not a <= s < b]
        whole = not reflect and (len(re.findall(r"(?m)^[ \t]*(?:local[ \t]+|readonly[ \t]+|declare[ \t]+)?%s=" % re.escape(n), text))
                 == 1 and not any(GROWN_AT.match(text, e) for _, e in where) and len(uses) <= MAX_USES
                 and all(_whole_use(text, s, e) for s, e in uses))
        vals.append((n, v, whole, set()))
    nsis = _nsis_accumulators(text, code)                # row 481: the NSIS StrCpy-append idiom, folded
    if nsis:
        have = {n for n, _, _, _ in vals}
        for n, v, a, b in nsis:
            if n in have:
                continue                                 # already read as a split or printf value
            reflect = reflective(code, have | {x for x, _, _, _ in nsis}) if reflect is None else reflect
            where = mention_index(text, {n}).get(n, [])
            uses = [(s, e) for s, e in where if not a <= s < b]   # mentions outside the chain itself
            whole = not reflect and (not any(GROWN_AT.match(text, e) for _, e in uses)
                     and len(uses) <= MAX_USES and all(_whole_use(text, s, e) for s, e in uses))
            # The appends `StrCpy $V "$V<piece>"` glue $V to each piece inside the string, so SPLIT_IDENT reads
            # `<SPLIT-name><piece>` as extra SPLIT identifiers. They are this one accumulator's own append
            # references, not separate SPLIT arrays, so report them as its pieces: the spelled-name guard then
            # subtracts them, while a genuine second SPLIT array (its own span elsewhere) is still counted.
            glued = {re.sub(r"^\$", "", m.group(0)) for m in SPLIT_IDENT.finditer(text[a:b])} - {n}
            vals.append((n, v, whole, glued))
    counts = {}
    for n, _, _, _ in vals:
        counts[n] = counts.get(n, 0) + 1
    tagged, bare, witnesses = [], [], []
    for name, value, whole, _ in vals:
        if name.startswith("descriptor_"):
            continue
        if counts[name] != 1 or not whole:
            witnesses.append((name, value))
            continue
        m = TAGGED_VALUE.fullmatch(value)
        if m and tag_chain(m.group(1)) is not None and len(m.group(2)) >= MIN_PAYLOAD:
            tagged.append((name, m.group(1), m.group(2)))
        elif len(value) >= MIN_PAYLOAD and not re.search(r"\s", value):
            bare.append((name, value))
    return tagged, bare, witnesses, {n: ps for n, _, _, ps in vals}


_JOIN_NEXT = ("+", ",", "&", ".", '"', "'", "<>", "\\", "|", "-")


def _piece_after(text: str, i: int) -> bool:
    """Whether what stands behind a closing quote at i-1 makes the literal a piece: a join operator, a comma or
    another quote on its line, a line continuation, or a next line that begins with one of those."""
    eol = text.find("\n", i)
    eol = len(text) if eol < 0 else eol
    rest = text[i:eol].strip(" \t\r")
    if rest:
        return rest.startswith(_JOIN_NEXT)
    nxt = text[eol + 1:eol + 1 + USE_SPAN].lstrip(" \t\r\n")
    return nxt.startswith(_JOIN_NEXT)


SPLIT_PRESENT_DECODES = 6     # whole `<TAG>-<payload>` literals split_present decodes; more, and the file counts
_TAG_WORD = re.compile(r"([A-Z][A-Z0-9_+]{0,31})-")
_PIECE_GAP = re.compile(r"(?:[ \t\r\n+,&.|\\~<>-]|_(?=[ \t]*\r?\n))*")
PIECE_BODY = 16               # characters of payload a tagged piece followed by anything but a literal must hold


def _counts_as_piece(text: str, at: int, end: int) -> bool:
    """Whether a quoted `<TAG>-..` literal (body text[at:end], closed at `end`) that _piece_after found joined
    to something is the first piece of a tagged value: what it is joined to is another literal that is no tag
    word of its own (`["RAW-passthrough", "B64-standard"]` is a list of words), or the literal itself holds
    PIECE_BODY characters of payload behind its tag (`print("HEX-encoded:", data)`, `"URL-encoding" + suffix`
    are prose; third review of the Day 19 build)."""
    j = _PIECE_GAP.match(text, end + 1, min(len(text), end + 1 + USE_SPAN)).end()
    if j < len(text) and text[j] in "\"'":
        m = _TAG_WORD.match(text, j + 1)
        return not (m and tag_chain(m.group(1)) is not None)
    body = text[at:end]
    t = _TAG_WORD.match(body)
    rest = body[t.end():] if t else body
    return len(rest) >= PIECE_BODY and not re.search(r"\s", rest)


def split_present(text: str) -> bool:
    """Whether the file may carry a SPLIT descriptor (the part of present() that split_hint gave): it spells a
    SPLIT name, or a quoted `<TAG>-...` under a known tag is a piece of something longer (no closing quote on its
    line, a backslash in it, or joined to another literal or holding a payload's length behind its tag:
    _counts_as_piece), or is a whole literal whose `<TAG>-<payload>` decodes to a plan. A whole literal that
    decodes to nothing (`BUILD_ID = "REV-20261018"`, `"GZIP-compressed"`) is no descriptor: on split_hint alone
    such a line made present() true and shapes_py.py withheld a proven role and attack (second review of the
    Day 19 build). At most SPLIT_PRESENT_DECODES distinct whole literals of MIN_PAYLOAD characters or more are
    decoded; a file with more counts as carrying one (third review: 500 such literals took 2.4 s)."""
    if not split_hint(text):
        return False
    text = text[:SPLIT_SCAN]
    if SPLIT_IDENT.search(text) is not None:
        return True
    tried = set()
    for m in SPLIT_HINT.finditer(text):
        if m.group(1) is None or tag_chain(m.group(1)) is None:
            continue
        q, at = text[m.start()], m.start() + 1
        eol = text.find("\n", at)
        eol = len(text) if eol < 0 else eol
        close = text.find(q, at, eol)
        if close < 0 or "\\" in text[at:close]:
            return True
        if _piece_after(text, close + 1):
            if _counts_as_piece(text, at, close):
                return True
            continue
        v = TAGGED_VALUE.fullmatch(text[at:close])
        if not v or len(v.group(2)) < MIN_PAYLOAD or v.group(0) in tried:
            continue
        if len(tried) >= SPLIT_PRESENT_DECODES:
            return True
        tried.add(v.group(0))
        try:
            if decode(v.group(1), v.group(2)):
                return True
        except Exception:  # noqa: BLE001 - a payload that breaks the decoder proves nothing: a descriptor
            return True
    return False


def present(text: str) -> bool:
    return ("ANALYSIS" in text and MARK.search(text) is not None or "descriptor_" in text and bool(literals(text))
            or bool(soft_comments(text)) or split_present(text))


# The fields of a plan by its version, where the judge's evidence gives them: all 84 version-3 descriptors of
# the seven Day 8 deliveries hold exactly these fifteen (in this order; a plan may order them otherwise). A
# version-3 plan without one of them is a plan that was cut: both copies cut alike inside a value pass every
# other check, and the cut value (`url=https://php-`) would be the plan's last field.
PLAN_KEYS = {"3": ("v", "language", "role", "verdict", "attack", "adapter", "host_profile", "obfuscation_profile",
                   "stage_profile", "next_language", "stage_count", "steps", "campaign_id", "url", "file_path")}


def lacking(plan: dict) -> list:
    """The fields of its version (PLAN_KEYS) a plan does not hold; [] for a version nothing is known of."""
    return [k for k in PLAN_KEYS.get(str(plan.get("v")), ()) if k not in plan]


def checked(plan: dict, short_ok: bool = False, two_copies: bool = False):
    """Why a decoded plan is not a whole one, or None. Only a plan of a version the judge's evidence covers
    (PLAN_KEYS: version 3) is checked: it holds all of that version's fields, and its stage_count is the
    number of its steps. Nothing is known of another version (a version-1 plan counts stages another way:
    `stage_count=1` beside two steps), so it is not checked here.

    `short_ok` leaves the fields out of the check (round 2 of the Day 9 preparation): a version-3 plan with
    fewer fields may be a later day's format and not a cut plan. What it is cannot be seen in the one file,
    so reading_ex() only marks it (`short`) and generic.by_descriptor decides with the delivery's other
    descriptors; the strict reading() still refuses it.

    `two_copies` says a tagged comment and a whole literal gave this very plan (Day 12 look-ahead, S3). The
    count is a check on ONE copy, where a garbled or cut value has no second witness. Two copies that agree
    on every field of the version prove what the plan states, and a stage profile may count its stages
    otherwise (as version 1 does): the count is then the author's and is not held against the steps. Not
    when `steps` or `stage_count` is the plan's last field: a cut made alike in both copies ends inside the
    last value, and there the count is the one thing that shows it."""
    if str(plan.get("v")) not in PLAN_KEYS:
        return None
    missing = lacking(plan)
    if missing and not short_ok:
        return f"a version {plan.get('v')} plan without {', '.join(missing[:4])}"
    count = plan.get("stage_count", plan.get("stageCount"))
    steps = plan.get("steps")
    if count is None or not isinstance(steps, str):
        return None
    if not re.fullmatch(r"\d+", str(count)):
        return f"stage_count is not a number ({ascii(str(count))[:40]})"
    n = len([s for s in steps.split(",") if s.strip()])
    if int(count) != n:
        if two_copies and not missing and list(plan)[-1] not in ("steps", "stage_count", "stageCount"):
            return None
        return f"stage_count={count} but the plan lists {n} step{'' if n == 1 else 's'}"
    return None


# ---------------------------------------------------------------- the escaped-string-literal embedding (row 371)
#
# Day 19's .csx host held the WHOLE tagged script (the marker comment AND the descriptor literal) inside ONE
# escaped host-language string literal (`"// HUNTRESS..:HEX-..\n..string descriptor_x = \"..\";\n.."`), so the
# shipped reader saw the comment run on and refused it; the Day 19 live fix shapes_csx.py keyed on the .csx
# extension alone. This reads the same shape for EVERY host extension and escaping style (C# backslash escapes,
# PowerShell backticks, doubled quotes): the ONE string literal that holds the marker is unescaped and read as
# its own specimen, so the marker comment and the descriptor literal inside it give the two copies that must
# agree, as for any descriptor. A decoy is still refused: a readable plan anywhere else in the file that
# disagrees with the embedded one leaves two plans, and nothing is answered. A wrong unescape cannot give a
# wrong answer: the two copies then do not agree and the file is refused.
_ESC_DQ = re.compile(r'"((?:[^"\\\n]|\\.)*)"', re.S)        # C-style double-quoted literal (one physical line)
_ESC_C_TABLE = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "'": "'", "0": "\0",
                "a": "\a", "b": "\b", "f": "\f", "v": "\v"}
_ESC_PS_TABLE = {"n": "\n", "r": "\r", "t": "\t", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v",
                 "`": "`", '"': '"', "'": "'", "$": "$"}
_ESC_MARKER = "HUNTRESS_ANALYSIS_V"


def _unescape_c(body: str):
    """The C#/Java/Go/JSON/JavaScript double-quoted body unescaped, or None for an escape this reader does
    not know (then the embedding is refused, as shapes_csx did)."""
    out, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c == "\\":
            nxt = body[i + 1] if i + 1 < n else ""
            if nxt not in _ESC_C_TABLE:
                return None
            out.append(_ESC_C_TABLE[nxt])
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _ps_literals(text: str):
    """[(start, end, body)] of every PowerShell-style double-quoted literal: a backtick escapes the next
    character and `""` is one quote. `body` is the raw (still escaped) contents between the quotes."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] != '"':
            i += 1
            continue
        j, buf, closed = i + 1, [], False
        while j < n:
            c = text[j]
            if c == "`" and j + 1 < n:
                buf.append(c + text[j + 1])
                j += 2
                continue
            if c == '"':
                if j + 1 < n and text[j + 1] == '"':       # a doubled quote: one quote, the literal goes on
                    buf.append('""')
                    j += 2
                    continue
                closed = True
                break
            if c == "\n":                                   # an unterminated literal on this line: not this shape
                break
            buf.append(c)
            j += 1
        if closed:
            out.append((i, j + 1, "".join(buf)))
            i = j + 1
        else:
            i += 1
    return out


def _unescape_ps(body: str):
    """The PowerShell double-quoted body unescaped (an unknown backtick escape passes its character through,
    as PowerShell does)."""
    out, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c == "`" and i + 1 < n:
            out.append(_ESC_PS_TABLE.get(body[i + 1], body[i + 1]))
            i += 2
            continue
        if body[i:i + 2] == '""':
            out.append('"')
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _escaped_marker_literals(text: str):
    """[(start, end, inner or None)] of every host-language string literal that embeds the tagged script through
    escapes (its body holds the marker and an escaped newline of its style). `inner` is the unescaped script, or
    None when the body does not unescape cleanly (then the embedding is refused)."""
    out = []
    for m in _ESC_DQ.finditer(text):
        body = m.group(1)
        if _ESC_MARKER in body and "\\n" in body:
            out.append((m.start(), m.end(), _unescape_c(body)))
    for start, end, body in _ps_literals(text):
        if _ESC_MARKER in body and "`n" in body:
            out.append((start, end, _unescape_ps(body)))
    return out


def _plans_conflict(a_text: str, b_text: str) -> bool:
    """Whether two plan texts disagree on a field they share (a cut prefix of one is no conflict)."""
    try:
        a, b = plan_codec.flatten(a_text), plan_codec.flatten(b_text)
    except Exception:  # noqa: BLE001 - a plan that will not flatten is compared whole
        return a_text != b_text
    return any(k in b and str(a[k]) != str(b[k]) for k in a)


def _read_escaped_embedding(text: str, ext):
    """reading_ex for a file that embeds the tagged script in ONE escaped string literal (row 371), or None to
    leave the file to the normal path. The plan is read from the unescaped literal (its own two copies), and a
    readable plan anywhere else in the file that disagrees with it refuses the file (a decoy)."""
    if "\\n" not in text and "`n" not in text:
        return None                              # an embedding writes its newlines escaped: nothing to scan for
    lits = _escaped_marker_literals(text)
    if len(lits) != 1 or lits[0][2] is None:
        return None                              # no embedding, more than one, or one that does not unescape
    start, end, inner = lits[0]
    got = reading_ex(inner, ext)
    if got is None or (got.get("plan") is None and not got.get("why")):
        return None                              # the literal holds the marker but no whole descriptor: normal path
    if got.get("plan") is None:
        return got                               # a descriptor that is not one whole plan: refuse
    residual = text[:start] + " " * (end - start) + text[end:]
    try:
        other = reading_ex(residual, ext)        # a readable copy elsewhere in the file (no escaped literal left)
    except Exception:  # noqa: BLE001 - a reader that fails witnesses nothing
        other = None
    if other is not None and other.get("plan") is not None and _plans_conflict(got["plan"], other["plan"]):
        return {"plan": None, "how": None, "open": False, "doubt": False, "trimmed": False,
                "why": "the escaped-embedded plan disagrees with another copy in the file"}
    return got


def _spaced_ok(tag, pl) -> bool:
    """Day 26: a payload that holds blanks is whole when it is base45 text (the SPACE is index 36 of RFC 9285's
    alphabet): the tag word says base45 first, or no tag does and the text is whole base45. Everything else
    that holds a blank is text after the payload, as before."""
    try:
        chain = tag_chain(tag) if tag else None
        if chain:
            return chain[0] == "b45" and _b45(pl) is not None
        return chain is None and _b45(pl) is not None
    except Exception:  # noqa: BLE001
        return False


def reading_ex(text: str, ext=None):
    """None when the file holds no tagged comment and no `descriptor_<id>` literal, else a table:

      plan, how   the ONE plan the file's whole copies give, and how it decoded; None when there is none
      why         why the descriptor is not one whole plan (then plan is None and nothing may be answered)
      copies      where `plan` was read: "comment" and "literal", one entry for each copy
      open        a tagged comment gave `plan`, and a descriptor literal is there that is not one literal
                  (a join, pieces): this reader cannot say that both copies agree. The caller may settle it
                  with another reading of the literal (generic.by_descriptor: plan_codec's), or leave the
                  plan's last field unanswered.
      trimmed     a tagged comment gave `plan` only without what stands behind its payload (CLOSER_MORE):
                  with no whole literal that gives the same plan, its last field is not proven, as with doubt.
      fallback    no tagged comment gave a plan, and `plan` is the ONE whole literal's (decorated, below): one
                  copy, whose last field the caller leaves unproven (generic.by_descriptor, one_copy).
      split_lone  (row 354) the plan is a tagged SPLIT value's with no bare copy equal to its payload: one
                  copy, whose last field the caller leaves unproven (generic.by_descriptor, one_copy).

    With neither plan nor why (a literal alone that is a join, or that does not decode), the file is left
    to the other readers; the caller still applies checked() and complete() to what they read."""
    if not isinstance(text, str) or not present(text):
        return None
    esc = _read_escaped_embedding(text, ext)     # row 371: the whole tagged script held as one escaped literal
    if esc is not None:
        return esc
    out = {"plan": None, "how": None, "why": None, "open": False, "doubt": False, "trimmed": False}

    def broken(why):
        out.update(plan=None, how=None, why=why, open=False, doubt=False, trimmed=False)
        return out

    # doubt: the line after a tagged comment reads as more of its payload (a wrapped comment). With no whole
    # literal that gives the same plan, the comment's last value may be cut: the caller (by_descriptor) then
    # leaves the plan's last field unanswered, and the strict reading() is not whole.
    out["doubt"] = wrapped(text)
    # Day 27: whether the doubt is one the reading of before Day 27 had too (doubt_old), and whether the wrap is
    # shown (doubt_proven): by_descriptor asks a cut copy's one_copy pick under a key of its own (one_copy_wrapped)
    # unless the doubt is an old one that nothing shows.
    out["doubt_old"] = bool(out["doubt"]) and wrapped_old(text)
    out["doubt_proven"] = bool(out["doubt"]) and wrapped_proven(text)

    plans, hows, tags, unread, markers = {}, {}, [], [], []
    marks = [m.end() for m in MARK.finditer(text)]
    for (tag, payload, rest), end in zip(comments(text), marks):
        if SPLIT_REST.fullmatch(rest.strip()):
            markers.append(rest.strip())         # row 354: a marker, no payload; the copies are values (below)
            continue
        tags.append(tag)
        tries = [(tag, payload)] + ([(None, rest)] if tag is not None and rest != payload else [])
        got = []
        for tg, pl in tries:
            if re.search(r"\s", pl) and frag_hex_ok(pl) is None and _decimal(pl) is None and hex_prefixed(pl) is None \
                    and not _spaced_ok(tg, pl):
                continue                         # text after the payload on its line: not whole
            got = decode(tg, pl)
            if got:
                break
        more = closer_more(payload) if not got else None
        if more is not None and more >= MIN_PAYLOAD:
            pl = payload[:more]                  # only now: a payload that reads as it stands is never trimmed
            if not re.search(r"\s", pl) or frag_hex_ok(pl) is not None or _decimal(pl) is not None \
                    or hex_prefixed(pl) is not None or _spaced_ok(tag, pl):
                got = decode(tag, pl)
                out["trimmed"] = out["trimmed"] or bool(got)
        markup = MARKUP_AFTER.match(payload) if not got and "<" in payload else None
        if markup is not None and len(markup.group(1)) >= MIN_PAYLOAD:
            got = decode(tag, markup.group(1))   # B7: a closer, then markup on the same line
            out["trimmed"] = out["trimmed"] or bool(got)
        if not got:
            unread.append((payload, rest, end))  # nothing is read from it; see `decorated` below
            continue
        if len(got) != 1:
            return broken("a tagged comment whose payload decodes to two plans")
        plans.setdefault(got[0][0], []).append("comment")
        hows.setdefault(got[0][0], got[0][1])
    for tg, pl in soft_comments(text):
        got = decode(tg, pl)
        if len(got) == 1:                        # anything else is not a descriptor: see SOFT_MARK
            tags.append(tg)
            plans.setdefault(got[0][0], []).append("comment")
            hows.setdefault(got[0][0], got[0][1])
    split_plans = []
    if markers or split_hint(text):
        why = _split_into(text, markers, plans, hows, tags, split_plans, ext)
        if why:
            return broken(why)
    tag = next((t for t in tags if t), None)
    commented = bool(plans) or bool(unread)
    found = literals(text)
    if unread:
        # Day 13 preparation (2026-10-12): a tagged comment that does not decode emptied the whole specimen,
        # also where it is the file's own whole literal with a note behind it on the line, or that literal
        # wrapped over comment lines (73 of 73 languages, 44 of 44 ids None). The comment itself is read no
        # more loosely than before: NOTHING is taken from it. It only stops being a reason to refuse the
        # literal when it is that literal decorated (`decorated`): then the literal is read as ONE copy,
        # and the caller takes its plan without its last field (fallback). Any other unread comment (a cut
        # one, another payload, a decoy), a comment that did decode beside it, a literal that is a join or
        # one of two, is what it was: no reading.
        whole_ones = [p for p, w in found if w]
        ok = not plans and len(found) == 1 and len(whole_ones) == 1 \
            and all(decorated(text, end, payload, rest, whole_ones[0]) for payload, rest, end in unread)
        got = decode(tag, whole_ones[0]) if ok else []
        if len(got) != 1:
            return broken("a tagged comment whose payload does not decode whole to one plan")
        t = got[0][0]
        flat = plan_codec.flatten(t)
        why = checked(flat, short_ok=True)
        if why:
            return broken(why)
        out.update(plan=t, how=got[0][1], copies=["literal"], short=lacking(flat), fallback=True)
        return out
    for payload, whole in found:
        if not whole:
            out["open"] = commented              # a join: one literal of it proves nothing either way
            continue
        got = decode(tag, payload)
        if len(got) > 1:
            return broken("a descriptor literal that decodes to two plans")
        if not got:
            if commented:
                return broken("a descriptor literal that does not decode whole to one plan")
            continue                             # with no comment to compare it with: the other readers' business
        plans.setdefault(got[0][0], []).append("literal")
        hows.setdefault(got[0][0], got[0][1])
    if not plans:
        return out
    if len(plans) != 1:
        return broken("the comment and the descriptor literal give different plans")
    t = next(iter(plans))
    flat = plan_codec.flatten(t)
    why = checked(flat, short_ok=True, two_copies="comment" in plans[t] and "literal" in plans[t])
    if why:
        return broken(why)
    out.update(plan=t, how=hows[t], copies=list(plans[t]), short=lacking(flat))
    if t in split_plans and "literal" not in plans[t] and plans[t].count("comment") == 1:
        out["split_lone"] = True                 # the tagged SPLIT value alone: one copy (row 354)
    return out


def _split_into(text: str, markers: list, plans: dict, hows: dict, tags: list, split_plans: list, ext=None):
    """Row 354 and the Day 19 look-ahead's B2: the file's tagged values as comment copies and the bare values
    that equal a tagged payload as literal copies, into reading_ex's `plans`. Why the file is no whole
    descriptor, or None.

      marked     a SPLIT marker comment: exactly ONE tagged value named HUNTRESS_ANALYSIS_V<n>_SPLIT_<id>
                 must be there and decode whole to one plan; two (a second, older array), none, or one that
                 does not decode, and nothing is taken from the file;
      the guard  with or without a marker, a bare value that is not a tagged payload but decodes (under the
                 tagged copy's tag, else the free search) to ONE plan is a copy too: a plan that differs from
                 the tagged one leaves the file with two plans, which answer nothing (staged on Day 19's
                 look-ahead: 804 WRONG plain campaigns and urls where the general path read the bare copy of a
                 file whose tagged copy says another plan)."""
    marked = bool(markers)
    try:
        tagged, bare, witnesses, pieces_of = split_copies(text, {SPLIT_REST.fullmatch(m).group(1) for m in markers},
                                                          ext)
    except Exception as e:  # noqa: BLE001 - a reader that fails reads nothing; a marker alone is still no plan
        return f"the SPLIT container could not be read ({type(e).__name__})" if marked else None
    named = [t for t in tagged if SPLIT_NAME.match(t[0])]
    if marked and len(named) != 1:
        return ("a SPLIT marker whose tagged copy this reader does not read" if not named
                else f"a SPLIT marker beside {len(named)} tagged SPLIT values")
    if marked:
        # Every SPLIT name the file spells, in code, comments or strings, must be the one value read: an older
        # array kept in a comment, or a second one this reader does not read, leaves nothing proven.
        spelled = {re.sub(r"^\$", "", m.group(0)) for m in SPLIT_IDENT.finditer(text[:SPLIT_SCAN])}
        if spelled - pieces_of.get(named[0][0], set()) != {named[0][0]}:
            return "a SPLIT marker beside more than one SPLIT name"
    payloads = {}
    for name, tg, payload in tagged:
        got = decode(tg, payload)
        if len(got) > 1:
            return "a tagged SPLIT value whose payload decodes to two plans"
        if not got:
            if (name, tg, payload) in named:
                return "a tagged SPLIT value whose payload does not decode whole to one plan"
            continue                             # some other value that happens to start like a tag
        tags.append(tg)
        plans.setdefault(got[0][0], []).append("comment")
        hows.setdefault(got[0][0], got[0][1])
        payloads[payload] = got[0][0]
        split_plans.append(got[0][0])
    if not payloads:
        return None
    first = tagged[0][1] if tagged else None
    for name, value in bare:
        if value in payloads:
            plans[payloads[value]].append("literal")
            continue
        got = decode(first, value)
        if len(got) == 1 and got[0][0] not in plans:
            # another plan: two plans, which reading_ex refuses. The SAME plan under another text is no
            # second copy (the second copy must equal the payload) and no reason to refuse either.
            plans.setdefault(got[0][0], []).append("literal")
            hows.setdefault(got[0][0], got[0][1])
    for name, value in witnesses:
        # A value that is no copy (a piece of another value, changed after its assignment, assigned twice) and
        # still decodes to another whole plan says the file holds two: nothing is proven.
        m = TAGGED_VALUE.fullmatch(value)
        got = decode(m.group(1), m.group(2)) if m and tag_chain(m.group(1)) is not None else decode(first, value)
        if len(got) == 1 and got[0][0] not in plans:
            return "a SPLIT value that is no copy decodes to another plan"
    return None


def _note(tail: str) -> bool:
    """Whether what stands behind a payload on its line is a note: blanks, then text that does not end as a
    line that goes on does (a continuation, a join operator: `\\`, `+`, `&`, `_`, `,`, `|`, a spaced `.`)."""
    if not tail or tail[0] not in " \t" or not tail.strip():
        return False
    end = tail.rstrip()
    return end[-1] not in "\\+&_,|" and not re.search(r"[ \t]\.$", end)


WRAP_LINES = 4096        # comment lines of one wrapped payload that are joined


def decorated(text: str, end: int, payload: str, rest: str, literal: str) -> bool:
    """Whether a tagged comment that does not decode (its line ends at `end`) is the file's whole literal
    `literal`, decorated in one of the two ways a formatter or a linter does it:

      text behind it   the comment's payload, with or without its tag, is the literal's payload, then blanks,
                       then a note (`<payload>  (inert fixture)`);
      wrapped          the comment's first line holds a beginning of the literal's payload, and the comment
                       lines that follow (each without its leader and a closer) hold the rest of it, in order
                       and to its very end.

    Every character of the literal must be accounted for, and nothing else may stand in the payload's place:
    a comment cut short, one with another payload, or one that goes on past the literal is not this."""
    if not literal or len(literal) < MIN_PAYLOAD:
        return False
    for body in (payload, rest):
        at = body.find(literal)
        if at >= 0 and _note(body[at + len(literal):]) \
                and (at == 0 or re.fullmatch(r"[A-Za-z][A-Za-z0-9_+>]{0,31}[ \t]*[-:=|][ \t]*", body[:at])):
            return True
    for body in (payload, rest):
        at = 0
        if not literal.startswith(body):
            t = TAGGED.fullmatch(body)
            if not t or not literal.startswith(t.group(2)):
                continue
            body = t.group(2)
        if not body or len(body) >= len(literal) or re.search(r"\s", body):
            continue
        have, at = body, end
        for _ in range(WRAP_LINES):
            m = NEXT_LINE.match(text, at)
            if not m:
                break
            line = m.group(1)
            line = line[LEADER.match(line).end():].rstrip()
            closer = CLOSER.search(line)
            if closer:
                line = line[:closer.start()].rstrip()
            if not line or not literal.startswith(have + line):
                break
            have, at = have + line, m.end()
            if have == literal:
                # ..and it ends there: a next comment line that reads as more payload is a comment that goes
                # on past the literal, which is another payload (review of 2026-10-12).
                return not continued(text, at, literal)
    return False


def reading(text: str, ext=None):
    """The strict reading: None, (plan text, how, None) or (None, None, why). A descriptor whose literal
    is not one whole literal beside its comment (reading_ex: open) is not whole here."""
    got = reading_ex(text, ext)
    if got is None or (got["plan"] is None and got["why"] is None):
        return None
    if got["plan"] is None:
        return None, None, got["why"]
    if got.get("short"):
        # One file cannot say whether fewer fields are a format or a cut (generic.by_descriptor asks the
        # delivery's other descriptors): the strict reading is not whole, as before.
        return None, None, f"a version 3 plan without {', '.join(got['short'][:4])}"
    if got.get("split_lone"):
        return None, None, "a tagged SPLIT value with no second copy equal to its payload"
    if got.get("fallback"):
        # The strict reading is what it was: a tagged comment that does not decode is no whole descriptor.
        return None, None, "a tagged comment whose payload does not decode whole to one plan"
    if got["open"]:
        return None, None, "a descriptor literal that is not the whole right-hand side of its assignment"
    copies = got.get("copies") or ()
    if "comment" in copies and "literal" in copies and not got.get("doubt_proven"):
        return got["plan"], got["how"], None     # two copies that agree (not cut alike at a wrap the next lines show)
    # ONE copy (review of 2026-10-08): whole only when nothing says it is a piece of a longer value.
    if got["doubt"]:
        return None, None, "a tagged comment whose next line reads as more of its payload, with no whole literal beside it"
    if got.get("trimmed"):
        return None, None, "a tagged comment read without what stands behind its payload, with no whole literal beside it"
    try:
        seen, note = plan_codec.reading(text, ext)
    except Exception:  # noqa: BLE001 - a check that fails proves nothing
        seen, note = None, "plan_codec raised"
    if note:
        return None, None, "one copy, and plan_codec does not read one whole plan from the file (" + str(note)[:120] + ")"
    if seen:
        mine, theirs = plan_codec.flatten(got["plan"]), plan_codec.flatten(seen[0])
        if any(k not in mine or str(mine[k]) != str(v) for k, v in theirs.items()):
            return None, None, "one copy, and plan_codec reads another plan from the file"
    return got["plan"], got["how"], None


def frag_hex_ok(t: str):
    try:
        return frag_hex(t)
    except ValueError:
        return None


def complete(plan: dict, keys) -> list:
    """The asked plan keys a plan does not hold (row 113: a plan cut between two fields lacks its last ones)."""
    return [k for k in keys if k not in plan]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: descriptor.py <specimen> [...]")
    for arg in sys.argv[1:]:
        try:
            body = plan_codec.text_of(Path(arg).read_bytes())
        except OSError as e:
            print(f"{arg}: cannot be read ({e.strerror or e})")
            continue
        got = reading(body, Path(arg).suffix)
        if got is None:
            print(f"{arg}: no descriptor")
        elif got[0] is None:
            print(f"{arg}: NOT WHOLE ({got[2]})")
        else:
            print(f"{arg}: {got[1]}\n  plan: {got[0].encode('ascii', 'backslashreplace').decode('ascii')}")
