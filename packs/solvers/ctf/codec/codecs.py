"""The codec registry of the shared codec graph (B-163): every edge the graph may take, by name.

A codec is one decode step `bytes -> bytes | None`. None means "this input is not in my form": every
codec here is all-or-nothing, so a decode either reads the whole input or refuses it. Four kinds:

  * ``strict``  -- a representation change (base64/32/85/58, ascii85, hex, binary, octal and decimal
    byte lists, url and html escapes, utf-16, run-length groups, gzip/zlib/bz2/xz). Information
    preserving; a strict step in a chain is what makes a reading "confirmed".
  * ``symbol``  -- a symbol alphabet: Morse, Bacon, tap code, Polybius, each also *over hex* (the
    symbols spell hex digits, which the graph then reads with ``hex``: Day 16's Morse of hex, Day 17's
    Bacon of hex). Strict parses too, and they count as representation steps.
  * ``loose``   -- a keyless character transform that always applies (rot13, rot47, caesar 1..25,
    atbash, reverse, swapcase, single-byte xor). On their own they make flag shapes out of noise, so
    the graph follows one only when its output reads on through a strict codec (``graph``), and a
    chain of loose steps alone is never "confirmed".
  * ``keyed``   -- a small keyed family searched exhaustively (rail fence with 2..12 rails: the
    long-slug transposition). Treated like ``loose``.

Every name is stable and parseable, so a chain (a tuple of names) can be re-applied to another
payload with `apply_chain` (the N-record consensus in `records` does that). Parameterised names:
``caesar<n>`` (n = 1..25, not 13), ``xor0x<kk>``, ``rail<n>``.

Nothing here executes input, touches the network or reads a file. Decompression is bounded by
MAX_OUT (a bomb is refused, not inflated).
"""
from __future__ import annotations

import base64
import binascii
import bz2
import html
import lzma
import re
import urllib.parse
import zlib
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

STRICT = "strict"
SYMBOL = "symbol"
LOOSE = "loose"
KEYED = "keyed"
PACK = "pack"            # a codec loaded from a breadth pack (ctf.codec.pack); a representation step
KINDS = (STRICT, SYMBOL, LOOSE, KEYED, PACK)
REPRESENTATION = frozenset({STRICT, SYMBOL, PACK})   # kinds whose step confirms a reading
PARTIAL = frozenset({"url", "html"})   # escape codecs that decode a text with only a few escapes in it

MAX_OUT = 8 << 20        # bytes a decompressor may produce before the stream is refused
MAX_BIGNUM = 4096        # characters of a base58 number that is read at all (quadratic big-int cost)
RAIL_MAX = 12            # rails the rail-fence family tries (2..RAIL_MAX)

Decode = Callable[[bytes], Optional[bytes]]


class CodecError(ValueError):
    """An unknown codec name, or a malformed chain."""


@dataclass(frozen=True)
class Codec:
    name: str
    kind: str
    decode: Decode
    doc: str = ""
    text_only: bool = False      # only tried on states that are printable text

    def __post_init__(self):
        if self.kind not in KINDS:
            raise CodecError(f"codec {self.name!r}: unknown kind {self.kind!r}")


# ------------------------------------------------------------------------------------------ helpers

_PRINTABLE = frozenset(range(0x20, 0x7F)) | frozenset(b"\t\r\n")
_LINEBREAKS = re.compile(rb"[\r\n\t ]*\n[\r\n\t ]*|\r")


def is_text(b: bytes) -> bool:
    """True when every byte is printable ASCII or tab/CR/LF (and there is at least one byte)."""
    return bool(b) and all(c in _PRINTABLE for c in b)


def _unwrapped(b: bytes) -> bytes:
    """The input with surrounding white space and line breaks removed (base text is often wrapped)."""
    return _LINEBREAKS.sub(b"", b.strip())


def _changed(src: bytes, out) -> Optional[bytes]:
    if out is None:
        return None
    out = bytes(out)
    return out if out and out != src else None


# ------------------------------------------------------------------------------------ strict codecs

_B64 = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
_B64URL = re.compile(rb"[A-Za-z0-9_-]+={0,2}")
_B32 = re.compile(rb"[A-Z2-7]+=*")
_B85 = re.compile(rb"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]+")
_A85 = re.compile(rb"(?:<~)?[!-uz\s]+(?:~>)?")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_RE = re.compile(rb"[1-9A-HJ-NP-Za-km-z]+")
_HEX_SEP = re.compile(rb"(?:0x|\\x)?[0-9a-fA-F]{2}(?:[\s,:;-]*(?:0x|\\x)?[0-9a-fA-F]{2})*")
_HEX_TOKEN = re.compile(rb"[0-9a-fA-F]{2}")
_BITS = re.compile(rb"[01]+(?:\s+[01]+)*")
_NUMS = re.compile(rb"\d+(?:[\s,;]+\d+)+")
_PCT = re.compile(rb"%[0-9A-Fa-f]{2}")
_ENTITY = re.compile(rb"&(?:#\d+|#[xX][0-9A-Fa-f]+|[A-Za-z]{2,10});")
_RLE = re.compile(rb"\d+:.(?:,\d+:.)*,?", re.S)


def d_b64(b: bytes):
    s = _unwrapped(b)
    if len(s) < 4 or not _B64.fullmatch(s):
        return None
    s = s.rstrip(b"=")
    if len(s) % 4 == 1:
        return None
    try:
        return _changed(b, base64.b64decode(s + b"=" * (-len(s) % 4), validate=True))
    except (binascii.Error, ValueError):
        return None


def d_b64url(b: bytes):
    s = _unwrapped(b)
    if len(s) < 4 or not (b"-" in s or b"_" in s) or not _B64URL.fullmatch(s):
        return None
    s = s.rstrip(b"=")
    if len(s) % 4 == 1:
        return None
    try:
        return _changed(b, base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4)))
    except (binascii.Error, ValueError):
        return None


def d_b32(b: bytes):
    s = _unwrapped(b)
    if s.islower():
        s = s.upper()
    if len(s) < 8 or not _B32.fullmatch(s):
        return None
    body = s.rstrip(b"=")
    if len(body) % 8 in (1, 3, 6):
        return None
    try:
        return _changed(b, base64.b32decode(body + b"=" * (-len(body) % 8)))
    except (binascii.Error, ValueError):
        return None


def d_b85(b: bytes):
    s = _unwrapped(b)
    if len(s) < 5 or not _B85.fullmatch(s) or len(s) % 5 == 1:
        return None
    try:
        return _changed(b, base64.b85decode(s))
    except (ValueError, binascii.Error):
        return None


def d_a85(b: bytes):
    s = b.strip()
    if len(s) < 5 or not _A85.fullmatch(s):
        return None
    adobe = s.startswith(b"<~") and s.endswith(b"~>")
    if not adobe and (b"<~" in s or b"~>" in s or b" " in s):
        return None          # bare ascii85 is one unspaced run (wrapped lines allowed); prose is not it
    try:
        return _changed(b, base64.a85decode(s, adobe=adobe, ignorechars=b" \t\n\r\v"))
    except (ValueError, binascii.Error):
        return None


def d_b58(b: bytes):
    s = b.strip()
    if not (6 <= len(s) <= MAX_BIGNUM) or not _B58_RE.fullmatch(s):
        return None
    n = 0
    for c in s.decode("ascii"):
        n = n * 58 + _B58.index(c)
    lead = len(s) - len(s.lstrip(b"1"))
    out = b"\x00" * lead + (n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"")
    return _changed(b, out)


def d_hex(b: bytes):
    s = b.strip()
    if len(s) < 2 or not _HEX_SEP.fullmatch(s):
        return None
    tokens = _HEX_TOKEN.findall(re.sub(rb"0x|\\x", b" ", s))
    if not tokens:
        return None
    joined = b"".join(tokens)
    compact = re.sub(rb"[\s,:;-]|0x|\\x", b"", s)
    if joined != compact:      # an odd run of digits between separators: not a byte list
        return None
    return _changed(b, bytes.fromhex(joined.decode("ascii")))


def d_binary(b: bytes):
    s = b.strip()
    if len(s) < 8 or not _BITS.fullmatch(s):
        return None
    groups = s.split()
    if len(groups) > 1:
        width = len(groups[0])
        if width not in (7, 8) or any(len(g) != width for g in groups):
            return None
    else:
        width = 8
        if len(s) % 8:
            return None
        groups = [s[i:i + 8] for i in range(0, len(s), 8)]
    return _changed(b, bytes(int(g, 2) for g in groups))


def _numlist(b: bytes, base: int):
    s = b.strip()
    if not _NUMS.fullmatch(s):
        return None
    try:
        vals = [int(t, base) for t in re.split(rb"[\s,;]+", s)]
    except ValueError:
        return None
    if any(v > 255 for v in vals):
        return None
    return _changed(b, bytes(vals))


def d_octal(b: bytes):
    if re.search(rb"[89]", b):
        return None
    return _numlist(b, 8)


def d_decimal(b: bytes):
    return _numlist(b, 10)


def d_url(b: bytes):
    if not _PCT.search(b) or not is_text(b):
        return None
    return _changed(b, urllib.parse.unquote_to_bytes(b.replace(b"+", b" ")))


def d_html(b: bytes):
    if not _ENTITY.search(b) or not is_text(b):
        return None
    try:
        return _changed(b, html.unescape(b.decode("ascii")).encode("utf-8"))
    except UnicodeDecodeError:
        return None


def d_utf16(b: bytes):
    if len(b) < 4 or len(b) % 2:
        return None
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        codec = "utf-16"
    elif all(c == 0 for c in b[1::2]):
        codec = "utf-16-le"
    elif all(c == 0 for c in b[0::2]):
        codec = "utf-16-be"
    else:
        return None
    try:
        return _changed(b, b.decode(codec).encode("utf-8"))
    except UnicodeDecodeError:
        return None


def d_runlength(b: bytes):
    """`<count>:<char>,` groups (Day 24), the character repeated count times."""
    s = b.strip(b"\r\n")
    if not _RLE.fullmatch(s):
        return None
    out, i, groups = bytearray(), 0, 0
    while i < len(s):
        j = s.index(b":", i)
        count = int(s[i:j])
        if not 1 <= count <= 100000:
            return None
        out += s[j + 1:j + 2] * count
        groups += 1
        i = j + 3          # past the char and its comma
        if len(out) > MAX_OUT:
            return None
    return _changed(b, out) if groups >= 2 else None


def _bounded(dec, data: bytes):
    """Run an incremental decompressor; None on error or when the output passes MAX_OUT."""
    try:
        out = dec.decompress(data, MAX_OUT + 1)
    except (zlib.error, OSError, EOFError, lzma.LZMAError, ValueError):
        return None
    if len(out) > MAX_OUT:
        return None
    if not getattr(dec, "eof", True):
        return None
    return out


def d_gzip(b: bytes):
    if not b.startswith(b"\x1f\x8b"):
        return None
    return _changed(b, _bounded(zlib.decompressobj(16 + zlib.MAX_WBITS), b))


def d_zlib(b: bytes):
    if len(b) < 2 or b[0] & 0x0F != 8 or ((b[0] << 8) | b[1]) % 31:
        return None
    return _changed(b, _bounded(zlib.decompressobj(), b))


def d_bz2(b: bytes):
    if not b.startswith(b"BZh"):
        return None
    return _changed(b, _bounded(bz2.BZ2Decompressor(), b))


def d_xz(b: bytes):
    if not (b.startswith(b"\xfd7zXZ\x00") or b.startswith(b"\x5d\x00\x00")):
        return None
    return _changed(b, _bounded(lzma.LZMADecompressor(), b))


# ------------------------------------------------------------------------------------ symbol codecs

MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h",
         "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p",
         "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
         "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
         ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9", "-....-": "-", ".-.-.-": ".",
         "--..--": ",", "---...": ":", "-.-.--": "!", "..--..": "?", ".----.": "'", "-..-.": "/",
         ".--.-.": "@", "-...-": "=", ".-.-.": "+", "..--.-": "_", "-.--.": "(", "-.--.-": ")"}
_MORSE_RE = re.compile(rb"[.\-_ \t\r\n/|]+")
HEX_DIGITS = "0123456789abcdef"


def d_morse(b: bytes):
    s = b.strip()
    if len(s) < 3 or not _MORSE_RE.fullmatch(s) or not re.search(rb"[.\-_]", s):
        return None
    text = s.decode("ascii").replace("_", "-")
    words = re.split(r"\s*[/|]\s*|\s{3,}|\r?\n", text)
    out = []
    for w in words:
        letters = w.split()
        if not letters:
            continue
        try:
            out.append("".join(MORSE[t] for t in letters))
        except KeyError:
            return None
    if not out:
        return None
    return _changed(b, " ".join(out).encode("ascii"))


_TWO_SYM = (b"ab", b"AB", b"01", b".-")


def _two_symbol_groups(b: bytes, widths, invert: bool = False) -> Optional[tuple[list[int], int]]:
    """(values, width) of a text written in exactly two symbols, in groups of one width (space split, or
    one run cut in fives), the pair's first listed symbol as 0 (the second one with `invert`)."""
    s = b.strip()
    kinds = set(s) - set(b" \t\r\n")
    pair = next((p for p in _TWO_SYM if kinds and kinds <= set(p)), None)
    if pair is None:
        return None
    zero, one = (pair[1], pair[0]) if invert else (pair[0], pair[1])
    tokens = s.split()
    if len(tokens) > 1:
        width = len(tokens[0])
        if width not in widths or any(len(t) != width for t in tokens):
            return None
    else:
        width = 5
        if 5 not in widths or len(s) % 5:
            return None
        tokens = [s[i:i + 5] for i in range(0, len(s), 5)]
    table = bytes.maketrans(bytes((zero, one)), b"01")
    return [int(t.translate(table), 2) for t in tokens], width


_BACON24 = "abcdefghiklmnopqrstuwxyz"     # i=j, u=v


def d_bacon(b: bytes):
    """Classic 26-letter Bacon (aaaaa = a .. bbaab = z) in a/b (or A/B), groups of five."""
    s = b.strip()
    if not s or s[0] not in b"aAbB":
        return None
    got = _two_symbol_groups(s, (5,))
    if got is None or len(got[0]) < 2 or any(v > 25 for v in got[0]):
        return None
    return _changed(b, bytes(0x61 + v for v in got[0]))


def d_bacon24(b: bytes):
    """The 24-letter Bacon alphabet (i/j and u/v share a code)."""
    s = b.strip()
    if not s or s[0] not in b"aAbB":
        return None
    got = _two_symbol_groups(s, (5,))
    if got is None or len(got[0]) < 2 or any(v > 23 for v in got[0]):
        return None
    return _changed(b, "".join(_BACON24[v] for v in got[0]).encode("ascii"))


def d_baconhex(b: bytes):
    """Hex digits written as two-symbol groups of four or five (the value of each group is one hex digit,
    0..15): returns the hex-digit text, which the graph reads on with `hex` (Bacon of hex). In groups of
    five every value is 15 or less, so the zero symbol leads every group: that pins the polarity (a/b with
    b as zero reads too)."""
    for invert in (False, True):
        got = _two_symbol_groups(b, (4, 5), invert)
        if got is None:
            return None
        vals, width = got
        if len(vals) >= 2 and not len(vals) % 2 and all(v <= 15 for v in vals):
            return _changed(b, "".join(HEX_DIGITS[v] for v in vals).encode("ascii"))
    return None


_TAP_SQUARE = "abcdefghijlmnopqrstuvwxyz"     # k is written as c
_TAP_RE = re.compile(rb"[.*xX \t\r\n/|]+")


def _tap_runs(b: bytes) -> Optional[list[list[int]]]:
    """Words of (row, column) pairs from a tap-code text: runs of one knock mark, single spaces between the
    two halves of a letter, two or more (or / or |) between letters/words."""
    s = b.strip()
    if len(s) < 3 or not _TAP_RE.fullmatch(s):
        return None
    marks = set(s) - set(b" \t\r\n/|")
    if len(marks) != 1:
        return None
    mark = re.escape(bytes(marks))
    words = []
    for w in re.split(rb"\s*[/|]\s*|\n", s):
        runs = [len(r) for r in re.findall(mark + rb"+", w)]
        if not runs:
            continue
        if len(runs) % 2:
            return None
        words.append(runs)
    return words or None


def _tap(b: bytes, square: str, side: int):
    words = _tap_runs(b)
    if words is None:
        return None
    out = []
    for runs in words:
        if any(r > side for r in runs):
            return None
        out.append("".join(square[(runs[i] - 1) * side + runs[i + 1] - 1] for i in range(0, len(runs), 2)))
    sep = "" if square is HEX_DIGITS else " "
    return _changed(b, sep.join(out).encode("ascii"))


def d_tap(b: bytes):
    """Tap code over the 5x5 square (k = c): letters."""
    return _tap(b, _TAP_SQUARE, 5)


def d_taphex(b: bytes):
    """Tap code over a 4x4 square of hex digits: the hex-digit text (tap of hex)."""
    return _tap(b, HEX_DIGITS, 4)


_POLY_SQUARE = "abcdefghiklmnopqrstuvwxyz"    # j is written as i
_POLY_RE = re.compile(rb"[1-5]{2}(?:[\s,/]*[1-5]{2})*")


def _polybius(b: bytes, square: str, side: int):
    s = b.strip()
    if len(s) < 4 or not _POLY_RE.fullmatch(s):
        return None
    words = []
    for w in re.split(rb"\s{2,}|\s*/\s*|\n", s):
        digits = re.sub(rb"[\s,]", b"", w)
        if not digits:
            continue
        if len(digits) % 2:
            return None
        pairs = [(digits[i] - 48, digits[i + 1] - 48) for i in range(0, len(digits), 2)]
        if any(r > side or c > side for r, c in pairs):
            return None
        words.append("".join(square[(r - 1) * side + c - 1] for r, c in pairs))
    if not words:
        return None
    sep = "" if square is HEX_DIGITS else " "
    return _changed(b, sep.join(words).encode("ascii"))


def d_polybius(b: bytes):
    """Polybius square 5x5 (i = j), coordinates row then column: letters."""
    return _polybius(b, _POLY_SQUARE, 5)


def d_polyhex(b: bytes):
    """Polybius coordinates over a 4x4 square of hex digits: the hex-digit text (Polybius of hex)."""
    return _polybius(b, HEX_DIGITS, 4)


# ------------------------------------------------------------------------------------- loose codecs

def _rot_letters(b: bytes, n: int) -> bytes:
    out = bytearray(b)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = (c - 65 + n) % 26 + 65
        elif 97 <= c <= 122:
            out[i] = (c - 97 + n) % 26 + 97
    return bytes(out)


def _has_letters(b: bytes) -> bool:
    return any(65 <= c <= 90 or 97 <= c <= 122 for c in b)


def d_rot13(b: bytes):
    return _changed(b, _rot_letters(b, 13)) if _has_letters(b) else None


def _caesar(n: int) -> Decode:
    def dec(b: bytes):
        return _changed(b, _rot_letters(b, -n)) if _has_letters(b) else None
    dec.__name__ = f"d_caesar{n}"
    return dec


def d_rot47(b: bytes):
    return _changed(b, bytes(33 + (c - 33 + 47) % 94 if 33 <= c <= 126 else c for c in b))


def d_atbash(b: bytes):
    out = bytearray(b)
    for i, c in enumerate(out):
        if 65 <= c <= 90:
            out[i] = 155 - c
        elif 97 <= c <= 122:
            out[i] = 219 - c
    return _changed(b, out)


def d_reverse(b: bytes):
    return _changed(b, b[::-1])


def d_swapcase(b: bytes):
    return _changed(b, b.swapcase()) if _has_letters(b) else None


def _xor(k: int) -> Decode:
    def dec(b: bytes):
        return _changed(b, bytes(c ^ k for c in b))
    dec.__name__ = f"d_xor0x{k:02x}"
    return dec


def xor_text_keys(b: bytes) -> list[int]:
    """Single-byte keys (1..255) under which every byte of `b` becomes printable text: the only xor edges the
    graph takes (a key that leaves a control byte cannot be the layer above a text codec)."""
    distinct = set(b)
    return [k for k in range(1, 256) if all((c ^ k) in _PRINTABLE for c in distinct)]


def rail_decode(s: bytes, rails: int) -> Optional[bytes]:
    """Undo a rail fence of `rails` rails (zig-zag write, row-wise read)."""
    n = len(s)
    if rails < 2 or rails >= n:
        return None
    cycle = 2 * (rails - 1)
    rows = [min(i % cycle, cycle - i % cycle) for i in range(n)]
    order = sorted(range(n), key=lambda i: (rows[i], i))
    out = bytearray(n)
    for src, pos in enumerate(order):
        out[pos] = s[src]
    return bytes(out)


def _rail(n: int) -> Decode:
    def dec(b: bytes):
        return _changed(b, rail_decode(b, n))
    dec.__name__ = f"d_rail{n}"
    return dec


# -------------------------------------------------------------------------------------- the registry

def _mk(fn: Decode, kind: str, text_only: bool = False) -> Codec:
    return Codec(fn.__name__[2:], kind, fn, (fn.__doc__ or "").strip().split("\n")[0], text_only)


CORE: tuple[Codec, ...] = (
    _mk(d_gzip, STRICT), _mk(d_zlib, STRICT), _mk(d_bz2, STRICT), _mk(d_xz, STRICT),
    _mk(d_utf16, STRICT),
    _mk(d_hex, STRICT, True), _mk(d_b64, STRICT, True), _mk(d_b64url, STRICT, True), _mk(d_b32, STRICT, True),
    _mk(d_b85, STRICT, True), _mk(d_a85, STRICT, True), _mk(d_b58, STRICT, True),
    _mk(d_binary, STRICT, True), _mk(d_octal, STRICT, True), _mk(d_decimal, STRICT, True),
    _mk(d_url, STRICT, True), _mk(d_html, STRICT, True), _mk(d_runlength, STRICT, True),
    _mk(d_morse, SYMBOL, True), _mk(d_bacon, SYMBOL, True), _mk(d_bacon24, SYMBOL, True),
    _mk(d_baconhex, SYMBOL, True), _mk(d_tap, SYMBOL, True), _mk(d_taphex, SYMBOL, True),
    _mk(d_polybius, SYMBOL, True), _mk(d_polyhex, SYMBOL, True),
    _mk(d_rot13, LOOSE, True), _mk(d_rot47, LOOSE, True), _mk(d_atbash, LOOSE, True),
    _mk(d_reverse, LOOSE), _mk(d_swapcase, LOOSE, True),
    *(_mk(_caesar(n), LOOSE, True) for n in range(1, 26) if n != 13),
    *(_mk(_rail(n), KEYED, True) for n in range(2, RAIL_MAX + 1)),
)
# xor is a family the graph enumerates per state (xor_text_keys), never all 255 keys blindly; its
# names are still resolvable so a chain re-applies.
XOR_PREFIX = "xor0x"


def core() -> tuple[Codec, ...]:
    return CORE


def by_name(name: str, codecs=None) -> Codec:
    """The codec called `name` in `codecs` (default: the core set), parameterised families included.
    CodecError for an unknown name."""
    for c in (codecs if codecs is not None else CORE):
        if c.name == name:
            return c
    m = re.fullmatch(r"xor0x([0-9a-f]{2})", name)
    if m and int(m.group(1), 16):
        return Codec(name, LOOSE, _xor(int(m.group(1), 16)))
    raise CodecError(f"unknown codec {name!r}")


def apply_chain(data: bytes, chain, codecs=None) -> Optional[bytes]:
    """Decode `data` through `chain` (codec names, outermost first). None when a step refuses.
    CodecError for an unknown name."""
    cur = bytes(data)
    for name in chain:
        cur = by_name(name, codecs).decode(cur)
        if cur is None:
            return None
    return cur


def representation_steps(chain, codecs=None) -> list[str]:
    """The steps of `chain` that are representation changes (strict, symbol or pack). A dotted name
    (`<pack>.<name>`) is a pack codec even when `codecs` does not hold it."""
    out = []
    for name in chain:
        try:
            if by_name(name, codecs).kind in REPRESENTATION:
                out.append(name)
        except CodecError:
            if "." in name:
                out.append(name)
    return out


def iter_kind(codecs, *kinds) -> Iterator[Codec]:
    return (c for c in codecs if c.kind in kinds)
