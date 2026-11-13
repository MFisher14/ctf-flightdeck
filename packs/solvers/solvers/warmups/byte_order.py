"""Day 21 look-ahead build (2026-10-20): strict readers for byte-order twists the older readers do not know.

Day 19 ("Little Things") was hex of UTF-16 little-endian, Day 20 ("Big Entrance") hex of UTF-16 big-endian, both
with a byte order mark. The neighbours of that pun that no reader of crib_decode, layered_decode or formats_more
read (docs/retro/day-21-predictions-warmups.md):

  wide     text in units of 2 or 4 bytes with ONE byte of each unit carrying the character and every other byte
           NUL, the carrying place the same in every unit, a byte order mark (its two bytes fe and ff, the rest
           NUL) at the start or the end or none. It reads only what the standard decoders do not: the mixed
           orders of UTF-32 (PDP-11 "middle-endian" 1032, half-swapped 2301), a byte order mark that lies
           (fe ff before little-endian units, ff fe before big-endian ones), and a mark at the END (the bytes
           of a UTF-16 text written last to first: the characters are given back in their order). A standard
           layout with no mark or its own mark is left to utf16, utf16be and utf32, so no day chain changes its
           name.
  hexnibw  hex of bytes whose two nibbles were swapped, where the bytes are a wide text (formats_more.d_hexnib
           takes only printable bytes, so UTF-16 with its NULs was refused); it gives the bytes, and utf16,
           utf16be, utf32 or wide reads them.
  hexbitsw the same for bytes whose eight bits were mirrored.
  od       an od(1) or hexdump(1) listing: an offset (7 octal digits or 6 to 8 hex) and tokens of one width per
           line: 2 hex digits (od -t x1), 4 (od -x, hexdump: 16-bit words, LOW byte first), 8 (od -t x4,
           32-bit words, low byte first), 3 octal digits (od -b), 6 octal digits (od -o, 16-bit words); the
           last line's bare offset, when there is one, is the length (od pads an odd byte).
  bomtok   a byte order mark written as the first token of a list of code points (65279, 0xFEFF, U+FEFF,
           \\ufeff, &#65279;) with a separator or its own delimiters after it; the list after it is read on.

All are all-or-nothing: every unit, every line, every token is in the form, or the reader refuses, and the
sentence still has to come out of what they give. Each costs a look at the first bytes of a payload that is not
in its form. Loaded by name: a copy of the folder without this file reads as before.
"""
import re

WALKING = [False]   # True while crib_decode's walk by the days reads a record (crib_decode._walking sets it)
MIN_UNITS = 8       # characters a wide text must have outside the walk (a Mastery record holds 4 to 7)
MAX_BYTES = 1 << 16

def _is_bom(unit: bytes) -> bool:
    """A byte order mark written in any order: fe and ff once each, every other byte NUL."""
    return sorted(unit) == [0] * (len(unit) - 2) + [0xFE, 0xFF]


_OWN = {(2, 0): b"\xff\xfe", (2, 1): b"\xfe\xff", (4, 0): b"\xff\xfe\x00\x00", (4, 3): b"\x00\x00\xfe\xff"}


def wide_shape(b: bytes, standard: bool = True):
    """(width, place, mark) of a wide text, or None. mark is 'start', 'end' or None. With standard=False a
    layout the standard decoders read (UTF-16 or UTF-32, either byte order, no mark or its own) is refused,
    before the bytes are looked at past the first unit (Days 19 and 20 pay one look)."""
    n = len(b)
    if n < 4 or n > MAX_BYTES or b"\x00" not in b[:8]:
        return None
    floor = 1 if WALKING[0] else MIN_UNITS
    for w in (2, 4):
        if n % w:
            continue
        head, tail, mark, body = b[:w], b[-w:], None, b
        if _is_bom(head):
            mark, body = "start", b[w:]
        elif _is_bom(tail):
            mark, body = "end", b[:-w]
        units = len(body) // w
        if units < floor or not units:
            continue
        places = [i for i in range(w) if body[i]]
        if len(places) != 1:
            continue
        p = places[0]
        if not standard and (w == 2 or p in (0, w - 1)) and (mark is None or (mark == "start" and head == _OWN[w, p])):
            continue
        if 0 in body[p::w] or any(body[q::w].count(0) != units for q in range(w) if q != p):
            continue
        return w, p, mark
    return None


def d_wide(b: bytes):
    shape = wide_shape(b, standard=False)
    if shape is None:
        return None
    w, p, mark = shape
    body = b[w:] if mark == "start" else b[:-w] if mark == "end" else b
    out = body[p::w]
    if mark == "end":   # a mark at the end: the bytes were written last to first, so the characters run back
        out = out[::-1]
    return out if out and b"\x00" not in out else None


_HEX_BYTES = re.compile(r"(?:0x|\\x)?([0-9a-fA-F]{2})")
_HEX_SEP = re.compile(r"[\s:,;]+")
_NIBBLES = bytes(((x << 4) | (x >> 4)) & 0xFF for x in range(256))
_MIRROR = bytes(int(f"{x:08b}"[::-1], 2) for x in range(256))


def _hex_turned(b: bytes, table: bytes):
    try:
        t = b.decode("ascii")
    except UnicodeDecodeError:
        return None
    # A look at the first 16 bytes first: a NUL among them, and every other byte, turned, a printable character
    # or a mark byte, where as it stands one is not (hex of a text the standard readers read costs only this).
    head = bytes.fromhex("".join(_HEX_BYTES.findall(_HEX_SEP.sub("", t[:160]))[:16]))
    turned = head.translate(table)
    if b"\x00" not in head or not all(x == 0 or 32 <= x < 127 or x >= 0xFE for x in turned):
        return None
    if all(x == 0 or 32 <= x < 127 or x >= 0xFE for x in head):
        return None
    compact = _HEX_SEP.sub("", t)
    if len(compact) < 16 or len(compact) % 2:
        return None
    pairs = _HEX_BYTES.findall(compact)
    if sum(len(m.group(0)) for m in _HEX_BYTES.finditer(compact)) != len(compact):
        return None
    out = bytes.fromhex("".join(pairs)).translate(table)
    return out if wide_shape(out) else None


def d_hexnibw(b: bytes):
    return _hex_turned(b, _NIBBLES)


def d_hexbitsw(b: bytes):
    return _hex_turned(b, _MIRROR)


_INVERT = bytes(x ^ 0xFF for x in range(256))


def d_hexinv(b: bytes):
    """Wave 2 (built 2026-10-21): hex of a wide text (UTF-16 / UTF-32 with its NUL fill) with every byte
    inverted (xor 0xff), so the NUL fill is written `ff` and a printable byte 81..df. layered_decode's xor
    steps are loose and run on the payload itself, not as a strict decode into a wide text, so this was None on
    both trees (the last row of the candidate table in docs/retro/day-21-predictions-warmups.md, "hex of
    UTF-16BE with every byte inverted (xor ff)"). All or nothing, as hexnibw and hexbitsw: it gives the
    inverted bytes, and wide, utf16, utf16be or utf32 reads them, so the sentence still has to come out. The
    head look mirrors _hex_turned's but for the OTHER polarity (a wide text's NUL fill inverts to 0xff, so the
    raw hex holds ff where the plain cases hold 00); a layout the standard readers already read as it stands is
    left to them."""
    try:
        t = b.decode("ascii")
    except UnicodeDecodeError:
        return None
    compact = _HEX_SEP.sub("", t)
    head = bytes.fromhex("".join(_HEX_BYTES.findall(compact[:160])[:16]))
    turned = head.translate(_INVERT)
    # the inverted NUL fill of a wide text is 0xff in the raw bytes; turned must then look like a wide text
    # (a NUL among its first bytes, every byte NUL/printable/mark) where the raw bytes as they stand do not.
    if 0xFF not in head or 0 not in turned:
        return None
    if not all(x == 0 or 32 <= x < 127 or x >= 0xFE for x in turned):
        return None
    if all(x == 0 or 32 <= x < 127 or x >= 0xFE for x in head):   # already a wide text as it stands: wide's / hex's
        return None
    if len(compact) < 16 or len(compact) % 2:
        return None
    if sum(len(m.group(0)) for m in _HEX_BYTES.finditer(compact)) != len(compact):
        return None
    out = bytes.fromhex("".join(_HEX_BYTES.findall(compact))).translate(_INVERT)
    return out if wide_shape(out) else None


_OD_LINE = re.compile(r"([0-9a-fA-F]{6,8})((?:[ \t]+[0-9a-fA-F]+)*)[ \t]*")
_OD_KINDS = {  # token width -> (digits, bytes per token, base)
    2: (r"[0-9a-fA-F]{2}", 1, 16),
    4: (r"[0-9a-fA-F]{4}", 2, 16),
    8: (r"[0-9a-fA-F]{8}", 4, 16),
    3: (r"[0-7]{3}", 1, 8),
    6: (r"[0-7]{6}", 2, 8),
}


def d_od(b: bytes):
    try:
        t = b.decode("ascii")
    except UnicodeDecodeError:
        return None
    lines = [ln for ln in t.splitlines() if ln.strip()]
    if len(lines) < 2:
        return None
    rows, offsets, tail = [], [], None
    for i, ln in enumerate(lines):
        m = _OD_LINE.fullmatch(ln.strip())
        if not m:
            return None
        toks = m.group(2).split()
        if not toks:
            if i != len(lines) - 1:
                return None
            tail = m.group(1)
            continue
        offsets.append(m.group(1))
        rows.append(toks)
    if not rows:
        return None
    width = len(rows[0][0])
    kind = _OD_KINDS.get(width)
    if kind is None:
        return None
    pat, size, base = kind
    tok = re.compile(pat)
    per = len(rows[0]) * size
    # the offsets: octal (od) or hex (hexdump, od -A x), each line's offset the bytes before it
    obase = None
    for cand in (8, 16):
        try:
            vals = [int(o, cand) for o in offsets]
        except ValueError:
            continue
        if all(v == i * per for i, v in enumerate(vals)):
            obase = cand
            break
    if obase is None:
        return None
    out = bytearray()
    for r, toks in enumerate(rows):
        if r < len(rows) - 1 and len(toks) * size != per:
            return None
        for x in toks:
            if len(x) != width or not tok.fullmatch(x):
                return None
            out += int(x, base).to_bytes(size, "little")
    if tail is not None:
        try:
            length = int(tail, obase)
        except ValueError:
            return None
        if not len(out) - size < length <= len(out):
            return None
        if any(out[length:]):
            return None
        del out[length:]
    return bytes(out) if len(out) >= 8 else None


# A byte order mark written as the first token of a list of code points: 65279, 0xFEFF, U+FEFF, ﻿, &#65279;
# or &#xFEFF; with a separator after it (a bare 'feff' run into the hex after it is Day 20's own text, left alone).
_BOMTOK = re.compile(rb"\s*(?:(?:65279|(?:0x|U\+)?feff)[\s,;]+|\\u\{?feff\}?|&#(?:65279|x0*feff);)", re.I)


def d_bomtok(b: bytes):
    m = _BOMTOK.match(b)
    rest = b[m.end():] if m else b""
    return rest if len(rest.strip()) >= 8 else None


BY_NAME = {"wide": d_wide, "hexnibw": d_hexnibw, "hexbitsw": d_hexbitsw, "od": d_od, "bomtok": d_bomtok}
NAMES = frozenset(BY_NAME)
_HEXISH = re.compile(rb"(?:\\x|0x)?[0-9a-fA-F]{2}")
_ODISH = re.compile(rb"[0-9a-fA-F]{6,8}[ \t]+[0-9a-fA-F]{2}")
_FFISH = re.compile(rb"[fF]{2}")   # the inverted NUL fill of a wide text (Wave 2, hexinv)


def _which(cur: bytes) -> tuple:
    """The readers worth asking on this payload, by a look at its first bytes."""
    if not 4 <= len(cur) <= MAX_BYTES:
        return ()
    if b"\x00" in cur[:8]:
        return ("wide",)
    if not cur[:1].isascii():
        return ()
    names = ()
    if _BOMTOK.match(cur):
        names += ("bomtok",)
    if _ODISH.match(cur):
        names += ("od",)
    if b"00" in cur[:96] and _HEXISH.match(cur):   # hex of a wide text holds NUL bytes from its start
        names += ("hexnibw", "hexbitsw")
    if _HEXISH.match(cur) and _FFISH.search(cur[:96]):   # Wave 2: inverted hex holds ff where the fill was
        names += ("hexinv",)
    return names


def steps(cur: bytes) -> list:
    """[(name, bytes)]: what the readers of this module make of one payload."""
    out = []
    for name in _which(cur):
        try:
            o = BY_NAME[name](cur)
        except Exception:
            o = None
        if o:
            out.append((name, o))
    return out


def step_fn(name: str):
    """The decoder (bytes -> bytes or None) of one step by its name, or None."""
    fn = BY_NAME.get(name)
    if fn is None:
        return None

    def f(b):
        return fn(b) if name in _which(b) else None
    f.__name__ = "d_" + name
    return f


# ---------------------------------------------------------------------------- Day 21 final prep
# mojibake16: a text in UTF-16 read in the other byte order and written out as UTF-8 (every unit's two bytes
# swapped: 'Ni' of UTF-16LE read as UTF-16BE is U+4E00 U+6900), with or without its mark (U+FEFF read in the other
# order is U+FFFE), or the \uXXXX / &#x...; escapes of such a text (uesc and html give the UTF-8 first, then this
# step). Swapping the bytes of each unit is the one inverse: re-encoding as UTF-16BE and decoding as UTF-16LE, or
# the reverse, give the same text. mojibake8 / mojibake8be: 8-bit text read as UTF-16 (two characters a unit),
# given back as the unit's bytes in LE or BE order. All three apply only where the text decodes as UTF-8 to at
# least 8 code points (1 inside the walk by the days), at least 90 % of them (all, inside the walk) in
# U+0100..U+FFFF, and at least 90 % of those units with a low byte of 0x00 or 0x20..0x7e; an ASCII payload never
# qualifies (the look is one byte), and what they give must be printable ASCII, or nothing. Plain, as every
# strict step: the sentence still has to come out of it.
MOJI_FLOOR = 8
_MOJI_LEADS = frozenset(range(0xE1, 0xF0))   # the lead byte of a UTF-8 character of U+1000..U+FFFF
_ASCII_TEXT = re.compile(rb"[\x20-\x7e\t\r\n]*")
_EDGE = " \t\r\n"
_LEAD_WS = re.compile(rb"[ \t\r\n]*")


def _moji_text(b: bytes):
    """(lead, core, trail) of a payload that qualifies, or None: the UTF-8 text without the ASCII white space at
    its edges (kept as it stands) and without a leading mark read in either order."""
    if len(b) < 3:
        return None
    i = _LEAD_WS.match(b).end()
    if i >= len(b) or b[i] not in _MOJI_LEADS:
        return None
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    core = t.strip(_EDGE)
    lead = t[:len(t) - len(t.lstrip(_EDGE))]
    trail = t[len(lead) + len(core):]
    if core[:1] in ("﻿", "￾"):
        core = core[1:]
    n = len(core)
    if n < (1 if WALKING[0] else MOJI_FLOOR):
        return None
    wide = [ord(c) for c in core if 0x100 <= ord(c) <= 0xFFFF]
    if len(wide) < (n if WALKING[0] else -(-9 * n // 10)):
        return None
    low = sum(1 for u in wide if (u & 0xFF) == 0 or 0x20 <= (u & 0xFF) <= 0x7E)
    if low < (len(wide) if WALKING[0] else -(-9 * len(wide) // 10)):
        return None
    return lead, core, trail


def _ascii_or_none(lead: str, body: bytes, trail: str):
    return (lead.encode() + body + trail.encode()) if body and _ASCII_TEXT.fullmatch(body) else None


def d_mojibake16(b: bytes):
    m = _moji_text(b)
    if m is None:
        return None
    lead, core, trail = m
    try:
        out = core.encode("utf-16-be").decode("utf-16-le")
    except UnicodeError:
        return None
    return _ascii_or_none(lead, out.lstrip("﻿").encode("utf-8"), trail)


def _mojibake8(b: bytes, codec: str):
    m = _moji_text(b)
    if m is None:
        return None
    lead, core, trail = m
    try:
        raw = core.encode(codec)
    except UnicodeError:
        return None
    return _ascii_or_none(lead, raw.rstrip(b"\x00"), trail)


def d_mojibake8(b: bytes):
    return _mojibake8(b, "utf-16-le")


def d_mojibake8be(b: bytes):
    return _mojibake8(b, "utf-16-be")


# ita2: Baudot-Murray (ITA2) 5-bit codes, as binary groups (`ita2`, the code's value written high bit first,
# A = 00011; `ita2rev`, the same bits low bit first, A = 11000), decimal values 0-31 (`ita2dec`) or hex values
# 00-1f (`ita2hex`), with LTRS 11111 and FIGS 11011 changing the shift; every token one code, every code defined
# in its shift (a national-use figure the sentence does not need is refused), NUL dropped. ITA2 has one case, so
# the text is given in small letters: the sentence proves the code, and the slug read through it is unsure under
# `warmups.case/ita2` (CASE_LOSSY below, which crib_decode registers) until the judge accepts `lower` for it.
ITA2_LTRS = {1: "e", 2: "\n", 3: "a", 4: " ", 5: "s", 6: "i", 7: "u", 8: "\r", 9: "d", 10: "r", 11: "j", 12: "n",
             13: "f", 14: "c", 15: "k", 16: "t", 17: "z", 18: "l", 19: "w", 20: "h", 21: "y", 22: "p", 23: "q",
             24: "o", 25: "b", 26: "g", 28: "m", 29: "x", 30: "v"}
ITA2_FIGS = {1: "3", 2: "\n", 3: "-", 4: " ", 5: "'", 6: "8", 7: "7", 8: "\r", 10: "4", 12: ",", 13: "!", 14: ":",
             15: "(", 16: "5", 17: "+", 18: ")", 19: "2", 21: "6", 22: "0", 23: "1", 24: "9", 25: "?", 28: ".",
             29: "/", 30: "="}
ITA2_FLOOR = 8   # codes outside the walk by the days
# Each form is one regular expression over the whole payload, so a payload not in it is refused at its first
# token that is not (a list of numbers up to 99 costs one failed match, not a parse).
_ITA_BIN_RUN = re.compile(rb"\s*((?:[01]{5})+)\s*")
_ITA_FORMS = {
    "bin": (re.compile(rb"\s*[01]{5}(?:[\s,;]+[01]{5})*[\s,;]*"), re.compile(rb"[01]{5}")),
    "dec": (re.compile(rb"\s*(?:3[01]|[0-2]?[0-9])(?:[\s,;]+(?:3[01]|[0-2]?[0-9]))*[\s,;]*"), re.compile(rb"[0-9]+")),
    "hex": (re.compile(rb"\s*(?:0[xX][01]?[0-9a-fA-F]|[01][0-9a-fA-F])(?:[\s,;]+(?:0[xX][01]?[0-9a-fA-F]|[01][0-9a-fA-F]))*"
                       rb"[\s,;]*"), re.compile(rb"(?<![0-9a-fA-FxX])(?:0[xX])?([0-9a-fA-F]+)")),
}


def _ita2_tokens(b: bytes, kind: str):
    if kind in ("ita2", "ita2rev"):
        form, tok = _ITA_FORMS["bin"]
        if form.fullmatch(b):
            toks = tok.findall(b)
        else:
            m = _ITA_BIN_RUN.fullmatch(b)
            if not m:
                return None
            run = m.group(1)
            toks = [run[i:i + 5] for i in range(0, len(run), 5)]
        return [int(x[::-1] if kind == "ita2rev" else x, 2) for x in toks]
    form, tok = _ITA_FORMS["dec" if kind == "ita2dec" else "hex"]
    if not form.fullmatch(b):
        return None
    return [int(x) for x in tok.findall(b)] if kind == "ita2dec" else [int(x, 16) for x in tok.findall(b)]


def _ita2(b: bytes, kind: str, usos: bool = False):
    """usos=True is unshift-on-space (Wave 2): a SPACE returns the shift to letters, so an encoder that relies
    on it omits the LTRS code after a space. It is the one divergence from standard ITA2, and it bites a
    warmups blob because the sentence has `! To` (a figure, then a space, then letters): a standard decoder
    stays in figures after the space and reads `To` as `5o`, so d_ita2 refuses the blob (None) and only this
    form reads it. Where the text has no figure-then-space-then-letter the two decode identically, so a
    standard blob is read the same way and offered the same unsure value."""
    if not b.isascii():
        return None
    vals = _ita2_tokens(b, kind)
    if not vals or len(vals) < (1 if WALKING[0] else ITA2_FLOOR):
        return None
    out, table, letters = [], ITA2_LTRS, 0
    for v in vals:
        if v == 31:
            table = ITA2_LTRS
        elif v == 27:
            table = ITA2_FIGS
        elif v:
            c = table.get(v)
            if c is None:
                return None
            letters += c.isalpha()
            out.append(c)
            if usos and c == " ":
                table = ITA2_LTRS
    return "".join(out).encode() if out and (letters or WALKING[0]) else None


def d_ita2(b):
    return _ita2(b, "ita2")


def d_ita2rev(b):
    return _ita2(b, "ita2rev")


def d_ita2dec(b):
    return _ita2(b, "ita2dec")


def d_ita2hex(b):
    return _ita2(b, "ita2hex")


def d_ita2usos(b):
    return _ita2(b, "ita2", usos=True)


def d_ita2usosrev(b):
    return _ita2(b, "ita2rev", usos=True)


def d_ita2usosdec(b):
    return _ita2(b, "ita2dec", usos=True)


def d_ita2usoshex(b):
    return _ita2(b, "ita2hex", usos=True)


FINAL = {"mojibake16": d_mojibake16, "mojibake8": d_mojibake8, "mojibake8be": d_mojibake8be, "ita2": d_ita2,
         "ita2rev": d_ita2rev, "ita2dec": d_ita2dec, "ita2hex": d_ita2hex}
FINAL_NAMES = frozenset(FINAL)
LOOKAHEAD_NAMES = NAMES          # the look-ahead build's five, for its own marker line
BY_NAME.update(FINAL)
# Wave 2 (2026-10-21): added behind LOOKAHEAD_NAMES and FINAL_NAMES so each marker keeps its own steps.
# hexinv: inverted hex of a wide text (plain). ita2usos*: ITA2 with unshift-on-space (unsure, warmups.case/ita2).
WAVE2 = {"hexinv": d_hexinv, "ita2usos": d_ita2usos, "ita2usosrev": d_ita2usosrev,
         "ita2usosdec": d_ita2usosdec, "ita2usoshex": d_ita2usoshex}
WAVE2_NAMES = frozenset(WAVE2)
BY_NAME.update(WAVE2)
NAMES = frozenset(BY_NAME)
CASE_LOSSY = {"ita2": "ita2", "ita2rev": "ita2", "ita2dec": "ita2", "ita2hex": "ita2",   # step -> warmups.case/<form>
              "ita2usos": "ita2", "ita2usosrev": "ita2", "ita2usosdec": "ita2", "ita2usoshex": "ita2"}
_ITA_HEAD_BIN = re.compile(rb"\s*[01]{5}(?:[\s,;]|[01]{5}|$)")
_ITA_HEAD_NUM = re.compile(rb"\s*(0x)?([0-9a-fA-F]{1,2})(?:[\s,;]|$)")


def _which_final(cur: bytes) -> tuple:
    """The final-prep readers worth asking on this payload, by a look at its first bytes (never raises)."""
    i = _LEAD_WS.match(cur).end() if cur[0] in b" \t\r\n" else 0   # no copy of the payload
    if i >= len(cur):
        return ()
    c = cur[i]
    if c in _MOJI_LEADS:
        return ("mojibake16", "mojibake8", "mojibake8be")
    if c > 0x7F:
        return ()
    if c in (0x30, 0x31) and _ITA_HEAD_BIN.match(cur):
        return ("ita2", "ita2rev")
    m = _ITA_HEAD_NUM.match(cur)
    if not m:
        return ()
    tok, names = m.group(2), ()
    if not m.group(1) and tok.isdigit() and int(tok) < 32:
        names += ("ita2dec",)
    if (m.group(1) or len(tok) == 2) and int(tok, 16) < 32:
        names += ("ita2hex",)
    return names


_ITA2_USOS = {"ita2": "ita2usos", "ita2rev": "ita2usosrev", "ita2dec": "ita2usosdec", "ita2hex": "ita2usoshex"}


def _wave2_from_final(final_names: tuple) -> tuple:
    """Wave 2's ITA2 unshift-on-space forms, worth asking wherever the standard ITA2 forms are (same token
    shapes); kept out of _which_final so that function's names stay the final prep's own."""
    return tuple(_ITA2_USOS[n] for n in final_names if n in _ITA2_USOS)


def _which_wave2(cur: bytes) -> tuple:
    return _wave2_from_final(_which_final(cur))


_which_lookahead = _which


def _which(cur: bytes) -> tuple:   # noqa: F811 (the look-ahead's look, then the final prep's, then Wave 2's)
    names = _which_lookahead(cur)
    if 1 <= len(cur) <= MAX_BYTES:
        final = _which_final(cur)
        names += final + _wave2_from_final(final)
    return names
