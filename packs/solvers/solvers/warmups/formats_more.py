#!/usr/bin/env python3
"""More Warmups formats (Day 9 round 2): what docs/day9-readiness.md listed as not built.

  .venv/bin/python solvers/warmups/formats_more.py <blob-file> [...]     every reading of each file, by name

crib_decode.py loads this module by name and asks it in three places. Without it (an armed export
that lacks the file) crib_decode.py runs exactly as before. Nothing here answers: every reading still
has to reproduce the Warmups sentence in crib_decode's search, or is offered unsure.

1. steps(payload) -> [(name, bytes)]: STRICT readers, asked on every state of the search like
   crib_decode's own strict decoders (so they chain with every other encoding, to depth six, and
   read a Mastery record as well as a whole blob). Each refuses what is not in its form.
     punycode    xn--... (RFC 3492), and ASCII text with the delimiter '-' that punycode puts behind it
     b65536      base65536, b32768 base32768, b2048 base2048 (qntm's repertoires, formats_tables.py);
                 b2048r the other base2048 (the Rust crate and PyPI's base2048, another table and ending)
     ecoji       Ecoji version 1; ecoji2 version 2 (1024 emoji for ten bits each, both paddings)
     emojiaz     letters as regional indicators, negative squared or negative circled letters, digits
                 as keycaps; marks and spaces as they are (one space between letters is dropped)
     b62i b62l b62u   base62 as one number with the alphabets 0-9a-zA-Z, a-zA-Z0-9, A-Za-z0-9
                 (crib_decode's own b62 is 0-9A-Za-z); b58f and b58r base58 with Flickr's and Ripple's
     mixnum      character codes in mixed notations (0x4e 0b1101001 0o143 101, or 4Eh 151o 1100011b 101d)
     phonetic    spelling alphabets beyond ICAO (LAPD, Able Baker, RAF, Western Union, the German
                 one), figures and marks by name, letters joined by '-' inside words or one per token
     morsew      morse spelled dit/dah (dah-dit, "dot dash"); morseinv dots and dashes swapped (only
                 where ordinary morse does not already give text of the sentence's characters);
                 morseab / morseba any two symbols for dot and dash (01 00 1010 0);
                 morsetime timing bits (1 dot, 111 dash, 0 / 000 / 0000000 gaps) in any two symbols;
                 morsekeep morse from a table without '!' (or ',' ':'): the mark stands as itself between
                 the codes (Day 12 build; a form of morse, crib_decode.ALIAS)
     brdots      braille by dot numbers (1345 24 14 15); gives braille cells, which the braille readers read
     cow whitespace malbolge jsfuck    programs, run by esolangs.py under a step cap and the blob's deadline
                 (a Whitespace program has line feeds in it: it can be a whole blob, never one numbered record)
     roman       each byte as a Roman numeral (Day 18 build, B5); brhex Braille hex with the number sign
                 before every digit; upside upside-down text (its digits are unsure: OPEN_DIGITS)
2. late(text, crib, deadline) -> [(name, plain)]: readers that need the sentence or cost too much
   for every state; asked once per blob, only when nothing else answered (crib_decode.keyed).
     layout:<name>     a text typed on another keyboard layout (dvorak, colemak; '-' behind the name is
                       the other direction). Digits are where both layouts have them: unsure, like a
                       letter cipher's (warmups.digits/layout).
     cpshift:<n>       every character n code points higher (cpshift:<n>s: spaces left alone)
     symsub:<id>       one symbol for each character (emoji, pigpen-like fonts, any alphabet): the table
                       is read off the sentence; a slug character the sentence does not hold is no
                       reading, digits and '-' written as themselves pass (digits unsure)
     bases:<b.b.b>     character codes whose base changes from token to token in a cycle
     befunge:93        a Befunge-93 program
     hexsym:<how>.<id> the text as hex, each hex digit one of sixteen tokens, the table learned from the
                       sentence's 174 hex digits (Day 18 build, row 333); a keyed step like symsub, so a
                       slug-only Mastery record needs the delivery's vouch (a shuffled table reads wrong)
3. lossy(...): codes that cannot carry the whole sentence (no marks, no case, sometimes no spaces):
   A1Z26, multi-tap and T9 phone keys, a 6x6 Polybius square, flag semaphore written as arrows or
   compass points, and any strict reading that came out without its marks. The reading must give the
   sentence's 68 letters in order and then a slug in exactly one way; it is returned as ONE option for
   an unsure answer (warmups.lossy/<code>), never plain. T9 only when each of the three words has a
   single word of the vocabulary. Codes that cannot carry the two digits at all (Bacon, tap code, a
   5x5 Polybius square) stay None, as before.
"""
import hashlib
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
for _p in (HERE.parent / "common", HERE):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
import layered_decode as L  # noqa: E402
import formats_tables as T  # noqa: E402
import esolangs as E  # noqa: E402
try:
    from _shadowed import common_module  # noqa: E402
    K = common_module("classical")  # common/classical.py by file: toolkits/classical.py wins a flat import
except Exception:   # the lossy readers of classical.py are then not asked
    K = None

BIG = 8192                 # bytes: above this only the program readers are asked
PROGRAM_MAX = 1 << 20      # bytes of a program that is run at all
DEADLINE = [None]          # time.perf_counter() value the blob being read must not pass (crib_decode sets it)
WALKING = [False]          # True while crib_decode's day walk reads a record by its day's proved chain (Day 18 build)
_TEXT = re.compile(rb"[\x20-\x7e\t\r\n]+")
_SPACE = re.compile(r"\s+")


def _deadline():
    d = DEADLINE[0]
    return d if d is not None else time.perf_counter() + 0.5


# ---------------------------------------------------------------------------- qntm's base-N in Unicode

def _expand(pairs: str) -> list:
    return [chr(c) for i in range(0, len(pairs), 2) for c in range(ord(pairs[i]), ord(pairs[i + 1]) + 1)]


def _qntm(pairs: str, last_pairs: str, bits: int, flip: bool = False):
    """The decoder of one of qntm's encodings: `bits` per character, the most significant first; a
    character of the second repertoire carries bits - 8 and may only stand last; what is left over
    must be the padding of ones. base65536 takes its two bytes in the other order (flip)."""
    table = {}
    for z, ch in enumerate(_expand(pairs)):
        table[ch] = (bits, ((z & 255) << 8 | z >> 8) if flip else z)
    for z, ch in enumerate(_expand(last_pairs)):
        table[ch] = (bits - 8, z)

    def f(t: str):
        acc = nbits = 0
        out = bytearray()
        last = len(t) - 1
        for i, ch in enumerate(t):
            got = table.get(ch)
            if got is None or (got[0] != bits and i != last):
                return None
            acc = (acc << got[0]) | got[1]
            nbits += got[0]
            while nbits >= 8:
                nbits -= 8
                out.append((acc >> nbits) & 255)
            acc &= (1 << nbits) - 1
        if acc != (1 << nbits) - 1:
            return None
        return bytes(out)
    return f


_B65536 = _qntm(T.BASE65536_PAIRS, T.BASE65536_LAST_PAIRS, 16, True)
_B32768 = _qntm(T.BASE32768_PAIRS, T.BASE32768_LAST_PAIRS, 15)
_B2048 = _qntm(T.BASE2048_PAIRS, T.BASE2048_LAST_PAIRS, 11)


def _unicode_base(fn):
    def f(t: str):
        t = _SPACE.sub("", t)
        return fn(t) if t else None
    return f


def _b2048r(t: str):
    """The Rust crate base2048 and its Python binding (PyPI base2048), which is not qntm's base2048: the
    table index is the eleven-bit value; the last character holds what is left to the byte boundary (four
    to eleven bits, right-aligned), or is one of eight tail characters when one to three bits are left."""
    acc = nbits = 0
    out = bytearray()
    last = len(t) - 1
    for i, ch in enumerate(t):
        v, k = _B2048R_TAIL.get(ch), (-11 * i) % 8
        if v is not None:
            if i != last or not 1 <= k <= 3:
                return None
        else:
            v = _B2048R.get(ch)
            if v is None:
                return None
            k = 11 if i != last else k + 8 if k < 4 else k
        if v >> k:
            return None
        acc = (acc << k) | v
        nbits += k
        while nbits >= 8:
            nbits -= 8
            out.append((acc >> nbits) & 255)
        acc &= (1 << nbits) - 1
    return bytes(out) if nbits == 0 and out else None


_B2048R = {ch: i for i, ch in enumerate(getattr(T, "BASE2048R", ""))}
_B2048R_TAIL = {ch: i for i, ch in enumerate(getattr(T, "BASE2048R_TAIL", ""))}

d_b65536 = _unicode_base(_B65536)
d_b32768 = _unicode_base(_B32768)
d_b2048 = _unicode_base(_B2048)
d_b2048r = _unicode_base(_b2048r)


def qntm_encode(data: bytes, pairs: str, last_pairs: str, bits: int, flip: bool = False) -> str:
    """The encoder (for tests and the command line), written from the same description as the decoder."""
    rep, last = _expand(pairs), _expand(last_pairs)
    out, acc, nbits = [], 0, 0
    for b in data:
        acc, nbits = (acc << 8) | b, nbits + 8
        if nbits >= bits:
            nbits -= bits
            z = acc >> nbits
            out.append(rep[((z & 255) << 8 | z >> 8) if flip else z])
            acc &= (1 << nbits) - 1
    if nbits:
        if nbits <= bits - 8:
            out.append(last[(acc << (bits - 8 - nbits)) | ((1 << (bits - 8 - nbits)) - 1)])
        else:
            out.append(rep[(acc << (bits - nbits)) | ((1 << (bits - nbits)) - 1)])
    return "".join(out)


# ---------------------------------------------------------------------------- Ecoji and emoji letters

def _ecoji(table: str, last: str):
    index = {ch: i for i, ch in enumerate(table)}
    lasts = {ch: i for i, ch in enumerate(last)}
    pad = T.ECOJI_PAD

    def f(t: str):
        t = _SPACE.sub("", t)
        if len(t) < 2:
            return None
        out, i, n = bytearray(), 0, len(t)
        while i < n:
            group = t[i:i + 4]
            i += 4
            vals = []
            for j, ch in enumerate(group):
                if ch == pad:
                    if j == 0 or any(c != pad for c in group[j:]) or i < n:
                        return None           # padding only ends the text
                    break
                if j == 3 and ch in lasts:
                    vals.append(("last", lasts[ch]))
                    continue
                if ch not in index:
                    return None
                vals.append(index[ch])
            count = len(vals)
            if count == 4 and isinstance(vals[3], tuple):
                bits = vals[0] << 30 | vals[1] << 20 | vals[2] << 10 | vals[3][1] << 8
                out += (bits >> 8).to_bytes(4, "big")
                if i < n:
                    return None
                continue
            if any(isinstance(v, tuple) for v in vals):
                return None
            if count < 4 and i < n:
                return None
            bits = 0
            for v in vals:
                bits = bits << 10 | v
            bits <<= 10 * (4 - count)
            whole = bits.to_bytes(5, "big")
            if count == 4:
                out += whole
            else:                              # 1, 2 or 3 emoji before the padding: 1, 2 or 3 bytes
                if len(group) == count:
                    return None                # a short group without its padding
                if any(whole[count:]):
                    return None                # bits behind the last byte must be zero
                out += whole[:count]
        return bytes(out)
    return f


d_ecoji = _ecoji(T.ECOJI_V1, T.ECOJI_LAST_V1)
d_ecoji2 = _ecoji(T.ECOJI_V2, T.ECOJI_LAST_V2)


def ecoji_encode(data: bytes, version: int = 1) -> str:
    """Ecoji as its Go source writes it (for tests): version 2 trims the padding of a short last group."""
    table, last = (T.ECOJI_V1, T.ECOJI_LAST_V1) if version == 1 else (T.ECOJI_V2, T.ECOJI_LAST_V2)
    out = []
    for i in range(0, len(data), 5):
        s = data[i:i + 5]
        bits = int.from_bytes(s + bytes(5 - len(s)), "big")
        e = [table[bits >> 30], table[bits >> 20 & 1023], table[bits >> 10 & 1023], table[bits & 1023]]
        if len(s) == 1:
            out += [e[0], T.ECOJI_PAD] + ([T.ECOJI_PAD] * 2 if version == 1 else [])
        elif len(s) == 2:
            out += e[:2] + [T.ECOJI_PAD] + ([T.ECOJI_PAD] if version == 1 else [])
        elif len(s) == 3:
            out += e[:3] + [T.ECOJI_PAD]
        elif len(s) == 4:
            out += e[:3] + [last[bits >> 8 & 3]]
        else:
            out += e
    return "".join(out)


_EMOJI_AZ = {}
for _base in (0x1F1E6, 0x1F170, 0x1F150, 0x1F130):   # regional indicators, negative squared, negative circled, squared
    for _i in range(26):
        _EMOJI_AZ[chr(_base + _i)] = chr(97 + _i)
_EMOJI_DROP = "\ufe0f\ufe0e\u200d\u200b\u200c\u2060\u20e3"   # variation selectors, joiners, zero width, the keycap


def d_emojiaz(t: str):
    """Letters written as emoji letters (regional indicators and the like), digits as keycaps (a digit
    followed by U+20E3) or as themselves, marks and spaces as they are. No plain letter may be in the
    text. Emoji letters are capitals without case: the reading is lower case.

    At least four emoji letters in the search. Inside crib_decode's day walk (WALKING) one emoji letter or
    keycap is enough (Day 18 look-ahead, B3): there the chain is the one both saved blobs of the record's
    day prove, and a six-character Mastery record written as keycap hex (keycaps for 0-9, regional
    indicators for a-f) holds about one letter; the walk's crib and slug state still check the record."""
    if WALKING[0] and "⃣" not in t and not any(ch in _EMOJI_AZ for ch in t):
        return None
    out, hits = [], 0
    for ch in t:
        if ch in _EMOJI_AZ:
            out.append(_EMOJI_AZ[ch])
            hits += 1
        elif ch in _EMOJI_DROP:
            continue
        elif ch.isascii() and not ch.isalpha() and (ch.isprintable() or ch in "\r\n"):
            out.append(ch)
        else:
            return None
    if hits < (0 if WALKING[0] else 4):
        return None
    text = "".join(out)
    if re.fullmatch(r"\S(?: \S| {2,}\S)*\s*", text.strip("\r\n")):   # one space between letters, more between words
        text = re.sub(r" {2,}", "\x00", text).replace(" ", "").replace("\x00", " ")
    return text.encode()


# ---------------------------------------------------------------------------- ASCII forms

def d_punycode(t: str):
    """Punycode (RFC 3492) behind 'xn--'; and ASCII text with nothing but the delimiter '-' behind it,
    which is what punycode makes of text that needs no encoding ('Nice work-')."""
    s = t.strip()
    prefixed = s[:4].lower() == "xn--"
    body = s[4:] if prefixed else s
    if len(body) < 6 or not body.isascii():
        return None
    if not prefixed:
        return body[:-1].encode() if body.endswith("-") and not body.endswith("--") else None
    try:
        out = body.encode("ascii").decode("punycode")
    except (UnicodeError, ValueError, IndexError):
        return None
    return out.encode() if out and out != body else None


def _bigbase(alphabet: str):
    index = {c: i for i, c in enumerate(alphabet)}
    base = len(alphabet)

    def f(t: str):
        t = _SPACE.sub("", t)
        if not 6 <= len(t) <= 1500 or any(c not in index for c in t):
            return None
        n = 0
        for c in t:
            n = n * base + index[c]
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
        return raw if raw and _TEXT.fullmatch(raw) else None   # only a reading that is text is kept
    return f


_DIGITS, _LOWER, _UPPER = "0123456789", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
d_b62i = _bigbase(_DIGITS + _LOWER + _UPPER)
d_b62l = _bigbase(_LOWER + _UPPER + _DIGITS)
d_b62u = _bigbase(_UPPER + _LOWER + _DIGITS)
d_b58f = _bigbase("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ")
d_b58r = _bigbase("rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz")

_MIX = re.compile(r"(?i)0x([0-9a-f]+)|0b([01]+)|0o([0-7]+)|([0-9a-f]+)h|([0-7]+)[oq]|([01]+)b|([0-9]+)d?")
_MIX_BASES = (16, 2, 8, 16, 8, 2, 10)


def d_mixnum(t: str):
    """Character codes in more than one notation in one list: prefixes (0x, 0b, 0o), suffixes (h, o or
    q, b, d) or bare decimal, separated by white space or , ; |. A list in one notation is another
    decoder's."""
    tokens = [x for x in re.split(r"[\s,;|]+", t.strip().strip("[](){}")) if x]
    if len(tokens) < 4:
        return None
    kinds, out = set(), []
    for tok in tokens:
        m = _MIX.fullmatch(tok)
        if not m:
            return None
        k = m.lastindex - 1
        v = int(m.group(k + 1), _MIX_BASES[k])
        if not 0 < v <= 0x10FFFF or 0xD800 <= v <= 0xDFFF:
            return None
        kinds.add(k)
        out.append(chr(v))
    return "".join(out).encode() if len(kinds) > 1 else None


_ALPHABETS = (
    "alfa bravo charlie delta echo foxtrot golf hotel india juliett kilo lima mike november oscar papa quebec romeo sierra"
    " tango uniform victor whiskey xray yankee zulu alpha juliet",
    "adam boy charles david edward frank george henry ida john king lincoln mary nora ocean paul queen robert sam tom"
    " union victor william xray young zebra",
    "able baker charlie dog easy fox george how item jig king love mike nan oboe peter queen roger sugar tare uncle victor"
    " william xray yoke zebra",
    "ack beer charlie don edward freddie george harry ink johnnie king london monkey nuts orange pip queen robert sugar"
    " toc uncle vic william xray yorker zebra",
    "adams boston chicago denver easy frank george henry ida john king lincoln mary newyork ocean peter queen roger"
    " sugar thomas union victor william xray young",
    "anton berta caesar dora emil friedrich gustav heinrich ida julius kaufmann ludwig martha nordpol otto paula quelle"
    " richard samuel theodor ulrich viktor wilhelm xanthippe ypsilon zacharias",
    "apple butter charlie duff edward freddy george harry ink johnnie king london monkey nuts orange pudding queenie"
    " robert sugar tommy uncle vinegar willie xerxes yellow zebra",
)
PHONETIC = {w: w[0] for line in _ALPHABETS for w in line.split()}
PHONETIC.update({"zero": "0", "one": "1", "two": "2", "three": "3", "four": "4", "five": "5", "six": "6", "seven": "7",
                 "eight": "8", "nine": "9", "niner": "9", "fife": "5", "fower": "4", "tree": "3", "wun": "1",
                 "dash": "-", "hyphen": "-", "minus": "-", "stop": ".", "period": ".", "decimal": ".", "point": ".",
                 "comma": ",", "colon": ":", "exclamation": "!", "bang": "!", "space": " "})


def d_phonetic(t: str):
    """Spelling-alphabet words as their letters (the ICAO alphabet and six older ones), figures and
    marks by name. Either one word per token, with '/', '|' or the word 'space' between words; or the
    letters of a word joined by '-' and words apart by spaces. A token that is a single mark stands
    for itself. Lower case: a spelling alphabet has no case."""
    low = t.lower().replace("x-ray", "xray").replace("new york", "newyork").replace("exclamation mark", "exclamation")
    tokens = low.split()
    if not tokens or not low.isascii():
        return None
    out, hits = [], 0
    if any("-" in tok.strip("-") and all(p in PHONETIC for p in tok.split("-")) for tok in tokens):
        for tok in tokens:                                    # november-india-charlie-echo whiskey-oscar-...
            word = []
            for p in tok.split("-"):
                if p in PHONETIC:
                    word.append(PHONETIC[p])
                    hits += 1
                elif len(p) == 1 and not p.isalnum():
                    word.append(p)
                else:
                    return None
            out.append("".join(word))
        return " ".join(out).encode() if hits >= 2 else None
    for tok in tokens:
        if tok in ("/", "|"):
            out.append(" ")
        elif tok in PHONETIC:
            out.append(PHONETIC[tok])
            hits += 1
        elif len(tok) == 1 and not tok.isalnum():
            out.append(tok)
        else:
            return None
    return "".join(out).encode() if hits >= 2 else None


MORSE = dict(L.MORSE)
MORSE.update({"-...-": "=", ".-.-.": "+", "-..-.": "/", ".--.-.": "@", "-.--.": "(", "-.--.-": ")", ".-...": "&",
              ".----.": "'", ".-..-.": '"', "-.-.-.": ";", "..--.-": "_", "...-..-": "$"})


def _morse(words):
    """Words (lists of dot-dash codes) as text, or None for a code that is no character."""
    try:
        return " ".join("".join(MORSE[c] for c in w) for w in words).encode()
    except KeyError:
        return None


_SYLLABLE = re.compile(r"(?:(?:dit|dah|di|dot|dash)-?)+")
_SYLLABLES = {"dit": ".", "di": ".", "dot": ".", "dah": "-", "dash": "-"}


def d_morsew(t: str):
    """Morse spelled out: dit / di / dot and dah / dash. The syllables of a letter are joined by '-' or
    by nothing with one space between letters (dah-dit di-dit), or stand apart with a comma or two
    spaces between letters (dah dit, dit dit). '/', '|' or a line end is between words."""
    low = t.lower().strip()
    if not re.search(r"dah|dash", low) or re.sub(r"dit|dah|di|dot|dash|[\s,;/|\-]", "", low):
        return None
    apart = bool(re.search(r"[,;]| {2,}", low)) and not re.search(r"(?:dit|dah|di|dot|dash)-?(?:dit|dah|di|dot|dash)", low)
    words = []
    for w in re.split(r"\s*[/|]\s*|\s*\n\s*", low):
        if not w.strip():
            continue
        letters = [x for x in (re.split(r"\s*[,;]\s*| {2,}", w) if apart else w.split()) if x.strip()]
        codes = []
        for letter in letters:
            joined = letter.replace(" ", "-") if apart else letter
            if not _SYLLABLE.fullmatch(joined):
                return None
            codes.append("".join(_SYLLABLES[s] for s in re.findall(r"dit|dah|di|dot|dash", joined)))
        words.append(codes)
    return _morse(words) if words else None


MORSE_KEPT = "!,:"   # the sentence's marks that hold no dot and no dash: a table without one leaves it as it stands


def d_morsekeep(t: str):
    """Morse from a table that lacks a mark of the text ('!' has no code in the ITU recommendation): the
    encoder left the mark as it stands, a token of its own between the codes. A token that is one such
    mark is kept, every other token must be a code. Not without a kept token: that is morse itself, which
    keeps its name. A '-' left as it stands is the letter t, so a table without the hyphen is not read."""
    words, kept = [], 0
    for w in re.split(r"\s*[/|]\s*|\s{3,}", t.strip()):
        chars = []
        for c in w.split():
            if c in MORSE:
                chars.append(MORSE[c])
            elif len(c) == 1 and c in MORSE_KEPT:
                chars.append(c)
                kept += 1
            else:
                return None
        words.append("".join(chars))
    return " ".join(words).encode() if kept else None


def _morse_symbols(t: str):
    """(the two symbols in sorted order, the text) of a morse-like text in any two symbols, or None."""
    kinds = set(t) - set(" \t\r\n/|")
    if len(kinds) != 2 or len(t) < 5:
        return None
    return sorted(kinds), t


def _morse_as(t: str, dot: str, dash: str):
    words = [w.split() for w in re.split(r"\s*[/|]\s*|\s*\n\s*|\s{3,}", t.strip()) if w.strip()]
    if not words or max(len(c) for w in words for c in w) > 7:
        return None
    table = {ord(dot): ".", ord(dash): "-"}
    return _morse([[c.translate(table) for c in w] for w in words])


_FITS = re.compile(rb"[A-Za-z0-9 !,:\-]+")


def d_morseinv(t: str):
    """Morse with dots and dashes swapped. Not when the text read as ordinary morse is already text of
    the sentence's own characters: two digits read the same both ways round (...-- .---- is 31, and
    76 swapped), and morse as everybody writes it comes first."""
    got = _morse_symbols(t)
    if not got or got[0] != ["-", "."]:
        return None
    usual = _morse_as(t, ".", "-")
    if usual and _FITS.fullmatch(usual):
        return None
    return _morse_as(t, "-", ".")


def d_morseab(t: str):
    """Morse in two other symbols, the one that sorts first as the dot (0 and 1: 0 is the dot)."""
    got = _morse_symbols(t)
    return _morse_as(t, got[0][0], got[0][1]) if got and got[0] != ["-", "."] else None


def d_morseba(t: str):
    got = _morse_symbols(t)
    return _morse_as(t, got[0][1], got[0][0]) if got and got[0] != ["-", "."] else None


def d_morsetime(t: str):
    """Morse as timing in two symbols with nothing between them (1 and 0, = and .): one mark is a dot,
    three a dash, one gap inside a letter, three between letters, seven between words. The text starts
    with a mark. Any other run length is a refusal."""
    s = _SPACE.sub("", t)
    kinds = set(s)
    if len(kinds) != 2 or len(s) < 9:
        return None
    mark = s[0]
    words, letter, code = [], [], ""
    for m in re.finditer(r"(.)\1*", s):
        run = len(m.group())
        if m.group(1) == mark:
            if run not in (1, 3):
                return None
            code += "." if run == 1 else "-"
        elif run == 1:
            continue
        elif run in (3, 7):
            letter.append(code)
            code = ""
            if run == 7:
                words.append(letter)
                letter = []
        else:
            return None
    if code:
        letter.append(code)
    if letter:
        words.append(letter)
    return _morse(words) if words else None


def d_brdots(t: str):
    """Braille written as dot numbers, one cell per token (1345 24 14 15; 1-3-4-5 too): the cells, as
    Unicode braille, for the braille readers. '/', two spaces or a line end is a blank cell; so is 0."""
    s = t.strip()
    if len(s) < 7 or re.sub(r"[0-6\s,/\-]", "", s):
        return None
    out, cells = [], 0
    for wi, w in enumerate(x for x in re.split(r"\s*/\s*|\s*\n\s*| {2,}", s) if x.strip()):
        if wi:
            out.append(chr(0x2800))
        for tok in re.split(r"[\s,]+", w.strip()):
            dots = tok.replace("-", "")
            if dots == "0":
                out.append(chr(0x2800))
                continue
            if not dots or any(a >= b for a, b in zip(dots, dots[1:])) or "0" in dots:
                return None
            out.append(chr(0x2800 + sum(1 << (int(d) - 1) for d in dots)))
            cells += 1
    return "".join(out).encode() if cells >= 4 else None


# ---------------------------------------------------------------------------- programs

def d_cow(t: str):
    return E.cow(t, deadline=_deadline())


def d_whitespace(t: str):
    return E.whitespace(t, deadline=_deadline())


def d_malbolge(t: str):
    if not isinstance(t, str):
        return None
    return E.malbolge(t.strip(), steps=1_000_000, deadline=_deadline())


def d_jsfuck(t: str):
    return E.jsfuck(t, deadline=_deadline())


def d_deadfish(t: str):
    return E.deadfish(t, deadline=_deadline())


# ---------------------------------------------------------------------------- Day 14 build (row 296)
#
# Strict readers for a text that was only stretched, and for hex whose bytes were turned. Each is all or
# nothing: every place of the payload must be in the form, or the reader refuses (doubled letters occur in
# ordinary words, and one pair proves nothing).

_HEX_BYTES = re.compile(r"(?:0x|\\x)?([0-9a-fA-F]{2})")
_HEX_SEP = re.compile(r"[\s:,;]+")
_NIBBLES = bytes(((x << 4) | (x >> 4)) & 0xFF for x in range(256))
_MIRROR = bytes(int(f"{x:08b}"[::-1], 2) for x in range(256))
_PRINTABLE = re.compile(rb"[\x20-\x7e\r\n\t]+")


def _hex_turned(t: str, table: bytes):
    """Hex pairs (any of space, colon, comma or semicolon between them, an 0x or \\x before each or none)
    whose bytes, each put through `table`, are all printable ASCII; or None. Hex of plain text is refused
    by both tables wherever a byte's turned form is no printable character: every letter with its nibbles
    swapped is above 0x7f or a control character but for the few with two nibbles from 2 to 7, and a
    hyphen (0x2d) never is; with its bits mirrored, every character with an odd code is above 0x7f."""
    compact = _HEX_SEP.sub("", t)
    pairs = _HEX_BYTES.findall(compact)
    if len(pairs) < 2 or sum(len(m.group(0)) for m in _HEX_BYTES.finditer(compact)) != len(compact):
        return None
    out = bytes.fromhex("".join(pairs)).translate(table)
    return out if _PRINTABLE.fullmatch(out) else None


def d_hexnib(t: str):
    """Hex of bytes whose two nibbles were swapped (0x4e written e4)."""
    return _hex_turned(t, _NIBBLES)


def d_hexbits(t: str):
    """Hex of bytes whose eight bits were written in the opposite order (0x4e written 72)."""
    return _hex_turned(t, _MIRROR)


def _repeated(n: int):
    def f(t: str):
        """Every character written n times: all of the text, or it is refused."""
        t = t.strip("\r\n")
        if len(t) < 2 * n or len(t) % n or "\n" in t:
            return None
        once = t[::n]
        if any(t[i::n] != once for i in range(1, n)):
            return None
        return once.encode()
    return f


d_doubled = _repeated(2)
d_tripled = _repeated(3)


def d_spaced(t: str):
    """One and the same character between every two characters of the text (`N i c e`, `N_i_c_e`): an odd
    length of five or more, every second character that one separator, and what is left holds another
    character than it. A space of the text is then three spaces in a row, which this reads back."""
    t = t.strip("\r\n")
    if len(t) < 5 or not len(t) % 2 or "\n" in t:
        return None
    sep, kept = t[1], t[0::2]
    if t[1::2] != sep * (len(t) // 2) or kept == sep * len(kept):
        return None
    return kept.encode()


def d_filler(t: str):
    """One and the same character behind every character of the text (`Nxixcxex`) or in front of every one
    (`*N*i*c*e`): an even length of six or more. Refused when both halves are one character each."""
    t = t.strip("\r\n")
    if len(t) < 6 or len(t) % 2 or "\n" in t:
        return None
    first, second = t[0::2], t[1::2]
    behind, before = second == second[0] * len(second), first == first[0] * len(first)
    if behind == before:
        return None
    return (first if behind else second).encode()


_FITS14 = re.compile(r"[A-Za-z0-9 !,:\-]+")
_GAPS = re.compile(r"( +)")


def d_spacemark(t: str):
    """A text with no space in it and one mark, `_` or `/`, wherever a space was (second round of the Day 14
    build): the mark read as a space. Neither mark is a character of the sentence or of a slug, so the
    step is an exact inverse; it refuses a text that holds a space, both marks or neither, and one that
    holds any other character than the sentence's and a slug's own once the mark is read."""
    t = t.strip("\r\n")
    marks = [c for c in "_/" if c in t]
    if len(marks) != 1 or " " in t or "\n" in t:
        return None
    out = t.replace(marks[0], " ")
    return out.encode() if _FITS14.fullmatch(out) else None


def d_spacedw(t: str):
    """One space between every two characters, where a space of the text is itself written as two spaces
    (`e    w`: four in a row): every other run of spaces is a single one. A run of three at either end
    is a space of the text there. A text whose runs are all single is read too (a Mastery record with no
    space in it), to what d_spaced gives."""
    t = t.strip("\r\n")
    if len(t) < 5 or "\n" in t or "\t" in t:
        return None
    parts = _GAPS.split(t)
    out = []
    for i, part in enumerate(parts):
        if i % 2 == 0:
            if len(part) == 1:
                out.append(part)
            elif part or i not in (0, len(parts) - 1):
                return None
        else:
            edge = (i == 1 and not parts[0]) or (i == len(parts) - 2 and not parts[-1])
            if len(part) == (3 if edge else 4):
                out.append(" ")
            elif edge or len(part) != 1:
                return None
    kept = "".join(out)
    return kept.encode() if len(kept) >= 3 and kept.strip() else None


_HEXISH = re.compile(rb"(?:\\x|0x)?[0-9a-fA-F]{2}")


# ---------------------------------------------------------------------------- Day 18 build (look-ahead B5)
#
# Three strict readers the Day 18 look-ahead staged as a base STOP (docs/retro/day-18-predictions-warmups.md,
# F2): Roman numerals of the bytes, Braille hex with a number sign before every digit, and upside-down text.
# Each is all or nothing over the payload.

_ROMAN = re.compile(r"M{0,3}(?:CM|CD|D?C{0,3})(?:XC|XL|L?X{0,3})(?:IX|IV|V?I{0,3})")
_ROMAN_VALUE = {"M": 1000, "D": 500, "C": 100, "L": 50, "X": 10, "V": 5, "I": 1}
_ROMAN_ONLY = re.compile(rb"[MDCLXVI]+(?:[\s,;|/]+[MDCLXVI]+)*\s*|[mdclxvi]+(?:[\s,;|/]+[mdclxvi]+)*\s*")


def d_roman(t: str):
    """Each byte of the text as a Roman numeral (`LXXVIII CV XCIX`), tokens split by white space or one of
    , ; | /: every token a numeral in its one canonical form (IV, never IIII), of one letter case through the
    whole payload, worth 1 to 255, and every byte printable ASCII or white space. Two tokens or more."""
    s = t.strip()
    if not s or (s.upper() != s and s.lower() != s):
        return None
    tokens = re.split(r"[\s,;|/]+", s.upper())
    if len(tokens) < 2:
        return None
    out = bytearray()
    for tok in tokens:
        if not tok or not _ROMAN.fullmatch(tok):
            return None
        n = sum(-_ROMAN_VALUE[c] if i + 1 < len(tok) and _ROMAN_VALUE[tok[i + 1]] > _ROMAN_VALUE[c] else _ROMAN_VALUE[c]
                for i, c in enumerate(tok))
        if not 1 <= n <= 255:
            return None
        out.append(n)
    out = bytes(out)
    return out if _PRINTABLE.fullmatch(out) else None


_BR_NUMBER = "⠼"                                    # the Braille number sign
_BR_DIGITS = dict(zip("⠁⠃⠉⠙⠑⠋⠛⠓⠊⠚", "1234567890"))   # cells a to j
_BR_HEXLETTERS = dict(zip("⠁⠃⠉⠙⠑⠋", "abcdef"))                      # cells a to f


def d_brhex(t: str):
    """Hex digits in Braille with the number sign before EVERY digit (`⠼⠙⠑⠼⠋...` is 4e 6...): the sign makes
    only the one cell after it a digit (a to j are 1 to 9 and 0), and any cell without it is a letter a to f.
    Grade 1's rule, a sign that opens a run of digits, is d_braille's and reads such a text otherwise. Cells
    only, with no white space between them (a spaced form is read by d_braille already), an even count of
    digits, at least one number sign, and every byte printable ASCII or white space."""
    s = t.strip("\r\n")
    if not s or s[0] not in _BR_HEXLETTERS and s[0] != _BR_NUMBER:
        return None
    digits, i, signs = [], 0, 0
    while i < len(s):
        ch = s[i]
        if ch == _BR_NUMBER:
            d = _BR_DIGITS.get(s[i + 1]) if i + 1 < len(s) else None
            if d is None:
                return None
            digits.append(d)
            signs += 1
            i += 2
            continue
        d = _BR_HEXLETTERS.get(ch)
        if d is None:
            return None
        digits.append(d)
        i += 1
    if not signs or len(digits) % 2:
        return None
    out = bytes.fromhex("".join(digits))
    return out if _PRINTABLE.fullmatch(out) else None


# Upside-down text: each character's turned glyph, the order reversed. The common tables agree on the
# lower-case letters and differ on capitals, digits and marks; this one holds the glyphs of the widely
# copied table (the look-ahead's) and a few other tables' glyphs for the same character, never one glyph
# for two characters. A glyph none of them holds makes the text no reading.
_UPSIDE_OF = {
    "a": "ɐ", "b": "q", "c": "ɔ", "d": "p", "e": "ǝ", "f": "ɟ", "g": "ƃ", "h": "ɥ", "i": "ᴉı", "j": "ɾ", "k": "ʞ",
    "l": "lʃ", "m": "ɯ", "n": "u", "o": "o", "p": "d", "q": "b", "r": "ɹ", "s": "s", "t": "ʇ", "u": "n", "v": "ʌ",
    "w": "ʍ", "x": "x", "y": "ʎ", "z": "z",
    "A": "∀", "B": "ꓭ𐐒", "C": "Ɔ", "D": "ꓷ◖", "E": "Ǝ", "F": "Ⅎ", "G": "⅁", "H": "H", "I": "I", "J": "ſ", "K": "ꓘ",
    "L": "⅂˥", "M": "W", "N": "N", "O": "O", "P": "Ԁ", "Q": "Ὁ", "R": "ᴚ", "S": "S", "T": "⊥ꓕ", "U": "∩", "V": "Λ",
    "W": "M", "X": "X", "Y": "⅄", "Z": "Z",
    "0": "0", "1": "Ɩ⇂1", "2": "ᄅ↊2", "3": "Ɛ↋3", "4": "ㄣᔭ4", "5": "ϛ5", "6": "9", "7": "ㄥ7", "8": "8", "9": "6",
    "!": "¡", ",": "'ʻ‘", ":": ":", "-": "-", ".": "˙", "?": "¿", " ": " ",
}
UPSIDE, UPSIDE_CLASHES = {}, set()   # glyph -> character; glyphs that would stand for two (none: a test holds it)
for _c, _glyphs in _UPSIDE_OF.items():
    for _g in _glyphs:
        if UPSIDE.setdefault(_g, _c) != _c:
            UPSIDE_CLASHES.add(_g)
for _g in UPSIDE_CLASHES:
    del UPSIDE[_g]
_UPSIDE_ASCII = re.compile(rb"[" + re.escape("".join(sorted(g for g in UPSIDE if g.isascii())).encode()) + rb"]+")
UPSIDE_FLOOR = 4   # characters the table must turn, outside crib_decode's day walk


def d_upside(t: str):
    """Upside-down text read back: the characters in the opposite order, each glyph by the table above.
    Every character must be in the table (a line end only at either end). Outside crib_decode's day walk
    the table must turn at least UPSIDE_FLOOR characters (l, o, s, x, z, 0, 8 and the marks : and - are
    their own glyphs, and a text of those is only reversed); inside it (WALKING) a Mastery record of a day
    whose two saved blobs it reads may turn none. ASCII 1 to 5 and 7 stand for themselves (a table that
    turns no digit), and 6 and 9 for each other: the sentence holds no digit, so crib_decode leaves the
    slug's digits read through this step unsure (`as_is`, then `unflipped`) until the judge accepts one."""
    s = t.strip("\r\n")
    if not s or "\n" in s or "\r" in s:
        return None
    out, turned = [], 0
    for ch in reversed(s):
        c = UPSIDE.get(ch)
        if c is None:
            return None
        turned += c != ch
        out.append(c)
    if turned < (0 if WALKING[0] else UPSIDE_FLOOR):
        return None
    return "".join(out).encode()


# ---- Bubble Babble (OpenSSH "xubah-xigak" fingerprint encoding; Antti Huima) -------------------
# A deterministic, fully reversible encoding with a running checksum, so a non-Bubble-Babble string
# fails to decode (near-zero false positive). The decoder re-encodes its result and compares byte for
# byte, so the separator placement and the trailing marker are verified exactly -- a string that is not
# a genuine Bubble Babble encoding of some byte string yields None, and the crib is a second gate.
BB_VOWELS = "aeiouy"
BB_CONS = "bcdfghklmnprstvzx"
BB_FLOOR = 11                 # at least two tuples ("xNNNN-NNNNNx"); shorter payloads are not asked
_BB_CHARS = frozenset(BB_VOWELS + BB_CONS + "-")


def bubblebabble_encode(data: bytes) -> str:
    """The Bubble Babble encoding of `data` (the inverse of d_bubblebabble; for the strict re-encode
    check and for tests)."""
    rounds = len(data) // 2 + 1
    seed = 1
    out = ["x"]
    for i in range(rounds):
        if i + 1 < rounds or len(data) % 2:
            b1 = data[i * 2]
            out += [BB_VOWELS[(((b1 >> 6) & 3) + seed) % 6], BB_CONS[(b1 >> 2) & 15],
                    BB_VOWELS[((b1 & 3) + seed // 6) % 6]]
            if i + 1 < rounds:
                b2 = data[i * 2 + 1]
                out += [BB_CONS[(b2 >> 4) & 15], "-", BB_CONS[b2 & 15]]
                seed = (seed * 5 + b1 * 7 + b2) % 36
        else:
            out += [BB_VOWELS[seed % 6], BB_CONS[16], BB_VOWELS[seed // 6]]
    out.append("x")
    return "".join(out)


def d_bubblebabble(t: str):
    """Bubble Babble decode, strict: the running checksum and a full re-encode comparison make a false
    positive on non-Bubble-Babble input essentially impossible. Returns the decoded bytes or None."""
    s = t.strip("\r\n")
    if len(s) < BB_FLOOR or s[0] != "x" or s[-1] != "x" or not (set(s) <= _BB_CHARS):
        return None
    vi = {c: i for i, c in enumerate(BB_VOWELS)}
    ci = {c: i for i, c in enumerate(BB_CONS)}
    body = s[1:-1].replace("-", "")
    if len(body) < 3 or (len(body) - 3) % 5 != 0:
        return None
    n_full = (len(body) - 3) // 5
    seed = 1
    out = bytearray()
    pos = 0
    for _ in range(n_full):
        y0, d1, y2, d3, d4 = body[pos], body[pos + 1], body[pos + 2], body[pos + 3], body[pos + 4]
        pos += 5
        if y0 not in vi or y2 not in vi or d1 not in ci or d3 not in ci or d4 not in ci:
            return None
        if ci[d1] > 15 or ci[d3] > 15 or ci[d4] > 15:   # data consonants are 0..15; 'x' (16) is a marker only
            return None
        high = (vi[y0] - seed) % 6
        low = (vi[y2] - seed // 6) % 6
        if high > 3 or low > 3:
            return None
        b1 = (high << 6) | (ci[d1] << 2) | low
        b2 = (ci[d3] << 4) | ci[d4]
        out += bytes((b1, b2))
        seed = (seed * 5 + b1 * 7 + b2) % 36
    y0, d1, y2 = body[pos], body[pos + 1], body[pos + 2]
    if y0 not in vi or y2 not in vi or d1 not in ci:
        return None
    if ci[d1] == 16:                    # padding tuple -> even length; the checksum is verified here
        if vi[y0] != seed % 6 or vi[y2] != seed // 6:
            return None
    else:                               # odd trailing byte
        if ci[d1] > 15:
            return None
        high = (vi[y0] - seed) % 6
        low = (vi[y2] - seed // 6) % 6
        if high > 3 or low > 3:
            return None
        out.append((high << 6) | (ci[d1] << 2) | low)
    data = bytes(out)
    if bubblebabble_encode(data) != s:  # strict: the separators and marker must match exactly
        return None
    return data or None


# ---------------------------------------------------------------------------- the strict steps

_BB_ONLY = re.compile(rb"[aeiouybcdfghklmnprstvzx-]+")   # Bubble Babble alphabet (vowels, consonants, '-')
_COW_ONLY = re.compile(rb"[mMoO\s]+")
_JSFUCK_ONLY = re.compile(rb"[\[\]()!+\s]+")
_DEADFISH_ONLY = re.compile(rb"[idso\s]+")
_ALNUM = re.compile(rb"[0-9A-Za-z\s]+")
_MIXISH = re.compile(rb"(?i)0[xbo][0-9a-f]|[0-9a-f][hoqbd](?:[\s,;|]|$)")
_BRDOTS = re.compile(rb"[0-6\s,/\-]+")
_MORSEW = re.compile(rb"(?i)da(?:h|sh)")
_MORSE_KEEP = frozenset(b".-" + MORSE_KEPT.encode())   # dots, dashes and the marks d_morsekeep keeps

_UNICODE = (("b65536", d_b65536), ("b32768", d_b32768), ("b2048", d_b2048), ("b2048r", d_b2048r), ("ecoji", d_ecoji),
            ("ecoji2", d_ecoji2), ("emojiaz", d_emojiaz), ("brhex", d_brhex), ("upside", d_upside))
_UNICODE_NAMES = tuple(name for name, _ in _UNICODE)
BY_NAME = {name: fn for name, fn in _UNICODE}
BY_NAME.update({"punycode": d_punycode, "b62i": d_b62i, "b62l": d_b62l, "b62u": d_b62u, "b58f": d_b58f, "b58r": d_b58r,
                "mixnum": d_mixnum, "phonetic": d_phonetic, "morsew": d_morsew, "morseinv": d_morseinv,
                "morseab": d_morseab, "morseba": d_morseba, "morsetime": d_morsetime, "morsekeep": d_morsekeep,
                "brdots": d_brdots, "cow": d_cow, "deadfish": d_deadfish,
                "whitespace": d_whitespace, "malbolge": d_malbolge, "jsfuck": d_jsfuck,
                "hexnib": d_hexnib, "hexbits": d_hexbits, "doubled": d_doubled, "tripled": d_tripled,
                "spaced": d_spaced, "filler": d_filler, "spacedw": d_spacedw, "spacemark": d_spacemark,
                "roman": d_roman, "bubblebabble": d_bubblebabble})
OPEN_DIGITS = ("upside",)   # steps whose digits the sentence cannot check (crib_decode._open_digits, _digit_options)
STRETCHED = ("doubled", "tripled", "spaced", "filler", "spacedw", "spacemark")
NAMES = frozenset(BY_NAME)
PROGRAMS = ("cow", "whitespace", "malbolge", "jsfuck", "deadfish")


def _which(cur: bytes) -> tuple:
    """The names of the readers worth asking on this payload: a few cheap looks at its bytes, so that a
    payload of an old encoding (hex, base64, a list of numbers) costs next to nothing here."""
    n = len(cur)
    if n < 4 or n > PROGRAM_MAX:
        return ()
    if not cur.isascii():
        return _UNICODE_NAMES if n <= BIG else ()
    if not cur.strip(b" \t\r\n"):
        return ("whitespace",) if b"\t" in cur and b"\n" in cur else ()
    head = cur[:1]
    if head in b"[(!+" and _JSFUCK_ONLY.fullmatch(cur):
        return ("jsfuck",)
    if head in b"mMoO" and _COW_ONLY.fullmatch(cur):
        return ("cow",)
    if head in b"ids o" and b"o" in cur and _DEADFISH_ONLY.fullmatch(cur):
        return ("deadfish",)
    names = []
    spaced = b" " in cur[:64]
    if not spaced and n >= 8 and E.malbolge_valid(cur[:16].decode("ascii")):
        names.append("malbolge")
    if n > BIG:
        return tuple(names)
    if cur[:4].lower() == b"xn--" or cur.rstrip(b"\r\n").endswith(b"-"):
        names.append("punycode")
    kinds = set(cur) - set(b" \t\r\n/|")
    if len(kinds) == 2:
        names += ["morseinv"] if kinds == {45, 46} else ["morseab", "morseba", "morsetime"]
    elif 2 < len(kinds) <= len(_MORSE_KEEP) and kinds <= _MORSE_KEEP:
        names.append("morsekeep")
    elif _ALNUM.fullmatch(cur) and b" " not in cur.strip():
        names += ["b62i", "b62l", "b62u", "b58f", "b58r"]
    if head.isalpha() and (spaced or b"-" in cur[:64]):
        names.append("phonetic")
        if _MORSEW.search(cur):
            names.append("morsew")
    if _MIXISH.search(cur):
        names.append("mixnum")
    if head.isdigit() and _BRDOTS.fullmatch(cur):
        names.append("brdots")
    if head in b"MDCLXVImdclxvi" and _ROMAN_ONLY.fullmatch(cur):
        names.append("roman")
    if head == b"x" and len(cur) >= BB_FLOOR and cur.rstrip(b"\r\n")[-1:] == b"x" and _BB_ONLY.fullmatch(cur.rstrip(b"\r\n")):
        names.append("bubblebabble")
    if WALKING[0] and _UPSIDE_ASCII.fullmatch(cur.strip(b"\r\n")):   # a record of glyphs that are ASCII
        names.append("upside")
    return tuple(names)


DAY14 = frozenset(("hexnib", "hexbits") + STRETCHED)


def _which14(cur: bytes) -> tuple:
    """The Day 14 readers worth asking on this payload, by a look at its first bytes: asked beside
    _which's, whatever it chose, and never above BIG."""
    n = len(cur)
    if n < 4 or n > BIG or not cur.isascii():
        return ()
    body = cur.strip(b"\r\n")
    n = len(body)
    names = []
    if n >= 4 and _HEXISH.match(body):
        names += ["hexnib", "hexbits"]
    if n >= 4 and not n % 2 and body[0] == body[1] and body[2] == body[3]:
        names.append("doubled")
    if n >= 6 and not n % 3 and body[0] == body[1] == body[2]:
        names.append("tripled")
    if n >= 5 and n % 2 and body[1] == body[3]:
        names.append("spaced")
    if n >= 5 and b" " in body[:5] and b"  " in body:
        names.append("spacedw")
    elif n >= 5 and body[1] == 32 == body[3] and b"  " not in body:
        names.append("spacedw")
    if b" " not in body and (b"_" in body) != (b"/" in body):
        names.append("spacemark")
    if n >= 6 and not n % 2 and (body[1] == body[3] == body[5] or body[0] == body[2] == body[4]):
        names.append("filler")
    return tuple(names)


def steps(cur: bytes) -> list:
    """[(name, bytes)]: what the strict readers of this module make of one payload."""
    names = _which(cur) + _which14(cur)
    if not names:
        return []
    t = L._text(cur)
    if t is None:
        return []
    out = []
    for name in names:
        try:
            o = BY_NAME[name](t)
        except Exception:
            o = None
        if o and len(o) <= PROGRAM_MAX:
            out.append((name, o))
    return out


def step_fn(name: str):
    """The decoder (bytes -> bytes or None) of one strict step by its name, or None."""
    fn = BY_NAME.get(name)
    if fn is None:
        return None

    def f(b):
        t = L._text(b)
        return fn(t) if t is not None and name in (_which14(b) if name in DAY14 else _which(b)) else None
    f.__name__ = "d_" + name
    return f


# ---------------------------------------------------------------------------- late readers (the sentence is the key)

_QWERTY = ("`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./" '~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:"ZXCVBNM<>?')
_OTHER = {
    "dvorak": ("`1234567890[]',.pyfgcrl/=\\aoeuidhtns-;qjkxbmwvz" '~!@#$%^&*(){}"<>PYFGCRL?+|AOEUIDHTNS_:QJKXBMWVZ'),
    "colemak": ("`1234567890-=qwfpgjluy;[]\\arstdhneio'zxcvbkm,./" '~!@#$%^&*()_+QWFPGJLUY:{}|ARSTDHNEIO"ZXCVBKM<>?'),
}
LAYOUTS = {}
for _name, _keys in _OTHER.items():
    assert len(_keys) == len(_QWERTY) == 94 and len(set(_keys)) == 94
    LAYOUTS[_name] = str.maketrans(_keys, _QWERTY)        # typed on that layout with QWERTY fingers
    LAYOUTS[_name + "-"] = str.maketrans(_QWERTY, _keys)  # typed on QWERTY with that layout's fingers

LETTER_KINDS = ("layout", "symsub")   # digits written as themselves pass through: unsure, like a letter cipher's
LATE_KINDS = ("layout", "cpshift", "symsub", "bases", "befunge", "hexsym")
STRICT_KINDS = ()                     # hexsym is NOT strict (review of f8fe87e): a slug-only record needs the vouch
_SYMSUB = {}                          # id -> {symbol: character}, for the key read off one blob to read another
_SYM_DROP = "\ufe0f\ufe0e\u200d\u200b\u200c\u2060\u20e3"


def _late_layout(text, crib):
    out = []
    if text.isascii() and not text.startswith(crib[:6]):
        for name, table in LAYOUTS.items():
            plain = text.translate(table)
            if plain.startswith(crib):
                out.append(("layout:" + name, plain))
    return out


def _cpshift(text, n, spaces):
    try:
        return "".join(c if (spaces and c.isspace()) or c in "\r\n" else chr(ord(c) - n) for c in text)
    except ValueError:
        return None


def _late_cpshift(text, crib):
    if text.isascii() or len(text) < len(crib):
        return []
    n = ord(text[0]) - ord(crib[0])
    out = []
    for spaces in (False, True):
        plain = _cpshift(text, n, spaces) if n > 0 else None
        if plain and plain.startswith(crib) and plain.isascii():
            out.append(("cpshift:%d%s" % (n, "s" if spaces else ""), plain))
            break
    return out


def _symbols(text):
    return [c for c in text if c not in _SYM_DROP]


def _symsub_apply(text, table):
    out = []
    for c in _symbols(text.strip("\r\n")):
        if c in table:
            out.append(table[c])
        elif c == "-" or (c.isascii() and c.isdigit()):
            out.append(c)
        else:
            return None       # a symbol the sentence did not show: what it stands for is not known
    return "".join(out)


def _late_symsub(text, crib):
    sym = _symbols(text)
    if len(sym) < len(crib) + 8:
        return []
    table, back = {}, {}
    low = crib.lower()
    for c, p in zip(sym, low):
        if table.setdefault(c, p) != p:
            return []
        back.setdefault(p, set()).add(c)
    if any(len(v) > 2 for v in back.values()):     # at most a capital and a small form of one letter
        return []
    if all(c == p or c.lower() == p for c, p in table.items()):
        return []                                   # the sentence itself
    if text.isascii() and all(c == p for c, p in table.items() if not c.isalpha()) and all(
            c.isalpha() for c, p in table.items() if p.isalpha()):
        return []                                   # letters for letters: classical.py's substitution has it
    if any(c == "-" or (c.isascii() and c.isdigit()) for c in table):
        return []                                   # '-' and the digits must be free to stand for themselves
    key = hashlib.sha256("".join(sorted(c + p for c, p in table.items())).encode()).hexdigest()
    _SYMSUB[key] = table
    plain = _symsub_apply(text, table)
    return [("symsub:" + key, crib + plain[len(crib):])] if plain and plain.startswith(low) else []


def _bases_apply(text, bases):
    tokens = [x for x in re.split(r"[\s,;|]+", text.strip().strip("[](){}")) if x]
    out = []
    for i, tok in enumerate(tokens):
        try:
            v = int(tok, bases[i % len(bases)])
        except ValueError:
            return None
        if not 0 < v <= 0x10FFFF:
            return None
        out.append(chr(v))
    return "".join(out)


def _late_bases(text, crib):
    if not text.isascii():
        return []
    tokens = [x for x in re.split(r"[\s,;|]+", text.strip().strip("[](){}")) if x]
    if len(tokens) < len(crib) + 8 or len(tokens) > 400 or not all(t.isalnum() and len(t) <= 9 for t in tokens):
        return []
    fits = []
    for tok, ch in zip(tokens, crib):
        ok = set()
        for b in range(2, 37):
            try:
                if int(tok, b) == ord(ch):
                    ok.add(b)
            except ValueError:
                pass
        if not ok:
            return []
        fits.append(ok)
    for period in range(2, 13):
        slots = [set.intersection(*fits[r::period]) for r in range(period)]
        if not all(slots):
            continue
        bases = [min(slot) for slot in slots]
        if len(set(bases)) == 1:
            return []                               # one base throughout: crib_decode's radix readers have it
        plain = _bases_apply(text, bases)
        if plain is None:
            return []
        # A slot the sentence leaves two bases for is decided only when every one of them reads the rest alike.
        for r, slot in enumerate(slots):
            for b in slot:
                if _bases_apply(text, bases[:r] + [b] + bases[r + 1:]) != plain:
                    return []
        return [("bases:" + ".".join(map(str, bases)), plain)]
    return []


def _late_befunge(text, crib):
    out = E.befunge(text, deadline=_deadline())
    t = L._text(out) if out else None
    return [("befunge:93", t)] if t else []


# Day 18 build (backlog row 333): the text written as hex, each hex digit as one of sixteen tokens of a code
# no reader knows (a 4x4 Polybius square, tap code, the digit's value or A1Z26 number, letters a to p, sixteen
# emoji, semaphore arrows, dice, Roman numerals, DNA pairs). Days 16 and 17 were two such codes, Morse and
# Bacon groups, and both stopped the lane at the base. The table is learned from the sentence: its 174 hex
# digits hold all sixteen values, so the first 174 tokens fix every token's value, one to one.
HEXSYM_WAYS = ("ws", "sp2", "graph") + tuple("w%d" % n for n in range(1, 9))
_HEXSYM = {}                      # id -> (tokeniser, {token: value}), for the table read off one blob to read another
_HEX_MARKS = "️︎⃣‍"   # joined to the character before them in a `graph` token
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _hexsym_tokens(text: str, how: str):
    """The tokens of a text by one tokeniser, or None: `ws` split on white space; `sp2` on two or more spaces
    or any other white space (a token may hold one space: tap code's knocks); `graph` each character with
    the marks behind it (variation selectors, a keycap, a joiner), white space left out; `wN` the text without
    its white space cut in pieces of N characters."""
    if how == "ws":
        return text.split()
    if how == "sp2":
        return [x for x in re.split(r" {2,}|[\t\r\n\f\v]+", text.strip()) if x]
    if how == "graph":
        out = []
        for ch in text:
            if out and ch in _HEX_MARKS:
                out[-1] += ch
            elif not ch.isspace():
                out.append(ch)
        return out
    w = int(how[1:])
    flat = re.sub(r"\s+", "", text)
    if not flat or len(flat) % w:
        return None
    return [flat[i:i + w] for i in range(0, len(flat), w)]


def _hexsym_apply(text: str, how: str, table: dict):
    """The text read by a learned table: every token in the table, an even count, the bytes text; or None."""
    toks = _hexsym_tokens(text, how)
    if not toks or len(toks) % 2:
        return None
    vals = [table.get(t) for t in toks]
    if None in vals:
        return None
    return L._text(bytes(16 * vals[i] + vals[i + 1] for i in range(0, len(vals), 2)))


def _late_hexsym(text, crib):
    """[('hexsym:<tokeniser>.<id>', plain)] when one tokeniser cuts the whole blob into tokens of which the first
    2 x len(crib) stand one to one for the crib's hex digits (each token one value, each value one token, all
    sixteen values met), every later token is one of them, the count is even, and the bytes are the sentence
    and more. Tokens that are themselves the hex digits are hex, which the strict readers read. The first
    tokeniser of HEXSYM_WAYS that reads the blob names the step; the table is kept under the id."""
    want = crib.encode().hex()
    deadline = _deadline()
    for how in HEXSYM_WAYS:
        if time.perf_counter() > deadline:
            break
        toks = _hexsym_tokens(text, how)
        if not toks or len(toks) % 2 or len(toks) < len(want) + 2:
            continue
        table, back = {}, {}
        for tok, h in zip(toks, want):
            v = int(h, 16)
            if table.setdefault(tok, v) != v or back.setdefault(v, tok) != tok:
                break
        else:
            if len(back) != 16 or all(t in _HEX_DIGITS for t in table):
                continue
            plain = _hexsym_apply(text, how, table)
            if not plain or not plain.startswith(crib):
                continue
            key = hashlib.sha256((how + "\x1f" + "\x1f".join(back[v] for v in range(16))).encode()).hexdigest()
            _HEXSYM[key] = (how, dict(table))
            return [("hexsym:%s.%s" % (how, key), plain)]
    return []


def late(text: str, crib: str, deadline: float) -> list:
    """[(step name, plain text)] of the late readers on one blob's text; each plain text starts with
    the sentence or is a program's output (the caller checks the sentence either way)."""
    out = []
    for fn in (_late_layout, _late_cpshift, _late_symsub, _late_bases, _late_befunge, _late_hexsym):
        if time.perf_counter() > deadline:
            break
        try:
            out += fn(text, crib) or []
        except Exception:
            continue
    return out


def keyed_fn(name: str):
    """The decoder (text -> text or None) of a late step by its name, or None."""
    kind, _, key = name.partition(":")
    try:
        if kind == "layout":
            table = LAYOUTS.get(key)
            return (lambda t: t.translate(table) if t.isascii() else None) if table else None
        if kind == "cpshift":
            spaces = key.endswith("s")
            n = int(key.rstrip("s"))
            return lambda t: _cpshift(t, n, spaces)
        if kind == "symsub":
            table = _SYMSUB.get(key)
            return (lambda t: _symsub_apply(t, table)) if table else None
        if kind == "bases":
            bases = [int(x) for x in key.split(".")]
            return (lambda t: _bases_apply(t, bases)) if bases and all(2 <= b <= 36 for b in bases) else None
        if kind == "befunge":
            def run(t):
                out = E.befunge(t, deadline=_deadline())
                return L._text(out) if out else None
            return run
        if kind == "hexsym":
            how, _, ident = key.partition(".")
            got = _HEXSYM.get(ident)
            if not got or got[0] != how:
                return None
            table = got[1]
            return lambda t: _hexsym_apply(t, how, table)
    except ValueError:
        return None
    return None


# ---------------------------------------------------------------------------- lossy codes (unsure only)

_KEYS = {"2": "abc", "3": "def", "4": "ghi", "5": "jkl", "6": "mno", "7": "pqrs", "8": "tuv", "9": "wxyz"}
_T9 = {c: d for d, letters in _KEYS.items() for c in letters}
_T9_INDEX = {}


def t9(word: str) -> str:
    return "".join(_T9.get(c, "?") for c in word.lower())


def multitap_decode(t: str):
    """Multi-tap phone keys, one group of the same key per token (66 444 222 33): a letter by the
    number of presses, the key's own digit by one press more, 0 a space (00 the digit 0). A token
    that is no key group is kept when it is a mark and is a break otherwise. None when no letter
    comes out."""
    out, hits = [], 0
    for tok in re.split(r"\s+", t.strip()):
        if not tok:
            continue
        if tok.isdigit() and len(set(tok)) == 1:
            d, k = tok[0], len(tok)
            if d in _KEYS:
                if k <= len(_KEYS[d]):
                    out.append(_KEYS[d][k - 1])
                    hits += 1
                elif k == len(_KEYS[d]) + 1:
                    out.append(d)
                else:
                    return None
            elif d == "0":
                out.append(" " if k == 1 else "0" if k == 2 else "\x00")
            else:
                out.append("1" if k == 2 else " ")      # the 1 key's marks differ from phone to phone
            if out[-1] == "\x00":
                return None
        elif len(tok) == 1 and tok in "-!,:.":
            out.append(tok)
        else:
            return None
    return "".join(out) if hits >= 4 else None


def a1z26_stream(t: str, last_number: bool = False):
    """A1Z26 with what the strict reader of classical.py refuses: a number over 26 is kept as digits.
    Groups joined by - , . are words; white space or '/' is between words. With last_number, a last
    word that is one number of two digits, or two numbers of one digit, is read as those digits."""
    s = t.strip()
    if not s or re.sub(r"[0-9\s/,.\-]", "", s):
        return None
    if "/" in s or re.search(r"\s{2,}|\n", s):
        words = [w for w in re.split(r"\s*/\s*|\s{2,}|\s*\n\s*", s) if w]
    elif re.search(r"[-,.]", s):
        words = s.split()
    else:
        words = [s]
    out = []
    for i, w in enumerate(words):
        nums = [x for x in re.split(r"[-,.\s]+", w) if x]
        if not nums or any(len(x) > 2 for x in nums):
            return None
        if last_number and i == len(words) - 1 and i and len("".join(nums)) == 2 and len(nums) in (1, 2):
            out.append("".join(nums))
            continue
        piece = []
        for x in nums:
            v = int(x)
            if 1 <= v <= 26:
                piece.append(chr(96 + v))
            elif v > 26:
                piece.append(x)
            else:
                return None
        out.append("".join(piece))
    return " ".join(out)


_ARROWS = {"↑": 0, "↗": 1, "→": 2, "↘": 3, "↓": 4, "↙": 5, "←": 6, "↖": 7, "⬆": 0, "⬈": 1, "➡": 2, "⬊": 3, "⬇": 4,
           "⬋": 5, "⬅": 6, "⬉": 7}
_COMPASS = {"n": 0, "ne": 1, "e": 2, "se": 3, "s": 4, "sw": 5, "w": 6, "nw": 7, "north": 0, "northeast": 1, "east": 2,
            "southeast": 3, "south": 4, "southwest": 5, "west": 6, "northwest": 7, "u": 0, "ur": 1, "r": 2, "dr": 3,
            "d": 4, "dl": 5, "l": 6, "ul": 7, "up": 0, "right": 2, "down": 4, "left": 6}
# Flag semaphore as the viewer sees it: the two arms of each letter, 0 = up and clockwise in eighths.
_SEMAPHORE_VIEW = {"a": (4, 5), "b": (4, 6), "c": (4, 7), "d": (4, 0), "e": (4, 1), "f": (4, 2), "g": (4, 3), "h": (5, 6),
                   "i": (5, 7), "j": (0, 2), "k": (5, 0), "l": (5, 1), "m": (5, 2), "n": (5, 3), "o": (6, 7), "p": (6, 0),
                   "q": (6, 1), "r": (6, 2), "s": (6, 3), "t": (7, 0), "u": (7, 1), "v": (0, 3), "w": (1, 2), "x": (1, 3),
                   "y": (7, 2), "z": (3, 2), "#": (0, 1), " ": (4, 4)}
_SEMAPHORE = {frozenset(v): k for k, v in _SEMAPHORE_VIEW.items()}
_SEMAPHORE_MIRROR = {frozenset((-a) % 8 for a in v): k for k, v in _SEMAPHORE_VIEW.items()}
_SEMAPHORE_DIGITS = dict(zip("abcdefghik", "1234567890"))


def semaphore_decode(t: str, mirror: bool = False):
    """Flag semaphore written as two directions per letter: arrows (↓↙ ↓←) or compass points and
    the like (S-SW, down/left) with white space between letters and '/' or two spaces between
    words. `mirror` reads it from the signaller's side. After the numerals sign (up and up-right)
    a to i are 1 to 9 and k is 0, until J (the letters sign) or a space. None for anything else."""
    table = _SEMAPHORE_MIRROR if mirror else _SEMAPHORE
    out, numbers, hits = [], False, 0
    for wi, w in enumerate(x for x in re.split(r"\s*/\s*|\s*\n\s*| {2,}", t.strip()) if x.strip()):
        if wi:
            out.append(" ")
            numbers = False
        for tok in w.split():
            arms = [_ARROWS[c] for c in tok if c in _ARROWS]
            if len(arms) != len(tok):
                parts = [p for p in re.split(r"[-+,&:]", tok.lower()) if p]
                if not all(p in _COMPASS for p in parts):
                    return None
                arms = [_COMPASS[p] for p in parts]
            if len(arms) != 2:
                return None
            c = table.get(frozenset(arms))
            if c is None:
                return None
            hits += 1
            if c == "#":
                numbers = True
            elif c == " ":
                out.append(" ")
                numbers = False
            elif numbers and c == "j":
                numbers = False
            elif numbers:
                if c not in _SEMAPHORE_DIGITS:
                    return None
                out.append(_SEMAPHORE_DIGITS[c])
            else:
                out.append(c)
    return "".join(out) if hits >= 4 else None


def _lossy_readers():
    yield "multitap", multitap_decode
    yield "a1z26", a1z26_stream
    yield "a1z26n", lambda t: a1z26_stream(t, True)
    yield "semaphore", semaphore_decode
    yield "semaphorem", lambda t: semaphore_decode(t, True)
    if K is not None:
        yield "polybius6", lambda t: K.polybius_decode(t, size=6) if re.fullmatch(r"[1-6\s/,.\-]+", t.strip()) else None


def _t9_words(token: str, words) -> list:
    if not _T9_INDEX:
        for w in words:
            if w.isascii() and w.isalpha() and w.islower():
                _T9_INDEX.setdefault(t9(w), []).append(w)
    return _T9_INDEX.get(token, [])


def _lossy_t9(text: str, crib: str, words):
    """The slug of a T9 text (one key per letter), when each of its three words is the only word of the
    vocabulary on its keys and the last token is two digits standing for themselves."""
    s = text.strip()
    if re.sub(r"[0-9\s/,.\-|_#*]", "", s):
        return None
    tokens = [x for x in re.split(r"[^0-9]+", s) if x] if re.search(r"[^0-9]", s) else [x for x in s.split("0") if x]
    want = [t9(w) for w in re.findall(r"[a-z]+", crib.lower())]
    if tokens[:len(want)] != want or len(tokens) != len(want) + 4:
        return None
    tail = tokens[len(want):]
    if not re.fullmatch(r"[0-9]{2}", tail[3]) or not all(re.fullmatch(r"[2-9]+", x) for x in tail[:3]):
        return None
    picks = [_t9_words(x, words) for x in tail[:3]]
    if any(len(p) != 1 for p in picks):
        return None
    return "%s-%s-%s-%s" % (picks[0][0], picks[1][0], picks[2][0], tail[3])


_SLUG = re.compile(r"[a-z]+-[a-z]+-[a-z]+-[0-9]{2}")


def _stream_slug(stream: str, crib_letters: str, words):
    """(method, slug) when a reading without marks gives the sentence's letters in order, nothing else
    before them, and then a slug in one way; else None."""
    s = stream.lower()
    count, end = 0, -1
    for i, c in enumerate(s):
        if "a" <= c <= "z":
            if c != crib_letters[count]:
                return None
            count += 1
            if count == len(crib_letters):
                end = i + 1
                break
        elif c.isdigit():
            return None
    if end < 0:
        return None
    tail = s[end:].strip().lstrip(":;.,!_ ").strip()
    if _SLUG.fullmatch(tail):
        return "as_read", tail
    tokens = [x for x in re.split(r"[^a-z0-9]+", tail) if x]
    if len(tokens) == 4 and all(x.isalpha() for x in tokens[:3]) and re.fullmatch(r"[0-9]{2}", tokens[3]):
        return "breaks_as_hyphens", "-".join(tokens)
    if len(tokens) == 5 and all(x.isalpha() for x in tokens[:3]) and all(re.fullmatch(r"[0-9]", x) for x in tokens[3:]):
        return "breaks_as_hyphens", "-".join(tokens[:3]) + "-" + tokens[3] + tokens[4]
    m = re.fullmatch(r"([a-z]{6,60})[^a-z0-9]*([0-9]{2})", tail)
    if m and words:
        run, splits = m.group(1), []
        for i in range(1, len(run) - 1):
            if run[:i] not in words:
                continue
            for j in range(i + 1, len(run)):
                if run[i:j] in words and run[j:] in words and min(i, j - i, len(run) - j) >= 3:
                    splits.append((run[:i], run[i:j], run[j:]))
        if len(splits) == 1:
            return "vocabulary_split", "-".join(splits[0]) + "-" + m.group(2)
    return None


def lossy(sources, crib: str, words, deadline: float):
    """(code, method, slug, reading) for a blob in a code that cannot carry the whole sentence, or None.

    `sources` is [(text, chain)]: the payload first, then its strict readings. Every reader is tried on
    each, and each text is also taken as it is (a strict reading that lost its marks). All readings that
    give a slug must give the same one; two different slugs are no answer."""
    crib_letters = "".join(c for c in crib.lower() if c.isalpha())
    low = crib.lower()
    found = {}
    for text, chain in sources:
        if time.perf_counter() > deadline:
            return None
        if not text or len(text) > BIG:
            continue
        got = _lossy_t9(text, crib, words)
        if got:
            found.setdefault(got, ("+".join(chain + ("t9",)), "single_word_per_key_run", text))
        streams = [("+".join(chain) or "plain", text)] if chain else []
        for name, reader in _lossy_readers():
            try:
                out = reader(text)
            except Exception:
                out = None
            if out:
                streams.append(("+".join(chain + (name,)), out))
        for code, stream in streams:
            if stream.lower().startswith(low):
                continue          # the sentence itself, marks and all: the crib search has judged this reading
            hit = _stream_slug(stream, crib_letters, words)
            if hit:
                found.setdefault(hit[1], (code, hit[0], stream))
    if len(found) != 1:
        return None
    slug, (code, method, reading) = next(iter(found.items()))
    return code, method, slug, reading


# ---------------------------------------------------------------------------- command line

def main(argv) -> int:
    if not argv or any(a.startswith("-") for a in argv):
        print("usage: formats_more.py <blob-file> [...]", file=sys.stderr)
        return 2
    for path in argv:
        try:
            raw = Path(path).read_bytes()
        except OSError as e:
            print("formats_more.py: %s: %s" % (path, e.strerror or e), file=sys.stderr)
            continue
        DEADLINE[0] = time.perf_counter() + 10
        shown = 0
        for name, out in steps(raw):
            shown += 1
            print("%s: STRICT %-10s %r" % (path, name, out[:160]))
        text = L._text(raw)
        if text is not None:
            crib = "Nice work decoding this warmup! To solve, submit this exact answer to the Game Master: "
            for name, plain in late(text.strip("\r\n"), crib, time.perf_counter() + 10):
                shown += 1
                print("%s: LATE   %-10s %r" % (path, name, plain[:160]))
            for name, reader in _lossy_readers():
                out = reader(text)
                if out:
                    shown += 1
                    print("%s: LOSSY  %-10s %r" % (path, name, out[:160]))
        if not shown:
            print("%s: no reader of formats_more.py takes it" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
