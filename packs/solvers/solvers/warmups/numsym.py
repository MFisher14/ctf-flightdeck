"""Numeric / symbolic encoding decoders for the Warmups & stego lanes (B-094).

Why this file exists
--------------------
Several already-solved challenges (PINK 8/18/22/31, Spooky Numerophobia and
I-D0nt-Feel-S0-G00d) each turned a list of *numbers* or *symbols* into the flag with a
one-off script: numbers read as ASCII codes with a constant offset / reversal / stride;
atomic numbers read as element symbols; a math constant's digits used as an XOR keystream;
leetspeak rotated by a fixed amount; a common factor (GCD) stripped before any of the above.
This module makes those decoders reusable and wires the deterministic ones into
crib_decode.py's strict search (byte_order.py's optional-module interface:
``NAMES`` / ``steps(cur)`` / ``step_fn(name)``), so a numeric blob that hides a flag is
read without a fresh script.

Never wrong (search path)
-------------------------
In the breadth-first search a reader fires only when its decoded bytes contain a
**flag-shaped** string (``word{...}``: ``ctf.flagfmt.BRACE_TEXT``, the any-event shape, see
``_looks_flag`` below). That shape is the signature:
a list of numbers that happens to pass through a reader but makes no flag yields *nothing*,
so the search never fans on garbage and never answers a wrong plain slug. The auto-detected
parameters (orientation, stride phase, offset, keystream offset) are baked into the step
*name* (e.g. ``numascii:rev,odd-13``), so ``step_fn`` replays the exact transform with no
search -- a chain is reproducible.

Candidate path (CLI / reader)
-----------------------------
Run standalone (``python -I numsym.py <file>``) the module also surfaces *candidate* readings
that do not (yet) contain a brace: the atomic-symbol clue (``POISONISNaCN``), the GCD-stripped
re-reading, the plain ASCII-code reading, the emoji name-acrostic, and -- unsure only, never
plain -- the emoji repeated-line diff (PINK 22 kosaken: ~14/23 symbols with ~9 false positives
on a plain line diff, so it is emitted as a human-checked candidate, never an answer).

Standard library plus ``ctf.flagfmt`` (the one source of flag shapes: this module compiles no
flag regex of its own), no I/O outside __main__, no clock, no import of crib_decode, the
math-constant digits computed here with integer arithmetic (no data file).
"""
import functools
import math
import re
import unicodedata

# ctf package import (script runs need the checkout root on sys.path)
try:
    from ctf import flagfmt
except ModuleNotFoundError:
    import sys as _sys
    from pathlib import Path as _Path
    _sys.path.append(str(_Path(__file__).resolve().parents[2]))
    from ctf import flagfmt

MAX_INTS = 4096          # integers parsed from one blob (a flag is short; this bounds the search)
MAX_TEXT = 1 << 16       # bytes of a text blob looked at
MAX_DIGITS = 20000       # decimal digits of a math constant computed (bounds the keystream search)
SEARCH_MAXOFF = 64       # keystream offset window inside the breadth-first search (cheap; deep offsets are CLI-only)
NUMASCII_MAXOFF = 95     # numeric-ASCII offset window in the search: the printable-ASCII span (covers +13, case +32)
CLI_MAXOFF = 4096        # keystream offset window for a dedicated standalone run (pink-18 needs ~1338)

def _looks_flag(text: str) -> bool:
    """True when the text holds a flag of ANY event: ``flagfmt.BRACE_TEXT``, a word of up to 32
    characters that starts at a word boundary, then a brace body of 2..256 characters with no
    brace or newline inside. This is the signature a reader must hit to fire in the search. It
    needs no event profile, so the pack works before a profile names the real prefixes; whether
    a decode IS the event's flag is still decided downstream by crib_decode (``flagfmt.TEXT``)
    and the submit gate, never here. A CSS-shaped token (``btn{color:red}``) is the broad
    shape's known look-alike and never counts (``flagfmt.css_like``)."""
    return any(not flagfmt.css_like(m.group(0)) for m in flagfmt.BRACE_TEXT.finditer(text))


def _clean_ascii(text: str) -> bool:
    """True when every character is printable ASCII or common white space. The search demands this
    of a numeric-ASCII decode so a wrong offset -- which leaves control bytes scattered through the
    text while the broad brace shape still matches some mixed-case brace run -- is refused. The
    correct offset decodes the WHOLE blob cleanly (padding and all), which is the real signature."""
    return all(c in "\t\n\r" or 0x20 <= ord(c) <= 0x7E for c in text)


# -- element symbols (atomic number -> symbol) -----------------------------------------------
# Index 0 unused; ELEMENTS[z] is the IUPAC symbol of element z (1..118). Case is preserved
# (Na, not NA) so a symbol run reads as the challenge intended (PINK 31's "ThINSg").
ELEMENTS = (
    "", "H", "He", "Li", "Be", "B", "C", "N", "O", "F", "Ne", "Na", "Mg", "Al", "Si", "P",
    "S", "Cl", "Ar", "K", "Ca", "Sc", "Ti", "V", "Cr", "Mn", "Fe", "Co", "Ni", "Cu", "Zn",
    "Ga", "Ge", "As", "Se", "Br", "Kr", "Rb", "Sr", "Y", "Zr", "Nb", "Mo", "Tc", "Ru", "Rh",
    "Pd", "Ag", "Cd", "In", "Sn", "Sb", "Te", "I", "Xe", "Cs", "Ba", "La", "Ce", "Pr", "Nd",
    "Pm", "Sm", "Eu", "Gd", "Tb", "Dy", "Ho", "Er", "Tm", "Yb", "Lu", "Hf", "Ta", "W", "Re",
    "Os", "Ir", "Pt", "Au", "Hg", "Tl", "Pb", "Bi", "Po", "At", "Rn", "Fr", "Ra", "Ac", "Th",
    "Pa", "U", "Np", "Pu", "Am", "Cm", "Bk", "Cf", "Es", "Fm", "Md", "No", "Lr", "Rf", "Db",
    "Sg", "Bh", "Hs", "Mt", "Ds", "Rg", "Cn", "Nh", "Fl", "Mc", "Lv", "Ts", "Og",
)
MAX_Z = len(ELEMENTS) - 1


# -- leetspeak table (self-contained; matches solvers/common/classical.py's LEET) ------------
# A digit/symbol stands for the letter(s) it resembles. '1' is ambiguous (i or l): the un-leet
# here maps it to 'i' (the common CTF convention) and keeps both readings available via
# un_leet's `one_is` argument for the standalone search.
LEET = {"4": "a", "@": "a", "8": "b", "3": "e", "6": "g", "9": "g", "1": "i", "!": "i",
        "0": "o", "5": "s", "$": "s", "7": "t", "2": "z"}


# -- integer parsing -------------------------------------------------------------------------
_INT_TOKEN = re.compile(r"0[xX][0-9a-fA-F]+|[0-9]+")
_SEP_ONLY = re.compile(r"[\s,;|/\\.\-:_\[\](){}<>]+")


def _text(b) -> "str | None":
    if isinstance(b, str):
        return b if len(b) <= MAX_TEXT else None
    if not isinstance(b, (bytes, bytearray, memoryview)):
        return None
    b = bytes(b)
    if len(b) > MAX_TEXT:
        return None
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return b.decode("latin-1")
        except UnicodeDecodeError:
            return None


def parse_ints(b) -> "list[int] | None":
    """The non-negative integers in a blob, in order, or None when the blob is not a list of
    numbers. Strict: between the number tokens there may be only separators (space, comma, and
    the usual bracketing / joining marks) -- any other letter means the blob is prose, not a
    number list, so a sentence that merely contains a number is refused. Decimal, or ``0x``-hex.
    """
    t = _text(b)
    if t is None:
        return None
    t = t.strip()
    if not t:
        return None
    tokens = _INT_TOKEN.findall(t)
    if len(tokens) < 2 or len(tokens) > MAX_INTS:
        return None
    # The gaps between/around tokens must be separators only (no stray letters).
    gaps = _INT_TOKEN.sub("\x00", t)
    for chunk in gaps.split("\x00"):
        if chunk and _SEP_ONLY.fullmatch(chunk) is None:
            return None
    out = []
    for tok in tokens:
        out.append(int(tok, 16) if tok[:2].lower() == "0x" else int(tok))
    return out


# -- atomic numbers -> element symbols -------------------------------------------------------
def atomic_decode(values) -> "str | None":
    """Each integer read as an atomic number and replaced by its element symbol, joined. None
    unless every value is a real element (1..118). Case is preserved from the symbol table."""
    if not values or any(not (1 <= v <= MAX_Z) for v in values):
        return None
    return "".join(ELEMENTS[v] for v in values)


# -- numeric ASCII / codepoint lists, with offset / stride / reversal auto-detect -------------
_ORIENTS = ("fwd", "rev")
_PHASES = ("all", "even", "odd")


def _apply_numascii(values, orient: str, phase: str, delta: int) -> "str | None":
    """Transform an int list and map to text, or None when a selected value leaves the valid
    codepoint range. ``orient`` reverses the stream; ``phase`` selects which positions have
    ``delta`` subtracted (all / even indices / odd indices); the rest pass through. A codepoint
    list is the special case delta=0, phase=all, orient=fwd."""
    seq = list(reversed(values)) if orient == "rev" else list(values)
    out = []
    for i, v in enumerate(seq):
        if phase == "all" or (phase == "even") == (i % 2 == 0):
            v = v - delta
        if not (0 <= v <= 0x10FFFF) or 0xD800 <= v <= 0xDFFF:
            return None
        out.append(chr(v))
    return "".join(out)


def numascii_search(values, maxoff: int = SEARCH_MAXOFF):
    """[(name, text)] for every orientation / stride-phase / offset whose decode contains a
    flag-shaped string. The offset is searched 0..maxoff (subtracted from the selected
    positions). Deterministic and self-gating: a list that hides no flag yields nothing."""
    hits = []
    seen = set()
    for orient in _ORIENTS:
        for phase in _PHASES:
            # delta 0 only needs phase 'all' (even/odd with delta 0 are identical to it)
            deltas = range(0, maxoff + 1) if phase == "all" else range(1, maxoff + 1)
            for delta in deltas:
                text = _apply_numascii(values, orient, phase, delta)
                if text is None or not _clean_ascii(text) or not _looks_flag(text):
                    continue
                name = "numascii:%s,%s%+d" % (orient, phase, -delta) if delta else "numascii:%s,%s+0" % (orient, phase)
                if text in seen:
                    continue
                seen.add(text)
                hits.append((name, text))
    return hits


def numascii_plain(values) -> "str | None":
    """The straightforward reading: forward, every value a codepoint (delta 0). This is the bare
    numeric-ASCII / Unicode-codepoint list decoder; a candidate, surfaced even without a flag."""
    return _apply_numascii(values, "fwd", "all", 0)


def _numascii_name_fn(name: str):
    """Rebuild the exact transform encoded in a ``numascii:orient,phase±delta`` step name."""
    m = re.fullmatch(r"numascii:(fwd|rev),(all|even|odd)([+-]\d+)", name)
    if not m:
        return None
    orient, phase, signed = m.group(1), m.group(2), int(m.group(3))
    delta = -signed  # name stores -delta (what was subtracted shown as a negative shift)

    def f(values):
        return _apply_numascii(values, orient, phase, delta)
    return f


# -- smooth-integer / divisor (common-factor) -------------------------------------------------
def gcd_all(values) -> int:
    g = 0
    for v in values:
        g = math.gcd(g, v)
    return g


def smooth_reduce(values) -> "tuple[int, list[int]] | None":
    """(g, [v // g]) when the values share a common factor g > 1, else None. This is the
    'smooth integer' / divisor step: strip the shared factor, then re-read the quotients."""
    if not values or any(v <= 0 for v in values):
        return None
    g = gcd_all(values)
    if g <= 1:
        return None
    return g, [v // g for v in values]


# -- math-constant digit keystreams (pi / e / phi), computed in-repo -------------------------
@functools.lru_cache(maxsize=4)
def _pi_digits(n: int) -> str:
    """The first n decimal digits of pi (leading '3' included) via Machin's formula in integers:
    pi = 16*arctan(1/5) - 4*arctan(1/239)."""
    guard = 10
    scale = 10 ** (n + guard)

    def arctan_inv(x):
        total = 0
        term = scale // x
        xx = x * x
        k = 1
        sign = 1
        while term:
            total += sign * (term // k)
            term //= xx
            k += 2
            sign = -sign
        return total

    pi = (16 * arctan_inv(5) - 4 * arctan_inv(239)) // (10 ** guard)
    return str(pi)[:n]


@functools.lru_cache(maxsize=4)
def _e_digits(n: int) -> str:
    """The first n decimal digits of e (leading '2') via e = sum_{k>=0} 1/k! in integers."""
    guard = 10
    scale = 10 ** (n + guard)
    total = 0
    term = scale
    k = 1
    while term:
        total += term
        term //= k
        k += 1
    return str(total // (10 ** guard))[:n]


@functools.lru_cache(maxsize=4)
def _phi_digits(n: int) -> str:
    """The first n decimal digits of phi = (1 + sqrt 5) / 2 (leading '1') via integer isqrt."""
    scale = 10 ** (n + 10)
    root5 = math.isqrt(5 * scale * scale)
    phi = (scale + root5) // 2
    return str(phi)[:n]


_CONSTS = {"pi": _pi_digits, "e": _e_digits, "phi": _phi_digits}


def const_digits(name: str, n: int) -> str:
    """The first n decimal digits (integer part included, no point) of pi / e / phi."""
    if name not in _CONSTS:
        raise ValueError("unknown constant %r" % (name,))
    if not (1 <= n <= MAX_DIGITS):
        raise ValueError("digit count out of range")
    return _CONSTS[name](n)


def _keystream_from(digits: str, group: int, off: int, count: int) -> "list[int] | None":
    """`count` key bytes from an already-computed digit string: `group` digits at a time from
    position `off`, each group a decimal number mod 256. None when the digits run short."""
    if off + group * count > len(digits):
        return None
    return [int(digits[off + group * i: off + group * i + group]) % 256 for i in range(count)]


def _keystream(const: str, group: int, off: int, count: int) -> "list[int] | None":
    """`count` key bytes of `const` (digits computed on demand). Convenience wrapper used by the
    replay path and the tests; the search computes the digit string once (mathkey_search)."""
    need = off + group * count
    if need > MAX_DIGITS:
        return None
    return _keystream_from(const_digits(const, need), group, off, count)


def _as_cipher(b) -> "bytes | None":
    """The ciphertext bytes of a blob, or None. A keystream cipher is a SINGLE contiguous hex run
    (e.g. pink-18's ``73665d14...``); a space/comma-separated list of numbers is NOT one -- that
    is numeric-ASCII / atomic territory, and reading it as hex would also run an expensive digit
    search on every numeric state of the warmups search. Raw non-ASCII bytes are taken as the
    cipher directly. A flag is short, so a cipher over 64 bytes is not a keystream target here."""
    t = _text(b)
    if t is not None:
        s = t.strip()
        if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", s):   # one contiguous hex run, no separators
            raw = bytes.fromhex(s)
            if 2 <= len(raw) <= 64:
                return raw
        return None   # any text that is not a single hex run is not a hex cipher
    if isinstance(b, (bytes, bytearray, memoryview)):
        raw = bytes(b)
        if 2 <= len(raw) <= 64 and not raw.isascii():
            return raw
    return None


def mathkey_search(b, maxoff: int = SEARCH_MAXOFF):
    """[(name, text)] for every pi/e/phi keystream (group 1..3, op xor/sub/add, offset 0..maxoff)
    whose plaintext contains a flag-shaped string. Self-gating on the flag shape, so a blob that
    is not a keystreamed cipher yields nothing."""
    cipher = _as_cipher(b)
    if cipher is None:
        return []
    hits = []
    seen = set()
    for const in _CONSTS:
        for group in (1, 2, 3):
            # Compute the digit string ONCE at the longest length any offset needs, then slice it
            # per offset. (Recomputing the constant inside the offset loop was O(maxoff) full
            # Machin/spigot evaluations -- tens of ms on every hex-looking search state.)
            need = min(MAX_DIGITS, maxoff + group * len(cipher))
            digits = const_digits(const, need)
            for off in range(0, maxoff + 1):
                ks = _keystream_from(digits, group, off, len(cipher))
                if ks is None:
                    break  # digits exhausted for this (const, group): larger off is worse
                for op in ("xor", "sub", "add"):
                    if op == "xor":
                        out = bytes((c ^ k) & 0xFF for c, k in zip(cipher, ks))
                    elif op == "sub":
                        out = bytes((c - k) & 0xFF for c, k in zip(cipher, ks))
                    else:
                        out = bytes((c + k) & 0xFF for c, k in zip(cipher, ks))
                    try:
                        text = out.decode("ascii")
                    except UnicodeDecodeError:
                        continue
                    if not _looks_flag(text) or text in seen:
                        continue
                    seen.add(text)
                    hits.append(("mathkey:%s,%d,%s,%d" % (const, group, op, off), text))
    return hits


def _mathkey_name_fn(name: str):
    m = re.fullmatch(r"mathkey:(pi|e|phi),(\d+),(xor|sub|add),(\d+)", name)
    if not m:
        return None
    const, group, op, off = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))

    def f(b):
        cipher = _as_cipher(b)
        if cipher is None:
            return None
        ks = _keystream(const, group, off, len(cipher))
        if ks is None:
            return None
        if op == "xor":
            out = bytes((c ^ k) & 0xFF for c, k in zip(cipher, ks))
        elif op == "sub":
            out = bytes((c - k) & 0xFF for c, k in zip(cipher, ks))
        else:
            out = bytes((c + k) & 0xFF for c, k in zip(cipher, ks))
        try:
            out.decode("ascii")
        except UnicodeDecodeError:
            return None
        return out
    return f


# -- crib-locked ROT-N leetspeak -------------------------------------------------------------
def un_leet(text: str, one_is: str = "i") -> str:
    """Leetspeak replaced letter for letter ('4'->a, '3'->e, ...). '1' maps to `one_is`."""
    out = []
    for ch in text:
        if ch == "1":
            out.append(one_is)
        elif ch in LEET:
            out.append(LEET[ch])
        else:
            out.append(ch)
    return "".join(out)


def _rot_letters(text: str, n: int) -> str:
    """Caesar shift of the ASCII letters of a text by n; digits, marks and spaces pass through."""
    out = []
    for ch in text:
        o = ord(ch)
        if 65 <= o <= 90:
            out.append(chr((o - 65 + n) % 26 + 65))
        elif 97 <= o <= 122:
            out.append(chr((o - 97 + n) % 26 + 97))
        else:
            out.append(ch)
    return "".join(out)


def leetrot_search(b):
    """[(name, text)] for ROT-N (0..25) applied to a leet text's letters (digits left as the
    leet markers they are) whose result contains a flag-shaped string. Self-gating on the flag
    shape. ROT is on the letters only, as the 'move the neon' (element 10 -> ROT-10) class of
    challenge intends."""
    t = _text(b)
    if t is None or not t.isascii():
        return []
    hits = []
    seen = set()
    for n in range(0, 26):
        text = _rot_letters(t, n)
        if _looks_flag(text) and text not in seen:
            seen.add(text)
            hits.append(("leetrot:%d" % n, text))
    return hits


def _leetrot_name_fn(name: str):
    m = re.fullmatch(r"leetrot:(\d+)", name)
    if not m:
        return None
    n = int(m.group(1)) % 26

    def f(b):
        t = _text(b)
        if t is None or not t.isascii():
            return None
        return _rot_letters(t, n).encode("ascii", "ignore")
    return f


# -- emoji readers (candidate / CLI only; multi-char or heuristic) ----------------------------
def _emoji_chars(text: str):
    """The pictographic (emoji) code points of a text, variation selectors and ZWJ dropped."""
    out = []
    for ch in text:
        if ch in ("️", "︎", "‍"):
            continue
        o = ord(ch)
        if o >= 0x2190 and (0x1F000 <= o <= 0x1FAFF or 0x2600 <= o <= 0x27BF or 0x2B00 <= o <= 0x2BFF
                            or 0x1F1E6 <= o <= 0x1F1FF or o in (0x203C, 0x2049)):
            out.append(ch)
    return out


def emoji_acrostic(text: str) -> "str | None":
    """First letter of each emoji's Unicode name, in order (PINK 8). A deterministic candidate:
    'PURSE'->P, 'IZAKAYA LANTERN'->I, ... A repeated filler emoji usually stands for one word
    (e.g. UNDERSCORE); that mapping is left to the human reading the acrostic. None when the text
    carries fewer than four emoji."""
    chars = _emoji_chars(text)
    if len(chars) < 4:
        return None
    letters = []
    for ch in chars:
        try:
            name = unicodedata.name(ch)
        except ValueError:
            return None
        letters.append(name[0])
    return "".join(letters)


def emoji_line_diff(text: str) -> "list[str]":
    """UNSURE candidates for the PINK-22 (kosaken) pattern: a block of repeated lyric lines with
    an emoji *inserted* here and there; the message is the first letter of each inserted emoji's
    name, in file order. A plain line diff recovers ~14 of 23 symbols with ~9 false positives
    (notes: lyric sense is also needed), so this is emitted as a candidate for a human to check,
    never as a plain answer.

    Method: the emoji of each line are diffed against the single most common line's emoji; the
    emoji present beyond that baseline are the insertions, mapped to the first letter of their
    name. Returns the acrostic string(s); empty when there is no repeated structure.
    """
    import difflib
    lines = [ln for ln in text.splitlines() if _emoji_chars(ln)]
    if len(lines) < 3:
        return []
    per_line = [_emoji_chars(ln) for ln in lines]
    # The baseline is the most common multiset of emoji across lines (the un-altered lyric line).
    from collections import Counter
    key = Counter(tuple(e) for e in per_line)
    baseline = list(max(key, key=lambda k: key[k]))
    inserted = []
    for emo in per_line:
        sm = difflib.SequenceMatcher(a=baseline, b=emo, autojunk=False)
        for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
            if tag in ("insert", "replace"):
                inserted.extend(emo[j1:j2])
    out = []
    for ch in inserted:
        try:
            out.append(unicodedata.name(ch)[0])
        except ValueError:
            continue
    return ["".join(out)] if out else []


# -- registry (byte_order.py optional-module interface) --------------------------------------
# The only non-parametric name; the rest (numascii:..., mathkey:..., smoothgcd:..., leetrot:...)
# carry their auto-detected parameters, so they cannot be enumerated. crib_decode adds NAMES to
# its strict-name set and dispatches any of our names through `owns` + step_fn.
NAMES = frozenset({"atomic"})
_NAME_KINDS = frozenset({"numascii", "mathkey", "smoothgcd", "leetrot"})


def owns(name: str) -> bool:
    """True when a step name belongs to this module (used by crib_decode._step_fn)."""
    return name == "atomic" or name.split(":", 1)[0] in _NAME_KINDS


def steps(cur):
    """[(name, bytes)] the deterministic readers make of one search state, each firing only when
    its decode holds a flag-shaped string (the signature). The parametric name lets step_fn
    replay the exact transform. Emoji readers are not here: they are multi-line / unsure and run
    only from the CLI / reader helpers."""
    out = []
    values = parse_ints(cur)
    if values is not None:
        # numeric-ASCII / codepoint list with offset / stride / reversal auto-detect
        for name, text in numascii_search(values):
            out.append((name, text.encode("utf-8")))
        # atomic-number -> symbol (fires only if the symbols themselves spell a flag)
        sym = atomic_decode(values)
        if sym is not None and _looks_flag(sym):
            out.append(("atomic", sym.encode("ascii")))
        # smooth-integer: strip a shared factor, then re-read the quotients
        red = smooth_reduce(values)
        if red is not None:
            g, quo = red
            qsym = atomic_decode(quo)
            if qsym is not None and _looks_flag(qsym):
                out.append(("smoothgcd:%d,atomic" % g, qsym.encode("ascii")))
            qtext = _apply_numascii(quo, "fwd", "all", 0)
            if qtext is not None and _looks_flag(qtext):
                out.append(("smoothgcd:%d,ascii" % g, qtext.encode("utf-8")))
    # math-constant keystream (only for a short hex / binary cipher)
    for name, text in mathkey_search(cur):
        out.append((name, text.encode("ascii")))
    # NOTE: leetrot is deliberately NOT in the search. Every ROT-N of a braced leet string stays
    # printable and brace-shaped, so all 26 rotations pass a flag-shape gate -- that would surface
    # 26 rival "flags" with no way to pick the right one without a dictionary. leetrot is a CLI /
    # read_candidates helper only (a human reads the 26 rotations), never a plain search answer.
    return out


def step_fn(name: str):
    """The decoder (bytes -> bytes | None) of one step by its name, or None. Replays the exact
    transform baked into the name; no search, so a chain is deterministic and reproducible."""
    if name == "atomic":
        def f_atomic(b):
            values = parse_ints(b)
            if values is None:
                return None
            sym = atomic_decode(values)
            return sym.encode("ascii") if sym is not None else None
        return f_atomic

    if name.startswith("smoothgcd:"):
        m = re.fullmatch(r"smoothgcd:(\d+),(atomic|ascii)", name)
        if not m:
            return None
        g, interp = int(m.group(1)), m.group(2)

        def f_smooth(b):
            values = parse_ints(b)
            if values is None or gcd_all(values) != g:
                return None
            quo = [v // g for v in values]
            if interp == "atomic":
                sym = atomic_decode(quo)
                return sym.encode("ascii") if sym is not None else None
            text = _apply_numascii(quo, "fwd", "all", 0)
            return text.encode("utf-8") if text is not None else None
        return f_smooth

    if name.startswith("numascii:"):
        fn = _numascii_name_fn(name)
        if fn is None:
            return None

        def f_num(b):
            values = parse_ints(b)
            if values is None:
                return None
            text = fn(values)
            return text.encode("utf-8") if text is not None else None
        return f_num

    if name.startswith("mathkey:"):
        return _mathkey_name_fn(name)

    if name.startswith("leetrot:"):
        return _leetrot_name_fn(name)

    return None


# -- standalone reader (CLI / test) ----------------------------------------------------------
def read_candidates(b) -> "list[tuple[str, str]]":
    """Every (name, reading) this module makes of a blob, flag-bearing readings first, then the
    clue candidates (atomic symbols, GCD-reduced re-readings, the plain ASCII-code reading, the
    emoji acrostic, and the unsure emoji line diff). For human / CLI use; the search uses
    ``steps`` (flag-gated) only."""
    out = []
    # flag-gated readings (the ones the search would surface)
    for name, raw in steps(b):
        try:
            out.append((name, raw.decode("utf-8")))
        except UnicodeDecodeError:
            out.append((name, raw.decode("latin-1")))
    # deep keystream search for a dedicated run (pink 18 needs offset ~1338)
    for name, text in mathkey_search(b, maxoff=CLI_MAXOFF):
        if (name, text) not in out:
            out.append((name, text))
    values = parse_ints(b)
    if values is not None:
        sym = atomic_decode(values)
        if sym is not None:
            out.append(("atomic?", sym))
        red = smooth_reduce(values)
        if red is not None:
            g, quo = red
            qsym = atomic_decode(quo)
            if qsym is not None:
                out.append(("smoothgcd:%d,atomic?" % g, qsym))
            qtext = _apply_numascii(quo, "fwd", "all", 0)
            if qtext is not None:
                out.append(("smoothgcd:%d,ascii?" % g, qtext))
        plain = numascii_plain(values)
        if plain is not None:
            out.append(("numascii?", plain))
    t = _text(b)
    if t is not None:
        acrostic = emoji_acrostic(t)
        if acrostic is not None:
            out.append(("emoji-acrostic?", acrostic))
        for cand in emoji_line_diff(t):
            out.append(("emoji-linediff? (UNSURE)", cand))
    # dedupe, keep first (search/flag readings rank first)
    seen = set()
    uniq = []
    for name, text in out:
        key = (name, text)
        if key in seen:
            continue
        seen.add(key)
        uniq.append((name, text))
    return uniq


if __name__ == "__main__":
    import sys
    args = sys.argv[1:]
    if not args or any(a in ("-h", "--help") for a in args):
        print("usage: numsym.py <file> [...]", file=sys.stdout if args else sys.stderr)
        raise SystemExit(0 if args else 2)
    for path in args:
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            print("numsym.py: %s" % (exc,), file=sys.stderr)
            raise SystemExit(2)
        cands = read_candidates(data)
        if not cands:
            print("%s: no numeric/symbolic reading" % (path,))
            continue
        print("%s:" % (path,))
        for name, text in cands:
            flag = "  <- FLAG-SHAPED" if _looks_flag(text) else ""
            print("  [%s] %s%s" % (name, text, flag))
