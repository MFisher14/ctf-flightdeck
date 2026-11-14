"""Warmups redundant decoders and the structural-decode backstop (wave123, 2026-10-24).

Two jobs, both ADAPTATION HARDENING: they only ever turn a blob the shipped readers left
None into an UNSURE, probeable answer, and they never make a plain answer. A `None` is the
one thing they replace.

1. A SECOND, INDEPENDENT decoder for the common radix/base families (base64, base32, URL
   percent, Ascii85/base85) and for run-length, the way layered_decode's decimal/octal/HTML
   already have d_dec2/d_oct2/d_html2. These are hand-written: they call neither `base64` nor
   `urllib`, so a bug in the shipped reader (which does) cannot blank them too. Each also reads
   a few presentations the strict shipped reader refuses (lowercase base32, `+`-for-space URL,
   char/count run-length), so a single-reader bug cannot blank a whole day: the day degrades
   to a probeable candidate instead of a total blank.

2. `candidates(data)`: the proposer-style backstop. When every shipped reader has left a WHOLE
   blob None (crib_decode asks this last, like _lattice and _enigma, and only for one payload),
   each independent decoder is run over the blob (and over an independent hex surface, since
   warmups so often wrap one encoding in hex), and a reading is offered ONLY when it is an
   unambiguous crib-anchored lane payload (the whole crib sentence intact, exactly one slug token,
   that slug the final content -- see _slug_of), so a shape a shipped reader would itself have seen
   and declined, and a stream nothing truly decoded, give nothing. crib_decode wraps the tokens in a `labels.candidates` set under
   a key fingerprinted by the blob's own bytes and readings, so an accepted name can never answer
   a different value on a different variant, and it is never plain before the judge accepts it and
   only ever probed off the clock (row 346). A free-text slug no reader nails degrades to a
   probeable candidate instead of None.

Pure and bounded: no Game Master request, no clock, no file read, no import of a shipped reader,
no state. Every function returns bytes/str/list or None and never raises on bad input. The slug
shape and the crib sentence are passed in by the caller, so this module knows nothing of the
lane's conventions.
"""

import re

# A slug is three lowercase words and two digits (crib_decode.SLUG_FULL); the caller passes the
# live object so this module never drifts from it, but a self-contained default keeps the unit
# tests and a standalone import honest.
SLUG_FULL = re.compile(r"[a-z]+-[a-z]+-[a-z]+-[0-9]{2}")

MAX_BYTES = 8192          # a blob this reader looks at at all (crib_decode.BIG); a base/TT is a few hundred
MIN_DECODED = 8           # a decoded reading shorter than this proves nothing
PRINTABLE_MIN = 0.90      # a decoded reading must be this printable to be read as text
MAX_OPTIONS = 12          # labels.candidates keeps 12; we never offer more

_B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_B32_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
_B85_RFC = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            "!#$%&()*+-;<=>?@^_`{|}~")
_WS = " \t\r\n\f\v"


def _text(b):
    """The bytes as text (UTF-8, else Latin-1), or None. Latin-1 never fails, so this is for the
    raw-text surface; a decoder that must see real UTF-8 decodes its own bytes."""
    if not isinstance(b, (bytes, bytearray, memoryview)):
        if isinstance(b, str):
            return b
        return None
    b = bytes(b)
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return b.decode("latin-1")
        except Exception:
            return None


def _strip_ws(s):
    return "".join(ch for ch in s if ch not in _WS)


def _mostly_printable(text):
    """True when `text` reads as text: non-empty, not too long, and at least PRINTABLE_MIN of its
    characters print (letters, digits, punctuation, the usual white space)."""
    if not text or len(text) > MAX_BYTES:
        return False
    good = 0
    for ch in text:
        o = ord(ch)
        if 32 <= o < 127 or ch in "\r\n\t":
            good += 1
        elif o >= 160 and ch.isprintable():
            good += 1
    return good / len(text) >= PRINTABLE_MIN


# --------------------------------------------------------------------------- independent decoders

def hex_alt(b):
    """Hexadecimal, independent of bytes.fromhex: a manual nibble map, tolerating 0x / \\x / %
    markers and ``:,; `` separators, an even number of digits, at least MIN_DECODED bytes out."""
    t = _text(b)
    if t is None:
        return None
    t = re.sub(r"0x|0X|\\x|%|[\s:,;]", "", t)
    if len(t) < 2 * MIN_DECODED or len(t) % 2:
        return None
    vals = []
    for i in range(0, len(t), 2):
        hi = _HEXVAL.get(t[i])
        lo = _HEXVAL.get(t[i + 1])
        if hi is None or lo is None:
            return None
        vals.append(hi * 16 + lo)
    return bytes(vals)


_HEXVAL = {c: i for i, c in enumerate("0123456789abcdef")}
_HEXVAL.update({c: i for i, c in enumerate("0123456789ABCDEF")})


def _base_n(alphabet, in_bits, out_bits):
    """A general radix decoder (base64 out_bits 8/in_bits 6, base32 8/5). Independent of the
    `base64` module. Tolerates white space and any amount of `=` padding; refuses a character
    outside the alphabet and an impossible leftover-bit count."""
    index = {c: i for i, c in enumerate(alphabet)}

    def f(b, _upper=False):
        t = _text(b)
        if t is None:
            return None
        t = _strip_ws(t)
        if _upper:
            t = t.upper()
        t = t.rstrip("=")
        if len(t) < 2:
            return None
        acc = bits = 0
        out = bytearray()
        for ch in t:
            v = index.get(ch)
            if v is None:
                return None
            acc = (acc << in_bits) | v
            bits += in_bits
            if bits >= out_bits:
                bits -= out_bits
                out.append((acc >> bits) & 0xFF)
        # the leftover bits must be padding zeros, and there must be fewer than a whole byte
        if bits >= out_bits or (acc & ((1 << bits) - 1)):
            return None
        return bytes(out) if len(out) >= MIN_DECODED else None
    return f


_b64_std_raw = _base_n(_B64_STD, 6, 8)
_b64_url_raw = _base_n(_B64_URL, 6, 8)
_b32_std_raw = _base_n(_B32_STD, 5, 8)
_b32_hex_raw = _base_n(_B32_HEX, 5, 8)


def b64_alt(b):
    """Standard base64 (A-Za-z0-9+/), hand-rolled."""
    return _b64_std_raw(b)


def b64url_alt(b):
    """URL-safe base64 (A-Za-z0-9-_), hand-rolled."""
    return _b64_url_raw(b)


def b32_alt(b):
    """RFC 4648 base32, hand-rolled; case-insensitive (the shipped reader upper-cases too, but a
    bug there cannot reach here)."""
    return _b32_std_raw(b, _upper=True)


def b32hex_alt(b):
    """base32hex (extended-hex alphabet 0-9A-V), hand-rolled, case-insensitive."""
    return _b32_hex_raw(b, _upper=True)


def url_alt(b):
    """Percent-decoding, hand-rolled (no urllib), with `+` read as a space. A string that uses only
    `+` for its spaces and no %XX is read here, where the shipped d_url (which needs a %XX) refuses
    it; a string with neither is refused."""
    t = _text(b)
    if t is None:
        return None
    if "%" not in t and "+" not in t:
        return None
    out = bytearray()
    i, n = 0, len(t)
    while i < n:
        c = t[i]
        if c == "%":
            if i + 2 >= n:
                return None
            hi = _HEXVAL.get(t[i + 1])
            lo = _HEXVAL.get(t[i + 2])
            if hi is None or lo is None:
                return None
            out.append(hi * 16 + lo)
            i += 3
        elif c == "+":
            out.append(0x20)
            i += 1
        else:
            out += c.encode("utf-8", "replace")
            i += 1
    return bytes(out) if len(out) >= MIN_DECODED else None


def a85_alt(b):
    """Ascii85 (btoa), hand-rolled: five characters !..u a group of four bytes, `z` four zero bytes,
    an optional Adobe <~ ~> frame, a short final group padded with `u`. Independent of base64.a85decode."""
    t = _text(b)
    if t is None:
        return None
    t = t.strip()
    if t.startswith("<~"):
        t = t[2:]
        t = t[:-2] if t.endswith("~>") else t
    t = _strip_ws(t)
    if len(t) < 5:
        return None
    out = bytearray()
    group = []
    for ch in t:
        if ch == "z" and not group:
            out += b"\x00\x00\x00\x00"
            continue
        o = ord(ch)
        if o < 33 or o > 117:        # not !..u
            return None
        group.append(o - 33)
        if len(group) == 5:
            acc = 0
            for g in group:
                acc = acc * 85 + g
            if acc > 0xFFFFFFFF:
                return None
            out += acc.to_bytes(4, "big")
            group = []
    if group:
        if len(group) == 1:
            return None
        pad = 5 - len(group)
        acc = 0
        for g in group + [84] * pad:
            acc = acc * 85 + g
        if acc > 0xFFFFFFFF:
            return None
        out += acc.to_bytes(4, "big")[:4 - pad]
    return bytes(out) if len(out) >= MIN_DECODED else None


def b85_alt(b):
    """RFC 1924 base85 (the alphabet base64.b85decode uses), hand-rolled: five characters a group
    of four bytes."""
    t = _text(b)
    if t is None:
        return None
    t = _strip_ws(t)
    if len(t) < 5:
        return None
    index = _B85_INDEX
    out = bytearray()
    for i in range(0, len(t), 5):
        chunk = t[i:i + 5]
        acc = 0
        for ch in chunk:
            v = index.get(ch)
            if v is None:
                return None
            acc = acc * 85 + v
        if len(chunk) == 5:
            if acc > 0xFFFFFFFF:
                return None
            out += acc.to_bytes(4, "big")
        else:
            if len(chunk) == 1:
                return None
            pad = 5 - len(chunk)
            for _ in range(pad):
                acc = acc * 85 + 84
            if acc > 0xFFFFFFFF:
                return None
            out += acc.to_bytes(4, "big")[:4 - pad]
    return bytes(out) if len(out) >= MIN_DECODED else None


_B85_INDEX = {c: i for i, c in enumerate(_B85_RFC)}


def rle_pairs_alt(b):
    """Run-length in the common ``<char><count>`` form (CyberChef's "Run Length Encoding": each byte
    followed by a decimal repeat count, e.g. ``N1i1c1e1 1w1...`` or ``a3b2``). The shipped d_runlength
    reads only ``<count>:<char>,``, so this is its independent complement. Strict: the whole string
    must parse as char/count pairs, each count 1..100000, at least two pairs, the result printable."""
    t = _text(b)
    if t is None:
        return None
    t = t.strip("\r\n")
    if len(t) < 2:
        return None
    out = []
    i, n, pairs = 0, len(t), 0
    while i < n:
        ch = t[i]
        if ch.isdigit():
            return None                      # a count with no character before it is the other form
        j = i + 1
        while j < n and t[j].isdigit():
            j += 1
        if j == i + 1:
            return None                      # no count after the character
        count = int(t[i + 1:j])
        if count < 1 or count > 100000:
            return None
        out.append(ch * count)
        pairs += 1
        i = j
    if pairs < 2:
        return None
    return "".join(out).encode("utf-8", "replace")


def rle_counts_alt(b):
    """Run-length in the ``<count><char>`` form (e.g. ``1N1i1c1e`` or ``3a2b``): a decimal count then
    one character, repeated. Independent of the shipped ``<count>:<char>,`` reader. Strict as above."""
    t = _text(b)
    if t is None:
        return None
    t = t.strip("\r\n")
    if len(t) < 2:
        return None
    out = []
    i, n, pairs = 0, len(t), 0
    while i < n:
        j = i
        while j < n and t[j].isdigit():
            j += 1
        if j == i or j >= n:
            return None                      # no leading count, or a count with no character after it
        count = int(t[i:j])
        if count < 1 or count > 100000:
            return None
        out.append(t[j] * count)
        pairs += 1
        i = j + 1
    if pairs < 2:
        return None
    return "".join(out).encode("utf-8", "replace")


# The independent decoders, best first (the plainer and more self-checking read earlier, so their
# token is the best-ranked candidate). Each is a REAL decode transform: a backstop offer must come
# from a transform that actually decoded the stream, never from an identity read of the raw bytes.
# There is deliberately no bare identity ("plain") reader here: _text() reads any bytes as latin-1, so
# an identity read of an UNDECODABLE stream (e.g. an lz4 block with no length header) that happens to
# carry a slug-shaped tail would manufacture a mangled slug from bytes nothing decoded -- a BAD offer.
# A blob that is already the plaintext is the shipped crib/plain readers' to answer, not the backstop's.
# Each name is a hypothesis, never a value.
DECODERS = [
    ("b64", b64_alt),
    ("b64url", b64url_alt),
    ("b32", b32_alt),
    ("b32hex", b32hex_alt),
    ("a85", a85_alt),
    ("b85", b85_alt),
    ("url", url_alt),
    ("rle_pairs", rle_pairs_alt),
    ("rle_counts", rle_counts_alt),
]


# --------------------------------------------------------------------------- the backstop

def _slug_of(decoded, crib_l, slug_re):
    """The slug an UNAMBIGUOUS, crib-anchored decoded reading offers, or None.

    A reading qualifies only when it is unmistakably the lane's own payload: it reads as clean text
    (mostly printable), it carries the WHOLE crib sentence intact, it holds exactly ONE slug-shaped
    token, and that slug is the final content (the right-stripped text ends with it). That is the
    lane's never-guess shape, derived from structure, not from one variant.

    So a reading a shipped crib-anchored reader would itself have SEEN and declined is declined here
    too: a footer or any text after the slug (the slug is not the final token), or two slugs / the
    sentence twice (more than one token), stays None -- the backstop never offers a candidate where a
    shipped reader correctly declined. And a stream nothing truly decoded (an lz4 block with no length
    header, or random bytes from a wrong decode) never carries the crib intact -- its control bytes
    break the sentence -- so it is a safe None, never a manufactured, mangled slug.

    crib_l is required: without the crib anchor the backstop cannot prove the reading is a warmup
    payload, and reading a bare final-line slug out of arbitrary decoded bytes is exactly the guess
    this backstop must not make."""
    text = _text(decoded)
    if text is None or not _mostly_printable(text):
        return None
    low = text.lower()
    anchor = (crib_l or "").rstrip()
    if not anchor or anchor not in low:          # the whole crib sentence must be present, intact
        return None
    found = slug_re.findall(low)
    if len(found) != 1:                          # no slug, or an ambiguous reading with more than one
        return None
    slug = found[0]
    if not low.rstrip().endswith(slug):          # trailing text after the slug: the slug is not final
        return None
    return slug


def candidates(data, crib="", slug_re=SLUG_FULL, max_options=MAX_OPTIONS):
    """[(hypothesis_name, slug_value)], best first, distinct by value, for a WHOLE blob every shipped
    reader left None. Each independent decoder is run over the blob and over an independent hex surface
    (warmups so often wrap an encoding in hex); a reading is a candidate only when it is an UNAMBIGUOUS
    crib-anchored lane payload (the whole crib sentence intact, exactly one slug token, that slug the
    final content -- see _slug_of). [] when nothing reads unambiguously, so an ambiguous or trailing
    shape a shipped reader would have declined, and a stream nothing truly decoded, give nothing. Pure;
    never raises.

    The caller wraps the result in labels.candidates under a blob-fingerprinted key: never plain before
    the judge accepts a name, scoped so an accepted name cannot answer another variant, probed off-clock."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return []
    data = bytes(data)
    if not (MIN_DECODED <= len(data) <= MAX_BYTES):
        return []
    crib_l = (crib or "").lower()

    surfaces = [("", data)]
    try:
        h = hex_alt(data)
    except Exception:
        h = None
    if h is not None and h != data and len(h) <= MAX_BYTES:
        surfaces.append(("hex_", h))

    out = []                 # (name, value)
    seen_values = set()
    for prefix, surface in surfaces:
        for name, dec in DECODERS:
            try:
                decoded = dec(surface)
            except Exception:
                decoded = None
            if decoded is None:
                continue
            try:
                slug = _slug_of(decoded, crib_l, slug_re)
            except Exception:
                slug = None
            if not slug or slug in seen_values:
                continue
            seen_values.add(slug)
            out.append((prefix + name, slug))
            if len(out) >= max_options:
                return out
    return out
