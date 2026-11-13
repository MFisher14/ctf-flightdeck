#!/usr/bin/env python3
"""More codecs for codec_search.py, applied only when the puzzle document names them (Day 9 hardening).

codec_search.py imports this module and calls register(), which adds to its tables:

  alphabets     base36, base62 (digits-upper-lower and digits-lower-upper), base45 (RFC 9285),
                base91 (basE91), quoted-printable, HTML entities, backslash escapes (\\x41, \\u0041,
                \\101), Morse code; and a custom alphabet beside base64, base32, base58 or base85
                (a field `alphabet`, `charset` or `table` of the right length)
  compression   zstd, lz4 (frame), brotli and snappy, each under base64, hex or base32 as zlib is.
                The libraries are imported only when the step is tried and are optional: without
                one, the step gives nothing
  transposition columnar (also scytale): the columns from a keyword, a list of column numbers or a
                count, read both ways; with no parameter the counts 2 to 10, kept only when the
                ANS- prefix proves one
  differences   delta (each byte the difference from the one before; also the running xor), and
                offsets (a list of per-character offsets, subtracted or added)
  ciphers       chacha20, des3 and fernet with a key from the document or the APK; jwt (the one
                answer code in the token's payload)

None of them is a search move: they are registered as steps that read the document (KEYED), so
an opaque codec name is searched exactly as before, and nothing here can change what a judged codec answers. A reading is
kept only when it is exactly ANS- plus 16 upper-case hex characters, and codec_search.py offers it
unsure (labels.pick under mobile.codec/<the document's name>) until the judge accepts its route.

By the document's own name only (OWN, Day 12 look-ahead; codec_search.apply() asks own()): unicode
(the escapes above), json (a JSON string, or the one answer code among an object's values), json_string
and quoted, pem and armor, hexdump and xxd, lower, lowercase, lower_hex, upper and swapcase,
xor_prev, add_index and sub_index; and reflection (Day 19: the code stands in `data` as it is, an
identity read tagged `plain`). These are in no table: such a word does not split a longer name
and does not make a document of a file in another container.

Day 28's `packet` is a strict named frame rather than a search move: hex bytes, `HA`, a one-byte
payload length, exactly that many payload bytes, and exactly one trailer byte. packet_frame() returns
only a complete upper-case Huntress answer payload. codec_search keeps the judge-accepted historical
route name `search:hex>unwrapped`, but no longer searches or unwraps arbitrary bytes for this codec.

Day 29's `table` is likewise a strict named reading: `data` is 20 hex bytes, byte i = code[i] + key +
step*i (mod 256), the step recovered from the `ANS-` prefix (table_offsets()); judged route
`table:sub-key-step` under `mobile.codec/table`.

Day 30's `layered` ("Layered Protections") is a strict named reading too (layered_rolling()): `data` is
base64 of 20 bytes, an integer `key`, and code[i] = raw[19-i] XOR (key + 19 - i) (mod 256), i.e. the
code was reversed, XORed byte j with key + j (a key rolling by one per byte), then base64-encoded. The judge accepted
the generic search's route `search:base64>reverse>prefix-roll-xor` (the roll seeded from the `ANS-`
prefix, k0 XOR i) on the base, where both readings coincide; codec_search answers under that accepted
spelling only when both readings give the same code, and under a name of its own otherwise.

The same byte relation under a genuinely unknown single codec name is exposed separately by
linear_offset_shape().  That helper is deliberately narrower than the judged `table` reader: the
key must be a JSON integer, the constant step must be the unique value that explains all four
known prefix bytes, and the complete result must be one upper-case answer code.  codec_search gives
that structural inference an artifact-scoped candidate key; it can never inherit `table`'s accepted
name.

B-249 (the Day 30 audit's M3): quadratic_offset_shape() reads byte i = code[i] + key + b*i + a*i*i with the
coefficients stated (`a`/`b`, `quadratic`) or recovered from the crib, and piecewise_offset_shape() a schedule whose
pieces the document states (`pieces`/`segments`: start, step[, base]) under the restart / continue / absolute
readings. Both read the linear carrier, answer only through the exact ANS fullmatch of all 20 bytes, leave a linear
schedule to linear_offset_shape(), and give None when the schedule is underdetermined or two readings give two
codes; codec_search offers them as candidates under keys of their own, under `table` too, never its judged name.

Plain Python on the timed path; every loop is bounded by the caller's clock or by a small constant.
"""
import base64
import binascii
import html
import json
import quopri
import re
import struct

MAX_OUT = 4096          # bytes of one decoded state (codec_search.MAX_STATE)
SEARCH_COLUMNS = range(2, 11)
MAX_COLUMNS = 64

# Every function below that needs codec_search takes it as its first argument, `C`: the solver is
# loaded more than once in one process (tools/run.py, the selftest's copy), and each instance
# registers steps bound to itself.


# ---------------------------------------------------------------------------- alphabets

_B36 = "0123456789abcdefghijklmnopqrstuvwxyz"
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_B62_LOWER = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B91 = ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        "!#$%&()*+,./:;<=>?@[]^_`{|}~\"")
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"


def _radix(text, alphabet):
    """A big number written in `alphabet`, as bytes; leading first-digits are leading zero bytes."""
    if not text or len(text) > 512:
        return None
    index = {c: i for i, c in enumerate(alphabet)}
    n = 0
    for ch in text:
        if ch not in index:
            return None
        n = n * len(alphabet) + index[ch]
    lead = len(text) - len(text.lstrip(alphabet[0]))
    return b"\0" * lead + n.to_bytes((n.bit_length() + 7) // 8, "big")


def _ascii(d):
    try:
        return bytes(d).decode("ascii").strip()
    except UnicodeDecodeError:
        return None


def base36(d):
    t = _ascii(d)
    return _radix(t.lower(), _B36) if t else None


def base62(d, alphabet=_B62):
    t = _ascii(d)
    return _radix(t, alphabet) if t else None


def base45(d):
    t = _ascii(d)
    if not t or len(t) % 3 == 1 or any(c not in _B45 for c in t):
        return None
    out = bytearray()
    for i in range(0, len(t), 3):
        chunk = t[i:i + 3]
        n = sum(_B45.index(c) * 45 ** k for k, c in enumerate(chunk))
        if len(chunk) == 3:
            if n > 0xFFFF:
                return None
            out += n.to_bytes(2, "big")
        else:
            if n > 0xFF:
                return None
            out.append(n)
    return bytes(out)


def base91(d):
    t = _ascii(d)
    if not t or any(c not in _B91 for c in t):
        return None
    v, b, n, out = -1, 0, 0, bytearray()
    for ch in t:
        c = _B91.index(ch)
        if v < 0:
            v = c
            continue
        v += c * 91
        b |= v << n
        n += 13 if (v & 8191) > 88 else 14
        while n > 7:
            out.append(b & 255)
            b >>= 8
            n -= 8
        v = -1
    if v >= 0:
        out.append((b | v << n) & 255)
    return bytes(out)


def qp(d):
    return quopri.decodestring(bytes(d)) if b"=" in d else None


def entities(d):
    t = bytes(d).decode("utf-8")
    if "&" not in t or ";" not in t:
        return None
    return html.unescape(t).encode("utf-8")


_ESC = re.compile(r"\\x([0-9A-Fa-f]{2})|\\u([0-9A-Fa-f]{4})|\\([0-7]{3})|%u([0-9A-Fa-f]{4})")


def escapes(d):
    """Text written as \\x41, \\u0041, \\101 or %u0041 escapes, each a character below 256."""
    t = _ascii(d)
    if not t or not _ESC.search(t):
        return None
    out, pos = bytearray(), 0
    for m in _ESC.finditer(t):
        out += t[pos:m.start()].encode()
        n = int(m.group(1) or m.group(2) or m.group(4), 16) if not m.group(3) else int(m.group(3), 8)
        if n > 255:
            return None
        out.append(n)
        pos = m.end()
    return bytes(out + t[pos:].encode())


_MORSE = {".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F", "--.": "G", "....": "H", "..": "I",
          ".---": "J", "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
          "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y", "--..": "Z",
          "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5", "-....": "6",
          "--...": "7", "---..": "8", "----.": "9", "-....-": "-"}


def morse(d):
    t = _ascii(d)
    if not t or re.sub(r"[.\-_/| ]", "", t):
        return None
    toks = [x for x in re.split(r"[ /|]+", t.replace("_", "-")) if x]
    if len(toks) < 4 or any(x not in _MORSE for x in toks):
        return None
    return "".join(_MORSE[x] for x in toks).encode()


ALPHABET_FIELDS = ("alphabet", "charset", "table", "base64_alphabet", "alphabet64", "custom_alphabet", "chars",
                   "base_alphabet", "dictionary")
_STANDARD = {"base64": _B64, "base64url": _B64, "b64": _B64, "base32": _B32, "b32": _B32, "base58": _B58,
             "base85": _B85, "base62": _B62, "base36": _B36, "base91": _B91, "base45": _B45}


def custom_alphabet(C, name, d, p):
    """[(output, tag)] for a base-N step read in the document's own alphabet (a field of ALPHABET_FIELDS
    holding exactly N different characters). The tag names the field, so the reading never takes
    the name of the step read in its standard alphabet."""
    std = _STANDARD.get(name)
    if std is None or not isinstance(p, dict):
        return []
    t = _ascii(d)
    if not t:
        return []
    outs = []
    for field in ALPHABET_FIELDS:
        v = p.get(field)
        if not (isinstance(v, str) and v.isascii() and len(v) in (len(std), len(std) + 1)
                and len(set(v[:len(std)])) == len(std)) or v[:len(std)] == std:
            continue
        own, pad = v[:len(std)], v[len(std):] or "="
        body = t.rstrip(pad) if name in ("base64", "base64url", "b64", "base32", "b32") else t
        if any(c not in own for c in body):
            continue
        tag = "alphabet" if field == "alphabet" else "alphabet=" + C._slug(field, 24)
        try:
            if name in ("base64", "base64url", "b64"):
                if len(body) % 4 == 1:
                    continue
                o = base64.b64decode(body.translate(str.maketrans(own, _B64)) + "=" * (-len(body) % 4))
            elif name in ("base32", "b32"):
                if len(body) % 8 in (1, 3, 6):
                    continue
                o = base64.b32decode(body.translate(str.maketrans(own, _B32)) + "=" * (-len(body) % 8))
            elif name == "base85":
                o = base64.b85decode(body.translate(str.maketrans(own, _B85)))
            elif name == "base91":
                o = base91(body.translate(str.maketrans(own, _B91)).encode())
            elif name == "base45":
                o = base45(body.translate(str.maketrans(own, _B45)).encode())
            else:
                o = _radix(body, own)
        except Exception:
            continue
        if o:
            outs.append((o, tag))
    return outs


# ---------------------------------------------------------------------------- compression

def _zstd(d):
    if d[:4] != b"\x28\xb5\x2f\xfd":
        return None
    import zstandard
    return zstandard.ZstdDecompressor().decompressobj().decompress(d)[:MAX_OUT + 1] or None


def _lz4(d):
    if d[:4] != b"\x04\x22\x4d\x18":
        return None
    import lz4.frame
    return lz4.frame.decompress(d) or None      # at most 4096 bytes in: an lz4 frame grows by 255 times at most


def _brotli(d):
    if not 4 <= len(d) <= 1024:
        return None
    import brotli
    dec = brotli.Decompressor()
    out = dec.process(bytes(d), output_buffer_limit=MAX_OUT)
    return out if out and dec.is_finished() else None


def _snappy(d):
    n, shift, i = 0, 0, 0
    while i < min(len(d), 5):       # the uncompressed length comes first, as a varint
        n |= (d[i] & 0x7F) << shift
        i += 1
        if not d[i - 1] & 0x80:
            break
        shift += 7
    if not 1 <= n <= MAX_OUT:
        return None
    import snappy
    return snappy.uncompress(bytes(d)) or None


def _packed(C, fn):
    """A compression step as codec_search applies zlib: to the data and to every text layer of it."""
    def step(d, p, clock):
        outs = []
        for x in C._layers(d):
            try:
                o = fn(x)
            except Exception:
                o = None
            if o and len(o) <= MAX_OUT:
                outs.append((o, ""))
        return outs
    return step


# ---------------------------------------------------------------------------- transposition

COLUMNS = ("columns", "cols", "column", "width", "key", "keyword", "order", "n", "k", "size", "block", "turns",
           "diameter", "wrap")


def _col_perm(v):
    """The column order a parameter means: a keyword (its letters ranked, stable), a list of
    different column numbers, or a count (the columns as they stand). None for anything else."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return list(range(v)) if 2 <= v <= MAX_COLUMNS else None
    if isinstance(v, list) and 2 <= len(v) <= MAX_COLUMNS and all(isinstance(x, int) and not isinstance(x, bool)
                                                                  for x in v) and len(set(v)) == len(v):
        rank = {x: i for i, x in enumerate(sorted(v))}
        return [rank[x] for x in v]
    if isinstance(v, str) and v.strip().isdigit() and 2 <= int(v) <= MAX_COLUMNS:
        return list(range(int(v)))
    if isinstance(v, str) and 2 <= len(v) <= MAX_COLUMNS and v.isalnum() and not v.isdigit():
        order = sorted(range(len(v)), key=lambda i: (v[i].upper(), i))
        perm = [0] * len(v)
        for rank, i in enumerate(order):
            perm[i] = rank
        return perm
    return None


def _col_positions(perm, length):
    """The positions of a text in the order a columnar transposition writes them out: column by
    column in the key's order, each column top to bottom."""
    n = len(perm)
    by_rank = sorted(range(n), key=lambda c: perm[c])
    return [i for c in by_rank for i in range(c, length, n)]


def col_decode(d, perm):
    if not 2 <= len(perm) < len(d):
        return None
    out = bytearray(len(d))
    for k, pos in enumerate(_col_positions(perm, len(d))):
        out[pos] = d[k]
    return bytes(out)


def col_encode(d, perm):
    if not 2 <= len(perm) < len(d):
        return None
    return bytes(d[i] for i in _col_positions(perm, len(d)))


def columnar(C, d, p, clock):
    """[(output, tag)] for a columnar transposition (a scytale is one with the columns in order).

    The columns come from a field (COLUMNS, each named in the tag when it is not `columns`), read
    both ways: written out by columns (the decode, no tag) and `inverse`. With no field that gives
    them, the counts 2 to 10 are tried and a count is kept only when the ANS- prefix proves it;
    counts that prove different codes are each offered under their own count, smallest first."""
    perms = [(perm, tag) for v, tag in C.params(p, COLUMNS) for perm in [_col_perm(v)] if perm]
    outs, layers = [], C._layers(d)
    seen = set()
    for perm, tag in clock.each(perms[:8]):
        if tuple(perm) in seen:
            continue
        seen.add(tuple(perm))
        for x in layers:
            outs += [(o, ":".join(t for t in (way, tag) if t)) for way, o in
                     (("", col_decode(x, perm)), ("inverse", col_encode(x, perm))) if o]
    if outs:
        return outs
    found = [(o, way + "columns-searched", n) for x in layers for n in clock.each(SEARCH_COLUMNS)
             for way, o in (("", col_decode(x, list(range(n)))), ("inverse:", col_encode(x, list(range(n)))))
             if o and C._proves(o)]
    if C._one([(o, t) for o, t, _ in found]):
        return [(found[0][0], found[0][1])]
    return [(o, "%s:%d" % (t, n)) for o, t, n in found]


# ---------------------------------------------------------------------------- differences

def _first_keys(C, p):
    """[(byte, tag)] for the one-byte keys the document gives (codec_search.key_candidates: those the
    Day 4 solver reads carry no tag, any other names its field)."""
    return [(k[0], tag) for k, tag in C.key_candidates(p) if len(k) == 1 and k[0]][:8]


def delta(C, d, p, clock):
    """[(output, tag)] for a difference coding: each byte is the difference from the byte before
    (the running sum decodes it, no tag), or the xor with it (`xor`). The first byte stands as it is.
    After those, the xor reading with the first byte under a one-byte key of the document
    (`xor:first-key`, the key's field named when it is not one the Day 4 solver reads)."""
    outs, keyed = [], []
    firsts = _first_keys(C, p)
    for x in C._layers(d):
        if not 2 <= len(x) <= MAX_OUT:
            continue
        acc, run = 0, bytearray()
        for c in x:
            acc = (acc + c) & 255
            run.append(acc)
        acc, chain = 0, bytearray()
        for c in x:
            acc ^= c
            chain.append(acc)
        outs += [(bytes(run), ""), (bytes(chain), "xor")]
        # a first byte xored with k moves every byte of the running xor by k
        keyed += [(bytes(c ^ k for c in chain), ":".join(t for t in ("xor", "first-key", tag) if t))
                  for k, tag in clock.each(firsts)]
    return outs + keyed


OFFSETS = ("offsets", "offset", "deltas", "shifts", "key", "keys", "pad", "mask", "adds", "increments")


def offsets(C, d, p, clock):
    """[(output, tag)] for per-character offsets: a list of integers (repeated when it is shorter
    than the text), subtracted from each byte (no tag) or added (`add`), mod 256. The field is
    named in the tag when it is not `offsets`. With no such list there is nothing to read."""
    lists = []
    for v, tag in C.params(p, OFFSETS):
        if isinstance(v, str) and re.fullmatch(r"\s*-?\d{1,4}(\s*[,;\s]\s*-?\d{1,4})+\s*", v):
            v = [int(t) for t in re.findall(r"-?\d{1,4}", v)]
        if isinstance(v, list) and 2 <= len(v) <= MAX_OUT and all(isinstance(x, int) and not isinstance(x, bool)
                                                                 and -65536 < x < 65536 for x in v):
            lists.append((v, tag))
    outs = []
    for ks, tag in clock.each(lists[:4]):
        for x in C._layers(d):
            outs.append((bytes((c - ks[i % len(ks)]) % 256 for i, c in enumerate(x)), tag))
            outs.append((bytes((c + ks[i % len(ks)]) % 256 for i, c in enumerate(x)),
                         ":".join(t for t in ("add", tag) if t)))
    return outs


# ---------------------------------------------------------------------------- ciphers and tokens

def _ready(C, clock) -> bool:
    import sys
    return "cryptography" in sys.modules or clock.left() >= C.IMPORT_RESERVE


def _keys(C, p):
    """The document's key candidates and, after them, the APK's (set by codec_search for this document)."""
    return C.key_candidates(p) + [(k, "key-apk") for k in C.APK_KEYS.get("keys", ())]


def _ivs(C, p):
    out = []
    for n, v in C.flat(p):
        if re.search(r"iv|nonce|counter", n, re.I):
            try:
                out += C.base._keys({"k": v})
            except Exception:
                pass
    return out


def chacha20(C, d, p, clock):
    """[(output, tag)] for ChaCha20: a 32-byte key (as given, or the SHA-256 of a shorter one, tagged)
    and a 16-byte nonce, or a 12-byte nonce after a zero counter, or the nonce in the data's first bytes."""
    if not _ready(C, clock):
        return []
    try:
        import hashlib
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    except ImportError:
        return []
    outs = []
    for x in (C._layers(d)[1:] or [bytes(d)]):
        nonces = [(iv if len(iv) == 16 else b"\0" * 4 + iv, x, "") for iv in _ivs(C, p) if len(iv) in (12, 16)]
        if len(x) > 16:
            nonces.append((x[:16], x[16:], "nonce-first"))
        if len(x) > 12:
            nonces.append((b"\0" * 4 + x[:12], x[12:], "nonce12-first"))
        for k, tag in clock.each(_keys(C, p)[:24]):
            for kk, kdf in ([(k, "")] if len(k) == 32 else [(hashlib.sha256(k).digest(), "sha256")]):
                for nonce, body, how in nonces:
                    try:
                        o = Cipher(algorithms.ChaCha20(kk, nonce), None).decryptor().update(body)
                    except Exception:
                        continue
                    outs.append((o, ":".join(t for t in (how, kdf, tag) if t)))
    return outs


def des3(C, d, p, clock):
    """[(output, tag)] for Triple DES (ECB, and CBC with an IV of the document or in the first block)."""
    if not _ready(C, clock):
        return []
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES
    except ImportError:
        return []
    outs = []
    for x in (C._layers(d)[1:] or [bytes(d)]):
        if len(x) % 8 or len(x) < 8:
            continue
        for k, tag in clock.each(_keys(C, p)[:24]):
            if len(k) not in (8, 16, 24):
                continue
            tries = [("ecb", modes.ECB(), x)] + [("cbc", modes.CBC(iv), x) for iv in _ivs(C, p) if len(iv) == 8]
            if len(x) >= 16:
                tries.append(("cbc-iv-first", modes.CBC(x[:8]), x[8:]))
            for how, mode, body in tries:
                try:
                    dec = Cipher(TripleDES(k * 3 if len(k) == 8 else k), mode).decryptor()   # one DES key is the same key three times
                    pt = dec.update(body) + dec.finalize()
                except Exception:
                    continue
                if pt and 1 <= pt[-1] <= 8:
                    outs.append((pt[:-pt[-1]], ":".join(t for t in (how, tag) if t)))
                outs.append((pt, ":".join(t for t in (how, tag) if t)))
    return outs


def blowfish(C, d, p, clock):
    """[(output, tag)] for Blowfish by name (Day 20 build, the Day 19 look-ahead's E07): ECB, and CBC with an
    8-byte IV of the document or in the first block, under a key of the document or the APK of 4 to 56 bytes
    (the cipher's own range). The same shape as des3: a block cipher with an 8-byte block and PKCS#5 padding;
    an output that is not an answer code is dropped by the caller, so a wrong key costs a decryption, no more."""
    if not _ready(C, clock):
        return []
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import Blowfish
        except ImportError:
            from cryptography.hazmat.primitives.ciphers.algorithms import Blowfish
    except ImportError:
        return []
    outs = []
    for x in (C._layers(d)[1:] or [bytes(d)]):
        if len(x) % 8 or len(x) < 8:
            continue
        for k, tag in clock.each(_keys(C, p)[:24]):
            if not 4 <= len(k) <= 56:
                continue
            tries = [("ecb", modes.ECB(), x)] + [("cbc", modes.CBC(iv), x) for iv in _ivs(C, p) if len(iv) == 8]
            if len(x) >= 16:
                tries.append(("cbc-iv-first", modes.CBC(x[:8]), x[8:]))
            for how, mode, body in tries:
                try:
                    dec = Cipher(Blowfish(k), mode).decryptor()
                    pt = dec.update(body) + dec.finalize()
                except Exception:
                    continue
                if pt and 1 <= pt[-1] <= 8:
                    outs.append((pt[:-pt[-1]], ":".join(t for t in (how, tag) if t)))
                outs.append((pt, ":".join(t for t in (how, tag) if t)))
    return outs


def fernet(C, d, p, clock):
    """[(output, tag)] for a Fernet token under a key of the document or the APK (44 base64 characters)."""
    if not _ready(C, clock):
        return []
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return []
    token = bytes(d).strip()
    outs = []
    for k, tag in clock.each(_keys(C, p)[:24]):
        cands = [k] if len(k) == 44 else [base64.urlsafe_b64encode(k)] if len(k) == 32 else []
        for kk in cands:
            try:
                outs.append((Fernet(kk).decrypt(token), tag))
            except Exception:
                continue
    return outs


def jwt(C, d, p, clock):
    """[(output, tag)] for a JSON Web Token: the one answer code among its payload's values (the
    signature is not checked: the document, not the token, is what the judge wrote)."""
    t = _ascii(d)
    parts = t.split(".") if t else []
    if len(parts) not in (2, 3) or not all(re.fullmatch(r"[A-Za-z0-9_-]*", x) for x in parts):
        return []
    try:
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception:
        return []
    found = {v.strip() for _, v in C.flat(payload) if isinstance(v, str) and C.strict(v.encode("utf-8", "replace"))}
    return [(found.pop().encode(), "")] if len(found) == 1 else []


# ---------------------------------------------------------------------------- by the document's own name
#
# Names a document may give its codec that nothing above applies (Day 12 look-ahead): the text in
# another letter case, in quotes, as JSON, between armor lines, as a hex dump, each byte moved by
# its place or xored with the byte before. They are in none of codec_search's tables: no search
# move, no word that splits a longer name, no mark of a document in another container.
# codec_search.apply() asks own() with the step's name as the document wrote it, so each is
# applied by that name only, and by_name keeps only an exact answer code.

def to_upper(d):
    """The text in upper case, when that changes it: a code written in lower case (lower,
    lowercase, lower_hex), or the step that undoes it (upper). A code has no lower-case letter."""
    o = bytes(d).upper()
    return o if o != bytes(d) else None


def swapcase(d):
    o = bytes(d).swapcase()
    return o if o != bytes(d) else None


def unquote(d):
    """One pair of quotes taken off: a JSON string with its escapes, or the text between ' ' or ` `."""
    t = bytes(d).decode("utf-8").strip()
    if len(t) < 3 or t[0] != t[-1]:
        return None
    if t[0] == '"':
        v = json.loads(t)
        return v.encode("utf-8") if isinstance(v, str) else None
    return t[1:-1].encode("utf-8") if t[0] in "'`" and t[0] not in t[1:-1] else None


def json_code(C, d, p, clock):
    """[(output, tag)] for data that is JSON text itself: a string is its value; an object or a
    list is the one answer code among its string values. Two different codes anywhere in the
    text are nothing: no field name says which is meant. A code spelled in lower case (ans-...)
    is a second code too: lower and lowercase read such text as a code, so it is no less one here."""
    try:
        obj = json.loads(bytes(d).decode("utf-8"))
        if isinstance(obj, str):
            return [(obj.encode("utf-8"), "")]
        texts = [v.encode("utf-8", "replace") for _, v in C.flat(obj) if isinstance(v, str)] \
            if isinstance(obj, (dict, list)) else []
    except (ValueError, RecursionError):
        return []
    exact = {C.strict(v) for v in texts} - {None}
    seen = C.answers_in(bytes(d).upper()).union(*(C.answers_in(v.upper()) for v in texts))
    return [(exact.pop().encode(), "")] if len(exact) == 1 and seen <= exact else []


_ARMOR = re.compile(r"-----BEGIN ([^-\r\n]{0,64})-----\r?\n(.*?)\r?\n-----END \1-----", re.S)


def pem(d):
    """The bytes between armor lines (-----BEGIN X----- and -----END X-----, the same X): base64,
    after the header lines that a blank line ends, without OpenPGP's last =XXXX checksum line."""
    t = _ascii(d)
    m = _ARMOR.fullmatch(t) if t else None
    if not m:
        return None
    lines = [x.strip() for x in m.group(2).splitlines()]
    if "" in lines:
        lines = lines[lines.index("") + 1:]
    if len(lines) > 1 and len(lines[-1]) == 5 and lines[-1][0] == "=":
        lines.pop()
    body = "".join(lines)
    if not body or len(body) % 4:
        return None
    return base64.b64decode(body, validate=True)


_DUMP = re.compile(r"([0-9A-Fa-f]{4,16})(?::[ \t]*|[ \t]+)(\S.*)")
_DUMP_END = re.compile(r"[0-9A-Fa-f]{4,16}:?")
_DUMP_ROW = re.compile(r"(\S+(?: \S+)*)(?: {2,}(.*))?")
_DUMP_BYTES = re.compile(r"(?:[0-9A-Fa-f]{2}){1,2}")


def hexdump(d):
    """The bytes of a hex dump: on each line an offset, the bytes in hex (singly or in pairs), and
    perhaps their text (hexdump -C between bars, xxd after two spaces).

    Nothing is taken on trust: every offset must be the count of bytes before its line, and a
    text column must be the text of its line's bytes, so a column of hex-looking text (the tail
    of a code) is never read as bytes. Any other line makes the whole dump nothing."""
    t = _ascii(d)
    out = bytearray()
    lines = [x.strip() for x in (t or "").splitlines() if x.strip()]
    for n, line in enumerate(lines):
        if n and n == len(lines) - 1 and _DUMP_END.fullmatch(line):   # hexdump's last line: the length alone
            if int(line.rstrip(":"), 16) != len(out):
                return None
            break
        m = _DUMP.fullmatch(line)
        if not m or int(m.group(1), 16) != len(out):
            return None
        rest, text = m.group(2), None
        if rest.endswith("|") and rest.count("|") >= 2:
            rest, text = rest[:rest.index("|")], rest[rest.index("|") + 1:-1]
            toks = rest.split()
        else:
            row = _DUMP_ROW.fullmatch(rest)
            if not row:
                return None
            toks, text = row.group(1).split(" "), row.group(2)
        if not toks or not all(_DUMP_BYTES.fullmatch(x) for x in toks):
            return None
        got = bytes.fromhex("".join(toks))
        if text is not None and text.rstrip() != "".join(chr(c) if 32 <= c < 127 else "." for c in got).rstrip():
            return None
        out += got
    return bytes(out) or None


def by_index(add):
    """A step for bytes moved by their place: add_index took byte i up by i and it is taken down
    again (no tag; `inverse` takes it up), sub_index the other way round. The place counts from 0.
    Over the data and every text layer of it, as a keyed step is."""
    def step(C, d, p, clock):
        outs = []
        for x in C._layers(d):
            if not 2 <= len(x) <= MAX_OUT:
                continue
            down = bytes((c - i) & 255 for i, c in enumerate(x))
            up = bytes((c + i) & 255 for i, c in enumerate(x))
            outs += [(down, ""), (up, "inverse")] if add else [(up, ""), (down, "inverse")]
        return outs
    return step


def xor_prev(C, d, p, clock):
    """[(output, tag)] for bytes each xored with the byte before it: the plain byte before, or
    the cipher byte before (`cipher`). The tag says what the first byte was xored with: a one-byte
    key of the document (`first-key`, its field named when it is not one the Day 4 solver reads)
    or nothing (`first-plain`). Over the data and every text layer of it."""
    firsts = [(k, ":".join(t for t in ("first-key", tag) if t)) for k, tag in _first_keys(C, p)] + [(0, "first-plain")]
    outs = []
    for x in C._layers(d):
        if not 2 <= len(x) <= MAX_OUT:
            continue
        for k, tag in clock.each(firsts):
            acc, plain = k, bytearray()
            for c in x:
                acc ^= c
                plain.append(acc)
            outs += [(bytes(plain), tag), (bytes(a ^ b for a, b in zip(x, bytes([k]) + x)), "cipher:" + tag)]
    return outs


def _own(fn):
    return lambda C, d, p, clock: [(fn(d), "")]


def reflection(C, d, p, clock):
    """The `reflection` codec (Day 19, folded in from that day's live fix): the answer code stands
    in `data` as it is, an identity read. It is tagged `plain`, so the route is reflection:plain
    (offered unsure under mobile.codec/reflection until the judge accepts the name, which it did on
    Day 19). It is NOT a base.NAMED identity (plain/none/identity): those answer plain, and this
    codec name had never been judged, so it stays a pick."""
    return [(bytes(d), "plain")]


_PACKET_HEX = re.compile(r"[0-9A-Fa-f]+")
_PACKET_ANSWER = re.compile(rb"ANS-[0-9A-F]{16}")


def packet_frame(p):
    """Return Day 28's exact `packet` payload, or None when the frame is not established.

    The framing observed and described by the challenge is::

        b"HA" + one-byte payload length + payload + one trailer byte

    The trailer is protocol state, not part of the answer, so its value is deliberately not
    hard-coded. Requiring one and only one trailer byte, the declared length, and the full answer
    shape keeps a malformed or merely answer-containing hex string from inheriting the accepted
    `mobile.codec/packet` route.
    """
    if not isinstance(p, dict):
        return None
    text = p.get("data")
    if not isinstance(text, str) or not text or len(text) % 2 or _PACKET_HEX.fullmatch(text) is None:
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    if len(raw) < 4 or raw[:2] != b"HA":
        return None
    size = raw[2]
    if size != 20 or len(raw) != 2 + 1 + size + 1:
        return None
    payload = raw[3:3 + size]
    if _PACKET_ANSWER.fullmatch(payload) is None:
        return None
    return payload.decode("ascii")


_TABLE_PREFIX = b"ANS-"


def table_offsets(p):
    """Return Day 29's exact `table` code, or None when the reading is not established.

    Day 29 ("White-Box Key Recovery", dex CONTROL `white_box_table`): `data` is the hex of 20 bytes
    and `key` an integer; byte i is code[i] + key + step*i (mod 256). The step is not taken from any
    field: it is recovered from the known `ANS-` prefix, whose four offsets must be exactly key,
    key+s, key+2s, key+3s. The whole result must be an exact upper-case answer code, so a document
    that merely contains hex does not inherit the judged `mobile.codec/table` route.
    """
    if not isinstance(p, dict):
        return None
    text = p.get("data")
    key = p.get("key")
    if isinstance(key, bool) or not isinstance(key, int):
        if isinstance(key, str) and re.fullmatch(r"-?[0-9]{1,6}", key.strip()):
            key = int(key.strip())
        else:
            return None
    if not isinstance(text, str) or len(text) != 40 or _PACKET_HEX.fullmatch(text) is None:
        return None
    raw = bytes.fromhex(text)
    d = [(raw[i] - _TABLE_PREFIX[i]) % 256 for i in range(4)]
    if d[0] != key % 256:
        return None
    step = (d[1] - d[0]) % 256
    if any((d[i] - key - step * i) % 256 for i in range(4)):
        return None
    out = bytes((raw[i] - key - step * i) % 256 for i in range(len(raw)))
    if _PACKET_ANSWER.fullmatch(out) is None:
        return None
    return out.decode("ascii")


_LAYERED_B64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")


def layered_rolling(p):
    """Day 30's `layered` code as (code, judged), or None when the reading is not established.

    Day 30 ("Layered Protections"): `data` is base64 of 20 bytes and `key` an integer; the code is
    raw[19-i] XOR ((key + 19 - i) mod 256): the code reversed, byte j XORed with key + j (a key rolling by
    one per byte), then base64. `judged` is True only when the judge-accepted route, `search:base64>reverse>prefix-roll-xor`
    (the reversed bytes XOR k0 XOR i, k0 recovered from the `A` of `ANS-`), reads the very same code; the
    two readings coincide when (key + 19) has its five low bits set (Day 30's base: key 12, k0 31). A key
    that is not an integer, base64 that is not strict, a length other than 20 bytes or a result that is not
    an exact upper-case answer code is None, so a document that merely says `layered` is not read here.
    """
    if not isinstance(p, dict):
        return None
    text = p.get("data")
    key = p.get("key")
    if isinstance(key, bool) or not isinstance(key, int):
        if isinstance(key, str) and re.fullmatch(r"-?[0-9]{1,6}", key.strip()):
            key = int(key.strip())
        else:
            return None
    if not isinstance(text, str) or len(text) != 28 or _LAYERED_B64.fullmatch(text) is None:
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception:
        return None
    n = len(raw)
    if n != 20:
        return None
    out = bytes(raw[n - 1 - i] ^ ((key + n - 1 - i) & 255) for i in range(n))
    if _PACKET_ANSWER.fullmatch(out) is None:
        return None
    d = raw[::-1]
    k0 = d[0] ^ 0x41
    judged = bytes(c ^ k0 ^ i for i, c in enumerate(d)) == out
    return out.decode("ascii"), judged


def linear_offset_shape(p):
    """Return a prefix-proven linear-offset code for an opaque codec, else None.

    This is the shape-only counterpart of :func:`table_offsets`, not an alias for its judged
    route.  The document must carry exactly one byte of evidence per answer character (40 hex
    digits) and a real JSON integer in ``key``.  Enumerating the 256 possible byte steps makes the
    uniqueness requirement explicit: exactly one constant step must explain every byte of the
    known ``ANS-`` crib.  The rest of the payload is accepted only when that same step produces
    the complete upper-case answer shape.

    String keys remain supported by the literal Day-29 ``table`` reader for historical replay,
    but are intentionally outside this forecast reader's narrower structural contract.
    """
    if not isinstance(p, dict):
        return None
    text, key = p.get("data"), p.get("key")
    if isinstance(key, bool) or not isinstance(key, int):
        return None
    if not isinstance(text, str) or len(text) != 40 or _PACKET_HEX.fullmatch(text) is None:
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    steps = [step for step in range(256)
             if all((raw[i] - _TABLE_PREFIX[i] - key - step * i) % 256 == 0
                    for i in range(len(_TABLE_PREFIX)))]
    # The crib's second byte (`N`, coefficient 1 in step*i) pins step to one residue mod 256, so this list
    # holds 0 or 1 entries, never more: `!= 1` rejects the no-step case and accepts the single pinned step
    # whose offsets reconstruct the whole crib. (Writing `< 1` here is an equivalent mutant: a >1 case is
    # unreachable. The real "one unique reading" work is the crib-wide all() and the answer-shape check below.)
    if len(steps) != 1:
        return None
    step = steps[0]
    out = bytes((raw[i] - key - step * i) % 256 for i in range(len(raw)))
    if _PACKET_ANSWER.fullmatch(out) is None:
        return None
    return out.decode("ascii")


# ---- B-249: the Day 29 table escalations the Day 30 audit (M3) names: a quadratic schedule (stated or recovered) and
# a piecewise one (stated). Both read the same carrier as linear_offset_shape (40 hex digits, a JSON integer key) and
# both answer only through the exact ANS fullmatch of all 20 bytes: the four-byte crib pins the coefficients, and the
# 16 body bytes (each 1 in 16 to be an upper-case hex digit by chance) are the independent full-output check. An
# underdetermined schedule (a piece whose step is not stated, two readings that give two codes) is None.

_QUAD_FIELDS = ("quadratic", "coefficients", "coeffs", "poly", "polynomial")
_PIECE_FIELDS = ("pieces", "segments", "piecewise", "schedule", "breaks")


def _offset_carrier(p):
    """(raw 20 bytes, key) of the table carrier: `data` exactly 40 hex digits and `key` a JSON integer; else None."""
    if not isinstance(p, dict):
        return None
    text, key = p.get("data"), p.get("key")
    if isinstance(key, bool) or not isinstance(key, int):
        return None
    if not isinstance(text, str) or len(text) != 40 or _PACKET_HEX.fullmatch(text) is None:
        return None
    try:
        return bytes.fromhex(text), key
    except ValueError:
        return None


def _apply_offsets(raw, offs):
    """The code `raw` minus the per-position offsets gives, when it is EXACTLY one upper-case ANS code; else None."""
    out = bytes((raw[i] - offs[i]) % 256 for i in range(len(raw)))
    return out.decode("ascii") if _PACKET_ANSWER.fullmatch(out) else None


def _is_linear(offs):
    """True when the offset sequence has every second difference 0 mod 256 (linear_offset_shape's reading)."""
    return all((offs[i + 2] - 2 * offs[i + 1] + offs[i]) % 256 == 0 for i in range(len(offs) - 2))


def _int_field(p, *names):
    for n in names:
        v = p.get(n)
        if isinstance(v, int) and not isinstance(v, bool):
            return v
    return None


def quadratic_offset_shape(p):
    """``(code, route)`` for a quadratic offset table, else None.

    byte i = code[i] + key + b*i + a*i*i (mod 256). The coefficients are the document's own when it states them
    (integers `a` and `b`, or a two-item `quadratic`/`coefficients` list [a, b]); otherwise every (a, b) the `ANS-`
    crib admits is tried. A schedule that is linear (every second difference 0: linear_offset_shape's reading) is not
    this shape. Exactly one distinct offset schedule must reconstruct the complete answer, else None: two (a, b) that
    give the same offsets on all 20 places (a and a+128 do) are one schedule, two schedules that give two codes are
    an underdetermined reading and never a guess."""
    got = _offset_carrier(p)
    if got is None:
        return None
    raw, key = got
    stated = None
    a, b = _int_field(p, "a"), _int_field(p, "b")
    if a is not None and b is not None:
        stated = [(a, b)]
    else:
        for f in _QUAD_FIELDS:
            v = p.get(f)
            if isinstance(v, list) and len(v) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in v):
                stated = [(v[0], v[1])]
                break
    if stated is not None:
        pairs, how = stated, "stated"
    else:
        d = [(raw[i] - _TABLE_PREFIX[i]) % 256 for i in range(4)]
        if d[0] != key % 256:
            return None
        pairs = [(qa, (d[1] - key - qa) % 256) for qa in range(256)]
        how = "recovered"
    schedules = {}
    for qa, qb in pairs:
        offs = tuple((key + qb * i + qa * i * i) % 256 for i in range(20))
        if _is_linear(offs) or offs in schedules:
            continue
        code = _apply_offsets(raw, offs)
        if code is not None:
            schedules[offs] = code
    codes = set(schedules.values())
    if len(schedules) != 1 or len(codes) != 1:
        return None
    return codes.pop(), "quadratic-offset:sub-key-%s" % how


def _pieces(p):
    """[(start, step, base or None)] the document states, starts strictly rising from 0, or None."""
    for f in _PIECE_FIELDS:
        v = p.get(f)
        if not isinstance(v, list) or not 2 <= len(v) <= 20:
            continue
        out = []
        for el in v:
            if isinstance(el, dict):
                start = _int_field(el, "start", "from", "at", "offset_start", "index")
                step = _int_field(el, "step", "delta", "stride", "increment")
                base = _int_field(el, "key", "base", "offset")
            elif isinstance(el, list) and len(el) in (2, 3) and all(
                    isinstance(x, int) and not isinstance(x, bool) for x in el):
                start, step = el[0], el[1]
                base = el[2] if len(el) == 3 else None
            else:
                return None
            if start is None or step is None:
                return None            # a piece whose start or step is not stated: underdetermined, no reading
            out.append((start, step, base))
        starts = [s for s, _st, _b in out]
        if starts[0] != 0 or any(b <= a for a, b in zip(starts, starts[1:])) or starts[-1] >= 20:
            return None
        return out
    return None


def piecewise_offset_shape(p):
    """``(code, route)`` for a piecewise linear offset table the document states, else None.

    `pieces` (or `segments`, `schedule`, ...) lists the pieces as {start, step[, key|base]} or [start, step[, base]],
    the first at 0. Three readings of a piece are tried: `restart` (offset = its own base, else `key`, + step*(i -
    start)), `continue` (the running offset steps by the piece's step from where the last piece left it) and
    `absolute` (offset = key + step*i with the piece's step). Every reading that gives a complete answer must give the
    same one code, else None; a schedule that is linear overall is linear_offset_shape's and not read here."""
    got = _offset_carrier(p)
    if got is None:
        return None
    raw, key = got
    pieces = _pieces(p)
    if pieces is None:
        return None
    bounds = [s for s, _st, _b in pieces] + [20]

    def piece_of(i):
        return next(k for k in range(len(pieces)) if bounds[k] <= i < bounds[k + 1])

    readings = {}
    restart = []
    for i in range(20):
        start, step, base = pieces[piece_of(i)]
        restart.append(((key if base is None else base) + step * (i - start)) % 256)
    readings["restart"] = tuple(restart)
    cont, cur = [], key % 256
    for i in range(20):
        if i:
            cur = (cur + pieces[piece_of(i)][1]) % 256
        cont.append(cur)
    readings["continue"] = tuple(cont)
    readings["absolute"] = tuple((key + pieces[piece_of(i)][1] * i) % 256 for i in range(20))
    hits = {}
    for name, offs in readings.items():
        if _is_linear(offs):
            continue
        code = _apply_offsets(raw, offs)
        if code is not None:
            hits.setdefault(code, []).append(name)
    if len(hits) != 1:
        return None
    code, names = next(iter(hits.items()))
    return code, "piecewise-offset:" + "+".join(names)


def keyed_schedule_shape(p):
    """Return ``(code, route)`` for one uniquely prefix-proven keyed schedule, else None.

    Finale forecast shape: ``data`` is exactly one 20-byte answer under hex, Base64 or Base32; ``key`` is a JSON
    integer; one of add/sub/xor with schedule ``key + step*i`` and forward/reverse-before/reverse-after ordering is
    the *only* combination (including its step) that reconstructs the complete ``ANS-`` code.  The codec name and
    rendering remain judge vocabulary, so codec_search exposes this only through labels.pick.
    """
    if not isinstance(p, dict):
        return None
    text, key = p.get("data"), p.get("key")
    if (isinstance(key, bool) or not isinstance(key, int) or not 0 <= key <= 255
            or not isinstance(text, str) or len(text) > 80):
        return None
    carriers = []
    if len(text) == 40 and _PACKET_HEX.fullmatch(text):
        try:
            carriers.append(("hex", bytes.fromhex(text)))
        except ValueError:
            pass
    try:
        if re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text) and len(text) % 4 == 0:
            carriers.append(("base64", base64.b64decode(text, validate=True)))
    except (ValueError, TypeError, binascii.Error):
        pass
    try:
        if re.fullmatch(r"[A-Z2-7]+={0,6}", text.upper()) and len(text) % 8 == 0:
            carriers.append(("base32", base64.b32decode(text.upper(), casefold=False)))
    except (ValueError, TypeError, binascii.Error):
        pass
    unique, seen = [], set()
    for carrier, raw in carriers:
        if len(raw) == 20 and raw not in seen:
            unique.append((carrier, raw))
            seen.add(raw)
    hits = []
    for carrier, raw in unique:
        for op in ("add", "sub", "xor"):
            for order in ("forward", "reverse-before", "reverse-after"):
                source = raw[::-1] if order == "reverse-before" else raw
                for step in range(256):
                    schedule = [(key + step * i) & 255 for i in range(20)]
                    if op == "add":
                        out = bytes((c + schedule[i]) & 255 for i, c in enumerate(source))
                    elif op == "sub":
                        out = bytes((c - schedule[i]) & 255 for i, c in enumerate(source))
                    else:
                        out = bytes(c ^ schedule[i] for i, c in enumerate(source))
                    if order == "reverse-after":
                        out = out[::-1]
                    if _PACKET_ANSWER.fullmatch(out):
                        hits.append((carrier, op, order, step, out.decode("ascii")))
    # Even two routes that happen to spell the same value are ambiguous author intent; neither may become plain.
    if len(hits) != 1:
        return None
    carrier, op, order, step, value = hits[0]
    return value, f"keyed-schedule:{carrier}:{op}:{order}:step-{step}"


OWN = {
    "unicode": _own(escapes),
    "json": json_code, "json_string": _own(unquote), "json-string": _own(unquote), "quoted": _own(unquote),
    "pem": _own(pem), "armor": _own(pem), "hexdump": _own(hexdump), "xxd": _own(hexdump),
    "lower": _own(to_upper), "lowercase": _own(to_upper), "lower_hex": _own(to_upper), "lower-hex": _own(to_upper),
    "upper": _own(to_upper), "swapcase": _own(swapcase),
    "xor_prev": xor_prev, "xor-prev": xor_prev,
    "add_index": by_index(True), "add-index": by_index(True), "sub_index": by_index(False), "sub-index": by_index(False),
    "reflection": reflection,
}


def own(C, name, d, p, clock):
    """[(output, tag)] for a step of OWN, or None for any other name: the caller's verdict on the
    name stands. A reading that fails gives nothing."""
    fn = OWN.get(name)
    if fn is None:
        return None
    try:
        return [(o, tag) for o, tag in fn(C, d, p if isinstance(p, dict) else {}, clock) if o and len(o) <= MAX_OUT]
    except Exception:
        return []


# ---------------------------------------------------------------------------- registration

def _plain(fn):
    def step(d, p, clock):
        try:
            o = fn(d)
        except Exception:
            o = None
        return [(o, "")] if o and len(o) <= MAX_OUT else []
    return step


def _base62(d, p, clock):
    outs = []
    for alphabet, tag in ((_B62, ""), (_B62_LOWER, "lower-first")):
        try:
            o = base62(d, alphabet)
        except Exception:
            o = None
        if o:
            outs.append((o, tag))
    return outs


def native(C, d, p, clock):
    """The `native` codec (Day 15, row 309): a recognised codec name whose answer is NOT in the
    document's `data` but in the APK's native libraries (lib/*/*.so). There is nothing to decode
    from `data` here, so this step reads nothing; codec_search.solve_doc returns None for a native
    document (NATIVE_NAMES) and codec_search.native_hit reads the libraries (apk_resources.native_secret)
    and offers the code under mobile.codec/native. Registering the name keeps `native` in the
    codec-by-name path so the machinery treats it as a known codec, never an opaque unknown."""
    return []


def steps(C) -> dict:
    """The steps of this module, bound to one instance of codec_search."""
    from functools import partial
    return {
        "base36": _plain(base36), "base62": _base62, "base45": _plain(base45), "base91": _plain(base91),
        "qp": _plain(qp), "entities": _plain(entities), "escapes": _plain(escapes), "morse": _plain(morse),
        "zstd": _packed(C, _zstd), "lz4": _packed(C, _lz4), "brotli": _packed(C, _brotli),
        "snappy": _packed(C, _snappy),
        "columnar": partial(columnar, C), "delta": partial(delta, C), "offsets": partial(offsets, C),
        "chacha20": partial(chacha20, C), "des3": partial(des3, C), "fernet": partial(fernet, C),
        "blowfish": partial(blowfish, C),
        "jwt": partial(jwt, C), "native": partial(native, C),
    }


STEP_NAMES = ("base36", "base62", "base45", "base91", "qp", "entities", "escapes", "morse", "zstd", "lz4", "brotli",
              "snappy", "columnar", "delta", "offsets", "chacha20", "des3", "fernet", "jwt", "native", "blowfish")

NAMES = {
    "b36": "base36", "base-36": "base36", "base_36": "base36", "b62": "base62", "base-62": "base62",
    "base_62": "base62", "b45": "base45", "base-45": "base45", "base_45": "base45", "b91": "base91",
    "base-91": "base91", "base_91": "base91", "basE91": "base91",
    "quoted-printable": "qp", "quoted_printable": "qp", "quotedprintable": "qp", "quopri": "qp",
    "html": "entities", "html-entities": "entities", "html_entities": "entities", "htmlentities": "entities",
    "entity": "entities", "xml-entities": "entities", "xml_entities": "entities", "numeric-entities": "entities",
    "escape": "escapes", "escaped": "escapes", "unicode-escape": "escapes", "unicode_escape": "escapes",
    "hex-escape": "escapes", "hex_escape": "escapes", "hexescape": "escapes",
    "c-escape": "escapes", "c_escape": "escapes", "octal-escape": "escapes", "octal_escape": "escapes",
    "backslash": "escapes", "js-escape": "escapes", "js_escape": "escapes",
    "morse-code": "morse", "morse_code": "morse", "morsecode": "morse",
    "zstandard": "zstd", "zst": "zstd", "lz4-frame": "lz4", "lz4_frame": "lz4", "lz4frame": "lz4", "br": "brotli",
    "snappy-raw": "snappy", "snappy_raw": "snappy",
    "columnar-transposition": "columnar", "columnar_transposition": "columnar", "transposition": "columnar",
    "column-transposition": "columnar", "column_transposition": "columnar", "columns": "columnar",
    "scytale": "columnar", "skytale": "columnar",
    "diff": "delta", "differential": "delta", "delta-encoding": "delta", "delta_encoding": "delta",
    "running-sum": "delta", "running_sum": "delta", "cumulative": "delta", "xor-chain": "delta",
    "xor_chain": "delta", "xorchain": "delta", "chained-xor": "delta", "chained_xor": "delta",
    "offset": "offsets", "per-char-offset": "offsets", "per_char_offset": "offsets", "char-offsets": "offsets",
    "char_offsets": "offsets", "per-character-offsets": "offsets", "per_character_offsets": "offsets",
    "deltas": "offsets", "shifts": "offsets", "otp": "offsets", "one-time-pad": "offsets", "one_time_pad": "offsets",
    "chacha": "chacha20", "cha-cha20": "chacha20", "chacha-20": "chacha20", "chacha_20": "chacha20",
    "3des": "des3", "tripledes": "des3", "triple-des": "des3", "triple_des": "des3", "des-ede3": "des3",
    "des_ede3": "des3", "desede": "des3", "tdes": "des3",
    # single DES by name (Day 14 look-ahead): Triple DES with one 8-byte key is DES
    "des": "des3", "des-ecb": "des3", "des_ecb": "des3", "des-cbc": "des3", "des_cbc": "des3", "3des-ecb": "des3",
    "3des-cbc": "des3", "3des_ecb": "des3", "3des_cbc": "des3", "des3-ecb": "des3", "des3-cbc": "des3",
    "des-ede3-cbc": "des3", "desede-cbc": "des3",
    # Blowfish by name (Day 20 build, the Day 19 look-ahead's E07)
    "blowfish-ecb": "blowfish", "blowfish_ecb": "blowfish", "blowfish-cbc": "blowfish",
    "blowfish_cbc": "blowfish", "bf-ecb": "blowfish", "bf_ecb": "blowfish", "bf-cbc": "blowfish", "bf_cbc": "blowfish",
    "fernet-token": "fernet", "fernet_token": "fernet",
    "jwt-payload": "jwt", "jwt_payload": "jwt", "jws": "jwt", "json-web-token": "jwt", "json_web_token": "jwt",
    # the native-library codec (Day 15, row 309): the code is in lib/*/*.so, read by codec_search.native_hit
    "native_library": "native", "native-library": "native", "nativelibrary": "native", "jni": "native",
    "ndk": "native", "native_secret": "native", "native-secret": "native",
    # Day 16 look-ahead (row 312): native-library synonyms for the deepened theme (obfuscated .so code)
    "so": "native", "so_secret": "native", "so-secret": "native", "shared_object": "native",
    "shared-object": "native", "sharedobject": "native", "native_obfuscated": "native",
    "native-obfuscated": "native", "libsecret": "native",
}


def register(C) -> None:
    """Add this module's steps to one codec_search instance's tables. Called by codec_search at import,
    with an object that gives its module globals by attribute."""
    for name, fn in steps(C).items():
        if name not in C.KEYED and name not in C.STEP and name not in C.base.NAMED:
            C.KEYED[name] = fn
    for alias, name in NAMES.items():
        if alias not in C.ALIASES and alias not in C.KEYED and alias not in C.STEP and alias not in C.base.NAMED:
            C.ALIASES[alias] = name


def also(C, name, d, p):
    """Further readings of a step codec_search applied itself: the step in the document's own alphabet."""
    try:
        return custom_alphabet(C, name, d, p)
    except Exception:
        return []
