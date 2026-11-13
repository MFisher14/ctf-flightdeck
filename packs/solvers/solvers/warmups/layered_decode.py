#!/usr/bin/env python3
"""Decode a layered text blob until it reads as English, then return the answer slug.

Usage:
  python3 solvers/warmups/layered_decode.py <blob-file> [...]

Blob shapes seen so far:
  * one payload in a single encoding (Single Solve, Time Trial)
  * numbered records "NN<TAB>payload", one per line, where every record is a
    fragment of the same sentence in its own encoding (Mastery). The decoded
    fragments are concatenated in record order.

Each payload goes through a small breadth-first search over strict decoders
(hex, base64/32/85/58/45, rot13, binary, octal, decimal, URL, HTML entities,
quoted-printable, morse, compression). Candidates are ranked by how English
they look, and a result is accepted only if the assembled text has common
English words and a slug such as `word-word-word-42` on its final non-empty
line. Looser transforms (caesar, atbash, rot47, reverse, single-byte XOR) are
tried only when nothing strict reads as English. Every blob has a hard time
budget, so a timed attempt can never stall here. Nothing about any particular
blob is hardcoded.
"""
import base64
import bz2
import codecs
import gzip
import html
import io
import itertools
import lzma
import math
import os
import quopri
import re
import sys
import time
import urllib.parse
import zlib

SLUG_STRICT = re.compile(r"(?<![A-Za-z0-9-])[a-z]+-[a-z]+-[a-z]+-\d{2}(?![A-Za-z0-9-])")
SLUG_ANY = re.compile(r"(?<![A-Za-z0-9-])[a-z]+(?:-[a-z]+)+-\d+(?![A-Za-z0-9-])")
RECORD = re.compile(rb"^ *(\d{1,4})\t(.*)$")
BUDGET = 0.35  # seconds per blob
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
MORSE = {".-": "a", "-...": "b", "-.-.": "c", "-..": "d", ".": "e", "..-.": "f", "--.": "g", "....": "h",
         "..": "i", ".---": "j", "-.-": "k", ".-..": "l", "--": "m", "-.": "n", "---": "o", ".--.": "p",
         "--.-": "q", ".-.": "r", "...": "s", "-": "t", "..-": "u", "...-": "v", ".--": "w", "-..-": "x",
         "-.--": "y", "--..": "z", "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
         ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9", "-....-": "-", ".-.-.-": ".",
         "--..--": ",", "---...": ":", "-.-.--": "!", "..--..": "?"}

# Rough character frequencies of English prose, used to rank candidate decodings.
_FREQ = {" ": .182, "e": .102, "t": .075, "a": .065, "o": .062, "n": .057, "i": .057, "s": .053, "r": .050,
         "h": .050, "d": .034, "l": .033, "u": .023, "c": .022, "m": .020, "f": .018, "w": .017, "g": .016,
         "p": .015, "y": .015, "b": .012, "v": .008, "k": .006, "x": .0014, "j": .0010, "q": .0008, "z": .0006}
_FREQ.update({c: .004 for c in "-,.!:;'\"?()"})
_FREQ.update({c: .003 for c in "0123456789"})
_LOGP = {c: math.log(p) for c, p in _FREQ.items()}
_LOG_WS, _LOG_OTHER, _LOG_BAD = math.log(.01), math.log(1e-4), math.log(1e-7)

COMMON = set("""the be to of and a in that have i it for not on with he as you do at this but his by from they we
say her she or an will my one all would there their what so up out if about who get which go me when make can
like time no just him know take people into year your good some could them see other than then now look only
come its over think also back after use two how our work first well way even new want because any these give
day most us is are was were has had here following answer submit exact solve solved game master nice decoding
decode decoded warmup final line flag message code word slug great job done please enter type send correct
value text congratulations""".split())


def _text(b: bytes):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _compact(b: bytes):
    t = _text(b)
    return None if t is None else re.sub(r"\s+", "", t)


def d_hex(b):
    t = _text(b)
    if t is None:
        return None
    t = re.sub(r"0x|\\x|[\s:,;]", "", t)
    if len(t) < 2 or len(t) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", t):
        return None
    return bytes.fromhex(t)


def _b64(alphabet_re, decode):
    def f(b):
        t = _compact(b)
        if not t or len(t) < 4 or not re.fullmatch(alphabet_re + r"={0,2}", t):
            return None
        t = t.rstrip("=")
        if len(t) % 4 == 1:
            return None
        try:
            return decode(t + "=" * (-len(t) % 4))
        except Exception:
            return None
    return f


d_b64 = _b64(r"[A-Za-z0-9+/]+", lambda t: base64.b64decode(t, validate=True))
d_b64url = _b64(r"[A-Za-z0-9_-]+", base64.urlsafe_b64decode)


def _b32(alphabet_re, decode):
    def f(b):
        t = _compact(b)
        if not t or len(t) < 8 or not re.fullmatch(alphabet_re + r"=*", t.upper()):
            return None
        t = t.upper().rstrip("=")
        try:
            return decode(t + "=" * (-len(t) % 8))
        except Exception:
            return None
    return f


d_b32 = _b32(r"[A-Z2-7]+", base64.b32decode)
d_b32hex = _b32(r"[0-9A-V]+", base64.b32hexdecode)


def _try(fn):
    def f(b):
        t = _compact(b)
        if not t or len(t) < 5:
            return None
        try:
            return fn(t.encode())
        except Exception:
            return None
    return f


d_b85 = _try(base64.b85decode)
d_a85 = _try(lambda t: base64.a85decode(t, adobe=t.startswith(b"<~")))


def d_b58(b):
    t = _compact(b)
    if not t or len(t) < 6 or any(c not in B58 for c in t):
        return None
    n = 0
    for c in t:
        n = n * 58 + B58.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(t) - len(t.lstrip("1"))) + body


def d_b45(b):
    t = _text(b)
    if t is None:
        return None
    t = t.strip("\r\n")
    if len(t) < 5 or any(c not in B45 for c in t) or len(t) % 3 == 1:
        return None
    out = bytearray()
    for i in range(0, len(t), 3):
        chunk = t[i:i + 3]
        v = sum(B45.index(c) * 45 ** j for j, c in enumerate(chunk))
        if v > (0xFFFF if len(chunk) == 3 else 0xFF):
            return None
        out += v.to_bytes(2 if len(chunk) == 3 else 1, "big")
    return bytes(out)


def d_binary(b):
    t = _text(b)
    if t is None or not re.fullmatch(r"[01\s]+", t):
        return None
    groups = t.split()
    if len(groups) > 1 and all(len(g) <= 8 for g in groups):
        return bytes(int(g, 2) for g in groups)
    bits = "".join(groups)
    if len(bits) < 8 or len(bits) % 8:
        return None
    return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))


def _numbers(base, pattern):
    def f(b):
        t = _text(b)
        if t is None:
            return None
        toks = [x for x in re.split(r"[\s,;]+", t.strip()) if x]
        if len(toks) < 2 or not all(re.fullmatch(pattern, x) for x in toks):
            return None
        vals = [int(x, base) for x in toks]
        return bytes(vals) if all(v < 256 for v in vals) else None
    return f


d_octal = _numbers(8, r"[0-7]{1,3}")
d_decimal = _numbers(10, r"\d{1,3}")


def d_url(b):
    t = _text(b)
    if t is None or not re.search(r"%[0-9a-fA-F]{2}", t):
        return None
    return urllib.parse.unquote_to_bytes(t)


def d_html(b):
    t = _text(b)
    if t is None or not re.search(r"&(#x?[0-9a-fA-F]+|[a-z]+);", t):
        return None
    return html.unescape(t).encode()


def d_qp(b):
    return quopri.decodestring(b) if re.search(rb"=[0-9A-F]{2}", b) else None


def d_morse(b):
    t = _text(b)
    if t is None or not re.fullmatch(r"[.\-/|\s]+", t) or ("." not in t and "-" not in t):
        return None
    words = re.split(r"\s*[/|]\s*|\s{3,}", t.strip())
    try:
        return " ".join("".join(MORSE[c] for c in w.split()) for w in words).encode()
    except KeyError:
        return None


def d_rot13(b):
    t = _text(b)
    if t is None or not re.search(r"[A-Za-z]", t):
        return None
    return codecs.decode(t, "rot13").encode()


# Modern compression codecs beside the stdlib's gzip/zlib/bzip2/xz: zstandard, lz4 (frame), brotli,
# snappy, and the header-less LZMA "alone"/.lzma format. The libraries are optional -- a copy of this
# folder without one of them reads every other form exactly as before. Each decoder is strict (it
# decodes only its own stream) and exception-guarded, and the search accepts a reading only when the
# decoded text reproduces the sentence, so a stream a codec cannot read, or one that decodes to
# garbage, yields None, never a wrong slug (no WRONG risk to any existing day).
try:
    import zstandard as _zstandard
except Exception:                       # pragma: no cover - library optional
    _zstandard = None
try:
    import brotli as _brotli
except Exception:                       # pragma: no cover - library optional
    _brotli = None
try:
    import lz4.frame as _lz4frame
except Exception:                       # pragma: no cover - library optional
    _lz4frame = None
try:
    import snappy as _snappy
except Exception:                       # pragma: no cover - library optional
    _snappy = None
try:
    import lz4.block as _lz4block
except Exception:                       # pragma: no cover - library optional
    _lz4block = None

# 1 MiB. No warmup blob decompresses past this (the sentence and a slug are a few hundred bytes), so
# any stream whose output would exceed the cap is a decompression bomb or not a warmup at all, and is
# rejected (None). The cap is enforced BEFORE a huge buffer is allocated wherever the codec lets us
# see the size first (zstd's frame header, snappy's length varint) and otherwise with a bounded
# incremental read, so a crafted input cannot make d_compress allocate gigabytes or stall a window.
# Rejecting fails closed: a dropped stream is a clean None, never a wrong plain slug (never-guess).
_COMP_CAP = 1 << 20


def _capped_oneshot(oneshot, factory, b):
    """``oneshot(b)`` for a stream that decompresses within the cap, else None.

    The stdlib one-shot decompressors (gzip/zlib/bz2/lzma) allocate their whole output before they
    return, so a bomb has to be caught first. A fresh incremental decompressor (``factory()`` with
    ``.decompress(data, max_length)``, ``.eof`` and ``.unused_data``) is driven with a bounded read;
    a stream whose output passes the cap is rejected before the full buffer ever grows. A stream that
    fits is handed to ``oneshot`` UNCHANGED, so the returned bytes are byte-for-byte what the shipped
    code returned -- multi-member, trailing-data and checksum behaviour is exactly the stdlib's, which
    keeps the saved-attempt regression identical. Rejection only ever removes a >1 MiB result that no
    warmup produces."""
    try:
        total, data = 0, b
        while data:
            d = factory()
            total += len(d.decompress(bytes(data), _COMP_CAP + 1 - total))
            if total > _COMP_CAP:          # bomb / over cap: stopped before the full buffer grew
                return None
            if not d.eof:                  # truncated, or needs more output than the cap allows
                break                      # hand to oneshot (it raises -> None) without unbounding
            data = d.unused_data
    except Exception:
        pass                               # pre-pass inconclusive; the guarded one-shot still caps
    try:
        out = oneshot(b)
    except Exception:
        return None
    return out if isinstance(out, (bytes, bytearray)) and len(out) <= _COMP_CAP else None


def _gzip_decompress(b):
    return _capped_oneshot(gzip.decompress, lambda: zlib.decompressobj(16 + zlib.MAX_WBITS), b)


def _zlib_decompress(b):
    return _capped_oneshot(zlib.decompress, zlib.decompressobj, b)


def _bz2_decompress(b):
    return _capped_oneshot(bz2.decompress, bz2.BZ2Decompressor, b)


# 128 MiB: above preset 9's 64 MiB dictionary, so every real (tiny) warmup at any standard preset
# decodes, while a crafted stream that declares a gigabyte dictionary is rejected before the buffer is
# allocated. An LZMA stream's dictionary is a separate, header-declared allocation that the output cap
# alone does not bound, so it is capped here with the format's own memlimit.
_LZMA_MEMLIMIT = 128 << 20


def _lzma_decompress(b):
    # FORMAT_AUTO reads both the .xz stream and the header-less .lzma "alone" stream; the magic loop
    # gates the alone branch on the properties byte 0x5d so the xz branch keeps the xz magic.
    return _capped_oneshot(lambda data: lzma.decompress(data, memlimit=_LZMA_MEMLIMIT),
                           lambda: lzma.LZMADecompressor(memlimit=_LZMA_MEMLIMIT), b)


_lzma_alone_decompress = _lzma_decompress   # the old name, kept for any caller that imported it


def _zstd_decompress(b):
    if _zstandard is None:
        return None
    try:
        size = _zstandard.frame_content_size(b)   # declared output size, -1 when the frame omits it
    except Exception:
        return None                               # not a readable zstd frame
    if size > _COMP_CAP:                           # declared bomb: reject before anything is allocated
        return None
    try:
        dctx = _zstandard.ZstdDecompressor()
        with dctx.stream_reader(io.BytesIO(b)) as r:   # a frame without a declared size stops here
            out = r.read(_COMP_CAP + 1)
    except Exception:
        return None
    return out if len(out) <= _COMP_CAP else None


def _lz4f_decompress(b):
    if _lz4frame is None:
        return None
    try:
        d = _lz4frame.LZ4FrameDecompressor()
        out = d.decompress(b, _COMP_CAP + 1)       # max_length bounds the output
    except Exception:
        return None
    return out if d.eof and len(out) <= _COMP_CAP else None


_BROTLI_BOUNDED = False
if _brotli is not None:                            # does this build's brotli cap the output buffer?
    try:
        _bd = _brotli.Decompressor()
        _bd.process(_brotli.compress(b"x"), output_buffer_limit=2)
        _BROTLI_BOUNDED = True
    except Exception:                               # pragma: no cover - old brotli without the limit
        _BROTLI_BOUNDED = False


def _brotli_decompress(b):
    # Brotli declares no output size, so it is read with the incremental decompressor under an
    # output-buffer limit: a bomb stops at the limit (is_finished() stays False) and is rejected, and
    # peak memory stays near the cap. A brotli build that does not support the limit is treated as
    # absent rather than run unbounded (fail closed); this build's brotli supports it.
    if _brotli is None or not _BROTLI_BOUNDED:
        return None
    try:
        d = _brotli.Decompressor()
        out = d.process(b, output_buffer_limit=_COMP_CAP + 1)
    except Exception:
        return None
    return out if d.is_finished() and len(out) <= _COMP_CAP else None


def _snappy_decompress(b):
    # Raw-block snappy begins with the uncompressed length as a base-128 varint. Reject a declared
    # length over the cap before the C library allocates it (this also covers the "huge length, tiny
    # data" craft, which the binding already rejects), then decode -- the output is then bounded.
    if _snappy is None:
        return None
    n = shift = 0
    for byte in b[:5]:
        n |= (byte & 0x7f) << shift
        if not (byte & 0x80):
            break
        shift += 7
    else:
        return None                                # no varint terminator in 5 bytes: not raw snappy
    if n > _COMP_CAP:
        return None
    try:
        out = _snappy.decompress(b)
    except Exception:
        return None
    return out if isinstance(out, (bytes, bytearray)) and len(out) <= _COMP_CAP else None


# Unix compress (.Z), the classic LZW container (magic 1f 9d). There is no stdlib or .venv decoder,
# so this is a small, bounded, pure-Python ncompress-compatible LZW reader (variable 9..maxbits codes,
# packed LSB-first, the block-boundary alignment quirk that real `compress` uses on each code-width bump
# and CLEAR). It is magic-gated and output-capped, so a non-.Z stream raises/returns None and a crafted
# header cannot make it allocate past the cap; a malformed body fails closed (None, never a wrong slug).
# Validated against /usr/bin/compress across bit widths (tests/test_wave2_warmups_breadth.py).
_LZW_INIT_BITS = 9


def _lzw_z_decompress(b):
    if len(b) < 3 or b[0] != 0x1f or b[1] != 0x9d:
        return None
    maxbits = b[2] & 0x1f
    block_mode = bool(b[2] & 0x80)
    if maxbits < _LZW_INIT_BITS or maxbits > 16:
        return None
    maxmaxcode = 1 << maxbits
    first_free = 257 if block_mode else 256
    prefix = [0] * (maxmaxcode + 1)
    suffix = bytearray(maxmaxcode + 1)
    for i in range(256):
        suffix[i] = i
    cr = b[3:]
    total = len(cr) * 8
    st = {"nbits": _LZW_INIT_BITS, "maxcode": (1 << _LZW_INIT_BITS) - 1, "free": first_free,
          "pos": 0, "clear": False}

    def align():                        # round the bit cursor up to the next n_bits-byte block
        blk = st["nbits"] << 3
        p = st["pos"]
        st["pos"] = p + ((blk - (p % blk)) % blk)

    def getcode():
        if st["clear"]:                 # after a CLEAR: reset to 9 bits, align on the new width
            st["nbits"] = _LZW_INIT_BITS
            st["maxcode"] = (1 << _LZW_INIT_BITS) - 1
            align()
            st["clear"] = False
        elif st["free"] > st["maxcode"] and st["nbits"] < maxbits:
            align()                     # a width bump aligns on the OLD width first (compress quirk)
            st["nbits"] += 1
            st["maxcode"] = maxmaxcode if st["nbits"] == maxbits else (1 << st["nbits"]) - 1
        nb = st["nbits"]
        p = st["pos"]
        if p + nb > total:
            return -1
        code = 0
        for i in range(nb):
            bit = p + i
            if (cr[bit >> 3] >> (bit & 7)) & 1:
                code |= 1 << i
        st["pos"] = p + nb
        return code

    out = bytearray()
    oldcode = getcode()
    if oldcode == -1:
        return None
    if oldcode >= 256:
        return None
    finchar = oldcode
    out.append(finchar)
    while True:
        code = getcode()
        if code == -1:
            break
        if block_mode and code == 256:                 # CLEAR: wipe the learned table
            st["free"] = first_free
            st["clear"] = True
            oldcode = getcode()
            if oldcode == -1:
                break
            if oldcode >= 256:
                return None
            finchar = oldcode
            out.append(finchar)
            continue
        incode = code
        stack = bytearray()
        if code >= st["free"]:                         # KwKwK special case
            stack.append(finchar)
            code = oldcode
        if code >= st["free"]:                         # corrupt reference: fail closed
            return None
        while code >= 256:
            stack.append(suffix[code])
            code = prefix[code]
        finchar = suffix[code]
        stack.append(finchar)
        out.extend(stack[::-1])
        if len(out) > _COMP_CAP:                       # output bomb: stop before it grows further
            return None
        if st["free"] < maxmaxcode:
            prefix[st["free"]] = oldcode
            suffix[st["free"]] = finchar
            st["free"] += 1
        oldcode = incode
    return bytes(out) or None


def _lz4b_decompress(b):
    # lz4 BLOCK format (the lz4 FRAME magic 04 22 4d 18 is handled above). Python's lz4.block.compress
    # prepends the uncompressed length as a little-endian uint32 (store_size=True, its default) so the
    # stream is self-describing; the header-less store_size=False form carries no length and is not read
    # (we never guess an output size). The declared length is bomb-checked against the cap before the C
    # library allocates it; a non-lz4 stream raises (LZ4BlockError) in microseconds and yields None.
    if _lz4block is None or len(b) < 5:
        return None
    size = int.from_bytes(b[:4], "little")
    if size == 0 or size > _COMP_CAP:
        return None
    try:
        out = _lz4block.decompress(bytes(b))
    except Exception:
        return None
    return out if isinstance(out, (bytes, bytearray)) and 0 < len(out) <= _COMP_CAP else None


def d_compress(b):
    for magic, fn in ((b"\x1f\x8b", _gzip_decompress), (b"BZh", _bz2_decompress),
                      (b"\xfd7zXZ", _lzma_decompress), (b"\x78", _zlib_decompress),
                      (b"\x28\xb5\x2f\xfd", _zstd_decompress), (b"\x04\x22\x4d\x18", _lz4f_decompress),
                      (b"\x1f\x9d", _lzw_z_decompress), (b"\x5d", _lzma_decompress)):
        if b.startswith(magic):
            try:
                out = fn(b)
            except Exception:
                out = None
            if out is not None:
                return out
    # Brotli and snappy carry no signature, so they are tried by decoding. Only on binary input (a
    # compressed stream is never ASCII text, and every real chain reaches this through hex/base64
    # first) and only when nothing with a magic above read it. Each is bounded to _COMP_CAP, so a
    # crafted non-ASCII search state cannot make the try-decode allocate a huge buffer or stall a
    # window; non-conforming bytes are still rejected in microseconds without allocating.
    if not b.isascii():
        for fn in (_brotli_decompress, _snappy_decompress, _lz4b_decompress):
            try:
                out = fn(b)
            except Exception:
                out = None
            if out:
                return out
    return None


def d_utf16(b):
    if b[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(b) > 8 and len(b) % 2 == 0 and b[1::2].count(0) > len(b) // 4):
        try:
            return b.decode("utf-16").encode()
        except Exception:
            return None
    return None


def d_reverse(b):
    return b[::-1]


def d_atbash(b):
    t = _text(b)
    if t is None or not t.isascii() or not re.search(r"[A-Za-z]", t):
        return None
    return "".join(chr(155 - ord(c)) if c.isupper() else chr(219 - ord(c)) if c.islower() else c for c in t).encode()


def d_rot47(b):
    t = _text(b)
    if t is None or not t.isascii():
        return None
    return "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in t).encode()


def _caesar(n):
    def f(b):
        t = _text(b)
        if t is None or not t.isascii() or not re.search(r"[A-Za-z]", t):
            return None
        return "".join(chr((ord(c) - 65 + n) % 26 + 65) if c.isupper() else
                       chr((ord(c) - 97 + n) % 26 + 97) if c.islower() else c for c in t).encode()
    f.__name__ = f"d_caesar{n}"
    return f


def _xor(k):
    def f(b):
        return bytes(x ^ k for x in b)
    f.__name__ = f"d_xor{k:02x}"
    return f


for _name, _fn in list(globals().items()):
    if _name.startswith("d_") and callable(_fn):
        _fn.__name__ = _name  # closures would otherwise all report themselves as "f"

STRICT = [d_hex, d_b64, d_b32, d_binary, d_octal, d_decimal, d_url, d_html, d_morse, d_rot13, d_compress,
          d_utf16, d_b64url, d_b32hex, d_qp, d_b85, d_a85, d_b58, d_b45]
LOOSE = [d_reverse, d_atbash, d_rot47] + [_caesar(n) for n in range(1, 26) if n != 13] + [_xor(k) for k in range(1, 256)]


def english(b: bytes) -> float:
    """Mean log-probability per character under an English model; -inf when b is not text."""
    t = _text(b)
    if not t:
        return float("-inf")
    total = 0.0
    for ch in t:
        lp = _LOGP.get(ch.lower())
        if lp is None:
            lp = _LOG_WS if ch in "\r\n\t" else _LOG_OTHER if (ch.isascii() and ch.isprintable()) else _LOG_BAD
        total += lp
    return total / len(t)


def records(data: bytes):
    """Payloads of a numbered-record blob in record order, or None for a plain blob."""
    lines = [ln for ln in data.splitlines() if ln.strip()]
    hits = [RECORD.match(ln) for ln in lines]
    if not lines or not all(hits):
        return None
    return [m.group(2) for m in sorted(hits, key=lambda m: int(m.group(1)))]


def candidates(payload: bytes, decoders, deadline: float, depth: int = 5, cap: int = 400):
    """Everything reachable from payload through the decoders: [(score, bytes, chain)], best first."""
    seen, frontier = {payload}, [(payload, ())]
    found = [(english(payload), payload, ())]
    for _ in range(depth):
        nxt = []
        for cur, chain in frontier:
            for dec in decoders:
                if len(seen) > cap or time.perf_counter() > deadline:
                    break
                try:
                    out = dec(cur)
                except Exception:
                    out = None
                if not out or out in seen:
                    continue
                seen.add(out)
                step = chain + (dec.__name__[2:],)
                found.append((english(out), out, step))
                nxt.append((out, step))
        frontier = nxt
        if not frontier:
            break
    found = [f for f in found if f[0] > float("-inf")]
    found.sort(key=lambda f: -f[0])
    return found


_DICT = None


def _dictionary():
    global _DICT
    if _DICT is None:
        _DICT = set()
        path = "/usr/share/dict/words"
        if os.path.exists(path):
            with open(path, encoding="utf-8", errors="ignore") as fh:
                _DICT = {w.strip().lower() for w in fh}
    return _DICT


def judge(text: str):
    """(slug, quality) when text reads as English and its final non-empty line carries a slug, else None.

    quality = (slug strictness, sentence tier, slug stands alone, common-word hits); higher is better.
    """
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    last = lines[-1]
    hits, strict = list(SLUG_STRICT.finditer(last)), 2
    if not hits:
        hits, strict = list(SLUG_ANY.finditer(last)), 1
    if not hits:
        return None
    slug = hits[-1].group(0)
    alone = int(hits[-1].start() == 0 or last[hits[-1].start() - 1].isspace())
    words = [w.lower() for w in re.findall(r"[A-Za-z]+", text.replace(slug, " "))]
    common = sum(w in COMMON for w in words)
    if common >= 3 and common / len(words) >= 0.3:
        return slug, (strict, 1, alone, common)
    # Terse messages: fall back to a dictionary check of the slug's own words.
    parts = slug.split("-")[:-1]
    known = _dictionary()
    if known and sum(p in known for p in parts) >= max(2, len(parts) - 1) and (not words or common >= 1):
        return slug, (strict, 0, alone, common)
    return None


def _real_words(text: str) -> int:
    """Real words minus non-words over the whole text, slug included."""
    known = _dictionary()
    words = [w.lower() for w in re.findall(r"[A-Za-z]+", text)]
    real = sum(w in COMMON or w in ("a", "i") or (len(w) > 1 and w in known) for w in words)
    return 2 * real - len(words)


def assemble(pools, joiner: str, deadline: float = float("inf")):
    """Pick one candidate per payload so the joined text is judged English: (slug, chains, text) or None."""
    passed = []
    for n, combo in enumerate(itertools.islice(itertools.product(*pools), 6000)):
        if n % 64 == 0 and time.perf_counter() > deadline:
            break
        text = joiner.join(c[1].decode("utf-8") for c in combo)
        verdict = judge(text)
        if not verdict:
            continue
        size = sum(len(c[1]) for c in combo) or 1
        passed.append({"slug": verdict[0], "quality": verdict[1], "text": text, "chains": [list(c[2]) for c in combo],
                       "single": sum(len(c[2]) == 1 for c in combo), "layers": sum(len(c[2]) for c in combo),
                       "score": sum(c[0] * len(c[1]) for c in combo) / size})
    if not passed:
        return None
    if len({p["slug"] for p in passed}) > 1:
        # Readings disagree on the slug. Short fragments carry too little signal for letter statistics,
        # so rank on the sentence: slug shape, whole real words, then the reading in which every
        # numbered record is exactly one encoding (how these blobs are built), then fewest layers.
        records_mode = len(pools) > 1
        best = max(passed, key=lambda p: (p["quality"][:3], _real_words(p["text"]),
                                          p["single"] if records_mode else 0, -p["layers"], p["score"]))
    else:
        best = max(passed, key=lambda p: (p["quality"], -p["layers"], p["score"]))
    return best["slug"], best["chains"], best["text"]


def _shortlist(found, payload: bytes, keep: int):
    """Candidates worth trying for one payload, best first."""
    if not found:
        return []
    best = found[0]
    if all(len(f[1]) >= 40 for f in found[:3]):
        # Enough text for letter statistics to be trusted.
        return [f for f in found if f[0] >= best[0] - 0.4][:2]
    # A short fragment can be over-decoded into something that merely scores well ("47" -> hex -> "G").
    # Keep the plain reading and every one-step decoding next to the best scorers; assemble() decides.
    picks, seen = [], set()
    for f in sorted([f for f in found if len(f[2]) <= 1], key=lambda f: len(f[2]), reverse=True) + found[:3]:
        if f[1] not in seen:
            seen.add(f[1])
            picks.append(f)
    return picks[:keep]


def solve_blob(data: bytes, budget: float = BUDGET):
    """Return (slug, [decoder chain per payload], decoded text) or None."""
    deadline = time.perf_counter() + budget
    shapes = []
    recs = records(data)
    if recs:
        shapes.append((recs, ""))
    shapes.append(([data], ""))
    lines = [ln for ln in data.splitlines() if ln.strip()]
    if not recs and len(lines) > 1:
        shapes.append((lines, "\n"))
        shapes.append((lines, ""))

    for decoders in (STRICT, None):
        for payloads, joiner in shapes:
            pools = []
            keep = max(1, min(6, int(6000 ** (1 / len(payloads)))))
            for p in payloads:
                found = candidates(p, STRICT, deadline)
                if decoders is None:
                    # Last resort: one loose transform on the payload and on its best strict readings.
                    seen = {f[1] for f in found}
                    for _, src, chain in [(0, p, ())] + found[:3]:
                        for dec in LOOSE:
                            if time.perf_counter() > deadline:
                                break
                            out = dec(src)
                            if out and out not in seen:
                                seen.add(out)
                                sc = english(out)
                                if sc > float("-inf"):
                                    found.append((sc, out, chain + (dec.__name__[2:],)))
                    found.sort(key=lambda f: -f[0])
                pools.append(_shortlist(found, p, keep))
            if all(pools):
                hit = assemble(pools, joiner, deadline + 0.15)
                if hit:
                    return hit
            if time.perf_counter() > deadline:
                return None
    return None


def solve_set(questions, files, ctx):
    out = {}
    for q in questions:
        data = files.get(q.get("member") or "") or files.get(q.get("artifact") or "") or ctx["delivery"]
        hit = solve_blob(data)
        out[q["qid"]] = hit[0] if hit else None
    return out


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("layered_decode.py: input file required", file=sys.stderr)
        raise SystemExit(2)
    if any(a in ("-h", "--help") for a in sys.argv[1:]):
        print("usage: layered_decode.py <file> [...]")
        raise SystemExit(0)
    for path in sys.argv[1:]:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError as exc:
            print(f"layered_decode.py: {exc}", file=sys.stderr)
            raise SystemExit(2)
        t0 = time.perf_counter()
        hit = solve_blob(blob)
        ms = (time.perf_counter() - t0) * 1000
        if hit:
            layers = " | ".join("+".join(c) or "plain" for c in hit[1])
            print(f"{path}: {hit[0]}   [{layers}]   {ms:.0f} ms\n    {hit[2].strip()!r}")
        else:
            print(f"{path}: no slug found   {ms:.0f} ms")
