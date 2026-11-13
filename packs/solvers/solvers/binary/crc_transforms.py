#!/usr/bin/env python3
"""CRC-gated transform widening for HCFG-layout payloads (B-246, oracle-search-audit row 4).

  python3 solvers/binary/crc_transforms.py <sample> [...]    every CRC-valid container, every reading

The HCFG header (`magic | version u8 | key u8 | length u16 | crc32 u32 | payload`) stores the CRC-32 of the
DECODED payload, so it is a 32-bit content proof: a candidate decode whose CRC-32 is not the stored one is
dropped, and nothing here can yield bytes the author did not write. hcfg.py reads the lane's single-byte XOR,
rolling/add/sub, reversed, UTF-16LE, zlib/gzip, base64, repeating XOR (now one reader for XOR, add and sub
keys of 2..64 bytes) and RC4 under a nearby string. This module adds the families row 4 lists, each behind
that same CRC-32 check and each with a bounded budget:

cheap (hcfg._other_readings, every tried header):
  rotate_r<R>         plain = ROTR(payload, R) XOR key_bytes, R in 1..7: the header key byte (as stored and
                      rotated), no key, and a repeating key of 1..13 bytes from the OPENING crib. XOR and
                      rotation commute (ROTR(a ^ k) == ROTR(a) ^ ROTR(k)), so this covers both "XOR then
                      rotate" and "rotate then XOR" encoders.
  deflate_raw, bz2, lzma, lz4f, rle_cb, rle_bc, packbits
                      the payload XOR-ed with the header key byte (as hcfg's zlib reading), decompressed;
                      with the suffix `_outer` the compression is the outer layer (decompress the payload,
                      then XOR with the key byte). bz2/lzma/lz4 frame need their magic; raw deflate and the
                      RLE readers need no magic and are prefiltered on the first two output bytes.

costly (hcfg._headers, only for the first hcfg.RC4_HEADERS headers of a file whose payload no other
reading opened, under hcfg.RC4_MAX_VERSION / RC4_MAX_LEN, WIDE_TIME CPU seconds a payload (time.thread_time, so a
loaded machine that keeps the process waiting for a core does not cut it) and hcfg.DEADLINE (wall clock)):
  lzss, lzss0, lznt1, aplib, lz4, lz4_sized (and `_outer`)
                      pure-Python decoders, output capped at PY_LIMIT, prefiltered on two output bytes.
  chacha20, salsa20   keystream XOR under a (key, nonce) from the bytes around the record, copied from the
                      RC4 near-key search: NUL-terminated printable or hex strings of key length near the
                      record, and raw key/nonce windows right before the header and right after the payload
                      (key then nonce, nonce then key); a zero nonce too; ChaCha20 at block counter 0 and 1.
  prng_<generator>    keystream XOR from a seeded PRNG: msvc / ansi (K&R) / numerical-recipes / minstd LCGs,
                      glibc rand() (TYPE_3), java.util.Random (nextBytes and nextInt(256)), xorshift32,
                      MT19937 (init_genrand, low byte), Python's random (randbytes, getrandbits(8), randint).
                      Seeds: the header key byte, 0..255, u32 words (LE and BE) at every offset in the
                      PRNG_WINDOW bytes on each side of the record, and decimal numbers near it; at most
                      PRNG_SEEDS.

Every costly reading is first tried on a few bytes: the first two decoded bytes must be able to open a payload
hcfg or nonjson_hcfg reads (plausible_head), and for a keystream (cipher or PRNG, whose first bytes are free)
the next two must be text too (plausible_head4; a CBOR / MessagePack map whose first key is one character is
the case this gives up). Only then is the whole payload decoded and its CRC-32 compared. A PRNG's first four
bytes per (generator, seed) are kept (_HEADS), since the same seeds recur for every header. A reading is kept only when the CRC-32 matches; what it decodes to (JSON, or a non-JSON map)
is hcfg's call. When the costly pass runs out of time before it has tried everything, `skipped` is set so
hcfg.containers does not keep that reading as final.

Stream ciphers need Cryptodome (pycryptodomex, pinned in requirements.in). When it cannot load, those two
readings are not run, and the reason is said once on stderr and kept in NOT_RUN (never a silent pass).
"""
from __future__ import annotations

import bz2
import importlib.util
import itertools
import lzma
import random
import re
import struct
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent

OPENING = b'{"campaign":"'      # hcfg.OPENING: how every config of the lane has opened so far
INFLATE_LIMIT = 1 << 20         # bytes a C-backed decompressor may produce (hcfg.INFLATE_LIMIT)
PY_LIMIT = 1 << 16              # bytes a pure-Python decoder may produce (a config is under 1 KB)
ROTATE_KEY_MAX = len(OPENING)   # a rotated repeating key is read only as far as the crib determines it
WIDE_TIME = 0.4                 # CPU seconds (this thread's) the costly pass may take for one payload
PRNG_WINDOW = 32                # bytes on each side of the record whose u32 words are tried as seeds
PRNG_SEEDS = 448                # seeds tried per generator and payload
NEAR = 1 << 14                  # bytes on each side of the record searched for key strings (hcfg.RC4_NEAR)
STREAM_PAIRS = 512              # (key, nonce) pairs tried per payload
DEADLINE = None                 # hcfg passes its own DEADLINE in

NOT_RUN: dict = {}              # family -> reason, when a family could not run at all
_M32 = 0xFFFFFFFF
_OPENS = b"{ \t\n\r"
_LETTERS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_")
_IDENT = _LETTERS | frozenset(b"0123456789.-=: \t")


class _Bad(Exception):
    """A malformed stream: no reading."""


def crc32(b: bytes) -> int:
    return zlib.crc32(b) & _M32


class Budget:
    """The costly pass's clock: `cpu` seconds of this thread's CPU time (time.thread_time: work, not the time a
    loaded machine keeps the process waiting, docs/build-log/SH-08.md) and, when given, a runner's wall-clock
    deadline (a time.monotonic() value)."""
    __slots__ = ("cpu_end", "wall_end")

    def __init__(self, cpu: float, wall_end: float | None = None):
        self.cpu_end = time.thread_time() + cpu
        self.wall_end = wall_end

    def over(self) -> bool:
        return time.thread_time() > self.cpu_end or (self.wall_end is not None and time.monotonic() > self.wall_end)


def _over(end) -> bool:
    """Whether `end` (a Budget, or a time.monotonic() value) has passed."""
    return end.over() if isinstance(end, Budget) else time.monotonic() > end


def _xor1(blob: bytes, key: int) -> bytes:
    return blob.translate(bytes(i ^ key for i in range(256))) if key else bytes(blob)


def _xor_stream(blob: bytes, stream: bytes) -> bytes:
    n = len(blob)
    if not n:
        return b""
    stream = (stream * (n // len(stream) + 1))[:n]
    return (int.from_bytes(blob, "little") ^ int.from_bytes(stream, "little")).to_bytes(n, "little")


def plausible_head(head: bytes, n: int | None = None) -> bool:
    """Whether two decoded bytes can open a payload hcfg (a JSON object) or nonjson_hcfg (key=value lines, flat
    XML, a CBOR / MessagePack / BSON map) reads. `n`, the decoded length when the reading fixes it (a keystream),
    admits a BSON document, whose first word is its own length."""
    if len(head) < 2:
        return False
    a, b = head[0], head[1]
    if a == 0x7B:                                   # {"... / {} / { "
        return b in b'"} \t\n\r'
    if a in b" \t\n\r":                             # leading white space, then any opener
        return b in _OPENS or b in _LETTERS or b == 0x3C
    if a == 0x3C:                                   # <tag, <?xml, <!--
        return b in _LETTERS or b in b"?!"
    if a in _LETTERS:                               # key=value lines
        return b in _IDENT
    if 0xA1 <= a <= 0xB7 or a in (0xB8, 0xB9, 0xBA, 0xBF):    # a CBOR map, keyed by a text string
        return 0x61 <= b <= 0x7B or b == 0x7F
    if 0x81 <= a <= 0x8F:                           # a MessagePack fixmap, keyed by a fixstr / str8
        return 0xA1 <= b <= 0xBF or b == 0xD9
    if a in (0xDE, 0xDF):                           # MessagePack map16 / map32
        return True
    if n is not None and n >= 5:                    # BSON: int32le total length first
        return head[:2] == (n & 0xFFFF).to_bytes(2, "little")
    return False


# ---------------------------------------------------------------------------- rotate (cheap)

_ROTR = [bytes(((i >> r) | (i << (8 - r))) & 0xFF for i in range(256)) for r in range(8)]


def rotate_readings(enc: bytes, key: int, crc: int, opening: bytes = OPENING):
    """(how, plain, key_bytes) for each CRC-valid rotated reading of `enc` (module docstring)."""
    n = len(enc)
    for r in range(1, 8):
        rot = enc.translate(_ROTR[r])
        tried = set()
        for k in dict.fromkeys((key, _ROTR[r][key], 0)):
            plain = _xor1(rot, k)
            tried.add(bytes([k]))
            if crc32(plain) == crc:
                yield f"rotate_r{r}", plain, bytes([k])
                return
        if n <= len(opening):
            continue
        for size in range(1, min(ROTATE_KEY_MAX, len(opening)) + 1):
            kb = bytes(a ^ b for a, b in zip(rot[:size], opening))
            if kb in tried:
                continue
            tried.add(kb)
            plain = _xor_stream(rot, kb)
            if crc32(plain) == crc:
                yield f"rotate_r{r}", plain, kb
                return


# ---------------------------------------------------------------------------- decompressors

def _cap(out, limit):
    if len(out) >= limit:
        raise _Limit(bytes(out[:limit]))


class _Limit(Exception):
    """A decoder reached its output limit: the output so far (a prefilter's two bytes, or a capped stream)."""

    def __init__(self, out: bytes):
        super().__init__("limit")
        self.out = out


def _run(fn, src: bytes, limit: int):
    """fn(src, limit) as bytes: its whole output, or its first `limit` bytes when it reaches the limit. None
    on a malformed stream."""
    try:
        return bytes(fn(src, limit))
    except _Limit as e:
        return e.out
    except (_Bad, IndexError, ValueError, struct.error, zlib.error, OSError, EOFError, lzma.LZMAError,
            MemoryError, OverflowError):
        return None


def deflate_raw(src: bytes, limit: int) -> bytes:
    d = zlib.decompressobj(-15)
    out = d.decompress(src, limit)
    if not d.eof and len(out) < limit:
        raise _Bad("raw deflate stream does not end")
    return out


def bz2_(src: bytes, limit: int) -> bytes:
    if src[:3] != b"BZh":
        raise _Bad("no bz2 magic")
    return bz2.BZ2Decompressor().decompress(src, limit)


def lzma_(src: bytes, limit: int) -> bytes:
    if src[:6] == b"\xfd7zXZ\x00":
        d = lzma.LZMADecompressor(lzma.FORMAT_XZ, memlimit=1 << 26)
    elif src[:1] == b"\x5d" and src[1:3] == b"\x00\x00":
        d = lzma.LZMADecompressor(lzma.FORMAT_ALONE, memlimit=1 << 26)
    else:
        raise _Bad("no xz / lzma-alone magic")
    return d.decompress(src, limit)


def rle_cb(src: bytes, limit: int) -> bytes:
    """(count, byte) pairs, count 1..255."""
    if len(src) % 2:
        raise _Bad("odd RLE length")
    out = bytearray()
    for i in range(0, len(src), 2):
        c = src[i]
        if not c:
            raise _Bad("zero RLE count")
        out += src[i + 1:i + 2] * c
        _cap(out, limit)
    return out


def rle_bc(src: bytes, limit: int) -> bytes:
    """(byte, count) pairs, count 1..255."""
    if len(src) % 2:
        raise _Bad("odd RLE length")
    out = bytearray()
    for i in range(0, len(src), 2):
        c = src[i + 1]
        if not c:
            raise _Bad("zero RLE count")
        out += src[i:i + 1] * c
        _cap(out, limit)
    return out


def packbits(src: bytes, limit: int) -> bytes:
    """Apple PackBits: h 0..127 copies h+1 literals, h 129..255 repeats the next byte 257-h times, 128 is a
    no-op."""
    out = bytearray()
    i, n = 0, len(src)
    while i < n:
        h = src[i]
        i += 1
        if h < 128:
            if i + h + 1 > n:
                raise _Bad("truncated PackBits literal run")
            out += src[i:i + h + 1]
            i += h + 1
        elif h > 128:
            if i >= n:
                raise _Bad("truncated PackBits repeat")
            out += src[i:i + 1] * (257 - h)
            i += 1
        _cap(out, limit)
    return out


def _lz4_block(src: bytes, limit: int, out: bytearray | None = None) -> bytearray:
    """One raw LZ4 block (no size header). The last sequence is literals only."""
    out = bytearray() if out is None else out
    i, n = 0, len(src)
    while i < n:
        tok = src[i]
        i += 1
        lit = tok >> 4
        if lit == 15:
            while True:
                b = src[i]
                i += 1
                lit += b
                if b != 255:
                    break
        if i + lit > n:
            raise _Bad("LZ4 literals run past the block")
        out += src[i:i + lit]
        i += lit
        _cap(out, limit)
        if i == n:
            return out
        if i + 2 > n:
            raise _Bad("truncated LZ4 offset")
        off = src[i] | (src[i + 1] << 8)
        i += 2
        if not off or off > len(out):
            raise _Bad("LZ4 offset outside the output")
        ml = tok & 15
        if ml == 15:
            while True:
                b = src[i]
                i += 1
                ml += b
                if b != 255:
                    break
        ml += 4
        start = len(out) - off
        if off >= ml:
            out += out[start:start + ml]
        else:
            for k in range(ml):
                out.append(out[start + k])
        _cap(out, limit)
    raise _Bad("LZ4 block ends with a match")


def lz4(src: bytes, limit: int) -> bytes:
    return _lz4_block(src, limit)


def lz4_sized(src: bytes, limit: int) -> bytes:
    """A u32le uncompressed size, then a raw block (python-lz4's default block format)."""
    if len(src) < 5:
        raise _Bad("short sized LZ4 block")
    size = struct.unpack_from("<I", src)[0]
    if not size or size > PY_LIMIT:
        raise _Bad("sized LZ4 block states no plausible size")
    out = _lz4_block(src[4:], min(limit, size))
    if len(out) != size and len(out) < limit:
        raise _Bad("sized LZ4 block decodes to another size")
    return out


def lz4f(src: bytes, limit: int) -> bytes:
    """An LZ4 frame (magic 04 22 4D 18): FLG, BD, optional content size and dictionary id, HC, then blocks
    (u32le size, the high bit marking a stored block), each with an optional checksum, to a zero end mark."""
    if src[:4] != b"\x04\x22\x4d\x18" or len(src) < 7:
        raise _Bad("no LZ4 frame magic")
    flg = src[4]
    if flg >> 6 != 1:
        raise _Bad("LZ4 frame version is not 01")
    i = 6 + (8 if flg & 0x08 else 0) + (4 if flg & 0x01 else 0) + 1
    out = bytearray()
    while True:
        size = struct.unpack_from("<I", src, i)[0]
        i += 4
        if size == 0:
            return out
        stored, size = size & 0x80000000, size & 0x7FFFFFFF
        block = src[i:i + size]
        if len(block) != size:
            raise _Bad("truncated LZ4 frame block")
        i += size + (4 if flg & 0x10 else 0)
        if stored:
            out += block
        else:
            _lz4_block(block, limit, out)
        _cap(out, limit)


def _lzss(src: bytes, limit: int, fill: int) -> bytes:
    """Okumura LZSS: N 4096, F 18, threshold 2, ring start N-F filled with `fill`; flag bits LSB-first, 1 a
    literal, 0 a (12-bit position, 4-bit length-3) pair."""
    N, F = 4096, 18
    buf = bytearray([fill]) * N
    r = N - F
    out = bytearray()
    i, n, flags = 0, len(src), 0
    while True:
        flags >>= 1
        if not flags & 0x100:
            if i >= n:
                return out
            flags = src[i] | 0xFF00
            i += 1
        if flags & 1:
            if i >= n:
                return out
            c = src[i]
            i += 1
            out.append(c)
            buf[r] = c
            r = (r + 1) & (N - 1)
        else:
            if i + 1 >= n:
                return out
            a, b = src[i], src[i + 1]
            i += 2
            pos, length = a | ((b & 0xF0) << 4), (b & 0x0F) + 3
            for k in range(length):
                c = buf[(pos + k) & (N - 1)]
                out.append(c)
                buf[r] = c
                r = (r + 1) & (N - 1)
        _cap(out, limit)


def lzss(src: bytes, limit: int) -> bytes:
    return _lzss(src, limit, 0x20)


def lzss0(src: bytes, limit: int) -> bytes:
    return _lzss(src, limit, 0x00)


def lznt1(src: bytes, limit: int) -> bytes:
    """Windows LZNT1 (RtlDecompressBuffer): 4 KiB chunks, each a u16le header (low 12 bits size-1, signature
    0b011, top bit compressed); a compressed chunk is flag groups LSB-first, a 1 bit a u16le phrase whose
    length/displacement split widens with the chunk's output."""
    out = bytearray()
    i, n = 0, len(src)
    while i + 2 <= n:
        h = src[i] | (src[i + 1] << 8)
        i += 2
        if h == 0:
            break
        if (h >> 12) & 7 != 3:
            raise _Bad("LZNT1 chunk signature is not 0b011")
        size = (h & 0xFFF) + 1
        chunk = src[i:i + size]
        if len(chunk) != size:
            raise _Bad("truncated LZNT1 chunk")
        i += size
        if not h & 0x8000:
            out += chunk
            _cap(out, limit)
            continue
        cout = bytearray()
        j = 0
        while j < size:
            flags = chunk[j]
            j += 1
            for _ in range(8):
                if j >= size:
                    break
                if not flags & 1:
                    cout.append(chunk[j])
                    j += 1
                else:
                    if j + 2 > size:
                        raise _Bad("truncated LZNT1 phrase")
                    tok = chunk[j] | (chunk[j + 1] << 8)
                    j += 2
                    p, lmask, oshift = len(cout) - 1, 0x0FFF, 12
                    while p >= 0x10:
                        p >>= 1
                        lmask >>= 1
                        oshift -= 1
                    length, disp = (tok & lmask) + 3, (tok >> oshift) + 1
                    start = len(cout) - disp
                    if start < 0:
                        raise _Bad("LZNT1 phrase before the chunk start")
                    for k in range(length):
                        cout.append(cout[start + k])
                flags >>= 1
                if len(out) + len(cout) >= limit:
                    raise _Limit(bytes((out + cout)[:limit]))
        out += cout
        _cap(out, limit)
    return out


_PACKER = []


def _packer_unpack():
    """solvers/binary/packer_unpack.py under a private name (its folder need not be on sys.path)."""
    if not _PACKER:
        name = "_crc_transforms_packer_unpack"
        mod = sys.modules.get(name)
        if mod is None:
            spec = importlib.util.spec_from_file_location(name, HERE / "packer_unpack.py")
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod          # registered first: a dataclass looks its module up
            try:
                spec.loader.exec_module(mod)
            except BaseException:
                sys.modules.pop(name, None)
                raise
        _PACKER.append(mod)
    return _PACKER[0]


def aplib(src: bytes, limit: int) -> bytes:
    """A raw aPLib stream (packer_unpack.decompress_aplib), or an AP32-wrapped one."""
    pu = _packer_unpack()
    try:
        if src[:4] == b"AP32":
            return pu.parse_ap32(src, max_output=max(1, limit)).data
        return pu.decompress_aplib(src, max_output=max(1, limit)).data
    except pu.UnpackError as e:
        if "cap" in str(e) and limit <= 2:
            raise _Limit(b"") from None      # cannot say two bytes cheaply: let the full decode decide
        raise _Bad(str(e)) from None


CHEAP_DECODERS = (("deflate_raw", deflate_raw, INFLATE_LIMIT), ("bz2", bz2_, INFLATE_LIMIT),
                  ("lzma", lzma_, INFLATE_LIMIT), ("lz4f", lz4f, PY_LIMIT), ("rle_cb", rle_cb, PY_LIMIT),
                  ("rle_bc", rle_bc, PY_LIMIT), ("packbits", packbits, PY_LIMIT))
COSTLY_DECODERS = (("lz4", lz4, PY_LIMIT), ("lz4_sized", lz4_sized, PY_LIMIT), ("lzss", lzss, PY_LIMIT),
                   ("lzss0", lzss0, PY_LIMIT), ("lznt1", lznt1, PY_LIMIT), ("aplib", aplib, PY_LIMIT))
_MAGIC_GATED = {"bz2", "lzma", "lz4f"}


def _decoded(fn, src: bytes, limit: int, prefilter: bool, key: int = 0):
    """fn's output on `src`, or None. With `prefilter`, first its two leading bytes, XOR `key` (the byte an
    `_outer` reading applies after the decoder), must pass plausible_head."""
    if prefilter:
        head = _run(fn, src, 2)
        if head is None or (head and not plausible_head(_xor1(head, key))):
            return None
    return _run(fn, src, limit)


def decompress_readings(enc: bytes, key: int, crc: int, decoders=CHEAP_DECODERS, *, end=None):
    """(how, plain, None) for each CRC-valid decompression of the payload: of `enc` XOR key (how = the
    decoder), and of `enc` itself then XOR key (how = decoder + "_outer"). Stops at `end` (a Budget, or a
    time.monotonic() value)."""
    x = _xor1(enc, key)
    forms = [("", x)] + ([("_outer", enc)] if key else [])
    for name, fn, limit in decoders:
        for suffix, src in forms:
            if end is not None and _over(end):
                raise TimeoutError
            out = _decoded(fn, src, limit, name not in _MAGIC_GATED, key if suffix else 0)
            if not out:
                continue
            plain = out if suffix == "" else _xor1(out, key)
            if crc32(plain) == crc:
                yield name + suffix, plain, None
                return


def cheap_readings(enc: bytes, key: int, crc: int, opening: bytes = OPENING):
    """Every cheap family (module docstring), in order: rotate, then the cheap decompressors."""
    yield from rotate_readings(enc, key, crc, opening)
    yield from decompress_readings(enc, key, crc, CHEAP_DECODERS)


# ---------------------------------------------------------------------------- PRNG keystreams

def _msvc(seed):
    s = seed & _M32
    while True:
        s = (s * 214013 + 2531011) & _M32
        yield (s >> 16) & 0xFF


def _ansi(seed):
    s = seed & _M32
    while True:
        s = (s * 1103515245 + 12345) & _M32
        yield (s >> 16) & 0xFF


def _nr(seed):
    s = seed & _M32
    while True:
        s = (s * 1664525 + 1013904223) & _M32
        yield s >> 24


def _minstd(seed):
    s = seed % 2147483647 or 1
    while True:
        s = s * 16807 % 2147483647
        yield s & 0xFF


def _glibc(seed):
    """glibc random()/rand() after srand(seed): the TYPE_3 additive feedback generator, low byte of each
    31-bit output."""
    r = [0] * 344
    r[0] = (seed & _M32) or 1
    for i in range(1, 31):
        hi, lo = divmod(r[i - 1], 127773)
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += 2147483647
        r[i] = word
    for i in range(31, 34):
        r[i] = r[i - 31]
    for i in range(34, 344):
        r[i] = (r[i - 31] + r[i - 3]) & _M32
    i = 344
    while True:
        v = (r[i - 31] + r[i - 3]) & _M32
        r.append(v)
        i += 1
        yield (v >> 1) & 0xFF


_JMUL, _JMASK = 0x5DEECE66D, (1 << 48) - 1


def _java_bytes(seed):
    """java.util.Random(seed).nextBytes: each nextInt() gives four bytes, low byte first."""
    s = (seed ^ _JMUL) & _JMASK
    while True:
        s = (s * _JMUL + 0xB) & _JMASK
        v = s >> 16
        for _ in range(4):
            yield v & 0xFF
            v >>= 8


def _java_int256(seed):
    """java.util.Random(seed).nextInt(256) per byte (a power-of-two bound: the top 8 of next(31))."""
    s = (seed ^ _JMUL) & _JMASK
    while True:
        s = (s * _JMUL + 0xB) & _JMASK
        yield (s >> 40) & 0xFF


def _xorshift32(seed):
    s = seed & _M32
    if not s:
        return
    while True:
        s ^= (s << 13) & _M32
        s ^= s >> 17
        s ^= (s << 5) & _M32
        yield s & 0xFF


def _mt19937(seed):
    """C++ std::mt19937(seed) / init_genrand, the low byte of each 32-bit output. The state is built here and
    handed to Python's own MT19937 (random.Random.setstate), whose getrandbits(32) is genrand_int32."""
    mt = [seed & _M32]
    for i in range(1, 624):
        p = mt[-1]
        mt.append((1812433253 * (p ^ (p >> 30)) + i) & _M32)
    rng = random.Random()
    rng.setstate((3, tuple(mt) + (624,), None))
    while True:
        yield rng.getrandbits(32) & 0xFF


def _py_getrandbits8(seed):
    rng = random.Random(seed)
    while True:
        yield rng.getrandbits(8)


def _py_randint(seed):
    rng = random.Random(seed)
    while True:
        yield rng.randint(0, 255)


PRNGS = (("msvc", _msvc, 32), ("ansi", _ansi, 32), ("nr", _nr, 32), ("minstd", _minstd, 31),
         ("glibc", _glibc, 32), ("java_bytes", _java_bytes, 48), ("java_int256", _java_int256, 48),
         ("xorshift32", _xorshift32, 32), ("mt19937", _mt19937, 32), ("py_getrandbits8", _py_getrandbits8, 64),
         ("py_randint", _py_randint, 64), ("py_randbytes", None, 64))
_DECIMAL = re.compile(rb"(?<![0-9])[1-9][0-9]{0,14}(?![0-9])")


def prng_seeds(data, o: int, e: int, key: int) -> list:
    """The seeds tried for the record at header offset `o` whose payload ends at `e` (module docstring)."""
    seeds = [key] + list(range(256))
    for lo, hi in ((max(0, o - PRNG_WINDOW), o), (e, min(len(data), e + PRNG_WINDOW))):
        win = bytes(data[lo:hi])
        for i in range(len(win) - 3):
            seeds.append(struct.unpack_from("<I", win, i)[0])
            seeds.append(struct.unpack_from(">I", win, i)[0])
    lo, hi = max(0, o - NEAR), min(len(data), e + NEAR)
    for m in _DECIMAL.finditer(bytes(data[lo:hi])):
        if lo + m.start() < e and lo + m.end() > o:
            continue                        # the record's own bytes are no seed
        seeds.append(int(m.group()))
    return list(dict.fromkeys(seeds))[:PRNG_SEEDS]


_HEADS = {}                    # (generator, seed) -> its first 4 keystream bytes: seeds 0..255 recur every header
HEADS_KEPT = 1 << 15


def _ks_head(name: str, gen, seed: int) -> bytes:
    got = _HEADS.get((name, seed))
    if got is None:
        got = random.Random(seed).randbytes(4) if gen is None else bytes(itertools.islice(gen(seed), 4))
        if len(_HEADS) >= HEADS_KEPT:
            _HEADS.clear()
        _HEADS[(name, seed)] = got
    return got


def plausible_head4(head: bytes, n: int) -> bool:
    """plausible_head on the first two decoded bytes of a keystream reading, and bytes 2..3 printable text (a JSON
    key, a key=value name, an XML tag, a CBOR / MessagePack map's first key of two or more characters), or a
    BSON document's whole int32 length. Four bytes, because a keystream's first bytes are free to compute."""
    if len(head) < 4 or not plausible_head(head[:2], n):
        return False
    if head[:4] == n.to_bytes(4, "little"):
        return True
    return all(0x20 <= c <= 0x7E or c in (9, 10, 13) for c in head[2:4])


def prng_reading(enc: bytes, crc: int, seeds, end: float):
    """(how, plain, seed) for the first PRNG keystream (XOR) whose decode has the stored CRC-32, or None."""
    n = len(enc)
    if n < 4:
        return None
    for name, gen, bits in PRNGS:
        top = 1 << bits
        for seed in seeds:
            if seed >= top:
                continue
            if _over(end):
                raise TimeoutError
            head = _ks_head(name, gen, seed)
            if len(head) < 4 or not plausible_head4(bytes(a ^ b for a, b in zip(enc[:4], head)), n):
                continue
            if gen is None:
                ks = random.Random(seed).randbytes(n)
            else:
                ks = bytes(itertools.islice(gen(seed), n))
            plain = _xor_stream(enc, ks)
            if crc32(plain) == crc:
                return f"prng_{name}", plain, seed
    return None


# ---------------------------------------------------------------------------- ChaCha20 / Salsa20

_CIPHERS = []


def _ciphers():
    """(ChaCha20, Salsa20) from Cryptodome, or None (NOT_RUN says why, once)."""
    if not _CIPHERS:
        try:
            from Cryptodome.Cipher import ChaCha20, Salsa20
            _CIPHERS.append((ChaCha20, Salsa20))
        except ImportError as exc:
            NOT_RUN["chacha20"] = NOT_RUN["salsa20"] = f"Cryptodome (pycryptodomex) cannot load: {exc}"
            print(f"[hcfg] chacha20/salsa20 readings not run: {NOT_RUN['chacha20']}", file=sys.stderr)
            _CIPHERS.append(None)
    return _CIPHERS[0]


_KEY_STR = re.compile(rb"(?<![\x20-\x7e])[\x21-\x7e][\x20-\x7e]{7,63}(?=\x00)")
_HEX = re.compile(rb"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){8,32}(?![0-9A-Fa-f])")


def stream_pairs(data, o: int, e: int) -> list:
    """[(key, nonce)] tried for the record at header offset `o` whose payload ends at `e`: key strings
    (printable, NUL-terminated, or hex) of 16 or 32 bytes near the record, each with a zero nonce, the bytes
    right after and right before it, and the nonce strings near the record; raw windows (key, then nonce, or
    nonce, then key) right before the header and right after the payload. At most STREAM_PAIRS."""
    L = len(data)
    lo, hi = max(0, o - NEAR), min(L, e + NEAR)
    region = bytes(data[lo:hi])
    keys, nonces = [], []
    for rx in (_KEY_STR, _HEX):
        for m in rx.finditer(region):
            a, b = lo + m.start(), lo + m.end()
            if a < e and b > o:
                continue                    # the record's own bytes are no key
            s = m.group()
            if rx is _HEX:
                s = bytes.fromhex(s.decode())
            if len(s) in (16, 32):
                keys.append((s, a, b))
            if len(s) in (8, 12):
                nonces.append(s)
    nonces = list(dict.fromkeys(nonces))[:8]
    pairs = []

    def add(k, nn):
        if len(k) in (16, 32) and len(nn) in (8, 12):
            pairs.append((bytes(k), bytes(nn)))

    for k, a, b in keys:
        for nl in (8, 12):
            add(k, bytes(nl))
            if b + 1 + nl <= L:
                add(k, data[b + 1:b + 1 + nl])          # after the key's NUL
            if b + nl <= L:
                add(k, data[b:b + nl])
            if a - nl >= 0:
                add(k, data[a - nl:a])
        for nn in nonces:
            add(k, nn)
    for kl in (32, 16):
        for nl in (8, 12):
            if o - kl - nl >= 0:
                add(data[o - kl - nl:o - nl], data[o - nl:o])           # key, nonce, header
                add(data[o - kl:o], data[o - kl - nl:o - kl])           # nonce, key, header
            if o - kl >= 0:
                add(data[o - kl:o], bytes(nl))
            if e + kl + nl <= L:
                add(data[e:e + kl], data[e + kl:e + kl + nl])           # payload, key, nonce
                add(data[e + nl:e + nl + kl], data[e:e + nl])           # payload, nonce, key
            if e + kl <= L:
                add(data[e:e + kl], bytes(nl))
    return list(dict.fromkeys(pairs))[:STREAM_PAIRS]


def stream_reading(enc: bytes, crc: int, pairs, end: float):
    """(how, plain, key, nonce, counter) for the first ChaCha20 / Salsa20 decode with the stored CRC-32, or
    None."""
    got = _ciphers()
    if got is None:
        return None
    ChaCha20, Salsa20 = got
    n = len(enc)
    for k, nn in pairs:
        if _over(end):
            raise TimeoutError
        trials = []
        if len(k) == 32:
            trials += [("chacha20", 0), ("chacha20", 1)]
        if len(nn) == 8:
            trials.append(("salsa20", 0))
        for how, counter in trials:
            def make():
                c = (ChaCha20.new(key=k, nonce=nn) if how == "chacha20" else Salsa20.new(key=k, nonce=nn))
                if counter:
                    c.seek(64 * counter)
                return c
            if not plausible_head4(make().decrypt(enc[:4]), n):
                continue
            plain = make().decrypt(enc)
            if crc32(plain) == crc:
                return how, plain, k, nn, counter
    return None


# ---------------------------------------------------------------------------- the costly pass

def costly_reading(data, o: int, enc: bytes, key: int, crc: int, deadline=None):
    """(reading, skipped): reading is {"how", "plain", ...} for the first CRC-valid costly reading of the record
    at header offset `o` (module docstring), or None; skipped is True when WIDE_TIME (CPU seconds) or `deadline`
    (a time.monotonic() value) ran out before every candidate was tried, so the None is not final."""
    walls = [d for d in (deadline, DEADLINE) if d is not None]
    end = Budget(WIDE_TIME, min(walls) if walls else None)
    e = o + 12 + len(enc)
    try:
        for how, plain, _ in decompress_readings(enc, key, crc, COSTLY_DECODERS, end=end):
            return {"how": how, "plain": plain}, False
        got = stream_reading(enc, crc, stream_pairs(data, o, e), end)
        if got:
            return {"how": got[0], "plain": got[1], "key_bytes": got[2], "nonce": got[3], "counter": got[4]}, False
        got = prng_reading(enc, crc, prng_seeds(data, o, e, key), end)
        if got:
            return {"how": got[0], "plain": got[1], "seed": got[2]}, False
    except TimeoutError:
        return None, True
    return None, False


# Readings whose key is not the header's single XOR byte (generic.xor_key_answer offers the byte unsure).
NEAR_KEYED = ("chacha20", "salsa20", "prng_")


def near_keyed(how: str) -> bool:
    """Whether a reading's key came from bytes around the record (a ChaCha20 / Salsa20 key, a PRNG seed)."""
    return isinstance(how, str) and how.startswith(NEAR_KEYED)


def header_byte_not_xor_key(how: str) -> bool:
    """Whether, in this module's reading `how`, the header key byte is NOT the payload's single-byte XOR key
    (a rotation, a near key, a PRNG seed). The decompressors XOR with that byte, so for them it is the key."""
    return isinstance(how, str) and (how.startswith("rotate_r") or near_keyed(how))


# ---------------------------------------------------------------------------- CLI

def _hcfg():
    name = "_crc_transforms_hcfg"
    mod = sys.modules.get(name)
    if mod is None:
        spec = importlib.util.spec_from_file_location(name, HERE / "hcfg.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod          # registered first: a dataclass looks its module up
        try:
            spec.loader.exec_module(mod)
        except BaseException:
            sys.modules.pop(name, None)
            raise
    return mod


def main(argv) -> int:
    if argv and argv[0] in ("-h", "--help"):
        print("usage: crc_transforms.py <sample> [...]   every CRC-valid HCFG container, every reading")
        return 0
    if not argv:
        print("crc_transforms.py: expected at least one sample", file=sys.stderr)
        return 2
    hcfg = _hcfg()
    try:
        for path in argv:
            with open(path, "rb") as fh:
                data = fh.read()
            hits = [h for h in hcfg.containers(data, others=True) if h["crc_ok"]]
            if not hits:
                print(f"{path}: no CRC-valid container")
                continue
            for h in hits:
                extra = "".join(f" {k}={h[k].hex() if isinstance(h[k], bytes) else h[k]}"
                                for k in ("key_bytes", "nonce", "counter", "seed", "nonjson") if k in h)
                print(f"{path}: offset=0x{h['offset']:x} version={h['version']} key=0x{h['key']:02x} "
                      f"crc32=0x{h['crc32']:08x} how={h['how']}{extra}")
                for k, v in h["json"].items():
                    print(f"  {k} = {v}")
    except Exception as exc:
        print(f"crc_transforms.py: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
